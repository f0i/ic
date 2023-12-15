use crossbeam_channel::{Receiver, TryRecvError};
use ic_interfaces::{
    batch_payload::{BatchPayloadBuilder, PastPayload, ProposalContext},
    consensus::{PayloadPermanentError, PayloadTransientError, PayloadValidationError},
    query_stats::{QueryStatsPermanentValidationError, QueryStatsTransientValidationError},
    validation::ValidationError,
};
use ic_interfaces_state_manager::StateReader;
use ic_logger::{error, warn, ReplicaLogger};
use ic_replicated_state::ReplicatedState;
use ic_types::{
    batch::{LocalQueryStats, QueryStatsPayload, ValidationContext, ENABLE_QUERY_STATS},
    epoch_from_height, CanisterId, Height, NodeId, NumBytes, QueryStatsEpoch,
};
use std::{
    collections::BTreeSet,
    sync::{Arc, RwLock},
};

/// The parameters for the payload builder that are handed over by the execution
/// environment during initialization.
///
/// We initialize the [`QueryStatsPayloadBuilder`] in two steps, because otherwise
/// we would have to pass consensus related arguments (like the [`NodeId`]) to the
/// execution environment.
pub struct QueryStatsPayloadBuilderParams(pub(crate) Receiver<LocalQueryStats>, pub(crate) u64);

impl QueryStatsPayloadBuilderParams {
    pub fn into_payload_builder(
        self,
        state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
        node_id: NodeId,
        log: ReplicaLogger,
    ) -> Box<dyn BatchPayloadBuilder> {
        Box::new(QueryStatsPayloadBuilderImpl {
            state_reader,
            node_id,
            log,
            current_stats: RwLock::new(None),
            receiver: self.0,
            epoch_length: self.1,
        })
    }
}

pub struct QueryStatsPayloadBuilderImpl {
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    node_id: NodeId,
    log: ReplicaLogger,
    current_stats: RwLock<Option<LocalQueryStats>>,
    receiver: Receiver<LocalQueryStats>,
    epoch_length: u64,
}

impl BatchPayloadBuilder for QueryStatsPayloadBuilderImpl {
    fn build_payload(
        &self,
        height: Height,
        max_size: NumBytes,
        past_payloads: &[PastPayload],
        context: &ValidationContext,
    ) -> Vec<u8> {
        match self.receiver.try_recv() {
            Ok(new_epoch) => {
                let Ok(mut epoch) = self.current_stats.write() else {
                    return vec![];
                };
                *epoch = Some(new_epoch);
            }
            Err(TryRecvError::Empty) => (),
            Err(TryRecvError::Disconnected) => {
                warn!(
                    every_n_seconds => 5,
                    self.log,
                    "QueryStatsCollector has been dropped. This is a bug"
                );
            }
        }

        match ENABLE_QUERY_STATS {
            true => self.build_payload_impl(height, max_size, past_payloads, context),
            false => vec![],
        }
    }

    fn validate_payload(
        &self,
        height: Height,
        proposal_context: &ProposalContext,
        payload: &[u8],
        past_payloads: &[PastPayload],
    ) -> Result<(), PayloadValidationError> {
        // Empty payloads are always valid
        if payload.is_empty() {
            return Ok(());
        }

        // Check whether feature is enabled and reject if it isn't.
        // NOTE: All payloads that are processed at this point are non-empty
        if !ENABLE_QUERY_STATS {
            return Err(transient_error(
                QueryStatsTransientValidationError::Disabled,
            ));
        }

        self.validate_payload_impl(height, proposal_context, payload, past_payloads)
    }
}

impl QueryStatsPayloadBuilderImpl {
    fn build_payload_impl(
        &self,
        _height: Height,
        max_size: NumBytes,
        past_payloads: &[PastPayload],
        context: &ValidationContext,
    ) -> Vec<u8> {
        let Ok(current_stats) = self.current_stats.read() else {
            return vec![];
        };
        let current_stats = match current_stats.as_ref() {
            Some(stats) => stats,
            None => {
                return {
                    warn!(self.log, "Current stats are uninitalized. This warning should go away after some minutes");
                    vec![]
                }
            }
        };

        let max_valid_epoch = epoch_from_height(context.certified_height, self.epoch_length);
        if current_stats.epoch > max_valid_epoch {
            warn!(
                self.log,
                "Current epoch {:?} is higher than epoch matching certified height {:?}",
                current_stats.epoch,
                max_valid_epoch
            );
            return vec![];
        }

        let Ok(previous_ids) =
            self.get_previous_ids(self.node_id, current_stats.epoch, past_payloads, context)
        else {
            return vec![];
        };

        // Pick all stats that have not been sent before
        let messages = current_stats
            .stats
            .iter()
            .filter(|stats| !previous_ids.contains(&stats.canister_id))
            .cloned()
            .collect();

        let payload = QueryStatsPayload {
            epoch: current_stats.epoch,
            proposer: self.node_id,
            stats: messages,
        };

        // Serialize the payload, drop messages at the end if necessary
        payload.serialize_with_limit(max_size)
    }

    fn validate_payload_impl(
        &self,
        _height: Height,
        proposal_context: &ProposalContext,
        payload: &[u8],
        past_payloads: &[PastPayload],
    ) -> Result<(), PayloadValidationError> {
        // Check that the payload actually deserializes
        let payload = match QueryStatsPayload::deserialize(payload) {
            Ok(Some(payload)) => payload,
            Ok(None) => return Ok(()),
            Err(err) => {
                return Err(permanent_error(
                    QueryStatsPermanentValidationError::DeserializationFailed(err),
                ))
            }
        };

        // Check that nodeid is actually in subnet
        if proposal_context.proposer != payload.proposer {
            return Err(permanent_error(
                QueryStatsPermanentValidationError::InvalidNodeId {
                    expected: proposal_context.proposer,
                    reported: payload.proposer,
                },
            ));
        }

        // Check that epoch is not too high
        let max_valid_epoch = epoch_from_height(
            proposal_context.validation_context.certified_height,
            self.epoch_length,
        );
        if payload.epoch > max_valid_epoch {
            return Err(permanent_error(
                QueryStatsPermanentValidationError::EpochTooHigh {
                    expected: max_valid_epoch,
                    reported: payload.epoch,
                },
            ));
        }

        // Check that there are no duplicates within an individual payload
        let mut seen_ids = BTreeSet::new();
        for id in payload.stats.iter().map(|stat| stat.canister_id) {
            if seen_ids.contains(&id) {
                return Err(permanent_error(
                    QueryStatsPermanentValidationError::DuplicateCanisterId(id),
                ));
            } else {
                seen_ids.insert(id);
            }
        }

        // Get the previous ids, that have been already reported by this node in the epoch
        // NOTE: This also checks that the epoch that is being reported has not been aggregated yet
        let previous_ids = self.get_previous_ids(
            payload.proposer,
            payload.epoch,
            past_payloads,
            proposal_context.validation_context,
        )?;

        // Check that payload does not contain previous ids
        if let Some(canister_id) = payload
            .stats
            .iter()
            .map(|stat| stat.canister_id)
            .find(|canister_id| previous_ids.contains(canister_id))
        {
            warn!(
                self.log,
                "Found duplicate CanisterId {:?} in payload", canister_id
            );
            return Err(permanent_error(
                QueryStatsPermanentValidationError::DuplicateCanisterId(canister_id),
            ));
        }

        Ok(())
    }

    /// Returns all previous [`CanisterId`]s, that the node of the specified [`NodeId`] has already
    /// reported in the given [`QueryStatsEpoch`].
    ///
    /// This function also returns an error, if we are requesting data on an epoch,
    /// that has been already aggregated.
    fn get_previous_ids(
        &self,
        node_id: NodeId,
        epoch: QueryStatsEpoch,
        past_payloads: &[PastPayload],
        context: &ValidationContext,
    ) -> Result<BTreeSet<CanisterId>, PayloadValidationError> {
        // Get unaggregated stats from certified state
        let certified_height = context.certified_height;
        let state_stats = &match self.state_reader.get_state_at(certified_height) {
            Ok(state) => state,
            Err(err) => {
                warn!(
                    every_n_seconds => 5,
                    self.log,
                    "StateManager doesn't have state for height {}: {:?}", certified_height, err
                );

                return Err(transient_error(
                    QueryStatsTransientValidationError::StateUnavailable(err),
                ));
            }
        }
        .take()
        .epoch_query_stats;

        // The query stats can be sent over multiple payloads
        // To not resend the same stats twice, we need to filter out the canister ids
        // we have already sent. It is imporant to only filter against canister ids if
        // the stats are not of a previous epoch
        let mut previous_ids = BTreeSet::<CanisterId>::new();

        // Check that the epoch we are requesting has not been aggregated yet
        if epoch < state_stats.epoch.unwrap_or(0.into()) {
            warn!(
                every_n_seconds => 5,
                self.log,
                "QueryStats: requesting previous_ids for epoch {:?} that is below aggregated epoch {:?}",
                epoch,
                state_stats.epoch
            );

            return Err(permanent_error(
                QueryStatsPermanentValidationError::EpochAlreadyAggregated {
                    expected: state_stats.epoch.unwrap_or(0.into()),
                    reported: epoch,
                },
            ));
        }

        // Check the certified state for stats already sent
        // Skip if certified state is not the same epoch
        if state_stats.epoch == Some(epoch) {
            previous_ids.extend(
                state_stats
                    .stats
                    .iter()
                    .filter(|(_, stat_map)| stat_map.contains_key(&node_id))
                    .map(|(canister_id, _)| canister_id),
            );
        }

        // Check past payloads for stats already sent
        previous_ids.extend(
            past_payloads
                .iter()
                // Deserialize the payload
                .filter_map(|past_payload| {
                    QueryStatsPayload::deserialize(past_payload.payload)
                        .map_err(|err| {
                            error!(
                                self.log,
                                "Failed to deserialize past payload, this is a bug"
                            );
                            err
                        })
                        .ok()
                        .flatten()
                })
                // Filter out payloads that have a different epoch or are sent from different node
                .filter(|stats| stats.epoch == epoch && stats.proposer == node_id)
                // Map payload to CanisterIds
                .flat_map(|stats| {
                    stats
                        .stats
                        .iter()
                        .map(|stat| stat.canister_id)
                        .collect::<Vec<CanisterId>>()
                }),
        );

        Ok(previous_ids)
    }
}

fn transient_error(err: QueryStatsTransientValidationError) -> PayloadValidationError {
    ValidationError::Transient(PayloadTransientError::QueryStatsPayloadValidationError(err))
}

fn permanent_error(err: QueryStatsPermanentValidationError) -> PayloadValidationError {
    ValidationError::Permanent(PayloadPermanentError::QueryStatsPayloadValidationError(err))
}
#[cfg(test)]
mod tests {
    use super::*;
    use ic_interfaces_state_manager_mocks::MockStateManager;
    use ic_logger::replica_logger::no_op_logger;
    use ic_test_utilities::{mock_time, state::ReplicatedStateBuilder};
    use ic_types::{
        batch::{CanisterQueryStats, QueryStats, RawQueryStats},
        crypto::{CryptoHash, CryptoHashOf},
        RegistryVersion,
    };
    use ic_types_test_utils::ids::{canister_test_id, node_test_id};
    use std::{ops::Range, time::Duration};

    const MAX_PAYLOAD_SIZE: NumBytes = NumBytes::new(1024 * 1024);

    /// Test simple inclusion of a stat
    ///
    /// - Put statistics of one canister into `current_stats`  
    /// - Build a payload
    /// - Check that the statistic is in the build payload
    #[test]
    fn query_stats_inclusion_test() {
        let test_stats = test_epoch_stats(0, 1);
        let state = test_state(RawQueryStats::default());
        let payload_builder = setup_payload_builder_impl(state, test_stats);
        let validation_context = test_validation_context();
        let proposal_context = test_proposal_context(&validation_context);

        let (payload, serialized_payload) = build_and_validate(
            &payload_builder,
            &proposal_context,
            Height::new(1),
            MAX_PAYLOAD_SIZE,
            &[],
        );

        assert!(!serialized_payload.is_empty());
        assert_eq!(payload.proposer, node_test_id(1));
        assert_eq!(payload.epoch, QueryStatsEpoch::new(0));
        assert_eq!(payload.stats.len(), 1);
    }

    /// Test that the payload builder respects the size limit and does not
    /// include more stats if it does not fit
    ///
    /// - Put 1000 statistics into `current_stats`
    /// - Build a payload that can only be 2000 bytes large
    /// - Check that payload is in fact smaller than 2000 bytes
    /// - Check that less than 1000 statistics have been included
    #[test]
    fn size_limit_test() {
        let test_stats = test_epoch_stats(0, 1000);
        let state = test_state(RawQueryStats::default());
        let payload_builder = setup_payload_builder_impl(state, test_stats);
        let validation_context = test_validation_context();
        let proposal_context = test_proposal_context(&validation_context);

        let (payload, serialized_payload) = build_and_validate(
            &payload_builder,
            &proposal_context,
            Height::new(1),
            NumBytes::new(2000),
            &[],
        );

        assert!(!serialized_payload.is_empty());
        assert!(serialized_payload.len() < 2000);
        assert_eq!(payload.proposer, node_test_id(1));
        assert_eq!(payload.epoch, QueryStatsEpoch::new(0));
        assert!(payload.stats.len() < 1000);
    }

    /// Test that ids already in state or in past payload will not be included
    ///
    /// - Build [`LocalQueryStats`] with 500 entries
    /// - Put first 200 entries into the state
    /// - Put the next 100 into `past_payloads`
    /// - Put the next 100 into another `past_payloads`
    /// - Build a payload
    /// - Check that it only includes the last 100 entries
    #[test]
    fn past_payload_test() {
        let test_stats = test_epoch_stats(0, 500);
        let state = test_state(epoch_stats_for_state(&test_stats, 0..200, node_test_id(1)));
        let payload_builder = setup_payload_builder_impl(state, test_stats.clone());
        let validation_context = test_validation_context();
        let proposal_context = test_proposal_context(&validation_context);

        let past_payload1 = payload_from_range(&test_stats, 200..300, node_test_id(1));
        let past_payload1 = as_past_payload(&past_payload1, 1);

        let past_payload2 = payload_from_range(&test_stats, 300..400, node_test_id(1));
        let past_payload2 = as_past_payload(&past_payload2, 2);

        let (payload, serialized_payload) = build_and_validate(
            &payload_builder,
            &proposal_context,
            Height::new(3),
            MAX_PAYLOAD_SIZE,
            &[past_payload2, past_payload1],
        );

        assert!(!serialized_payload.is_empty());
        assert_eq!(payload.proposer, node_test_id(1));
        assert_eq!(payload.epoch, QueryStatsEpoch::new(0));
        assert!(payload.stats.len() == 100);
        for stat_idx in 0..100 {
            assert_eq!(payload.stats[stat_idx], test_stats.stats[stat_idx + 400]);
        }
    }

    /// Test that the payload builder checks that past_payloads and staticstics in
    /// the state which are only excluded when they are from the same node id.
    ///
    /// - Build [`LocalQueryStats`] with 500 entries
    /// - Put first 100 entries into the state as own node id
    /// - Put next 100 entries into the state as foreign node id
    /// - Put the next 100 into `past_payloads` as own node id
    /// - Put the next 100 into another `past_payloads` as foreign id
    /// - Build a payload
    /// - Check that it includes the entries 100 to 200, 300 to 500
    #[test]
    fn node_id_check_test() {
        let test_stats = test_epoch_stats(0, 500);

        let stats1 = epoch_stats_for_state(&test_stats, 0..100, node_test_id(1));
        let stats2 = epoch_stats_for_state(&test_stats, 100..200, node_test_id(2));
        let stats = merge_raw_query_stats(stats1, stats2);
        let state = test_state(stats);

        let payload_builder = setup_payload_builder_impl(state, test_stats.clone());
        let validation_context = test_validation_context();
        let proposal_context = test_proposal_context(&validation_context);

        let past_payload1 = payload_from_range(&test_stats, 200..300, node_test_id(1));
        let past_payload1 = as_past_payload(&past_payload1, 1);

        let past_payload2 = payload_from_range(&test_stats, 300..400, node_test_id(2));
        let past_payload2 = as_past_payload(&past_payload2, 2);

        let (payload, serialized_payload) = build_and_validate(
            &payload_builder,
            &proposal_context,
            Height::new(3),
            MAX_PAYLOAD_SIZE,
            &[past_payload2, past_payload1],
        );

        assert!(!serialized_payload.is_empty());
        assert_eq!(payload.proposer, node_test_id(1));
        assert_eq!(payload.epoch, QueryStatsEpoch::new(0));

        assert!(payload.stats.len() == 300);

        for stat_idx in 0..100 {
            assert_eq!(payload.stats[stat_idx], test_stats.stats[stat_idx + 100]);
        }
        for stat_idx in 100..300 {
            assert_eq!(payload.stats[stat_idx], test_stats.stats[stat_idx + 200]);
        }
    }

    /// Test wrong node_id does not validate
    #[test]
    fn invalid_node_id_test() {
        let test_stats = test_epoch_stats(0, 0);
        let state = test_state(RawQueryStats::default());
        let payload_builder = setup_payload_builder_impl(state, test_stats);
        let validation_context = test_validation_context();
        let proposal_context = test_proposal_context(&validation_context);

        let payload = QueryStatsPayload {
            epoch: QueryStatsEpoch::new(0),
            proposer: node_test_id(2),
            stats: vec![CanisterQueryStats {
                canister_id: canister_test_id(0),
                stats: QueryStats::default(),
            }],
        }
        .serialize_with_limit(MAX_PAYLOAD_SIZE);

        let validation_result =
            payload_builder.validate_payload_impl(Height::new(1), &proposal_context, &payload, &[]);

        match validation_result {
            Err(ValidationError::Permanent(
                PayloadPermanentError::QueryStatsPayloadValidationError(
                    QueryStatsPermanentValidationError::InvalidNodeId { expected, reported },
                ),
            )) if expected == node_test_id(1) && reported == node_test_id(2) => (),
            Err(err) => panic!(
                "QueryStatsPayload had wrong node id, yet instead got error {:?}",
                err
            ),
            Ok(_) => panic!("QueryStatsPayload had wrong node id, yet got validated"),
        }
    }

    /// Test that epoch too low won't validate
    #[test]
    fn epoch_too_low_test() {
        let test_stats = test_epoch_stats(1234, 100);
        let state = test_state(epoch_stats_for_state(&test_stats, 0..100, node_test_id(1)));
        let payload_builder = setup_payload_builder_impl(state, test_stats);
        let validation_context = test_validation_context();
        let proposal_context = test_proposal_context(&validation_context);

        let payload = QueryStatsPayload {
            epoch: QueryStatsEpoch::new(0),
            proposer: node_test_id(1),
            stats: vec![CanisterQueryStats {
                canister_id: canister_test_id(0),
                stats: QueryStats::default(),
            }],
        }
        .serialize_with_limit(MAX_PAYLOAD_SIZE);

        let validation_result =
            payload_builder.validate_payload_impl(Height::new(1), &proposal_context, &payload, &[]);

        match validation_result {
            Err(ValidationError::Permanent(
                PayloadPermanentError::QueryStatsPayloadValidationError(
                    QueryStatsPermanentValidationError::EpochAlreadyAggregated {
                        expected,
                        reported,
                    },
                ),
            )) if expected == QueryStatsEpoch::new(1234) && reported == QueryStatsEpoch::new(0) => {
            }
            Err(err) => panic!(
                "QueryStatsPayload had epoch too low, yet instead got error {:?}",
                err
            ),
            Ok(_) => panic!("QueryStatsPayload had epoch too low, yet got validated"),
        }
    }

    /// Test that epoch too high won't validate
    #[test]
    fn epoch_too_high_test() {
        let test_stats = test_epoch_stats(0, 0);
        let state = test_state(RawQueryStats::default());
        let payload_builder = setup_payload_builder_impl(state, test_stats);
        let validation_context = test_validation_context();
        let proposal_context = test_proposal_context(&validation_context);

        let payload = QueryStatsPayload {
            epoch: QueryStatsEpoch::new(1234),
            proposer: node_test_id(1),
            stats: vec![CanisterQueryStats {
                canister_id: canister_test_id(0),
                stats: QueryStats::default(),
            }],
        }
        .serialize_with_limit(MAX_PAYLOAD_SIZE);

        let validation_result =
            payload_builder.validate_payload_impl(Height::new(1), &proposal_context, &payload, &[]);

        match validation_result {
            Err(ValidationError::Permanent(
                PayloadPermanentError::QueryStatsPayloadValidationError(
                    QueryStatsPermanentValidationError::EpochTooHigh { expected, reported },
                ),
            )) if expected == QueryStatsEpoch::new(0) && reported == QueryStatsEpoch::new(1234) => {
            }
            Err(err) => panic!(
                "QueryStatsPayload had epoch too high, yet instead got error {:?}",
                err
            ),
            Ok(_) => panic!("QueryStatsPayload had epoch too high, yet got validated"),
        }
    }

    /// Test that payload with duplicate node_id won't validate
    /// - Put stats for canister 1 in state
    /// - Put stats for canister 2 in past payload
    /// - Put stats for canister 3 in current payload
    /// - Either put stats for canister 1, 2, 3 and 4 in the current payload
    /// - In either of the first 3 cases, the payload does not validate, in the last case it does
    #[test]
    fn duplicate_id_test() {
        let test_stats = test_epoch_stats(0, 4);
        let state = test_state(epoch_stats_for_state(&test_stats, 0..1, node_test_id(1)));
        let payload_builder = setup_payload_builder_impl(state, test_stats.clone());
        let validation_context = test_validation_context();
        let proposal_context = test_proposal_context(&validation_context);

        let past_payload = payload_from_range(&test_stats, 1..2, node_test_id(1));
        let past_payload = as_past_payload(&past_payload, 1);
        //let template_payload = payload_from_range(&test_stats, 3..4, node_test_id(1));
        let template_payload = QueryStatsPayload {
            epoch: test_stats.epoch,
            proposer: node_test_id(1),
            stats: test_stats.stats[2..3].to_vec(),
        };

        for id in 0..3 {
            let mut payload = template_payload.clone();
            payload.stats.push(test_stats.stats[id].clone());
            let payload = payload.serialize_with_limit(MAX_PAYLOAD_SIZE);

            let validation_result = payload_builder.validate_payload_impl(
                Height::new(1),
                &proposal_context,
                &payload,
                &[past_payload.clone()],
            );

            match validation_result {
                Ok(_) if id >= 3 => (),
                Err(ValidationError::Permanent(
                    PayloadPermanentError::QueryStatsPayloadValidationError(
                        QueryStatsPermanentValidationError::DuplicateCanisterId(canister_id),
                    ),
                )) if canister_id == canister_test_id(id as u64) => (),
                Err(err) => panic!(
                    "QueryStatsPayload test {} had duplicates, yet instead got error {:?}",
                    id, err
                ),
                Ok(_) => panic!(
                    "QueryStatsPayload test {} had duplicates, yet got validated",
                    id
                ),
            }
        }
    }

    fn test_validation_context() -> ValidationContext {
        ValidationContext {
            registry_version: RegistryVersion::new(0),
            certified_height: Height::new(0),
            time: mock_time(),
        }
    }

    fn test_proposal_context(validation_context: &ValidationContext) -> ProposalContext<'_> {
        ProposalContext {
            proposer: node_test_id(1),
            validation_context,
        }
    }

    fn build_and_validate(
        payload_builder: &QueryStatsPayloadBuilderImpl,
        proposal_context: &ProposalContext,
        height: Height,
        max_size: NumBytes,
        past_payloads: &[PastPayload],
    ) -> (QueryStatsPayload, Vec<u8>) {
        let payload = payload_builder.build_payload_impl(
            height,
            max_size,
            past_payloads,
            proposal_context.validation_context,
        );

        assert!(payload_builder
            .validate_payload_impl(height, proposal_context, &payload, past_payloads)
            .is_ok());

        (
            QueryStatsPayload::deserialize(&payload).unwrap().unwrap(),
            payload,
        )
    }

    /// Set up a payload builder for testing with the supplied internal state
    fn setup_payload_builder_impl(
        state: MockStateManager,
        stats: LocalQueryStats,
    ) -> QueryStatsPayloadBuilderImpl {
        let (_, rx) = crossbeam_channel::bounded(1);
        QueryStatsPayloadBuilderImpl {
            state_reader: Arc::new(state),
            node_id: node_test_id(1),
            log: no_op_logger(),
            current_stats: Some(stats).into(),
            receiver: rx,
            epoch_length: ic_config::execution_environment::QUERY_STATS_EPOCH_LENGTH,
        }
    }

    /// Generate some statistics for testing
    fn test_epoch_stats(epoch: u64, num_stats: u64) -> LocalQueryStats {
        LocalQueryStats {
            epoch: QueryStatsEpoch::new(epoch),
            stats: (0..num_stats)
                .map(|id| CanisterQueryStats {
                    canister_id: canister_test_id(id),
                    stats: QueryStats {
                        num_calls: 1,
                        num_instructions: 1000,
                        ingress_payload_size: 1000,
                        egress_payload_size: 1000,
                    },
                })
                .collect(),
        }
    }

    fn epoch_stats_for_state(
        query_stats: &LocalQueryStats,
        range: Range<usize>,
        node: NodeId,
    ) -> RawQueryStats {
        RawQueryStats {
            epoch: Some(query_stats.epoch),
            stats: query_stats.stats[range]
                .iter()
                .map(|stat| {
                    (
                        stat.canister_id,
                        [(node, stat.stats.clone())].into_iter().collect(),
                    )
                })
                .collect(),
        }
    }

    fn merge_raw_query_stats(mut stats1: RawQueryStats, stats2: RawQueryStats) -> RawQueryStats {
        assert_eq!(stats1.epoch, stats2.epoch);

        for (canister_id, stat2) in stats2.stats {
            stats1
                .stats
                .entry(canister_id)
                // NOTE: This assumes that there are no nodeids identical in stats1 and stats2
                .and_modify(|entry| entry.extend(stat2.clone().into_iter()))
                .or_insert(stat2);
        }

        stats1
    }

    fn payload_from_range(
        query_stats: &LocalQueryStats,
        range: Range<usize>,
        node: NodeId,
    ) -> Vec<u8> {
        let past_payload = QueryStatsPayload {
            epoch: query_stats.epoch,
            proposer: node,
            stats: query_stats.stats[range].to_vec(),
        };
        past_payload.serialize_with_limit(MAX_PAYLOAD_SIZE)
    }

    fn as_past_payload(payload: &[u8], height: u64) -> PastPayload {
        PastPayload {
            height: Height::from(height),
            time: mock_time() + Duration::from_nanos(10 * height),
            block_hash: CryptoHashOf::from(CryptoHash(vec![])),
            payload,
        }
    }

    /// Generate some test state which has some predetermined statisticss
    fn test_state(query_stats: RawQueryStats) -> MockStateManager {
        let mut state_manager = MockStateManager::new();
        state_manager.expect_get_state_at().return_const(Ok(
            ic_interfaces_state_manager::Labeled::new(
                Height::new(0),
                Arc::new(
                    ReplicatedStateBuilder::new()
                        .with_query_stats(query_stats)
                        .build(),
                ),
            ),
        ));
        state_manager
    }
}
