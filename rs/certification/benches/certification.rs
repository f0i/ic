use criterion::*;
use ic_base_types::{CanisterId, PrincipalId, SubnetId};
use ic_certification::{verify_certified_data, verify_certified_data_with_cache};
use ic_certification_test_utils::CertificateData::*;
use ic_certification_test_utils::*;
use ic_crypto_tree_hash::Digest;
use ic_types::crypto::threshold_sig::ThresholdSigPublicKey;
use rand::{thread_rng, Rng};

criterion_main!(benches);
criterion_group!(benches, canister_sig, invalid_canister_sig);

fn canister_sig(c: &mut Criterion) {
    let group = c.benchmark_group("canister_signatures");
    canister_signature_bench_impl(group, false);
}

fn invalid_canister_sig(c: &mut Criterion) {
    let group = c.benchmark_group("invalid_canister_signatures");
    canister_signature_bench_impl(group, true);
}

fn canister_signature_bench_impl(
    mut group: BenchmarkGroup<criterion::measurement::WallTime>,
    corrupt: bool,
) {
    group.bench_function("subnet_delegation_no_caching_no", move |b| {
        b.iter_batched(
            || {
                let (digest, pk, cbor) = new_random_cert_without_delegation();
                (digest, conditionally_corrupt_pk(&pk, corrupt), cbor)
            },
            |(digest, pk, cbor)| {
                let result =
                    verify_certified_data(&cbor[..], &GLOBAL_CANISTER_ID, &pk, digest.as_bytes());
                assert_eq!(result.is_err(), corrupt);
            },
            BatchSize::SmallInput,
        )
    });

    group.bench_function("subnet_delegation_yes_cache_no", move |b| {
        b.iter_batched(
            || {
                let (digest, pk, cbor) = new_random_cert_with_delegation();
                (digest, conditionally_corrupt_pk(&pk, corrupt), cbor)
            },
            |(digest, pk, cbor)| {
                let result =
                    verify_certified_data(&cbor[..], &GLOBAL_CANISTER_ID, &pk, digest.as_bytes());
                assert_eq!(result.is_err(), corrupt);
            },
            BatchSize::SmallInput,
        )
    });

    group.bench_function("subnet_delegation_no_cache_yes", move |b| {
        b.iter_batched(
            || {
                let (digest, pk, cbor) = new_random_cert_without_delegation();
                let result = verify_certified_data_with_cache(
                    &cbor[..],
                    &GLOBAL_CANISTER_ID,
                    &pk,
                    digest.as_bytes(),
                );
                assert!(result.is_ok());
                (digest, conditionally_corrupt_pk(&pk, corrupt), cbor)
            },
            |(digest, pk, cbor)| {
                let result = verify_certified_data_with_cache(
                    &cbor[..],
                    &GLOBAL_CANISTER_ID,
                    &pk,
                    digest.as_bytes(),
                );
                assert_eq!(result.is_err(), corrupt);
            },
            BatchSize::SmallInput,
        )
    });

    group.bench_function("subnet_delegation_yes_caching_yes", move |b| {
        b.iter_batched(
            || {
                let (digest, pk, cbor) = new_random_cert_with_delegation();
                let result = verify_certified_data_with_cache(
                    &cbor[..],
                    &GLOBAL_CANISTER_ID,
                    &pk,
                    digest.as_bytes(),
                );
                assert!(result.is_ok());
                (digest, conditionally_corrupt_pk(&pk, corrupt), cbor)
            },
            |(digest, pk, cbor)| {
                let result = verify_certified_data_with_cache(
                    &cbor[..],
                    &GLOBAL_CANISTER_ID,
                    &pk,
                    digest.as_bytes(),
                );
                assert_eq!(result.is_err(), corrupt);
            },
            BatchSize::SmallInput,
        )
    });
}

fn new_random_certified_data() -> Digest {
    let mut random_certified_data: [u8; 32] = [0; 32];
    thread_rng().fill(&mut random_certified_data);
    Digest(random_certified_data)
}

fn new_random_cert_without_delegation() -> (Digest, ThresholdSigPublicKey, Vec<u8>) {
    let certified_data = new_random_certified_data();
    let (_cert, pk, cbor) = CertificateBuilder::new(CanisterData {
        canister_id: GLOBAL_CANISTER_ID,
        certified_data: certified_data.clone(),
    })
    .build();
    (certified_data, pk, cbor)
}

fn new_random_cert_with_delegation() -> (Digest, ThresholdSigPublicKey, Vec<u8>) {
    let certified_data = new_random_certified_data();
    let (_cert, pk, cbor) = CertificateBuilder::new(CanisterData {
        canister_id: GLOBAL_CANISTER_ID,
        certified_data: certified_data.clone(),
    })
    .with_delegation(CertificateBuilder::new(SubnetData {
        subnet_id: subnet_id(123),
        canister_id_ranges: vec![(canister_id(0), canister_id(10))],
    }))
    .build();
    (certified_data, pk, cbor)
}

fn conditionally_corrupt_pk(pk: &ThresholdSigPublicKey, corrupt: bool) -> ThresholdSigPublicKey {
    if corrupt {
        let mut corrupted_pk: [u8; 96] = pk.into_bytes();
        corrupted_pk[0] ^= 1;
        ThresholdSigPublicKey::from(
            ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::PublicKeyBytes(
                corrupted_pk,
            ),
        )
    } else {
        *pk
    }
}

fn subnet_id(id: u64) -> SubnetId {
    SubnetId::from(PrincipalId::new_subnet_test_id(id))
}

const fn canister_id(id: u64) -> CanisterId {
    CanisterId::from_u64(id)
}

const GLOBAL_CANISTER_ID: CanisterId = canister_id(1);
