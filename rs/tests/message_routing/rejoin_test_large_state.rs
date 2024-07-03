use anyhow::Result;

use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;
use ic_tests::message_routing::rejoin_test_large_state::Config;
use std::time::Duration;

const PER_TASK_TIMEOUT: Duration = Duration::from_secs(3600 * 2);
const OVERALL_TIMEOUT: Duration = Duration::from_secs(3600 * 2);
const NUM_NODES: usize = 4;
const SIZE_LEVEL: usize = 8;
const NUM_CANISTERS: usize = 8;

fn main() -> Result<()> {
    let config = Config::new(NUM_NODES, SIZE_LEVEL, NUM_CANISTERS);
    let test = config.clone().test();
    SystemTestGroup::new()
        .with_setup(config.build())
        .add_test(systest!(test))
        .with_timeout_per_test(PER_TASK_TIMEOUT)
        .with_overall_timeout(OVERALL_TIMEOUT)
        .execute_from_args()?;
    Ok(())
}
