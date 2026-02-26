pub mod cross_references;
pub mod migration;
pub mod operational;
pub mod security;
pub mod xml_validity;

use crate::config::DiscoveredConfig;
use crate::result::CheckResult;

pub fn run_all(config: &DiscoveredConfig, check_remote: bool) -> Vec<CheckResult> {
    let mut results = Vec::new();
    results.extend(xml_validity::run(config));
    results.extend(cross_references::run(config, check_remote));
    results.extend(security::run(config));
    results.extend(migration::run(config));
    results.extend(operational::run(config));
    results
}
