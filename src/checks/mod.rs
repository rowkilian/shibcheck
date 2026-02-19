pub mod cross_references;
pub mod security;
pub mod xml_validity;

use crate::config::DiscoveredConfig;
use crate::result::CheckResult;

pub fn run_all(config: &DiscoveredConfig) -> Vec<CheckResult> {
    let mut results = Vec::new();
    results.extend(xml_validity::run(config));
    results.extend(cross_references::run(config));
    results.extend(security::run(config));
    results
}
