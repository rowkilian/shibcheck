pub mod json;
pub mod terminal;

use crate::config::DiscoveredConfig;
use crate::result::{CheckResult, CheckSummary};

pub fn print_results(
    results: &[CheckResult],
    verbose: bool,
    json_output: bool,
    config: &DiscoveredConfig,
) {
    let summary = CheckSummary::from_results(results);

    if json_output {
        json::print(results, &summary, config);
    } else {
        terminal::print(results, &summary, verbose, config);
    }
}
