pub mod html;
pub mod json;
pub mod sarif;
pub mod terminal;

use crate::config::DiscoveredConfig;
use crate::result::{CheckResult, CheckSummary};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Terminal,
    Json,
    Sarif,
    Html,
}

pub fn print_results(
    results: &[CheckResult],
    verbose: bool,
    format: OutputFormat,
    config: &DiscoveredConfig,
) {
    let summary = CheckSummary::from_results(results);

    match format {
        OutputFormat::Json => json::print(results, &summary, config),
        OutputFormat::Sarif => sarif::print(results, config),
        OutputFormat::Html => html::print(results, &summary, config),
        OutputFormat::Terminal => terminal::print(results, &summary, verbose, config),
    }
}
