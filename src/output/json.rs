use serde::Serialize;

use crate::result::{CheckResult, CheckSummary};

#[derive(Serialize)]
struct JsonReport<'a> {
    results: &'a [CheckResult],
    summary: &'a CheckSummary,
}

pub fn print(results: &[CheckResult], summary: &CheckSummary) {
    let report = JsonReport { results, summary };
    match serde_json::to_string_pretty(&report) {
        Ok(json) => println!("{}", json),
        Err(e) => eprintln!("Failed to serialize JSON: {}", e),
    }
}
