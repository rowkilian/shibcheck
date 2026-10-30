use std::path::Path;

use colored::Colorize;

use crate::checks;
use crate::config;
use crate::result::{CheckResult, CheckSummary, Severity};

/// Compare two SP configuration directories by running checks on both
/// and showing what changed.
pub fn run(dir1: &Path, dir2: &Path, check_remote: bool) {
    let label1 = dir1.display().to_string();
    let label2 = dir2.display().to_string();

    let (results1, results2) = match (config::discover(dir1), config::discover(dir2)) {
        (Ok(c1), Ok(c2)) => (
            checks::run_all(&c1, check_remote),
            checks::run_all(&c2, check_remote),
        ),
        (Err(e), _) => {
            eprintln!("Error discovering {}: {}", label1, e);
            return;
        }
        (_, Err(e)) => {
            eprintln!("Error discovering {}: {}", label2, e);
            return;
        }
    };

    let summary1 = CheckSummary::from_results(&results1);
    let summary2 = CheckSummary::from_results(&results2);

    println!(
        "\n{}\n  {} — {} checks, {} errors, {} warnings\n  {} — {} checks, {} errors, {} warnings\n",
        "── Configuration Diff ──".bold(),
        label1.dimmed(), summary1.total, summary1.errors, summary1.warnings,
        label2.dimmed(), summary2.total, summary2.errors, summary2.warnings,
    );

    // Build maps by code for comparison
    let map1 = results_by_code(&results1);
    let map2 = results_by_code(&results2);

    let mut all_codes: Vec<&String> = map1.keys().chain(map2.keys()).collect();
    all_codes.sort();
    all_codes.dedup();

    let mut changes = 0;
    for code in &all_codes {
        let (a, b) = (map1.get(*code), map2.get(*code));
        // A code can report several elements; compare the whole set, not the first result.
        fn outcomes<'a>(rs: Option<&Vec<&'a CheckResult>>) -> Vec<(bool, &'a str)> {
            let mut v: Vec<(bool, &str)> = rs
                .map(|rs| rs.iter().map(|r| (r.passed, r.message.as_str())).collect())
                .unwrap_or_default();
            v.sort_unstable();
            v
        }
        if outcomes(a) == outcomes(b) {
            continue;
        }
        changes += 1;
        let label = |rs: Option<&Vec<&CheckResult>>| match rs {
            None => "none".dimmed(),
            Some(rs) => match rs.iter().find(|r| !r.passed) {
                Some(worst) => fail_label(
                    rs.iter()
                        .filter(|r| !r.passed)
                        .map(|r| r.severity)
                        .max()
                        .unwrap_or(worst.severity),
                ),
                None => "PASS".green().bold(),
            },
        };
        let message = b
            .and_then(|rs| rs.iter().find(|r| !r.passed))
            .or_else(|| a.and_then(|rs| rs.iter().find(|r| !r.passed)))
            .or_else(|| b.and_then(|rs| rs.first()))
            .or_else(|| a.and_then(|rs| rs.first()))
            .map_or("", |r| r.message.as_str());
        println!(
            "  {} → {} [{}] {}",
            label(a),
            label(b),
            code.dimmed(),
            message
        );
    }

    if changes == 0 {
        println!("  {}", "No differences found.".dimmed());
    } else {
        println!("\n  {} change(s) between the two configurations.", changes);
    }
}

fn results_by_code(
    results: &[CheckResult],
) -> std::collections::HashMap<String, Vec<&CheckResult>> {
    let mut map: std::collections::HashMap<String, Vec<&CheckResult>> =
        std::collections::HashMap::new();
    for r in results {
        map.entry(r.code.clone()).or_default().push(r);
    }
    map
}

fn fail_label(severity: Severity) -> colored::ColoredString {
    match severity {
        Severity::Error => "FAIL".red().bold(),
        Severity::Warning => "WARN".yellow().bold(),
        Severity::Info => "INFO".blue().bold(),
    }
}
