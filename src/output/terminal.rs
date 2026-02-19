use colored::Colorize;

use crate::result::{CheckCategory, CheckResult, CheckSummary, Severity};

pub fn print(results: &[CheckResult], summary: &CheckSummary, verbose: bool) {
    let categories = [
        CheckCategory::XmlValidity,
        CheckCategory::CrossReferences,
        CheckCategory::Security,
    ];

    for category in &categories {
        let cat_results: Vec<_> = results.iter().filter(|r| r.category == *category).collect();
        if cat_results.is_empty() {
            continue;
        }

        println!("\n{}", format!("── {} ──", category).bold());

        for result in &cat_results {
            if !verbose && result.passed {
                continue;
            }
            print_result(result);
        }
    }

    println!();
    print_summary(summary);
}

fn print_result(result: &CheckResult) {
    let status = if result.passed {
        "PASS".green().bold()
    } else {
        match result.severity {
            Severity::Error => "FAIL".red().bold(),
            Severity::Warning => "WARN".yellow().bold(),
            Severity::Info => "INFO".blue().bold(),
        }
    };

    let code = format!("[{}]", result.code).dimmed();
    println!("  {} {} {}", status, code, result.message);

    if !result.passed {
        if let Some(ref suggestion) = result.suggestion {
            println!("       {} {}", "→".dimmed(), suggestion.dimmed());
        }
        if let Some(ref doc_url) = result.doc_url {
            println!("       {} {}", "docs:".dimmed(), doc_url.dimmed());
        }
    }
}

fn print_summary(summary: &CheckSummary) {
    let line = format!(
        "Summary: {} checks | {} passed | {} errors | {} warnings | {} info",
        summary.total, summary.passed, summary.errors, summary.warnings, summary.info,
    );

    if summary.errors > 0 {
        println!("{}", line.red().bold());
    } else if summary.warnings > 0 {
        println!("{}", line.yellow().bold());
    } else {
        println!("{}", line.green().bold());
    }
}
