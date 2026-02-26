use colored::Colorize;

use super::{collect_file_summary, FileEntry};
use crate::config::DiscoveredConfig;
use crate::result::{CheckCategory, CheckResult, CheckSummary, Severity};

pub fn print(
    results: &[CheckResult],
    summary: &CheckSummary,
    verbose: bool,
    config: &DiscoveredConfig,
) {
    print_metadata_sources(config);

    let categories = [
        CheckCategory::XmlValidity,
        CheckCategory::CrossReferences,
        CheckCategory::Security,
        CheckCategory::Migration,
        CheckCategory::Operational,
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
    print_file_summary(&collect_file_summary(config));
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

fn print_metadata_sources(config: &DiscoveredConfig) {
    let sc = match config.shibboleth_config.as_ref() {
        Some(sc) => sc,
        None => return,
    };

    let providers: Vec<_> = sc
        .metadata_providers
        .iter()
        .filter(|mp| mp.provider_type != "Chaining")
        .collect();

    if providers.is_empty() {
        return;
    }

    println!("\n{}", "── Metadata sources ──".bold());
    for mp in &providers {
        let kind = &mp.provider_type;
        if let Some(ref path) = mp.path {
            println!("  {} [{}] {}", "•".dimmed(), kind.dimmed(), path);
        }
        if let Some(ref uri) = mp.uri {
            println!("  {} [{}] {}", "•".dimmed(), kind.dimmed(), uri);
        }
        if let Some(ref url) = mp.url {
            if mp.uri.is_none() {
                println!("  {} [{}] {}", "•".dimmed(), kind.dimmed(), url);
            }
        }
        if let Some(ref src_dir) = mp.source_directory {
            println!("  {} [{}] {}", "•".dimmed(), kind.dimmed(), src_dir);
        }
        if let Some(ref backing) = mp.backing_file_path {
            println!("       {} backing: {}", "↳".dimmed(), backing.dimmed());
        }
    }
}

fn print_file_summary(files: &[FileEntry]) {
    if files.is_empty() {
        return;
    }

    println!("{}", "── Files ──".bold());

    // Find the longest path for alignment
    let max_path_len = files.iter().map(|f| f.path.len()).max().unwrap_or(0);

    for file in files {
        let icon = if file.found {
            "✓".green().to_string()
        } else {
            "✗".red().to_string()
        };
        let kind = format!("({})", file.kind).dimmed();
        println!(
            "  {} {:<width$}  {}",
            icon,
            file.path,
            kind,
            width = max_path_len
        );
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
