mod checks;
mod cli;
mod config;
mod diff;
mod filter;
mod fix;
mod http;
mod init_test_idp;
pub mod location;
mod model;
mod output;
mod parsers;
mod rc_config;
mod result;
mod watch;

use std::path::PathBuf;
use std::process;

use clap::Parser;
use clap_complete::generate;
use colored::control;

use cli::{Cli, Command, SeverityArg};
use output::OutputFormat;
use result::{CheckSummary, Severity};

fn main() {
    let cli = Cli::parse();

    if cli.no_color {
        control::set_override(false);
    }

    match &cli.command {
        Some(Command::InitTestIdp { path, force }) => {
            run_init_test_idp(path, *force);
        }
        Some(Command::Completions { shell }) => {
            let mut cmd = <Cli as clap::CommandFactory>::command();
            generate(*shell, &mut cmd, "shibcheck", &mut std::io::stdout());
        }
        Some(Command::Diff { dir1, dir2 }) => {
            let d1 = resolve_dir(dir1);
            let d2 = resolve_dir(dir2);
            diff::run(&d1, &d2, cli.check_remote);
        }
        Some(Command::Multi { dirs }) => {
            run_multi(&cli, dirs);
        }
        None => {
            let base_dir = resolve_dir(&cli.path);
            let rc = rc_config::RcConfig::load(&base_dir);
            if !cli.no_color && rc.no_color.unwrap_or(false) {
                control::set_override(false);
            }
            let watch_enabled = cli.watch || rc.watch.unwrap_or(false);
            if watch_enabled {
                run_watch(&cli);
            } else {
                let exit = run_check(&cli, &base_dir, &rc);
                process::exit(exit);
            }
        }
    }
}

fn run_init_test_idp(path: &std::path::Path, force: bool) {
    let base_dir = resolve_dir(path);
    if let Err(e) = init_test_idp::run(&base_dir, force) {
        eprintln!("Error: {}", e);
        process::exit(2);
    }
}

fn run_check(cli: &Cli, base_dir: &std::path::Path, rc: &rc_config::RcConfig) -> i32 {
    if !base_dir.is_dir() {
        eprintln!("Error: '{}' is not a directory", base_dir.display());
        return 2;
    }

    let verbose = cli.verbose || rc.verbose.unwrap_or(false);
    let check_remote = cli.check_remote || rc.check_remote.unwrap_or(false);
    let do_fix = cli.fix || rc.fix.unwrap_or(false);

    let format = determine_format(cli, rc);
    let severity_threshold = determine_severity(cli, rc);

    let include = cli.check.clone().or_else(|| rc.check.clone());
    let exclude = cli.skip.clone().or_else(|| rc.skip.clone());

    let discovered = match config::discover(base_dir) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Error discovering configuration: {}", e);
            return 2;
        }
    };

    let results = checks::run_all(&discovered, check_remote);
    let results = filter::apply_filters(results, include.as_deref(), exclude.as_deref());

    // Optional auto-fix
    if do_fix && fix::has_fixable(&results) {
        let fixes = fix::apply_fixes(&results, &discovered.shibboleth_xml_path);
        for f in &fixes {
            eprintln!("Fixed: {}", f);
        }
        if !fixes.is_empty() {
            eprintln!(
                "Backup saved to {}",
                discovered
                    .shibboleth_xml_path
                    .with_extension("xml.bak")
                    .display()
            );
            // Re-run checks after fixes
            let rediscovered = match config::discover(base_dir) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Error re-discovering after fix: {}", e);
                    return 2;
                }
            };
            let new_results = checks::run_all(&rediscovered, check_remote);
            let new_results =
                filter::apply_filters(new_results, include.as_deref(), exclude.as_deref());
            let summary = CheckSummary::from_results(&new_results);
            if let Err(e) = output::print_results(&new_results, verbose, format, &rediscovered) {
                eprintln!("Error: {:#}", e);
                return 2;
            }
            return if summary.has_failures_at_severity(severity_threshold) {
                1
            } else {
                0
            };
        }
    }

    let summary = CheckSummary::from_results(&results);
    if let Err(e) = output::print_results(&results, verbose, format, &discovered) {
        eprintln!("Error: {:#}", e);
        return 2;
    }

    if summary.has_failures_at_severity(severity_threshold) {
        1
    } else {
        0
    }
}

fn run_watch(cli: &Cli) {
    let base_dir = resolve_dir(&cli.path);
    if !base_dir.is_dir() {
        eprintln!("Error: '{}' is not a directory", base_dir.display());
        process::exit(2);
    }

    let cli_clone = Cli::parse(); // re-parse to get owned copy for closure
    let base_dir_clone = base_dir.clone();
    if let Err(e) = watch::watch_and_run(&base_dir, move || {
        // Reload rc on each run so edits to .shibcheckrc take effect without restart.
        let rc = rc_config::RcConfig::load(&base_dir_clone);
        let code = run_check(&cli_clone, &base_dir_clone, &rc);
        if code == 2 {
            eprintln!("Watch run failed (tool error); will retry on next change.");
        }
    }) {
        eprintln!("Watch error: {}", e);
        process::exit(2);
    }
}

fn run_multi(cli: &Cli, dirs: &[PathBuf]) {
    let mut any_failed = false;
    for dir in dirs {
        eprintln!("\n=== Checking: {} ===", dir.display());
        // Build a modified Cli for each directory
        let base_dir = resolve_dir(dir);
        if !base_dir.is_dir() {
            eprintln!("Error: '{}' is not a directory", base_dir.display());
            any_failed = true;
            continue;
        }

        let rc = rc_config::RcConfig::load(&base_dir);
        // Honor rc.no_color per-dir in multi mode (CLI --no-color is already set in main).
        if !cli.no_color && rc.no_color.unwrap_or(false) {
            control::set_override(false);
        }
        let verbose = cli.verbose || rc.verbose.unwrap_or(false);
        let check_remote = cli.check_remote || rc.check_remote.unwrap_or(false);
        let format = determine_format(cli, &rc);
        let severity_threshold = determine_severity(cli, &rc);
        let include = cli.check.clone().or(rc.check);
        let exclude = cli.skip.clone().or(rc.skip);

        let discovered = match config::discover(&base_dir) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Error discovering {}: {}", base_dir.display(), e);
                any_failed = true;
                continue;
            }
        };

        let results = checks::run_all(&discovered, check_remote);
        let results = filter::apply_filters(results, include.as_deref(), exclude.as_deref());
        let summary = CheckSummary::from_results(&results);
        if let Err(e) = output::print_results(&results, verbose, format, &discovered) {
            eprintln!("Error rendering output for {}: {:#}", base_dir.display(), e);
            any_failed = true;
            continue;
        }

        if summary.has_failures_at_severity(severity_threshold) {
            any_failed = true;
        }
    }

    if any_failed {
        process::exit(1);
    }
}

fn resolve_dir(path: &std::path::Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(path)
    }
}

fn determine_format(cli: &Cli, rc: &rc_config::RcConfig) -> OutputFormat {
    if cli.sarif {
        OutputFormat::Sarif
    } else if cli.html {
        OutputFormat::Html
    } else if cli.markdown {
        OutputFormat::Markdown
    } else if cli.json || rc.json.unwrap_or(false) {
        OutputFormat::Json
    } else if rc.sarif.unwrap_or(false) {
        OutputFormat::Sarif
    } else if rc.html.unwrap_or(false) {
        OutputFormat::Html
    } else if rc.markdown.unwrap_or(false) {
        OutputFormat::Markdown
    } else {
        OutputFormat::Terminal
    }
}

fn determine_severity(cli: &Cli, rc: &rc_config::RcConfig) -> Severity {
    // CLI always wins
    match cli.severity {
        SeverityArg::Info => Severity::Info,
        SeverityArg::Warning => Severity::Warning,
        SeverityArg::Error => {
            // "error" is the default — check if rc has something else
            if let Some(ref s) = rc.severity {
                match s.to_lowercase().as_str() {
                    "info" => Severity::Info,
                    "warning" => Severity::Warning,
                    _ => Severity::Error,
                }
            } else {
                Severity::Error
            }
        }
    }
}
