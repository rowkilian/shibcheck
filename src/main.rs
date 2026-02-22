mod checks;
mod cli;
mod config;
mod init_test_idp;
mod model;
mod output;
mod parsers;
mod result;

use std::process;

use clap::Parser;
use colored::control;

use cli::{Cli, Command};
use result::CheckSummary;

fn main() {
    let cli = Cli::parse();

    if cli.no_color {
        control::set_override(false);
    }

    match &cli.command {
        Some(Command::InitTestIdp { path, force }) => {
            run_init_test_idp(path, *force);
        }
        None => {
            run_check(&cli);
        }
    }
}

fn run_init_test_idp(path: &std::path::Path, force: bool) {
    let base_dir = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_default()
            .join(path)
    };

    if let Err(e) = init_test_idp::run(&base_dir, force) {
        eprintln!("Error: {}", e);
        process::exit(2);
    }
}

fn run_check(cli: &Cli) {
    let base_dir = if cli.path.is_absolute() {
        cli.path.clone()
    } else {
        std::env::current_dir()
            .unwrap_or_default()
            .join(&cli.path)
    };

    if !base_dir.is_dir() {
        eprintln!("Error: '{}' is not a directory", base_dir.display());
        process::exit(2);
    }

    let discovered = match config::discover(&base_dir) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Error discovering configuration: {}", e);
            process::exit(2);
        }
    };

    let results = checks::run_all(&discovered, cli.check_remote);
    let summary = CheckSummary::from_results(&results);

    output::print_results(&results, cli.verbose, cli.json, &discovered);

    if summary.has_errors() {
        process::exit(1);
    }
}
