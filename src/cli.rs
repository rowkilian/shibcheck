use clap::Parser;
use std::path::PathBuf;

/// Shibboleth SP Configuration Checker
#[derive(Parser, Debug)]
#[command(name = "shibcheck", version, about)]
pub struct Cli {
    /// Directory to check (default: current directory)
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Show all checks including passed ones
    #[arg(short, long)]
    pub verbose: bool,

    /// Output results as JSON
    #[arg(long)]
    pub json: bool,

    /// Disable colored output
    #[arg(long)]
    pub no_color: bool,
}
