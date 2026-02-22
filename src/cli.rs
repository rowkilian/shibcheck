use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Shibboleth SP Configuration Checker
#[derive(Parser, Debug)]
#[command(
    name = "shibcheck",
    version,
    about = "Validate Shibboleth SP configuration files",
    long_about = "Validates shibboleth2.xml and related files in a directory, checking XML \
                  validity, cross-file references, and security best practices. Reports \
                  findings with severity levels, actionable suggestions, and links to the \
                  Shibboleth SP3 documentation.",
    after_help = "\
EXAMPLES:
  shibcheck /etc/shibboleth          Check the given directory
  shibcheck -v                       Show all checks including passed
  shibcheck --json /etc/shibboleth   Output results as JSON
  shibcheck --no-color | less        Pipe output without ANSI codes
  shibcheck init-test-idp /tmp/shib  Set up mocksaml.com test IdP

EXIT CODES:
  0  All checks passed (no errors)
  1  One or more errors found
  2  Tool failure (e.g., directory not found)

CHECKS:
  59 checks across three categories:
    XML-001..021   XML validity and required elements
    REF-001..017   Cross-file reference validation
    SEC-001..021   Security best practices

  See https://github.com/<owner>/shibcheck#checks-reference for details."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Directory containing Shibboleth SP config files
    #[arg(default_value = ".", value_name = "PATH")]
    pub path: PathBuf,

    /// Show all checks including passed ones
    #[arg(short, long)]
    pub verbose: bool,

    /// Output results as JSON (for scripting and CI)
    #[arg(long)]
    pub json: bool,

    /// Disable colored output
    #[arg(long)]
    pub no_color: bool,

    /// Fetch and validate remote metadata URLs
    #[arg(long)]
    pub check_remote: bool,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Set up mocksaml.com as a test IdP
    #[command(name = "init-test-idp")]
    InitTestIdp {
        /// Directory containing Shibboleth SP config files
        #[arg(default_value = ".", value_name = "PATH")]
        path: PathBuf,

        /// Overwrite existing metadata file
        #[arg(long)]
        force: bool,
    },
}
