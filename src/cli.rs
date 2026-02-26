use clap::{Parser, Subcommand, ValueEnum};
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
  shibcheck /etc/shibboleth              Check the given directory
  shibcheck -v                           Show all checks including passed
  shibcheck --json /etc/shibboleth       Output results as JSON
  shibcheck --sarif /etc/shibboleth      Output SARIF for GitHub Code Scanning
  shibcheck --html /etc/shibboleth       Output self-contained HTML report
  shibcheck --check SEC,REF-001          Run only SEC-* and REF-001 checks
  shibcheck --skip XML-005               Skip XML-005 check
  shibcheck --severity warning           Fail on warnings and errors
  shibcheck --fix /etc/shibboleth        Auto-fix safe issues
  shibcheck --watch /etc/shibboleth      Re-run on file changes
  shibcheck --no-color | less            Pipe output without ANSI codes
  shibcheck completions bash             Generate shell completions
  shibcheck diff /etc/shib-old /etc/shib Diff two SP configs
  shibcheck multi dir1 dir2 dir3         Check multiple SP configs
  shibcheck init-test-idp /tmp/shib      Set up mocksaml.com test IdP

EXIT CODES:
  0  All checks passed (at threshold)
  1  One or more failures found
  2  Tool failure (e.g., directory not found)

CHECKS:
  200+ checks across five categories:
    XML-001..047   XML validity and required elements
    REF-001..033   Cross-file reference validation
    SEC-001..064   Security best practices
    MIG-001..024   SP2 to SP3 migration
    OPS-001..031   Operational best practices

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
    #[arg(long, group = "output_format")]
    pub json: bool,

    /// Output results as SARIF v2.1.0 (for GitHub Code Scanning)
    #[arg(long, group = "output_format")]
    pub sarif: bool,

    /// Output results as a self-contained HTML report
    #[arg(long, group = "output_format")]
    pub html: bool,

    /// Disable colored output
    #[arg(long)]
    pub no_color: bool,

    /// Fetch and validate remote metadata URLs
    #[arg(long)]
    pub check_remote: bool,

    /// Only run checks matching these prefixes (comma-separated, e.g. SEC,REF-001)
    #[arg(long, value_delimiter = ',', value_name = "CHECKS")]
    pub check: Option<Vec<String>>,

    /// Skip checks matching these prefixes (comma-separated)
    #[arg(long, value_delimiter = ',', value_name = "CHECKS")]
    pub skip: Option<Vec<String>>,

    /// Minimum severity for non-zero exit code
    #[arg(long, default_value = "error", value_name = "LEVEL")]
    pub severity: SeverityArg,

    /// Auto-fix safe issues (SEC-001, SEC-002, SEC-003, SEC-017)
    #[arg(long)]
    pub fix: bool,

    /// Watch for file changes and re-run checks
    #[arg(long)]
    pub watch: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum SeverityArg {
    Info,
    Warning,
    Error,
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

    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },

    /// Compare two SP configuration directories
    Diff {
        /// First SP config directory
        dir1: PathBuf,

        /// Second SP config directory
        dir2: PathBuf,
    },

    /// Check multiple SP configuration directories
    Multi {
        /// SP config directories to check
        #[arg(required = true)]
        dirs: Vec<PathBuf>,
    },
}
