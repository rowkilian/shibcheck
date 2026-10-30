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
  shibcheck --markdown /etc/shibboleth   Output Markdown report
  shibcheck --check SEC,REF-001          Run only SEC-* and REF-001 checks
  shibcheck --skip XML-005               Skip XML-005 check
  shibcheck --severity warning           Fail on warnings and errors
  shibcheck fix /etc/shibboleth          Auto-fix safe issues (see fix --help)
  shibcheck fix --dry-run                Show what fix would change
  shibcheck migrate --dry-run /etc/shibboleth   Show the SP2 to SP3 migration
  shibcheck --watch /etc/shibboleth      Re-run on file changes
  shibcheck baseline /etc/shibboleth     Record current findings as accepted
  shibcheck --baseline .shibcheck-baseline.json /etc/shibboleth
                                         Report only findings not in the baseline
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
  330+ checks across five categories:
    XML-001..076   XML validity and required elements
    REF-001..044   Cross-file reference validation
    SEC-001..147   Security best practices
    MIG-001..027   SP2 to SP3 migration
    OPS-001..088   Operational best practices

  See https://github.com/rowkilian/shibcheck#checks-reference for details."
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

    /// Output results as Markdown
    #[arg(long, group = "output_format")]
    pub markdown: bool,

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

    /// Watch for file changes and re-run checks
    #[arg(long)]
    pub watch: bool,

    /// Hide findings listed in this baseline file (create one with `shibcheck baseline`)
    #[arg(long, value_name = "FILE")]
    pub baseline: Option<PathBuf>,

    /// Show every finding: ignore `shibcheck-ignore` comments and the baseline
    #[arg(long)]
    pub no_ignore: bool,
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

    /// Fix issues that have one safe answer, keeping a backup of the original
    #[command(after_help = "\
Only checks with a single safe answer are fixed (see --list). Edits stay inside the
element's start tag, so comments and formatting are kept. Everything else needs a
person: run `shibcheck` to see what is left.

EXAMPLES:
  shibcheck fix --dry-run /etc/shibboleth   Show the changes, write nothing
  shibcheck fix /etc/shibboleth             Fix and keep shibboleth2.xml.bak
  shibcheck fix --only SEC-001 .            Fix one check
  shibcheck fix --skip SEC-133 .            Fix all but one")]
    Fix {
        /// Directory containing Shibboleth SP config files
        #[arg(default_value = ".", value_name = "PATH")]
        path: PathBuf,

        /// Show the changes and write nothing
        #[arg(long)]
        dry_run: bool,

        /// Do not keep a backup of shibboleth2.xml
        #[arg(long)]
        no_backup: bool,

        /// Only fix these checks (comma-separated codes)
        #[arg(long, value_delimiter = ',', value_name = "CODES")]
        only: Option<Vec<String>>,

        /// Do not fix these checks (comma-separated codes)
        #[arg(long, value_delimiter = ',', value_name = "CODES")]
        skip: Option<Vec<String>>,

        /// List the checks that fix can handle and exit
        #[arg(long)]
        list: bool,
    },

    /// Move an SP2 configuration to the SP3 format, keeping a backup of each file
    #[command(after_help = "\
Applies the edits the SP3 documentation prescribes and that keep behavior the same:
  - the 2.0 namespace becomes 3.0 in shibboleth2.xml and security-policy.xml
  - MetadataProvider file and uri become path and url
  - redirectWhitelist, redirectLimit \"whitelist\" and the Whitelist, Blacklist and
    EntityRoleWhiteList filter types get their SP 3.2 names
  - SessionCache gets cacheAssertions=\"true\" so the SP2 default is kept

Edits stay inside one start tag, so comments and layout are kept. What needs a person
(SessionInitiator and LogoutInitiator elements, the attribute resolver, and so on) is
listed at the end. The result needs SP 3.2 or later on every node. Run it on a copy
first, or use --dry-run, or --output to leave the originals alone.

EXAMPLES:
  shibcheck migrate --dry-run /etc/shibboleth        Show the changes, write nothing
  shibcheck migrate /etc/shibboleth                  Migrate and keep .bak files
  shibcheck migrate --output ./sp3 /etc/shibboleth   Write the new files to ./sp3
  shibcheck migrate --keep-namespace .               Rename settings, leave the namespace")]
    Migrate {
        /// Directory containing Shibboleth SP config files
        #[arg(default_value = ".", value_name = "PATH")]
        path: PathBuf,

        /// Show the changes and write nothing
        #[arg(long)]
        dry_run: bool,

        /// Do not keep a .bak copy of each changed file
        #[arg(long)]
        no_backup: bool,

        /// Write the migrated files to this directory and leave the originals alone
        #[arg(long, value_name = "DIR", conflicts_with = "no_backup")]
        output: Option<PathBuf>,

        /// Fix deprecated settings but keep the 2.0 namespace, as a first step
        #[arg(long)]
        keep_namespace: bool,
    },

    /// Record today's findings in a baseline file, so later runs report only new ones
    #[command(after_help = "\
Run the checks, then write the failed ones to a file (default: .shibcheck-baseline.json
in PATH). Check it in and run `shibcheck --baseline FILE PATH` in CI. Entries match on
check code, file and message, not line number. Edit the config to fix a finding and the
baseline notes the entry as stale; run this command again to refresh it.")]
    Baseline {
        /// Directory containing Shibboleth SP config files
        #[arg(default_value = ".", value_name = "PATH")]
        path: PathBuf,

        /// Where to write the baseline
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,
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
