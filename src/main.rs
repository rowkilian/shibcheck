use std::path::PathBuf;
use std::process;

use clap::Parser;
use clap_complete::generate;
use colored::control;

use shibcheck::cli::{Cli, Command, SeverityArg};
use shibcheck::output::{self, OutputFormat};
use shibcheck::result::{self, CheckSummary, Severity};
use shibcheck::{
    baseline, checks, config, diff, filter, fix, init_test_idp, migrate, parsers, rc_config,
    suppress, watch,
};

fn main() {
    let cli = Cli::parse();

    if cli.no_color {
        control::set_override(false);
    }

    match &cli.command {
        Some(Command::InitTestIdp { path, force }) => {
            run_init_test_idp(path, *force);
        }
        Some(Command::Fix {
            path,
            dry_run,
            no_backup,
            only,
            skip,
            list,
        }) => {
            let opts = FixOptions {
                dry_run: *dry_run,
                backup: !*no_backup,
                only: only.as_deref(),
                skip: skip.as_deref(),
            };
            let code = if *list {
                print_fixable();
                0
            } else {
                run_fix(&resolve_dir(path), &opts)
            };
            process::exit(code);
        }
        Some(Command::Migrate {
            path,
            dry_run,
            no_backup,
            output,
            keep_namespace,
        }) => {
            let opts = MigrateOptions {
                dry_run: *dry_run,
                backup: !*no_backup,
                output: output.as_deref(),
                keep_namespace: *keep_namespace,
            };
            process::exit(run_migrate(&resolve_dir(path), &opts));
        }
        Some(Command::Baseline { path, output }) => {
            process::exit(run_baseline(&resolve_dir(path), output.as_deref()));
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

    let format = determine_format(cli, rc);
    let severity_threshold = determine_severity(cli, rc);

    let include = cli.check.clone().or_else(|| rc.check.clone());
    let exclude = cli.skip.clone().or_else(|| rc.skip.clone());

    let (discovered, results) = match discover_and_check(base_dir, check_remote, &include, &exclude)
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error discovering configuration: {}", e);
            return 2;
        }
    };
    let baseline = cli
        .baseline
        .clone()
        .or_else(|| rc.baseline.as_ref().map(|b| base_dir.join(b)));
    let results = match hide_accepted(results, &discovered, baseline.as_deref(), cli.no_ignore) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error: {:#}", e);
            return 2;
        }
    };

    let mut results = results;
    attach_fix_edits(&mut results, &discovered);

    let summary = CheckSummary::from_results(&results);
    if let Err(e) = output::print_results(&results, verbose, format, &discovered) {
        eprintln!("Error: {:#}", e);
        return 2;
    }

    i32::from(summary.has_failures_at_severity(severity_threshold))
}

/// Drop findings the user has accepted: `shibcheck-ignore` comments, then the baseline.
/// Says on stderr how many were hidden, so nothing disappears silently.
fn hide_accepted(
    results: Vec<result::CheckResult>,
    discovered: &config::DiscoveredConfig,
    baseline: Option<&std::path::Path>,
    no_ignore: bool,
) -> anyhow::Result<Vec<result::CheckResult>> {
    if no_ignore {
        return Ok(results);
    }
    let (results, ignored) = suppress::apply_directives(
        results,
        &discovered.base_dir,
        &discovered.shibboleth_xml_path,
    );
    if ignored > 0 {
        eprintln!(
            "{} hidden by shibcheck-ignore comments (use --no-ignore to see them)",
            pluralize(ignored, "finding")
        );
    }
    let Some(path) = baseline else {
        return Ok(results);
    };
    let loaded = baseline::load(path)?;
    let (results, applied) = baseline::apply(results, &loaded);
    if applied.hidden > 0 {
        eprintln!(
            "{} hidden by baseline {}",
            pluralize(applied.hidden, "finding"),
            path.display()
        );
    }
    if applied.stale > 0 {
        eprintln!(
            "{} in the baseline no longer match. Run `shibcheck baseline` to refresh it",
            pluralize(applied.stale, "entry")
        );
    }
    Ok(results)
}

/// Let JSON and SARIF carry the edit `shibcheck fix` would make for each result.
fn attach_fix_edits(results: &mut [result::CheckResult], discovered: &config::DiscoveredConfig) {
    let (Some(content), Some(sc), Some(file)) = (
        discovered.shibboleth_xml_content.as_deref(),
        discovered.shibboleth_config.as_ref(),
        discovered.shibboleth_xml_path.file_name(),
    ) else {
        return;
    };
    fix::attach_edits(results, content, &file.to_string_lossy(), sc.sp_version);
}

/// `shibcheck baseline`: write today's failed findings to a baseline file.
fn run_baseline(base_dir: &std::path::Path, output: Option<&std::path::Path>) -> i32 {
    if !base_dir.is_dir() {
        eprintln!("Error: '{}' is not a directory", base_dir.display());
        return 2;
    }
    let (discovered, results) = match discover_and_check(base_dir, false, &None, &None) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error discovering configuration: {}", e);
            return 2;
        }
    };
    // Findings you already ignore inline do not belong in the baseline.
    let (results, _) = suppress::apply_directives(
        results,
        &discovered.base_dir,
        &discovered.shibboleth_xml_path,
    );
    let target = output.map_or_else(|| base_dir.join(baseline::DEFAULT_FILE), PathBuf::from);
    let recorded = baseline::create(&results);
    if let Err(e) = baseline::save(&recorded, &target) {
        eprintln!("Error: {:#}", e);
        return 2;
    }
    println!(
        "Recorded {} in {}",
        pluralize(recorded.entries.len(), "finding"),
        target.display()
    );
    0
}

struct FixOptions<'a> {
    dry_run: bool,
    backup: bool,
    only: Option<&'a [String]>,
    skip: Option<&'a [String]>,
}

struct MigrateOptions<'a> {
    dry_run: bool,
    backup: bool,
    output: Option<&'a std::path::Path>,
    keep_namespace: bool,
}

/// One file of a migration: where it lives and what changes.
struct MigrationFile {
    path: PathBuf,
    migration: migrate::Migration,
}

fn run_migrate(base_dir: &std::path::Path, opts: &MigrateOptions) -> i32 {
    if !base_dir.is_dir() {
        eprintln!("Error: '{}' is not a directory", base_dir.display());
        return 2;
    }
    let (discovered, results) = match discover_and_check(base_dir, false, &None, &None) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error discovering configuration: {}", e);
            return 2;
        }
    };
    if discovered.shibboleth_config.is_none() {
        eprintln!(
            "Error: no readable shibboleth2.xml in '{}'",
            base_dir.display()
        );
        return 2;
    }
    let options = migrate::Options {
        keep_namespace: opts.keep_namespace,
    };

    let mut files = Vec::new();
    match std::fs::read_to_string(&discovered.shibboleth_xml_path) {
        Ok(content) => files.push(MigrationFile {
            path: discovered.shibboleth_xml_path.clone(),
            migration: migrate::plan_main(&content, options),
        }),
        Err(e) => {
            eprintln!(
                "Error: cannot read {}: {}",
                discovered.shibboleth_xml_path.display(),
                e
            );
            return 2;
        }
    }
    if let Some(policy) = parsers::security_policy::load_for(&discovered) {
        files.push(MigrationFile {
            path: policy.path,
            migration: migrate::plan_policy(&policy.content, options),
        });
    }

    let changed: Vec<&MigrationFile> = files.iter().filter(|f| !f.migration.is_empty()).collect();
    for f in &changed {
        let edits = &f.migration.plan.applied;
        println!(
            "{} {} in {}:",
            if opts.dry_run { "Would make" } else { "Made" },
            pluralize(edits.len(), "edit"),
            f.path.display()
        );
        for e in edits {
            println!(
                "  line {}  {}  ({})",
                e.line,
                e.description,
                e.codes.join(", ")
            );
        }
        if opts.dry_run {
            println!("\n{}", fix::render_diff(&f.migration.plan));
        }
    }
    if changed.is_empty() {
        println!("Nothing to migrate in {}", base_dir.display());
    }
    for f in &files {
        for note in &f.migration.notes {
            println!("Note ({}): {}", f.path.display(), note);
        }
    }

    // What is left for a person: failed migration checks no edit addressed.
    let handled: Vec<&str> = files.iter().flat_map(|f| f.migration.codes()).collect();
    let mut manual: Vec<&result::CheckResult> = results
        .iter()
        .filter(|r| {
            // MIG-001 and MIG-014 only summarize the others.
            !r.passed
                && r.code.starts_with("MIG-")
                && !matches!(r.code.as_str(), "MIG-001" | "MIG-014")
                && !handled.contains(&r.code.as_str())
        })
        .collect();
    manual.sort_by(|a, b| a.code.cmp(&b.code));
    if !manual.is_empty() {
        println!("\nNeeds a person ({}):", manual.len());
        for r in manual {
            println!("  {}  {}", r.code, r.message);
            if let Some(ref s) = r.suggestion {
                println!("          {}", s);
            }
        }
    }

    if opts.dry_run {
        if !changed.is_empty() {
            println!("\nDry run: no files were changed.");
        }
        return 0;
    }
    if changed.is_empty() {
        return 0;
    }

    if let Some(dir) = opts.output {
        if let Err(e) = std::fs::create_dir_all(dir) {
            eprintln!("Error: cannot create {}: {}", dir.display(), e);
            return 2;
        }
        // --output writes without a backup, so it must not land on the originals.
        let out = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
        let clobbers = changed.iter().any(|f| {
            f.path
                .parent()
                .and_then(|p| std::fs::canonicalize(p).ok())
                .is_some_and(|p| p == out)
        });
        if clobbers {
            eprintln!(
                "Error: --output {} is the directory of the original files; omit --output to migrate in place with a backup",
                dir.display()
            );
            return 2;
        }
        for f in &changed {
            let target = dir.join(f.path.file_name().unwrap_or_default());
            if let Err(e) = std::fs::write(&target, &f.migration.plan.fixed) {
                eprintln!("Error: cannot write {}: {}", target.display(), e);
                return 2;
            }
            println!("Wrote {}", target.display());
        }
    } else {
        for f in &changed {
            match fix::write_plan(&f.path, &f.migration.plan, opts.backup) {
                Ok(Some(backup)) => println!("Backup saved to {}", backup.display()),
                Ok(None) => {}
                Err(e) => {
                    eprintln!("Error: {:#}", e);
                    return 2;
                }
            }
        }
    }
    println!(
        "\nThe result needs SP 3.2 or later on every node. Restart shibd, read its log for \
         Shibboleth.DEPRECATION warnings, and run shibcheck on the migrated files."
    );
    0
}

fn print_fixable() {
    for (code, what) in fix::FIXABLE {
        println!("{code}  {what}");
    }
}

/// `shibcheck fix`: apply the safe fixes to shibboleth2.xml, or show them with --dry-run.
fn run_fix(base_dir: &std::path::Path, opts: &FixOptions) -> i32 {
    if !base_dir.is_dir() {
        eprintln!("Error: '{}' is not a directory", base_dir.display());
        return 2;
    }
    let known = |code: &str| {
        fix::FIXABLE
            .iter()
            .any(|(c, _)| c.eq_ignore_ascii_case(code))
    };
    for code in opts
        .only
        .iter()
        .chain(opts.skip.iter())
        .flat_map(|c| c.iter())
    {
        if !known(code) {
            eprintln!(
                "Error: {code} is not a fixable check. Run `shibcheck fix --list` to see them"
            );
            return 2;
        }
    }

    let (discovered, results) = match discover_and_check(base_dir, false, &None, &None) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error discovering configuration: {}", e);
            return 2;
        }
    };
    let path = &discovered.shibboleth_xml_path;
    let Some(sp_version) = discovered.shibboleth_config.as_ref().map(|c| c.sp_version) else {
        eprintln!(
            "Error: no readable shibboleth2.xml in '{}'",
            base_dir.display()
        );
        return 2;
    };
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: cannot read {}: {}", path.display(), e);
            return 2;
        }
    };

    let wanted = |code: &str| {
        let listed = |list: &[String]| list.iter().any(|c| c.eq_ignore_ascii_case(code));
        opts.only.is_none_or(listed) && !opts.skip.is_some_and(listed)
    };
    let codes: Vec<&str> = fix::failed_fixable(&results)
        .into_iter()
        .filter(|c| wanted(c))
        .collect();
    let plan = fix::plan(&content, &codes, sp_version);

    if plan.applied.is_empty() {
        println!("Nothing to fix in {}", path.display());
        return 0;
    }

    println!(
        "{} {} in {}:",
        if opts.dry_run { "Would fix" } else { "Fixed" },
        pluralize(plan.applied.len(), "issue"),
        path.display()
    );
    for f in &plan.applied {
        println!(
            "  line {}  {}  ({})",
            f.line,
            f.description,
            f.codes.join(", ")
        );
    }

    if opts.dry_run {
        println!("\n{}", fix::render_diff(&plan));
        println!("Dry run: no files were changed.");
        return 0;
    }

    match fix::write_plan(path, &plan, opts.backup) {
        Ok(Some(backup)) => println!("Backup saved to {}", backup.display()),
        Ok(None) => {}
        Err(e) => {
            eprintln!("Error: {:#}", e);
            return 2;
        }
    }

    // Re-run so the user sees what is left for a person to decide
    match discover_and_check(base_dir, false, &None, &None) {
        Ok((_, after)) => {
            let remaining = after.iter().filter(|r| !r.passed).count();
            if remaining > 0 {
                println!(
                    "{} still fail. Run `shibcheck {}` to see them.",
                    pluralize(remaining, "check"),
                    base_dir.display()
                );
            }
        }
        Err(e) => {
            eprintln!("Error re-checking after fix: {}", e);
            return 2;
        }
    }
    0
}

fn pluralize(n: usize, word: &str) -> String {
    format!("{n} {word}{}", if n == 1 { "" } else { "s" })
}

/// Discover the config in `base_dir`, run all checks, and apply the include/exclude filters.
fn discover_and_check(
    base_dir: &std::path::Path,
    check_remote: bool,
    include: &Option<Vec<String>>,
    exclude: &Option<Vec<String>>,
) -> anyhow::Result<(config::DiscoveredConfig, Vec<result::CheckResult>)> {
    let discovered = config::discover(base_dir)?;
    let results = checks::run_all(&discovered, check_remote);
    let results = filter::apply_filters(results, include.as_deref(), exclude.as_deref());
    Ok((discovered, results))
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

        let (discovered, results) =
            match discover_and_check(&base_dir, check_remote, &include, &exclude) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Error discovering {}: {}", base_dir.display(), e);
                    any_failed = true;
                    continue;
                }
            };
        let baseline = cli
            .baseline
            .clone()
            .or_else(|| rc.baseline.as_ref().map(|b| base_dir.join(b)));
        let results = match hide_accepted(results, &discovered, baseline.as_deref(), cli.no_ignore)
        {
            Ok(r) => r,
            Err(e) => {
                eprintln!("Error in {}: {:#}", base_dir.display(), e);
                any_failed = true;
                continue;
            }
        };
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
    // An explicit --severity wins, then .shibcheckrc, then "error".
    match cli.severity {
        Some(SeverityArg::Info) => Severity::Info,
        Some(SeverityArg::Warning) => Severity::Warning,
        Some(SeverityArg::Error) => Severity::Error,
        None => match rc.severity.as_deref().map(str::to_lowercase).as_deref() {
            Some("info") => Severity::Info,
            Some("warning") => Severity::Warning,
            _ => Severity::Error,
        },
    }
}
