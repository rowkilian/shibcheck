pub mod html;
pub mod json;
pub mod sarif;
pub mod terminal;

use std::collections::BTreeSet;

use serde::Serialize;

use crate::config::DiscoveredConfig;
use crate::result::{CheckResult, CheckSummary};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Terminal,
    Json,
    Sarif,
    Html,
}

#[derive(Debug, Serialize)]
pub struct FileEntry {
    pub path: String,
    pub found: bool,
    pub kind: String,
}

pub fn collect_file_summary(config: &DiscoveredConfig) -> Vec<FileEntry> {
    // Deduplicate by path — first occurrence wins (more specific kind)
    let mut seen = BTreeSet::new();
    let mut entries = Vec::new();

    let base_dir = &config.base_dir;

    // Helper: insert if not already seen
    fn add(
        seen: &mut BTreeSet<String>,
        entries: &mut Vec<FileEntry>,
        path: &str,
        found: bool,
        kind: &str,
    ) {
        if seen.insert(path.to_string()) {
            entries.push(FileEntry {
                path: path.to_string(),
                found,
                kind: kind.to_string(),
            });
        }
    }

    // Primary config files
    let shib_path = config
        .shibboleth_xml_path
        .strip_prefix(base_dir)
        .unwrap_or(&config.shibboleth_xml_path)
        .to_string_lossy();
    add(
        &mut seen,
        &mut entries,
        &shib_path,
        config.shibboleth_xml_exists,
        "config",
    );

    let am_path = config
        .attribute_map_path
        .strip_prefix(base_dir)
        .unwrap_or(&config.attribute_map_path)
        .to_string_lossy();
    add(
        &mut seen,
        &mut entries,
        &am_path,
        config.attribute_map_exists,
        "attribute map",
    );

    let ap_path = config
        .attribute_policy_path
        .strip_prefix(base_dir)
        .unwrap_or(&config.attribute_policy_path)
        .to_string_lossy();
    add(
        &mut seen,
        &mut entries,
        &ap_path,
        config.attribute_policy_exists,
        "attribute policy",
    );

    // Referenced files from parsed ShibbolethConfig (added before other_xml_files
    // so that specific kinds like "metadata" win over the generic "xml" kind)
    if let Some(ref sc) = config.shibboleth_config {
        // Credential resolvers: certificates and keys
        for cr in &sc.credential_resolvers {
            if let Some(ref cert) = cr.certificate {
                let full = base_dir.join(cert);
                add(&mut seen, &mut entries, cert, full.exists(), "certificate");
            }
            if let Some(ref key) = cr.key {
                let full = base_dir.join(key);
                add(&mut seen, &mut entries, key, full.exists(), "key");
            }
        }

        // Metadata providers: path, backing_file_path, filter certificates
        for mp in &sc.metadata_providers {
            if let Some(ref path) = mp.path {
                let full = base_dir.join(path);
                add(&mut seen, &mut entries, path, full.exists(), "metadata");
            }
            if let Some(ref backing) = mp.backing_file_path {
                let full = base_dir.join(backing);
                add(
                    &mut seen,
                    &mut entries,
                    backing,
                    full.exists(),
                    "backing file",
                );
            }
            for f in &mp.filters {
                if let Some(ref cert) = f.certificate {
                    let full = base_dir.join(cert);
                    add(
                        &mut seen,
                        &mut entries,
                        cert,
                        full.exists(),
                        "metadata certificate",
                    );
                }
            }
        }

        // Attribute extractor paths
        for path in &sc.attribute_extractor_paths {
            let full = base_dir.join(path);
            add(
                &mut seen,
                &mut entries,
                path,
                full.exists(),
                "attribute extractor",
            );
        }

        // Attribute filter paths
        for path in &sc.attribute_filter_paths {
            let full = base_dir.join(path);
            add(
                &mut seen,
                &mut entries,
                path,
                full.exists(),
                "attribute filter",
            );
        }

        // Security policy provider path
        if let Some(ref path) = sc.security_policy_provider_path {
            let full = base_dir.join(path);
            add(
                &mut seen,
                &mut entries,
                path,
                full.exists(),
                "security policy",
            );
        }

        // Error templates
        if let Some(ref errors) = sc.errors {
            let error_fields: &[(&Option<String>, &str)] = &[
                (&errors.style_sheet, "error stylesheet"),
                (&errors.session_error, "error template"),
                (&errors.access_error, "error template"),
                (&errors.ssl_error, "error template"),
                (&errors.local_logout, "error template"),
                (&errors.metadata_error, "error template"),
                (&errors.global_logout, "error template"),
            ];
            for (opt, kind) in error_fields {
                if let Some(ref path) = opt {
                    let full = base_dir.join(path);
                    add(&mut seen, &mut entries, path, full.exists(), kind);
                }
            }
        }
    }

    // Other XML files found in the directory (generic "xml" kind, deduped against above)
    for p in &config.other_xml_files {
        let rel = p.strip_prefix(base_dir).unwrap_or(p).to_string_lossy();
        add(&mut seen, &mut entries, &rel, true, "xml");
    }

    // Scan directory for files not explicitly referenced by the config.
    // Well-known Shibboleth SP files get their proper kind; everything else is "unused".
    if let Ok(dir) = std::fs::read_dir(base_dir) {
        let mut extra: Vec<(String, &str)> = dir
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().map(|ft| ft.is_file()).unwrap_or(false))
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                if name.starts_with('.') || seen.contains(&name) {
                    return None;
                }
                let kind = well_known_shibboleth_file(&name);
                Some((name, kind))
            })
            .collect();
        extra.sort_by(|a, b| a.0.cmp(&b.0));
        for (name, kind) in extra {
            entries.push(FileEntry {
                path: name,
                found: true,
                kind: kind.to_string(),
            });
        }
    }

    entries
}

/// Map well-known Shibboleth SP filenames to their role.
/// Returns "unused" for files not recognized as standard SP files.
fn well_known_shibboleth_file(name: &str) -> &'static str {
    match name {
        // Default error templates
        "accessError.html" | "sessionError.html" | "sslError.html" | "metadataError.html" => {
            "error template"
        }
        "localLogout.html" | "globalLogout.html" | "partialLogout.html" => "logout template",

        // Handler templates
        "postTemplate.html" => "post template",
        "bindingTemplate.html" => "binding template",
        "discoveryTemplate.html" => "discovery template",
        "attrChecker.html" => "attribute checker",

        // Logger configurations
        "shibd.logger" | "native.logger" | "console.logger" | "syslog.logger" => "logger config",

        // Upgrade utility
        "upgrade.xsl" => "upgrade stylesheet",

        _ => "unused",
    }
}

pub fn print_results(
    results: &[CheckResult],
    verbose: bool,
    format: OutputFormat,
    config: &DiscoveredConfig,
) {
    let summary = CheckSummary::from_results(results);

    match format {
        OutputFormat::Json => json::print(results, &summary, config),
        OutputFormat::Sarif => sarif::print(results, config),
        OutputFormat::Html => html::print(results, &summary, config),
        OutputFormat::Terminal => terminal::print(results, &summary, verbose, config),
    }
}
