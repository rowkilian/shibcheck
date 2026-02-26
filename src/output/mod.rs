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

    let mut add = |path: &str, found: bool, kind: &str| {
        if seen.insert(path.to_string()) {
            entries.push(FileEntry {
                path: path.to_string(),
                found,
                kind: kind.to_string(),
            });
        }
    };

    // Primary config files
    let shib_path = config
        .shibboleth_xml_path
        .strip_prefix(base_dir)
        .unwrap_or(&config.shibboleth_xml_path)
        .to_string_lossy();
    add(&shib_path, config.shibboleth_xml_exists, "config");

    let am_path = config
        .attribute_map_path
        .strip_prefix(base_dir)
        .unwrap_or(&config.attribute_map_path)
        .to_string_lossy();
    add(&am_path, config.attribute_map_exists, "attribute map");

    let ap_path = config
        .attribute_policy_path
        .strip_prefix(base_dir)
        .unwrap_or(&config.attribute_policy_path)
        .to_string_lossy();
    add(&ap_path, config.attribute_policy_exists, "attribute policy");

    // Referenced files from parsed ShibbolethConfig (added before other_xml_files
    // so that specific kinds like "metadata" win over the generic "xml" kind)
    if let Some(ref sc) = config.shibboleth_config {
        // Credential resolvers: certificates and keys
        for cr in &sc.credential_resolvers {
            if let Some(ref cert) = cr.certificate {
                let full = base_dir.join(cert);
                add(cert, full.exists(), "certificate");
            }
            if let Some(ref key) = cr.key {
                let full = base_dir.join(key);
                add(key, full.exists(), "key");
            }
        }

        // Metadata providers: path, backing_file_path, filter certificates
        for mp in &sc.metadata_providers {
            if let Some(ref path) = mp.path {
                let full = base_dir.join(path);
                add(path, full.exists(), "metadata");
            }
            if let Some(ref backing) = mp.backing_file_path {
                let full = base_dir.join(backing);
                add(backing, full.exists(), "backing file");
            }
            for f in &mp.filters {
                if let Some(ref cert) = f.certificate {
                    let full = base_dir.join(cert);
                    add(cert, full.exists(), "metadata certificate");
                }
            }
        }

        // Attribute extractor paths
        for path in &sc.attribute_extractor_paths {
            let full = base_dir.join(path);
            add(path, full.exists(), "attribute extractor");
        }

        // Attribute filter paths
        for path in &sc.attribute_filter_paths {
            let full = base_dir.join(path);
            add(path, full.exists(), "attribute filter");
        }

        // Security policy provider path
        if let Some(ref path) = sc.security_policy_provider_path {
            let full = base_dir.join(path);
            add(path, full.exists(), "security policy");
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
                    add(path, full.exists(), kind);
                }
            }
        }
    }

    // Other XML files found in the directory (generic "xml" kind, deduped against above)
    for p in &config.other_xml_files {
        let rel = p.strip_prefix(base_dir).unwrap_or(p).to_string_lossy();
        add(&rel, true, "xml");
    }

    entries
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
