use std::path::{Path, PathBuf};

use quick_xml::events::Event;
use quick_xml::reader::Reader;

use crate::config::DiscoveredConfig;
use crate::result::{CheckCategory, CheckResult, Severity};

const CAT: CheckCategory = CheckCategory::CrossReferences;

// Shibboleth SP3 documentation URLs
const DOC_CREDENTIAL_RESOLVER: &str = "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334414/CredentialResolver";
const DOC_METADATA_PROVIDER: &str = "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2060616124/MetadataProvider";
const DOC_METADATA_FILTER: &str = "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2063696193/MetadataFilter";
const DOC_ATTR_EXTRACTOR: &str = "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334421/XMLAttributeExtractor";
const DOC_ATTR_FILTER: &str = "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334516/AttributeFilter";
const DOC_ATTR_ACCESS: &str = "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065335257/AttributeAccess";

pub fn run(config: &DiscoveredConfig, check_remote: bool) -> Vec<CheckResult> {
    let mut results = Vec::new();

    let sc = match config.shibboleth_config.as_ref() {
        Some(sc) => sc,
        None => return results, // Can't check references without a parsed config
    };

    // REF-001: CredentialResolver certificate files exist
    for cr in &sc.credential_resolvers {
        if let Some(ref cert_path) = cr.certificate {
            let full_path = config.base_dir.join(cert_path);
            if full_path.exists() {
                results.push(CheckResult::pass(
                    "REF-001", CAT, Severity::Error,
                    &format!("Certificate file exists: {}", cert_path),
                ));
            } else {
                results.push(CheckResult::fail(
                    "REF-001", CAT, Severity::Error,
                    &format!("Certificate file not found: {}", cert_path),
                    Some("Ensure the certificate file path is correct and the file exists"),
                ).with_doc(DOC_CREDENTIAL_RESOLVER));
            }
        }
    }

    // REF-002: CredentialResolver key files exist
    for cr in &sc.credential_resolvers {
        if let Some(ref key_path) = cr.key {
            let full_path = config.base_dir.join(key_path);
            if full_path.exists() {
                results.push(CheckResult::pass(
                    "REF-002", CAT, Severity::Error,
                    &format!("Key file exists: {}", key_path),
                ));
            } else {
                results.push(CheckResult::fail(
                    "REF-002", CAT, Severity::Error,
                    &format!("Key file not found: {}", key_path),
                    Some("Ensure the key file path is correct and the file exists"),
                ).with_doc(DOC_CREDENTIAL_RESOLVER));
            }
        }
    }

    // REF-003: MetadataProvider local file references exist
    for mp in &sc.metadata_providers {
        // Check path attribute (local metadata file)
        if let Some(ref path) = mp.path {
            if !path.starts_with("http://") && !path.starts_with("https://") {
                let full_path = config.base_dir.join(path);
                if full_path.exists() {
                    results.push(CheckResult::pass(
                        "REF-003", CAT, Severity::Error,
                        &format!("Metadata file exists: {}", path),
                    ));
                } else {
                    results.push(CheckResult::fail(
                        "REF-003", CAT, Severity::Error,
                        &format!("Metadata file not found: {}", path),
                        Some("Ensure the metadata file path is correct and the file exists"),
                    ).with_doc(DOC_METADATA_PROVIDER));
                }
            }
        }

        // Check backingFilePath attribute (auto-created cache file, info-level if missing)
        if let Some(ref backing) = mp.backing_file_path {
            let full_path = if Path::new(backing).is_absolute() {
                PathBuf::from(backing)
            } else {
                config.base_dir.join(backing)
            };
            if full_path.exists() {
                results.push(CheckResult::pass(
                    "REF-003", CAT, Severity::Info,
                    &format!("Backing file exists: {}", backing),
                ));
            } else {
                results.push(CheckResult::fail(
                    "REF-003", CAT, Severity::Info,
                    &format!("Backing file not found (will be auto-created on first fetch): {}", backing),
                    Some("The backing file is created automatically when metadata is first fetched; ensure the parent directory is writable"),
                ).with_doc(DOC_METADATA_PROVIDER));
            }
        }

        // Check sourceDirectory attribute (LocalDynamicMetadataProvider)
        if let Some(ref src_dir) = mp.source_directory {
            let full_path = if Path::new(src_dir).is_absolute() {
                PathBuf::from(src_dir)
            } else {
                config.base_dir.join(src_dir)
            };
            if full_path.is_dir() {
                results.push(CheckResult::pass(
                    "REF-003", CAT, Severity::Error,
                    &format!("Source directory exists: {}", src_dir),
                ));
            } else {
                results.push(CheckResult::fail(
                    "REF-003", CAT, Severity::Error,
                    &format!("Source directory not found: {}", src_dir),
                    Some("Ensure the sourceDirectory path points to an existing directory containing per-entity metadata files"),
                ).with_doc(DOC_METADATA_PROVIDER));
            }
        }
    }

    // REF-009: Remote metadata URL reachable and valid SAML metadata
    if check_remote {
        for mp in &sc.metadata_providers {
            let remote_url = mp.uri.as_deref().or(mp.url.as_deref());
            if let Some(url) = remote_url {
                if url.starts_with("http://") || url.starts_with("https://") {
                    check_remote_metadata(url, &mut results);
                }
            }
        }
    }

    // REF-004: MetadataFilter certificate files exist
    for mp in &sc.metadata_providers {
        for filter in &mp.filters {
            if let Some(ref cert_path) = filter.certificate {
                let full_path = config.base_dir.join(cert_path);
                if full_path.exists() {
                    results.push(CheckResult::pass(
                        "REF-004", CAT, Severity::Warning,
                        &format!("MetadataFilter certificate exists: {}", cert_path),
                    ));
                } else {
                    results.push(CheckResult::fail(
                        "REF-004", CAT, Severity::Warning,
                        &format!("MetadataFilter certificate not found: {}", cert_path),
                        Some("Ensure the metadata signature verification certificate exists"),
                    ).with_doc(DOC_METADATA_FILTER));
                }
            }
        }
    }

    // REF-005: AttributeExtractor paths exist
    for path in &sc.attribute_extractor_paths {
        let full_path = config.base_dir.join(path);
        if full_path.exists() {
            results.push(CheckResult::pass(
                "REF-005", CAT, Severity::Warning,
                &format!("AttributeExtractor file exists: {}", path),
            ));
        } else {
            results.push(CheckResult::fail(
                "REF-005", CAT, Severity::Warning,
                &format!("AttributeExtractor file not found: {}", path),
                Some("Ensure the AttributeExtractor path points to a valid file"),
            ).with_doc(DOC_ATTR_EXTRACTOR));
        }
    }

    // REF-006: AttributeFilter paths exist
    for path in &sc.attribute_filter_paths {
        let full_path = config.base_dir.join(path);
        if full_path.exists() {
            results.push(CheckResult::pass(
                "REF-006", CAT, Severity::Warning,
                &format!("AttributeFilter file exists: {}", path),
            ));
        } else {
            results.push(CheckResult::fail(
                "REF-006", CAT, Severity::Warning,
                &format!("AttributeFilter file not found: {}", path),
                Some("Ensure the AttributeFilter path points to a valid file"),
            ).with_doc(DOC_ATTR_FILTER));
        }
    }

    // REF-007: Attribute policy IDs match attribute map IDs
    if let (Some(ref map), Some(ref policy)) = (&config.attribute_map, &config.attribute_policy) {
        let map_ids: std::collections::HashSet<&str> =
            map.attributes.iter().map(|a| a.id.as_str()).collect();

        let mut all_match = true;
        for rule in &policy.rules {
            if !map_ids.contains(rule.attribute_id.as_str()) {
                results.push(CheckResult::fail(
                    "REF-007", CAT, Severity::Warning,
                    &format!(
                        "attribute-policy.xml references '{}' which is not defined in attribute-map.xml",
                        rule.attribute_id
                    ),
                    Some("Add a matching <Attribute> entry in attribute-map.xml or remove the rule from attribute-policy.xml"),
                ).with_doc(DOC_ATTR_EXTRACTOR));
                all_match = false;
            }
        }
        if all_match && !policy.rules.is_empty() {
            results.push(CheckResult::pass(
                "REF-007", CAT, Severity::Warning,
                "All attribute policy IDs match attribute map entries",
            ));
        }
    }

    // REF-008: REMOTE_USER attributes defined in attribute-map
    if let Some(ref app_defaults) = sc.application_defaults {
        if let Some(ref remote_user) = app_defaults.remote_user {
            if let Some(ref map) = config.attribute_map {
                let map_ids: std::collections::HashSet<&str> =
                    map.attributes.iter().map(|a| a.id.as_str()).collect();

                let attrs: Vec<&str> = remote_user.split_whitespace().collect();
                let mut all_found = true;
                for attr in &attrs {
                    if !map_ids.contains(attr) {
                        results.push(CheckResult::fail(
                            "REF-008", CAT, Severity::Warning,
                            &format!(
                                "REMOTE_USER attribute '{}' is not defined in attribute-map.xml",
                                attr
                            ),
                            Some("Add a mapping for this attribute in attribute-map.xml"),
                        ).with_doc(DOC_ATTR_ACCESS));
                        all_found = false;
                    }
                }
                if all_found && !attrs.is_empty() {
                    results.push(CheckResult::pass(
                        "REF-008", CAT, Severity::Warning,
                        "All REMOTE_USER attributes are defined in attribute-map.xml",
                    ));
                }
            }
        }
    }

    results
}

fn check_remote_metadata(url: &str, results: &mut Vec<CheckResult>) {
    let body = match ureq::get(url).call() {
        Ok(response) => {
            match response.into_body().read_to_string() {
                Ok(body) => body,
                Err(e) => {
                    results.push(CheckResult::fail(
                        "REF-009", CAT, Severity::Error,
                        &format!("Failed to read response body from {}: {}", url, e),
                        Some("Ensure the remote metadata URL returns valid content"),
                    ).with_doc(DOC_METADATA_PROVIDER));
                    return;
                }
            }
        }
        Err(e) => {
            results.push(CheckResult::fail(
                "REF-009", CAT, Severity::Error,
                &format!("Remote metadata URL unreachable: {} ({})", url, e),
                Some("Ensure the remote metadata URL is correct and the server is reachable"),
            ).with_doc(DOC_METADATA_PROVIDER));
            return;
        }
    };

    // Check XML well-formedness
    let mut reader = Reader::from_str(&body);
    let mut is_well_formed = true;
    let mut root_element: Option<String> = None;

    loop {
        match reader.read_event() {
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) => {
                if root_element.is_none() {
                    let full_name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    let local = full_name.rsplit(':').next().unwrap_or(&full_name).to_string();
                    root_element = Some(local);
                }
            }
            Err(_) => {
                is_well_formed = false;
                break;
            }
            _ => {}
        }
    }

    if !is_well_formed {
        results.push(CheckResult::fail(
            "REF-009", CAT, Severity::Warning,
            &format!("Remote metadata is not well-formed XML: {}", url),
            Some("The remote URL returned content that is not valid XML"),
        ).with_doc(DOC_METADATA_PROVIDER));
        return;
    }

    // Check for SAML metadata root element
    match root_element.as_deref() {
        Some("EntityDescriptor") | Some("EntitiesDescriptor") => {
            results.push(CheckResult::pass(
                "REF-009", CAT, Severity::Error,
                &format!("Remote metadata is valid SAML metadata: {}", url),
            ));
        }
        Some(other) => {
            results.push(CheckResult::fail(
                "REF-009", CAT, Severity::Warning,
                &format!("Remote URL returned XML but not SAML metadata (root element: <{}>): {}", other, url),
                Some("Expected <EntityDescriptor> or <EntitiesDescriptor> as root element"),
            ).with_doc(DOC_METADATA_PROVIDER));
        }
        None => {
            results.push(CheckResult::fail(
                "REF-009", CAT, Severity::Warning,
                &format!("Remote URL returned empty XML document: {}", url),
                Some("The remote metadata URL returned an empty document"),
            ).with_doc(DOC_METADATA_PROVIDER));
        }
    }
}
