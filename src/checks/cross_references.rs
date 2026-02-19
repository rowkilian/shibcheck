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

pub fn run(config: &DiscoveredConfig) -> Vec<CheckResult> {
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

    // REF-003: MetadataProvider local file exists
    for mp in &sc.metadata_providers {
        if let Some(ref path) = mp.path {
            // Only check local file paths, not URLs
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
                        "Attribute policy references '{}' which is not defined in attribute-map.xml",
                        rule.attribute_id
                    ),
                    Some("Ensure all attribute policy IDs have corresponding entries in the attribute map"),
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
