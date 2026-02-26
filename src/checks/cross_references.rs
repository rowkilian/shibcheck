use std::collections::HashSet;
use std::path::{Path, PathBuf};

use quick_xml::events::Event;
use quick_xml::reader::Reader;

use crate::config::DiscoveredConfig;
use crate::model::shibboleth_config::SpVersion;
use crate::parsers::certificate;
use crate::result::{CheckCategory, CheckResult, Severity};

const CAT: CheckCategory = CheckCategory::CrossReferences;

// Shibboleth SP3 documentation URLs
const DOC_CREDENTIAL_RESOLVER: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334414/CredentialResolver";
const DOC_METADATA_PROVIDER: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2060616124/MetadataProvider";
const DOC_METADATA_FILTER: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2063696193/MetadataFilter";
const DOC_ATTR_EXTRACTOR: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334421/XMLAttributeExtractor";
const DOC_ATTR_FILTER: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334516/AttributeFilter";
const DOC_ATTR_ACCESS: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065335257/AttributeAccess";
const DOC_ERRORS: &str = "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334308/Errors";

const DOC_SP2_WIKI: &str = "https://shibboleth.atlassian.net/wiki/spaces/SHIB2/";

fn doc_for(sp3_url: &str, version: SpVersion) -> &str {
    match version {
        SpVersion::V2 => DOC_SP2_WIKI,
        _ => sp3_url,
    }
}

pub fn run(config: &DiscoveredConfig, check_remote: bool) -> Vec<CheckResult> {
    let mut results = Vec::new();

    let sc = match config.shibboleth_config.as_ref() {
        Some(sc) => sc,
        None => return results, // Can't check references without a parsed config
    };

    let v = sc.sp_version;

    // REF-001: CredentialResolver certificate files exist
    for cr in &sc.credential_resolvers {
        if let Some(ref cert_path) = cr.certificate {
            let full_path = config.base_dir.join(cert_path);
            if full_path.exists() {
                results.push(CheckResult::pass(
                    "REF-001",
                    CAT,
                    Severity::Error,
                    &format!("Certificate file exists: {}", cert_path),
                ));
            } else {
                results.push(
                    CheckResult::fail(
                        "REF-001",
                        CAT,
                        Severity::Error,
                        &format!("Certificate file not found: {}", cert_path),
                        Some("Ensure the certificate file path is correct and the file exists"),
                    )
                    .with_doc(doc_for(DOC_CREDENTIAL_RESOLVER, v)),
                );
            }
        }
    }

    // REF-002: CredentialResolver key files exist
    for cr in &sc.credential_resolvers {
        if let Some(ref key_path) = cr.key {
            let full_path = config.base_dir.join(key_path);
            if full_path.exists() {
                results.push(CheckResult::pass(
                    "REF-002",
                    CAT,
                    Severity::Error,
                    &format!("Key file exists: {}", key_path),
                ));
            } else {
                results.push(
                    CheckResult::fail(
                        "REF-002",
                        CAT,
                        Severity::Error,
                        &format!("Key file not found: {}", key_path),
                        Some("Ensure the key file path is correct and the file exists"),
                    )
                    .with_doc(doc_for(DOC_CREDENTIAL_RESOLVER, v)),
                );
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
                        "REF-003",
                        CAT,
                        Severity::Error,
                        &format!("Metadata file exists: {}", path),
                    ));
                } else {
                    results.push(
                        CheckResult::fail(
                            "REF-003",
                            CAT,
                            Severity::Error,
                            &format!("Metadata file not found: {}", path),
                            Some("Ensure the metadata file path is correct and the file exists"),
                        )
                        .with_doc(doc_for(DOC_METADATA_PROVIDER, v)),
                    );
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
                    "REF-003",
                    CAT,
                    Severity::Info,
                    &format!("Backing file exists: {}", backing),
                ));
            } else {
                results.push(CheckResult::fail(
                    "REF-003", CAT, Severity::Info,
                    &format!("Backing file not found (will be auto-created on first fetch): {}", backing),
                    Some("The backing file is created automatically when metadata is first fetched; ensure the parent directory is writable"),
                ).with_doc(doc_for(DOC_METADATA_PROVIDER, v)));
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
                    "REF-003",
                    CAT,
                    Severity::Error,
                    &format!("Source directory exists: {}", src_dir),
                ));
            } else {
                results.push(CheckResult::fail(
                    "REF-003", CAT, Severity::Error,
                    &format!("Source directory not found: {}", src_dir),
                    Some("Ensure the sourceDirectory path points to an existing directory containing per-entity metadata files"),
                ).with_doc(doc_for(DOC_METADATA_PROVIDER, v)));
            }
        }
    }

    // REF-009: Remote metadata URL reachable and valid SAML metadata
    if check_remote {
        for mp in &sc.metadata_providers {
            let remote_url = mp.uri.as_deref().or(mp.url.as_deref());
            if let Some(url) = remote_url {
                if url.starts_with("http://") || url.starts_with("https://") {
                    check_remote_metadata(url, &mut results, v);
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
                        "REF-004",
                        CAT,
                        Severity::Warning,
                        &format!("MetadataFilter certificate exists: {}", cert_path),
                    ));
                } else {
                    results.push(
                        CheckResult::fail(
                            "REF-004",
                            CAT,
                            Severity::Warning,
                            &format!("MetadataFilter certificate not found: {}", cert_path),
                            Some("Ensure the metadata signature verification certificate exists"),
                        )
                        .with_doc(doc_for(DOC_METADATA_FILTER, v)),
                    );
                }
            }
        }
    }

    // REF-005: AttributeExtractor paths exist
    for path in &sc.attribute_extractor_paths {
        let full_path = config.base_dir.join(path);
        if full_path.exists() {
            results.push(CheckResult::pass(
                "REF-005",
                CAT,
                Severity::Warning,
                &format!("AttributeExtractor file exists: {}", path),
            ));
        } else {
            results.push(
                CheckResult::fail(
                    "REF-005",
                    CAT,
                    Severity::Warning,
                    &format!("AttributeExtractor file not found: {}", path),
                    Some("Ensure the AttributeExtractor path points to a valid file"),
                )
                .with_doc(doc_for(DOC_ATTR_EXTRACTOR, v)),
            );
        }
    }

    // REF-006: AttributeFilter paths exist
    for path in &sc.attribute_filter_paths {
        let full_path = config.base_dir.join(path);
        if full_path.exists() {
            results.push(CheckResult::pass(
                "REF-006",
                CAT,
                Severity::Warning,
                &format!("AttributeFilter file exists: {}", path),
            ));
        } else {
            results.push(
                CheckResult::fail(
                    "REF-006",
                    CAT,
                    Severity::Warning,
                    &format!("AttributeFilter file not found: {}", path),
                    Some("Ensure the AttributeFilter path points to a valid file"),
                )
                .with_doc(doc_for(DOC_ATTR_FILTER, v)),
            );
        }
    }

    // REF-007: Attribute policy IDs match attribute map IDs
    if let (Some(ref map), Some(ref policy)) = (&config.attribute_map, &config.attribute_policy) {
        let map_ids: HashSet<&str> = map.attributes.iter().map(|a| a.id.as_str()).collect();

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
                ).with_doc(doc_for(DOC_ATTR_EXTRACTOR, v)));
                all_match = false;
            }
        }
        if all_match && !policy.rules.is_empty() {
            results.push(CheckResult::pass(
                "REF-007",
                CAT,
                Severity::Warning,
                "All attribute policy IDs match attribute map entries",
            ));
        }
    }

    // REF-008: REMOTE_USER attributes defined in attribute-map
    if let Some(ref app_defaults) = sc.application_defaults {
        if let Some(ref remote_user) = app_defaults.remote_user {
            if let Some(ref map) = config.attribute_map {
                let map_ids: HashSet<&str> = map.attributes.iter().map(|a| a.id.as_str()).collect();

                let attrs: Vec<&str> = remote_user.split_whitespace().collect();
                let mut all_found = true;
                for attr in &attrs {
                    if !map_ids.contains(attr) {
                        results.push(
                            CheckResult::fail(
                                "REF-008",
                                CAT,
                                Severity::Warning,
                                &format!(
                                "REMOTE_USER attribute '{}' is not defined in attribute-map.xml",
                                attr
                            ),
                                Some("Add a mapping for this attribute in attribute-map.xml"),
                            )
                            .with_doc(doc_for(DOC_ATTR_ACCESS, v)),
                        );
                        all_found = false;
                    }
                }
                if all_found && !attrs.is_empty() {
                    results.push(CheckResult::pass(
                        "REF-008",
                        CAT,
                        Severity::Warning,
                        "All REMOTE_USER attributes are defined in attribute-map.xml",
                    ));
                }
            }
        }
    }

    // REF-010: Local metadata files contain valid SAML root element
    for mp in &sc.metadata_providers {
        if let Some(ref path) = mp.path {
            if !path.starts_with("http://") && !path.starts_with("https://") {
                let full_path = config.base_dir.join(path);
                if full_path.exists() {
                    check_local_metadata_saml(&full_path, path, &mut results, v);
                }
            }
        }
    }

    // REF-011: Key file is a valid PEM private key
    for cr in &sc.credential_resolvers {
        if let Some(ref key_path) = cr.key {
            let full_path = config.base_dir.join(key_path);
            if full_path.exists() {
                match certificate::validate_pem_key_file(&full_path) {
                    Ok(()) => {
                        results.push(CheckResult::pass(
                            "REF-011",
                            CAT,
                            Severity::Warning,
                            &format!("Key file is a valid PEM private key: {}", key_path),
                        ));
                    }
                    Err(_) => {
                        results.push(CheckResult::fail(
                            "REF-011", CAT, Severity::Warning,
                            &format!("Key file is not a recognized PEM private key: {}", key_path),
                            Some("Ensure the key file contains a PEM-encoded private key (PKCS#8 or traditional format)"),
                        ).with_doc(doc_for(DOC_CREDENTIAL_RESOLVER, v)));
                    }
                }
            }
        }
    }

    // REF-012: No duplicate MetadataProvider sources
    {
        let mut seen_sources: HashSet<String> = HashSet::new();
        let mut has_duplicate = false;
        for mp in &sc.metadata_providers {
            if mp.provider_type == "Chaining" {
                continue;
            }
            let source = if let Some(ref path) = mp.path {
                Some(format!("path={}", path))
            } else if let Some(ref uri) = mp.uri {
                Some(format!("uri={}", uri))
            } else {
                mp.url.as_ref().map(|url| format!("url={}", url))
            };
            if let Some(src) = source {
                if !seen_sources.insert(src.clone()) {
                    results.push(
                        CheckResult::fail(
                            "REF-012",
                            CAT,
                            Severity::Warning,
                            &format!("Duplicate MetadataProvider source: {}", src),
                            Some("Remove the duplicate MetadataProvider or use different sources"),
                        )
                        .with_doc(doc_for(DOC_METADATA_PROVIDER, v)),
                    );
                    has_duplicate = true;
                }
            }
        }
        if !has_duplicate && seen_sources.len() > 1 {
            results.push(CheckResult::pass(
                "REF-012",
                CAT,
                Severity::Warning,
                "No duplicate MetadataProvider sources found",
            ));
        }
    }

    // REF-014: Duplicate attribute IDs in attribute-map.xml
    if let Some(ref map) = config.attribute_map {
        let mut seen_ids: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
        let mut has_dup = false;
        for attr in &map.attributes {
            if let Some(&prev_name) = seen_ids.get(attr.id.as_str()) {
                let different_names = prev_name != attr.name.as_str();
                let suggestion = if different_names {
                    format!(
                        "Duplicate id '{}' maps different names ('{}' and '{}'); \
                         this may be intentional (e.g., NameID vs attribute). \
                         Remove the one your IdP does not send",
                        attr.id, prev_name, attr.name
                    )
                } else {
                    "Remove or rename the duplicate <Attribute> entry; later entries shadow earlier ones".to_string()
                };
                results.push(
                    CheckResult::fail(
                        "REF-014",
                        CAT,
                        Severity::Warning,
                        &format!("Duplicate attribute id '{}' in attribute-map.xml", attr.id),
                        Some(&suggestion),
                    )
                    .with_doc(doc_for(DOC_ATTR_EXTRACTOR, v)),
                );
                has_dup = true;
            } else {
                seen_ids.insert(&attr.id, &attr.name);
            }
        }
        if !has_dup && !map.attributes.is_empty() {
            results.push(CheckResult::pass(
                "REF-014",
                CAT,
                Severity::Warning,
                "No duplicate attribute IDs in attribute-map.xml",
            ));
        }
    }

    // REF-015: Duplicate attribute names in attribute-map.xml
    if let Some(ref map) = config.attribute_map {
        let mut seen_names: HashSet<&str> = HashSet::new();
        let mut has_dup = false;
        for attr in &map.attributes {
            if !seen_names.insert(attr.name.as_str()) {
                results.push(CheckResult::fail(
                    "REF-015", CAT, Severity::Info,
                    &format!("Duplicate attribute name '{}' in attribute-map.xml", attr.name),
                    Some("The same OID/URN is mapped more than once; this is usually unintentional"),
                ).with_doc(doc_for(DOC_ATTR_EXTRACTOR, v)));
                has_dup = true;
            }
        }
        if !has_dup && !map.attributes.is_empty() {
            results.push(CheckResult::pass(
                "REF-015",
                CAT,
                Severity::Info,
                "No duplicate attribute names in attribute-map.xml",
            ));
        }
    }

    // REF-016: SSO entityID references an IdP found in loaded metadata
    if let Some(ref sessions) = sc.sessions {
        if let Some(ref sso_entity_id) = sessions.sso_entity_id {
            let mut found = false;
            for mp in &sc.metadata_providers {
                if let Some(ref path) = mp.path {
                    if !path.starts_with("http://") && !path.starts_with("https://") {
                        let full_path = config.base_dir.join(path);
                        if full_path.exists() && metadata_contains_entity(&full_path, sso_entity_id)
                        {
                            found = true;
                            break;
                        }
                    }
                }
            }
            if found {
                results.push(CheckResult::pass(
                    "REF-016",
                    CAT,
                    Severity::Warning,
                    &format!("SSO entityID '{}' found in local metadata", sso_entity_id),
                ));
            } else if sc
                .metadata_providers
                .iter()
                .any(|mp| mp.uri.is_some() || mp.url.is_some())
            {
                // Remote providers exist that we can't check without --check-remote
                results.push(CheckResult::pass(
                    "REF-016",
                    CAT,
                    Severity::Warning,
                    &format!(
                        "SSO entityID '{}' not found in local metadata (remote providers present)",
                        sso_entity_id
                    ),
                ));
            } else {
                results.push(CheckResult::fail(
                    "REF-016", CAT, Severity::Warning,
                    &format!("SSO entityID '{}' not found in any loaded metadata", sso_entity_id),
                    Some("Ensure a MetadataProvider loads metadata for the IdP referenced in <SSO>"),
                ).with_doc(doc_for(DOC_METADATA_PROVIDER, v)));
            }
        }
    }

    // REF-017: Remote MetadataProvider should have backingFilePath
    {
        let mut has_missing_backing = false;
        for mp in &sc.metadata_providers {
            let remote_url = mp.uri.as_deref().or(mp.url.as_deref());
            if let Some(url) = remote_url {
                if mp.backing_file_path.is_none() {
                    results.push(CheckResult::fail(
                        "REF-017", CAT, Severity::Warning,
                        &format!("Remote MetadataProvider has no backingFilePath: {}", url),
                        Some("Add backingFilePath to cache metadata locally; without it the SP cannot start if the remote source is unavailable"),
                    ).with_doc(doc_for(DOC_METADATA_PROVIDER, v)));
                    has_missing_backing = true;
                }
            }
        }
        if !has_missing_backing {
            let has_remote = sc
                .metadata_providers
                .iter()
                .any(|mp| mp.uri.is_some() || mp.url.is_some());
            if has_remote {
                results.push(CheckResult::pass(
                    "REF-017",
                    CAT,
                    Severity::Warning,
                    "All remote MetadataProviders have backingFilePath configured",
                ));
            }
        }
    }

    // REF-018: SecurityPolicyProvider file exists
    if let Some(ref spp_path) = sc.security_policy_provider_path {
        let full_path = config.base_dir.join(spp_path);
        if full_path.exists() {
            results.push(CheckResult::pass(
                "REF-018",
                CAT,
                Severity::Error,
                &format!("SecurityPolicyProvider file exists: {}", spp_path),
            ));
        } else {
            results.push(
                CheckResult::fail(
                    "REF-018",
                    CAT,
                    Severity::Error,
                    &format!("SecurityPolicyProvider file not found: {}", spp_path),
                    Some("Ensure the security-policy.xml file exists at the configured path"),
                )
                .with_doc(doc_for(DOC_METADATA_PROVIDER, v)),
            );
        }
    }

    // REF-019: Logging config files exist (shibd.logger, native.logger)
    {
        let logger_files = ["shibd.logger", "native.logger"];
        for logger in &logger_files {
            let full_path = config.base_dir.join(logger);
            if full_path.exists() {
                results.push(CheckResult::pass(
                    "REF-019",
                    CAT,
                    Severity::Info,
                    &format!("Logging config file exists: {}", logger),
                ));
            } else {
                results.push(
                    CheckResult::fail(
                        "REF-019",
                        CAT,
                        Severity::Info,
                        &format!("Logging config file not found: {}", logger),
                        Some("Create the logger file to customize logging output"),
                    )
                    .with_doc(doc_for(DOC_METADATA_PROVIDER, v)),
                );
            }
        }
    }

    // REF-020: MetadataFilter Signature certificate is valid PEM
    for mp in &sc.metadata_providers {
        for filter in &mp.filters {
            if !filter.filter_type.contains("Signature") {
                continue;
            }
            if let Some(ref cert_path) = filter.certificate {
                let full_path = config.base_dir.join(cert_path);
                if full_path.exists() {
                    match certificate::parse_pem_file(&full_path) {
                        Ok(_) => {
                            results.push(CheckResult::pass(
                                "REF-020",
                                CAT,
                                Severity::Warning,
                                &format!(
                                    "MetadataFilter Signature certificate is valid PEM: {}",
                                    cert_path
                                ),
                            ));
                        }
                        Err(_) => {
                            results.push(
                                CheckResult::fail(
                                    "REF-020",
                                    CAT,
                                    Severity::Warning,
                                    &format!(
                                        "MetadataFilter Signature certificate is not valid PEM: {}",
                                        cert_path
                                    ),
                                    Some("Ensure the certificate file contains a valid PEM-encoded certificate"),
                                )
                                .with_doc(doc_for(DOC_METADATA_FILTER, v)),
                            );
                        }
                    }
                }
            }
        }
    }

    // REF-021: MetadataFilter Signature certificate not expired
    {
        let now = chrono::Utc::now();
        for mp in &sc.metadata_providers {
            for filter in &mp.filters {
                if !filter.filter_type.contains("Signature") {
                    continue;
                }
                if let Some(ref cert_path) = filter.certificate {
                    let full_path = config.base_dir.join(cert_path);
                    if full_path.exists() {
                        if let Ok(cert_info) = certificate::parse_pem_file(&full_path) {
                            if cert_info.not_after < now {
                                results.push(
                                    CheckResult::fail(
                                        "REF-021",
                                        CAT,
                                        Severity::Warning,
                                        &format!(
                                            "MetadataFilter Signature certificate has expired: {} ({})",
                                            cert_path,
                                            cert_info.not_after.format("%Y-%m-%d")
                                        ),
                                        Some("Replace the expired metadata signing certificate"),
                                    )
                                    .with_doc(doc_for(DOC_METADATA_FILTER, v)),
                                );
                            } else {
                                results.push(CheckResult::pass(
                                    "REF-021",
                                    CAT,
                                    Severity::Warning,
                                    &format!(
                                        "MetadataFilter Signature certificate is not expired: {}",
                                        cert_path
                                    ),
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    // REF-022: postTemplate file path doesn't exist
    if let Some(ref content) = config.shibboleth_xml_content {
        // Scan for postTemplate="..." in raw XML
        if let Some(start) = content.find("postTemplate=\"") {
            let rest = &content[start + 14..];
            if let Some(end) = rest.find('"') {
                let template_path = &rest[..end];
                if !template_path.is_empty() {
                    let full_path = config.base_dir.join(template_path);
                    if full_path.exists() {
                        results.push(CheckResult::pass(
                            "REF-022",
                            CAT,
                            Severity::Info,
                            &format!("postTemplate file exists: {}", template_path),
                        ));
                    } else {
                        results.push(
                            CheckResult::fail(
                                "REF-022",
                                CAT,
                                Severity::Info,
                                &format!("postTemplate file not found: {}", template_path),
                                Some("Ensure the postTemplate file path is correct and the file exists"),
                            )
                            .with_doc(doc_for(DOC_ATTR_EXTRACTOR, v)),
                        );
                    }
                }
            }
        }
    }

    // REF-024: ApplicationOverride entityID same as parent (redundant)
    if let Some(ref parent_entity_id) = sc.entity_id {
        for (override_id, override_entity_id) in &sc.application_override_entity_ids {
            if let Some(ref eid) = override_entity_id {
                if eid == parent_entity_id {
                    results.push(
                        CheckResult::fail(
                            "REF-024",
                            CAT,
                            Severity::Info,
                            &format!(
                                "ApplicationOverride '{}' has same entityID as parent: {}",
                                override_id, eid
                            ),
                            Some("Remove redundant entityID from ApplicationOverride or use a different value"),
                        )
                        .with_doc(doc_for(DOC_ATTR_EXTRACTOR, v)),
                    );
                } else {
                    results.push(CheckResult::pass(
                        "REF-024",
                        CAT,
                        Severity::Info,
                        &format!(
                            "ApplicationOverride '{}' has distinct entityID",
                            override_id
                        ),
                    ));
                }
            }
        }
    }

    // REF-025: Invalid AttributeDecoder type in attribute-map.xml
    if let Some(ref map) = config.attribute_map {
        let known_decoders = [
            "StringAttributeDecoder",
            "ScopedAttributeDecoder",
            "NameIDAttributeDecoder",
            "NameIDFromScopedAttributeDecoder",
            "Base64AttributeDecoder",
            "XMLAttributeDecoder",
            "DOMAttributeDecoder",
            "KeyInfoAttributeDecoder",
            "DelegationAttributeDecoder",
        ];
        for attr in &map.attributes {
            if let Some(ref decoder) = attr.decoder_type {
                if known_decoders.contains(&decoder.as_str()) {
                    results.push(CheckResult::pass(
                        "REF-025",
                        CAT,
                        Severity::Warning,
                        &format!(
                            "AttributeDecoder type '{}' for '{}' is valid",
                            decoder, attr.id
                        ),
                    ));
                } else {
                    results.push(
                        CheckResult::fail(
                            "REF-025",
                            CAT,
                            Severity::Warning,
                            &format!(
                                "AttributeDecoder type '{}' for '{}' is not recognized",
                                decoder, attr.id
                            ),
                            Some("Check the AttributeDecoder xsi:type against Shibboleth SP3 documentation"),
                        )
                        .with_doc(doc_for(DOC_ATTR_EXTRACTOR, v)),
                    );
                }
            }
        }
    }

    // REF-026: Signature MetadataFilter has no certificate or TrustEngine
    for mp in &sc.metadata_providers {
        for filter in &mp.filters {
            if filter.filter_type.contains("Signature") {
                if filter.certificate.is_some() || filter.has_trust_engine {
                    results.push(CheckResult::pass(
                        "REF-026",
                        CAT,
                        Severity::Warning,
                        "Signature MetadataFilter has certificate or TrustEngine configured",
                    ));
                } else {
                    results.push(
                        CheckResult::fail(
                            "REF-026",
                            CAT,
                            Severity::Warning,
                            "Signature MetadataFilter has no certificate or TrustEngine",
                            Some("Add a certificate attribute or <TrustEngine> child to the Signature MetadataFilter"),
                        )
                        .with_doc(doc_for(DOC_METADATA_FILTER, v)),
                    );
                }
            }
        }
    }

    // REF-027: Chaining CredentialResolver has < 2 children
    for cr in &sc.credential_resolvers {
        if cr.resolver_type == "Chaining" {
            if cr.children_count >= 2 {
                results.push(CheckResult::pass(
                    "REF-027",
                    CAT,
                    Severity::Info,
                    &format!(
                        "Chaining CredentialResolver has {} children",
                        cr.children_count
                    ),
                ));
            } else {
                results.push(
                    CheckResult::fail(
                        "REF-027",
                        CAT,
                        Severity::Info,
                        &format!(
                            "Chaining CredentialResolver has only {} child(ren)",
                            cr.children_count
                        ),
                        Some("A Chaining CredentialResolver should have at least 2 children; otherwise use a single resolver"),
                    )
                    .with_doc(doc_for(DOC_CREDENTIAL_RESOLVER, v)),
                );
            }
        }
    }

    // REF-028: Deprecated eduPersonTargetedID OID mapping present
    if let Some(ref map) = config.attribute_map {
        let deprecated_oid = "urn:oid:1.3.6.1.4.1.5923.1.1.1.10";
        let mut found = false;
        for attr in &map.attributes {
            if attr.name == deprecated_oid {
                results.push(
                    CheckResult::fail(
                        "REF-028",
                        CAT,
                        Severity::Info,
                        &format!(
                            "Deprecated eduPersonTargetedID OID mapping present (id='{}')",
                            attr.id
                        ),
                        Some("eduPersonTargetedID is deprecated; consider using pairwise-id or subject-id instead"),
                    )
                    .with_doc(doc_for(DOC_ATTR_EXTRACTOR, v)),
                );
                found = true;
            }
        }
        if !found {
            results.push(CheckResult::pass(
                "REF-028",
                CAT,
                Severity::Info,
                "No deprecated eduPersonTargetedID OID mapping found",
            ));
        }
    }

    // REF-029: Policy rule for scoped attr uses ANY without scope validation
    if let (Some(ref map), Some(ref policy)) = (&config.attribute_map, &config.attribute_policy) {
        // Find attributes that use ScopedAttributeDecoder
        let scoped_attr_ids: std::collections::HashSet<&str> = map
            .attributes
            .iter()
            .filter(|a| {
                a.decoder_type
                    .as_deref()
                    .is_some_and(|d| d.contains("Scoped"))
            })
            .map(|a| a.id.as_str())
            .collect();

        for rule in &policy.rules {
            if scoped_attr_ids.contains(rule.attribute_id.as_str())
                && rule.permit_value_rule_type.as_deref() == Some("ANY")
                && !rule.has_scope_match
            {
                results.push(
                    CheckResult::fail(
                        "REF-029",
                        CAT,
                        Severity::Warning,
                        &format!(
                            "Policy rule for scoped attribute '{}' uses PermitValueRule type=ANY without scope validation",
                            rule.attribute_id
                        ),
                        Some("Use ScopeMatchesShibMDScope instead of ANY for scoped attributes to prevent scope spoofing"),
                    )
                    .with_doc(doc_for(DOC_ATTR_FILTER, v)),
                );
            }
        }
    }

    // REF-013: Error template file paths exist
    if let Some(ref errors) = sc.errors {
        let template_fields: &[(&str, &Option<String>)] = &[
            ("styleSheet", &errors.style_sheet),
            ("session", &errors.session_error),
            ("access", &errors.access_error),
            ("ssl", &errors.ssl_error),
            ("localLogout", &errors.local_logout),
            ("metadata", &errors.metadata_error),
            ("globalLogout", &errors.global_logout),
        ];
        for (attr_name, value) in template_fields {
            if let Some(ref path) = value {
                // Skip URLs
                if path.starts_with("http://") || path.starts_with("https://") {
                    continue;
                }
                let full_path = config.base_dir.join(path);
                if full_path.exists() {
                    results.push(CheckResult::pass(
                        "REF-013",
                        CAT,
                        Severity::Info,
                        &format!("Errors {} template exists: {}", attr_name, path),
                    ));
                } else {
                    results.push(CheckResult::fail(
                        "REF-013", CAT, Severity::Info,
                        &format!("Errors {} template not found: {}", attr_name, path),
                        Some("Ensure the error template file path is correct and the file exists"),
                    ).with_doc(doc_for(DOC_ERRORS, v)));
                }
            }
        }
    }

    results
}

fn metadata_contains_entity(full_path: &Path, entity_id: &str) -> bool {
    let content = match std::fs::read_to_string(full_path) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let mut reader = Reader::from_str(&content);
    loop {
        match reader.read_event() {
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                let full_name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                let local = full_name.rsplit(':').next().unwrap_or(&full_name);
                if local == "EntityDescriptor" {
                    if let Some(eid) = e.attributes().filter_map(|a| a.ok()).find_map(|a| {
                        let key = String::from_utf8_lossy(a.key.as_ref()).to_string();
                        let local_key = key.rsplit(':').next().unwrap_or(&key);
                        if local_key == "entityID" {
                            Some(String::from_utf8_lossy(&a.value).to_string())
                        } else {
                            None
                        }
                    }) {
                        if eid == entity_id {
                            return true;
                        }
                    }
                }
            }
            Err(_) => return false,
            _ => {}
        }
    }
    false
}

fn check_local_metadata_saml(
    full_path: &Path,
    display_path: &str,
    results: &mut Vec<CheckResult>,
    v: SpVersion,
) {
    let content = match std::fs::read_to_string(full_path) {
        Ok(c) => c,
        Err(_) => {
            results.push(
                CheckResult::fail(
                    "REF-010",
                    CAT,
                    Severity::Warning,
                    &format!("Could not read local metadata file: {}", display_path),
                    Some("Ensure the metadata file is readable"),
                )
                .with_doc(doc_for(DOC_METADATA_PROVIDER, v)),
            );
            return;
        }
    };

    let mut reader = Reader::from_str(&content);
    let mut root_element: Option<String> = None;

    loop {
        match reader.read_event() {
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) => {
                if root_element.is_none() {
                    let full_name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    let local = full_name
                        .rsplit(':')
                        .next()
                        .unwrap_or(&full_name)
                        .to_string();
                    root_element = Some(local);
                }
            }
            Err(_) => {
                results.push(
                    CheckResult::fail(
                        "REF-010",
                        CAT,
                        Severity::Warning,
                        &format!(
                            "Local metadata file is not well-formed XML: {}",
                            display_path
                        ),
                        Some("Fix XML syntax errors in the metadata file"),
                    )
                    .with_doc(doc_for(DOC_METADATA_PROVIDER, v)),
                );
                return;
            }
            _ => {}
        }
    }

    match root_element.as_deref() {
        Some("EntityDescriptor") | Some("EntitiesDescriptor") => {
            results.push(CheckResult::pass(
                "REF-010",
                CAT,
                Severity::Warning,
                &format!(
                    "Local metadata contains valid SAML root element: {}",
                    display_path
                ),
            ));
        }
        Some(other) => {
            results.push(
                CheckResult::fail(
                    "REF-010",
                    CAT,
                    Severity::Warning,
                    &format!(
                        "Local metadata has unexpected root element <{}>: {}",
                        other, display_path
                    ),
                    Some("Expected <EntityDescriptor> or <EntitiesDescriptor> as root element"),
                )
                .with_doc(doc_for(DOC_METADATA_PROVIDER, v)),
            );
        }
        None => {
            results.push(CheckResult::fail(
                "REF-010", CAT, Severity::Warning,
                &format!("Local metadata file is empty: {}", display_path),
                Some("The metadata file should contain a SAML EntityDescriptor or EntitiesDescriptor"),
            ).with_doc(doc_for(DOC_METADATA_PROVIDER, v)));
        }
    }
}

fn check_remote_metadata(url: &str, results: &mut Vec<CheckResult>, v: SpVersion) {
    let body = match ureq::get(url).call() {
        Ok(response) => match response.into_body().read_to_string() {
            Ok(body) => body,
            Err(e) => {
                results.push(
                    CheckResult::fail(
                        "REF-009",
                        CAT,
                        Severity::Error,
                        &format!("Failed to read response body from {}: {}", url, e),
                        Some("Ensure the remote metadata URL returns valid content"),
                    )
                    .with_doc(doc_for(DOC_METADATA_PROVIDER, v)),
                );
                return;
            }
        },
        Err(e) => {
            results.push(
                CheckResult::fail(
                    "REF-009",
                    CAT,
                    Severity::Error,
                    &format!("Remote metadata URL unreachable: {} ({})", url, e),
                    Some("Ensure the remote metadata URL is correct and the server is reachable"),
                )
                .with_doc(doc_for(DOC_METADATA_PROVIDER, v)),
            );
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
                    let local = full_name
                        .rsplit(':')
                        .next()
                        .unwrap_or(&full_name)
                        .to_string();
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
        results.push(
            CheckResult::fail(
                "REF-009",
                CAT,
                Severity::Warning,
                &format!("Remote metadata is not well-formed XML: {}", url),
                Some("The remote URL returned content that is not valid XML"),
            )
            .with_doc(doc_for(DOC_METADATA_PROVIDER, v)),
        );
        return;
    }

    // Check for SAML metadata root element
    match root_element.as_deref() {
        Some("EntityDescriptor") | Some("EntitiesDescriptor") => {
            results.push(CheckResult::pass(
                "REF-009",
                CAT,
                Severity::Error,
                &format!("Remote metadata is valid SAML metadata: {}", url),
            ));
        }
        Some(other) => {
            results.push(
                CheckResult::fail(
                    "REF-009",
                    CAT,
                    Severity::Warning,
                    &format!(
                        "Remote URL returned XML but not SAML metadata (root element: <{}>): {}",
                        other, url
                    ),
                    Some("Expected <EntityDescriptor> or <EntitiesDescriptor> as root element"),
                )
                .with_doc(doc_for(DOC_METADATA_PROVIDER, v)),
            );
        }
        None => {
            results.push(
                CheckResult::fail(
                    "REF-009",
                    CAT,
                    Severity::Warning,
                    &format!("Remote URL returned empty XML document: {}", url),
                    Some("The remote metadata URL returned an empty document"),
                )
                .with_doc(doc_for(DOC_METADATA_PROVIDER, v)),
            );
        }
    }
}
