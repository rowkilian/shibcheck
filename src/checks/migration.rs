use crate::config::DiscoveredConfig;
use crate::model::shibboleth_config::SpVersion;
use crate::result::{CheckCategory, CheckResult, Severity};

const CAT: CheckCategory = CheckCategory::Migration;
const DOC_UPGRADE: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065335062/Upgrading";

/// Run migration checks. MIG-001..010 only fire for V2 configs.
/// MIG-011..016 fire on both V2 and V3 configs.
pub fn run(config: &DiscoveredConfig) -> Vec<CheckResult> {
    let mut results = Vec::new();

    let sc = match config.shibboleth_config.as_ref() {
        Some(sc) => sc,
        _ => return results,
    };

    // ── V2-only checks ──
    if sc.sp_version == SpVersion::V2 {
        // MIG-001: SP2 detected — upgrade recommended
        results.push(
            CheckResult::fail(
                "MIG-001",
                CAT,
                Severity::Warning,
                "Shibboleth SP2 configuration detected — upgrade to SP3 recommended",
                Some("SP2 is end-of-life. See the SP3 upgrade guide for migration steps."),
            )
            .with_doc(DOC_UPGRADE),
        );

        // MIG-002: SP2 uses <SessionInitiator> instead of SP3 <SSO>
        if let Some(ref sessions) = sc.sessions {
            if sessions.has_session_initiator && !sessions.has_sso {
                results.push(
                    CheckResult::fail(
                        "MIG-002",
                        CAT,
                        Severity::Info,
                        "SP2-style <SessionInitiator> found; SP3 uses the simpler <SSO> element",
                        Some(
                            "Replace <SessionInitiator> with <SSO entityID=\"...\">SAML2</SSO> in SP3",
                        ),
                    )
                    .with_doc(DOC_UPGRADE),
                );
            } else {
                results.push(CheckResult::pass(
                    "MIG-002",
                    CAT,
                    Severity::Info,
                    "SSO configuration is SP3-compatible",
                ));
            }
        }

        // MIG-003: SP2 uses <LogoutInitiator> instead of SP3 <Logout>
        if let Some(ref sessions) = sc.sessions {
            if sessions.has_logout {
                results.push(
                    CheckResult::fail(
                        "MIG-003",
                        CAT,
                        Severity::Info,
                        "SP2-style logout configuration found; SP3 uses <Logout> element",
                        Some("Replace <LogoutInitiator> with <Logout>SAML2 Local</Logout> in SP3"),
                    )
                    .with_doc(DOC_UPGRADE),
                );
            } else {
                results.push(CheckResult::pass(
                    "MIG-003",
                    CAT,
                    Severity::Info,
                    "No SP2-style logout configuration to migrate",
                ));
            }
        }

        // MIG-004: Check for SP2 xmlns namespace
        if sc.has_sp_config {
            results.push(
                CheckResult::fail(
                    "MIG-004",
                    CAT,
                    Severity::Warning,
                    "SPConfig uses SP2 namespace URI",
                    Some("Update xmlns to \"urn:mace:shibboleth:3.0:native:sp:config\" for SP3"),
                )
                .with_doc(DOC_UPGRADE),
            );
        }

        // MIG-006: MetadataProvider uses deprecated file/uri attrs
        for mp in &sc.metadata_providers {
            if mp.file_attr.is_some() {
                results.push(
                    CheckResult::fail(
                        "MIG-006",
                        CAT,
                        Severity::Warning,
                        "MetadataProvider uses deprecated 'file' attribute",
                        Some("Replace 'file' with 'path' attribute in SP3"),
                    )
                    .with_doc(DOC_UPGRADE),
                );
            }
        }

        // MIG-007: attribute-policy.xml uses deprecated basic:/saml: namespace
        {
            let policy_path = config.base_dir.join("attribute-policy.xml");
            if policy_path.exists() {
                if let Ok(content) = std::fs::read_to_string(&policy_path) {
                    if content.contains("urn:mace:shibboleth:2.0:afp:mf:basic")
                        || content.contains("urn:mace:shibboleth:2.0:afp:mf:saml")
                    {
                        results.push(
                            CheckResult::fail(
                                "MIG-007",
                                CAT,
                                Severity::Info,
                                "attribute-policy.xml uses deprecated SP2 namespace (basic:/saml:)",
                                Some("Update to SP3 namespace URIs in attribute-policy.xml"),
                            )
                            .with_doc(DOC_UPGRADE),
                        );
                    } else {
                        results.push(CheckResult::pass(
                            "MIG-007",
                            CAT,
                            Severity::Info,
                            "attribute-policy.xml does not use deprecated SP2 namespaces",
                        ));
                    }
                }
            }
        }

        // MIG-008: redirectWhitelist present (renamed to redirectAllow in SP3)
        if let Some(ref sessions) = sc.sessions {
            if sessions.redirect_whitelist.is_some() {
                results.push(
                    CheckResult::fail(
                        "MIG-008",
                        CAT,
                        Severity::Info,
                        "Sessions uses deprecated 'redirectWhitelist' attribute",
                        Some("Rename 'redirectWhitelist' to 'redirectAllow' for SP3"),
                    )
                    .with_doc(DOC_UPGRADE),
                );
            } else {
                results.push(CheckResult::pass(
                    "MIG-008",
                    CAT,
                    Severity::Info,
                    "No deprecated redirectWhitelist attribute found",
                ));
            }
        }

        // MIG-009: AttributeResolver type=Query subjectMatch detected
        if let Some(ref content) = config.shibboleth_xml_content {
            if content.contains("AttributeResolver") && content.contains("subjectMatch") {
                results.push(
                    CheckResult::fail(
                        "MIG-009",
                        CAT,
                        Severity::Info,
                        "AttributeResolver with subjectMatch detected (SP2 pattern)",
                        Some("Review AttributeResolver configuration for SP3 compatibility"),
                    )
                    .with_doc(DOC_UPGRADE),
                );
            } else {
                results.push(CheckResult::pass(
                    "MIG-009",
                    CAT,
                    Severity::Info,
                    "No SP2-style AttributeResolver subjectMatch found",
                ));
            }
        }

        // MIG-010: MetadataProvider uses deprecated Provider attribute
        if let Some(ref content) = config.shibboleth_xml_content {
            if content.contains("MetadataProvider") && content.contains("Provider=") {
                results.push(
                    CheckResult::fail(
                        "MIG-010",
                        CAT,
                        Severity::Warning,
                        "MetadataProvider uses deprecated 'Provider' attribute",
                        Some("Replace 'Provider' with 'type' attribute in SP3"),
                    )
                    .with_doc(DOC_UPGRADE),
                );
            } else {
                results.push(CheckResult::pass(
                    "MIG-010",
                    CAT,
                    Severity::Warning,
                    "No deprecated MetadataProvider 'Provider' attribute found",
                ));
            }
        }

        // MIG-005: Check for signing/encryption attributes (SP3 defaults differ)
        if let Some(ref app) = sc.application_defaults {
            if app.signing.is_none() && app.encryption.is_none() {
                results.push(
                    CheckResult::fail(
                        "MIG-005",
                        CAT,
                        Severity::Info,
                        "No signing/encryption attributes set — SP3 defaults may differ from SP2",
                        Some("Explicitly set signing=\"true\" and encryption=\"true\" on ApplicationDefaults for SP3"),
                    )
                    .with_doc(DOC_UPGRADE),
                );
            } else {
                results.push(CheckResult::pass(
                    "MIG-005",
                    CAT,
                    Severity::Info,
                    "Signing/encryption attributes explicitly configured",
                ));
            }
        }
    }

    // ── V2+V3 checks ──

    // MIG-011: Deprecated EntityRoleWhiteList filter type → use EntityRole
    {
        let mut found = false;
        for mp in &sc.metadata_providers {
            for filter in &mp.filters {
                if filter.filter_type == "EntityRoleWhiteList" {
                    results.push(
                        CheckResult::fail(
                            "MIG-011",
                            CAT,
                            Severity::Warning,
                            "MetadataFilter type 'EntityRoleWhiteList' is deprecated",
                            Some("Rename to type=\"EntityRole\" (SP 3.1+)"),
                        )
                        .with_doc(DOC_UPGRADE),
                    );
                    found = true;
                }
            }
        }
        if !found {
            let has_filters = sc
                .metadata_providers
                .iter()
                .any(|mp| !mp.filters.is_empty());
            if has_filters {
                results.push(CheckResult::pass(
                    "MIG-011",
                    CAT,
                    Severity::Warning,
                    "No deprecated EntityRoleWhiteList filter type found",
                ));
            }
        }
    }

    // MIG-012: Deprecated Whitelist/Blacklist filter types → use Include/Exclude
    {
        let mut found = false;
        for mp in &sc.metadata_providers {
            for filter in &mp.filters {
                if filter.filter_type == "Whitelist" || filter.filter_type == "Blacklist" {
                    let replacement = if filter.filter_type == "Whitelist" {
                        "Include"
                    } else {
                        "Exclude"
                    };
                    results.push(
                        CheckResult::fail(
                            "MIG-012",
                            CAT,
                            Severity::Warning,
                            &format!("MetadataFilter type '{}' is deprecated", filter.filter_type),
                            Some(&format!("Rename to type=\"{}\" (SP 3.1+)", replacement)),
                        )
                        .with_doc(DOC_UPGRADE),
                    );
                    found = true;
                }
            }
        }
        if !found {
            let has_filters = sc
                .metadata_providers
                .iter()
                .any(|mp| !mp.filters.is_empty());
            if has_filters {
                results.push(CheckResult::pass(
                    "MIG-012",
                    CAT,
                    Severity::Warning,
                    "No deprecated Whitelist/Blacklist filter types found",
                ));
            }
        }
    }

    // MIG-013: uri attribute on MetadataProvider → use url
    {
        let mut found = false;
        for mp in &sc.metadata_providers {
            if mp.uri.is_some() {
                results.push(
                    CheckResult::fail(
                        "MIG-013",
                        CAT,
                        Severity::Info,
                        &format!(
                            "MetadataProvider type='{}' uses deprecated 'uri' attribute",
                            mp.provider_type
                        ),
                        Some("Rename 'uri' to 'url' for SP3 compatibility"),
                    )
                    .with_doc(DOC_UPGRADE),
                );
                found = true;
            }
        }
        if !found {
            let has_remote = sc.metadata_providers.iter().any(|mp| mp.url.is_some());
            if has_remote {
                results.push(CheckResult::pass(
                    "MIG-013",
                    CAT,
                    Severity::Info,
                    "No MetadataProvider uses deprecated 'uri' attribute",
                ));
            }
        }
    }

    // MIG-014: SP3 config uses deprecated constructs (combination check)
    {
        let mut deprecated_count = 0;
        // Check for deprecated filter types
        for mp in &sc.metadata_providers {
            for filter in &mp.filters {
                if filter.filter_type == "EntityRoleWhiteList"
                    || filter.filter_type == "Whitelist"
                    || filter.filter_type == "Blacklist"
                {
                    deprecated_count += 1;
                }
            }
            if mp.uri.is_some() {
                deprecated_count += 1;
            }
        }
        if let Some(ref sessions) = sc.sessions {
            if sessions.redirect_whitelist.is_some() {
                deprecated_count += 1;
            }
            if sessions.check_address.is_some() {
                deprecated_count += 1;
            }
        }

        if deprecated_count > 0 {
            results.push(
                CheckResult::fail(
                    "MIG-014",
                    CAT,
                    Severity::Info,
                    &format!(
                        "Configuration contains {} deprecated construct(s) (SP 3.3+ will warn)",
                        deprecated_count
                    ),
                    Some("Review and update deprecated attributes and filter types"),
                )
                .with_doc(DOC_UPGRADE),
            );
        } else {
            results.push(CheckResult::pass(
                "MIG-014",
                CAT,
                Severity::Info,
                "No deprecated SP3 constructs detected",
            ));
        }
    }

    // MIG-015: checkAddress used instead of SP3 consistentAddress
    if let Some(ref sessions) = sc.sessions {
        if sessions.check_address.is_some() {
            results.push(
                CheckResult::fail(
                    "MIG-015",
                    CAT,
                    Severity::Info,
                    "Sessions uses deprecated 'checkAddress' attribute",
                    Some("Replace 'checkAddress' with 'consistentAddress' for SP3"),
                )
                .with_doc(DOC_UPGRADE),
            );
        } else {
            results.push(CheckResult::pass(
                "MIG-015",
                CAT,
                Severity::Info,
                "No deprecated checkAddress attribute found",
            ));
        }
    }

    // MIG-016: Leftover SP2 explicit handler declarations in V3 config
    if sc.sp_version == SpVersion::V3 {
        if let Some(ref content) = config.shibboleth_xml_content {
            // Look for SP2-style explicit handler types that V3 auto-registers
            let sp2_handlers = [
                "ArtifactResolutionService",
                "AssertionConsumerService",
                "SingleLogoutService",
            ];
            let mut found_legacy = Vec::new();
            for handler in &sp2_handlers {
                if content.contains(handler) {
                    found_legacy.push(*handler);
                }
            }
            if !found_legacy.is_empty() {
                results.push(
                    CheckResult::fail(
                        "MIG-016",
                        CAT,
                        Severity::Info,
                        &format!(
                            "SP3 config has leftover SP2 handler declarations: {}",
                            found_legacy.join(", ")
                        ),
                        Some("SP3 auto-registers these handlers; explicit declarations can be removed"),
                    )
                    .with_doc(DOC_UPGRADE),
                );
            } else {
                results.push(CheckResult::pass(
                    "MIG-016",
                    CAT,
                    Severity::Info,
                    "No leftover SP2 handler declarations in SP3 config",
                ));
            }
        }
    }

    // MIG-017: MetadataGenerator handler present (disabled by default in SP 3.4+)
    if sc.sp_version == SpVersion::V3 {
        let has_metadata_gen = sc
            .handlers
            .iter()
            .any(|h| h.handler_type.contains("MetadataGenerator"));
        if has_metadata_gen {
            results.push(
                CheckResult::fail(
                    "MIG-017",
                    CAT,
                    Severity::Info,
                    "MetadataGenerator handler present (disabled by default in SP 3.4+)",
                    Some("MetadataGenerator is disabled by default in SP 3.4+; consider removing if not needed"),
                )
                .with_doc(DOC_UPGRADE),
            );
        } else {
            results.push(CheckResult::pass(
                "MIG-017",
                CAT,
                Severity::Info,
                "No MetadataGenerator handler (consistent with SP 3.4+ defaults)",
            ));
        }
    }

    // MIG-018: redirectLimit="whitelist" deprecated value (use "allow" in SP 3.3+)
    if let Some(ref sessions) = sc.sessions {
        if let Some(ref limit) = sessions.redirect_limit {
            if limit == "whitelist" {
                results.push(
                    CheckResult::fail(
                        "MIG-018",
                        CAT,
                        Severity::Warning,
                        "redirectLimit=\"whitelist\" is a deprecated value",
                        Some("Use redirectLimit=\"allow\" instead (SP 3.3+)"),
                    )
                    .with_doc(DOC_UPGRADE),
                );
            } else {
                results.push(CheckResult::pass(
                    "MIG-018",
                    CAT,
                    Severity::Warning,
                    &format!("redirectLimit value '{}' is not deprecated", limit),
                ));
            }
        }
    }

    // MIG-019: SSO discoveryProtocol="WAYF" deprecated (use SAMLDS)
    if let Some(ref sessions) = sc.sessions {
        if let Some(ref proto) = sessions.sso_discovery_protocol {
            if proto.contains("WAYF") {
                results.push(
                    CheckResult::fail(
                        "MIG-019",
                        CAT,
                        Severity::Warning,
                        &format!("SSO discoveryProtocol '{}' is deprecated", proto),
                        Some("Use discoveryProtocol=\"SAMLDS\" instead of WAYF"),
                    )
                    .with_doc(DOC_UPGRADE),
                );
            } else {
                results.push(CheckResult::pass(
                    "MIG-019",
                    CAT,
                    Severity::Warning,
                    &format!("SSO discoveryProtocol '{}' is not deprecated", proto),
                ));
            }
        }
    }

    // MIG-020: MetadataProvider legacyOrgNames="true" deprecated
    if let Some(ref content) = config.shibboleth_xml_content {
        if content.contains("legacyOrgNames=\"true\"") {
            results.push(
                CheckResult::fail(
                    "MIG-020",
                    CAT,
                    Severity::Warning,
                    "MetadataProvider legacyOrgNames=\"true\" is deprecated",
                    Some("Remove legacyOrgNames=\"true\" — legacy organization name handling is no longer recommended"),
                )
                .with_doc(DOC_UPGRADE),
            );
        } else {
            results.push(CheckResult::pass(
                "MIG-020",
                CAT,
                Severity::Warning,
                "No deprecated legacyOrgNames attribute found",
            ));
        }
    }

    // MIG-021: attribute-map.xml aliases attribute deprecated
    {
        let attr_map_path = config.base_dir.join("attribute-map.xml");
        if attr_map_path.exists() {
            if let Ok(content) = std::fs::read_to_string(&attr_map_path) {
                if content.contains("aliases=") {
                    results.push(
                        CheckResult::fail(
                            "MIG-021",
                            CAT,
                            Severity::Info,
                            "attribute-map.xml uses deprecated 'aliases' attribute",
                            Some(
                                "Replace aliases with separate <Attribute> elements for each name",
                            ),
                        )
                        .with_doc(DOC_UPGRADE),
                    );
                } else {
                    results.push(CheckResult::pass(
                        "MIG-021",
                        CAT,
                        Severity::Info,
                        "attribute-map.xml does not use deprecated aliases attribute",
                    ));
                }
            }
        }
    }

    // MIG-022: SessionInitiator type="Shib1" or type="WAYF" (legacy)
    for si in &sc.session_initiators {
        if let Some(ref t) = si.initiator_type {
            if t == "Shib1" || t == "WAYF" {
                results.push(
                    CheckResult::fail(
                        "MIG-022",
                        CAT,
                        Severity::Warning,
                        &format!(
                            "SessionInitiator type=\"{}\" is a legacy protocol{}",
                            t,
                            si.id
                                .as_ref()
                                .map(|id| format!(" (id=\"{}\")", id))
                                .unwrap_or_default()
                        ),
                        Some("Replace with type=\"SAML2\" for modern SAML 2.0 authentication"),
                    )
                    .with_doc(DOC_UPGRADE),
                );
            }
        }
    }

    // MIG-023: SSO defaultACSIndex/acsIndex explicitly set (deprecated in SP3)
    if let Some(ref content) = config.shibboleth_xml_content {
        if content.contains("defaultACSIndex") || content.contains("acsIndex") {
            results.push(
                CheckResult::fail(
                    "MIG-023",
                    CAT,
                    Severity::Info,
                    "SSO uses deprecated defaultACSIndex or acsIndex attribute",
                    Some("Remove defaultACSIndex/acsIndex — SP3 manages ACS index automatically"),
                )
                .with_doc(DOC_UPGRADE),
            );
        } else {
            results.push(CheckResult::pass(
                "MIG-023",
                CAT,
                Severity::Info,
                "No deprecated ACS index attributes found",
            ));
        }
    }

    // MIG-024: ApplicationOverride <Sessions> missing handlerSSL/cookieProps (not inherited)
    if let Some(ref content) = config.shibboleth_xml_content {
        // Simple scan: find <Sessions inside ApplicationOverride blocks
        let mut in_override = false;
        let mut found_issue = false;
        let mut sessions_buf = String::new();
        let mut collecting_sessions = false;

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.contains("<ApplicationOverride") {
                in_override = true;
            }
            if in_override && trimmed.contains("<Sessions") {
                collecting_sessions = true;
                sessions_buf.clear();
            }
            if collecting_sessions {
                sessions_buf.push_str(trimmed);
                sessions_buf.push(' ');
                // Check if tag is closed (self-closing or opening tag end)
                if trimmed.contains("/>") || trimmed.contains(">") {
                    let missing_handler_ssl = !sessions_buf.contains("handlerSSL");
                    let missing_cookie_props = !sessions_buf.contains("cookieProps");
                    if missing_handler_ssl || missing_cookie_props {
                        let mut missing = Vec::new();
                        if missing_handler_ssl {
                            missing.push("handlerSSL");
                        }
                        if missing_cookie_props {
                            missing.push("cookieProps");
                        }
                        results.push(
                            CheckResult::fail(
                                "MIG-024",
                                CAT,
                                Severity::Warning,
                                &format!(
                                    "ApplicationOverride <Sessions> missing {} (NOT inherited from ApplicationDefaults)",
                                    missing.join(", ")
                                ),
                                Some("Add handlerSSL and cookieProps to <Sessions> inside <ApplicationOverride> — they are not inherited"),
                            )
                            .with_doc(DOC_UPGRADE),
                        );
                        found_issue = true;
                    }
                    collecting_sessions = false;
                }
            }
            if trimmed.contains("</ApplicationOverride") {
                in_override = false;
            }
        }
        if !found_issue && !sc.application_override_ids.is_empty() {
            results.push(CheckResult::pass(
                "MIG-024",
                CAT,
                Severity::Warning,
                "ApplicationOverride Sessions elements have required attributes",
            ));
        }
    }

    results
}
