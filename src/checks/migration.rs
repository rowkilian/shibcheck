use crate::config::DiscoveredConfig;
use crate::model::shibboleth_config::{ShibbolethConfig, SpVersion};
use crate::result::{CheckCategory, CheckResult, Severity};

const CAT: CheckCategory = CheckCategory::Migration;
const DOC_UPGRADE: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065335062/Upgrading";

/// Each registered migration check receives the discovered config plus the parsed
/// `ShibbolethConfig` and returns zero or more `CheckResult`s.
type CheckFn = fn(&DiscoveredConfig, &ShibbolethConfig) -> Vec<CheckResult>;

/// Ordered registry of migration checks. Adding a new check is one entry here
/// plus a matching function below.
const REGISTRY: &[(&str, CheckFn)] = &[
    ("MIG-001", mig_001),
    ("MIG-002", mig_002),
    ("MIG-003", mig_003),
    ("MIG-004", mig_004),
    ("MIG-005", mig_005),
    ("MIG-006", mig_006),
    ("MIG-007", mig_007),
    ("MIG-008", mig_008),
    ("MIG-009", mig_009),
    ("MIG-010", mig_010),
    ("MIG-011", mig_011),
    ("MIG-012", mig_012),
    ("MIG-013", mig_013),
    ("MIG-014", mig_014),
    ("MIG-015", mig_015),
    ("MIG-016", mig_016),
    ("MIG-017", mig_017),
    ("MIG-018", mig_018),
    ("MIG-019", mig_019),
    ("MIG-020", mig_020),
    ("MIG-021", mig_021),
    ("MIG-022", mig_022),
    ("MIG-023", mig_023),
    ("MIG-024", mig_024),
];

pub fn run(config: &DiscoveredConfig) -> Vec<CheckResult> {
    let sc = match config.shibboleth_config.as_ref() {
        Some(sc) => sc,
        _ => return Vec::new(),
    };
    let mut out = Vec::new();
    for (_, check) in REGISTRY {
        out.extend(check(config, sc));
    }
    out
}

fn fail(code: &str, sev: Severity, msg: &str, suggestion: &str) -> CheckResult {
    CheckResult::fail(code, CAT, sev, msg, Some(suggestion)).with_doc(DOC_UPGRADE)
}

fn pass(code: &str, sev: Severity, msg: &str) -> CheckResult {
    CheckResult::pass(code, CAT, sev, msg)
}

// ── V2-only checks (MIG-001..MIG-010) ──

fn mig_001(_config: &DiscoveredConfig, sc: &ShibbolethConfig) -> Vec<CheckResult> {
    if sc.sp_version != SpVersion::V2 {
        return Vec::new();
    }
    vec![fail(
        "MIG-001",
        Severity::Warning,
        "Shibboleth SP2 configuration detected — upgrade to SP3 recommended",
        "SP2 is end-of-life. See the SP3 upgrade guide for migration steps.",
    )]
}

fn mig_002(_config: &DiscoveredConfig, sc: &ShibbolethConfig) -> Vec<CheckResult> {
    if sc.sp_version != SpVersion::V2 {
        return Vec::new();
    }
    let Some(sessions) = sc.sessions.as_ref() else {
        return Vec::new();
    };
    if sessions.has_session_initiator && !sessions.has_sso {
        vec![fail(
            "MIG-002",
            Severity::Info,
            "SP2-style <SessionInitiator> found; SP3 uses the simpler <SSO> element",
            "Replace <SessionInitiator> with <SSO entityID=\"...\">SAML2</SSO> in SP3",
        )]
    } else {
        vec![pass(
            "MIG-002",
            Severity::Info,
            "SSO configuration is SP3-compatible",
        )]
    }
}

fn mig_003(_config: &DiscoveredConfig, sc: &ShibbolethConfig) -> Vec<CheckResult> {
    if sc.sp_version != SpVersion::V2 {
        return Vec::new();
    }
    let Some(sessions) = sc.sessions.as_ref() else {
        return Vec::new();
    };
    if sessions.has_logout {
        vec![fail(
            "MIG-003",
            Severity::Info,
            "SP2-style logout configuration found; SP3 uses <Logout> element",
            "Replace <LogoutInitiator> with <Logout>SAML2 Local</Logout> in SP3",
        )]
    } else {
        vec![pass(
            "MIG-003",
            Severity::Info,
            "No SP2-style logout configuration to migrate",
        )]
    }
}

fn mig_004(_config: &DiscoveredConfig, sc: &ShibbolethConfig) -> Vec<CheckResult> {
    if sc.sp_version != SpVersion::V2 || !sc.has_sp_config {
        return Vec::new();
    }
    vec![fail(
        "MIG-004",
        Severity::Warning,
        "SPConfig uses SP2 namespace URI",
        "Update xmlns to \"urn:mace:shibboleth:3.0:native:sp:config\" for SP3",
    )]
}

fn mig_005(_config: &DiscoveredConfig, sc: &ShibbolethConfig) -> Vec<CheckResult> {
    if sc.sp_version != SpVersion::V2 {
        return Vec::new();
    }
    let Some(app) = sc.application_defaults.as_ref() else {
        return Vec::new();
    };
    if app.signing.is_none() && app.encryption.is_none() {
        vec![fail(
            "MIG-005",
            Severity::Info,
            "No signing/encryption attributes set — SP3 defaults may differ from SP2",
            "Explicitly set signing=\"true\" and encryption=\"true\" on ApplicationDefaults for SP3",
        )]
    } else {
        vec![pass(
            "MIG-005",
            Severity::Info,
            "Signing/encryption attributes explicitly configured",
        )]
    }
}

fn mig_006(_config: &DiscoveredConfig, sc: &ShibbolethConfig) -> Vec<CheckResult> {
    if sc.sp_version != SpVersion::V2 {
        return Vec::new();
    }
    let mut results = Vec::new();
    for mp in &sc.metadata_providers {
        if mp.file_attr.is_some() {
            results.push(fail(
                "MIG-006",
                Severity::Warning,
                &format!(
                    "MetadataProvider{} uses deprecated 'file' attribute",
                    mp.label()
                ),
                "Replace 'file' with 'path' attribute in SP3",
            ));
        }
    }
    results
}

fn mig_007(config: &DiscoveredConfig, sc: &ShibbolethConfig) -> Vec<CheckResult> {
    if sc.sp_version != SpVersion::V2 {
        return Vec::new();
    }
    let policy_path = config.base_dir.join("attribute-policy.xml");
    if !policy_path.exists() {
        return Vec::new();
    }
    let content = match std::fs::read_to_string(&policy_path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    if content.contains("urn:mace:shibboleth:2.0:afp:mf:basic")
        || content.contains("urn:mace:shibboleth:2.0:afp:mf:saml")
    {
        vec![fail(
            "MIG-007",
            Severity::Info,
            "attribute-policy.xml uses deprecated SP2 namespace (basic:/saml:)",
            "Update to SP3 namespace URIs in attribute-policy.xml",
        )]
    } else {
        vec![pass(
            "MIG-007",
            Severity::Info,
            "attribute-policy.xml does not use deprecated SP2 namespaces",
        )]
    }
}

fn mig_008(_config: &DiscoveredConfig, sc: &ShibbolethConfig) -> Vec<CheckResult> {
    if sc.sp_version != SpVersion::V2 {
        return Vec::new();
    }
    let Some(sessions) = sc.sessions.as_ref() else {
        return Vec::new();
    };
    if sessions.redirect_whitelist.is_some() {
        vec![fail(
            "MIG-008",
            Severity::Info,
            "Sessions uses deprecated 'redirectWhitelist' attribute",
            "Rename 'redirectWhitelist' to 'redirectAllow' for SP3",
        )]
    } else {
        vec![pass(
            "MIG-008",
            Severity::Info,
            "No deprecated redirectWhitelist attribute found",
        )]
    }
}

fn mig_009(config: &DiscoveredConfig, sc: &ShibbolethConfig) -> Vec<CheckResult> {
    if sc.sp_version != SpVersion::V2 {
        return Vec::new();
    }
    let Some(content) = config.shibboleth_xml_content.as_ref() else {
        return Vec::new();
    };
    if content.contains("AttributeResolver") && content.contains("subjectMatch") {
        vec![fail(
            "MIG-009",
            Severity::Info,
            "AttributeResolver with subjectMatch detected (SP2 pattern)",
            "Review AttributeResolver configuration for SP3 compatibility",
        )]
    } else {
        vec![pass(
            "MIG-009",
            Severity::Info,
            "No SP2-style AttributeResolver subjectMatch found",
        )]
    }
}

fn mig_010(config: &DiscoveredConfig, sc: &ShibbolethConfig) -> Vec<CheckResult> {
    if sc.sp_version != SpVersion::V2 {
        return Vec::new();
    }
    let Some(content) = config.shibboleth_xml_content.as_ref() else {
        return Vec::new();
    };
    if content.contains("MetadataProvider") && content.contains("Provider=") {
        vec![fail(
            "MIG-010",
            Severity::Warning,
            "MetadataProvider uses deprecated 'Provider' attribute",
            "Replace 'Provider' with 'type' attribute in SP3",
        )]
    } else {
        vec![pass(
            "MIG-010",
            Severity::Warning,
            "No deprecated MetadataProvider 'Provider' attribute found",
        )]
    }
}

// ── V2+V3 checks (MIG-011..MIG-024) ──

fn mig_011(_config: &DiscoveredConfig, sc: &ShibbolethConfig) -> Vec<CheckResult> {
    let mut results = Vec::new();
    let mut found = false;
    for mp in &sc.metadata_providers {
        for filter in &mp.filters {
            if filter.filter_type == "EntityRoleWhiteList" {
                results.push(fail(
                    "MIG-011",
                    Severity::Warning,
                    &format!(
                        "MetadataFilter type 'EntityRoleWhiteList' is deprecated in MetadataProvider{}",
                        mp.label()
                    ),
                    "Rename to type=\"EntityRole\" (SP 3.1+)",
                ));
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
            results.push(pass(
                "MIG-011",
                Severity::Warning,
                "No deprecated EntityRoleWhiteList filter type found",
            ));
        }
    }
    results
}

fn mig_012(_config: &DiscoveredConfig, sc: &ShibbolethConfig) -> Vec<CheckResult> {
    let mut results = Vec::new();
    let mut found = false;
    for mp in &sc.metadata_providers {
        for filter in &mp.filters {
            if filter.filter_type == "Whitelist" || filter.filter_type == "Blacklist" {
                let replacement = if filter.filter_type == "Whitelist" {
                    "Include"
                } else {
                    "Exclude"
                };
                results.push(fail(
                    "MIG-012",
                    Severity::Warning,
                    &format!(
                        "MetadataFilter type '{}' is deprecated in MetadataProvider{}",
                        filter.filter_type,
                        mp.label()
                    ),
                    &format!("Rename to type=\"{}\" (SP 3.1+)", replacement),
                ));
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
            results.push(pass(
                "MIG-012",
                Severity::Warning,
                "No deprecated Whitelist/Blacklist filter types found",
            ));
        }
    }
    results
}

fn mig_013(_config: &DiscoveredConfig, sc: &ShibbolethConfig) -> Vec<CheckResult> {
    let mut results = Vec::new();
    let mut found = false;
    for mp in &sc.metadata_providers {
        if mp.uri.is_some() {
            results.push(fail(
                "MIG-013",
                Severity::Info,
                &format!(
                    "MetadataProvider type='{}'{} uses deprecated 'uri' attribute",
                    mp.provider_type,
                    mp.label()
                ),
                "Rename 'uri' to 'url' for SP3 compatibility",
            ));
            found = true;
        }
    }
    if !found {
        let has_remote = sc.metadata_providers.iter().any(|mp| mp.url.is_some());
        if has_remote {
            results.push(pass(
                "MIG-013",
                Severity::Info,
                "No MetadataProvider uses deprecated 'uri' attribute",
            ));
        }
    }
    results
}

fn mig_014(_config: &DiscoveredConfig, sc: &ShibbolethConfig) -> Vec<CheckResult> {
    let mut deprecated_count = 0;
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
    if let Some(sessions) = sc.sessions.as_ref() {
        if sessions.redirect_whitelist.is_some() {
            deprecated_count += 1;
        }
        if sessions.check_address.is_some() {
            deprecated_count += 1;
        }
    }

    if deprecated_count > 0 {
        vec![fail(
            "MIG-014",
            Severity::Info,
            &format!(
                "Configuration contains {} deprecated construct(s) (SP 3.3+ will warn)",
                deprecated_count
            ),
            "Review and update deprecated attributes and filter types",
        )]
    } else {
        vec![pass(
            "MIG-014",
            Severity::Info,
            "No deprecated SP3 constructs detected",
        )]
    }
}

fn mig_015(_config: &DiscoveredConfig, sc: &ShibbolethConfig) -> Vec<CheckResult> {
    let Some(sessions) = sc.sessions.as_ref() else {
        return Vec::new();
    };
    if sessions.check_address.is_some() {
        vec![fail(
            "MIG-015",
            Severity::Info,
            "Sessions uses deprecated 'checkAddress' attribute",
            "Replace 'checkAddress' with 'consistentAddress' for SP3",
        )]
    } else {
        vec![pass(
            "MIG-015",
            Severity::Info,
            "No deprecated checkAddress attribute found",
        )]
    }
}

fn mig_016(config: &DiscoveredConfig, sc: &ShibbolethConfig) -> Vec<CheckResult> {
    if sc.sp_version != SpVersion::V3 {
        return Vec::new();
    }
    let Some(content) = config.shibboleth_xml_content.as_ref() else {
        return Vec::new();
    };
    let sp2_handlers = [
        "ArtifactResolutionService",
        "AssertionConsumerService",
        "SingleLogoutService",
    ];
    let found_legacy: Vec<&str> = sp2_handlers
        .iter()
        .filter(|h| content.contains(**h))
        .copied()
        .collect();
    if !found_legacy.is_empty() {
        vec![fail(
            "MIG-016",
            Severity::Info,
            &format!(
                "SP3 config has leftover SP2 handler declarations: {}",
                found_legacy.join(", ")
            ),
            "SP3 auto-registers these handlers; explicit declarations can be removed",
        )]
    } else {
        vec![pass(
            "MIG-016",
            Severity::Info,
            "No leftover SP2 handler declarations in SP3 config",
        )]
    }
}

fn mig_017(_config: &DiscoveredConfig, sc: &ShibbolethConfig) -> Vec<CheckResult> {
    if sc.sp_version != SpVersion::V3 {
        return Vec::new();
    }
    let has_metadata_gen = sc
        .handlers
        .iter()
        .any(|h| h.handler_type.contains("MetadataGenerator"));
    if has_metadata_gen {
        vec![fail(
            "MIG-017",
            Severity::Info,
            "MetadataGenerator handler present (disabled by default in SP 3.4+)",
            "MetadataGenerator is disabled by default in SP 3.4+; consider removing if not needed",
        )]
    } else {
        vec![pass(
            "MIG-017",
            Severity::Info,
            "No MetadataGenerator handler (consistent with SP 3.4+ defaults)",
        )]
    }
}

fn mig_018(_config: &DiscoveredConfig, sc: &ShibbolethConfig) -> Vec<CheckResult> {
    let Some(sessions) = sc.sessions.as_ref() else {
        return Vec::new();
    };
    let Some(limit) = sessions.redirect_limit.as_ref() else {
        return Vec::new();
    };
    if limit == "whitelist" {
        vec![fail(
            "MIG-018",
            Severity::Warning,
            "redirectLimit=\"whitelist\" is a deprecated value",
            "Use redirectLimit=\"allow\" instead (SP 3.3+)",
        )]
    } else {
        vec![pass(
            "MIG-018",
            Severity::Warning,
            &format!("redirectLimit value '{}' is not deprecated", limit),
        )]
    }
}

fn mig_019(_config: &DiscoveredConfig, sc: &ShibbolethConfig) -> Vec<CheckResult> {
    let Some(sessions) = sc.sessions.as_ref() else {
        return Vec::new();
    };
    let Some(proto) = sessions.sso_discovery_protocol.as_ref() else {
        return Vec::new();
    };
    if proto.contains("WAYF") {
        vec![fail(
            "MIG-019",
            Severity::Warning,
            &format!("SSO discoveryProtocol '{}' is deprecated", proto),
            "Use discoveryProtocol=\"SAMLDS\" instead of WAYF",
        )]
    } else {
        vec![pass(
            "MIG-019",
            Severity::Warning,
            &format!("SSO discoveryProtocol '{}' is not deprecated", proto),
        )]
    }
}

fn mig_020(config: &DiscoveredConfig, _sc: &ShibbolethConfig) -> Vec<CheckResult> {
    let Some(content) = config.shibboleth_xml_content.as_ref() else {
        return Vec::new();
    };
    if content.contains("legacyOrgNames=\"true\"") {
        vec![fail(
            "MIG-020",
            Severity::Warning,
            "MetadataProvider legacyOrgNames=\"true\" is deprecated",
            "Remove legacyOrgNames=\"true\" — legacy organization name handling is no longer recommended",
        )]
    } else {
        vec![pass(
            "MIG-020",
            Severity::Warning,
            "No deprecated legacyOrgNames attribute found",
        )]
    }
}

fn mig_021(config: &DiscoveredConfig, _sc: &ShibbolethConfig) -> Vec<CheckResult> {
    let attr_map_path = config.base_dir.join("attribute-map.xml");
    if !attr_map_path.exists() {
        return Vec::new();
    }
    let content = match std::fs::read_to_string(&attr_map_path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    if content.contains("aliases=") {
        vec![fail(
            "MIG-021",
            Severity::Info,
            "attribute-map.xml uses deprecated 'aliases' attribute",
            "Replace aliases with separate <Attribute> elements for each name",
        )]
    } else {
        vec![pass(
            "MIG-021",
            Severity::Info,
            "attribute-map.xml does not use deprecated aliases attribute",
        )]
    }
}

fn mig_022(_config: &DiscoveredConfig, sc: &ShibbolethConfig) -> Vec<CheckResult> {
    let mut results = Vec::new();
    for si in &sc.session_initiators {
        if let Some(t) = si.initiator_type.as_ref() {
            if t == "Shib1" || t == "WAYF" {
                let id_suffix = si
                    .id
                    .as_ref()
                    .map(|id| format!(" (id=\"{}\")", id))
                    .unwrap_or_default();
                results.push(fail(
                    "MIG-022",
                    Severity::Warning,
                    &format!(
                        "SessionInitiator type=\"{}\" is a legacy protocol{}",
                        t, id_suffix
                    ),
                    "Replace with type=\"SAML2\" for modern SAML 2.0 authentication",
                ));
            }
        }
    }
    results
}

fn mig_023(config: &DiscoveredConfig, _sc: &ShibbolethConfig) -> Vec<CheckResult> {
    let Some(content) = config.shibboleth_xml_content.as_ref() else {
        return Vec::new();
    };
    if content.contains("defaultACSIndex") || content.contains("acsIndex") {
        vec![fail(
            "MIG-023",
            Severity::Info,
            "SSO uses deprecated defaultACSIndex or acsIndex attribute",
            "Remove defaultACSIndex/acsIndex — SP3 manages ACS index automatically",
        )]
    } else {
        vec![pass(
            "MIG-023",
            Severity::Info,
            "No deprecated ACS index attributes found",
        )]
    }
}

fn mig_024(config: &DiscoveredConfig, sc: &ShibbolethConfig) -> Vec<CheckResult> {
    let Some(content) = config.shibboleth_xml_content.as_ref() else {
        return Vec::new();
    };
    let mut in_override = false;
    let mut found_issue = false;
    let mut results = Vec::new();
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
                    results.push(fail(
                        "MIG-024",
                        Severity::Warning,
                        &format!(
                            "ApplicationOverride <Sessions> missing {} (NOT inherited from ApplicationDefaults)",
                            missing.join(", ")
                        ),
                        "Add handlerSSL and cookieProps to <Sessions> inside <ApplicationOverride> — they are not inherited",
                    ));
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
        results.push(pass(
            "MIG-024",
            Severity::Warning,
            "ApplicationOverride Sessions elements have required attributes",
        ));
    }
    results
}
