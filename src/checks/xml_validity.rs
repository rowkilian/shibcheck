use crate::config::DiscoveredConfig;
use crate::model::shibboleth_config::SpVersion;
use crate::result::{CheckCategory, CheckResult, Severity};

const CAT: CheckCategory = CheckCategory::XmlValidity;

// Shibboleth SP3 documentation URLs
const DOC_SPCONFIG: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2063695926/SPConfig";
const DOC_APP_DEFAULTS: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2063695997/ApplicationDefaults";
const DOC_SESSIONS: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334342/Sessions";
const DOC_SSO: &str = "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334348/SSO";
const DOC_METADATA_PROVIDER: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2060616124/MetadataProvider";
const DOC_CREDENTIAL_RESOLVER: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334414/CredentialResolver";
const DOC_ATTR_EXTRACTOR: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334421/XMLAttributeExtractor";
const DOC_ATTR_FILTER: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334516/AttributeFilter";

const DOC_NOTIFY: &str = "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334394/Notify";

const DOC_SAML2_SESSION_INITIATOR: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334736/SAML2+SessionInitiator";

const DOC_SP2_WIKI: &str = "https://shibboleth.atlassian.net/wiki/spaces/SHIB2/";

/// Return the SP2 wiki root for V2 configs, otherwise the SP3-specific page URL.
fn doc_for(sp3_url: &str, version: SpVersion) -> &str {
    match version {
        SpVersion::V2 => DOC_SP2_WIKI,
        _ => sp3_url,
    }
}

pub fn run(config: &DiscoveredConfig) -> Vec<CheckResult> {
    let mut results = Vec::new();

    // XML-001: shibboleth2.xml exists
    if config.shibboleth_xml_exists {
        results.push(CheckResult::pass(
            "XML-001",
            CAT,
            Severity::Error,
            "shibboleth2.xml exists",
        ));
    } else {
        results.push(
            CheckResult::fail(
                "XML-001",
                CAT,
                Severity::Error,
                "shibboleth2.xml not found",
                Some("Ensure shibboleth2.xml is present in the configuration directory"),
            )
            .with_doc(DOC_SPCONFIG),
        );
    }

    // XML-002: shibboleth2.xml is well-formed
    if config.shibboleth_xml_exists {
        if config.shibboleth_xml_well_formed {
            results.push(CheckResult::pass(
                "XML-002",
                CAT,
                Severity::Error,
                "shibboleth2.xml is well-formed XML",
            ));
        } else {
            results.push(
                CheckResult::fail(
                    "XML-002",
                    CAT,
                    Severity::Error,
                    "shibboleth2.xml is not well-formed XML",
                    Some("Fix XML syntax errors in shibboleth2.xml"),
                )
                .with_doc(DOC_SPCONFIG),
            );
        }
    }

    // XML-003: attribute-map.xml exists
    if config.attribute_map_exists {
        results.push(CheckResult::pass(
            "XML-003",
            CAT,
            Severity::Warning,
            "attribute-map.xml exists",
        ));
    } else {
        results.push(
            CheckResult::fail(
                "XML-003",
                CAT,
                Severity::Warning,
                "attribute-map.xml not found",
                Some(
                    "Create attribute-map.xml to define attribute mappings from IdP to local names",
                ),
            )
            .with_doc(DOC_ATTR_EXTRACTOR),
        );
    }

    // XML-004: attribute-map.xml is well-formed
    if config.attribute_map_exists {
        if config.attribute_map_well_formed {
            results.push(CheckResult::pass(
                "XML-004",
                CAT,
                Severity::Error,
                "attribute-map.xml is well-formed XML",
            ));
        } else {
            results.push(
                CheckResult::fail(
                    "XML-004",
                    CAT,
                    Severity::Error,
                    "attribute-map.xml is not well-formed XML",
                    Some("Fix XML syntax errors in attribute-map.xml"),
                )
                .with_doc(DOC_ATTR_EXTRACTOR),
            );
        }
    }

    // XML-017: attribute-map.xml has at least one attribute mapping
    if let Some(ref map) = config.attribute_map {
        if map.attributes.is_empty() {
            results.push(CheckResult::fail(
                "XML-017", CAT, Severity::Warning,
                "attribute-map.xml contains no attribute mappings",
                Some("Add <Attribute> elements to attribute-map.xml to map IdP attributes to local names"),
            ).with_doc(DOC_ATTR_EXTRACTOR));
        } else {
            results.push(CheckResult::pass(
                "XML-017",
                CAT,
                Severity::Warning,
                &format!(
                    "attribute-map.xml defines {} attribute mapping(s)",
                    map.attributes.len()
                ),
            ));
        }
    }

    // XML-005: attribute-policy.xml exists
    if config.attribute_policy_exists {
        results.push(CheckResult::pass(
            "XML-005",
            CAT,
            Severity::Info,
            "attribute-policy.xml exists",
        ));
    } else {
        results.push(
            CheckResult::fail(
                "XML-005",
                CAT,
                Severity::Info,
                "attribute-policy.xml not found",
                Some("Consider creating attribute-policy.xml to filter attribute values"),
            )
            .with_doc(DOC_ATTR_FILTER),
        );
    }

    // XML-006: attribute-policy.xml is well-formed
    if config.attribute_policy_exists {
        if config.attribute_policy_well_formed {
            results.push(CheckResult::pass(
                "XML-006",
                CAT,
                Severity::Error,
                "attribute-policy.xml is well-formed XML",
            ));
        } else {
            results.push(
                CheckResult::fail(
                    "XML-006",
                    CAT,
                    Severity::Error,
                    "attribute-policy.xml is not well-formed XML",
                    Some("Fix XML syntax errors in attribute-policy.xml"),
                )
                .with_doc(DOC_ATTR_FILTER),
            );
        }
    }

    // The following checks require a parsed shibboleth config
    if let Some(ref sc) = config.shibboleth_config {
        let v = sc.sp_version;

        // XML-007: SPConfig root element
        if sc.has_sp_config {
            results.push(CheckResult::pass(
                "XML-007",
                CAT,
                Severity::Error,
                "SPConfig root element present",
            ));
        } else {
            results.push(
                CheckResult::fail(
                    "XML-007",
                    CAT,
                    Severity::Error,
                    "SPConfig root element not found",
                    Some("The root element of shibboleth2.xml must be <SPConfig>"),
                )
                .with_doc(doc_for(DOC_SPCONFIG, v)),
            );
        }

        // XML-008: ApplicationDefaults element
        if sc.has_application_defaults {
            results.push(CheckResult::pass(
                "XML-008",
                CAT,
                Severity::Error,
                "ApplicationDefaults element present",
            ));
        } else {
            results.push(
                CheckResult::fail(
                    "XML-008",
                    CAT,
                    Severity::Error,
                    "ApplicationDefaults element not found",
                    Some("Add an <ApplicationDefaults> element inside <SPConfig>"),
                )
                .with_doc(doc_for(DOC_APP_DEFAULTS, v)),
            );
        }

        // XML-009: entityID attribute
        if sc.entity_id.is_some() {
            results.push(CheckResult::pass(
                "XML-009",
                CAT,
                Severity::Error,
                "entityID attribute is set",
            ));
        } else {
            results.push(
                CheckResult::fail(
                    "XML-009",
                    CAT,
                    Severity::Error,
                    "entityID attribute not set on ApplicationDefaults",
                    Some("Set entityID on <ApplicationDefaults> to your SP's entity ID"),
                )
                .with_doc(doc_for(DOC_APP_DEFAULTS, v)),
            );
        }

        // XML-010: Sessions element
        if sc.sessions.is_some() {
            results.push(CheckResult::pass(
                "XML-010",
                CAT,
                Severity::Error,
                "Sessions element present",
            ));
        } else {
            results.push(
                CheckResult::fail(
                    "XML-010",
                    CAT,
                    Severity::Error,
                    "Sessions element not found",
                    Some("Add a <Sessions> element inside <ApplicationDefaults>"),
                )
                .with_doc(doc_for(DOC_SESSIONS, v)),
            );
        }

        // XML-011: At least one SSO/SessionInitiator
        if let Some(ref sessions) = sc.sessions {
            if sessions.has_sso || sessions.has_session_initiator {
                results.push(CheckResult::pass(
                    "XML-011",
                    CAT,
                    Severity::Error,
                    "SSO or SessionInitiator configured",
                ));
            } else {
                results.push(
                    CheckResult::fail(
                        "XML-011",
                        CAT,
                        Severity::Error,
                        "No SSO or SessionInitiator element found",
                        Some("Add an <SSO> or <SessionInitiator> element inside <Sessions>"),
                    )
                    .with_doc(doc_for(DOC_SSO, v)),
                );
            }
        }

        // XML-012: handlerURL on Sessions
        if let Some(ref sessions) = sc.sessions {
            if sessions.handler_url.is_some() {
                results.push(CheckResult::pass(
                    "XML-012",
                    CAT,
                    Severity::Info,
                    "handlerURL is set on Sessions",
                ));
            } else {
                results.push(CheckResult::fail(
                    "XML-012", CAT, Severity::Info,
                    "handlerURL not set on Sessions element (defaults to /Shibboleth.sso)",
                    Some("Set handlerURL on <Sessions> to override the default \"/Shibboleth.sso\""),
                ).with_doc(doc_for(DOC_SESSIONS, v)));
            }
        }

        // XML-013: At least one MetadataProvider
        if !sc.metadata_providers.is_empty() {
            results.push(CheckResult::pass(
                "XML-013",
                CAT,
                Severity::Error,
                "MetadataProvider configured",
            ));
        } else {
            results.push(
                CheckResult::fail(
                    "XML-013",
                    CAT,
                    Severity::Error,
                    "No MetadataProvider configured",
                    Some("Add a <MetadataProvider> element to load IdP metadata"),
                )
                .with_doc(doc_for(DOC_METADATA_PROVIDER, v)),
            );
        }

        // XML-014: At least one CredentialResolver
        if !sc.credential_resolvers.is_empty() {
            results.push(CheckResult::pass(
                "XML-014",
                CAT,
                Severity::Warning,
                "CredentialResolver configured",
            ));
        } else {
            results.push(
                CheckResult::fail(
                    "XML-014",
                    CAT,
                    Severity::Warning,
                    "No CredentialResolver configured",
                    Some("Add a <CredentialResolver> for SP signing/encryption credentials"),
                )
                .with_doc(doc_for(DOC_CREDENTIAL_RESOLVER, v)),
            );
        }

        // XML-018: handlerURL starts with /
        if let Some(ref sessions) = sc.sessions {
            if let Some(ref handler_url) = sessions.handler_url {
                if handler_url.starts_with('/') {
                    results.push(CheckResult::pass(
                        "XML-018",
                        CAT,
                        Severity::Warning,
                        &format!("handlerURL is a valid relative path: {}", handler_url),
                    ));
                } else {
                    results.push(CheckResult::fail(
                        "XML-018", CAT, Severity::Warning,
                        &format!("handlerURL does not start with '/': {}", handler_url),
                        Some("handlerURL should be a relative path starting with '/' (e.g., \"/Shibboleth.sso\")"),
                    ).with_doc(doc_for(DOC_SESSIONS, v)));
                }
            }
        }

        // XML-019: Logout element present
        if let Some(ref sessions) = sc.sessions {
            if sessions.has_logout {
                results.push(CheckResult::pass(
                    "XML-019",
                    CAT,
                    Severity::Info,
                    "Logout or LogoutInitiator configured",
                ));
            } else {
                let suggestion = match v {
                    SpVersion::V3 => "Add a <Logout>SAML2 Local</Logout> element inside <Sessions> for logout support",
                    SpVersion::V2 => "Add a <LogoutInitiator> element inside <Sessions> for logout support",
                    SpVersion::Unknown => "Add a <Logout> or <LogoutInitiator> element inside <Sessions> for logout support",
                };
                results.push(
                    CheckResult::fail(
                        "XML-019",
                        CAT,
                        Severity::Info,
                        "No Logout or LogoutInitiator element found",
                        Some(suggestion),
                    )
                    .with_doc(doc_for(DOC_SESSIONS, v)),
                );
            }
        }

        // XML-020: SP version detection
        match v {
            SpVersion::V3 => {
                results.push(
                    CheckResult::pass(
                        "XML-020",
                        CAT,
                        Severity::Info,
                        "Shibboleth SP3 configuration detected",
                    )
                    .at_element("SPConfig"),
                );
            }
            SpVersion::V2 => {
                results.push(CheckResult::fail(
                    "XML-020", CAT, Severity::Info,
                    "Shibboleth SP2 configuration detected",
                    Some("SP2 is end-of-life; consider upgrading to SP3"),
                ).at_element("SPConfig").with_doc("https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2067400004/UpgradingFromV2"));
            }
            SpVersion::Unknown => {
                results.push(
                    CheckResult::fail(
                        "XML-020",
                        CAT,
                        Severity::Info,
                        "SP version could not be determined from SPConfig xmlns",
                        Some("Ensure <SPConfig> has a valid xmlns attribute"),
                    )
                    .at_element("SPConfig")
                    .with_doc(DOC_SPCONFIG),
                );
            }
        }

        // XML-021: REMOTE_USER attribute set
        if let Some(ref app) = sc.application_defaults {
            if app.remote_user.is_some() {
                results.push(
                    CheckResult::pass(
                        "XML-021",
                        CAT,
                        Severity::Warning,
                        "REMOTE_USER attribute is set on ApplicationDefaults",
                    )
                    .at_element("ApplicationDefaults"),
                );
            } else {
                results.push(CheckResult::fail(
                    "XML-021", CAT, Severity::Warning,
                    "REMOTE_USER not set on ApplicationDefaults",
                    Some("Set REMOTE_USER on <ApplicationDefaults> (e.g., REMOTE_USER=\"eppn\") so applications can identify users"),
                ).at_element("ApplicationDefaults").with_doc(doc_for(DOC_APP_DEFAULTS, v)));
            }
        }

        // XML-022: Errors supportContact is present
        if let Some(ref errors) = sc.errors {
            if errors.support_contact.is_some() {
                results.push(CheckResult::pass(
                    "XML-022",
                    CAT,
                    Severity::Warning,
                    "Errors supportContact is configured",
                ));
            } else {
                results.push(
                    CheckResult::fail(
                        "XML-022",
                        CAT,
                        Severity::Warning,
                        "Errors element has no supportContact attribute",
                        Some("Set supportContact on <Errors> to provide a contact email for error pages"),
                    )
                    .with_doc(doc_for(DOC_APP_DEFAULTS, v)),
                );
            }
        }

        // XML-023: SSO has entityID or discoveryURL
        if let Some(ref sessions) = sc.sessions {
            if sessions.has_sso {
                if sessions.sso_entity_id.is_some() || sessions.sso_discovery_url.is_some() {
                    results.push(CheckResult::pass(
                        "XML-023",
                        CAT,
                        Severity::Warning,
                        "SSO has entityID or discoveryURL configured",
                    ));
                } else {
                    results.push(
                        CheckResult::fail(
                            "XML-023",
                            CAT,
                            Severity::Warning,
                            "SSO element has neither entityID nor discoveryURL",
                            Some(
                                "Set entityID or discoveryURL on <SSO> to identify the target IdP",
                            ),
                        )
                        .with_doc(doc_for(DOC_SSO, v)),
                    );
                }
            }
        }

        // XML-024: SSO has entityID XOR discoveryURL, not both
        if let Some(ref sessions) = sc.sessions {
            if sessions.sso_entity_id.is_some() && sessions.sso_discovery_url.is_some() {
                results.push(
                    CheckResult::fail(
                        "XML-024",
                        CAT,
                        Severity::Info,
                        "SSO has both entityID and discoveryURL (entityID takes precedence)",
                        Some("Use either entityID (single IdP) or discoveryURL (discovery service), not both"),
                    )
                    .with_doc(doc_for(DOC_SSO, v)),
                );
            } else if sessions.sso_entity_id.is_some() || sessions.sso_discovery_url.is_some() {
                results.push(CheckResult::pass(
                    "XML-024",
                    CAT,
                    Severity::Info,
                    "SSO uses entityID or discoveryURL exclusively",
                ));
            }
        }

        // XML-025: SecurityPolicyProvider path file exists
        if let Some(ref spp_path) = sc.security_policy_provider_path {
            let full_path = config.base_dir.join(spp_path);
            if full_path.exists() {
                results.push(CheckResult::pass(
                    "XML-025",
                    CAT,
                    Severity::Error,
                    &format!("SecurityPolicyProvider file exists: {}", spp_path),
                ));
            } else {
                results.push(
                    CheckResult::fail(
                        "XML-025",
                        CAT,
                        Severity::Error,
                        &format!("SecurityPolicyProvider file not found: {}", spp_path),
                        Some("Ensure the security-policy.xml file exists at the configured path"),
                    )
                    .with_doc(doc_for(DOC_SPCONFIG, v)),
                );
            }
        }

        // XML-026: ApplicationOverride IDs are unique
        if !sc.application_override_ids.is_empty() {
            let mut seen = std::collections::HashSet::new();
            let mut has_dup = false;
            for id in &sc.application_override_ids {
                if !seen.insert(id.as_str()) {
                    results.push(
                        CheckResult::fail(
                            "XML-026",
                            CAT,
                            Severity::Error,
                            &format!("Duplicate ApplicationOverride id: {}", id),
                            Some("Each ApplicationOverride must have a unique id attribute"),
                        )
                        .with_doc(doc_for(DOC_APP_DEFAULTS, v)),
                    );
                    has_dup = true;
                }
            }
            if !has_dup {
                results.push(CheckResult::pass(
                    "XML-026",
                    CAT,
                    Severity::Error,
                    "All ApplicationOverride IDs are unique",
                ));
            }
        }

        // XML-027: SSO protocol text is valid (SAML2/SAML1/empty)
        if let Some(ref sessions) = sc.sessions {
            if let Some(ref protocols) = sessions.sso_protocols {
                let valid = ["SAML2", "SAML1"];
                let parts: Vec<&str> = protocols.split_whitespace().collect();
                let all_valid = parts.iter().all(|p| valid.contains(p));
                if all_valid {
                    results.push(CheckResult::pass(
                        "XML-027",
                        CAT,
                        Severity::Warning,
                        &format!("SSO protocol text is valid: {}", protocols),
                    ));
                } else {
                    results.push(
                        CheckResult::fail(
                            "XML-027",
                            CAT,
                            Severity::Warning,
                            &format!("SSO protocol text contains invalid value: {}", protocols),
                            Some("Valid SSO protocol values are: SAML2, SAML1"),
                        )
                        .with_doc(doc_for(DOC_SSO, v)),
                    );
                }
            }
        }

        // XML-028: Logout protocol text is valid (SAML2/Local/empty)
        if let Some(ref sessions) = sc.sessions {
            if let Some(ref protocols) = sessions.logout_protocols {
                let valid = ["SAML2", "Local"];
                let parts: Vec<&str> = protocols.split_whitespace().collect();
                let all_valid = parts.iter().all(|p| valid.contains(p));
                if all_valid {
                    results.push(CheckResult::pass(
                        "XML-028",
                        CAT,
                        Severity::Warning,
                        &format!("Logout protocol text is valid: {}", protocols),
                    ));
                } else {
                    results.push(
                        CheckResult::fail(
                            "XML-028",
                            CAT,
                            Severity::Warning,
                            &format!("Logout protocol text contains invalid value: {}", protocols),
                            Some("Valid Logout protocol values are: SAML2, Local"),
                        )
                        .with_doc(doc_for(DOC_SESSIONS, v)),
                    );
                }
            }
        }

        // XML-029: MetadataProvider has a source (path/url/uri/sourceDirectory)
        for mp in &sc.metadata_providers {
            // Chaining has child providers; Dynamic names its sources in Subst/Regex children
            if mp.provider_type == "Chaining" || mp.provider_type == "Dynamic" {
                continue;
            }
            let has_source = if mp.provider_type == "MDQ" {
                mp.base_url.is_some()
            } else {
                mp.path.is_some()
                    || mp.uri.is_some()
                    || mp.url.is_some()
                    || mp.source_directory.is_some()
                    || mp.file_attr.is_some()
            };
            if has_source {
                results.push(CheckResult::pass(
                    "XML-029",
                    CAT,
                    Severity::Error,
                    &format!(
                        "MetadataProvider type={}{}  has a data source configured",
                        mp.provider_type,
                        mp.label()
                    ),
                ));
            } else {
                results.push(
                    CheckResult::fail(
                        "XML-029",
                        CAT,
                        Severity::Error,
                        &format!(
                            "MetadataProvider type={}{} has no data source (path/url/uri/file/sourceDirectory)",
                            mp.provider_type, mp.label()
                        ),
                        Some(if mp.provider_type == "MDQ" {
                            "Add baseUrl, the root of the MDQ server, to the MDQ MetadataProvider"
                        } else {
                            "Add a path, url, uri, file, or sourceDirectory attribute to the MetadataProvider"
                        }),
                    )
                    .with_doc(doc_for(DOC_METADATA_PROVIDER, v)),
                );
            }
        }

        // XML-030: File CredentialResolver has both key and certificate
        for cr in &sc.credential_resolvers {
            if cr.resolver_type == "File" {
                if cr.certificate.is_some() && cr.key.is_some() {
                    results.push(CheckResult::pass(
                        "XML-030",
                        CAT,
                        Severity::Warning,
                        "File CredentialResolver has both certificate and key",
                    ));
                } else {
                    let missing = if cr.certificate.is_none() && cr.key.is_none() {
                        "certificate and key"
                    } else if cr.certificate.is_none() {
                        "certificate"
                    } else {
                        "key"
                    };
                    results.push(
                        CheckResult::fail(
                            "XML-030",
                            CAT,
                            Severity::Warning,
                            &format!(
                                "File CredentialResolver is missing {}",
                                missing
                            ),
                            Some("A File CredentialResolver should have both certificate and key attributes"),
                        )
                        .with_doc(doc_for(DOC_CREDENTIAL_RESOLVER, v)),
                    );
                }
            }
        }

        // XML-016: entityID is a valid absolute URI
        if let Some(ref entity_id) = sc.entity_id {
            if entity_id.starts_with("https://")
                || entity_id.starts_with("http://")
                || entity_id.starts_with("urn:")
            {
                results.push(CheckResult::pass(
                    "XML-016",
                    CAT,
                    Severity::Warning,
                    &format!("entityID is a valid absolute URI: {}", entity_id),
                ));
            } else {
                results.push(
                    CheckResult::fail(
                        "XML-016",
                        CAT,
                        Severity::Warning,
                        &format!("entityID is not a valid absolute URI: {}", entity_id),
                        Some("entityID should be an absolute URI (https://, http://, or urn:)"),
                    )
                    .with_doc(doc_for(DOC_APP_DEFAULTS, v)),
                );
            }
        }
    }

    // The following checks require a parsed shibboleth config (continued)
    if let Some(ref sc) = config.shibboleth_config {
        let v = sc.sp_version;

        // XML-031: No <Errors> element configured
        if sc.errors.is_some() {
            results.push(CheckResult::pass(
                "XML-031",
                CAT,
                Severity::Info,
                "Errors element is configured",
            ));
        } else {
            results.push(
                CheckResult::fail(
                    "XML-031",
                    CAT,
                    Severity::Info,
                    "No <Errors> element configured",
                    Some("Add an <Errors> element to customize error pages and provide a support contact"),
                )
                .with_doc(doc_for(DOC_APP_DEFAULTS, v)),
            );
        }

        // XML-032: Errors has no helpLocation
        if let Some(ref errors) = sc.errors {
            if errors.help_location.is_some() {
                results.push(CheckResult::pass(
                    "XML-032",
                    CAT,
                    Severity::Info,
                    "Errors helpLocation is configured",
                ));
            } else {
                results.push(
                    CheckResult::fail(
                        "XML-032",
                        CAT,
                        Severity::Info,
                        "Errors element has no helpLocation attribute",
                        Some("Set helpLocation on <Errors> to provide a help page URL for error pages"),
                    )
                    .with_doc(doc_for(DOC_APP_DEFAULTS, v)),
                );
            }
        }

        // XML-033: MetadataProvider type not recognized
        {
            let known_types = [
                "XML",
                "Dynamic",
                "MDQ",
                "Chaining",
                "Folder",
                "LocalDynamic",
                "Null",
            ];
            for mp in &sc.metadata_providers {
                // Strip any namespace prefix (e.g., "md:XML" -> "XML")
                let bare_type = mp
                    .provider_type
                    .rsplit(':')
                    .next()
                    .unwrap_or(&mp.provider_type);
                if mp.provider_type.is_empty() {
                    // Type omitted — a separate concern, don't produce a false positive here.
                    continue;
                }
                if known_types.contains(&bare_type) {
                    results.push(CheckResult::pass(
                        "XML-033",
                        CAT,
                        Severity::Error,
                        &format!(
                            "MetadataProvider type '{}'{} is recognized",
                            mp.provider_type,
                            mp.label()
                        ),
                    ));
                } else {
                    results.push(
                        CheckResult::fail(
                            "XML-033",
                            CAT,
                            Severity::Error,
                            &format!(
                                "MetadataProvider type '{}'{} is not recognized",
                                mp.provider_type, mp.label()
                            ),
                            Some("Valid types: XML, Dynamic, MDQ, Chaining, Folder, LocalDynamic, Null"),
                        )
                        .with_doc(doc_for(DOC_METADATA_PROVIDER, v)),
                    );
                }
            }
        }

        // XML-034: CredentialResolver type not recognized
        {
            let known_types = ["File", "Chaining", "PKCS12"];
            for cr in &sc.credential_resolvers {
                if cr.resolver_type.is_empty() {
                    continue;
                }
                let bare_type = cr
                    .resolver_type
                    .rsplit(':')
                    .next()
                    .unwrap_or(&cr.resolver_type);
                if known_types.contains(&bare_type) {
                    results.push(CheckResult::pass(
                        "XML-034",
                        CAT,
                        Severity::Error,
                        &format!(
                            "CredentialResolver type '{}' is recognized",
                            cr.resolver_type
                        ),
                    ));
                } else {
                    results.push(
                        CheckResult::fail(
                            "XML-034",
                            CAT,
                            Severity::Error,
                            &format!(
                                "CredentialResolver type '{}' is not recognized",
                                cr.resolver_type
                            ),
                            Some("Valid types: File, Chaining, PKCS12"),
                        )
                        .with_doc(doc_for(DOC_CREDENTIAL_RESOLVER, v)),
                    );
                }
            }
        }

        // XML-035: MetadataFilter type not recognized
        {
            let known_types = [
                "Signature",
                "RequireValidUntil",
                "EntityRoleWhiteList",
                "EntityRole",
                "Whitelist",
                "Blacklist",
                "Include",
                "Exclude",
                "EntityAttributes",
                "NameIDFormat",
                "Predicate",
                "Algorithm",
            ];
            for mp in &sc.metadata_providers {
                for filter in &mp.filters {
                    if filter.filter_type.is_empty() {
                        // Type omitted — don't produce a false positive here.
                        continue;
                    }
                    // Strip any namespace prefix (e.g., "md:Signature" -> "Signature")
                    let bare_type = filter
                        .filter_type
                        .rsplit(':')
                        .next()
                        .unwrap_or(&filter.filter_type);
                    if known_types.contains(&bare_type) {
                        results.push(CheckResult::pass(
                            "XML-035",
                            CAT,
                            Severity::Warning,
                            &format!(
                                "MetadataFilter type '{}'{} is recognized",
                                filter.filter_type,
                                mp.label()
                            ),
                        ));
                    } else {
                        results.push(
                            CheckResult::fail(
                                "XML-035",
                                CAT,
                                Severity::Warning,
                                &format!(
                                    "MetadataFilter type '{}'{} is not recognized",
                                    filter.filter_type, mp.label()
                                ),
                                Some("Check the MetadataFilter type spelling against Shibboleth SP3 documentation"),
                            )
                            .with_doc(doc_for(DOC_METADATA_PROVIDER, v)),
                        );
                    }
                }
            }
        }

        // XML-036: Logout missing Local protocol for fallback
        if let Some(ref sessions) = sc.sessions {
            if sessions.has_logout {
                if let Some(ref protocols) = sessions.logout_protocols {
                    if protocols.contains("Local") {
                        results.push(CheckResult::pass(
                            "XML-036",
                            CAT,
                            Severity::Info,
                            "Logout includes 'Local' protocol for fallback",
                        ));
                    } else {
                        results.push(
                            CheckResult::fail(
                                "XML-036",
                                CAT,
                                Severity::Info,
                                "Logout does not include 'Local' protocol",
                                Some("Add 'Local' to <Logout> protocols (e.g., <Logout>SAML2 Local</Logout>) for local-only logout fallback"),
                            )
                            .with_doc(doc_for(DOC_SESSIONS, v)),
                        );
                    }
                }
            }
        }

        // XML-037: ECP support status on SSO
        if sc.sso_ecp.is_some() {
            results.push(CheckResult::pass(
                "XML-037",
                CAT,
                Severity::Info,
                &format!(
                    "ECP attribute is set on SSO: {}",
                    sc.sso_ecp.as_deref().unwrap_or("?")
                ),
            ));
        } else if sc.sessions.as_ref().is_some_and(|s| s.has_sso) {
            results.push(CheckResult::pass(
                "XML-037",
                CAT,
                Severity::Info,
                "ECP not configured on SSO (disabled by default)",
            ));
        }

        // XML-038: authnContextClassRef on SSO is not a valid URI
        if let Some(ref acr) = sc.sso_authn_context_class_ref {
            if acr.starts_with("urn:") || acr.starts_with("http://") || acr.starts_with("https://")
            {
                results.push(CheckResult::pass(
                    "XML-038",
                    CAT,
                    Severity::Warning,
                    &format!("SSO authnContextClassRef is a valid URI: {}", acr),
                ));
            } else {
                results.push(
                    CheckResult::fail(
                        "XML-038",
                        CAT,
                        Severity::Warning,
                        &format!("SSO authnContextClassRef is not a valid URI: {}", acr),
                        Some("authnContextClassRef should be a URI (e.g., urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport)"),
                    )
                    .with_doc(doc_for(DOC_SSO, v)),
                );
            }
        }

        // XML-039: SSO discoveryProtocol not a recognized value
        if let Some(ref sessions) = sc.sessions {
            if let Some(ref proto) = sessions.sso_discovery_protocol {
                if proto == "SAMLDS" {
                    results.push(CheckResult::pass(
                        "XML-039",
                        CAT,
                        Severity::Warning,
                        &format!("SSO discoveryProtocol is recognized: {}", proto),
                    ));
                } else {
                    results.push(
                        CheckResult::fail(
                            "XML-039",
                            CAT,
                            Severity::Warning,
                            &format!(
                                "SSO discoveryProtocol '{}' is not a recognized value",
                                proto
                            ),
                            Some("Expected discoveryProtocol=\"SAMLDS\" on <SSO>"),
                        )
                        .with_doc(doc_for(DOC_SSO, v)),
                    );
                }
            }
        }

        // XML-040: RequestMap applicationId references collected
        if !sc.request_map_application_ids.is_empty() {
            results.push(CheckResult::pass(
                "XML-040",
                CAT,
                Severity::Info,
                &format!(
                    "RequestMap contains {} applicationId reference(s)",
                    sc.request_map_application_ids.len()
                ),
            ));
        }

        // XML-041: ApplicationOverride element has no entityID attribute
        for (id, entity_id) in &sc.application_override_entity_ids {
            if entity_id.is_none() {
                results.push(
                    CheckResult::fail(
                        "XML-041",
                        CAT,
                        Severity::Warning,
                        &format!(
                            "ApplicationOverride '{}' has no entityID attribute",
                            id
                        ),
                        Some("Set entityID on ApplicationOverride to define the SP identity for this override"),
                    )
                    .with_doc(doc_for(DOC_APP_DEFAULTS, v)),
                );
            } else {
                results.push(CheckResult::pass(
                    "XML-041",
                    CAT,
                    Severity::Warning,
                    &format!("ApplicationOverride '{}' has entityID set", id),
                ));
            }
        }

        // XML-042: Errors template file paths don't exist on disk
        if let Some(ref errors) = sc.errors {
            let template_fields: &[(&str, &Option<String>)] = &[
                ("session", &errors.session_error),
                ("access", &errors.access_error),
                ("ssl", &errors.ssl_error),
                ("localLogout", &errors.local_logout),
                ("metadata", &errors.metadata_error),
                ("globalLogout", &errors.global_logout),
            ];
            for (attr_name, value) in template_fields {
                if let Some(ref path) = value {
                    if path.starts_with("http://") || path.starts_with("https://") {
                        continue;
                    }
                    let full_path = config.base_dir.join(path);
                    if full_path.exists() {
                        results.push(CheckResult::pass(
                            "XML-042",
                            CAT,
                            Severity::Warning,
                            &format!("Errors {} template exists: {}", attr_name, path),
                        ));
                    } else {
                        results.push(
                            CheckResult::fail(
                                "XML-042",
                                CAT,
                                Severity::Warning,
                                &format!("Errors {} template file not found: {}", attr_name, path),
                                Some(
                                    "Ensure the error template file exists at the configured path",
                                ),
                            )
                            .with_doc(doc_for(DOC_APP_DEFAULTS, v)),
                        );
                    }
                }
            }
        }

        // XML-043: Logout outgoingBindings attribute configured
        if let Some(ref sessions) = sc.sessions {
            if let Some(ref bindings) = sessions.logout_outgoing_bindings {
                results.push(CheckResult::pass(
                    "XML-043",
                    CAT,
                    Severity::Info,
                    &format!("Logout outgoingBindings configured: {}", bindings),
                ));
            }
        }

        // XML-044: MetadataProvider has no validate attribute (schema validation off)
        for mp in &sc.metadata_providers {
            if mp.provider_type == "Chaining" {
                continue;
            }
            if mp.validate_attr.is_some() {
                results.push(CheckResult::pass(
                    "XML-044",
                    CAT,
                    Severity::Info,
                    &format!(
                        "MetadataProvider type='{}'{} has validate attribute set",
                        mp.provider_type,
                        mp.label()
                    ),
                ));
            } else {
                results.push(
                    CheckResult::fail(
                        "XML-044",
                        CAT,
                        Severity::Info,
                        &format!(
                            "MetadataProvider type='{}'{} has no validate attribute (schema validation off by default)",
                            mp.provider_type, mp.label()
                        ),
                        Some("Add validate=\"true\" to MetadataProvider to enable schema validation of metadata"),
                    )
                    .with_doc(doc_for(DOC_METADATA_PROVIDER, v)),
                );
            }
        }

        // XML-045: isPassive="true" combined with requireSession="true" (users get errors, not login)
        for cs in &sc.request_map_content_settings {
            if cs.is_passive.as_deref() == Some("true")
                && cs.require_session.as_deref() == Some("true")
            {
                results.push(
                    CheckResult::fail(
                        "XML-045",
                        CAT,
                        Severity::Warning,
                        &format!(
                            "<{}{}> has isPassive=\"true\" with requireSession=\"true\" (users get errors instead of login prompts)",
                            cs.element,
                            cs.name
                                .as_ref()
                                .map(|n| format!(" name=\"{}\"", n))
                                .unwrap_or_default()
                        ),
                        Some("Remove isPassive=\"true\" or requireSession=\"true\" — combining them causes authentication errors for unauthenticated users"),
                    )
                    .with_doc(doc_for(DOC_SESSIONS, v)),
                );
            }
        }

        // XML-046: requireSession="true" without authType="shibboleth" (SP ignores resource)
        for cs in &sc.request_map_content_settings {
            if cs.require_session.as_deref() == Some("true") && cs.auth_type.is_none() {
                results.push(
                    CheckResult::fail(
                        "XML-046",
                        CAT,
                        Severity::Warning,
                        &format!(
                            "<{}{}> has requireSession=\"true\" without authType (SP may not enforce protection)",
                            cs.element,
                            cs.name
                                .as_ref()
                                .map(|n| format!(" name=\"{}\"", n))
                                .unwrap_or_default()
                        ),
                        Some("Add authType=\"shibboleth\" alongside requireSession=\"true\" in web server configuration, or ensure the web server module enforces it"),
                    )
                    .with_doc(doc_for(DOC_SESSIONS, v)),
                );
            }
        }

        // XML-047: RequestMapper type="XML" (web server directives ignored)
        if let Some(ref rm_type) = sc.request_map_type {
            if rm_type == "XML" {
                results.push(
                    CheckResult::fail(
                        "XML-047",
                        CAT,
                        Severity::Info,
                        "RequestMapper type=\"XML\" — web server directives (e.g., Apache <Location>) are ignored",
                        Some("With type=\"XML\", all access control must be in shibboleth2.xml RequestMap; web server directives have no effect"),
                    )
                    .with_doc(doc_for(DOC_SPCONFIG, v)),
                );
            } else {
                results.push(CheckResult::pass(
                    "XML-047",
                    CAT,
                    Severity::Info,
                    &format!("RequestMapper type is '{}' (not XML-only)", rm_type),
                ));
            }
        }
    }

    // XML-015: Other XML files well-formed
    if config.other_xml_malformed.is_empty() {
        if !config.other_xml_files.is_empty() {
            results.push(CheckResult::pass(
                "XML-015",
                CAT,
                Severity::Warning,
                "All other XML files are well-formed",
            ));
        } else {
            results.push(CheckResult::pass(
                "XML-015",
                CAT,
                Severity::Warning,
                "No additional XML files to check",
            ));
        }
    } else {
        for (path, error) in &config.other_xml_malformed {
            let filename = path.file_name().unwrap_or_default().to_string_lossy();
            results.push(CheckResult::fail(
                "XML-015",
                CAT,
                Severity::Warning,
                &format!("{} is not well-formed: {}", filename, error),
                Some("Fix XML syntax errors in this file"),
            ));
        }
    }

    check_notify(config, &mut results);
    check_redirect_limit(config, &mut results);
    check_authn_context_comparison(config, &mut results);

    results
}
/// XML-048: each <Notify> needs Channel="front"|"back" and an absolute Location.
fn check_notify(config: &DiscoveredConfig, results: &mut Vec<CheckResult>) {
    let Some(sc) = config.shibboleth_config.as_ref() else {
        return;
    };
    for notify in &sc.notify_elements {
        let problem = match (notify.channel.as_deref(), notify.location.as_deref()) {
            (None, _) => Some((
                Severity::Error,
                "Notify has no Channel attribute".to_string(),
                "Set Channel=\"front\" or Channel=\"back\"",
            )),
            (Some(c), _) if c != "front" && c != "back" => Some((
                Severity::Warning,
                format!("Notify Channel '{}' is not \"front\" or \"back\"", c),
                "Set Channel=\"front\" or Channel=\"back\"",
            )),
            (_, None) => Some((
                Severity::Warning,
                "Notify has no Location attribute".to_string(),
                "Set Location to the absolute URL that receives the notification",
            )),
            (_, Some(l)) if !l.starts_with("http://") && !l.starts_with("https://") => Some((
                Severity::Warning,
                format!("Notify Location is not an absolute URL: {}", l),
                "Use an absolute http(s) URL for Location",
            )),
            _ => None,
        };
        let result = match problem {
            Some((severity, message, suggestion)) => {
                CheckResult::fail("XML-048", CAT, severity, &message, Some(suggestion))
                    .with_doc(DOC_NOTIFY)
            }
            None => CheckResult::pass(
                "XML-048",
                CAT,
                Severity::Warning,
                "Notify has a valid Channel and absolute Location",
            ),
        };
        results.push(result.at_element("Notify"));
    }
}

const REDIRECT_LIMITS: &[&str] = &[
    "none",
    "exact",
    "host",
    "allow",
    "exact+allow",
    "host+allow",
    // names used before SP 3.2
    "whitelist",
    "exact+whitelist",
    "host+whitelist",
];

/// XML-049: redirectLimit must be one of the documented values.
fn check_redirect_limit(config: &DiscoveredConfig, results: &mut Vec<CheckResult>) {
    let Some(sc) = config.shibboleth_config.as_ref() else {
        return;
    };
    let Some(limit) = sc
        .sessions
        .as_ref()
        .and_then(|s| s.redirect_limit.as_deref())
    else {
        return;
    };
    let result = if REDIRECT_LIMITS.contains(&limit) {
        CheckResult::pass(
            "XML-049",
            CAT,
            Severity::Warning,
            "redirectLimit is a recognized value",
        )
    } else {
        CheckResult::fail(
            "XML-049",
            CAT,
            Severity::Warning,
            &format!("redirectLimit has unrecognized value '{}'", limit),
            Some("Use one of none, exact, host, allow, exact+allow or host+allow"),
        )
        .with_doc(doc_for(DOC_SESSIONS, sc.sp_version))
    };
    results.push(result.at_element("Sessions"));
}

/// XML-050: authnContextComparison takes four values and is ignored without
/// authnContextClassRef.
fn check_authn_context_comparison(config: &DiscoveredConfig, results: &mut Vec<CheckResult>) {
    let Some(sc) = config.shibboleth_config.as_ref() else {
        return;
    };
    let Some(ref comparison) = sc.sso_authn_context_comparison else {
        return;
    };
    let result = if !["exact", "minimum", "maximum", "better"].contains(&comparison.as_str()) {
        CheckResult::fail(
            "XML-050",
            CAT,
            Severity::Warning,
            &format!(
                "SSO authnContextComparison has unrecognized value '{}'",
                comparison
            ),
            Some("Use one of exact, minimum, maximum or better"),
        )
        .with_doc(DOC_SAML2_SESSION_INITIATOR)
    } else if sc.sso_authn_context_class_ref.is_none() {
        CheckResult::fail(
            "XML-050",
            CAT,
            Severity::Info,
            "SSO authnContextComparison is set without authnContextClassRef, so it is ignored",
            Some("Set authnContextClassRef too, or remove authnContextComparison"),
        )
        .with_doc(DOC_SAML2_SESSION_INITIATOR)
    } else {
        CheckResult::pass(
            "XML-050",
            CAT,
            Severity::Warning,
            "SSO authnContextComparison is valid and has an authnContextClassRef",
        )
    };
    results.push(result.at_element("SSO"));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::config_from_xml;

    fn notify_results(notify: &str) -> Vec<CheckResult> {
        let xml = format!(
            r#"<SPConfig xmlns="urn:mace:shibboleth:3.0:native:sp:config">
  <ApplicationDefaults entityID="https://sp.example.org/shibboleth">
    <Sessions>{notify}</Sessions>
  </ApplicationDefaults>
</SPConfig>"#
        );
        let (_dir, config) = config_from_xml(&xml);
        run(&config)
            .into_iter()
            .filter(|r| r.code == "XML-048")
            .collect()
    }

    #[test]
    fn valid_notify_passes() {
        let r = notify_results(r#"<Notify Channel="back" Location="https://app.example.org/n"/>"#);
        assert_eq!(r.len(), 1);
        assert!(r[0].passed);
    }

    #[test]
    fn notify_problems_are_reported() {
        for (notify, severity) in [
            (
                r#"<Notify Location="https://a.example/n"/>"#,
                Severity::Error,
            ),
            (
                r#"<Notify Channel="sideways" Location="https://a.example/n"/>"#,
                Severity::Warning,
            ),
            (r#"<Notify Channel="back"/>"#, Severity::Warning),
            (
                r#"<Notify Channel="back" Location="/relative"/>"#,
                Severity::Warning,
            ),
        ] {
            let r = notify_results(notify);
            assert_eq!(r.len(), 1, "{notify}");
            assert!(!r[0].passed, "{notify}");
            assert_eq!(r[0].severity, severity, "{notify}");
        }
    }

    fn run_app(body: &str, sso_attrs: &str) -> Vec<CheckResult> {
        let xml = crate::testutil::sp3_app(
            "",
            &format!(
                r#"<Sessions {body}><SSO entityID="https://idp.example.org/idp" {sso_attrs}>SAML2</SSO></Sessions>"#
            ),
        );
        let (_dir, config) = config_from_xml(&xml);
        run(&config)
    }

    #[test]
    fn redirect_limit_values() {
        for (value, passed) in [
            ("exact", true),
            ("host+allow", true),
            ("exact+whitelist", true),
            ("Exact", false),
            ("strict", false),
        ] {
            let r = run_app(&format!(r#"redirectLimit="{value}""#), "");
            crate::testutil::assert_outcome(&r, "XML-049", passed);
        }
        crate::testutil::assert_absent(&run_app("", ""), "XML-049");
    }

    #[test]
    fn authn_context_comparison_values() {
        let class = r#"authnContextClassRef="urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport""#;
        let r = run_app("", &format!(r#"{class} authnContextComparison="exact""#));
        crate::testutil::assert_outcome(&r, "XML-050", true);
        let r = run_app("", &format!(r#"{class} authnContextComparison="roughly""#));
        crate::testutil::assert_outcome(&r, "XML-050", false);
        let r = run_app("", r#"authnContextComparison="exact""#);
        crate::testutil::assert_outcome(&r, "XML-050", false);
        crate::testutil::assert_absent(&run_app("", ""), "XML-050");
    }

    #[test]
    fn mdq_provider_needs_base_url_not_a_path() {
        let provider = |attrs: &str| {
            let xml = crate::testutil::sp3_app(
                "",
                &format!(r#"<Sessions><SSO>SAML2</SSO></Sessions><MetadataProvider {attrs}/>"#),
            );
            let (_dir, config) = config_from_xml(&xml);
            run(&config)
        };
        crate::testutil::assert_outcome(
            &provider(r#"type="MDQ" baseUrl="https://mdq.example.org/""#),
            "XML-029",
            true,
        );
        crate::testutil::assert_outcome(&provider(r#"type="MDQ""#), "XML-029", false);
        // Dynamic providers name their sources in child elements
        crate::testutil::assert_absent(&provider(r#"type="Dynamic""#), "XML-029");
        crate::testutil::assert_outcome(&provider(r#"type="XML""#), "XML-029", false);
    }
}
