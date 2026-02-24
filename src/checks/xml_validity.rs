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
                results.push(CheckResult::pass(
                    "XML-020",
                    CAT,
                    Severity::Info,
                    "Shibboleth SP3 configuration detected",
                ));
            }
            SpVersion::V2 => {
                results.push(CheckResult::fail(
                    "XML-020", CAT, Severity::Info,
                    "Shibboleth SP2 configuration detected",
                    Some("SP2 is end-of-life; consider upgrading to SP3"),
                ).with_doc("https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065335062/Upgrading"));
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
                    .with_doc(DOC_SPCONFIG),
                );
            }
        }

        // XML-021: REMOTE_USER attribute set
        if let Some(ref app) = sc.application_defaults {
            if app.remote_user.is_some() {
                results.push(CheckResult::pass(
                    "XML-021",
                    CAT,
                    Severity::Warning,
                    "REMOTE_USER attribute is set on ApplicationDefaults",
                ));
            } else {
                results.push(CheckResult::fail(
                    "XML-021", CAT, Severity::Warning,
                    "REMOTE_USER not set on ApplicationDefaults",
                    Some("Set REMOTE_USER on <ApplicationDefaults> (e.g., REMOTE_USER=\"eppn\") so applications can identify users"),
                ).with_doc(doc_for(DOC_APP_DEFAULTS, v)));
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

    results
}
