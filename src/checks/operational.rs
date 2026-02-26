use std::collections::HashSet;

use crate::config::DiscoveredConfig;
use crate::result::{CheckCategory, CheckResult, Severity};

const CAT: CheckCategory = CheckCategory::Operational;

const DOC_ERRORS: &str = "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334308/Errors";
const DOC_METADATA_PROVIDER: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2060616124/MetadataProvider";
const DOC_SESSIONS: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334342/Sessions";
const DOC_APP_DEFAULTS: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2063695997/ApplicationDefaults";
const DOC_ATTR_FILTER: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334516/AttributeFilter";
const DOC_ATTR_EXTRACTOR: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334421/XMLAttributeExtractor";
const DOC_SPCONFIG: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2063695926/SPConfig";

pub fn run(config: &DiscoveredConfig) -> Vec<CheckResult> {
    let mut results = Vec::new();

    let sc = match config.shibboleth_config.as_ref() {
        Some(sc) => sc,
        None => return results,
    };

    // OPS-001: supportContact is placeholder (example.org, localhost)
    if let Some(ref errors) = sc.errors {
        if let Some(ref contact) = errors.support_contact {
            let lower = contact.to_lowercase();
            if lower.contains("example.org")
                || lower.contains("example.com")
                || lower.contains("localhost")
            {
                results.push(
                    CheckResult::fail(
                        "OPS-001",
                        CAT,
                        Severity::Warning,
                        &format!(
                            "Errors supportContact appears to be a placeholder: {}",
                            contact
                        ),
                        Some("Set supportContact to a real support email address"),
                    )
                    .with_doc(DOC_ERRORS),
                );
            } else {
                results.push(CheckResult::pass(
                    "OPS-001",
                    CAT,
                    Severity::Warning,
                    "Errors supportContact is not a placeholder",
                ));
            }
        }
    }

    // OPS-002: Remote MetadataProvider reloadInterval outside 5min–24hr
    for mp in &sc.metadata_providers {
        let is_remote = mp.uri.is_some() || mp.url.is_some();
        if !is_remote || mp.provider_type == "Chaining" {
            continue;
        }
        if let Some(ref interval_str) = mp.reload_interval {
            if let Ok(interval) = interval_str.parse::<u64>() {
                if interval < 300 {
                    results.push(
                        CheckResult::fail(
                            "OPS-002",
                            CAT,
                            Severity::Info,
                            &format!(
                                "MetadataProvider reloadInterval is {}s (< 5 minutes)",
                                interval
                            ),
                            Some(
                                "Very frequent reloads waste bandwidth; consider 1800 (30 minutes)",
                            ),
                        )
                        .with_doc(DOC_METADATA_PROVIDER),
                    );
                } else if interval > 86400 {
                    results.push(
                        CheckResult::fail(
                            "OPS-002",
                            CAT,
                            Severity::Info,
                            &format!(
                                "MetadataProvider reloadInterval is {}s (> 24 hours)",
                                interval
                            ),
                            Some("Infrequent reloads may delay metadata updates; consider 1800–86400 seconds"),
                        )
                        .with_doc(DOC_METADATA_PROVIDER),
                    );
                } else {
                    results.push(CheckResult::pass(
                        "OPS-002",
                        CAT,
                        Severity::Info,
                        &format!(
                            "MetadataProvider reloadInterval is {}s (within recommended range)",
                            interval
                        ),
                    ));
                }
            }
        }
    }

    // OPS-003: Session lifetime < timeout (logical inconsistency)
    if let Some(ref sessions) = sc.sessions {
        if let (Some(ref lifetime_str), Some(ref timeout_str)) =
            (&sessions.lifetime, &sessions.timeout)
        {
            if let (Ok(lifetime), Ok(timeout)) =
                (lifetime_str.parse::<u64>(), timeout_str.parse::<u64>())
            {
                if lifetime > 0 && timeout > 0 && lifetime < timeout {
                    results.push(
                        CheckResult::fail(
                            "OPS-003",
                            CAT,
                            Severity::Info,
                            &format!(
                                "Session lifetime ({}s) is less than timeout ({}s)",
                                lifetime, timeout
                            ),
                            Some("Session lifetime should be >= timeout; otherwise sessions expire before the idle timeout fires"),
                        )
                        .with_doc(DOC_SESSIONS),
                    );
                } else if lifetime > 0 && timeout > 0 {
                    results.push(CheckResult::pass(
                        "OPS-003",
                        CAT,
                        Severity::Info,
                        &format!("Session lifetime ({}s) >= timeout ({}s)", lifetime, timeout),
                    ));
                }
            }
        }
    }

    // OPS-004: REMOTE_USER uses mutable attribute (displayName/mail/cn)
    if let Some(ref app) = sc.application_defaults {
        if let Some(ref remote_user) = app.remote_user {
            let mutable_attrs = ["displayName", "mail", "cn", "givenName", "sn"];
            let attrs: Vec<&str> = remote_user.split_whitespace().collect();
            let mut has_mutable = false;
            for attr in &attrs {
                if mutable_attrs.contains(attr) {
                    results.push(
                        CheckResult::fail(
                            "OPS-004",
                            CAT,
                            Severity::Info,
                            &format!(
                                "REMOTE_USER includes mutable attribute '{}'",
                                attr
                            ),
                            Some("Prefer a stable identifier like 'eppn' or 'persistent-id' for REMOTE_USER"),
                        )
                        .with_doc(DOC_APP_DEFAULTS),
                    );
                    has_mutable = true;
                }
            }
            if !has_mutable {
                results.push(CheckResult::pass(
                    "OPS-004",
                    CAT,
                    Severity::Info,
                    "REMOTE_USER does not use mutable attributes",
                ));
            }
        }
    }

    // OPS-005: Scoped attrs in attr-map lack scope validation in attr-policy
    if let Some(ref map) = config.attribute_map {
        // Use decoder_type to identify scoped attributes
        let scoped_in_map: Vec<&str> = map
            .attributes
            .iter()
            .filter(|a| {
                a.decoder_type
                    .as_deref()
                    .is_some_and(|d| d.contains("Scoped"))
            })
            .map(|a| a.id.as_str())
            .collect();

        if !scoped_in_map.is_empty() {
            if let Some(ref policy) = config.attribute_policy {
                let policy_scope_ids: HashSet<&str> = policy
                    .rules
                    .iter()
                    .filter(|r| r.has_scope_match)
                    .map(|r| r.attribute_id.as_str())
                    .collect();

                let mut missing_scope = Vec::new();
                for attr in &scoped_in_map {
                    if !policy_scope_ids.contains(attr) {
                        missing_scope.push(*attr);
                    }
                }

                if missing_scope.is_empty() {
                    results.push(CheckResult::pass(
                        "OPS-005",
                        CAT,
                        Severity::Warning,
                        "All scoped attributes have scope validation in attribute-policy.xml",
                    ));
                } else {
                    for attr in &missing_scope {
                        results.push(
                            CheckResult::fail(
                                "OPS-005",
                                CAT,
                                Severity::Warning,
                                &format!(
                                    "Scoped attribute '{}' lacks ScopeMatchesShibMDScope in attribute-policy.xml",
                                    attr
                                ),
                                Some("Add a ScopeMatchesShibMDScope rule to prevent scope injection attacks"),
                            )
                            .with_doc(DOC_ATTR_FILTER),
                        );
                    }
                }
            }
        }
    }

    // OPS-006: Remote MetadataProvider has no explicit maxRefreshDelay
    {
        let mut has_missing = false;
        for mp in &sc.metadata_providers {
            let is_remote = mp.uri.is_some() || mp.url.is_some();
            if !is_remote || mp.provider_type == "Chaining" {
                continue;
            }
            if mp.max_refresh_delay.is_none() {
                results.push(
                    CheckResult::fail(
                        "OPS-006",
                        CAT,
                        Severity::Info,
                        &format!(
                            "Remote MetadataProvider type='{}' has no explicit maxRefreshDelay",
                            mp.provider_type
                        ),
                        Some("Set maxRefreshDelay to control how often metadata is refreshed (e.g., maxRefreshDelay=\"3600\")"),
                    )
                    .with_doc(DOC_METADATA_PROVIDER),
                );
                has_missing = true;
            }
        }
        if !has_missing {
            let has_remote = sc
                .metadata_providers
                .iter()
                .any(|mp| mp.uri.is_some() || mp.url.is_some());
            if has_remote {
                results.push(CheckResult::pass(
                    "OPS-006",
                    CAT,
                    Severity::Info,
                    "All remote MetadataProviders have maxRefreshDelay configured",
                ));
            }
        }
    }

    // OPS-007: idpHistory enabled without idpHistoryDays
    if let Some(ref sessions) = sc.sessions {
        if sessions.idp_history.as_deref().is_some_and(|v| v == "true") {
            if sessions.idp_history_days.is_some() {
                results.push(CheckResult::pass(
                    "OPS-007",
                    CAT,
                    Severity::Info,
                    "idpHistory is enabled with idpHistoryDays configured",
                ));
            } else {
                results.push(
                    CheckResult::fail(
                        "OPS-007",
                        CAT,
                        Severity::Info,
                        "idpHistory is enabled but idpHistoryDays is not set",
                        Some("Set idpHistoryDays on <Sessions> to control how long IdP history is retained"),
                    )
                    .with_doc(DOC_SESSIONS),
                );
            }
        }
    }

    // OPS-008: No scoped attributes (ScopedAttributeDecoder) in attribute-map.xml
    if let Some(ref map) = config.attribute_map {
        let has_scoped = map.attributes.iter().any(|a| {
            a.decoder_type
                .as_deref()
                .is_some_and(|d| d.contains("Scoped"))
        });
        if has_scoped {
            results.push(CheckResult::pass(
                "OPS-008",
                CAT,
                Severity::Info,
                "attribute-map.xml contains scoped attribute(s) with ScopedAttributeDecoder",
            ));
        } else if !map.attributes.is_empty() {
            results.push(
                CheckResult::fail(
                    "OPS-008",
                    CAT,
                    Severity::Info,
                    "No ScopedAttributeDecoder found in attribute-map.xml",
                    Some("Scoped attributes (like eppn) should use ScopedAttributeDecoder for proper scope handling"),
                )
                .with_doc(DOC_ATTR_EXTRACTOR),
            );
        }
    }

    // OPS-009: MetadataGenerator handler present (not for production)
    {
        let has_metadata_gen = sc
            .handlers
            .iter()
            .any(|h| h.handler_type.contains("MetadataGenerator"));
        if has_metadata_gen {
            results.push(
                CheckResult::fail(
                    "OPS-009",
                    CAT,
                    Severity::Info,
                    "MetadataGenerator handler is enabled",
                    Some("MetadataGenerator exposes SP metadata publicly; consider restricting or removing for production"),
                )
                .with_doc(DOC_SESSIONS),
            );
        } else {
            results.push(CheckResult::pass(
                "OPS-009",
                CAT,
                Severity::Info,
                "No MetadataGenerator handler found",
            ));
        }
    }

    // OPS-010: No Notify endpoints configured for logout notification
    if sc.notify_endpoints.is_empty() {
        results.push(
            CheckResult::fail(
                "OPS-010",
                CAT,
                Severity::Info,
                "No <Notify> endpoints configured for logout notification",
                Some("Add <Notify> elements in <Sessions> to receive logout notifications"),
            )
            .with_doc(DOC_SESSIONS),
        );
    } else {
        results.push(CheckResult::pass(
            "OPS-010",
            CAT,
            Severity::Info,
            &format!(
                "{} Notify endpoint(s) configured",
                sc.notify_endpoints.len()
            ),
        ));
    }

    // OPS-011: supportContact not a valid email (no @)
    if let Some(ref errors) = sc.errors {
        if let Some(ref contact) = errors.support_contact {
            if contact.contains('@') {
                results.push(CheckResult::pass(
                    "OPS-011",
                    CAT,
                    Severity::Info,
                    "Errors supportContact looks like a valid email address",
                ));
            } else {
                results.push(
                    CheckResult::fail(
                        "OPS-011",
                        CAT,
                        Severity::Info,
                        &format!(
                            "Errors supportContact does not look like an email: {}",
                            contact
                        ),
                        Some("Set supportContact to a valid email address (must contain '@')"),
                    )
                    .with_doc(DOC_ERRORS),
                );
            }
        }
    }

    // OPS-012: REMOTE_USER has multiple attributes (fallback chain)
    if let Some(ref app) = sc.application_defaults {
        if let Some(ref remote_user) = app.remote_user {
            let attrs: Vec<&str> = remote_user.split_whitespace().collect();
            if attrs.len() > 1 {
                results.push(
                    CheckResult::fail(
                        "OPS-012",
                        CAT,
                        Severity::Info,
                        &format!(
                            "REMOTE_USER has {} attributes as fallback chain: {}",
                            attrs.len(),
                            remote_user
                        ),
                        Some("Multiple REMOTE_USER attributes form a fallback chain; ensure the order is intentional"),
                    )
                    .with_doc(DOC_APP_DEFAULTS),
                );
            } else if attrs.len() == 1 {
                results.push(CheckResult::pass(
                    "OPS-012",
                    CAT,
                    Severity::Info,
                    "REMOTE_USER uses a single attribute",
                ));
            }
        }
    }

    // OPS-013: clockSkew not explicitly set (defaults to 180s)
    if sc.clock_skew.is_some() {
        results.push(CheckResult::pass(
            "OPS-013",
            CAT,
            Severity::Info,
            &format!(
                "clockSkew is explicitly set to {}s",
                sc.clock_skew.as_deref().unwrap_or("?")
            ),
        ));
    } else {
        results.push(
            CheckResult::fail(
                "OPS-013",
                CAT,
                Severity::Info,
                "clockSkew not explicitly set (defaults to 180s)",
                Some("Set clockSkew on <SPConfig> to explicitly control clock skew tolerance"),
            )
            .with_doc(DOC_SPCONFIG),
        );
    }

    // OPS-014: No TransportOption TLS constraints configured
    if let Some(ref content) = config.shibboleth_xml_content {
        if content.contains("TransportOption") {
            results.push(CheckResult::pass(
                "OPS-014",
                CAT,
                Severity::Info,
                "TransportOption TLS constraints are configured",
            ));
        } else {
            results.push(
                CheckResult::fail(
                    "OPS-014",
                    CAT,
                    Severity::Info,
                    "No <TransportOption> TLS constraints configured",
                    Some("Add <TransportOption> elements to configure TLS settings for outbound connections"),
                )
                .with_doc(DOC_APP_DEFAULTS),
            );
        }
    }

    // OPS-015: reloadChanges not set on external XML resources
    if let Some(ref content) = config.shibboleth_xml_content {
        // Check if any external resource references use reloadChanges
        if content.contains("reloadChanges=") {
            results.push(CheckResult::pass(
                "OPS-015",
                CAT,
                Severity::Info,
                "reloadChanges is configured on external XML resource(s)",
            ));
        } else {
            // Only flag if there are external XML resources (AttributeExtractor/AttributeFilter with path)
            let has_external = sc
                .attribute_extractor_paths
                .iter()
                .chain(sc.attribute_filter_paths.iter())
                .any(|p| !p.is_empty());
            if has_external {
                results.push(
                    CheckResult::fail(
                        "OPS-015",
                        CAT,
                        Severity::Info,
                        "reloadChanges not set on external XML resources",
                        Some("Add reloadChanges=\"true\" to AttributeExtractor/AttributeFilter to auto-reload on file changes"),
                    )
                    .with_doc(DOC_APP_DEFAULTS),
                );
            }
        }
    }

    results
}
