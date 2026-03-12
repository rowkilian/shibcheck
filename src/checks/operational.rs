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
const DOC_APP_OVERRIDE: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334278/ApplicationOverride";

use crate::model::shibboleth_config::ShibbolethConfig;

/// Summarise the parent `<Sessions>` attributes that an override will lose.
fn describe_parent_sessions(sc: &ShibbolethConfig) -> String {
    let Some(ref s) = sc.sessions else {
        return "no explicit attributes".to_string();
    };
    let mut parts = Vec::new();
    if let Some(ref v) = s.handler_ssl {
        parts.push(format!("handlerSSL=\"{}\"", v));
    }
    if let Some(ref v) = s.cookie_props {
        parts.push(format!("cookieProps=\"{}\"", v));
    }
    if let Some(ref v) = s.lifetime {
        parts.push(format!("lifetime=\"{}\"", v));
    }
    if let Some(ref v) = s.timeout {
        parts.push(format!("timeout=\"{}\"", v));
    }
    if let Some(ref v) = s.redirect_limit {
        parts.push(format!("redirectLimit=\"{}\"", v));
    }
    if let Some(ref v) = s.consistent_address {
        parts.push(format!("consistentAddress=\"{}\"", v));
    }
    if let Some(ref v) = s.same_site_fallback {
        parts.push(format!("sameSiteFallback=\"{}\"", v));
    }
    if let Some(ref v) = s.post_data {
        parts.push(format!("postData=\"{}\"", v));
    }
    if parts.is_empty() {
        "no explicit attributes".to_string()
    } else {
        parts.join(", ")
    }
}

/// Summarise the parent `<Errors>` attributes that an override will lose.
fn describe_parent_errors(sc: &ShibbolethConfig) -> String {
    let Some(ref e) = sc.errors else {
        return "no explicit attributes".to_string();
    };
    let mut parts = Vec::new();
    if let Some(ref v) = e.support_contact {
        parts.push(format!("supportContact=\"{}\"", v));
    }
    if let Some(ref v) = e.help_location {
        parts.push(format!("helpLocation=\"{}\"", v));
    }
    if let Some(ref v) = e.style_sheet {
        parts.push(format!("styleSheet=\"{}\"", v));
    }
    if e.session_error.is_some()
        || e.access_error.is_some()
        || e.ssl_error.is_some()
        || e.metadata_error.is_some()
    {
        parts.push("custom error pages".to_string());
    }
    if parts.is_empty() {
        "no explicit attributes".to_string()
    } else {
        parts.join(", ")
    }
}

/// Summarise the parent `<CredentialResolver>` that an override will lose.
fn describe_parent_credentials(sc: &ShibbolethConfig) -> String {
    if sc.credential_resolvers.is_empty() {
        return "no CredentialResolver".to_string();
    }
    let summaries: Vec<String> = sc
        .credential_resolvers
        .iter()
        .map(|cr| {
            let mut desc = format!("type=\"{}\"", cr.resolver_type);
            if let Some(ref u) = cr.use_attr {
                desc.push_str(&format!(" use=\"{}\"", u));
            }
            if let Some(ref c) = cr.certificate {
                desc.push_str(&format!(" certificate=\"{}\"", c));
            }
            if let Some(ref k) = cr.key {
                desc.push_str(&format!(" key=\"{}\"", k));
            }
            desc
        })
        .collect();
    format!(
        "{} CredentialResolver(s): {}",
        summaries.len(),
        summaries.join("; ")
    )
}

/// Summarise the parent `<MetadataProvider>` sources that an override will lose.
fn describe_parent_metadata(sc: &ShibbolethConfig) -> String {
    let non_chaining: Vec<_> = sc
        .metadata_providers
        .iter()
        .filter(|mp| mp.provider_type != "Chaining")
        .collect();
    if non_chaining.is_empty() {
        return "no MetadataProvider".to_string();
    }
    let summaries: Vec<String> = non_chaining
        .iter()
        .map(|mp| {
            let source = mp
                .uri
                .as_deref()
                .or(mp.url.as_deref())
                .or(mp.path.as_deref())
                .unwrap_or("(inline)");
            format!("type=\"{}\" source={}", mp.provider_type, source)
        })
        .collect();
    format!(
        "{} MetadataProvider(s): {}",
        summaries.len(),
        summaries.join("; ")
    )
}

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
                                "MetadataProvider{} reloadInterval is {}s (< 5 minutes)",
                                mp.label(),
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
                                "MetadataProvider{} reloadInterval is {}s (> 24 hours)",
                                mp.label(),
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
                            "MetadataProvider{} reloadInterval is {}s (within recommended range)",
                            mp.label(),
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
                            "Remote MetadataProvider type='{}'{} has no explicit maxRefreshDelay",
                            mp.provider_type,
                            mp.label()
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

    // OPS-016: sameSiteFallback not set on Sessions
    if let Some(ref sessions) = sc.sessions {
        if sessions.same_site_fallback.is_some() {
            results.push(CheckResult::pass(
                "OPS-016",
                CAT,
                Severity::Info,
                "sameSiteFallback is set on Sessions",
            ));
        } else {
            results.push(
                CheckResult::fail(
                    "OPS-016",
                    CAT,
                    Severity::Info,
                    "sameSiteFallback not set on Sessions (needed for Safari/older browsers)",
                    Some("Set sameSiteFallback=\"true\" on <Sessions> for compatibility with older browsers"),
                )
                .with_doc(DOC_SESSIONS),
            );
        }
    }

    // OPS-017: relayState not configured on Sessions
    if let Some(ref sessions) = sc.sessions {
        if sessions.relay_state.is_some() {
            results.push(CheckResult::pass(
                "OPS-017",
                CAT,
                Severity::Info,
                "relayState is configured on Sessions",
            ));
        } else {
            results.push(
                CheckResult::fail(
                    "OPS-017",
                    CAT,
                    Severity::Info,
                    "relayState not configured on Sessions (no post-login redirect control)",
                    Some("Set relayState on <Sessions> to control post-login redirect behavior"),
                )
                .with_doc(DOC_SESSIONS),
            );
        }
    }

    // OPS-018: postData not configured on Sessions
    if let Some(ref sessions) = sc.sessions {
        if sessions.post_data.is_some() {
            results.push(CheckResult::pass(
                "OPS-018",
                CAT,
                Severity::Info,
                "postData is configured on Sessions",
            ));
        } else {
            results.push(
                CheckResult::fail(
                    "OPS-018",
                    CAT,
                    Severity::Info,
                    "postData not configured on Sessions (POST data may be lost during SSO)",
                    Some("Set postData on <Sessions> to preserve POST data during SSO redirects"),
                )
                .with_doc(DOC_SESSIONS),
            );
        }
    }

    // OPS-019: Remote MetadataProvider has no reloadInterval set
    {
        let mut has_missing = false;
        for mp in &sc.metadata_providers {
            let is_remote = mp.uri.is_some() || mp.url.is_some();
            if !is_remote || mp.provider_type == "Chaining" {
                continue;
            }
            if mp.reload_interval.is_none() {
                results.push(
                    CheckResult::fail(
                        "OPS-019",
                        CAT,
                        Severity::Info,
                        &format!(
                            "Remote MetadataProvider type='{}'{} has no reloadInterval set",
                            mp.provider_type,
                            mp.label()
                        ),
                        Some("Set reloadInterval on remote MetadataProvider to control refresh frequency"),
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
                .any(|mp| (mp.uri.is_some() || mp.url.is_some()) && mp.provider_type != "Chaining");
            if has_remote {
                results.push(CheckResult::pass(
                    "OPS-019",
                    CAT,
                    Severity::Info,
                    "All remote MetadataProviders have reloadInterval configured",
                ));
            }
        }
    }

    // OPS-020: supportContact has mailto: prefix (SP adds it automatically)
    if let Some(ref errors) = sc.errors {
        if let Some(ref contact) = errors.support_contact {
            if contact.starts_with("mailto:") {
                results.push(
                    CheckResult::fail(
                        "OPS-020",
                        CAT,
                        Severity::Info,
                        &format!(
                            "supportContact has 'mailto:' prefix: {} (SP adds it automatically, causing double-prefix)",
                            contact
                        ),
                        Some("Remove the 'mailto:' prefix from supportContact; the SP adds it automatically"),
                    )
                    .with_doc(DOC_ERRORS),
                );
            } else {
                results.push(CheckResult::pass(
                    "OPS-020",
                    CAT,
                    Severity::Info,
                    "supportContact does not have redundant mailto: prefix",
                ));
            }
        }
    }

    // OPS-021: No <AttributeFilter> element configured
    if sc.attribute_filter_paths.is_empty() {
        results.push(
            CheckResult::fail(
                "OPS-021",
                CAT,
                Severity::Info,
                "No <AttributeFilter> element configured (attribute release policy not applied)",
                Some("Add an <AttributeFilter> element with a path to an attribute policy file"),
            )
            .with_doc(DOC_ATTR_FILTER),
        );
    } else {
        results.push(CheckResult::pass(
            "OPS-021",
            CAT,
            Severity::Info,
            &format!(
                "{} AttributeFilter element(s) configured",
                sc.attribute_filter_paths.len()
            ),
        ));
    }

    // OPS-022: maxTimeSinceAuthn not set (no authentication freshness check)
    if let Some(ref sessions) = sc.sessions {
        if sessions.max_time_since_authn.is_some() {
            results.push(CheckResult::pass(
                "OPS-022",
                CAT,
                Severity::Info,
                &format!(
                    "maxTimeSinceAuthn is set: {}s",
                    sessions.max_time_since_authn.as_deref().unwrap_or("?")
                ),
            ));
        } else {
            results.push(
                CheckResult::fail(
                    "OPS-022",
                    CAT,
                    Severity::Info,
                    "maxTimeSinceAuthn not set on Sessions (no authentication freshness check)",
                    Some("Set maxTimeSinceAuthn on <Sessions> to enforce re-authentication after a period (e.g., 28800 for 8 hours)"),
                )
                .with_doc(DOC_SESSIONS),
            );
        }
    }

    // OPS-023: cookieLifetime set (persistent session cookies increase theft window)
    if let Some(ref sessions) = sc.sessions {
        if let Some(ref cl) = sessions.cookie_lifetime {
            results.push(
                CheckResult::fail(
                    "OPS-023",
                    CAT,
                    Severity::Info,
                    &format!(
                        "cookieLifetime is set to {} (persistent session cookies increase theft window)",
                        cl
                    ),
                    Some("Persistent cookies survive browser restarts; remove cookieLifetime for session-scoped cookies"),
                )
                .with_doc(DOC_SESSIONS),
            );
        } else {
            results.push(CheckResult::pass(
                "OPS-023",
                CAT,
                Severity::Info,
                "cookieLifetime is not set (session cookies are browser-scoped)",
            ));
        }
    }

    // OPS-024: MetadataProvider missing id in multi-provider setup (hard to debug)
    {
        let non_chaining: Vec<_> = sc
            .metadata_providers
            .iter()
            .filter(|mp| mp.provider_type != "Chaining")
            .collect();
        if non_chaining.len() >= 2 {
            let missing_id = non_chaining.iter().any(|mp| mp.id_attr.is_none());
            if missing_id {
                results.push(
                    CheckResult::fail(
                        "OPS-024",
                        CAT,
                        Severity::Info,
                        "One or more MetadataProviders lack an 'id' attribute in a multi-provider setup",
                        Some("Add id attributes to MetadataProviders to simplify debugging and log analysis"),
                    )
                    .with_doc(DOC_METADATA_PROVIDER),
                );
            } else {
                results.push(CheckResult::pass(
                    "OPS-024",
                    CAT,
                    Severity::Info,
                    "All MetadataProviders have id attributes in multi-provider setup",
                ));
            }
        }
    }

    // OPS-025: LogoutInitiator notifyWithout not set (local logouts won't trigger app notifications)
    for li in &sc.logout_initiators {
        if li.notify_without.is_none() {
            results.push(
                CheckResult::fail(
                    "OPS-025",
                    CAT,
                    Severity::Info,
                    "LogoutInitiator has no notifyWithout attribute (local logouts won't trigger application notifications)",
                    Some("Set notifyWithout=\"true\" on LogoutInitiator to send Notify messages even for local-only logouts"),
                )
                .with_doc(DOC_SESSIONS),
            );
        } else {
            results.push(CheckResult::pass(
                "OPS-025",
                CAT,
                Severity::Info,
                &format!(
                    "LogoutInitiator notifyWithout is set: {}",
                    li.notify_without.as_deref().unwrap_or("?")
                ),
            ));
        }
    }

    // OPS-026: LogoutInitiator asynchronous is true/unset (logout may not return to SP)
    for li in &sc.logout_initiators {
        let is_async = li.asynchronous.as_deref() != Some("false");
        if is_async && li.asynchronous.is_some() {
            results.push(
                CheckResult::fail(
                    "OPS-026",
                    CAT,
                    Severity::Info,
                    &format!(
                        "LogoutInitiator asynchronous=\"{}\" (IdP may not return user to SP after logout)",
                        li.asynchronous.as_deref().unwrap_or("true")
                    ),
                    Some("Set asynchronous=\"false\" on LogoutInitiator if you need the user to return to the SP after logout"),
                )
                .with_doc(DOC_SESSIONS),
            );
        }
    }

    // OPS-027: Multiple SessionInitiators without isDefault (first is implicitly default)
    if sc.session_initiators.len() > 1 {
        let has_explicit_default = sc
            .session_initiators
            .iter()
            .any(|si| si.is_default.is_some());
        if !has_explicit_default {
            results.push(
                CheckResult::fail(
                    "OPS-027",
                    CAT,
                    Severity::Info,
                    &format!(
                        "{} SessionInitiators found without any isDefault attribute (first is implicitly default)",
                        sc.session_initiators.len()
                    ),
                    Some("Add isDefault=\"true\" to one SessionInitiator to make the default explicit"),
                )
                .with_doc(DOC_SESSIONS),
            );
        } else {
            results.push(CheckResult::pass(
                "OPS-027",
                CAT,
                Severity::Info,
                "Multiple SessionInitiators with explicit isDefault",
            ));
        }
    }

    // OPS-028: forceAuthn="true" at Host scope (excessive re-auth for all paths)
    for cs in &sc.request_map_content_settings {
        if cs.element == "Host" && cs.force_authn.as_deref() == Some("true") {
            results.push(
                CheckResult::fail(
                    "OPS-028",
                    CAT,
                    Severity::Info,
                    &format!(
                        "<Host{}> has forceAuthn=\"true\" (all paths under this host will require re-authentication)",
                        cs.name
                            .as_ref()
                            .map(|n| format!(" name=\"{}\"", n))
                            .unwrap_or_default()
                    ),
                    Some("Consider moving forceAuthn=\"true\" to specific <Path> elements to avoid excessive re-authentication"),
                )
                .with_doc(DOC_SESSIONS),
            );
        }
    }

    // OPS-029: SignatureMetadataFilter verifyBackup="false" (backed-up metadata not verified)
    for mp in &sc.metadata_providers {
        for filter in &mp.filters {
            if filter.filter_type == "Signature" {
                if filter.verify_backup.as_deref() == Some("false") {
                    results.push(
                        CheckResult::fail(
                            "OPS-029",
                            CAT,
                            Severity::Info,
                            &format!("SignatureMetadataFilter{} has verifyBackup=\"false\" (backed-up metadata will not be signature-verified on load)", mp.label()),
                            Some("Set verifyBackup=\"true\" or remove the attribute to verify backed-up metadata"),
                        )
                        .with_doc(DOC_METADATA_PROVIDER),
                    );
                } else {
                    results.push(CheckResult::pass(
                        "OPS-029",
                        CAT,
                        Severity::Info,
                        &format!("SignatureMetadataFilter{} verifyBackup is not disabled", mp.label()),
                    ));
                }
            }
        }
    }

    // OPS-030: cipherSuites does not disable TLSv1/1.1
    if let Some(ref app) = sc.application_defaults {
        if let Some(ref suites) = app.cipher_suites {
            // Check if TLSv1 or TLSv1.1 are explicitly disabled
            let disables_tls10 = suites.contains("!TLSv1") || suites.contains("-TLSv1");
            let disables_tls11 = suites.contains("!TLSv1.1") || suites.contains("-TLSv1.1");
            if !disables_tls10 || !disables_tls11 {
                let mut missing = Vec::new();
                if !disables_tls10 {
                    missing.push("TLSv1");
                }
                if !disables_tls11 {
                    missing.push("TLSv1.1");
                }
                results.push(
                    CheckResult::fail(
                        "OPS-030",
                        CAT,
                        Severity::Info,
                        &format!(
                            "cipherSuites does not explicitly disable: {}",
                            missing.join(", ")
                        ),
                        Some("Add !TLSv1:!TLSv1.1 to cipherSuites to disable legacy TLS versions"),
                    )
                    .with_doc(DOC_APP_DEFAULTS),
                );
            } else {
                results.push(CheckResult::pass(
                    "OPS-030",
                    CAT,
                    Severity::Info,
                    "cipherSuites explicitly disables TLSv1 and TLSv1.1",
                ));
            }
        }
    }

    // OPS-031: DataSealer type="Static" (no key rotation for session recovery)
    if let Some(ref content) = config.shibboleth_xml_content {
        if content.contains("DataSealer") && content.contains("type=\"Static\"") {
            results.push(
                CheckResult::fail(
                    "OPS-031",
                    CAT,
                    Severity::Info,
                    "DataSealer type=\"Static\" found (no key rotation for session recovery)",
                    Some("Consider using DataSealer type=\"Versioned\" for automatic key rotation"),
                )
                .with_doc(DOC_SESSIONS),
            );
        } else if content.contains("DataSealer") {
            results.push(CheckResult::pass(
                "OPS-031",
                CAT,
                Severity::Info,
                "DataSealer does not use static key type",
            ));
        }
    }

    // OPS-036: homeURL not set on ApplicationDefaults (no fallback landing page)
    if let Some(ref app) = sc.application_defaults {
        if let Some(ref home_url) = app.home_url {
            if !home_url.is_empty() {
                results.push(CheckResult::pass(
                    "OPS-036",
                    CAT,
                    Severity::Info,
                    &format!("homeURL is set: {}", home_url),
                ));
            } else {
                results.push(
                    CheckResult::fail(
                        "OPS-036",
                        CAT,
                        Severity::Info,
                        "homeURL is set but empty on ApplicationDefaults",
                        Some("Set homeURL to a valid URL so the SP has a fallback landing page for error recovery"),
                    )
                    .with_doc(DOC_APP_DEFAULTS),
                );
            }
        } else {
            results.push(
                CheckResult::fail(
                    "OPS-036",
                    CAT,
                    Severity::Info,
                    "homeURL not set on ApplicationDefaults (no fallback landing page for error recovery)",
                    Some("Set homeURL on <ApplicationDefaults> to provide a landing page when the SP has no better redirect target"),
                )
                .with_doc(DOC_APP_DEFAULTS),
            );
        }
    }

    // OPS-037: homeURL is a placeholder (example.org, localhost)
    if let Some(ref app) = sc.application_defaults {
        if let Some(ref home_url) = app.home_url {
            let lower = home_url.to_lowercase();
            if lower.contains("example.org")
                || lower.contains("example.com")
                || lower.contains("localhost")
            {
                results.push(
                    CheckResult::fail(
                        "OPS-037",
                        CAT,
                        Severity::Warning,
                        &format!("homeURL appears to be a placeholder: {}", home_url),
                        Some("Set homeURL to a real URL for your application"),
                    )
                    .with_doc(DOC_APP_DEFAULTS),
                );
            } else if !home_url.is_empty() {
                results.push(CheckResult::pass(
                    "OPS-037",
                    CAT,
                    Severity::Warning,
                    "homeURL is not a placeholder",
                ));
            }
        }
    }

    // OPS-038: No custom error pages configured in <Errors>
    if let Some(ref errors) = sc.errors {
        let has_custom_pages = errors.session_error.is_some()
            || errors.access_error.is_some()
            || errors.ssl_error.is_some()
            || errors.metadata_error.is_some()
            || errors.local_logout.is_some()
            || errors.global_logout.is_some();
        if has_custom_pages {
            results.push(CheckResult::pass(
                "OPS-038",
                CAT,
                Severity::Info,
                "Custom error page(s) configured in <Errors>",
            ));
        } else {
            results.push(
                CheckResult::fail(
                    "OPS-038",
                    CAT,
                    Severity::Info,
                    "No custom error pages configured in <Errors> (users see default SP error pages)",
                    Some("Add session, access, ssl, metadata, localLogout, or globalLogout attributes to <Errors> for user-friendly error pages"),
                )
                .with_doc(DOC_ERRORS),
            );
        }
    }

    // OPS-039: helpLocation not set on <Errors>
    if let Some(ref errors) = sc.errors {
        if let Some(ref help) = errors.help_location {
            if !help.is_empty() {
                results.push(CheckResult::pass(
                    "OPS-039",
                    CAT,
                    Severity::Info,
                    &format!("helpLocation is set on Errors: {}", help),
                ));
            } else {
                results.push(
                    CheckResult::fail(
                        "OPS-039",
                        CAT,
                        Severity::Info,
                        "helpLocation is set but empty on <Errors>",
                        Some("Set helpLocation to a URL where users can find help or documentation"),
                    )
                    .with_doc(DOC_ERRORS),
                );
            }
        } else {
            results.push(
                CheckResult::fail(
                    "OPS-039",
                    CAT,
                    Severity::Info,
                    "helpLocation not set on <Errors> (error pages have no link to help documentation)",
                    Some("Set helpLocation on <Errors> to provide a support/documentation URL on error pages"),
                )
                .with_doc(DOC_ERRORS),
            );
        }
    }

    // OPS-040: Session lifetime not explicitly set (no absolute session cap)
    if let Some(ref sessions) = sc.sessions {
        if sessions.lifetime.is_some() {
            results.push(CheckResult::pass(
                "OPS-040",
                CAT,
                Severity::Info,
                &format!(
                    "Session lifetime is explicitly set: {}s",
                    sessions.lifetime.as_deref().unwrap_or("?")
                ),
            ));
        } else {
            results.push(
                CheckResult::fail(
                    "OPS-040",
                    CAT,
                    Severity::Info,
                    "Session lifetime not explicitly set (defaults to 28800s / 8 hours)",
                    Some("Set lifetime on <Sessions> to explicitly control maximum session duration"),
                )
                .with_doc(DOC_SESSIONS),
            );
        }
    }

    // OPS-041: Session timeout not explicitly set (no idle timeout)
    if let Some(ref sessions) = sc.sessions {
        if sessions.timeout.is_some() {
            results.push(CheckResult::pass(
                "OPS-041",
                CAT,
                Severity::Info,
                &format!(
                    "Session timeout is explicitly set: {}s",
                    sessions.timeout.as_deref().unwrap_or("?")
                ),
            ));
        } else {
            results.push(
                CheckResult::fail(
                    "OPS-041",
                    CAT,
                    Severity::Info,
                    "Session timeout not explicitly set (defaults to 3600s / 1 hour)",
                    Some("Set timeout on <Sessions> to explicitly control idle session expiration"),
                )
                .with_doc(DOC_SESSIONS),
            );
        }
    }

    // OPS-042: Remote MetadataProvider has no MetadataFilter children (metadata not validated)
    {
        let mut any_unfiltered = false;
        for mp in &sc.metadata_providers {
            let is_remote = mp.uri.is_some() || mp.url.is_some();
            if !is_remote || mp.provider_type == "Chaining" {
                continue;
            }
            if mp.filters.is_empty() {
                results.push(
                    CheckResult::fail(
                        "OPS-042",
                        CAT,
                        Severity::Warning,
                        &format!(
                            "Remote MetadataProvider type='{}'{} has no MetadataFilter children (metadata accepted without validation)",
                            mp.provider_type,
                            mp.label()
                        ),
                        Some("Add MetadataFilter elements (e.g., Signature, RequireValidUntil) to validate remote metadata"),
                    )
                    .with_doc(DOC_METADATA_PROVIDER),
                );
                any_unfiltered = true;
            }
        }
        if !any_unfiltered {
            let has_remote = sc
                .metadata_providers
                .iter()
                .any(|mp| (mp.uri.is_some() || mp.url.is_some()) && mp.provider_type != "Chaining");
            if has_remote {
                results.push(CheckResult::pass(
                    "OPS-042",
                    CAT,
                    Severity::Warning,
                    "All remote MetadataProviders have MetadataFilter children",
                ));
            }
        }
    }

    // OPS-043: Errors styleSheet not set (unstyled error pages)
    if let Some(ref errors) = sc.errors {
        if let Some(ref ss) = errors.style_sheet {
            if !ss.is_empty() {
                results.push(CheckResult::pass(
                    "OPS-043",
                    CAT,
                    Severity::Info,
                    &format!("Errors styleSheet is set: {}", ss),
                ));
            } else {
                results.push(
                    CheckResult::fail(
                        "OPS-043",
                        CAT,
                        Severity::Info,
                        "Errors styleSheet is set but empty",
                        Some("Set styleSheet on <Errors> to a CSS file path for branded error pages"),
                    )
                    .with_doc(DOC_ERRORS),
                );
            }
        } else {
            results.push(
                CheckResult::fail(
                    "OPS-043",
                    CAT,
                    Severity::Info,
                    "Errors styleSheet not set (error pages will use default unstyled appearance)",
                    Some("Set styleSheet on <Errors> to a CSS file path for branded, user-friendly error pages"),
                )
                .with_doc(DOC_ERRORS),
            );
        }
    }

    // OPS-044: No requireSession on any Host or Path in RequestMap
    if !sc.request_map_content_settings.is_empty() {
        let has_require_session = sc
            .request_map_content_settings
            .iter()
            .any(|cs| cs.require_session.as_deref() == Some("true"));
        if has_require_session {
            results.push(CheckResult::pass(
                "OPS-044",
                CAT,
                Severity::Info,
                "At least one Host/Path has requireSession=\"true\"",
            ));
        } else {
            results.push(
                CheckResult::fail(
                    "OPS-044",
                    CAT,
                    Severity::Info,
                    "No Host or Path in RequestMap has requireSession=\"true\" (SP not enforcing sessions on any path)",
                    Some("Set requireSession=\"true\" on <Host> or <Path> elements to require authentication"),
                )
                .with_doc(DOC_SESSIONS),
            );
        }
    }

    // OPS-045: redirectToSSL not set on any content settings
    if !sc.request_map_content_settings.is_empty() {
        let has_redirect_ssl = sc
            .request_map_content_settings
            .iter()
            .any(|cs| cs.redirect_to_ssl.is_some());
        if has_redirect_ssl {
            results.push(CheckResult::pass(
                "OPS-045",
                CAT,
                Severity::Info,
                "redirectToSSL is set on at least one Host/Path",
            ));
        } else {
            results.push(
                CheckResult::fail(
                    "OPS-045",
                    CAT,
                    Severity::Info,
                    "redirectToSSL not set on any Host or Path (HTTP requests won't be auto-redirected to HTTPS by the SP)",
                    Some("Set redirectToSSL=\"443\" on <Host> or <Path> elements to auto-redirect HTTP to HTTPS"),
                )
                .with_doc(DOC_SESSIONS),
            );
        }
    }

    // OPS-046: discoveryURL set without explicit discoveryProtocol
    if let Some(ref sessions) = sc.sessions {
        if sessions.sso_discovery_url.is_some() {
            if sessions.sso_discovery_protocol.is_some() {
                results.push(CheckResult::pass(
                    "OPS-046",
                    CAT,
                    Severity::Info,
                    &format!(
                        "discoveryProtocol is explicitly set: {}",
                        sessions.sso_discovery_protocol.as_deref().unwrap_or("?")
                    ),
                ));
            } else {
                results.push(
                    CheckResult::fail(
                        "OPS-046",
                        CAT,
                        Severity::Info,
                        "discoveryURL is set but discoveryProtocol is not explicitly specified (defaults to SAMLDS)",
                        Some("Set discoveryProtocol on <SSO> to make the discovery protocol explicit (e.g., \"SAMLDS\")"),
                    )
                    .with_doc(DOC_SESSIONS),
                );
            }
        }
    }

    // OPS-047: MetadataProvider validate attribute not set to true
    {
        let mut any_not_validated = false;
        for mp in &sc.metadata_providers {
            if mp.provider_type == "Chaining" {
                continue;
            }
            match mp.validate_attr.as_deref() {
                Some("true") | Some("1") => {}
                _ => {
                    let source = mp
                        .uri
                        .as_deref()
                        .or(mp.url.as_deref())
                        .or(mp.path.as_deref())
                        .unwrap_or("(unknown)");
                    results.push(
                        CheckResult::fail(
                            "OPS-047",
                            CAT,
                            Severity::Info,
                            &format!(
                                "MetadataProvider{} source={} does not set validate=\"true\" (schema validation disabled)",
                                mp.label(),
                                source
                            ),
                            Some("Set validate=\"true\" on MetadataProvider to validate metadata XML against the SAML schema"),
                        )
                        .with_doc(DOC_METADATA_PROVIDER),
                    );
                    any_not_validated = true;
                }
            }
        }
        if !any_not_validated && !sc.metadata_providers.is_empty() {
            let has_non_chaining = sc
                .metadata_providers
                .iter()
                .any(|mp| mp.provider_type != "Chaining");
            if has_non_chaining {
                results.push(CheckResult::pass(
                    "OPS-047",
                    CAT,
                    Severity::Info,
                    "All MetadataProviders have validate=\"true\"",
                ));
            }
        }
    }

    // OPS-048: No signing or digest algorithm explicitly set on ApplicationDefaults
    if let Some(ref app) = sc.application_defaults {
        let has_signing_alg = app.signing_alg.is_some();
        let has_digest_alg = app.digest_alg.is_some();
        if has_signing_alg && has_digest_alg {
            results.push(CheckResult::pass(
                "OPS-048",
                CAT,
                Severity::Info,
                &format!(
                    "Signing and digest algorithms are explicitly set (signingAlg={}, digestAlg={})",
                    app.signing_alg.as_deref().unwrap_or("?"),
                    app.digest_alg.as_deref().unwrap_or("?")
                ),
            ));
        } else {
            let mut missing = Vec::new();
            if !has_signing_alg {
                missing.push("signingAlg");
            }
            if !has_digest_alg {
                missing.push("digestAlg");
            }
            results.push(
                CheckResult::fail(
                    "OPS-048",
                    CAT,
                    Severity::Info,
                    &format!(
                        "{} not explicitly set on ApplicationDefaults (SP uses built-in defaults)",
                        missing.join(" and ")
                    ),
                    Some("Set signingAlg and digestAlg on <ApplicationDefaults> to explicitly control signature algorithms (e.g., signingAlg=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\")"),
                )
                .with_doc(DOC_APP_DEFAULTS),
            );
        }
    }

    // OPS-049: RequireValidUntil MetadataFilter without maxValidityInterval
    for mp in &sc.metadata_providers {
        if mp.provider_type == "Chaining" {
            continue;
        }
        for filter in &mp.filters {
            if filter.filter_type.contains("RequireValidUntil") {
                if filter.max_validity_interval.is_some() {
                    results.push(CheckResult::pass(
                        "OPS-049",
                        CAT,
                        Severity::Info,
                        &format!(
                            "RequireValidUntil filter{} has maxValidityInterval={}",
                            mp.label(),
                            filter.max_validity_interval.as_deref().unwrap_or("?")
                        ),
                    ));
                } else {
                    results.push(
                        CheckResult::fail(
                            "OPS-049",
                            CAT,
                            Severity::Info,
                            &format!("RequireValidUntil MetadataFilter{} has no maxValidityInterval (no upper cap on how far in the future validUntil can be)", mp.label()),
                            Some("Set maxValidityInterval on RequireValidUntil filter to cap acceptable validity periods (e.g., maxValidityInterval=\"2592000\" for 30 days)"),
                        )
                        .with_doc(DOC_METADATA_PROVIDER),
                    );
                }
            }
        }
    }

    // OPS-050: No AttributeExtractor path configured
    if sc.attribute_extractor_paths.is_empty() {
        results.push(
            CheckResult::fail(
                "OPS-050",
                CAT,
                Severity::Info,
                "No <AttributeExtractor> path configured (no attributes will be extracted from assertions unless using defaults)",
                Some("Add an <AttributeExtractor> element with a path to an attribute-map.xml file"),
            )
            .with_doc(DOC_ATTR_EXTRACTOR),
        );
    } else {
        results.push(CheckResult::pass(
            "OPS-050",
            CAT,
            Severity::Info,
            &format!(
                "{} AttributeExtractor path(s) configured",
                sc.attribute_extractor_paths.len()
            ),
        ));
    }

    // OPS-051: CredentialResolver use attribute not set in multi-resolver setup
    {
        let non_chaining: Vec<_> = sc
            .credential_resolvers
            .iter()
            .filter(|cr| cr.resolver_type != "Chaining")
            .collect();
        if non_chaining.len() >= 2 {
            let missing_use = non_chaining.iter().any(|cr| cr.use_attr.is_none());
            if missing_use {
                results.push(
                    CheckResult::fail(
                        "OPS-051",
                        CAT,
                        Severity::Warning,
                        "Multiple CredentialResolvers without explicit 'use' attribute (unclear which is for signing vs encryption)",
                        Some("Add use=\"signing\" or use=\"encryption\" to each CredentialResolver to clarify their purpose"),
                    )
                    .with_doc(DOC_APP_DEFAULTS),
                );
            } else {
                results.push(CheckResult::pass(
                    "OPS-051",
                    CAT,
                    Severity::Warning,
                    "All CredentialResolvers have explicit 'use' attributes",
                ));
            }
        }
    }

    // OPS-052: Multiple ApplicationOverrides defined (configuration complexity)
    if sc.application_override_ids.len() > 3 {
        results.push(
            CheckResult::fail(
                "OPS-052",
                CAT,
                Severity::Info,
                &format!(
                    "{} ApplicationOverride elements defined (complex multi-application setup)",
                    sc.application_override_ids.len()
                ),
                Some("Large numbers of ApplicationOverrides increase maintenance burden; document the purpose of each override"),
            )
            .with_doc(DOC_APP_OVERRIDE),
        );
    } else if !sc.application_override_ids.is_empty() {
        results.push(CheckResult::pass(
            "OPS-052",
            CAT,
            Severity::Info,
            &format!(
                "{} ApplicationOverride(s) defined",
                sc.application_override_ids.len()
            ),
        ));
    }

    // OPS-053: Local MetadataProvider has no reloadInterval
    {
        let mut any_local_no_reload = false;
        for mp in &sc.metadata_providers {
            if mp.provider_type == "Chaining" {
                continue;
            }
            let is_local = mp.path.is_some() || mp.file_attr.is_some() || mp.source_directory.is_some();
            let is_remote = mp.uri.is_some() || mp.url.is_some();
            if is_local && !is_remote && mp.reload_interval.is_none() {
                let source = mp
                    .path
                    .as_deref()
                    .or(mp.file_attr.as_deref())
                    .or(mp.source_directory.as_deref())
                    .unwrap_or("(unknown)");
                results.push(
                    CheckResult::fail(
                        "OPS-053",
                        CAT,
                        Severity::Info,
                        &format!(
                            "Local MetadataProvider{} source={} has no reloadInterval (file changes won't be detected automatically)",
                            mp.label(),
                            source
                        ),
                        Some("Set reloadInterval on local MetadataProvider to auto-detect file updates (e.g., reloadInterval=\"3600\")"),
                    )
                    .with_doc(DOC_METADATA_PROVIDER),
                );
                any_local_no_reload = true;
            }
        }
        if !any_local_no_reload {
            let has_local = sc.metadata_providers.iter().any(|mp| {
                mp.provider_type != "Chaining"
                    && (mp.path.is_some() || mp.file_attr.is_some() || mp.source_directory.is_some())
                    && mp.uri.is_none()
                    && mp.url.is_none()
            });
            if has_local {
                results.push(CheckResult::pass(
                    "OPS-053",
                    CAT,
                    Severity::Info,
                    "All local MetadataProviders have reloadInterval configured",
                ));
            }
        }
    }

    // OPS-054: No StorageService configured (in-memory session storage, lost on restart)
    if let Some(ref content) = config.shibboleth_xml_content {
        if content.contains("StorageService") {
            results.push(CheckResult::pass(
                "OPS-054",
                CAT,
                Severity::Info,
                "StorageService is configured for session persistence",
            ));
        } else {
            results.push(
                CheckResult::fail(
                    "OPS-054",
                    CAT,
                    Severity::Info,
                    "No <StorageService> configured (sessions stored in-memory, lost on SP restart)",
                    Some("Add a <StorageService> element for persistent session storage across SP restarts"),
                )
                .with_doc(DOC_SPCONFIG),
            );
        }
    }

    // OPS-055: OutOfProcess/InProcess extensions not configured
    if let Some(ref content) = config.shibboleth_xml_content {
        let has_oop = content.contains("<OutOfProcess") || content.contains("< OutOfProcess");
        let has_ip = content.contains("<InProcess") || content.contains("< InProcess");
        if has_oop || has_ip {
            let mut parts = Vec::new();
            if has_oop {
                parts.push("OutOfProcess");
            }
            if has_ip {
                parts.push("InProcess");
            }
            results.push(CheckResult::pass(
                "OPS-055",
                CAT,
                Severity::Info,
                &format!("{} extension(s) configured", parts.join(" and ")),
            ));
        } else {
            results.push(
                CheckResult::fail(
                    "OPS-055",
                    CAT,
                    Severity::Info,
                    "No <OutOfProcess> or <InProcess> extensions configured (using default process model settings)",
                    Some("Add <OutOfProcess> or <InProcess> elements to configure extensions like logging or additional storage services"),
                )
                .with_doc(DOC_SPCONFIG),
            );
        }
    }

    // OPS-056: No ReplayCache configured (assertion replay protection)
    if let Some(ref content) = config.shibboleth_xml_content {
        if content.contains("ReplayCache") {
            results.push(CheckResult::pass(
                "OPS-056",
                CAT,
                Severity::Info,
                "ReplayCache is configured for assertion replay protection",
            ));
        } else {
            results.push(
                CheckResult::fail(
                    "OPS-056",
                    CAT,
                    Severity::Info,
                    "No <ReplayCache> configured (using default in-memory replay protection; not shared across instances)",
                    Some("Add a <ReplayCache> element backed by a StorageService for persistent replay protection in clustered environments"),
                )
                .with_doc(DOC_SPCONFIG),
            );
        }
    }

    // OPS-057: SSO protocols not explicitly specified
    if let Some(ref sessions) = sc.sessions {
        if sessions.has_sso {
            if let Some(ref protocols) = sessions.sso_protocols {
                if !protocols.trim().is_empty() {
                    results.push(CheckResult::pass(
                        "OPS-057",
                        CAT,
                        Severity::Info,
                        &format!("SSO protocols explicitly specified: {}", protocols.trim()),
                    ));
                } else {
                    results.push(
                        CheckResult::fail(
                            "OPS-057",
                            CAT,
                            Severity::Info,
                            "SSO element has no protocol content (all supported protocols will be enabled)",
                            Some("Specify protocols in <SSO> element text (e.g., \"SAML2\") to limit which protocols are offered"),
                        )
                        .with_doc(DOC_SESSIONS),
                    );
                }
            } else {
                results.push(
                    CheckResult::fail(
                        "OPS-057",
                        CAT,
                        Severity::Info,
                        "SSO element has no protocol content (all supported protocols will be enabled)",
                        Some("Specify protocols in <SSO> element text (e.g., \"SAML2\") to limit which protocols are offered"),
                    )
                    .with_doc(DOC_SESSIONS),
                );
            }
        }
    }

    // OPS-058: Logout protocols not explicitly specified
    if let Some(ref sessions) = sc.sessions {
        if sessions.has_logout {
            if let Some(ref protocols) = sessions.logout_protocols {
                if !protocols.trim().is_empty() {
                    results.push(CheckResult::pass(
                        "OPS-058",
                        CAT,
                        Severity::Info,
                        &format!(
                            "Logout protocols explicitly specified: {}",
                            protocols.trim()
                        ),
                    ));
                } else {
                    results.push(
                        CheckResult::fail(
                            "OPS-058",
                            CAT,
                            Severity::Info,
                            "Logout element has no protocol content (all supported logout protocols will be enabled)",
                            Some("Specify protocols in <Logout> element text (e.g., \"SAML2 Local\") to control logout behavior"),
                        )
                        .with_doc(DOC_SESSIONS),
                    );
                }
            } else {
                results.push(
                    CheckResult::fail(
                        "OPS-058",
                        CAT,
                        Severity::Info,
                        "Logout element has no protocol content (all supported logout protocols will be enabled)",
                        Some("Specify protocols in <Logout> element text (e.g., \"SAML2 Local\") to control logout behavior"),
                    )
                    .with_doc(DOC_SESSIONS),
                );
            }
        }
    }

    // OPS-059: Logging configuration not present
    if let Some(ref content) = config.shibboleth_xml_content {
        let has_logging = content.contains("log4j")
            || content.contains("log4shib")
            || content.contains("Logging")
            || content.contains("logging");
        if has_logging {
            results.push(CheckResult::pass(
                "OPS-059",
                CAT,
                Severity::Info,
                "Logging configuration is referenced in the SP config",
            ));
        } else {
            results.push(
                CheckResult::fail(
                    "OPS-059",
                    CAT,
                    Severity::Info,
                    "No logging configuration detected (SP uses built-in default logging)",
                    Some("Configure logging (e.g., log4shib) for audit trail and troubleshooting"),
                )
                .with_doc(DOC_SPCONFIG),
            );
        }
    }

    // OPS-060: consistentAddress not explicitly set on Sessions
    if let Some(ref sessions) = sc.sessions {
        if sessions.consistent_address.is_some() {
            results.push(CheckResult::pass(
                "OPS-060",
                CAT,
                Severity::Info,
                &format!(
                    "consistentAddress is explicitly set: {}",
                    sessions.consistent_address.as_deref().unwrap_or("?")
                ),
            ));
        } else {
            results.push(
                CheckResult::fail(
                    "OPS-060",
                    CAT,
                    Severity::Info,
                    "consistentAddress not explicitly set on Sessions (defaults to false; sessions valid from any IP)",
                    Some("Set consistentAddress on <Sessions> to control IP address binding behavior for sessions"),
                )
                .with_doc(DOC_SESSIONS),
            );
        }
    }

    // OPS-061: handlerURL uses default /Shibboleth.sso path
    if let Some(ref sessions) = sc.sessions {
        if let Some(ref handler_url) = sessions.handler_url {
            if handler_url == "/Shibboleth.sso" {
                results.push(CheckResult::pass(
                    "OPS-061",
                    CAT,
                    Severity::Info,
                    "handlerURL uses standard /Shibboleth.sso path",
                ));
            } else {
                results.push(
                    CheckResult::fail(
                        "OPS-061",
                        CAT,
                        Severity::Info,
                        &format!(
                            "handlerURL uses non-standard path: {} (ensure web server/proxy is configured to route this path)",
                            handler_url
                        ),
                        Some("Non-standard handlerURL paths require matching web server configuration to route requests to the SP"),
                    )
                    .with_doc(DOC_SESSIONS),
                );
            }
        }
    }

    // OPS-062: ArtifactMap not configured (artifact resolution state not persistent)
    if let Some(ref content) = config.shibboleth_xml_content {
        if content.contains("ArtifactMap") {
            results.push(CheckResult::pass(
                "OPS-062",
                CAT,
                Severity::Info,
                "ArtifactMap is configured for artifact resolution state",
            ));
        } else {
            results.push(
                CheckResult::fail(
                    "OPS-062",
                    CAT,
                    Severity::Info,
                    "No <ArtifactMap> configured (artifact resolution state stored in-memory only)",
                    Some("Add an <ArtifactMap> element backed by a StorageService if using artifact binding in a clustered environment"),
                )
                .with_doc(DOC_SPCONFIG),
            );
        }
    }

    // OPS-063: Small attribute map (< 3 attributes) may indicate incomplete setup
    if let Some(ref map) = config.attribute_map {
        let count = map.attributes.len();
        if count >= 3 {
            results.push(CheckResult::pass(
                "OPS-063",
                CAT,
                Severity::Info,
                &format!("attribute-map.xml defines {} attributes", count),
            ));
        } else if count > 0 {
            results.push(
                CheckResult::fail(
                    "OPS-063",
                    CAT,
                    Severity::Info,
                    &format!(
                        "attribute-map.xml defines only {} attribute(s) — may be incomplete",
                        count
                    ),
                    Some("Review whether additional attributes (e.g., eppn, mail, displayName, affiliation) should be mapped"),
                )
                .with_doc(DOC_ATTR_EXTRACTOR),
            );
        }
    }

    // OPS-064: Attribute policy uses PermitValueRule type="ANY" (accepts all values without filtering)
    if let Some(ref policy) = config.attribute_policy {
        let any_rules: Vec<&str> = policy
            .rules
            .iter()
            .filter(|r| r.permit_value_rule_type.as_deref() == Some("ANY") && !r.has_scope_match)
            .map(|r| r.attribute_id.as_str())
            .collect();
        if any_rules.is_empty() {
            if !policy.rules.is_empty() {
                results.push(CheckResult::pass(
                    "OPS-064",
                    CAT,
                    Severity::Info,
                    "No attribute policy rules use unrestricted PermitValueRule type=\"ANY\"",
                ));
            }
        } else {
            results.push(
                CheckResult::fail(
                    "OPS-064",
                    CAT,
                    Severity::Info,
                    &format!(
                        "{} attribute(s) use PermitValueRule type=\"ANY\" without additional filtering: {}",
                        any_rules.len(),
                        any_rules.join(", ")
                    ),
                    Some("PermitValueRule type=\"ANY\" accepts all values; consider adding value constraints for sensitive attributes"),
                )
                .with_doc(DOC_ATTR_FILTER),
            );
        }
    }

    // OPS-065: Multiple Host elements in RequestMap (multi-vhost setup)
    {
        let host_count = sc
            .request_map_content_settings
            .iter()
            .filter(|cs| cs.element == "Host")
            .count();
        if host_count > 1 {
            results.push(
                CheckResult::fail(
                    "OPS-065",
                    CAT,
                    Severity::Info,
                    &format!(
                        "{} Host elements in RequestMap (multi-vhost setup — ensure each host has appropriate session and access settings)",
                        host_count
                    ),
                    Some("Review that each <Host> element has the correct requireSession, authType, and applicationId settings"),
                )
                .with_doc(DOC_SESSIONS),
            );
        } else if host_count == 1 {
            results.push(CheckResult::pass(
                "OPS-065",
                CAT,
                Severity::Info,
                "Single Host in RequestMap",
            ));
        }
    }

    // OPS-066: SessionInitiator without id attribute (can't be deep-linked)
    {
        let initiators_without_id: Vec<_> = sc
            .session_initiators
            .iter()
            .filter(|si| si.id.is_none())
            .collect();
        if !initiators_without_id.is_empty() && sc.session_initiators.len() > 1 {
            results.push(
                CheckResult::fail(
                    "OPS-066",
                    CAT,
                    Severity::Info,
                    &format!(
                        "{} of {} SessionInitiator(s) have no id attribute (cannot be deep-linked via ?target=)",
                        initiators_without_id.len(),
                        sc.session_initiators.len()
                    ),
                    Some("Add id attributes to SessionInitiators so they can be referenced individually in login links"),
                )
                .with_doc(DOC_SESSIONS),
            );
        } else if sc.session_initiators.len() > 1 {
            results.push(CheckResult::pass(
                "OPS-066",
                CAT,
                Severity::Info,
                "All SessionInitiators have id attributes",
            ));
        }
    }

    // OPS-067: No AccessControl elements configured
    if let Some(ref content) = config.shibboleth_xml_content {
        if content.contains("AccessControl") || content.contains("htaccess") {
            results.push(CheckResult::pass(
                "OPS-067",
                CAT,
                Severity::Info,
                "AccessControl or htaccess authorization is configured",
            ));
        } else {
            results.push(
                CheckResult::fail(
                    "OPS-067",
                    CAT,
                    Severity::Info,
                    "No <AccessControl> elements configured (authorization relies on web server or application layer)",
                    Some("Add <AccessControl> elements in <RequestMap> for SP-level attribute-based authorization, or ensure authorization is handled at the application layer"),
                )
                .with_doc(DOC_SESSIONS),
            );
        }
    }

    // OPS-068: Logout is enabled but no logout error pages configured
    if let Some(ref sessions) = sc.sessions {
        if sessions.has_logout {
            if let Some(ref errors) = sc.errors {
                let has_logout_pages =
                    errors.local_logout.is_some() || errors.global_logout.is_some();
                if has_logout_pages {
                    results.push(CheckResult::pass(
                        "OPS-068",
                        CAT,
                        Severity::Info,
                        "Logout error page(s) configured for logout-enabled SP",
                    ));
                } else {
                    results.push(
                        CheckResult::fail(
                            "OPS-068",
                            CAT,
                            Severity::Info,
                            "Logout is enabled but no localLogout or globalLogout error pages configured in <Errors>",
                            Some("Set localLogout and/or globalLogout on <Errors> to show a user-friendly page after logout"),
                        )
                        .with_doc(DOC_ERRORS),
                    );
                }
            }
        }
    }

    // OPS-069: authnContextClassRef not set (no explicit authentication strength requirement)
    if sc.sso_authn_context_class_ref.is_some() {
        results.push(CheckResult::pass(
            "OPS-069",
            CAT,
            Severity::Info,
            &format!(
                "authnContextClassRef is set on SSO: {}",
                sc.sso_authn_context_class_ref.as_deref().unwrap_or("?")
            ),
        ));
    } else if sc.sessions.as_ref().is_some_and(|s| s.has_sso) {
        results.push(
            CheckResult::fail(
                "OPS-069",
                CAT,
                Severity::Info,
                "authnContextClassRef not set on SSO (no explicit authentication strength requirement)",
                Some("Set authnContextClassRef on <SSO> to request a specific authentication method (e.g., urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport)"),
            )
            .with_doc(DOC_SESSIONS),
        );
    }

    // OPS-070: ApplicationOverride without entityID (inherits parent)
    for (id, entity_id) in &sc.application_override_entity_ids {
        if entity_id.is_some() {
            results.push(CheckResult::pass(
                "OPS-070",
                CAT,
                Severity::Info,
                &format!(
                    "ApplicationOverride '{}' has explicit entityID: {}",
                    id,
                    entity_id.as_deref().unwrap_or("?")
                ),
            ));
        } else {
            results.push(
                CheckResult::fail(
                    "OPS-070",
                    CAT,
                    Severity::Info,
                    &format!(
                        "ApplicationOverride '{}' has no entityID (inherits parent entityID)",
                        id
                    ),
                    Some("Set entityID on ApplicationOverride if this application should have a distinct SP identity"),
                )
                .with_doc(DOC_APP_OVERRIDE),
            );
        }
    }

    // OPS-071: No cipherSuites set on ApplicationDefaults (TLS defaults depend on system OpenSSL)
    if let Some(ref app) = sc.application_defaults {
        if app.cipher_suites.is_some() {
            results.push(CheckResult::pass(
                "OPS-071",
                CAT,
                Severity::Info,
                "cipherSuites is explicitly configured on ApplicationDefaults",
            ));
        } else {
            results.push(
                CheckResult::fail(
                    "OPS-071",
                    CAT,
                    Severity::Info,
                    "cipherSuites not set on ApplicationDefaults (outbound TLS uses system defaults)",
                    Some("Set cipherSuites on <ApplicationDefaults> to control TLS ciphers for outbound connections to IdPs and metadata sources"),
                )
                .with_doc(DOC_APP_DEFAULTS),
            );
        }
    }

    // OPS-072: homeURL does not start with / or https:// (may not resolve correctly)
    if let Some(ref app) = sc.application_defaults {
        if let Some(ref home_url) = app.home_url {
            if !home_url.is_empty()
                && !home_url.starts_with('/')
                && !home_url.starts_with("https://")
                && !home_url.starts_with("http://")
            {
                results.push(
                    CheckResult::fail(
                        "OPS-072",
                        CAT,
                        Severity::Warning,
                        &format!(
                            "homeURL does not start with '/' or 'https://': {}",
                            home_url
                        ),
                        Some("homeURL should be an absolute path (e.g., '/') or full URL (e.g., 'https://sp.example.org/')"),
                    )
                    .with_doc(DOC_APP_DEFAULTS),
                );
            } else if !home_url.is_empty() {
                results.push(CheckResult::pass(
                    "OPS-072",
                    CAT,
                    Severity::Warning,
                    "homeURL has a valid path or URL format",
                ));
            }
        }
    }

    // OPS-073: Multiple AttributeExtractor or AttributeFilter paths (complex multi-source setup)
    {
        let ext_count = sc.attribute_extractor_paths.len();
        let filt_count = sc.attribute_filter_paths.len();
        if ext_count > 1 || filt_count > 1 {
            let mut parts = Vec::new();
            if ext_count > 1 {
                parts.push(format!("{} AttributeExtractor paths", ext_count));
            }
            if filt_count > 1 {
                parts.push(format!("{} AttributeFilter paths", filt_count));
            }
            results.push(
                CheckResult::fail(
                    "OPS-073",
                    CAT,
                    Severity::Info,
                    &format!(
                        "Multiple attribute configuration sources: {} (ensure all files are consistent)",
                        parts.join(", ")
                    ),
                    Some("Multiple attribute sources increase maintenance complexity; ensure all files are kept in sync"),
                )
                .with_doc(DOC_ATTR_EXTRACTOR),
            );
        }
    }

    // OPS-074: AttributeChecker handler not configured (no pre-access attribute validation)
    {
        let has_attr_checker = sc
            .handlers
            .iter()
            .any(|h| h.handler_type.contains("AttributeChecker"));
        if has_attr_checker {
            results.push(CheckResult::pass(
                "OPS-074",
                CAT,
                Severity::Info,
                "AttributeChecker handler is configured for pre-access attribute validation",
            ));
        } else {
            results.push(
                CheckResult::fail(
                    "OPS-074",
                    CAT,
                    Severity::Info,
                    "No AttributeChecker handler configured (no pre-access validation that required attributes are present)",
                    Some("Add a Handler type=\"AttributeChecker\" to verify required attributes exist before granting access"),
                )
                .with_doc(DOC_SESSIONS),
            );
        }
    }

    // OPS-075: Configuration contains TODO/FIXME comments (incomplete setup)
    if let Some(ref content) = config.shibboleth_xml_content {
        let upper = content.to_uppercase();
        let has_todo = upper.contains("TODO") || upper.contains("FIXME") || upper.contains("XXX");
        if has_todo {
            results.push(
                CheckResult::fail(
                    "OPS-075",
                    CAT,
                    Severity::Warning,
                    "Configuration contains TODO/FIXME/XXX comments (may indicate incomplete setup)",
                    Some("Review and resolve all TODO/FIXME comments in the configuration before production deployment"),
                )
                .with_doc(DOC_SPCONFIG),
            );
        } else {
            results.push(CheckResult::pass(
                "OPS-075",
                CAT,
                Severity::Warning,
                "No TODO/FIXME/XXX comments found in configuration",
            ));
        }
    }

    // OPS-076: DiscoveryFeed handler enabled (exposes IdP list)
    {
        let has_discovery_feed = sc
            .handlers
            .iter()
            .any(|h| h.handler_type.contains("DiscoveryFeed"));
        if has_discovery_feed {
            results.push(
                CheckResult::fail(
                    "OPS-076",
                    CAT,
                    Severity::Info,
                    "DiscoveryFeed handler is enabled (exposes list of trusted IdPs as JSON)",
                    Some("DiscoveryFeed publishes trusted IdP metadata; ensure this is intentional and ACL-restricted if needed"),
                )
                .with_doc(DOC_SESSIONS),
            );
        } else {
            results.push(CheckResult::pass(
                "OPS-076",
                CAT,
                Severity::Info,
                "No DiscoveryFeed handler found",
            ));
        }
    }

    // OPS-032 to OPS-035: ApplicationOverride child element replacement checks
    if let Some(ref content) = config.shibboleth_xml_content {
        let mut current_override_id: Option<String> = None;
        let mut has_sessions = false;
        let mut has_errors = false;
        let mut has_credential_resolver = false;
        let mut has_metadata_provider = false;
        let mut any_override_found = false;

        for line in content.lines() {
            let trimmed = line.trim();

            if let Some(pos) = trimmed.find("<ApplicationOverride") {
                let rest = &trimmed[pos..];
                let override_id = rest
                    .find("id=\"")
                    .and_then(|start| {
                        let after = &rest[start + 4..];
                        after.find('"').map(|end| after[..end].to_string())
                    })
                    .or_else(|| {
                        rest.find("id='").and_then(|start| {
                            let after = &rest[start + 4..];
                            after.find('\'').map(|end| after[..end].to_string())
                        })
                    })
                    .unwrap_or_else(|| "unknown".to_string());
                current_override_id = Some(override_id);
                has_sessions = false;
                has_errors = false;
                has_credential_resolver = false;
                has_metadata_provider = false;
                any_override_found = true;
                if trimmed.contains("/>") {
                    current_override_id = None;
                }
                continue;
            }

            if current_override_id.is_some() {
                if trimmed.contains("<Sessions") {
                    has_sessions = true;
                }
                if trimmed.contains("<Errors") {
                    has_errors = true;
                }
                if trimmed.contains("<CredentialResolver") {
                    has_credential_resolver = true;
                }
                if trimmed.contains("<MetadataProvider") {
                    has_metadata_provider = true;
                }

                if trimmed.contains("</ApplicationOverride") {
                    let override_id = current_override_id.take().unwrap();

                    if has_sessions {
                        let parent_summary = describe_parent_sessions(sc);
                        results.push(
                            CheckResult::fail(
                                "OPS-032",
                                CAT,
                                Severity::Info,
                                &format!("ApplicationOverride '{}' defines own <Sessions> — parent Sessions settings are replaced, not merged", override_id),
                                Some(&format!("Parent <Sessions> has {}. None of these are inherited — set all required attributes in the override", parent_summary)),
                            )
                            .with_doc(DOC_APP_OVERRIDE),
                        );
                    }
                    if has_errors {
                        let parent_summary = describe_parent_errors(sc);
                        results.push(
                            CheckResult::fail(
                                "OPS-033",
                                CAT,
                                Severity::Info,
                                &format!("ApplicationOverride '{}' defines own <Errors> — parent error config is replaced", override_id),
                                Some(&format!("Parent <Errors> has {}. These are lost in the override — replicate any needed attributes", parent_summary)),
                            )
                            .with_doc(DOC_APP_OVERRIDE),
                        );
                    }
                    if has_credential_resolver {
                        let parent_summary = describe_parent_credentials(sc);
                        results.push(
                            CheckResult::fail(
                                "OPS-034",
                                CAT,
                                Severity::Info,
                                &format!("ApplicationOverride '{}' defines own <CredentialResolver> — parent credentials are replaced", override_id),
                                Some(&format!("Parent has {}. The override must provide its own signing/encryption credentials", parent_summary)),
                            )
                            .with_doc(DOC_APP_OVERRIDE),
                        );
                    }
                    if has_metadata_provider {
                        let parent_summary = describe_parent_metadata(sc);
                        results.push(
                            CheckResult::fail(
                                "OPS-035",
                                CAT,
                                Severity::Info,
                                &format!("ApplicationOverride '{}' defines own <MetadataProvider> — parent metadata sources are replaced", override_id),
                                Some(&format!("Parent has {}. The override must include all required Identity Providers", parent_summary)),
                            )
                            .with_doc(DOC_APP_OVERRIDE),
                        );
                    }
                }
            }
        }

        if any_override_found {
            let ops032_emitted = results.iter().any(|r| r.code == "OPS-032");
            if !ops032_emitted {
                results.push(CheckResult::pass(
                    "OPS-032",
                    CAT,
                    Severity::Info,
                    "No ApplicationOverride redefines <Sessions>",
                ));
            }
            let ops033_emitted = results.iter().any(|r| r.code == "OPS-033");
            if !ops033_emitted {
                results.push(CheckResult::pass(
                    "OPS-033",
                    CAT,
                    Severity::Info,
                    "No ApplicationOverride redefines <Errors>",
                ));
            }
            let ops034_emitted = results.iter().any(|r| r.code == "OPS-034");
            if !ops034_emitted {
                results.push(CheckResult::pass(
                    "OPS-034",
                    CAT,
                    Severity::Info,
                    "No ApplicationOverride redefines <CredentialResolver>",
                ));
            }
            let ops035_emitted = results.iter().any(|r| r.code == "OPS-035");
            if !ops035_emitted {
                results.push(CheckResult::pass(
                    "OPS-035",
                    CAT,
                    Severity::Info,
                    "No ApplicationOverride redefines <MetadataProvider>",
                ));
            }
        }
    }

    results
}
