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
                            "Remote MetadataProvider type='{}' has no reloadInterval set",
                            mp.provider_type
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
                            "SignatureMetadataFilter has verifyBackup=\"false\" (backed-up metadata will not be signature-verified on load)",
                            Some("Set verifyBackup=\"true\" or remove the attribute to verify backed-up metadata"),
                        )
                        .with_doc(DOC_METADATA_PROVIDER),
                    );
                } else {
                    results.push(CheckResult::pass(
                        "OPS-029",
                        CAT,
                        Severity::Info,
                        "SignatureMetadataFilter verifyBackup is not disabled",
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
