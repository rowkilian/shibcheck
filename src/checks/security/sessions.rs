use super::*;

pub(super) fn run(
    config: &DiscoveredConfig,
    sc: &ShibbolethConfig,
    v: SpVersion,
    results: &mut Vec<CheckResult>,
) {
    // SEC-001: handlerSSL=true
    if let Some(ref sessions) = sc.sessions {
        match sessions.handler_ssl.as_deref() {
            Some("true") => {
                results.push(
                    CheckResult::pass(
                        "SEC-001",
                        CAT,
                        Severity::Warning,
                        "handlerSSL is set to true",
                    )
                    .at_element("Sessions"),
                );
            }
            Some("false") => {
                results.push(CheckResult::fail(
                    "SEC-001", CAT, Severity::Warning,
                    "handlerSSL is set to false",
                    Some("Set handlerSSL=\"true\" on <Sessions> to require HTTPS for handler endpoints"),
                ).at_element("Sessions").with_doc(doc_for(DOC_SESSIONS, v)));
            }
            _ => {
                results.push(CheckResult::fail(
                    "SEC-001", CAT, Severity::Warning,
                    "handlerSSL is not explicitly set",
                    Some("Set handlerSSL=\"true\" on <Sessions> to require HTTPS for handler endpoints"),
                ).at_element("Sessions").with_doc(doc_for(DOC_SESSIONS, v)));
            }
        }
    }

    // SEC-002: cookieProps includes "secure"
    if let Some(ref sessions) = sc.sessions {
        if let Some(ref cookie_props) = sessions.cookie_props {
            let lower = cookie_props.to_lowercase();
            let https_shorthand = lower == "https" && v == SpVersion::V3;
            if lower.contains("secure") || https_shorthand {
                results.push(
                    CheckResult::pass(
                        "SEC-002",
                        CAT,
                        Severity::Warning,
                        "cookieProps includes secure flag",
                    )
                    .at_element("Sessions"),
                );
            } else {
                let suggestion = if v == SpVersion::V2 {
                    "Add '; secure' to cookieProps (the \"https\" shorthand only works in SP3)"
                } else {
                    "Add 'secure' to cookieProps or set cookieProps=\"https\""
                };
                results.push(
                    CheckResult::fail(
                        "SEC-002",
                        CAT,
                        Severity::Warning,
                        "cookieProps does not include 'secure'",
                        Some(suggestion),
                    )
                    .at_element("Sessions")
                    .with_doc(doc_for(DOC_SESSIONS, v)),
                );
            }
        } else {
            results.push(
                CheckResult::fail(
                    "SEC-002",
                    CAT,
                    Severity::Warning,
                    "cookieProps not set on Sessions",
                    Some("Set cookieProps=\"https\" on <Sessions> for secure cookies"),
                )
                .at_element("Sessions")
                .with_doc(doc_for(DOC_SESSIONS, v)),
            );
        }
    }

    // SEC-003: cookieProps includes "httpOnly"
    if let Some(ref sessions) = sc.sessions {
        if let Some(ref cookie_props) = sessions.cookie_props {
            let lower = cookie_props.to_lowercase();
            // "https" shorthand implies httpOnly only in SP3
            let https_shorthand = lower == "https" && v == SpVersion::V3;
            if lower.contains("httponly") || https_shorthand {
                results.push(
                    CheckResult::pass(
                        "SEC-003",
                        CAT,
                        Severity::Warning,
                        "cookieProps includes httpOnly flag",
                    )
                    .at_element("Sessions"),
                );
            } else {
                let suggestion = if v == SpVersion::V2 {
                    "Add '; HttpOnly' to cookieProps (the \"https\" shorthand only works in SP3)"
                } else {
                    "Add 'httpOnly' to cookieProps or set cookieProps=\"https\""
                };
                results.push(
                    CheckResult::fail(
                        "SEC-003",
                        CAT,
                        Severity::Warning,
                        "cookieProps does not include 'httpOnly'",
                        Some(suggestion),
                    )
                    .at_element("Sessions")
                    .with_doc(doc_for(DOC_SESSIONS, v)),
                );
            }
        } else {
            results.push(
                CheckResult::fail(
                    "SEC-003",
                    CAT,
                    Severity::Warning,
                    "cookieProps not set on Sessions",
                    Some("Set cookieProps=\"https\" on <Sessions> for httpOnly cookies"),
                )
                .at_element("Sessions")
                .with_doc(doc_for(DOC_SESSIONS, v)),
            );
        }
    }

    // SEC-017: cookieProps does not set SameSite. Supported SP versions add the right
    // SameSite value to each cookie themselves; the SameSite and Sessions topics say
    // not to put it in cookieProps (use sameSiteSession for the session cookie).
    if let Some(ref sessions) = sc.sessions {
        if v != SpVersion::V2 {
            let sets_samesite = sessions
                .cookie_props
                .as_deref()
                .is_some_and(|p| p.to_lowercase().contains("samesite"));
            if sets_samesite {
                results.push(
                    CheckResult::fail(
                        "SEC-017",
                        CAT,
                        Severity::Warning,
                        "cookieProps sets a SameSite attribute",
                        Some("Remove SameSite from cookieProps: the SP adds the value each cookie needs. To change the session cookie, use sameSiteSession"),
                    )
                    .at_element("Sessions")
                    .with_doc(DOC_SAMESITE),
                );
            } else {
                results.push(
                    CheckResult::pass(
                        "SEC-017",
                        CAT,
                        Severity::Warning,
                        "cookieProps leaves SameSite to the SP",
                    )
                    .at_element("Sessions"),
                );
            }
        }
    }

    // SEC-127: sameSiteSession value (SP 3.1+)
    if let Some(ref sessions) = sc.sessions {
        if let Some(ref value) = sessions.same_site_session {
            let (passed, severity, message, suggestion) = match value.as_str() {
                "Lax" => (true, Severity::Info, "sameSiteSession is Lax".to_string(), ""),
                "None" => (
                    false,
                    Severity::Warning,
                    "sameSiteSession=\"None\" makes the session cookie available cross-site".to_string(),
                    "Remove sameSiteSession unless an application really needs the SP session in cross-site requests. The SP itself does not need it",
                ),
                "Strict" => (
                    false,
                    Severity::Info,
                    "sameSiteSession=\"Strict\" will generally not work".to_string(),
                    "Session cookies are set during the cross-site POST from the IdP, so Strict is usually non-functional. Use Lax or remove the setting",
                ),
                other => (
                    false,
                    Severity::Warning,
                    format!("sameSiteSession has unrecognized value '{}'", other),
                    "Use one of \"None\", \"Lax\" or \"Strict\" (case-sensitive), or remove the setting",
                ),
            };
            let result = if passed {
                CheckResult::pass("SEC-127", CAT, severity, &message)
            } else {
                CheckResult::fail("SEC-127", CAT, severity, &message, Some(suggestion))
                    .with_doc(DOC_SAMESITE)
            };
            results.push(result.at_element("Sessions"));
        }
    }

    // SEC-019: Sessions lifetime is reasonable
    if let Some(ref sessions) = sc.sessions {
        if let Some(ref lifetime_str) = sessions.lifetime {
            if let Ok(lifetime) = lifetime_str.parse::<u64>() {
                if lifetime == 0 {
                    results.push(
                        CheckResult::fail(
                            "SEC-019",
                            CAT,
                            Severity::Info,
                            "Sessions lifetime is 0 (sessions never expire by time)",
                            Some("Set a reasonable session lifetime (e.g., 28800 for 8 hours)"),
                        )
                        .at_element("Sessions")
                        .with_doc(doc_for(DOC_SESSIONS, v)),
                    );
                } else if lifetime > 86400 {
                    results.push(CheckResult::fail(
                        "SEC-019", CAT, Severity::Info,
                        &format!("Sessions lifetime is {} seconds ({:.1} days)", lifetime, lifetime as f64 / 86400.0),
                        Some("Consider a shorter session lifetime (default is 28800 seconds / 8 hours)"),
                    ).at_element("Sessions").with_doc(doc_for(DOC_SESSIONS, v)));
                } else {
                    results.push(
                        CheckResult::pass(
                            "SEC-019",
                            CAT,
                            Severity::Info,
                            &format!(
                                "Sessions lifetime is {} seconds ({:.1} hours)",
                                lifetime,
                                lifetime as f64 / 3600.0
                            ),
                        )
                        .at_element("Sessions"),
                    );
                }
            }
        }
    }

    // SEC-020: Sessions timeout is reasonable
    if let Some(ref sessions) = sc.sessions {
        if let Some(ref timeout_str) = sessions.timeout {
            if let Ok(timeout) = timeout_str.parse::<u64>() {
                if timeout == 0 {
                    results.push(
                        CheckResult::fail(
                            "SEC-020",
                            CAT,
                            Severity::Info,
                            "Sessions timeout is 0 (sessions never expire by inactivity)",
                            Some("Set a reasonable idle timeout (e.g., 3600 for 1 hour)"),
                        )
                        .at_element("Sessions")
                        .with_doc(doc_for(DOC_SESSIONS, v)),
                    );
                } else if timeout > 28800 {
                    results.push(CheckResult::fail(
                        "SEC-020", CAT, Severity::Info,
                        &format!("Sessions timeout is {} seconds ({:.1} hours)", timeout, timeout as f64 / 3600.0),
                        Some("Consider a shorter idle timeout (default is 3600 seconds / 1 hour)"),
                    ).at_element("Sessions").with_doc(doc_for(DOC_SESSIONS, v)));
                } else {
                    results.push(
                        CheckResult::pass(
                            "SEC-020",
                            CAT,
                            Severity::Info,
                            &format!(
                                "Sessions timeout is {} seconds ({:.1} hours)",
                                timeout,
                                timeout as f64 / 3600.0
                            ),
                        )
                        .at_element("Sessions"),
                    );
                }
            }
        }
    }

    // SEC-022: redirectLimit not "none" (open redirect vulnerability)
    if let Some(ref sessions) = sc.sessions {
        if let Some(ref redirect_limit) = sessions.redirect_limit {
            let lower = redirect_limit.to_lowercase();
            if lower == "none" {
                results.push(
                    CheckResult::fail(
                        "SEC-022",
                        CAT,
                        Severity::Warning,
                        "Sessions redirectLimit is set to 'none' (open redirect vulnerability)",
                        Some("Set redirectLimit to 'exact' or 'host' to prevent open redirect attacks"),
                    ).at_element("Sessions")
                    .with_doc(doc_for(DOC_SESSIONS, v)),
                );
            } else {
                results.push(
                    CheckResult::pass(
                        "SEC-022",
                        CAT,
                        Severity::Warning,
                        &format!("Sessions redirectLimit is set to '{}'", redirect_limit),
                    )
                    .at_element("Sessions"),
                );
            }
        }
    }

    // SEC-023: consistentAddress not explicitly "false"
    if let Some(ref sessions) = sc.sessions {
        if let Some(ref consistent_addr) = sessions.consistent_address {
            if consistent_addr == "false" {
                results.push(
                    CheckResult::fail(
                        "SEC-023",
                        CAT,
                        Severity::Info,
                        "Sessions consistentAddress is explicitly false",
                        Some("consistentAddress=\"true\" binds sessions to the client IP for additional security"),
                    ).at_element("Sessions")
                    .with_doc(doc_for(DOC_SESSIONS, v)),
                );
            } else {
                results.push(
                    CheckResult::pass(
                        "SEC-023",
                        CAT,
                        Severity::Info,
                        "Sessions consistentAddress is not disabled",
                    )
                    .at_element("Sessions"),
                );
            }
        }
    }

    // SEC-024: clockSkew not > 600s
    if let Some(ref clock_skew_str) = sc.clock_skew {
        if let Ok(skew) = clock_skew_str.parse::<u64>() {
            if skew > 600 {
                results.push(
                    CheckResult::fail(
                        "SEC-024",
                        CAT,
                        Severity::Warning,
                        &format!(
                            "clockSkew is {}s (> 600s increases replay attack window)",
                            skew
                        ),
                        Some("Set clockSkew to 180 or less; large values weaken replay protection"),
                    )
                    .at_element("SPConfig")
                    .with_doc(doc_for(DOC_APP_DEFAULTS, v)),
                );
            } else {
                results.push(
                    CheckResult::pass(
                        "SEC-024",
                        CAT,
                        Severity::Warning,
                        &format!("clockSkew is {}s (within safe range)", skew),
                    )
                    .at_element("SPConfig"),
                );
            }
        }
    }

    // SEC-031: relayState uses ss: prefix (cookie-based storage)
    if let Some(ref sessions) = sc.sessions {
        if let Some(ref relay_state) = sessions.relay_state {
            if relay_state.starts_with("ss:") {
                results.push(
                    CheckResult::pass(
                        "SEC-031",
                        CAT,
                        Severity::Info,
                        "Sessions relayState uses server-side storage (ss: prefix)",
                    )
                    .at_element("Sessions"),
                );
            } else if relay_state.starts_with("cookie:") || relay_state == "cookie" {
                results.push(
                    CheckResult::fail(
                        "SEC-031",
                        CAT,
                        Severity::Info,
                        "Sessions relayState uses cookie storage",
                        Some("Consider using ss: prefix for server-side relay state storage"),
                    )
                    .at_element("Sessions")
                    .with_doc(doc_for(DOC_SESSIONS, v)),
                );
            } else {
                results.push(
                    CheckResult::pass(
                        "SEC-031",
                        CAT,
                        Severity::Info,
                        &format!("Sessions relayState is set to '{}'", relay_state),
                    )
                    .at_element("Sessions"),
                );
            }
        }
    }

    // SEC-034: exportAssertion="true" leaks SAML assertion in headers
    if let Some(ref content) = config.shibboleth_xml_content {
        if content.contains("exportAssertion=\"true\"") {
            results.push(
                CheckResult::fail(
                    "SEC-034",
                    CAT,
                    Severity::Warning,
                    "exportAssertion=\"true\" found (leaks full SAML assertion in HTTP headers)",
                    Some(
                        "Remove exportAssertion or set to \"false\" unless required for debugging",
                    ),
                )
                .with_doc(doc_for(DOC_APP_DEFAULTS, v)),
            );
        } else {
            results.push(CheckResult::pass(
                "SEC-034",
                CAT,
                Severity::Warning,
                "exportAssertion is not enabled",
            ));
        }
    }

    // SEC-042: handlerURL is absolute URL using http://
    if let Some(ref sessions) = sc.sessions {
        if let Some(ref handler_url) = sessions.handler_url {
            if handler_url.starts_with("http://") {
                results.push(
                    CheckResult::fail(
                        "SEC-042",
                        CAT,
                        Severity::Warning,
                        &format!("handlerURL uses plaintext HTTP: {}", handler_url),
                        Some("Use a relative path or HTTPS URL for handlerURL"),
                    )
                    .at_element("Sessions")
                    .with_doc(doc_for(DOC_SESSIONS, v)),
                );
            } else {
                results.push(
                    CheckResult::pass(
                        "SEC-042",
                        CAT,
                        Severity::Warning,
                        "handlerURL does not use plaintext HTTP",
                    )
                    .at_element("Sessions"),
                );
            }
        }
    }

    // SEC-045: redirectLimit not explicitly set on Sessions
    if let Some(ref sessions) = sc.sessions {
        if sessions.redirect_limit.is_some() {
            results.push(
                CheckResult::pass(
                    "SEC-045",
                    CAT,
                    Severity::Info,
                    "redirectLimit is explicitly set on Sessions",
                )
                .at_element("Sessions"),
            );
        } else {
            results.push(
                CheckResult::fail(
                    "SEC-045",
                    CAT,
                    Severity::Info,
                    "redirectLimit not explicitly set on Sessions (defaults vary by SP version)",
                    Some("Set redirectLimit on <Sessions> to explicitly control redirect behavior"),
                )
                .at_element("Sessions")
                .with_doc(doc_for(DOC_SESSIONS, v)),
            );
        }
    }

    // SEC-049: homeURL uses plain HTTP or is a placeholder
    if let Some(ref app) = sc.application_defaults {
        if let Some(ref home_url) = app.home_url {
            let lower = home_url.to_lowercase();
            if lower.starts_with("http://") {
                results.push(
                    CheckResult::fail(
                        "SEC-049",
                        CAT,
                        Severity::Info,
                        &format!("homeURL uses plain HTTP: {}", home_url),
                        Some("Use HTTPS for homeURL"),
                    )
                    .at_element("ApplicationDefaults")
                    .with_doc(doc_for(DOC_APP_DEFAULTS, v)),
                );
            } else if lower.contains("example.org")
                || lower.contains("example.com")
                || lower.contains("localhost")
            {
                results.push(
                    CheckResult::fail(
                        "SEC-049",
                        CAT,
                        Severity::Info,
                        &format!("homeURL appears to be a placeholder: {}", home_url),
                        Some("Set homeURL to your actual application URL"),
                    )
                    .at_element("ApplicationDefaults")
                    .with_doc(doc_for(DOC_APP_DEFAULTS, v)),
                );
            } else {
                results.push(
                    CheckResult::pass(
                        "SEC-049",
                        CAT,
                        Severity::Info,
                        &format!("homeURL is set: {}", home_url),
                    )
                    .at_element("ApplicationDefaults"),
                );
            }
        }
    }

    // SEC-050: exportAssertion="true" without any requireSession in config
    if let Some(ref content) = config.shibboleth_xml_content {
        if content.contains("exportAssertion=\"true\"")
            && !content.contains("requireSession=\"true\"")
        {
            results.push(
                CheckResult::fail(
                    "SEC-050",
                    CAT,
                    Severity::Warning,
                    "exportAssertion=\"true\" found without requireSession=\"true\" in config",
                    Some("Ensure requireSession=\"true\" is set when exporting assertions to prevent unauthenticated access"),
                )
                .with_doc(doc_for(DOC_APP_DEFAULTS, v)),
            );
        } else if content.contains("exportAssertion=\"true\"") {
            results.push(CheckResult::pass(
                "SEC-050",
                CAT,
                Severity::Warning,
                "exportAssertion has requireSession configured",
            ));
        }
    }

    // SEC-061: redirectLimit contains "+allow" but redirectAllow is missing
    if let Some(ref sessions) = sc.sessions {
        if let Some(ref limit) = sessions.redirect_limit {
            if limit.contains("allow") && sessions.redirect_allow.is_none() {
                results.push(
                    CheckResult::fail(
                        "SEC-061",
                        CAT,
                        Severity::Warning,
                        &format!(
                            "redirectLimit=\"{}\" references allow-list but redirectAllow is not set",
                            limit
                        ),
                        Some("Set redirectAllow on <Sessions> with allowed redirect URLs"),
                    ).at_element("Sessions")
                    .with_doc(doc_for(DOC_SESSIONS, v)),
                );
            } else if limit.contains("allow") {
                results.push(
                    CheckResult::pass(
                        "SEC-061",
                        CAT,
                        Severity::Warning,
                        "redirectLimit allow-list has redirectAllow configured",
                    )
                    .at_element("Sessions"),
                );
            }
        }
    }

    // SEC-065: ApplicationOverride <Sessions> missing redirectLimit (not inherited)
    if let Some(ref content) = config.shibboleth_xml_content {
        let mut in_override = false;
        let mut override_id = String::new();
        let mut sessions_buf = String::new();
        let mut collecting_sessions = false;
        let mut found_issue = false;

        for line in content.lines() {
            let trimmed = line.trim();
            if let Some(pos) = trimmed.find("<ApplicationOverride") {
                in_override = true;
                let rest = &trimmed[pos..];
                override_id = rest
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
                if trimmed.contains("/>") {
                    in_override = false;
                }
                continue;
            }
            if in_override && trimmed.contains("<Sessions") {
                collecting_sessions = true;
                sessions_buf.clear();
            }
            if collecting_sessions {
                sessions_buf.push_str(trimmed);
                sessions_buf.push(' ');
                if trimmed.contains("/>") || trimmed.contains(">") {
                    if !sessions_buf.contains("redirectLimit") {
                        results.push(
                            CheckResult::fail(
                                "SEC-065",
                                CAT,
                                Severity::Warning,
                                &format!(
                                    "ApplicationOverride '{}' <Sessions> missing redirectLimit (not inherited — may allow open redirects)",
                                    override_id
                                ),
                                Some("Set redirectLimit on <Sessions> inside <ApplicationOverride> to prevent open redirect attacks"),
                            )
                            .with_doc(doc_for(DOC_SESSIONS, v)),
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
            // Check if any override has its own Sessions
            let has_override_sessions = {
                let mut in_ov = false;
                let mut found = false;
                for line in content.lines() {
                    let t = line.trim();
                    if t.contains("<ApplicationOverride") {
                        in_ov = true;
                    }
                    if in_ov && t.contains("<Sessions") {
                        found = true;
                        break;
                    }
                    if t.contains("</ApplicationOverride") {
                        in_ov = false;
                    }
                }
                found
            };
            if has_override_sessions {
                results.push(CheckResult::pass(
                    "SEC-065",
                    CAT,
                    Severity::Warning,
                    "ApplicationOverride Sessions elements have redirectLimit set",
                ));
            }
        }
    }

    // SEC-066: idpHistory enabled (leaks IdP usage pattern to client via cookie)
    if let Some(ref sessions) = sc.sessions {
        if sessions.idp_history.as_deref() == Some("true") {
            let days_info = sessions
                .idp_history_days
                .as_deref()
                .map(|d| format!(" (retained for {} days)", d))
                .unwrap_or_default();
            results.push(
                CheckResult::fail(
                    "SEC-066",
                    CAT,
                    Severity::Info,
                    &format!(
                        "idpHistory is enabled{} — client cookie reveals which IdPs the user has visited",
                        days_info
                    ),
                    Some("Disable idpHistory or set idpHistoryDays to a low value to reduce tracking exposure"),
                ).at_element("Sessions")
                .with_doc(doc_for(DOC_SESSIONS, v)),
            );
        } else if sessions.idp_history.is_some() {
            results.push(
                CheckResult::pass("SEC-066", CAT, Severity::Info, "idpHistory is not enabled")
                    .at_element("Sessions"),
            );
        }
    }

    // SEC-067: maxTimeSinceAuthn not set (stale authentications accepted)
    if let Some(ref sessions) = sc.sessions {
        if sessions.max_time_since_authn.is_some() {
            results.push(
                CheckResult::pass(
                    "SEC-067",
                    CAT,
                    Severity::Info,
                    "maxTimeSinceAuthn is set on Sessions",
                )
                .at_element("Sessions"),
            );
        } else {
            results.push(
                CheckResult::fail(
                    "SEC-067",
                    CAT,
                    Severity::Info,
                    "maxTimeSinceAuthn not set on Sessions (IdP may reuse old authentications)",
                    Some("Set maxTimeSinceAuthn on <Sessions> to limit how old an IdP authentication can be"),
                ).at_element("Sessions")
                .with_doc(doc_for(DOC_SESSIONS, v)),
            );
        }
    }

    // SEC-068: cookieLifetime exceeds session lifetime (cookie persists beyond session)
    if let Some(ref sessions) = sc.sessions {
        if let (Some(ref cookie_lt), Some(ref session_lt)) =
            (&sessions.cookie_lifetime, &sessions.lifetime)
        {
            if let (Ok(cookie_secs), Ok(session_secs)) =
                (cookie_lt.parse::<u64>(), session_lt.parse::<u64>())
            {
                if cookie_secs > session_secs && session_secs > 0 {
                    results.push(
                        CheckResult::fail(
                            "SEC-068",
                            CAT,
                            Severity::Info,
                            &format!(
                                "cookieLifetime ({}) exceeds session lifetime ({}) — cookie persists after session expires",
                                cookie_secs, session_secs
                            ),
                            Some("Set cookieLifetime <= session lifetime to avoid stale session cookies"),
                        ).at_element("Sessions")
                        .with_doc(doc_for(DOC_SESSIONS, v)),
                    );
                } else {
                    results.push(
                        CheckResult::pass(
                            "SEC-068",
                            CAT,
                            Severity::Info,
                            "cookieLifetime does not exceed session lifetime",
                        )
                        .at_element("Sessions"),
                    );
                }
            }
        }
    }

    // SEC-071: checkAddress explicitly set to "false" (source IP checking disabled)
    if let Some(ref sessions) = sc.sessions {
        if sessions.check_address.as_deref() == Some("false") {
            results.push(
                CheckResult::fail(
                    "SEC-071",
                    CAT,
                    Severity::Info,
                    "checkAddress is explicitly set to \"false\" (source IP consistency checking disabled)",
                    Some("Consider enabling checkAddress to detect session hijacking via IP change"),
                ).at_element("Sessions")
                .with_doc(doc_for(DOC_SESSIONS, v)),
            );
        } else if sessions.check_address.is_some() {
            results.push(
                CheckResult::pass(
                    "SEC-071",
                    CAT,
                    Severity::Info,
                    "checkAddress is not disabled",
                )
                .at_element("Sessions"),
            );
        }
    }

    // SEC-078: idpHistoryDays is very high (> 365 days, long tracking window)
    if let Some(ref sessions) = sc.sessions {
        if let Some(ref days) = sessions.idp_history_days {
            if let Ok(d) = days.parse::<u64>() {
                if d > 365 {
                    results.push(
                        CheckResult::fail(
                            "SEC-078",
                            CAT,
                            Severity::Info,
                            &format!(
                                "idpHistoryDays is {} (> 365 days) — long IdP tracking window",
                                d
                            ),
                            Some("Reduce idpHistoryDays to limit how long IdP visit history is retained in cookies"),
                        ).at_element("Sessions")
                        .with_doc(doc_for(DOC_SESSIONS, v)),
                    );
                } else {
                    results.push(
                        CheckResult::pass(
                            "SEC-078",
                            CAT,
                            Severity::Info,
                            &format!("idpHistoryDays is {} (reasonable retention)", d),
                        )
                        .at_element("Sessions"),
                    );
                }
            }
        }
    }

    // SEC-079: sameSiteFallback enabled (unnecessary on modern browsers, expands cookie surface)
    if let Some(ref sessions) = sc.sessions {
        if sessions.same_site_fallback.as_deref() == Some("true") {
            results.push(
                CheckResult::fail(
                    "SEC-079",
                    CAT,
                    Severity::Info,
                    "sameSiteFallback is enabled (sends additional fallback cookies for legacy browsers)",
                    Some("Disable sameSiteFallback if all users are on modern browsers to reduce cookie surface area"),
                ).at_element("Sessions")
                .with_doc(doc_for(DOC_SESSIONS, v)),
            );
        } else if sessions.same_site_fallback.is_some() {
            results.push(
                CheckResult::pass(
                    "SEC-079",
                    CAT,
                    Severity::Info,
                    "sameSiteFallback is not enabled",
                )
                .at_element("Sessions"),
            );
        }
    }

    // SEC-084: relayState set to a non-HTTPS URL
    if let Some(ref sessions) = sc.sessions {
        if let Some(ref rs) = sessions.relay_state {
            if rs.starts_with("http://") {
                results.push(
                    CheckResult::fail(
                        "SEC-084",
                        CAT,
                        Severity::Warning,
                        &format!("relayState uses plain HTTP: {}", rs),
                        Some("Use HTTPS for relayState URLs to protect the post-login redirect"),
                    )
                    .at_element("Sessions")
                    .with_doc(doc_for(DOC_SESSIONS, v)),
                );
            } else {
                results.push(
                    CheckResult::pass(
                        "SEC-084",
                        CAT,
                        Severity::Warning,
                        "relayState does not use plain HTTP",
                    )
                    .at_element("Sessions"),
                );
            }
        }
    }

    // SEC-092: redirectWhitelist deprecated attribute used (should use redirectAllow)
    if let Some(ref sessions) = sc.sessions {
        if sessions.redirect_whitelist.is_some() {
            results.push(
                CheckResult::fail(
                    "SEC-092",
                    CAT,
                    Severity::Info,
                    "Sessions uses deprecated 'redirectWhitelist' attribute",
                    Some("Migrate to 'redirectAllow' attribute (redirectWhitelist is deprecated in SP3)"),
                ).at_element("Sessions")
                .with_doc(doc_for(DOC_SESSIONS, v)),
            );
        }
    }

    // SEC-093: ContentSetting authType="shibboleth" with requireSession="false"
    for cs in &sc.request_map_content_settings {
        if cs.auth_type.as_deref() == Some("shibboleth")
            && cs.require_session.as_deref() == Some("false")
        {
            results.push(
                CheckResult::fail(
                    "SEC-093",
                    CAT,
                    Severity::Warning,
                    &format!(
                        "Content setting for {} '{}' has authType=\"shibboleth\" but requireSession=\"false\" (authentication not enforced)",
                        cs.element,
                        cs.name.as_deref().unwrap_or("(unnamed)")
                    ),
                    Some("Set requireSession=\"true\" when authType=\"shibboleth\" to enforce authentication"),
                )
                .with_doc(doc_for(DOC_APP_DEFAULTS, v)),
            );
        }
    }

    // SEC-099: postData cache enabled (may store sensitive form data on disk)
    if let Some(ref sessions) = sc.sessions {
        if sessions.post_data.is_some() {
            results.push(
                CheckResult::fail(
                    "SEC-099",
                    CAT,
                    Severity::Info,
                    "PostData cache is enabled (form data may be stored on disk during SSO redirect)",
                    Some("Ensure PostData cache directory has restrictive permissions to protect sensitive form data"),
                )
                .with_doc(doc_for(DOC_SESSIONS, v)),
            );
        }
    }

    // SEC-100: ContentSetting forceAuthn="false" explicitly disables re-authentication
    for cs in &sc.request_map_content_settings {
        if cs.force_authn.as_deref() == Some("false") {
            results.push(
                CheckResult::fail(
                    "SEC-100",
                    CAT,
                    Severity::Info,
                    &format!(
                        "Content setting for {} '{}' has forceAuthn=\"false\" (re-authentication explicitly disabled)",
                        cs.element,
                        cs.name.as_deref().unwrap_or("(unnamed)")
                    ),
                    Some("Consider requiring forceAuthn for sensitive resources"),
                )
                .with_doc(doc_for(DOC_APP_DEFAULTS, v)),
            );
        }
    }

    // SEC-101: isPassive="true" on content settings (may silently fail authentication)
    for cs in &sc.request_map_content_settings {
        if cs.is_passive.as_deref() == Some("true") && cs.require_session.as_deref() == Some("true")
        {
            results.push(
                CheckResult::fail(
                    "SEC-101",
                    CAT,
                    Severity::Info,
                    &format!(
                        "Content setting for {} '{}' has isPassive=\"true\" with requireSession — authentication may silently fail if user has no IdP session",
                        cs.element,
                        cs.name.as_deref().unwrap_or("(unnamed)")
                    ),
                    Some("Remove isPassive or set to \"false\" on paths that require authentication"),
                )
                .with_doc(doc_for(DOC_APP_DEFAULTS, v)),
            );
        }
    }

    // SEC-109: clockSkew set to 0 (may reject valid assertions with minor time drift)
    if let Some(ref skew) = sc.clock_skew {
        if let Ok(s) = skew.parse::<u64>() {
            if s == 0 {
                results.push(
                    CheckResult::fail(
                        "SEC-109",
                        CAT,
                        Severity::Info,
                        "clockSkew is 0 (zero tolerance for clock drift — may reject valid assertions)",
                        Some("Set clockSkew to a small value like 180 to tolerate minor time differences"),
                    )
                    .with_doc(doc_for(DOC_APP_DEFAULTS, v)),
                );
            } else {
                results.push(CheckResult::pass(
                    "SEC-109",
                    CAT,
                    Severity::Info,
                    &format!("clockSkew is {} (non-zero)", s),
                ));
            }
        }
    }

    check_session_recovery(sc, results);
}

/// SEC-139: `persistedAttributes` turns on session recovery. A recovered session counts as
/// freshly used, so the client can bypass the timeout, and logout cannot revoke it.
fn check_session_recovery(sc: &ShibbolethConfig, results: &mut Vec<CheckResult>) {
    let Some(ref cache) = sc.session_cache else {
        return;
    };
    let persisted = cache
        .persisted_attributes
        .as_deref()
        .is_some_and(|a| !a.trim().is_empty());
    if !persisted {
        results.push(
            CheckResult::pass(
                "SEC-139",
                CAT,
                Severity::Warning,
                "Session recovery (persistedAttributes) is not enabled",
            )
            .at_element("SessionCache"),
        );
        return;
    }
    results.push(
        CheckResult::fail(
            "SEC-139",
            CAT,
            Severity::Warning,
            "SessionCache persistedAttributes enables session recovery: a recovered session skips the inactivity timeout and survives logout",
            Some("Use a shared StorageService instead unless you accept these limits. Keep the attribute list short and protect the DataSealer keys"),
        )
        .at_element("SessionCache")
        .with_doc("https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334650/SessionCache"),
    );
}
