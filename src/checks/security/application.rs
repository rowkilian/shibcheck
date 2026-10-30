use super::*;

pub(super) fn run(
    config: &DiscoveredConfig,
    sc: &ShibbolethConfig,
    v: SpVersion,
    results: &mut Vec<CheckResult>,
) {
    // SEC-018: entityID uses HTTPS (prefer over HTTP)
    if let Some(ref entity_id) = sc.entity_id {
        if entity_id.starts_with("https://") || entity_id.starts_with("urn:") {
            results.push(
                CheckResult::pass(
                    "SEC-018",
                    CAT,
                    Severity::Info,
                    "entityID uses HTTPS or URN scheme",
                )
                .at_element("ApplicationDefaults"),
            );
        } else if entity_id.starts_with("http://") {
            results.push(
                CheckResult::fail(
                    "SEC-018",
                    CAT,
                    Severity::Info,
                    &format!("entityID uses HTTP instead of HTTPS: {}", entity_id),
                    Some(
                        "Consider using an HTTPS entityID for consistency with TLS best practices",
                    ),
                )
                .at_element("ApplicationDefaults")
                .with_doc(doc_for(DOC_APP_DEFAULTS, v)),
            );
        }
    }

    // SEC-028: entityID not placeholder (example.org)
    if let Some(ref entity_id) = sc.entity_id {
        let lower = entity_id.to_lowercase();
        if lower.contains("example.org")
            || lower.contains("example.com")
            || lower.contains("localhost")
        {
            results.push(
                CheckResult::fail(
                    "SEC-028",
                    CAT,
                    Severity::Warning,
                    &format!("entityID appears to be a placeholder: {}", entity_id),
                    Some("Set entityID to your actual SP entity ID"),
                )
                .at_element("ApplicationDefaults")
                .with_doc(doc_for(DOC_APP_DEFAULTS, v)),
            );
        } else {
            results.push(
                CheckResult::pass(
                    "SEC-028",
                    CAT,
                    Severity::Warning,
                    "entityID is not a placeholder value",
                )
                .at_element("ApplicationDefaults"),
            );
        }
    }

    // SEC-041: Notify endpoint uses plaintext HTTP
    {
        let mut has_http = false;
        for endpoint in &sc.notify_endpoints {
            if endpoint.starts_with("http://") {
                results.push(
                    CheckResult::fail(
                        "SEC-041",
                        CAT,
                        Severity::Warning,
                        &format!("Notify endpoint uses plaintext HTTP: {}", endpoint),
                        Some("Use HTTPS for Notify endpoints to protect logout notifications"),
                    )
                    .at_element("Notify")
                    .with_doc(doc_for(DOC_SESSIONS, v)),
                );
                has_http = true;
            }
        }
        if !has_http && !sc.notify_endpoints.is_empty() {
            results.push(
                CheckResult::pass(
                    "SEC-041",
                    CAT,
                    Severity::Warning,
                    "All Notify endpoints use HTTPS",
                )
                .at_element("Notify"),
            );
        }
    }

    // SEC-056: requireTransportAuth="false" (disables TLS cert validation on back-channel)
    if let Some(ref app) = sc.application_defaults {
        if app.require_transport_auth.as_deref() == Some("false") {
            results.push(
                CheckResult::fail(
                    "SEC-056",
                    CAT,
                    Severity::Warning,
                    "requireTransportAuth=\"false\" disables TLS certificate validation on back-channel",
                    Some("Remove requireTransportAuth=\"false\" or set to \"true\" to validate TLS certificates"),
                ).at_element("ApplicationDefaults")
                .with_doc(doc_for(DOC_APP_DEFAULTS, v)),
            );
        } else if app.require_transport_auth.is_some() {
            results.push(
                CheckResult::pass(
                    "SEC-056",
                    CAT,
                    Severity::Warning,
                    "requireTransportAuth is not disabled",
                )
                .at_element("ApplicationDefaults"),
            );
        }
    }

    // SEC-057: requireConfidentiality="false" (allows unencrypted back-channel)
    if let Some(ref app) = sc.application_defaults {
        if app.require_confidentiality.as_deref() == Some("false") {
            results.push(
                CheckResult::fail(
                    "SEC-057",
                    CAT,
                    Severity::Warning,
                    "requireConfidentiality=\"false\" allows unencrypted back-channel communication",
                    Some("Remove requireConfidentiality=\"false\" or set to \"true\" to require encrypted back-channel"),
                ).at_element("ApplicationDefaults")
                .with_doc(doc_for(DOC_APP_DEFAULTS, v)),
            );
        } else if app.require_confidentiality.is_some() {
            results.push(
                CheckResult::pass(
                    "SEC-057",
                    CAT,
                    Severity::Warning,
                    "requireConfidentiality is not disabled",
                )
                .at_element("ApplicationDefaults"),
            );
        }
    }

    // SEC-058: exportACL set beyond localhost (assertion export exposed)
    if let Some(ref sessions) = sc.sessions {
        if let Some(ref acl) = sessions.export_acl {
            let trimmed = acl.trim();
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            let is_localhost_only = parts
                .iter()
                .all(|p| *p == "127.0.0.1" || *p == "::1" || *p == "localhost");
            if !is_localhost_only {
                results.push(
                    CheckResult::fail(
                        "SEC-058",
                        CAT,
                        Severity::Warning,
                        &format!("exportACL extends beyond localhost: {}", acl),
                        Some("Restrict exportACL to \"127.0.0.1 ::1\" to limit assertion export access"),
                    ).at_element("Sessions")
                    .with_doc(doc_for(DOC_SESSIONS, v)),
                );
            } else {
                results.push(
                    CheckResult::pass(
                        "SEC-058",
                        CAT,
                        Severity::Warning,
                        "exportACL is restricted to localhost",
                    )
                    .at_element("Sessions"),
                );
            }
        }
    }

    // SEC-059: exportLocation set (assertion export is enabled)
    if let Some(ref sessions) = sc.sessions {
        if let Some(ref loc) = sessions.export_location {
            let acl_safe = sessions
                .export_acl
                .as_ref()
                .map(|a| {
                    let parts: Vec<&str> = a.split_whitespace().collect();
                    parts
                        .iter()
                        .all(|p| *p == "127.0.0.1" || *p == "::1" || *p == "localhost")
                })
                .unwrap_or(false);
            if acl_safe {
                results.push(
                    CheckResult::pass(
                        "SEC-059",
                        CAT,
                        Severity::Info,
                        &format!(
                            "exportLocation is set ({}) with localhost-only exportACL",
                            loc
                        ),
                    )
                    .at_element("Sessions"),
                );
            } else {
                results.push(
                    CheckResult::fail(
                        "SEC-059",
                        CAT,
                        Severity::Warning,
                        &format!(
                            "exportLocation is set ({}) without restrictive exportACL",
                            loc
                        ),
                        Some("Set exportACL=\"127.0.0.1 ::1\" when using exportLocation to restrict access"),
                    ).at_element("Sessions")
                    .with_doc(doc_for(DOC_SESSIONS, v)),
                );
            }
        }
    }

    // SEC-060: LogoutInitiator signing not set (logout requests may be unsigned)
    for li in &sc.logout_initiators {
        if li.signing.is_none() {
            results.push(
                CheckResult::fail(
                    "SEC-060",
                    CAT,
                    Severity::Warning,
                    "LogoutInitiator has no 'signing' attribute (logout requests may be unsigned)",
                    Some("Set signing=\"true\" on LogoutInitiator to sign logout requests"),
                )
                .at_element("Logout")
                .with_doc(doc_for(DOC_SESSIONS, v)),
            );
        } else {
            results.push(
                CheckResult::pass(
                    "SEC-060",
                    CAT,
                    Severity::Warning,
                    &format!(
                        "LogoutInitiator signing is set: {}",
                        li.signing.as_deref().unwrap_or("?")
                    ),
                )
                .at_element("Logout"),
            );
        }
    }

    // SEC-080: supportContact in Errors uses mailto: or contains @ (email exposed to users)
    if let Some(ref errors) = sc.errors {
        if let Some(ref contact) = errors.support_contact {
            if contact.contains('@') || contact.starts_with("mailto:") {
                results.push(
                    CheckResult::fail(
                        "SEC-080",
                        CAT,
                        Severity::Info,
                        &format!(
                            "Errors supportContact exposes an email address: {}",
                            contact
                        ),
                        Some("Consider using a support page URL instead of a direct email to reduce spam/phishing risk"),
                    ).at_element("Errors")
                    .with_doc(doc_for(DOC_APP_DEFAULTS, v)),
                );
            } else {
                results.push(
                    CheckResult::pass(
                        "SEC-080",
                        CAT,
                        Severity::Info,
                        "Errors supportContact does not expose a direct email address",
                    )
                    .at_element("Errors"),
                );
            }
        }
    }

    // SEC-083: logout outgoing binding uses HTTP-GET (tokens visible in URL/logs)
    if let Some(ref sessions) = sc.sessions {
        if let Some(ref bindings) = sessions.logout_outgoing_bindings {
            if bindings.contains("HTTP-GET") || bindings.contains("REDIRECT") {
                results.push(
                    CheckResult::fail(
                        "SEC-083",
                        CAT,
                        Severity::Info,
                        &format!(
                            "Logout outgoing binding includes GET/Redirect: {} (tokens visible in URL/server logs)",
                            bindings
                        ),
                        Some("Prefer SOAP or HTTP-POST bindings for logout to keep tokens out of URLs"),
                    ).at_element("Sessions")
                    .with_doc(doc_for(DOC_SESSIONS, v)),
                );
            } else {
                results.push(
                    CheckResult::pass(
                        "SEC-083",
                        CAT,
                        Severity::Info,
                        "Logout outgoing bindings do not use GET/Redirect",
                    )
                    .at_element("Sessions"),
                );
            }
        }
    }

    // SEC-096: LogoutInitiator asynchronous with signing disabled (logout may not complete reliably)
    for li in &sc.logout_initiators {
        if li.asynchronous.as_deref() == Some("true") && li.signing.as_deref() == Some("false") {
            results.push(
                CheckResult::fail(
                    "SEC-096",
                    CAT,
                    Severity::Info,
                    "LogoutInitiator is asynchronous with signing disabled (logout notifications may be rejected)",
                    Some("Enable signing on asynchronous LogoutInitiators to ensure logout notifications are accepted"),
                ).at_element("Logout")
                .with_doc(doc_for(DOC_SESSIONS, v)),
            );
        }
    }

    // SEC-103: LogoutInitiator notifyWithout set (skips notification to some services)
    for li in &sc.logout_initiators {
        if let Some(ref nw) = li.notify_without {
            results.push(
                CheckResult::fail(
                    "SEC-103",
                    CAT,
                    Severity::Info,
                    &format!(
                        "LogoutInitiator has notifyWithout=\"{}\" (logout skips notification to some services)",
                        nw
                    ),
                    Some("Ensure all services are notified on logout to prevent dangling sessions"),
                ).at_element("Logout")
                .with_doc(doc_for(DOC_SESSIONS, v)),
            );
        }
    }

    // SEC-104: Errors helpLocation uses plain HTTP
    if let Some(ref errors) = sc.errors {
        if let Some(ref help) = errors.help_location {
            if help.starts_with("http://") {
                results.push(
                    CheckResult::fail(
                        "SEC-104",
                        CAT,
                        Severity::Info,
                        &format!("Errors helpLocation uses plain HTTP: {}", help),
                        Some("Use HTTPS for helpLocation to avoid mixed content and protect user navigation"),
                    ).at_element("Errors")
                    .with_doc(doc_for(DOC_APP_DEFAULTS, v)),
                );
            } else {
                results.push(
                    CheckResult::pass(
                        "SEC-104",
                        CAT,
                        Severity::Info,
                        "Errors helpLocation does not use plain HTTP",
                    )
                    .at_element("Errors"),
                );
            }
        }
    }

    // SEC-105: Notify endpoint count is high (broad logout notification surface)
    if sc.notify_endpoints.len() > 5 {
        results.push(
            CheckResult::fail(
                "SEC-105",
                CAT,
                Severity::Info,
                &format!(
                    "{} Notify endpoints configured (broad logout notification surface)",
                    sc.notify_endpoints.len()
                ),
                Some("Review Notify endpoints to ensure only necessary services receive logout notifications"),
            ).at_element("Notify")
            .with_doc(doc_for(DOC_SESSIONS, v)),
        );
    }

    // SEC-106: No attributePrefix set (header name collision risk with environment variables)
    if let Some(ref content) = config.shibboleth_xml_content {
        if content.contains("attributePrefix=") {
            results.push(
                CheckResult::pass(
                    "SEC-106",
                    CAT,
                    Severity::Info,
                    "attributePrefix is set (reduces header name collision risk)",
                )
                .at_element("ApplicationDefaults"),
            );
        } else {
            results.push(
                CheckResult::fail(
                    "SEC-106",
                    CAT,
                    Severity::Info,
                    "No attributePrefix set — attribute headers may collide with other environment variables",
                    Some("Set attributePrefix on <ApplicationDefaults> to namespace attribute headers (e.g., \"AJP_\")"),
                ).at_element("ApplicationDefaults")
                .with_doc(doc_for(DOC_APP_DEFAULTS, v)),
            );
        }
    }

    // SEC-111: Errors session/access/ssl template paths are absolute URLs (potential redirect)
    if let Some(ref errors) = sc.errors {
        let templates = [
            ("sessionError", &errors.session_error),
            ("accessError", &errors.access_error),
            ("sslError", &errors.ssl_error),
            ("localLogout", &errors.local_logout),
            ("globalLogout", &errors.global_logout),
            ("metadataError", &errors.metadata_error),
        ];
        for (name, path_opt) in &templates {
            if let Some(ref path) = path_opt {
                if path.starts_with("http://") || path.starts_with("https://") {
                    results.push(
                        CheckResult::fail(
                            "SEC-111",
                            CAT,
                            Severity::Info,
                            &format!(
                                "Errors {} is an absolute URL: {} (redirects user to external page on error)",
                                name, path
                            ),
                            Some("Use local file paths for error templates to avoid redirecting users to external sites"),
                        )
                        .with_doc(doc_for(DOC_APP_DEFAULTS, v)),
                    );
                }
            }
        }
    }

    // SEC-116: ApplicationOverride entityID uses HTTP instead of HTTPS
    for (override_id, entity_id_opt) in &sc.application_override_entity_ids {
        if let Some(ref eid) = entity_id_opt {
            if eid.starts_with("http://") {
                results.push(
                    CheckResult::fail(
                        "SEC-116",
                        CAT,
                        Severity::Warning,
                        &format!(
                            "ApplicationOverride '{}' entityID uses HTTP: {}",
                            override_id, eid
                        ),
                        Some("Use HTTPS for entityID in ApplicationOverride elements"),
                    )
                    .with_doc(doc_for(DOC_APP_DEFAULTS, v)),
                );
            } else {
                results.push(CheckResult::pass(
                    "SEC-116",
                    CAT,
                    Severity::Warning,
                    &format!("ApplicationOverride '{}' entityID uses HTTPS", override_id),
                ));
            }
        }
    }

    // SEC-124: Notify endpoint is same as handlerURL (loop risk)
    if let Some(ref sessions) = sc.sessions {
        if let Some(ref handler_url) = sessions.handler_url {
            for endpoint in &sc.notify_endpoints {
                if endpoint.contains(handler_url) {
                    results.push(
                        CheckResult::fail(
                            "SEC-124",
                            CAT,
                            Severity::Warning,
                            &format!(
                                "Notify endpoint '{}' appears to point back to the SP handler (loop risk)",
                                endpoint
                            ),
                            Some("Notify endpoints should point to application endpoints, not the SP handler itself"),
                        ).at_element("Notify")
                        .with_doc(doc_for(DOC_SESSIONS, v)),
                    );
                }
            }
        }
    }

    // SEC-125: ApplicationOverride entityID is same as parent entityID (shadowing)
    if let Some(ref parent_eid) = sc.entity_id {
        for (override_id, entity_id_opt) in &sc.application_override_entity_ids {
            if let Some(ref eid) = entity_id_opt {
                if eid == parent_eid {
                    results.push(
                        CheckResult::fail(
                            "SEC-125",
                            CAT,
                            Severity::Info,
                            &format!(
                                "ApplicationOverride '{}' has same entityID as parent: {} (redundant — may cause confusion)",
                                override_id, eid
                            ),
                            Some("Use a distinct entityID for ApplicationOverride or omit to inherit the parent's"),
                        )
                        .with_doc(doc_for(DOC_APP_DEFAULTS, v)),
                    );
                }
            }
        }
    }

    check_application_defaults_flags(sc, v, results);
    check_errors_external_parameters(sc, v, results);
    check_redirect_allow_prefixes(sc, v, results);
}

/// SEC-129 (artifactByFilesystem) and SEC-132 (attributePrefix) on ApplicationDefaults.
fn check_application_defaults_flags(
    sc: &ShibbolethConfig,
    v: SpVersion,
    results: &mut Vec<CheckResult>,
) {
    let Some(ref defaults) = sc.application_defaults else {
        return;
    };

    if defaults.artifact_by_filesystem.as_deref() == Some("true") {
        results.push(
            CheckResult::fail(
                "SEC-129",
                CAT,
                Severity::Info,
                "artifactByFilesystem is enabled (file-based external authentication)",
                Some("Only enable this if you use the BackDoor mechanism; the SP then trusts SAML artifacts it finds as files"),
            )
            .at_element("ApplicationDefaults")
            .with_doc(DOC_BACKDOOR),
        );
    }

    if let Some(ref prefix) = defaults.attribute_prefix {
        if prefix.to_uppercase().starts_with("HTTP_") {
            results.push(
                CheckResult::fail(
                    "SEC-132",
                    CAT,
                    Severity::Error,
                    &format!("attributePrefix '{}' starts with HTTP_", prefix),
                    Some("Use another prefix. On IIS, server variables named HTTP_* are treated as request headers without header smuggling protection, which allows impersonation"),
                )
                .at_element("ApplicationDefaults")
                .with_doc(doc_for(DOC_APP_DEFAULTS, v)),
            );
        } else {
            results.push(
                CheckResult::pass(
                    "SEC-132",
                    CAT,
                    Severity::Error,
                    "attributePrefix does not start with HTTP_",
                )
                .at_element("ApplicationDefaults"),
            );
        }
    }
}

/// SEC-131: externalParameters lets the browser fill error page tags.
fn check_errors_external_parameters(
    sc: &ShibbolethConfig,
    v: SpVersion,
    results: &mut Vec<CheckResult>,
) {
    let Some(ref errors) = sc.errors else {
        return;
    };
    match errors.external_parameters.as_deref() {
        Some("true") | Some("1") => results.push(
            CheckResult::fail(
                "SEC-131",
                CAT,
                Severity::Warning,
                "Errors externalParameters is enabled",
                Some("Error page tags can then be filled from browser-supplied values, which exposes users to XSS and phishing. Leave it disabled unless your templates need it"),
            )
            .at_element("Errors")
            .with_doc(doc_for(DOC_ERRORS, v)),
        ),
        Some(_) => results.push(
            CheckResult::pass(
                "SEC-131",
                CAT,
                Severity::Warning,
                "Errors externalParameters is not enabled",
            )
            .at_element("Errors"),
        ),
        None => {}
    }
}

/// SEC-130: redirectAllow entries must end with a slash after the host, or
/// "https://example.com" also matches example.com.evil.com.
fn check_redirect_allow_prefixes(
    sc: &ShibbolethConfig,
    v: SpVersion,
    results: &mut Vec<CheckResult>,
) {
    let Some(ref sessions) = sc.sessions else {
        return;
    };
    let list = sessions
        .redirect_allow
        .as_deref()
        .or(sessions.redirect_whitelist.as_deref());
    let Some(list) = list else {
        return;
    };
    let bad: Vec<&str> = list
        .split_whitespace()
        .filter(|prefix| {
            // Needs scheme://host[:port]/ — a "/" after the authority
            prefix
                .split_once("://")
                .is_none_or(|(_, rest)| !rest.contains('/') || rest.starts_with('/'))
        })
        .collect();
    if bad.is_empty() {
        results.push(
            CheckResult::pass(
                "SEC-130",
                CAT,
                Severity::Warning,
                "redirect allow-list entries end with a slash after the host",
            )
            .at_element("Sessions"),
        );
    } else {
        results.push(
            CheckResult::fail(
                "SEC-130",
                CAT,
                Severity::Warning,
                &format!(
                    "redirect allow-list entries lack a trailing slash: {}",
                    bad.join(", ")
                ),
                Some("Write each prefix as scheme://hostname[:port]/ . Without the slash, https://example.com also allows example.com.evil.com"),
            )
            .at_element("Sessions")
            .with_doc(doc_for(DOC_SESSIONS, v)),
        );
    }
}
