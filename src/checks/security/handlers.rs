use super::*;

pub(super) fn run(sc: &ShibbolethConfig, v: SpVersion, results: &mut Vec<CheckResult>) {
    // SEC-015: Status handler ACL configured
    if let Some(ref handler) = sc.status_handler {
        if handler.acl.as_ref().is_some_and(|acl| !acl.is_empty()) {
            results.push(CheckResult::pass(
                "SEC-015",
                CAT,
                Severity::Info,
                "Status handler ACL is configured",
            ));
        } else {
            results.push(
                CheckResult::fail(
                    "SEC-015",
                    CAT,
                    Severity::Info,
                    "Status handler has no ACL configured",
                    Some("Set acl attribute on the Status handler to restrict access"),
                )
                .with_doc(doc_for(DOC_STATUS_HANDLER, v)),
            );
        }
    } else {
        results.push(CheckResult::pass(
            "SEC-015",
            CAT,
            Severity::Info,
            "No Status handler found (not exposed)",
        ));
    }

    // SEC-032: Session handler showAttributeValues="true" exposes PII
    {
        let mut has_exposed = false;
        for handler in &sc.handlers {
            if handler
                .show_attribute_values
                .as_deref()
                .is_some_and(|v| v == "true")
            {
                let loc = handler.location.as_deref().unwrap_or("(unknown)");
                results.push(
                    CheckResult::fail(
                        "SEC-032",
                        CAT,
                        Severity::Warning,
                        &format!(
                            "Handler at {} has showAttributeValues=\"true\" (exposes PII)",
                            loc
                        ),
                        Some("Remove showAttributeValues or set to \"false\" in production"),
                    )
                    .with_doc(doc_for(DOC_STATUS_HANDLER, v)),
                );
                has_exposed = true;
            }
        }
        if !has_exposed && !sc.handlers.is_empty() {
            results.push(CheckResult::pass(
                "SEC-032",
                CAT,
                Severity::Warning,
                "No handlers expose attribute values",
            ));
        }
    }

    // SEC-033: Session handler lacks ACL restriction
    {
        let session_handlers: Vec<_> = sc
            .handlers
            .iter()
            .filter(|h| {
                h.handler_type.contains("Session")
                    || h.handler_type.contains("Status")
                    || h.handler_type.contains("MetadataGenerator")
            })
            .collect();
        let mut has_missing_acl = false;
        for handler in &session_handlers {
            if handler.acl.is_none() {
                let loc = handler.location.as_deref().unwrap_or("(unknown)");
                results.push(
                    CheckResult::fail(
                        "SEC-033",
                        CAT,
                        Severity::Info,
                        &format!(
                            "Handler type='{}' at {} has no ACL restriction",
                            handler.handler_type, loc
                        ),
                        Some("Add acl attribute to restrict handler access (e.g., acl=\"127.0.0.1 ::1\")"),
                    )
                    .with_doc(doc_for(DOC_STATUS_HANDLER, v)),
                );
                has_missing_acl = true;
            }
        }
        if !has_missing_acl && !session_handlers.is_empty() {
            results.push(CheckResult::pass(
                "SEC-033",
                CAT,
                Severity::Info,
                "All sensitive handlers have ACL restrictions",
            ));
        }
    }

    // SEC-046: MetadataGenerator handler has no ACL restriction
    {
        for handler in &sc.handlers {
            if handler.handler_type.contains("MetadataGenerator") {
                if handler.acl.is_some() {
                    results.push(CheckResult::pass(
                        "SEC-046",
                        CAT,
                        Severity::Warning,
                        "MetadataGenerator handler has ACL restriction",
                    ));
                } else {
                    results.push(
                        CheckResult::fail(
                            "SEC-046",
                            CAT,
                            Severity::Warning,
                            "MetadataGenerator handler has no ACL restriction",
                            Some(
                                "Add acl attribute to MetadataGenerator handler to restrict access",
                            ),
                        )
                        .with_doc(doc_for(DOC_STATUS_HANDLER, v)),
                    );
                }
            }
        }
    }

    // SEC-047: DiscoveryFeed handler has no ACL restriction
    {
        for handler in &sc.handlers {
            if handler.handler_type.contains("DiscoveryFeed") {
                if handler.acl.is_some() {
                    results.push(CheckResult::pass(
                        "SEC-047",
                        CAT,
                        Severity::Warning,
                        "DiscoveryFeed handler has ACL restriction",
                    ));
                } else {
                    results.push(
                        CheckResult::fail(
                            "SEC-047",
                            CAT,
                            Severity::Warning,
                            "DiscoveryFeed handler has no ACL restriction",
                            Some("Add acl attribute to DiscoveryFeed handler to restrict access"),
                        )
                        .with_doc(doc_for(DOC_STATUS_HANDLER, v)),
                    );
                }
            }
        }
    }

    // SEC-062: ExternalAuth handler has no ACL (authentication bypass risk)
    for handler in &sc.handlers {
        if handler.handler_type == "ExternalAuth" {
            if handler.acl.is_some() {
                results.push(CheckResult::pass(
                    "SEC-062",
                    CAT,
                    Severity::Warning,
                    "ExternalAuth handler has ACL restriction",
                ));
            } else {
                results.push(
                    CheckResult::fail(
                        "SEC-062",
                        CAT,
                        Severity::Warning,
                        "ExternalAuth handler has no ACL (authentication bypass risk)",
                        Some("Add acl=\"127.0.0.1 ::1\" to the ExternalAuth handler to restrict access"),
                    )
                    .with_doc(doc_for(DOC_STATUS_HANDLER, v)),
                );
            }
        }
    }

    // SEC-063: AttributeResolver handler has no ACL (PII exposure)
    for handler in &sc.handlers {
        if handler.handler_type == "AttributeResolver" {
            if handler.acl.is_some() {
                results.push(CheckResult::pass(
                    "SEC-063",
                    CAT,
                    Severity::Warning,
                    "AttributeResolver handler has ACL restriction",
                ));
            } else {
                results.push(
                    CheckResult::fail(
                        "SEC-063",
                        CAT,
                        Severity::Warning,
                        "AttributeResolver handler has no ACL (PII exposure risk)",
                        Some("Add acl=\"127.0.0.1 ::1\" to the AttributeResolver handler to restrict access"),
                    )
                    .with_doc(doc_for(DOC_STATUS_HANDLER, v)),
                );
            }
        }
    }

    // SEC-064: Handler ACL contains broad CIDR (0.0.0.0/0 or ::/0)
    for handler in &sc.handlers {
        if let Some(ref acl) = handler.acl {
            if acl.contains("0.0.0.0/0") || acl.contains("::/0") {
                results.push(
                    CheckResult::fail(
                        "SEC-064",
                        CAT,
                        Severity::Info,
                        &format!(
                            "Handler type='{}' ACL contains broad CIDR: {}",
                            handler.handler_type, acl
                        ),
                        Some("Restrict ACL to specific IP addresses or subnets instead of 0.0.0.0/0 or ::/0"),
                    )
                    .with_doc(doc_for(DOC_STATUS_HANDLER, v)),
                );
            }
        }
    }

    // SEC-090: ECP (Enhanced Client/Proxy) enabled — requires additional authentication controls
    if sc.sso_ecp.as_deref() == Some("true") {
        results.push(
            CheckResult::fail(
                "SEC-090",
                CAT,
                Severity::Info,
                "ECP (Enhanced Client/Proxy) is enabled — allows non-browser authentication",
                Some("Ensure ECP clients are properly authenticated and consider disabling if not needed"),
            )
            .with_doc(doc_for(DOC_SSO, v)),
        );
    } else if sc.sso_ecp.is_some() {
        results.push(CheckResult::pass(
            "SEC-090",
            CAT,
            Severity::Info,
            "ECP is not enabled",
        ));
    }

    // SEC-094: Handler Location path is at root "/" (broad handler exposure)
    for handler in &sc.handlers {
        if handler.location.as_deref() == Some("/") {
            results.push(
                CheckResult::fail(
                    "SEC-094",
                    CAT,
                    Severity::Warning,
                    &format!(
                        "Handler type='{}' is at Location=\"/\" (root path — intercepts all requests)",
                        handler.handler_type
                    ),
                    Some("Use a specific subpath for handler Locations (e.g., /Shibboleth.sso/Status)"),
                )
                .with_doc(doc_for(DOC_STATUS_HANDLER, v)),
            );
        }
    }

    // SEC-102: RequestMapper type is "Native" (relies on web server config for access control)
    if let Some(ref rmt) = sc.request_map_type {
        if rmt == "Native" {
            results.push(
                CheckResult::fail(
                    "SEC-102",
                    CAT,
                    Severity::Info,
                    "RequestMapper type=\"Native\" — access control relies on web server configuration, not SP XML",
                    Some("Ensure web server configuration properly enforces Shibboleth protection on intended paths"),
                )
                .with_doc(doc_for(DOC_APP_DEFAULTS, v)),
            );
        }
    }

    // SEC-113: DiagnosticService handler has no ACL
    for handler in &sc.handlers {
        if handler.handler_type.contains("Diagnostic") {
            if handler.acl.is_some() {
                results.push(CheckResult::pass(
                    "SEC-113",
                    CAT,
                    Severity::Warning,
                    "DiagnosticService handler has ACL restriction",
                ));
            } else {
                results.push(
                    CheckResult::fail(
                        "SEC-113",
                        CAT,
                        Severity::Warning,
                        "DiagnosticService handler has no ACL (exposes internal diagnostics)",
                        Some("Add acl=\"127.0.0.1 ::1\" to the DiagnosticService handler to restrict access"),
                    )
                    .with_doc(doc_for(DOC_STATUS_HANDLER, v)),
                );
            }
        }
    }

    // SEC-115: Handler at default Shibboleth.sso path without ACL (information disclosure handlers)
    {
        let info_handlers = [
            "Session",
            "Status",
            "MetadataGenerator",
            "DiscoveryFeed",
            "Diagnostic",
        ];
        for handler in &sc.handlers {
            if info_handlers.contains(&handler.handler_type.as_str()) {
                if let Some(ref loc) = handler.location {
                    if loc.contains("Shibboleth.sso") && handler.acl.is_none() {
                        results.push(
                            CheckResult::fail(
                                "SEC-115",
                                CAT,
                                Severity::Info,
                                &format!(
                                    "Handler type='{}' at default path '{}' has no ACL restriction",
                                    handler.handler_type, loc
                                ),
                                Some("Add an ACL to restrict access to informational handlers at well-known paths"),
                            )
                            .with_doc(doc_for(DOC_STATUS_HANDLER, v)),
                        );
                    }
                }
            }
        }
    }

    // SEC-119: Duplicate handler Locations (may cause routing conflicts)
    {
        let mut locations: Vec<&str> = Vec::new();
        let mut duplicates: Vec<String> = Vec::new();
        for handler in &sc.handlers {
            if let Some(ref loc) = handler.location {
                if locations.contains(&loc.as_str()) {
                    if !duplicates.contains(loc) {
                        duplicates.push(loc.clone());
                    }
                } else {
                    locations.push(loc);
                }
            }
        }
        if !duplicates.is_empty() {
            results.push(
                CheckResult::fail(
                    "SEC-119",
                    CAT,
                    Severity::Warning,
                    &format!(
                        "Duplicate handler Locations: {} (may cause routing conflicts or handler shadowing)",
                        duplicates.join(", ")
                    ),
                    Some("Ensure each handler has a unique Location to avoid unpredictable behavior"),
                )
                .with_doc(doc_for(DOC_STATUS_HANDLER, v)),
            );
        } else if !locations.is_empty() {
            results.push(CheckResult::pass(
                "SEC-119",
                CAT,
                Severity::Warning,
                "All handler Locations are unique",
            ));
        }
    }

    check_loopback_handlers(sc, results);
}

/// True when every address in an ACL is loopback (or the name `localhost`).
pub(super) fn acl_is_loopback_only(acl: &str) -> bool {
    acl.split_whitespace().all(|a| {
        let host = a.split('/').next().unwrap_or(a);
        host == "::1" || host == "localhost" || host.starts_with("127.")
    })
}

/// SEC-128: the ExternalAuth and AttributeResolver handlers have no security beyond
/// their ACL and are meant for local use only.
fn check_loopback_handlers(sc: &ShibbolethConfig, results: &mut Vec<CheckResult>) {
    for handler in &sc.handlers {
        let doc = match handler.handler_type.as_str() {
            "ExternalAuth" => DOC_EXTERNAL_AUTH,
            "AttributeResolver" => DOC_ATTR_RESOLVER_HANDLER,
            _ => continue,
        };
        let Some(ref acl) = handler.acl else {
            continue; // SEC-062 / SEC-063 report a missing ACL
        };
        if acl_is_loopback_only(acl) {
            results.push(
                CheckResult::pass(
                    "SEC-128",
                    CAT,
                    Severity::Warning,
                    &format!(
                        "{} handler ACL is limited to loopback",
                        handler.handler_type
                    ),
                )
                .at_element("Handler"),
            );
        } else {
            results.push(
                CheckResult::fail(
                    "SEC-128",
                    CAT,
                    Severity::Warning,
                    &format!(
                        "{} handler ACL allows non-loopback addresses: {}",
                        handler.handler_type, acl
                    ),
                    Some("Limit acl to 127.0.0.1 and ::1. The handler has no other protection, so any address you add must be on a secured network"),
                )
                .at_element("Handler")
                .with_doc(doc),
            );
        }
    }
}
