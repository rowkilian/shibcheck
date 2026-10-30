use super::handlers::acl_is_loopback_only;
use super::*;

pub(super) fn run(
    config: &DiscoveredConfig,
    sc: &ShibbolethConfig,
    v: SpVersion,
    results: &mut Vec<CheckResult>,
) {
    // SEC-030: Config files not world-writable (Unix)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let config_files = [
            "shibboleth2.xml",
            "attribute-map.xml",
            "attribute-policy.xml",
        ];
        for file in &config_files {
            let full_path = config.base_dir.join(file);
            if full_path.exists() {
                if let Ok(metadata) = std::fs::metadata(&full_path) {
                    let mode = metadata.permissions().mode();
                    if mode & 0o002 != 0 {
                        results.push(
                            CheckResult::fail(
                                "SEC-030",
                                CAT,
                                Severity::Warning,
                                &format!(
                                    "Config file {} is world-writable (mode {:04o})",
                                    file,
                                    mode & 0o7777
                                ),
                                Some("Remove world-write permission: chmod o-w"),
                            )
                            .with_doc(doc_for(DOC_APP_DEFAULTS, v)),
                        );
                    } else {
                        results.push(CheckResult::pass(
                            "SEC-030",
                            CAT,
                            Severity::Warning,
                            &format!(
                                "Config file {} is not world-writable (mode {:04o})",
                                file,
                                mode & 0o7777
                            ),
                        ));
                    }
                }
            }
        }
    }

    // SEC-036: No spoofKey configured (header spoofing risk). IIS generates one itself.
    if !sc.has_isapi {
        let r = if sc.in_process_spoof_key_set {
            CheckResult::pass("SEC-036", CAT, Severity::Warning, "spoofKey is configured")
        } else {
            CheckResult::fail(
                "SEC-036",
                CAT,
                Severity::Warning,
                "No spoofKey on <InProcess>; the SP falls back to a weaker check for spoofed headers",
                Some("Set spoofKey on <InProcess> to a long random value when attributes reach the application as headers"),
            )
            .with_doc(DOC_INPROCESS)
        };
        results.push(if sc.has_in_process {
            r.at_element("InProcess")
        } else {
            r
        });
    }
    // SEC-044: TCPListener binds to non-localhost address
    if let Some(ref addr) = sc.tcp_listener_address {
        let lower = addr.to_lowercase();
        if lower == "127.0.0.1" || lower == "::1" || lower == "localhost" {
            results.push(
                CheckResult::pass(
                    "SEC-044",
                    CAT,
                    Severity::Warning,
                    &format!("TCPListener binds to localhost: {}", addr),
                )
                .at_element("TCPListener"),
            );
        } else {
            results.push(
                CheckResult::fail(
                    "SEC-044",
                    CAT,
                    Severity::Warning,
                    &format!(
                        "TCPListener binds to non-localhost address: {} (exposes internal socket)",
                        addr
                    ),
                    Some("Set address=\"127.0.0.1\" on <TCPListener> to bind only to localhost"),
                )
                .at_element("TCPListener")
                .with_doc(doc_for(DOC_SESSIONS, v)),
            );
        }
    }

    // SEC-081: listener choice
    if sc.has_unix_listener {
        results.push(
            CheckResult::pass(
                "SEC-081",
                CAT,
                Severity::Info,
                "UnixListener is configured (uses Unix domain socket)",
            )
            .at_element("UnixListener"),
        );
    } else if sc.has_tcp_listener && sc.tcp_listener_address.is_none() {
        results.push(
            CheckResult::fail(
                "SEC-081",
                CAT,
                Severity::Info,
                "TCPListener used without explicit address (may bind to all interfaces)",
                Some("Set address=\"127.0.0.1\" on <TCPListener> or switch to <UnixListener> for local-only communication"),
            )
            .at_element("TCPListener")
            .with_doc(doc_for(DOC_SESSIONS, v)),
        );
    }
    // SEC-121: catchAll="true" traps crashes, which hides bugs and can leave the process unstable
    for (element, value) in [
        ("OutOfProcess", &sc.out_of_process_catch_all),
        ("InProcess", &sc.in_process_catch_all),
    ] {
        if value.as_deref().map(str::trim) == Some("true") {
            results.push(
                CheckResult::fail(
                    "SEC-121",
                    CAT,
                    Severity::Info,
                    &format!("{element} has catchAll=\"true\", so crashes are trapped instead of reported"),
                    Some("Remove catchAll in production so failures surface in monitoring; the docs say it should generally be left off"),
                )
                .at_element(element)
                .with_doc(doc_for(DOC_APP_DEFAULTS, v)),
            );
        }
    }

    check_web_server_settings(sc, results);
}

/// SEC-133 (checkSpoofing), SEC-134 (ISAPI normalizeRequest), SEC-135 (ISAPI useHeaders)
/// and SEC-136 (TCPListener acl).
fn check_web_server_settings(sc: &ShibbolethConfig, results: &mut Vec<CheckResult>) {
    if let Some(ref value) = sc.in_process_check_spoofing {
        if value == "false" || value == "0" {
            results.push(
                CheckResult::fail(
                    "SEC-133",
                    CAT,
                    Severity::Warning,
                    "InProcess checkSpoofing is disabled",
                    Some("Leave checkSpoofing enabled. It rejects requests whose headers clash with names the SP controls; fix false alarms with spoofKey instead"),
                )
                .at_element("InProcess")
                .with_doc(DOC_INPROCESS),
            );
        } else {
            results.push(
                CheckResult::pass(
                    "SEC-133",
                    CAT,
                    Severity::Warning,
                    "InProcess checkSpoofing is enabled",
                )
                .at_element("InProcess"),
            );
        }
    }

    if sc.isapi_normalize_request.as_deref() == Some("false") {
        results.push(
            CheckResult::fail(
                "SEC-134",
                CAT,
                Severity::Warning,
                "ISAPI normalizeRequest is disabled",
                Some("Leave normalizeRequest enabled. Turning it off generally causes security issues unless you avoid content settings and the RequestMapper"),
            )
            .at_element("ISAPI")
            .with_doc(DOC_ISAPI),
        );
    }

    if sc.isapi_use_headers.as_deref() == Some("true") || !sc.site_use_headers.is_empty() {
        results.push(
            CheckResult::fail(
                "SEC-135",
                CAT,
                Severity::Info,
                "IIS passes attributes as HTTP headers (useHeaders=\"true\")",
                Some("Avoid useHeaders and read attributes from server variables. Headers are only there for compatibility with applications written for the old ISAPI extension"),
            )
            .at_element("ISAPI")
            .with_doc(DOC_ISAPI),
        );
    }

    if let Some(ref acl) = sc.tcp_listener_acl {
        if acl_is_loopback_only(acl) {
            results.push(
                CheckResult::pass(
                    "SEC-136",
                    CAT,
                    Severity::Warning,
                    "TCPListener acl is limited to loopback",
                )
                .at_element("TCPListener"),
            );
        } else {
            results.push(
                CheckResult::fail(
                    "SEC-136",
                    CAT,
                    Severity::Warning,
                    &format!("TCPListener acl allows non-loopback addresses: {}", acl),
                    Some("Keep the listener on 127.0.0.1 and ::1. The shibd link is not secured, so any other address needs a network you control"),
                )
                .at_element("TCPListener")
                .with_doc(DOC_LISTENER),
            );
        }
    }
}
