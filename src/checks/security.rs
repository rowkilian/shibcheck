use chrono::Utc;

use crate::config::DiscoveredConfig;
use crate::model::shibboleth_config::SpVersion;
use crate::parsers::certificate;
use crate::result::{CheckCategory, CheckResult, Severity};

const CAT: CheckCategory = CheckCategory::Security;

// Shibboleth SP3 documentation URLs
const DOC_SESSIONS: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334342/Sessions";
const DOC_CREDENTIAL_RESOLVER: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334414/CredentialResolver";
const DOC_SIGNING_ENCRYPTION: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334379/SigningEncryption";
const DOC_SIGNATURE_FILTER: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2063696211/SignatureMetadataFilter";
const DOC_VALID_UNTIL_FILTER: &str = "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2063696214/RequireValidUntilMetadataFilter";
const DOC_METADATA_PROVIDER: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2060616124/MetadataProvider";
const DOC_STATUS_HANDLER: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334870/Status+Handler";
const DOC_APP_DEFAULTS: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2063695997/ApplicationDefaults";
const DOC_SSO: &str = "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334348/SSO";

const DOC_SP2_WIKI: &str = "https://shibboleth.atlassian.net/wiki/spaces/SHIB2/";

fn doc_for(sp3_url: &str, version: SpVersion) -> &str {
    match version {
        SpVersion::V2 => DOC_SP2_WIKI,
        _ => sp3_url,
    }
}

pub fn run(config: &DiscoveredConfig) -> Vec<CheckResult> {
    let mut results = Vec::new();

    let sc = match config.shibboleth_config.as_ref() {
        Some(sc) => sc,
        None => return results,
    };

    let v = sc.sp_version;

    // SEC-001: handlerSSL=true
    if let Some(ref sessions) = sc.sessions {
        match sessions.handler_ssl.as_deref() {
            Some("true") => {
                results.push(CheckResult::pass(
                    "SEC-001",
                    CAT,
                    Severity::Warning,
                    "handlerSSL is set to true",
                ));
            }
            Some("false") => {
                results.push(CheckResult::fail(
                    "SEC-001", CAT, Severity::Warning,
                    "handlerSSL is set to false",
                    Some("Set handlerSSL=\"true\" on <Sessions> to require HTTPS for handler endpoints"),
                ).with_doc(doc_for(DOC_SESSIONS, v)));
            }
            _ => {
                results.push(CheckResult::fail(
                    "SEC-001", CAT, Severity::Warning,
                    "handlerSSL is not explicitly set",
                    Some("Set handlerSSL=\"true\" on <Sessions> to require HTTPS for handler endpoints"),
                ).with_doc(doc_for(DOC_SESSIONS, v)));
            }
        }
    }

    // SEC-002: cookieProps includes "secure"
    if let Some(ref sessions) = sc.sessions {
        if let Some(ref cookie_props) = sessions.cookie_props {
            let lower = cookie_props.to_lowercase();
            let https_shorthand = lower == "https" && v == SpVersion::V3;
            if lower.contains("secure") || https_shorthand {
                results.push(CheckResult::pass(
                    "SEC-002",
                    CAT,
                    Severity::Warning,
                    "cookieProps includes secure flag",
                ));
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
                results.push(CheckResult::pass(
                    "SEC-003",
                    CAT,
                    Severity::Warning,
                    "cookieProps includes httpOnly flag",
                ));
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
                .with_doc(doc_for(DOC_SESSIONS, v)),
            );
        }
    }

    // SEC-004: Signing credentials configured
    let has_signing = sc
        .credential_resolvers
        .iter()
        .any(|cr| cr.use_attr.as_deref().is_none_or(|u| u.contains("signing")));
    if has_signing && !sc.credential_resolvers.is_empty() {
        results.push(CheckResult::pass(
            "SEC-004",
            CAT,
            Severity::Warning,
            "Signing credentials configured",
        ));
    } else {
        results.push(
            CheckResult::fail(
                "SEC-004",
                CAT,
                Severity::Warning,
                "No signing credentials configured",
                Some("Add a <CredentialResolver> with use=\"signing\" for SAML signing"),
            )
            .with_doc(doc_for(DOC_CREDENTIAL_RESOLVER, v)),
        );
    }

    // SEC-005: Encryption credentials configured
    let has_encryption = sc.credential_resolvers.iter().any(|cr| {
        cr.use_attr
            .as_deref()
            .is_none_or(|u| u.contains("encryption"))
    });
    if has_encryption && !sc.credential_resolvers.is_empty() {
        results.push(CheckResult::pass(
            "SEC-005",
            CAT,
            Severity::Warning,
            "Encryption credentials configured",
        ));
    } else {
        results.push(
            CheckResult::fail(
                "SEC-005",
                CAT,
                Severity::Warning,
                "No encryption credentials configured",
                Some("Add a <CredentialResolver> with use=\"encryption\" for SAML encryption"),
            )
            .with_doc(doc_for(DOC_CREDENTIAL_RESOLVER, v)),
        );
    }

    // SEC-006: signing attribute on ApplicationDefaults
    if let Some(ref app) = sc.application_defaults {
        if let Some(ref signing) = app.signing {
            if signing == "true" || signing == "front" || signing == "back" {
                results.push(CheckResult::pass(
                    "SEC-006",
                    CAT,
                    Severity::Info,
                    "signing attribute set on ApplicationDefaults",
                ));
            } else {
                results.push(
                    CheckResult::fail(
                        "SEC-006",
                        CAT,
                        Severity::Info,
                        &format!(
                            "signing attribute is '{}' (consider 'true' or 'front')",
                            signing
                        ),
                        Some("Set signing=\"true\" or signing=\"front\" on <ApplicationDefaults>"),
                    )
                    .with_doc(doc_for(DOC_SIGNING_ENCRYPTION, v)),
                );
            }
        } else {
            results.push(
                CheckResult::fail(
                    "SEC-006",
                    CAT,
                    Severity::Info,
                    "signing attribute not set on ApplicationDefaults",
                    Some("Set signing=\"true\" on <ApplicationDefaults> to sign SAML messages"),
                )
                .with_doc(doc_for(DOC_SIGNING_ENCRYPTION, v)),
            );
        }
    }

    // SEC-007: encryption attribute on ApplicationDefaults
    if let Some(ref app) = sc.application_defaults {
        if let Some(ref encryption) = app.encryption {
            if encryption == "true" || encryption == "front" || encryption == "back" {
                results.push(CheckResult::pass(
                    "SEC-007",
                    CAT,
                    Severity::Info,
                    "encryption attribute set on ApplicationDefaults",
                ));
            } else {
                results.push(
                    CheckResult::fail(
                        "SEC-007",
                        CAT,
                        Severity::Info,
                        &format!("encryption attribute is '{}' (consider 'true')", encryption),
                        Some("Set encryption=\"true\" on <ApplicationDefaults>"),
                    )
                    .with_doc(doc_for(DOC_SIGNING_ENCRYPTION, v)),
                );
            }
        } else {
            results.push(CheckResult::fail(
                "SEC-007", CAT, Severity::Info,
                "encryption attribute not set on ApplicationDefaults",
                Some("Set encryption=\"true\" on <ApplicationDefaults> to request encrypted assertions"),
            ).with_doc(doc_for(DOC_SIGNING_ENCRYPTION, v)));
        }
    }

    // SEC-008 through SEC-010 and SEC-013: Certificate checks
    let now = Utc::now();
    for cr in &sc.credential_resolvers {
        if let Some(ref cert_path) = cr.certificate {
            let full_path = config.base_dir.join(cert_path);
            if !full_path.exists() {
                continue; // REF-001 already flags this
            }
            match certificate::parse_pem_file(&full_path) {
                Ok(cert_info) => {
                    // SEC-008: Certificate not expired
                    if cert_info.not_after < now {
                        results.push(
                            CheckResult::fail(
                                "SEC-008",
                                CAT,
                                Severity::Error,
                                &format!(
                                    "Certificate {} has expired ({})",
                                    cert_path,
                                    cert_info.not_after.format("%Y-%m-%d")
                                ),
                                Some("Replace the expired certificate with a new one"),
                            )
                            .with_doc(doc_for(DOC_CREDENTIAL_RESOLVER, v)),
                        );
                    } else {
                        results.push(CheckResult::pass(
                            "SEC-008",
                            CAT,
                            Severity::Error,
                            &format!("Certificate {} is not expired", cert_path),
                        ));
                    }

                    // SEC-009: Certificate expiring within 30 days
                    let days_until_expiry = (cert_info.not_after - now).num_days();
                    if (0..=30).contains(&days_until_expiry) {
                        results.push(
                            CheckResult::fail(
                                "SEC-009",
                                CAT,
                                Severity::Warning,
                                &format!(
                                    "Certificate {} expires in {} days ({})",
                                    cert_path,
                                    days_until_expiry,
                                    cert_info.not_after.format("%Y-%m-%d")
                                ),
                                Some("Plan certificate renewal before expiry"),
                            )
                            .with_doc(doc_for(DOC_CREDENTIAL_RESOLVER, v)),
                        );
                    } else if days_until_expiry > 30 {
                        results.push(CheckResult::pass(
                            "SEC-009",
                            CAT,
                            Severity::Warning,
                            &format!(
                                "Certificate {} expires in {} days",
                                cert_path, days_until_expiry
                            ),
                        ));
                    }

                    // SEC-010: Certificate not-yet-valid
                    if cert_info.not_before > now {
                        results.push(
                            CheckResult::fail(
                                "SEC-010",
                                CAT,
                                Severity::Error,
                                &format!(
                                    "Certificate {} is not yet valid (valid from {})",
                                    cert_path,
                                    cert_info.not_before.format("%Y-%m-%d")
                                ),
                                Some("Check the certificate's notBefore date"),
                            )
                            .with_doc(doc_for(DOC_CREDENTIAL_RESOLVER, v)),
                        );
                    } else {
                        results.push(CheckResult::pass(
                            "SEC-010",
                            CAT,
                            Severity::Error,
                            &format!("Certificate {} validity period has started", cert_path),
                        ));
                    }

                    // SEC-013: Key size >= 2048 bits
                    if cert_info.key_size_bits > 0 {
                        if cert_info.key_size_bits >= 2048 {
                            results.push(CheckResult::pass(
                                "SEC-013",
                                CAT,
                                Severity::Warning,
                                &format!(
                                    "Certificate {} key size is {} bits",
                                    cert_path, cert_info.key_size_bits
                                ),
                            ));
                        } else {
                            results.push(
                                CheckResult::fail(
                                    "SEC-013",
                                    CAT,
                                    Severity::Warning,
                                    &format!(
                                        "Certificate {} key size is {} bits (< 2048)",
                                        cert_path, cert_info.key_size_bits
                                    ),
                                    Some("Use a certificate with at least 2048-bit key size"),
                                )
                                .with_doc(doc_for(DOC_CREDENTIAL_RESOLVER, v)),
                            );
                        }
                    }
                }
                Err(_) => {
                    // Certificate couldn't be parsed - skip cert checks for this file
                }
            }
        }
    }

    // SEC-021: Certificate and key file match
    for cr in &sc.credential_resolvers {
        if let (Some(ref cert_path), Some(ref key_path)) = (&cr.certificate, &cr.key) {
            let full_cert = config.base_dir.join(cert_path);
            let full_key = config.base_dir.join(key_path);
            if full_cert.exists() && full_key.exists() {
                match certificate::check_cert_key_match(&full_cert, &full_key) {
                    Ok(true) => {
                        results.push(CheckResult::pass(
                            "SEC-021",
                            CAT,
                            Severity::Error,
                            &format!(
                                "Certificate {} and key {} form a matching pair",
                                cert_path, key_path
                            ),
                        ));
                    }
                    Ok(false) => {
                        results.push(CheckResult::fail(
                            "SEC-021", CAT, Severity::Error,
                            &format!("Certificate {} and key {} do not match (different RSA modulus)", cert_path, key_path),
                            Some("Ensure the private key corresponds to the certificate's public key"),
                        ).with_doc(doc_for(DOC_CREDENTIAL_RESOLVER, v)));
                    }
                    Err(_) => {
                        // Non-RSA or parse error — skip silently
                    }
                }
            }
        }
    }

    // SEC-011: MetadataFilter with signature validation
    let has_sig_filter = sc.metadata_providers.iter().any(|mp| {
        mp.filters
            .iter()
            .any(|f| f.filter_type.contains("Signature") || f.filter_type.contains("signature"))
    });
    if has_sig_filter {
        results.push(CheckResult::pass(
            "SEC-011",
            CAT,
            Severity::Warning,
            "Metadata signature validation configured",
        ));
    } else if !sc.metadata_providers.is_empty() {
        results.push(
            CheckResult::fail(
                "SEC-011",
                CAT,
                Severity::Warning,
                "No MetadataFilter with signature validation found",
                Some(
                    "Add a <MetadataFilter type=\"Signature\" ...> to validate metadata signatures",
                ),
            )
            .with_doc(doc_for(DOC_SIGNATURE_FILTER, v)),
        );
    }

    // SEC-012: MetadataFilter with RequireValidUntil
    let has_valid_until = sc.metadata_providers.iter().any(|mp| {
        mp.filters
            .iter()
            .any(|f| f.filter_type.contains("RequireValidUntil"))
    });
    if has_valid_until {
        results.push(CheckResult::pass(
            "SEC-012",
            CAT,
            Severity::Info,
            "RequireValidUntil metadata filter configured",
        ));
    } else if !sc.metadata_providers.is_empty() {
        results.push(
            CheckResult::fail(
                "SEC-012",
                CAT,
                Severity::Info,
                "No MetadataFilter with RequireValidUntil found",
                Some("Add a <MetadataFilter type=\"RequireValidUntil\"> to reject stale metadata"),
            )
            .with_doc(doc_for(DOC_VALID_UNTIL_FILTER, v)),
        );
    }

    // SEC-014: No plaintext HTTP metadata URLs
    let mut has_http_url = false;
    for mp in &sc.metadata_providers {
        for url in [&mp.uri, &mp.url].into_iter().flatten() {
            if url.starts_with("http://") {
                results.push(
                    CheckResult::fail(
                        "SEC-014",
                        CAT,
                        Severity::Warning,
                        &format!("MetadataProvider uses plaintext HTTP URL: {}", url),
                        Some("Use HTTPS for metadata URLs to prevent tampering"),
                    )
                    .with_doc(doc_for(DOC_METADATA_PROVIDER, v)),
                );
                has_http_url = true;
            }
        }
    }
    if !has_http_url && !sc.metadata_providers.is_empty() {
        results.push(CheckResult::pass(
            "SEC-014",
            CAT,
            Severity::Warning,
            "No plaintext HTTP metadata URLs found",
        ));
    }

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

    // SEC-017: cookieProps includes SameSite
    if let Some(ref sessions) = sc.sessions {
        if let Some(ref cookie_props) = sessions.cookie_props {
            let lower = cookie_props.to_lowercase();
            // "https" shorthand does NOT imply SameSite in Shibboleth
            if lower.contains("samesite") {
                results.push(CheckResult::pass(
                    "SEC-017",
                    CAT,
                    Severity::Info,
                    "cookieProps includes SameSite attribute",
                ));
            } else {
                let suggestion = if v == SpVersion::V2 {
                    "SP2 does not support SameSite in cookieProps; set it via web server headers or upgrade to SP3"
                } else {
                    "Add 'SameSite=None' to cookieProps for cross-site SSO in modern browsers"
                };
                results.push(
                    CheckResult::fail(
                        "SEC-017",
                        CAT,
                        Severity::Info,
                        "cookieProps does not include SameSite attribute",
                        Some(suggestion),
                    )
                    .with_doc(doc_for(DOC_SESSIONS, v)),
                );
            }
        } else {
            results.push(
                CheckResult::fail(
                    "SEC-017",
                    CAT,
                    Severity::Info,
                    "cookieProps not set on Sessions",
                    Some(
                        "Set cookieProps with SameSite attribute for modern browser compatibility",
                    ),
                )
                .with_doc(doc_for(DOC_SESSIONS, v)),
            );
        }
    }

    // SEC-018: entityID uses HTTPS (prefer over HTTP)
    if let Some(ref entity_id) = sc.entity_id {
        if entity_id.starts_with("https://") || entity_id.starts_with("urn:") {
            results.push(CheckResult::pass(
                "SEC-018",
                CAT,
                Severity::Info,
                "entityID uses HTTPS or URN scheme",
            ));
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
                .with_doc(doc_for(DOC_APP_DEFAULTS, v)),
            );
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
                        .with_doc(doc_for(DOC_SESSIONS, v)),
                    );
                } else if lifetime > 86400 {
                    results.push(CheckResult::fail(
                        "SEC-019", CAT, Severity::Info,
                        &format!("Sessions lifetime is {} seconds ({:.1} days)", lifetime, lifetime as f64 / 86400.0),
                        Some("Consider a shorter session lifetime (default is 28800 seconds / 8 hours)"),
                    ).with_doc(doc_for(DOC_SESSIONS, v)));
                } else {
                    results.push(CheckResult::pass(
                        "SEC-019",
                        CAT,
                        Severity::Info,
                        &format!(
                            "Sessions lifetime is {} seconds ({:.1} hours)",
                            lifetime,
                            lifetime as f64 / 3600.0
                        ),
                    ));
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
                        .with_doc(doc_for(DOC_SESSIONS, v)),
                    );
                } else if timeout > 28800 {
                    results.push(CheckResult::fail(
                        "SEC-020", CAT, Severity::Info,
                        &format!("Sessions timeout is {} seconds ({:.1} hours)", timeout, timeout as f64 / 3600.0),
                        Some("Consider a shorter idle timeout (default is 3600 seconds / 1 hour)"),
                    ).with_doc(doc_for(DOC_SESSIONS, v)));
                } else {
                    results.push(CheckResult::pass(
                        "SEC-020",
                        CAT,
                        Severity::Info,
                        &format!(
                            "Sessions timeout is {} seconds ({:.1} hours)",
                            timeout,
                            timeout as f64 / 3600.0
                        ),
                    ));
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
                    )
                    .with_doc(doc_for(DOC_SESSIONS, v)),
                );
            } else {
                results.push(CheckResult::pass(
                    "SEC-022",
                    CAT,
                    Severity::Warning,
                    &format!("Sessions redirectLimit is set to '{}'", redirect_limit),
                ));
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
                    )
                    .with_doc(doc_for(DOC_SESSIONS, v)),
                );
            } else {
                results.push(CheckResult::pass(
                    "SEC-023",
                    CAT,
                    Severity::Info,
                    "Sessions consistentAddress is not disabled",
                ));
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
                    .with_doc(doc_for(DOC_APP_DEFAULTS, v)),
                );
            } else {
                results.push(CheckResult::pass(
                    "SEC-024",
                    CAT,
                    Severity::Warning,
                    &format!("clockSkew is {}s (within safe range)", skew),
                ));
            }
        }
    }

    // SEC-025: SAML1 not in SSO protocols
    if let Some(ref sessions) = sc.sessions {
        if let Some(ref protocols) = sessions.sso_protocols {
            if protocols.contains("SAML1") {
                results.push(
                    CheckResult::fail(
                        "SEC-025",
                        CAT,
                        Severity::Info,
                        "SSO protocols include SAML1 (deprecated and less secure)",
                        Some("Remove SAML1 from <SSO> and use only SAML2 unless SAML1 is required"),
                    )
                    .with_doc(doc_for(DOC_SSO, v)),
                );
            } else {
                results.push(CheckResult::pass(
                    "SEC-025",
                    CAT,
                    Severity::Info,
                    "SSO protocols do not include SAML1",
                ));
            }
        }
    }

    // SEC-026: maxValidityInterval set and <= 30 days (2592000s)
    {
        let mut has_check = false;
        for mp in &sc.metadata_providers {
            for filter in &mp.filters {
                if filter.filter_type.contains("RequireValidUntil") {
                    if let Some(ref interval_str) = filter.max_validity_interval {
                        has_check = true;
                        if let Ok(interval) = interval_str.parse::<u64>() {
                            if interval <= 2_592_000 {
                                results.push(CheckResult::pass(
                                    "SEC-026",
                                    CAT,
                                    Severity::Info,
                                    &format!(
                                        "maxValidityInterval is {}s ({} days)",
                                        interval,
                                        interval / 86400
                                    ),
                                ));
                            } else {
                                results.push(
                                    CheckResult::fail(
                                        "SEC-026",
                                        CAT,
                                        Severity::Info,
                                        &format!(
                                            "maxValidityInterval is {}s ({} days, > 30 days)",
                                            interval,
                                            interval / 86400
                                        ),
                                        Some(
                                            "Set maxValidityInterval to 2592000 (30 days) or less",
                                        ),
                                    )
                                    .with_doc(doc_for(DOC_METADATA_PROVIDER, v)),
                                );
                            }
                        }
                    } else {
                        has_check = true;
                        results.push(
                            CheckResult::fail(
                                "SEC-026",
                                CAT,
                                Severity::Info,
                                "RequireValidUntil filter has no maxValidityInterval set",
                                Some("Set maxValidityInterval on the RequireValidUntil filter (e.g., 2592000 for 30 days)"),
                            )
                            .with_doc(doc_for(DOC_METADATA_PROVIDER, v)),
                        );
                    }
                }
            }
        }
        if !has_check && !sc.metadata_providers.is_empty() {
            results.push(
                CheckResult::fail(
                    "SEC-026",
                    CAT,
                    Severity::Info,
                    "No RequireValidUntil filter with maxValidityInterval found",
                    Some("Add a RequireValidUntil MetadataFilter with maxValidityInterval"),
                )
                .with_doc(doc_for(DOC_METADATA_PROVIDER, v)),
            );
        }
    }

    // SEC-027: security-policy.xml has no disabled AlgorithmBlacklist
    {
        let security_policy_path = config.base_dir.join("security-policy.xml");
        if security_policy_path.exists() {
            if let Ok(content) = std::fs::read_to_string(&security_policy_path) {
                let lower = content.to_lowercase();
                if lower.contains("algorithmblacklist") || lower.contains("algorithmfilter") {
                    results.push(CheckResult::pass(
                        "SEC-027",
                        CAT,
                        Severity::Warning,
                        "security-policy.xml contains algorithm filtering rules",
                    ));
                } else {
                    results.push(
                        CheckResult::fail(
                            "SEC-027",
                            CAT,
                            Severity::Warning,
                            "security-policy.xml has no AlgorithmBlacklist/AlgorithmFilter",
                            Some("Configure algorithm filtering in security-policy.xml to block weak algorithms"),
                        )
                        .with_doc(doc_for(DOC_APP_DEFAULTS, v)),
                    );
                }
            }
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
                .with_doc(doc_for(DOC_APP_DEFAULTS, v)),
            );
        } else {
            results.push(CheckResult::pass(
                "SEC-028",
                CAT,
                Severity::Warning,
                "entityID is not a placeholder value",
            ));
        }
    }

    // SEC-029: discoveryURL uses HTTPS
    if let Some(ref sessions) = sc.sessions {
        if let Some(ref discovery_url) = sessions.sso_discovery_url {
            if discovery_url.starts_with("https://") {
                results.push(CheckResult::pass(
                    "SEC-029",
                    CAT,
                    Severity::Warning,
                    "SSO discoveryURL uses HTTPS",
                ));
            } else if discovery_url.starts_with("http://") {
                results.push(
                    CheckResult::fail(
                        "SEC-029",
                        CAT,
                        Severity::Warning,
                        &format!("SSO discoveryURL uses HTTP: {}", discovery_url),
                        Some("Use HTTPS for the discovery service URL"),
                    )
                    .with_doc(doc_for(DOC_SSO, v)),
                );
            }
        }
    }

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

    // SEC-031: relayState uses ss: prefix (cookie-based storage)
    if let Some(ref sessions) = sc.sessions {
        if let Some(ref relay_state) = sessions.relay_state {
            if relay_state.starts_with("ss:") {
                results.push(CheckResult::pass(
                    "SEC-031",
                    CAT,
                    Severity::Info,
                    "Sessions relayState uses server-side storage (ss: prefix)",
                ));
            } else if relay_state.starts_with("cookie:") || relay_state == "cookie" {
                results.push(
                    CheckResult::fail(
                        "SEC-031",
                        CAT,
                        Severity::Info,
                        "Sessions relayState uses cookie storage",
                        Some("Consider using ss: prefix for server-side relay state storage"),
                    )
                    .with_doc(doc_for(DOC_SESSIONS, v)),
                );
            } else {
                results.push(CheckResult::pass(
                    "SEC-031",
                    CAT,
                    Severity::Info,
                    &format!("Sessions relayState is set to '{}'", relay_state),
                ));
            }
        }
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

    // SEC-035: Weak cipherSuites on ApplicationDefaults
    if let Some(ref app) = sc.application_defaults {
        if let Some(ref ciphers) = app.cipher_suites {
            let lower = ciphers.to_lowercase();
            let weak_patterns = ["rc4", "des", "null", "export"];
            let found_weak: Vec<&str> = weak_patterns
                .iter()
                .filter(|p| lower.contains(**p))
                .copied()
                .collect();
            if found_weak.is_empty() {
                results.push(CheckResult::pass(
                    "SEC-035",
                    CAT,
                    Severity::Warning,
                    "cipherSuites does not contain known weak ciphers",
                ));
            } else {
                results.push(
                    CheckResult::fail(
                        "SEC-035",
                        CAT,
                        Severity::Warning,
                        &format!(
                            "cipherSuites contains weak cipher pattern(s): {}",
                            found_weak.join(", ")
                        ),
                        Some(
                            "Remove weak cipher suites (RC4, DES, NULL, EXPORT) from cipherSuites",
                        ),
                    )
                    .with_doc(doc_for(DOC_APP_DEFAULTS, v)),
                );
            }
        }
    }

    // SEC-036: No spoofKey configured (header spoofing risk)
    if let Some(ref content) = config.shibboleth_xml_content {
        if content.contains("spoofKey=") {
            results.push(CheckResult::pass(
                "SEC-036",
                CAT,
                Severity::Warning,
                "spoofKey is configured",
            ));
        } else {
            results.push(
                CheckResult::fail(
                    "SEC-036",
                    CAT,
                    Severity::Warning,
                    "No spoofKey configured (header spoofing risk with non-default setup)",
                    Some("Set spoofKey on <ApplicationDefaults> when using header-based attribute passing"),
                )
                .with_doc(doc_for(DOC_APP_DEFAULTS, v)),
            );
        }
    }

    // SEC-038: postLimit set to 0 or > 10MB
    if let Some(ref sessions) = sc.sessions {
        if let Some(ref post_limit_str) = sessions.post_limit {
            if let Ok(limit) = post_limit_str.parse::<u64>() {
                if limit == 0 {
                    results.push(
                        CheckResult::fail(
                            "SEC-038",
                            CAT,
                            Severity::Info,
                            "Sessions postLimit is 0 (no limit on POST data)",
                            Some("Set a reasonable postLimit (e.g., 1048576 for 1MB)"),
                        )
                        .with_doc(doc_for(DOC_SESSIONS, v)),
                    );
                } else if limit > 10_485_760 {
                    results.push(
                        CheckResult::fail(
                            "SEC-038",
                            CAT,
                            Severity::Info,
                            &format!("Sessions postLimit is {} bytes (> 10MB)", limit),
                            Some("Consider a smaller postLimit to prevent abuse"),
                        )
                        .with_doc(doc_for(DOC_SESSIONS, v)),
                    );
                } else {
                    results.push(CheckResult::pass(
                        "SEC-038",
                        CAT,
                        Severity::Info,
                        &format!("Sessions postLimit is {} bytes", limit),
                    ));
                }
            }
        }
    }

    // SEC-039: SecurityPolicyProvider missing validate="true"
    if sc.security_policy_provider_path.is_some() {
        if sc
            .security_policy_provider_validate
            .as_deref()
            .is_some_and(|v| v == "true")
        {
            results.push(CheckResult::pass(
                "SEC-039",
                CAT,
                Severity::Info,
                "SecurityPolicyProvider has validate=\"true\"",
            ));
        } else {
            results.push(
                CheckResult::fail(
                    "SEC-039",
                    CAT,
                    Severity::Info,
                    "SecurityPolicyProvider missing validate=\"true\"",
                    Some("Add validate=\"true\" to SecurityPolicyProvider to validate the policy file on load"),
                )
                .with_doc(doc_for(DOC_APP_DEFAULTS, v)),
            );
        }
    }

    // SEC-040: AlgorithmBlacklist explicitly disables default blacklist
    {
        let security_policy_path = config.base_dir.join("security-policy.xml");
        if security_policy_path.exists() {
            if let Ok(content) = std::fs::read_to_string(&security_policy_path) {
                // Check for exclude="#default" or equivalent patterns that disable the default blacklist
                if content.contains("exclude=\"#default\"")
                    || content.contains("excludeDefaults=\"true\"")
                {
                    results.push(
                        CheckResult::fail(
                            "SEC-040",
                            CAT,
                            Severity::Warning,
                            "security-policy.xml explicitly disables default algorithm blacklist",
                            Some("Do not exclude default algorithm blacklists unless you have specific requirements"),
                        )
                        .with_doc(doc_for(DOC_APP_DEFAULTS, v)),
                    );
                } else {
                    results.push(CheckResult::pass(
                        "SEC-040",
                        CAT,
                        Severity::Warning,
                        "security-policy.xml does not disable default algorithm blacklist",
                    ));
                }
            }
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
                    .with_doc(doc_for(DOC_SESSIONS, v)),
                );
                has_http = true;
            }
        }
        if !has_http && !sc.notify_endpoints.is_empty() {
            results.push(CheckResult::pass(
                "SEC-041",
                CAT,
                Severity::Warning,
                "All Notify endpoints use HTTPS",
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
                    .with_doc(doc_for(DOC_SESSIONS, v)),
                );
            } else {
                results.push(CheckResult::pass(
                    "SEC-042",
                    CAT,
                    Severity::Warning,
                    "handlerURL does not use plaintext HTTP",
                ));
            }
        }
    }

    // SEC-043: Signing and encryption CredentialResolvers use the same key file
    {
        let signing_keys: Vec<&str> = sc
            .credential_resolvers
            .iter()
            .filter(|cr| {
                cr.use_attr
                    .as_deref()
                    .is_some_and(|u| u.contains("signing"))
            })
            .filter_map(|cr| cr.key.as_deref())
            .collect();
        let encryption_keys: Vec<&str> = sc
            .credential_resolvers
            .iter()
            .filter(|cr| {
                cr.use_attr
                    .as_deref()
                    .is_some_and(|u| u.contains("encryption"))
            })
            .filter_map(|cr| cr.key.as_deref())
            .collect();
        let mut shared = false;
        for sk in &signing_keys {
            if encryption_keys.contains(sk) {
                results.push(
                    CheckResult::fail(
                        "SEC-043",
                        CAT,
                        Severity::Warning,
                        &format!(
                            "Signing and encryption CredentialResolvers share the same key file: {}",
                            sk
                        ),
                        Some("Use separate key files for signing and encryption for better key management"),
                    )
                    .with_doc(doc_for(DOC_CREDENTIAL_RESOLVER, v)),
                );
                shared = true;
            }
        }
        if !shared && !signing_keys.is_empty() && !encryption_keys.is_empty() {
            results.push(CheckResult::pass(
                "SEC-043",
                CAT,
                Severity::Warning,
                "Signing and encryption use different key files",
            ));
        }
    }

    // SEC-044: TCPListener binds to non-localhost address
    if let Some(ref addr) = sc.tcp_listener_address {
        let lower = addr.to_lowercase();
        if lower == "127.0.0.1" || lower == "::1" || lower == "localhost" {
            results.push(CheckResult::pass(
                "SEC-044",
                CAT,
                Severity::Warning,
                &format!("TCPListener binds to localhost: {}", addr),
            ));
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
                .with_doc(doc_for(DOC_SESSIONS, v)),
            );
        }
    }

    // SEC-045: redirectLimit not explicitly set on Sessions
    if let Some(ref sessions) = sc.sessions {
        if sessions.redirect_limit.is_some() {
            results.push(CheckResult::pass(
                "SEC-045",
                CAT,
                Severity::Info,
                "redirectLimit is explicitly set on Sessions",
            ));
        } else {
            results.push(
                CheckResult::fail(
                    "SEC-045",
                    CAT,
                    Severity::Info,
                    "redirectLimit not explicitly set on Sessions (defaults vary by SP version)",
                    Some("Set redirectLimit on <Sessions> to explicitly control redirect behavior"),
                )
                .with_doc(doc_for(DOC_SESSIONS, v)),
            );
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

    // SEC-048: No SecurityPolicyProvider configured
    if sc.security_policy_provider_path.is_some() {
        results.push(CheckResult::pass(
            "SEC-048",
            CAT,
            Severity::Warning,
            "SecurityPolicyProvider is configured",
        ));
    } else {
        results.push(
            CheckResult::fail(
                "SEC-048",
                CAT,
                Severity::Warning,
                "No SecurityPolicyProvider configured",
                Some("Add a <SecurityPolicyProvider> element to define security policies"),
            )
            .with_doc(doc_for(DOC_APP_DEFAULTS, v)),
        );
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
                    .with_doc(doc_for(DOC_APP_DEFAULTS, v)),
                );
            } else {
                results.push(CheckResult::pass(
                    "SEC-049",
                    CAT,
                    Severity::Info,
                    &format!("homeURL is set: {}", home_url),
                ));
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

    // SEC-051: Chaining CredentialResolver has zero children
    for cr in &sc.credential_resolvers {
        if cr.resolver_type == "Chaining" && cr.children_count == 0 {
            results.push(
                CheckResult::fail(
                    "SEC-051",
                    CAT,
                    Severity::Error,
                    "Chaining CredentialResolver has zero children",
                    Some("Add child CredentialResolver elements or remove the empty Chaining resolver"),
                )
                .with_doc(doc_for(DOC_CREDENTIAL_RESOLVER, v)),
            );
        } else if cr.resolver_type == "Chaining" {
            results.push(CheckResult::pass(
                "SEC-051",
                CAT,
                Severity::Error,
                &format!(
                    "Chaining CredentialResolver has {} children",
                    cr.children_count
                ),
            ));
        }
    }

    // SEC-052: signingAlg uses SHA-1 (rsa-sha1)
    if let Some(ref app) = sc.application_defaults {
        if let Some(ref alg) = app.signing_alg {
            let lower = alg.to_lowercase();
            if lower.contains("sha1") || lower.contains("sha-1") {
                results.push(
                    CheckResult::fail(
                        "SEC-052",
                        CAT,
                        Severity::Warning,
                        &format!("signingAlg uses SHA-1: {}", alg),
                        Some(
                            "Use a stronger algorithm like rsa-sha256 or ecdsa-sha256 for signing",
                        ),
                    )
                    .with_doc(doc_for(DOC_SIGNING_ENCRYPTION, v)),
                );
            } else {
                results.push(CheckResult::pass(
                    "SEC-052",
                    CAT,
                    Severity::Warning,
                    &format!("signingAlg does not use SHA-1: {}", alg),
                ));
            }
        }
    }

    // SEC-053: digestAlg uses SHA-1
    if let Some(ref app) = sc.application_defaults {
        if let Some(ref alg) = app.digest_alg {
            let lower = alg.to_lowercase();
            if lower.contains("sha1") || lower.contains("sha-1") {
                results.push(
                    CheckResult::fail(
                        "SEC-053",
                        CAT,
                        Severity::Warning,
                        &format!("digestAlg uses SHA-1: {}", alg),
                        Some("Use a stronger digest algorithm like sha256 or sha384"),
                    )
                    .with_doc(doc_for(DOC_SIGNING_ENCRYPTION, v)),
                );
            } else {
                results.push(CheckResult::pass(
                    "SEC-053",
                    CAT,
                    Severity::Warning,
                    &format!("digestAlg does not use SHA-1: {}", alg),
                ));
            }
        }
    }

    // SEC-054: SignatureMetadataFilter has verifyName="false"
    for mp in &sc.metadata_providers {
        for filter in &mp.filters {
            if filter.filter_type == "Signature" {
                if filter.verify_name.as_deref() == Some("false") {
                    results.push(
                        CheckResult::fail(
                            "SEC-054",
                            CAT,
                            Severity::Warning,
                            "SignatureMetadataFilter has verifyName=\"false\" (signature name verification disabled)",
                            Some("Remove verifyName=\"false\" or set to \"true\" to verify the signer's name matches"),
                        )
                        .with_doc(doc_for(DOC_SIGNATURE_FILTER, v)),
                    );
                } else {
                    results.push(CheckResult::pass(
                        "SEC-054",
                        CAT,
                        Severity::Warning,
                        "SignatureMetadataFilter verifyName is not disabled",
                    ));
                }
            }
        }
    }

    // SEC-055: MetadataProvider ignoreTransport="true" without Signature filter
    for mp in &sc.metadata_providers {
        if mp.ignore_transport.as_deref() == Some("true") {
            let has_sig_filter = mp.filters.iter().any(|f| f.filter_type == "Signature");
            if !has_sig_filter {
                results.push(
                    CheckResult::fail(
                        "SEC-055",
                        CAT,
                        Severity::Warning,
                        &format!(
                            "MetadataProvider type='{}' has ignoreTransport=\"true\" without a Signature filter",
                            mp.provider_type
                        ),
                        Some("Add a SignatureMetadataFilter or remove ignoreTransport=\"true\" to validate transport security"),
                    )
                    .with_doc(doc_for(DOC_METADATA_PROVIDER, v)),
                );
            } else {
                results.push(CheckResult::pass(
                    "SEC-055",
                    CAT,
                    Severity::Warning,
                    &format!(
                        "MetadataProvider type='{}' has ignoreTransport=\"true\" with compensating Signature filter",
                        mp.provider_type
                    ),
                ));
            }
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
                )
                .with_doc(doc_for(DOC_APP_DEFAULTS, v)),
            );
        } else if app.require_transport_auth.is_some() {
            results.push(CheckResult::pass(
                "SEC-056",
                CAT,
                Severity::Warning,
                "requireTransportAuth is not disabled",
            ));
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
                )
                .with_doc(doc_for(DOC_APP_DEFAULTS, v)),
            );
        } else if app.require_confidentiality.is_some() {
            results.push(CheckResult::pass(
                "SEC-057",
                CAT,
                Severity::Warning,
                "requireConfidentiality is not disabled",
            ));
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
                    )
                    .with_doc(doc_for(DOC_SESSIONS, v)),
                );
            } else {
                results.push(CheckResult::pass(
                    "SEC-058",
                    CAT,
                    Severity::Warning,
                    "exportACL is restricted to localhost",
                ));
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
                results.push(CheckResult::pass(
                    "SEC-059",
                    CAT,
                    Severity::Info,
                    &format!(
                        "exportLocation is set ({}) with localhost-only exportACL",
                        loc
                    ),
                ));
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
                    )
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
                .with_doc(doc_for(DOC_SESSIONS, v)),
            );
        } else {
            results.push(CheckResult::pass(
                "SEC-060",
                CAT,
                Severity::Warning,
                &format!(
                    "LogoutInitiator signing is set: {}",
                    li.signing.as_deref().unwrap_or("?")
                ),
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
                    )
                    .with_doc(doc_for(DOC_SESSIONS, v)),
                );
            } else if limit.contains("allow") {
                results.push(CheckResult::pass(
                    "SEC-061",
                    CAT,
                    Severity::Warning,
                    "redirectLimit allow-list has redirectAllow configured",
                ));
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

    // SEC-016: Private key file not world-readable (Unix only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for cr in &sc.credential_resolvers {
            if let Some(ref key_path) = cr.key {
                let full_path = config.base_dir.join(key_path);
                if full_path.exists() {
                    if let Ok(metadata) = std::fs::metadata(&full_path) {
                        let mode = metadata.permissions().mode();
                        if mode & 0o077 == 0 {
                            results.push(CheckResult::pass(
                                "SEC-016",
                                CAT,
                                Severity::Warning,
                                &format!(
                                    "Key file {} is not world/group-readable (mode {:04o})",
                                    key_path,
                                    mode & 0o7777
                                ),
                            ));
                        } else {
                            results.push(CheckResult::fail(
                                "SEC-016", CAT, Severity::Warning,
                                &format!("Key file {} is accessible by group/others (mode {:04o})", key_path, mode & 0o7777),
                                Some("Set file permissions to 0600 or 0400 to restrict access to the owner only"),
                            ).with_doc(doc_for(DOC_CREDENTIAL_RESOLVER, v)));
                        }
                    }
                }
            }
        }
    }

    results
}
