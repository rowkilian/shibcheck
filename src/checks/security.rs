use chrono::Utc;

use crate::config::DiscoveredConfig;
use crate::parsers::certificate;
use crate::result::{CheckCategory, CheckResult, Severity};

const CAT: CheckCategory = CheckCategory::Security;

// Shibboleth SP3 documentation URLs
const DOC_SESSIONS: &str = "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334342/Sessions";
const DOC_CREDENTIAL_RESOLVER: &str = "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334414/CredentialResolver";
const DOC_SIGNING_ENCRYPTION: &str = "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334379/SigningEncryption";
const DOC_SIGNATURE_FILTER: &str = "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2063696211/SignatureMetadataFilter";
const DOC_VALID_UNTIL_FILTER: &str = "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2063696214/RequireValidUntilMetadataFilter";
const DOC_METADATA_PROVIDER: &str = "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2060616124/MetadataProvider";
const DOC_STATUS_HANDLER: &str = "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334870/Status+Handler";

pub fn run(config: &DiscoveredConfig) -> Vec<CheckResult> {
    let mut results = Vec::new();

    let sc = match config.shibboleth_config.as_ref() {
        Some(sc) => sc,
        None => return results,
    };

    // SEC-001: handlerSSL=true
    if let Some(ref sessions) = sc.sessions {
        match sessions.handler_ssl.as_deref() {
            Some("true") => {
                results.push(CheckResult::pass("SEC-001", CAT, Severity::Warning, "handlerSSL is set to true"));
            }
            Some("false") => {
                results.push(CheckResult::fail(
                    "SEC-001", CAT, Severity::Warning,
                    "handlerSSL is set to false",
                    Some("Set handlerSSL=\"true\" on <Sessions> to require HTTPS for handler endpoints"),
                ).with_doc(DOC_SESSIONS));
            }
            _ => {
                results.push(CheckResult::fail(
                    "SEC-001", CAT, Severity::Warning,
                    "handlerSSL is not explicitly set",
                    Some("Set handlerSSL=\"true\" on <Sessions> to require HTTPS for handler endpoints"),
                ).with_doc(DOC_SESSIONS));
            }
        }
    }

    // SEC-002: cookieProps includes "secure"
    if let Some(ref sessions) = sc.sessions {
        if let Some(ref cookie_props) = sessions.cookie_props {
            let lower = cookie_props.to_lowercase();
            if lower.contains("secure") || lower == "https" {
                results.push(CheckResult::pass("SEC-002", CAT, Severity::Warning, "cookieProps includes secure flag"));
            } else {
                results.push(CheckResult::fail(
                    "SEC-002", CAT, Severity::Warning,
                    "cookieProps does not include 'secure'",
                    Some("Add 'secure' to cookieProps or set cookieProps=\"https\""),
                ).with_doc(DOC_SESSIONS));
            }
        } else {
            results.push(CheckResult::fail(
                "SEC-002", CAT, Severity::Warning,
                "cookieProps not set on Sessions",
                Some("Set cookieProps=\"https\" on <Sessions> for secure cookies"),
            ).with_doc(DOC_SESSIONS));
        }
    }

    // SEC-003: cookieProps includes "httpOnly"
    if let Some(ref sessions) = sc.sessions {
        if let Some(ref cookie_props) = sessions.cookie_props {
            let lower = cookie_props.to_lowercase();
            // "https" shorthand implies httpOnly in Shibboleth
            if lower.contains("httponly") || lower == "https" {
                results.push(CheckResult::pass("SEC-003", CAT, Severity::Warning, "cookieProps includes httpOnly flag"));
            } else {
                results.push(CheckResult::fail(
                    "SEC-003", CAT, Severity::Warning,
                    "cookieProps does not include 'httpOnly'",
                    Some("Add 'httpOnly' to cookieProps or set cookieProps=\"https\""),
                ).with_doc(DOC_SESSIONS));
            }
        } else {
            results.push(CheckResult::fail(
                "SEC-003", CAT, Severity::Warning,
                "cookieProps not set on Sessions",
                Some("Set cookieProps=\"https\" on <Sessions> for httpOnly cookies"),
            ).with_doc(DOC_SESSIONS));
        }
    }

    // SEC-004: Signing credentials configured
    let has_signing = sc.credential_resolvers.iter().any(|cr| {
        cr.use_attr.as_deref().map_or(true, |u| u.contains("signing"))
    });
    if has_signing && !sc.credential_resolvers.is_empty() {
        results.push(CheckResult::pass("SEC-004", CAT, Severity::Warning, "Signing credentials configured"));
    } else {
        results.push(CheckResult::fail(
            "SEC-004", CAT, Severity::Warning,
            "No signing credentials configured",
            Some("Add a <CredentialResolver> with use=\"signing\" for SAML signing"),
        ).with_doc(DOC_CREDENTIAL_RESOLVER));
    }

    // SEC-005: Encryption credentials configured
    let has_encryption = sc.credential_resolvers.iter().any(|cr| {
        cr.use_attr.as_deref().map_or(true, |u| u.contains("encryption"))
    });
    if has_encryption && !sc.credential_resolvers.is_empty() {
        results.push(CheckResult::pass("SEC-005", CAT, Severity::Warning, "Encryption credentials configured"));
    } else {
        results.push(CheckResult::fail(
            "SEC-005", CAT, Severity::Warning,
            "No encryption credentials configured",
            Some("Add a <CredentialResolver> with use=\"encryption\" for SAML encryption"),
        ).with_doc(DOC_CREDENTIAL_RESOLVER));
    }

    // SEC-006: signing attribute on ApplicationDefaults
    if let Some(ref app) = sc.application_defaults {
        if let Some(ref signing) = app.signing {
            if signing == "true" || signing == "front" || signing == "back" {
                results.push(CheckResult::pass("SEC-006", CAT, Severity::Info, "signing attribute set on ApplicationDefaults"));
            } else {
                results.push(CheckResult::fail(
                    "SEC-006", CAT, Severity::Info,
                    &format!("signing attribute is '{}' (consider 'true' or 'front')", signing),
                    Some("Set signing=\"true\" or signing=\"front\" on <ApplicationDefaults>"),
                ).with_doc(DOC_SIGNING_ENCRYPTION));
            }
        } else {
            results.push(CheckResult::fail(
                "SEC-006", CAT, Severity::Info,
                "signing attribute not set on ApplicationDefaults",
                Some("Set signing=\"true\" on <ApplicationDefaults> to sign SAML messages"),
            ).with_doc(DOC_SIGNING_ENCRYPTION));
        }
    }

    // SEC-007: encryption attribute on ApplicationDefaults
    if let Some(ref app) = sc.application_defaults {
        if let Some(ref encryption) = app.encryption {
            if encryption == "true" || encryption == "front" || encryption == "back" {
                results.push(CheckResult::pass("SEC-007", CAT, Severity::Info, "encryption attribute set on ApplicationDefaults"));
            } else {
                results.push(CheckResult::fail(
                    "SEC-007", CAT, Severity::Info,
                    &format!("encryption attribute is '{}' (consider 'true')", encryption),
                    Some("Set encryption=\"true\" on <ApplicationDefaults>"),
                ).with_doc(DOC_SIGNING_ENCRYPTION));
            }
        } else {
            results.push(CheckResult::fail(
                "SEC-007", CAT, Severity::Info,
                "encryption attribute not set on ApplicationDefaults",
                Some("Set encryption=\"true\" on <ApplicationDefaults> to request encrypted assertions"),
            ).with_doc(DOC_SIGNING_ENCRYPTION));
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
                        results.push(CheckResult::fail(
                            "SEC-008", CAT, Severity::Error,
                            &format!("Certificate {} has expired ({})", cert_path, cert_info.not_after.format("%Y-%m-%d")),
                            Some("Replace the expired certificate with a new one"),
                        ).with_doc(DOC_CREDENTIAL_RESOLVER));
                    } else {
                        results.push(CheckResult::pass(
                            "SEC-008", CAT, Severity::Error,
                            &format!("Certificate {} is not expired", cert_path),
                        ));
                    }

                    // SEC-009: Certificate expiring within 30 days
                    let days_until_expiry = (cert_info.not_after - now).num_days();
                    if days_until_expiry >= 0 && days_until_expiry <= 30 {
                        results.push(CheckResult::fail(
                            "SEC-009", CAT, Severity::Warning,
                            &format!("Certificate {} expires in {} days ({})", cert_path, days_until_expiry, cert_info.not_after.format("%Y-%m-%d")),
                            Some("Plan certificate renewal before expiry"),
                        ).with_doc(DOC_CREDENTIAL_RESOLVER));
                    } else if days_until_expiry > 30 {
                        results.push(CheckResult::pass(
                            "SEC-009", CAT, Severity::Warning,
                            &format!("Certificate {} expires in {} days", cert_path, days_until_expiry),
                        ));
                    }

                    // SEC-010: Certificate not-yet-valid
                    if cert_info.not_before > now {
                        results.push(CheckResult::fail(
                            "SEC-010", CAT, Severity::Error,
                            &format!("Certificate {} is not yet valid (valid from {})", cert_path, cert_info.not_before.format("%Y-%m-%d")),
                            Some("Check the certificate's notBefore date"),
                        ).with_doc(DOC_CREDENTIAL_RESOLVER));
                    } else {
                        results.push(CheckResult::pass(
                            "SEC-010", CAT, Severity::Error,
                            &format!("Certificate {} validity period has started", cert_path),
                        ));
                    }

                    // SEC-013: Key size >= 2048 bits
                    if cert_info.key_size_bits > 0 {
                        if cert_info.key_size_bits >= 2048 {
                            results.push(CheckResult::pass(
                                "SEC-013", CAT, Severity::Warning,
                                &format!("Certificate {} key size is {} bits", cert_path, cert_info.key_size_bits),
                            ));
                        } else {
                            results.push(CheckResult::fail(
                                "SEC-013", CAT, Severity::Warning,
                                &format!("Certificate {} key size is {} bits (< 2048)", cert_path, cert_info.key_size_bits),
                                Some("Use a certificate with at least 2048-bit key size"),
                            ).with_doc(DOC_CREDENTIAL_RESOLVER));
                        }
                    }
                }
                Err(_) => {
                    // Certificate couldn't be parsed - skip cert checks for this file
                }
            }
        }
    }

    // SEC-011: MetadataFilter with signature validation
    let has_sig_filter = sc.metadata_providers.iter().any(|mp| {
        mp.filters.iter().any(|f| {
            f.filter_type.contains("Signature") || f.filter_type.contains("signature")
        })
    });
    if has_sig_filter {
        results.push(CheckResult::pass("SEC-011", CAT, Severity::Warning, "Metadata signature validation configured"));
    } else if !sc.metadata_providers.is_empty() {
        results.push(CheckResult::fail(
            "SEC-011", CAT, Severity::Warning,
            "No MetadataFilter with signature validation found",
            Some("Add a <MetadataFilter type=\"Signature\" ...> to validate metadata signatures"),
        ).with_doc(DOC_SIGNATURE_FILTER));
    }

    // SEC-012: MetadataFilter with RequireValidUntil
    let has_valid_until = sc.metadata_providers.iter().any(|mp| {
        mp.filters.iter().any(|f| {
            f.filter_type.contains("RequireValidUntil")
        })
    });
    if has_valid_until {
        results.push(CheckResult::pass("SEC-012", CAT, Severity::Info, "RequireValidUntil metadata filter configured"));
    } else if !sc.metadata_providers.is_empty() {
        results.push(CheckResult::fail(
            "SEC-012", CAT, Severity::Info,
            "No MetadataFilter with RequireValidUntil found",
            Some("Add a <MetadataFilter type=\"RequireValidUntil\"> to reject stale metadata"),
        ).with_doc(DOC_VALID_UNTIL_FILTER));
    }

    // SEC-014: No plaintext HTTP metadata URLs
    let mut has_http_url = false;
    for mp in &sc.metadata_providers {
        for url in [&mp.uri, &mp.url].into_iter().flatten() {
            if url.starts_with("http://") {
                results.push(CheckResult::fail(
                    "SEC-014", CAT, Severity::Warning,
                    &format!("MetadataProvider uses plaintext HTTP URL: {}", url),
                    Some("Use HTTPS for metadata URLs to prevent tampering"),
                ).with_doc(DOC_METADATA_PROVIDER));
                has_http_url = true;
            }
        }
    }
    if !has_http_url && !sc.metadata_providers.is_empty() {
        results.push(CheckResult::pass("SEC-014", CAT, Severity::Warning, "No plaintext HTTP metadata URLs found"));
    }

    // SEC-015: Status handler ACL configured
    if let Some(ref handler) = sc.status_handler {
        if handler.acl.as_ref().map_or(false, |acl| !acl.is_empty()) {
            results.push(CheckResult::pass("SEC-015", CAT, Severity::Info, "Status handler ACL is configured"));
        } else {
            results.push(CheckResult::fail(
                "SEC-015", CAT, Severity::Info,
                "Status handler has no ACL configured",
                Some("Set acl attribute on the Status handler to restrict access"),
            ).with_doc(DOC_STATUS_HANDLER));
        }
    } else {
        results.push(CheckResult::pass("SEC-015", CAT, Severity::Info, "No Status handler found (not exposed)"));
    }

    results
}
