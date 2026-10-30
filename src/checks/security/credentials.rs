use super::*;

pub(super) fn run(
    config: &DiscoveredConfig,
    sc: &ShibbolethConfig,
    v: SpVersion,
    results: &mut Vec<CheckResult>,
) {
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
                results.push(
                    CheckResult::pass(
                        "SEC-006",
                        CAT,
                        Severity::Info,
                        "signing attribute set on ApplicationDefaults",
                    )
                    .at_element("ApplicationDefaults"),
                );
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
                    .at_element("ApplicationDefaults")
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
                .at_element("ApplicationDefaults")
                .with_doc(doc_for(DOC_SIGNING_ENCRYPTION, v)),
            );
        }
    }

    // SEC-007: encryption attribute on ApplicationDefaults
    if let Some(ref app) = sc.application_defaults {
        if let Some(ref encryption) = app.encryption {
            if encryption == "true" || encryption == "front" || encryption == "back" {
                results.push(
                    CheckResult::pass(
                        "SEC-007",
                        CAT,
                        Severity::Info,
                        "encryption attribute set on ApplicationDefaults",
                    )
                    .at_element("ApplicationDefaults"),
                );
            } else {
                results.push(
                    CheckResult::fail(
                        "SEC-007",
                        CAT,
                        Severity::Info,
                        &format!("encryption attribute is '{}' (consider 'true')", encryption),
                        Some("Set encryption=\"true\" on <ApplicationDefaults>"),
                    )
                    .at_element("ApplicationDefaults")
                    .with_doc(doc_for(DOC_SIGNING_ENCRYPTION, v)),
                );
            }
        } else {
            results.push(CheckResult::fail(
                "SEC-007", CAT, Severity::Info,
                "encryption attribute not set on ApplicationDefaults",
                Some("Set encryption=\"true\" on <ApplicationDefaults> to request encrypted assertions"),
            ).at_element("ApplicationDefaults").with_doc(doc_for(DOC_SIGNING_ENCRYPTION, v)));
        }
    }

    // SEC-008 through SEC-010 and SEC-013: Certificate checks
    let now = Utc::now();
    for cr in &sc.credential_resolvers {
        if let Some(ref cert_path) = cr.certificate {
            let full_path = config.resolve_path(cert_path);
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
                Err(e) => {
                    results.push(
                        CheckResult::fail(
                            CODE_CERT_PARSE_ERROR,
                            CAT,
                            Severity::Warning,
                            &format!(
                                "Certificate {} could not be parsed: {} (expiry and key-size checks skipped)",
                                cert_path, e
                            ),
                            Some("Ensure the file is a valid PEM-encoded X.509 certificate"),
                        )
                        .with_doc(doc_for(DOC_CREDENTIAL_RESOLVER, v)),
                    );
                }
            }
        }
    }

    // SEC-021: Certificate and key file match
    for cr in &sc.credential_resolvers {
        if let (Some(ref cert_path), Some(ref key_path)) = (&cr.certificate, &cr.key) {
            let full_cert = config.resolve_path(cert_path);
            let full_key = config.resolve_path(key_path);
            if full_cert.exists() && full_key.exists() {
                match certificate::check_cert_key_match(&full_cert, &full_key) {
                    Ok(certificate::CertKeyMatch::Match) => {
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
                    Ok(certificate::CertKeyMatch::Mismatch) => {
                        results.push(CheckResult::fail(
                            "SEC-021", CAT, Severity::Error,
                            &format!("Certificate {} and key {} do not match (different RSA modulus)", cert_path, key_path),
                            Some("Ensure the private key corresponds to the certificate's public key"),
                        ).with_doc(doc_for(DOC_CREDENTIAL_RESOLVER, v)));
                    }
                    Ok(certificate::CertKeyMatch::SkippedNonRsa) => {
                        // Non-RSA pair — SEC-021 only validates RSA modulus matching.
                    }
                    Err(e) => {
                        results.push(
                            CheckResult::fail(
                                CODE_CERT_PARSE_ERROR,
                                CAT,
                                Severity::Warning,
                                &format!(
                                    "Certificate/key pair {} + {} could not be parsed: {} (match check skipped)",
                                    cert_path, key_path, e
                                ),
                                Some("Ensure both files are valid PEM-encoded; for RSA, check they are not corrupted"),
                            )
                            .with_doc(doc_for(DOC_CREDENTIAL_RESOLVER, v)),
                        );
                    }
                }
            }
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
                results.push(
                    CheckResult::pass(
                        "SEC-035",
                        CAT,
                        Severity::Warning,
                        "cipherSuites does not contain known weak ciphers",
                    )
                    .at_element("ApplicationDefaults"),
                );
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
                    .at_element("ApplicationDefaults")
                    .with_doc(doc_for(DOC_APP_DEFAULTS, v)),
                );
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
                    .at_element("ApplicationDefaults")
                    .with_doc(doc_for(DOC_SIGNING_ENCRYPTION, v)),
                );
            } else {
                results.push(
                    CheckResult::pass(
                        "SEC-052",
                        CAT,
                        Severity::Warning,
                        &format!("signingAlg does not use SHA-1: {}", alg),
                    )
                    .at_element("ApplicationDefaults"),
                );
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
                    .at_element("ApplicationDefaults")
                    .with_doc(doc_for(DOC_SIGNING_ENCRYPTION, v)),
                );
            } else {
                results.push(
                    CheckResult::pass(
                        "SEC-053",
                        CAT,
                        Severity::Warning,
                        &format!("digestAlg does not use SHA-1: {}", alg),
                    )
                    .at_element("ApplicationDefaults"),
                );
            }
        }
    }

    // SEC-072: Inline private key material detected in configuration XML
    if let Some(ref content) = config.shibboleth_xml_content {
        if content.contains("-----BEGIN RSA PRIVATE KEY-----")
            || content.contains("-----BEGIN PRIVATE KEY-----")
            || content.contains("-----BEGIN EC PRIVATE KEY-----")
        {
            results.push(
                CheckResult::fail(
                    "SEC-072",
                    CAT,
                    Severity::Error,
                    "Inline private key material detected in shibboleth2.xml",
                    Some("Move private keys to separate files with restricted permissions instead of embedding in XML"),
                )
                .with_doc(doc_for(DOC_CREDENTIAL_RESOLVER, v)),
            );
        } else {
            results.push(CheckResult::pass(
                "SEC-072",
                CAT,
                Severity::Error,
                "No inline private key material in shibboleth2.xml",
            ));
        }
    }

    // SEC-074: No encryption CredentialResolver configured (cannot decrypt assertions)
    {
        let has_encryption_cr = sc.credential_resolvers.iter().any(|cr| {
            cr.use_attr
                .as_deref()
                .is_some_and(|u| u.contains("encryption"))
        });
        let has_unspecified_cr = sc
            .credential_resolvers
            .iter()
            .any(|cr| cr.use_attr.is_none());
        if has_encryption_cr || has_unspecified_cr {
            results.push(CheckResult::pass(
                "SEC-074",
                CAT,
                Severity::Info,
                "Encryption credential is available (explicit or unspecified use)",
            ));
        } else if !sc.credential_resolvers.is_empty() {
            results.push(
                CheckResult::fail(
                    "SEC-074",
                    CAT,
                    Severity::Info,
                    "No encryption CredentialResolver configured (cannot decrypt encrypted assertions)",
                    Some("Add a CredentialResolver with use=\"encryption\" or omit the use attribute to enable decryption"),
                )
                .with_doc(doc_for(DOC_CREDENTIAL_RESOLVER, v)),
            );
        }
    }

    // SEC-077: Signing and encryption use the same certificate
    {
        let signing_certs: Vec<&str> = sc
            .credential_resolvers
            .iter()
            .filter(|cr| {
                cr.use_attr
                    .as_deref()
                    .is_some_and(|u| u.contains("signing"))
            })
            .filter_map(|cr| cr.certificate.as_deref())
            .collect();
        let encryption_certs: Vec<&str> = sc
            .credential_resolvers
            .iter()
            .filter(|cr| {
                cr.use_attr
                    .as_deref()
                    .is_some_and(|u| u.contains("encryption"))
            })
            .filter_map(|cr| cr.certificate.as_deref())
            .collect();
        let mut shared = false;
        for sc_cert in &signing_certs {
            if encryption_certs.contains(sc_cert) {
                results.push(
                    CheckResult::fail(
                        "SEC-077",
                        CAT,
                        Severity::Info,
                        &format!(
                            "Signing and encryption CredentialResolvers share the same certificate: {}",
                            sc_cert
                        ),
                        Some("Use separate certificates for signing and encryption for better key management"),
                    )
                    .with_doc(doc_for(DOC_CREDENTIAL_RESOLVER, v)),
                );
                shared = true;
            }
        }
        if !shared && !signing_certs.is_empty() && !encryption_certs.is_empty() {
            results.push(CheckResult::pass(
                "SEC-077",
                CAT,
                Severity::Info,
                "Signing and encryption use different certificates",
            ));
        }
    }

    // SEC-087: Certificate file has overly permissive permissions (world-writable)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for cr in &sc.credential_resolvers {
            if let Some(ref cert_path) = cr.certificate {
                let full_path = config.resolve_path(cert_path);
                if full_path.exists() {
                    if let Ok(metadata) = std::fs::metadata(&full_path) {
                        let mode = metadata.permissions().mode();
                        if mode & 0o002 != 0 {
                            results.push(
                                CheckResult::fail(
                                    "SEC-087",
                                    CAT,
                                    Severity::Warning,
                                    &format!(
                                        "Certificate file {} is world-writable (mode {:04o}) — could be tampered with",
                                        cert_path,
                                        mode & 0o7777
                                    ),
                                    Some("Set certificate file permissions to 0644 or more restrictive"),
                                )
                                .with_doc(doc_for(DOC_CREDENTIAL_RESOLVER, v)),
                            );
                        } else {
                            results.push(CheckResult::pass(
                                "SEC-087",
                                CAT,
                                Severity::Warning,
                                &format!(
                                    "Certificate file {} is not world-writable (mode {:04o})",
                                    cert_path,
                                    mode & 0o7777
                                ),
                            ));
                        }
                    }
                }
            }
        }
    }

    // SEC-088: signing="false" explicitly disables signing on ApplicationDefaults
    if let Some(ref app) = sc.application_defaults {
        if app.signing.as_deref() == Some("false") {
            results.push(
                CheckResult::fail(
                    "SEC-088",
                    CAT,
                    Severity::Warning,
                    "signing is explicitly set to \"false\" on ApplicationDefaults (SAML messages will not be signed)",
                    Some("Set signing=\"true\" to sign SAML requests for integrity and authenticity"),
                ).at_element("ApplicationDefaults")
                .with_doc(doc_for(DOC_SIGNING_ENCRYPTION, v)),
            );
        } else if app.signing.is_some() {
            results.push(
                CheckResult::pass(
                    "SEC-088",
                    CAT,
                    Severity::Warning,
                    "signing is not explicitly disabled on ApplicationDefaults",
                )
                .at_element("ApplicationDefaults"),
            );
        }
    }

    // SEC-089: encryption="false" explicitly disables encryption on ApplicationDefaults
    if let Some(ref app) = sc.application_defaults {
        if app.encryption.as_deref() == Some("false") {
            results.push(
                CheckResult::fail(
                    "SEC-089",
                    CAT,
                    Severity::Warning,
                    "encryption is explicitly set to \"false\" on ApplicationDefaults (assertions will not be encrypted)",
                    Some("Set encryption=\"true\" to request encrypted assertions from IdPs"),
                ).at_element("ApplicationDefaults")
                .with_doc(doc_for(DOC_SIGNING_ENCRYPTION, v)),
            );
        } else if app.encryption.is_some() {
            results.push(
                CheckResult::pass(
                    "SEC-089",
                    CAT,
                    Severity::Warning,
                    "encryption is not explicitly disabled on ApplicationDefaults",
                )
                .at_element("ApplicationDefaults"),
            );
        }
    }

    // SEC-091: CredentialResolver has key but no certificate (incomplete credential)
    for cr in &sc.credential_resolvers {
        if cr.resolver_type == "File" && cr.key.is_some() && cr.certificate.is_none() {
            results.push(
                CheckResult::fail(
                    "SEC-091",
                    CAT,
                    Severity::Warning,
                    &format!(
                        "CredentialResolver (use={}) has key but no certificate",
                        cr.use_attr.as_deref().unwrap_or("unspecified")
                    ),
                    Some("Add a certificate attribute to the CredentialResolver for a complete credential pair"),
                )
                .with_doc(doc_for(DOC_CREDENTIAL_RESOLVER, v)),
            );
        }
    }

    // SEC-095: No signing CredentialResolver configured (cannot sign requests)
    {
        let has_signing_cr = sc.credential_resolvers.iter().any(|cr| {
            cr.use_attr
                .as_deref()
                .is_some_and(|u| u.contains("signing"))
        });
        let has_unspecified_cr = sc
            .credential_resolvers
            .iter()
            .any(|cr| cr.use_attr.is_none());
        if has_signing_cr || has_unspecified_cr {
            results.push(CheckResult::pass(
                "SEC-095",
                CAT,
                Severity::Info,
                "Signing credential is available (explicit or unspecified use)",
            ));
        } else if !sc.credential_resolvers.is_empty() {
            results.push(
                CheckResult::fail(
                    "SEC-095",
                    CAT,
                    Severity::Info,
                    "No signing CredentialResolver configured (cannot sign SAML requests)",
                    Some("Add a CredentialResolver with use=\"signing\" or omit the use attribute"),
                )
                .with_doc(doc_for(DOC_CREDENTIAL_RESOLVER, v)),
            );
        }
    }

    // SEC-097: cipher_suites contains known weak algorithms
    if let Some(ref app) = sc.application_defaults {
        if let Some(ref suites) = app.cipher_suites {
            let lower = suites.to_lowercase();
            let weak_patterns = ["rc4", "des", "md5", "null", "export", "anon", "3des"];
            let mut found_weak: Vec<&str> = Vec::new();
            for pattern in &weak_patterns {
                if lower.contains(pattern) {
                    found_weak.push(pattern);
                }
            }
            if !found_weak.is_empty() {
                results.push(
                    CheckResult::fail(
                        "SEC-097",
                        CAT,
                        Severity::Warning,
                        &format!(
                            "cipherSuites contains weak algorithms: {}",
                            found_weak.join(", ")
                        ),
                        Some("Remove weak cipher suites (RC4, DES, 3DES, MD5, NULL, EXPORT, ANON) from cipherSuites"),
                    ).at_element("ApplicationDefaults")
                    .with_doc(doc_for(DOC_APP_DEFAULTS, v)),
                );
            } else {
                results.push(
                    CheckResult::pass(
                        "SEC-097",
                        CAT,
                        Severity::Warning,
                        "cipherSuites does not contain known weak algorithms",
                    )
                    .at_element("ApplicationDefaults"),
                );
            }
        }
    }

    // SEC-107: XML configuration contains password/secret in comments
    if let Some(ref content) = config.shibboleth_xml_content {
        let lower = content.to_lowercase();
        if lower.contains("<!-- ") || lower.contains("<!--\n") {
            let sensitive_patterns = ["password", "secret", "apikey", "api_key", "token"];
            let mut found_in_comment = false;
            let mut in_comment = false;
            for line in lower.lines() {
                let trimmed = line.trim();
                if trimmed.contains("<!--") {
                    in_comment = true;
                }
                if in_comment {
                    for pat in &sensitive_patterns {
                        if trimmed.contains(pat) {
                            found_in_comment = true;
                            break;
                        }
                    }
                }
                if trimmed.contains("-->") {
                    in_comment = false;
                }
                if found_in_comment {
                    break;
                }
            }
            if found_in_comment {
                results.push(
                    CheckResult::fail(
                        "SEC-107",
                        CAT,
                        Severity::Warning,
                        "XML comments contain sensitive keywords (password, secret, token, apikey)",
                        Some("Remove comments containing credentials or secrets from configuration files"),
                    )
                    .with_doc(doc_for(DOC_APP_DEFAULTS, v)),
                );
            } else {
                results.push(CheckResult::pass(
                    "SEC-107",
                    CAT,
                    Severity::Warning,
                    "XML comments do not contain obvious sensitive keywords",
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
                let full_path = config.resolve_path(key_path);
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

    check_data_sealers(sc, results);
}

/// SEC-114: a Static DataSealer keeps the secret key in shibboleth2.xml (the docs call it
/// a testing variant); a Versioned one that loads keys from a URL needs backingFilePath.
fn check_data_sealers(sc: &ShibbolethConfig, results: &mut Vec<CheckResult>) {
    for sealer in &sc.data_sealers {
        let problem = match sealer.sealer_type.as_str() {
            "Static" => Some((
                Severity::Warning,
                "DataSealer type=\"Static\" embeds the secret key in shibboleth2.xml".to_string(),
                "Use type=\"Versioned\" and keep the keys in a separate file that only the SP can read",
                DOC_STATIC_DATASEALER,
            )),
            "Versioned" if sealer.url.is_some() && sealer.backing_file_path.is_none() => Some((
                Severity::Error,
                "Versioned DataSealer loads keys from a url but has no backingFilePath".to_string(),
                "Set backingFilePath so a valid copy of the key file survives a restart, or use a local path",
                DOC_VERSIONED_DATASEALER,
            )),
            _ => None,
        };
        let result = match problem {
            Some((severity, message, suggestion, doc)) => {
                CheckResult::fail("SEC-114", CAT, severity, &message, Some(suggestion))
                    .with_doc(doc)
            }
            None => CheckResult::pass(
                "SEC-114",
                CAT,
                Severity::Warning,
                "DataSealer keeps its keys outside shibboleth2.xml",
            ),
        };
        results.push(result.at_element("DataSealer"));
    }
}
