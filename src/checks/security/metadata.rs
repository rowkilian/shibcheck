use super::*;

pub(super) fn run(
    config: &DiscoveredConfig,
    sc: &ShibbolethConfig,
    v: SpVersion,
    results: &mut Vec<CheckResult>,
) {
    // SEC-011: MetadataFilter with signature validation.
    // Shibboleth type names are case-sensitive; a mistyped "signature" is ignored at load time.
    let has_sig_filter = sc.metadata_providers.iter().any(|mp| {
        mp.filters
            .iter()
            .any(|f| f.filter_type.contains("Signature"))
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
                        &format!(
                            "MetadataProvider{} uses plaintext HTTP URL: {}",
                            mp.label(),
                            url
                        ),
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
                    .at_element("SSO")
                    .with_doc(doc_for(DOC_SSO, v)),
                );
            } else {
                results.push(
                    CheckResult::pass(
                        "SEC-025",
                        CAT,
                        Severity::Info,
                        "SSO protocols do not include SAML1",
                    )
                    .at_element("SSO"),
                );
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

    // SEC-029: discoveryURL uses HTTPS
    if let Some(ref sessions) = sc.sessions {
        if let Some(ref discovery_url) = sessions.sso_discovery_url {
            if discovery_url.starts_with("https://") {
                results.push(
                    CheckResult::pass(
                        "SEC-029",
                        CAT,
                        Severity::Warning,
                        "SSO discoveryURL uses HTTPS",
                    )
                    .at_element("SSO"),
                );
            } else if discovery_url.starts_with("http://") {
                results.push(
                    CheckResult::fail(
                        "SEC-029",
                        CAT,
                        Severity::Warning,
                        &format!("SSO discoveryURL uses HTTP: {}", discovery_url),
                        Some("Use HTTPS for the discovery service URL"),
                    )
                    .at_element("SSO")
                    .with_doc(doc_for(DOC_SSO, v)),
                );
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
                            &format!("SignatureMetadataFilter{} has verifyName=\"false\" (signature name verification disabled)", mp.label()),
                            Some("Remove verifyName=\"false\" or set to \"true\" to verify the signer's name matches"),
                        )
                        .with_doc(doc_for(DOC_SIGNATURE_FILTER, v)),
                    );
                } else {
                    results.push(CheckResult::pass(
                        "SEC-054",
                        CAT,
                        Severity::Warning,
                        &format!(
                            "SignatureMetadataFilter{} verifyName is not disabled",
                            mp.label()
                        ),
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
                            "MetadataProvider type='{}'{} has ignoreTransport=\"true\" without a Signature filter",
                            mp.provider_type, mp.label()
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
                        "MetadataProvider type='{}'{} has ignoreTransport=\"true\" with compensating Signature filter",
                        mp.provider_type, mp.label()
                    ),
                ));
            }
        }
    }

    // SEC-069: RequireValidUntil MetadataFilter explicitly disabled
    for mp in &sc.metadata_providers {
        for filter in &mp.filters {
            if filter.filter_type == "RequireValidUntil"
                && filter.require_valid_until.as_deref() == Some("false")
            {
                results.push(
                    CheckResult::fail(
                        "SEC-069",
                        CAT,
                        Severity::Warning,
                        &format!("RequireValidUntil MetadataFilter{} is explicitly disabled (accepts expired metadata)", mp.label()),
                        Some("Remove require=\"false\" or set to \"true\" to enforce metadata expiration"),
                    )
                    .with_doc(doc_for(DOC_VALID_UNTIL_FILTER, v)),
                );
            }
        }
    }

    // SEC-070: Signature MetadataFilter has no certificate and no TrustEngine
    for mp in &sc.metadata_providers {
        for filter in &mp.filters {
            if filter.filter_type == "Signature" {
                if filter.certificate.is_none() && !filter.has_trust_engine {
                    results.push(
                        CheckResult::fail(
                            "SEC-070",
                            CAT,
                            Severity::Error,
                            &format!("SignatureMetadataFilter{} has no certificate and no TrustEngine (cannot verify signatures)", mp.label()),
                            Some("Add a certificate attribute or nested TrustEngine to the Signature filter"),
                        )
                        .with_doc(doc_for(DOC_SIGNATURE_FILTER, v)),
                    );
                } else {
                    results.push(CheckResult::pass(
                        "SEC-070",
                        CAT,
                        Severity::Error,
                        &format!(
                            "SignatureMetadataFilter{} has certificate or TrustEngine configured",
                            mp.label()
                        ),
                    ));
                }
            }
        }
    }

    // SEC-073: maxRefreshDelay on remote MetadataProvider exceeds 24 hours
    for mp in &sc.metadata_providers {
        if mp.uri.is_some() || mp.url.is_some() {
            if let Some(ref delay) = mp.max_refresh_delay {
                if let Ok(secs) = delay.parse::<u64>() {
                    if secs > 86400 {
                        results.push(
                            CheckResult::fail(
                                "SEC-073",
                                CAT,
                                Severity::Info,
                                &format!(
                                    "Remote MetadataProvider{} maxRefreshDelay is {} seconds (> 24h) — stale metadata risk",
                                    mp.label(), secs
                                ),
                                Some("Set maxRefreshDelay to 86400 or less to ensure timely metadata updates"),
                            )
                            .with_doc(doc_for(DOC_METADATA_PROVIDER, v)),
                        );
                    } else {
                        results.push(CheckResult::pass(
                            "SEC-073",
                            CAT,
                            Severity::Info,
                            &format!(
                                "Remote MetadataProvider{} maxRefreshDelay is {} seconds",
                                mp.label(),
                                secs
                            ),
                        ));
                    }
                }
            }
        }
    }

    // SEC-076: SessionInitiator uses SAML1 protocol
    for si in &sc.session_initiators {
        if let Some(ref itype) = si.initiator_type {
            if itype == "SAML1" {
                results.push(
                    CheckResult::fail(
                        "SEC-076",
                        CAT,
                        Severity::Warning,
                        "SessionInitiator uses SAML1 protocol (obsolete and less secure)",
                        Some("Migrate to SAML2 SessionInitiator for better security features"),
                    )
                    .at_element("SessionInitiator")
                    .with_doc(doc_for(DOC_SSO, v)),
                );
            }
        }
    }

    // SEC-082: SAML1 protocol in SSO protocols list
    if let Some(ref sessions) = sc.sessions {
        if let Some(ref protocols) = sessions.sso_protocols {
            let lower = protocols.to_lowercase();
            if lower.contains("saml1") || lower.contains("urn:oasis:names:tc:saml:1") {
                results.push(
                    CheckResult::fail(
                        "SEC-082",
                        CAT,
                        Severity::Warning,
                        &format!("SSO protocols include SAML1: {}", protocols),
                        Some("Remove SAML1 from SSO protocols — SAML 1.x is obsolete and lacks modern security features"),
                    ).at_element("Sessions")
                    .with_doc(doc_for(DOC_SSO, v)),
                );
            } else {
                results.push(
                    CheckResult::pass(
                        "SEC-082",
                        CAT,
                        Severity::Warning,
                        "SSO protocols do not include SAML1",
                    )
                    .at_element("Sessions"),
                );
            }
        }
    }

    // SEC-086: Metadata backing file is world-writable (could be tampered)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for mp in &sc.metadata_providers {
            if let Some(ref bf) = mp.backing_file_path {
                let full_path = config.base_dir.join(bf);
                if full_path.exists() {
                    if let Ok(metadata) = std::fs::metadata(&full_path) {
                        let mode = metadata.permissions().mode();
                        if mode & 0o002 != 0 {
                            results.push(
                                CheckResult::fail(
                                    "SEC-086",
                                    CAT,
                                    Severity::Warning,
                                    &format!(
                                        "Metadata backing file {} is world-writable (mode {:04o}) — could be tampered with",
                                        bf,
                                        mode & 0o7777
                                    ),
                                    Some("Set metadata backing file permissions to 0644 or more restrictive"),
                                )
                                .with_doc(doc_for(DOC_METADATA_PROVIDER, v)),
                            );
                        } else {
                            results.push(CheckResult::pass(
                                "SEC-086",
                                CAT,
                                Severity::Warning,
                                &format!(
                                    "Metadata backing file {} is not world-writable (mode {:04o})",
                                    bf,
                                    mode & 0o7777
                                ),
                            ));
                        }
                    }
                }
            }
        }
    }

    // SEC-098: Metadata Signature filter verifyBackup="false"
    for mp in &sc.metadata_providers {
        for filter in &mp.filters {
            if filter.filter_type == "Signature" && filter.verify_backup.as_deref() == Some("false")
            {
                results.push(
                    CheckResult::fail(
                        "SEC-098",
                        CAT,
                        Severity::Info,
                        &format!("SignatureMetadataFilter{} has verifyBackup=\"false\" (backup signature verification disabled)", mp.label()),
                        Some("Remove verifyBackup=\"false\" to enable backup signature verification"),
                    )
                    .with_doc(doc_for(DOC_SIGNATURE_FILTER, v)),
                );
            }
        }
    }

    // SEC-117: WAYF discovery protocol (outdated, less secure than SAMLDS)
    if let Some(ref sessions) = sc.sessions {
        if let Some(ref proto) = sessions.sso_discovery_protocol {
            if proto == "WAYF" {
                results.push(
                    CheckResult::fail(
                        "SEC-117",
                        CAT,
                        Severity::Info,
                        "SSO discoveryProtocol is WAYF (outdated protocol)",
                        Some("Migrate to SAMLDS discovery protocol for better security and standards compliance"),
                    ).at_element("SSO")
                    .with_doc(doc_for(DOC_SSO, v)),
                );
            } else {
                results.push(
                    CheckResult::pass(
                        "SEC-117",
                        CAT,
                        Severity::Info,
                        &format!("SSO discoveryProtocol is {} (not WAYF)", proto),
                    )
                    .at_element("SSO"),
                );
            }
        }
    }

    // SEC-118: Multiple default SessionInitiators (ambiguous default)
    {
        let default_count = sc
            .session_initiators
            .iter()
            .filter(|si| si.is_default.as_deref() == Some("true"))
            .count();
        if default_count > 1 {
            results.push(
                CheckResult::fail(
                    "SEC-118",
                    CAT,
                    Severity::Warning,
                    &format!(
                        "{} SessionInitiators marked as isDefault=\"true\" (ambiguous default — behavior is undefined)",
                        default_count
                    ),
                    Some("Only one SessionInitiator should have isDefault=\"true\""),
                ).at_element("SessionInitiator")
                .with_doc(doc_for(DOC_SSO, v)),
            );
        } else if default_count == 1 {
            results.push(
                CheckResult::pass(
                    "SEC-118",
                    CAT,
                    Severity::Warning,
                    "Only one SessionInitiator is the default",
                )
                .at_element("SessionInitiator"),
            );
        }
    }

    // SEC-120: Shib1 SessionInitiator type (legacy SAML1 browser profile)
    for si in &sc.session_initiators {
        if let Some(ref itype) = si.initiator_type {
            if itype == "Shib1" {
                results.push(
                    CheckResult::fail(
                        "SEC-120",
                        CAT,
                        Severity::Warning,
                        &format!(
                            "SessionInitiator id='{}' uses Shib1 type (legacy SAML1 browser profile)",
                            si.id.as_deref().unwrap_or("(unnamed)")
                        ),
                        Some("Migrate to SAML2 SessionInitiator type for modern security features"),
                    ).at_element("SessionInitiator")
                    .with_doc(doc_for(DOC_SSO, v)),
                );
            }
        }
    }

    // SEC-122: Remote MetadataProvider with no filters at all (no validation whatsoever)
    for mp in &sc.metadata_providers {
        if (mp.uri.is_some() || mp.url.is_some()) && mp.filters.is_empty() {
            // SEC-011 already checks for Signature filter; this is stricter — no filters at all
            results.push(
                CheckResult::fail(
                    "SEC-122",
                    CAT,
                    Severity::Warning,
                    &format!(
                        "Remote MetadataProvider type='{}'{} has no MetadataFilter elements (metadata accepted without any validation)",
                        mp.provider_type, mp.label()
                    ),
                    Some("Add at least a RequireValidUntil and Signature MetadataFilter to validate remote metadata"),
                )
                .with_doc(doc_for(DOC_METADATA_PROVIDER, v)),
            );
        }
    }

    // SEC-123: Metadata Signature filter certificate path uses HTTP URL
    for mp in &sc.metadata_providers {
        for filter in &mp.filters {
            if filter.filter_type == "Signature" {
                if let Some(ref cert) = filter.certificate {
                    if cert.starts_with("http://") {
                        results.push(
                            CheckResult::fail(
                                "SEC-123",
                                CAT,
                                Severity::Warning,
                                &format!(
                                    "SignatureMetadataFilter{} certificate is fetched over plain HTTP: {}",
                                    mp.label(), cert
                                ),
                                Some("Use a local certificate file or HTTPS URL for the metadata signing certificate"),
                            )
                            .with_doc(doc_for(DOC_SIGNATURE_FILTER, v)),
                        );
                    }
                }
            }
        }
    }
}
