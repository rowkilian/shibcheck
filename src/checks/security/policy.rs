use super::*;

pub(super) fn run(
    config: &DiscoveredConfig,
    sc: &ShibbolethConfig,
    v: SpVersion,
    results: &mut Vec<CheckResult>,
) {
    // SEC-027: security-policy.xml has no disabled AlgorithmBlacklist
    {
        let security_policy_path = config.base_dir.join("security-policy.xml");
        if security_policy_path.exists() {
            if let Ok(content) = std::fs::read_to_string(&security_policy_path) {
                let lower = content.to_lowercase();
                if lower.contains("algorithmblacklist")
                    || lower.contains("excludedalgorithms")
                    || lower.contains("algorithmfilter")
                {
                    results.push(CheckResult::pass(
                        "SEC-027",
                        CAT,
                        Severity::Warning,
                        "security-policy.xml contains algorithm filtering rules",
                    ));
                }
                // Without the element the SP still excludes its default list of weak
                // algorithms (excludeDefaults is true), so there is nothing to report.
            }
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
                        .at_element("Sessions")
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
                        .at_element("Sessions")
                        .with_doc(doc_for(DOC_SESSIONS, v)),
                    );
                } else {
                    results.push(
                        CheckResult::pass(
                            "SEC-038",
                            CAT,
                            Severity::Info,
                            &format!("Sessions postLimit is {} bytes", limit),
                        )
                        .at_element("Sessions"),
                    );
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
            results.push(
                CheckResult::pass(
                    "SEC-039",
                    CAT,
                    Severity::Info,
                    "SecurityPolicyProvider has validate=\"true\"",
                )
                .at_element("SecurityPolicyProvider"),
            );
        } else {
            results.push(
                CheckResult::fail(
                    "SEC-039",
                    CAT,
                    Severity::Info,
                    "SecurityPolicyProvider missing validate=\"true\"",
                    Some("Add validate=\"true\" to SecurityPolicyProvider to validate the policy file on load"),
                ).at_element("SecurityPolicyProvider")
                .with_doc(doc_for(DOC_APP_DEFAULTS, v)),
            );
        }
    }

    // SEC-040: security-policy.xml must not stop the SP from excluding known weak algorithms.
    // The docs make excludeDefaults (formerly includeDefaultBlacklist) true unless set to "false".
    if let Some(loaded) = crate::parsers::security_policy::load_for(config) {
        if loaded.policy.defaults_disabled {
            let line =
                find_attr_value_line(&loaded.content, "excludeDefaults", "false").or_else(|| {
                    find_attr_value_line(&loaded.content, "includeDefaultBlacklist", "false")
                });
            results.push(
                CheckResult::fail(
                    "SEC-040",
                    CAT,
                    Severity::Warning,
                    &format!(
                        "{} sets excludeDefaults=\"false\", so known weak algorithms stay enabled",
                        loaded.file_name
                    ),
                    Some("Remove excludeDefaults=\"false\" (or includeDefaultBlacklist=\"false\") unless you must accept a weak algorithm"),
                )
                .with_location(&loaded.file_name, line)
                .with_doc("https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334583/ExcludedAlgorithms"),
            );
        } else {
            results.push(CheckResult::pass(
                "SEC-040",
                CAT,
                Severity::Warning,
                &format!(
                    "{} keeps the default exclusion of weak algorithms",
                    loaded.file_name
                ),
            ));
        }
    }

    // SEC-048: No SecurityPolicyProvider configured
    if sc.security_policy_provider_path.is_some() {
        results.push(
            CheckResult::pass(
                "SEC-048",
                CAT,
                Severity::Warning,
                "SecurityPolicyProvider is configured",
            )
            .at_element("SecurityPolicyProvider"),
        );
    } else {
        results.push(
            CheckResult::fail(
                "SEC-048",
                CAT,
                Severity::Warning,
                "No SecurityPolicyProvider configured",
                Some("Add a <SecurityPolicyProvider> element to define security policies"),
            )
            .at_element("SecurityPolicyProvider")
            .with_doc(doc_for(DOC_APP_DEFAULTS, v)),
        );
    }

    // SEC-075: NameIDFormat contains emailAddress (PII in NameID)
    if let Some(ref content) = config.shibboleth_xml_content {
        if super::super::without_comments(content)
            .contains("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
        {
            results.push(
                CheckResult::fail(
                    "SEC-075",
                    CAT,
                    Severity::Info,
                    "NameIDFormat uses emailAddress (PII exposed in SAML NameID)",
                    Some("Consider using transient or persistent NameIDFormat to avoid exposing email addresses in SAML assertions"),
                )
                .with_doc(doc_for(DOC_SSO, v)),
            );
        }
    }

    // SEC-085: Attribute policy file uses wildcard scope matching
    {
        let policy_path = config.base_dir.join("attribute-policy.xml");
        if policy_path.exists() {
            if let Ok(policy_content) = std::fs::read_to_string(&policy_path) {
                let policy_content = super::super::without_comments(&policy_content);
                if policy_content.contains("type=\"ANY\"")
                    && (policy_content.contains("scope=\"any\"")
                        || policy_content.contains("Scope=\"any\""))
                {
                    results.push(
                        CheckResult::fail(
                            "SEC-085",
                            CAT,
                            Severity::Warning,
                            "Attribute policy uses PermitValueRule type=\"ANY\" with scope=\"any\" (accepts attributes from any scope)",
                            Some("Restrict attribute scopes to known domains instead of accepting any scope"),
                        )
                        .with_doc(doc_for(DOC_APP_DEFAULTS, v)),
                    );
                }
            }
        }
    }

    // SEC-108: Attribute map maps to security-sensitive header names
    if let Some(ref attr_map) = config.attribute_map {
        let sensitive_ids = [
            "REMOTE_USER",
            "HTTP_HOST",
            "HTTP_AUTHORIZATION",
            "HTTP_COOKIE",
            "CONTENT_TYPE",
            "CONTENT_LENGTH",
            "SERVER_NAME",
            "SCRIPT_NAME",
            "PATH_INFO",
        ];
        for attr in &attr_map.attributes {
            let upper_id = attr.id.to_uppercase();
            if sensitive_ids.contains(&upper_id.as_str()) {
                results.push(
                    CheckResult::fail(
                        "SEC-108",
                        CAT,
                        Severity::Warning,
                        &format!(
                            "Attribute '{}' maps to security-sensitive header name '{}'",
                            attr.name, attr.id
                        ),
                        Some("Use a unique attribute ID that won't collide with standard HTTP/CGI headers"),
                    )
                    .with_doc(doc_for(DOC_APP_DEFAULTS, v)),
                );
            }
        }
    }

    // SEC-110: security-policy.xml contains weak algorithm URIs (SHA-1 signing, 3DES encryption)
    {
        let security_policy_path = config.base_dir.join("security-policy.xml");
        if security_policy_path.exists() {
            if let Ok(content) = std::fs::read_to_string(&security_policy_path) {
                let weak_algos = [
                    (
                        "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
                        "RSA-SHA1 signing",
                    ),
                    (
                        "http://www.w3.org/2000/09/xmldsig#dsa-sha1",
                        "DSA-SHA1 signing",
                    ),
                    ("http://www.w3.org/2000/09/xmldsig#sha1", "SHA-1 digest"),
                    (
                        "http://www.w3.org/2001/04/xmlenc#tripledes-cbc",
                        "3DES encryption",
                    ),
                ];
                let mut found: Vec<&str> = Vec::new();
                // Listing a weak algorithm in an exclusion list is the point of the list.
                let outside_exclusions =
                    without_exclusion_lists(&super::super::without_comments(&content));
                for (uri, label) in &weak_algos {
                    if outside_exclusions.contains(uri) {
                        found.push(label);
                    }
                }
                if !found.is_empty() {
                    results.push(
                        CheckResult::fail(
                            "SEC-110",
                            CAT,
                            Severity::Warning,
                            &format!(
                                "security-policy.xml references weak algorithms: {}",
                                found.join(", ")
                            ),
                            Some("Remove weak algorithms from the security policy or move them to the blacklist"),
                        )
                        .with_doc(doc_for(DOC_APP_DEFAULTS, v)),
                    );
                } else {
                    results.push(CheckResult::pass(
                        "SEC-110",
                        CAT,
                        Severity::Warning,
                        "security-policy.xml does not reference known weak algorithms outside blacklists",
                    ));
                }
            }
        }
    }

    // SEC-112: Attribute policy rule permits all values without scope checking
    if let Some(ref policy) = config.attribute_policy {
        for rule in &policy.rules {
            if rule.permit_value_rule_type.as_deref() == Some("ANY") && !rule.has_scope_match {
                // Check if this is a scoped attribute that should have scope checking
                let is_likely_scoped = rule.attribute_id.contains("scoped")
                    || rule.attribute_id == "eppn"
                    || rule.attribute_id == "epsa"
                    || rule.attribute_id == "eduPersonScopedAffiliation"
                    || rule.attribute_id == "eduPersonPrincipalName";
                if is_likely_scoped {
                    results.push(
                        CheckResult::fail(
                            "SEC-112",
                            CAT,
                            Severity::Warning,
                            &format!(
                                "Attribute policy for '{}' permits ANY value without scope validation (scoped attribute may accept spoofed values)",
                                rule.attribute_id
                            ),
                            Some("Add ScopeMatchesShibMDScope condition to validate scoped attributes against IdP metadata"),
                        )
                        .with_doc(doc_for(DOC_APP_DEFAULTS, v)),
                    );
                }
            }
        }
    }

    check_policy_rules(config, sc, results);
}

/// `content` with the body of each `ExcludedAlgorithms` and `AlgorithmBlacklist` element removed.
fn without_exclusion_lists(content: &str) -> String {
    let mut rest = content.to_string();
    for name in ["ExcludedAlgorithms", "AlgorithmBlacklist"] {
        let open = format!("<{name}");
        let close = format!("</{name}>");
        while let Some(start) = rest.find(&open) {
            let Some(len) = rest[start..].find(&close) else {
                // An unclosed or self-closed element has no body to remove.
                rest.replace_range(start..start + open.len(), "");
                continue;
            };
            rest.replace_range(start..start + len + close.len(), "");
        }
    }
    rest
}

/// Line of `attr="value"` or `attr='value'` in `content`.
fn find_attr_value_line(content: &str, attr: &str, value: &str) -> Option<usize> {
    crate::location::find_line(content, &format!("{}=\"{}\"", attr, value))
        .or_else(|| crate::location::find_line(content, &format!("{}='{}'", attr, value)))
}

/// SEC-137 (NullSecurity rule) and SEC-138 (MessageFlow checkReplay="false"), in
/// security-policy.xml and in policies written inline in shibboleth2.xml.
fn check_policy_rules(
    config: &DiscoveredConfig,
    sc: &ShibbolethConfig,
    results: &mut Vec<CheckResult>,
) {
    let file_name = |path: &std::path::Path| {
        path.file_name()
            .map(|f| f.to_string_lossy().into_owned())
            .unwrap_or_default()
    };
    let mut sources: Vec<(String, String)> = Vec::new();
    if let Some(ref content) = config.shibboleth_xml_content {
        sources.push((
            file_name(&config.shibboleth_xml_path),
            super::super::without_comments(content),
        ));
    }
    let policy_path = match sc.security_policy_provider_path {
        Some(ref p) => config.resolve_path(p),
        None => config.base_dir.join("security-policy.xml"),
    };
    if let Ok(content) = std::fs::read_to_string(&policy_path) {
        sources.push((
            file_name(&policy_path),
            super::super::without_comments(&content),
        ));
    }
    if sources.is_empty() {
        return;
    }

    struct Rule {
        code: &'static str,
        severity: Severity,
        fail_message: &'static str,
        suggestion: &'static str,
        attr: &'static str,
        value: &'static str,
        pass_message: &'static str,
        doc: &'static str,
    }
    let rules = [
        Rule {
            code: "SEC-137",
            severity: Severity::Error,
            fail_message: "A NullSecurity policy rule is configured",
            suggestion: "Remove the NullSecurity rule. It disables security checks and lets unauthenticated messages through; it is for debugging only",
            attr: "type",
            value: "NullSecurity",
            pass_message: "No NullSecurity policy rule is configured",
            doc: DOC_NULL_SECURITY,
        },
        Rule {
            code: "SEC-138",
            severity: Severity::Warning,
            fail_message: "A MessageFlow policy rule disables the replay check (checkReplay=\"false\")",
            suggestion: "Remove checkReplay=\"false\". Do not turn off the replay check in production",
            attr: "checkReplay",
            value: "false",
            pass_message: "No policy rule disables the replay check",
            doc: DOC_MESSAGE_FLOW,
        },
    ];
    for rule in rules {
        let hit = sources.iter().find_map(|(name, content)| {
            find_attr_value_line(content, rule.attr, rule.value).map(|line| (name.clone(), line))
        });
        match hit {
            Some((name, line)) => results.push(
                CheckResult::fail(
                    rule.code,
                    CAT,
                    rule.severity,
                    rule.fail_message,
                    Some(rule.suggestion),
                )
                .with_location(&name, Some(line))
                .with_doc(rule.doc),
            ),
            None => results.push(CheckResult::pass(
                rule.code,
                CAT,
                rule.severity,
                rule.pass_message,
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::checks::security::run;
    use crate::result::CheckResult;
    use crate::testutil::{assert_absent, assert_outcome, TestDir};

    fn run_policy(policy: Option<&str>) -> Vec<CheckResult> {
        let dir = TestDir::new();
        dir.write(
            "shibboleth2.xml",
            r#"<SPConfig xmlns="urn:mace:shibboleth:3.0:native:sp:config"><ApplicationDefaults entityID="https://sp.example.org/shibboleth"/></SPConfig>"#,
        );
        if let Some(policy) = policy {
            dir.write("security-policy.xml", policy);
        }
        run(&dir.discover())
    }

    #[test]
    fn default_algorithm_exclusion_must_stay_on() {
        let with = |attrs: &str| {
            run_policy(Some(&format!(
                r#"<SecurityPolicies><Policy id="default"/><ExcludedAlgorithms {attrs}>x</ExcludedAlgorithms></SecurityPolicies>"#
            )))
        };
        assert_outcome(&with(r#"excludeDefaults="false""#), "SEC-040", false);
        assert_outcome(
            &with(r#"includeDefaultBlacklist="false""#),
            "SEC-040",
            false,
        );
        // true is the default and the safe setting
        assert_outcome(&with(r#"excludeDefaults="true""#), "SEC-040", true);
        assert_outcome(&with(""), "SEC-040", true);
        assert_absent(&run_policy(None), "SEC-040");
    }

    #[test]
    fn weak_algorithms_inside_exclusion_lists_are_fine() {
        const SHA1: &str = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
        let policy = |body: &str| {
            run_policy(Some(&format!(
                r#"<SecurityPolicies><Policy id="default"/>{body}</SecurityPolicies>"#
            )))
        };
        assert_outcome(
            &policy(&format!("<ExcludedAlgorithms>{SHA1}</ExcludedAlgorithms>")),
            "SEC-110",
            true,
        );
        assert_outcome(
            &policy(&format!("<AlgorithmBlacklist>{SHA1}</AlgorithmBlacklist>")),
            "SEC-110",
            true,
        );
        assert_outcome(
            &policy(&format!("<IncludedAlgorithms>{SHA1}</IncludedAlgorithms>")),
            "SEC-110",
            false,
        );
        assert_outcome(
            &policy("<ExcludedAlgorithms>x</ExcludedAlgorithms>"),
            "SEC-027",
            true,
        );
        // Without the element the SP still excludes its default list.
        crate::testutil::assert_absent(&policy(""), "SEC-027");
    }
}
