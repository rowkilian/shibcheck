//! Checks on `<RelyingParty>` overrides. They can change the same security settings as
//! `ApplicationDefaults`, but only for some IdPs, so a weakened setting is easy to miss.

use crate::config::DiscoveredConfig;
use crate::location::find_element_line;
use crate::model::shibboleth_config::RelyingPartyInfo;
use crate::result::{CheckCategory, CheckResult, Severity};

const DOC: &str = "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334363/RelyingParty";

/// What to call this override in a message: its Name, else its matcher type.
fn label(rp: &RelyingPartyInfo) -> String {
    match (&rp.name, &rp.matcher_type) {
        (Some(n), _) => format!("RelyingParty '{n}'"),
        (None, Some(t)) => format!("RelyingParty of type {t}"),
        (None, None) => "RelyingParty".to_string(),
    }
}

fn locate(config: &DiscoveredConfig, rp: &RelyingPartyInfo) -> Option<usize> {
    let xml = config.shibboleth_xml_content.as_deref()?;
    match &rp.name {
        Some(n) => find_element_line(xml, "RelyingParty", Some("Name"), Some(n)),
        None => find_element_line(xml, "RelyingParty", None, None),
    }
}

fn file(config: &DiscoveredConfig) -> String {
    config
        .shibboleth_xml_path
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn is_sha1(alg: &str) -> bool {
    let lower = alg.to_lowercase();
    lower.contains("sha1") || lower.contains("sha-1")
}

/// XML-058: without `Name` or `type`, the override cannot match any IdP.
pub fn structure(config: &DiscoveredConfig, results: &mut Vec<CheckResult>) {
    let Some(sc) = &config.shibboleth_config else {
        return;
    };
    for rp in &sc.relying_parties {
        let cat = CheckCategory::XmlValidity;
        // The EntityMatcher types the SP ships with.
        if let Some(kind) = rp
            .matcher_type
            .as_deref()
            .filter(|t| !matches!(*t, "Name" | "EntityAttributes" | "RegistrationAuthority"))
        {
            results.push(
                CheckResult::fail(
                    "XML-058",
                    cat,
                    Severity::Error,
                    &format!(
                        "{} has type=\"{kind}\", which is not an EntityMatcher type",
                        label(rp)
                    ),
                    Some("Use Name, EntityAttributes or RegistrationAuthority"),
                )
                .with_location(&file(config), locate(config, rp))
                .with_doc(DOC),
            );
            continue;
        }
        let ok = rp.name.is_some() || rp.matcher_type.is_some();
        if ok {
            results.push(
                CheckResult::pass(
                    "XML-058",
                    cat,
                    Severity::Error,
                    &format!("{} can match an IdP", label(rp)),
                )
                .with_location(&file(config), locate(config, rp)),
            );
        } else {
            results.push(
                CheckResult::fail(
                    "XML-058",
                    cat,
                    Severity::Error,
                    "RelyingParty has neither Name nor type, so it never matches an IdP",
                    Some("Set Name to an IdP entityID or a metadata group name, or set type to an EntityMatcher"),
                )
                .with_location(&file(config), locate(config, rp))
                .with_doc(DOC),
            );
        }
    }
}

/// SEC-140 to SEC-144: settings a `RelyingParty` can weaken for one IdP. SEC-142 and
/// SEC-143 also apply to the same attributes on `ApplicationDefaults`.
pub fn security(config: &DiscoveredConfig, results: &mut Vec<CheckResult>) {
    let Some(sc) = &config.shibboleth_config else {
        return;
    };
    let cat = CheckCategory::Security;
    if let Some(app) = &sc.application_defaults {
        if app
            .auth_type
            .as_deref()
            .is_some_and(|a| a.eq_ignore_ascii_case("basic"))
        {
            results.push(
                CheckResult::fail(
                    "SEC-142",
                    cat,
                    Severity::Info,
                    "ApplicationDefaults uses authType=\"basic\", which sends a name and password in cleartext",
                    Some("Use TLS client certificate authentication (the default). If you must use Basic, make sure the back-channel URL is https"),
                )
                .at_element("ApplicationDefaults")
                .with_doc(DOC),
            );
        }
        if app.has_auth_password {
            results.push(
                CheckResult::fail(
                    "SEC-143",
                    cat,
                    Severity::Warning,
                    "ApplicationDefaults keeps authPassword in shibboleth2.xml",
                    Some("Prefer TLS client certificate authentication. If you keep the password, limit read access to this file and keep it out of version control"),
                )
                .at_element("ApplicationDefaults")
                .with_doc(DOC),
            );
        }
    }
    let file = file(config);
    for rp in &sc.relying_parties {
        let line = locate(config, rp);
        let who = label(rp);
        let mut emit = |code: &str, sev: Severity, bad: bool, ok: &str, fail: &str, hint: &str| {
            let r = if bad {
                CheckResult::fail(code, cat, sev, fail, Some(hint)).with_doc(DOC)
            } else {
                CheckResult::pass(code, cat, sev, ok)
            };
            results.push(r.with_location(&file, line));
        };

        for (code, attr, value, what) in [
            (
                "SEC-140",
                "requireTransportAuth",
                &rp.require_transport_auth,
                "TLS certificate validation on the back channel",
            ),
            (
                "SEC-141",
                "requireConfidentiality",
                &rp.require_confidentiality,
                "encryption of the back channel",
            ),
        ] {
            if let Some(v) = value {
                emit(
                    code,
                    Severity::Warning,
                    v == "false",
                    &format!("{who} does not turn off {what}"),
                    &format!("{who} sets {attr}=\"false\", which turns off {what} for this IdP"),
                    &format!("Remove {attr}=\"false\" from this RelyingParty"),
                );
            }
        }

        if let Some(auth) = &rp.auth_type {
            let basic = auth.eq_ignore_ascii_case("basic");
            emit(
                "SEC-142",
                Severity::Info,
                basic,
                &format!("{who} does not use HTTP Basic authentication"),
                &format!("{who} uses authType=\"basic\", which sends a name and password in cleartext"),
                "Use TLS client certificate authentication (the default). If you must use Basic, make sure the back-channel URL is https",
            );
        }

        if rp.has_auth_password {
            emit(
                "SEC-143",
                Severity::Warning,
                true,
                "",
                &format!("{who} keeps authPassword in shibboleth2.xml"),
                "Prefer TLS client certificate authentication. If you keep the password, limit read access to this file and keep it out of version control",
            );
        }

        for (attr, enabled) in [("signing", &rp.signing), ("encryption", &rp.encryption)] {
            if let Some(v) = enabled {
                emit(
                    "SEC-144",
                    Severity::Warning,
                    v == "false",
                    &format!("{who} does not disable {attr}"),
                    &format!("{who} sets {attr}=\"false\", which turns off outbound {attr} for this IdP"),
                    &format!("Remove {attr}=\"false\", or limit it to an IdP that cannot handle it and note why"),
                );
            }
        }

        for (attr, alg) in [
            ("signingAlg", &rp.signing_alg),
            ("digestAlg", &rp.digest_alg),
        ] {
            if let Some(a) = alg {
                emit(
                    "SEC-145",
                    Severity::Warning,
                    is_sha1(a),
                    &format!("{who} {attr} does not use SHA-1"),
                    &format!("{who} {attr} uses SHA-1: {a}"),
                    "Use a SHA-256 or stronger algorithm",
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{assert_absent, assert_outcome, config_from_xml, sp3_app};

    fn run_rp(attrs: &str) -> Vec<CheckResult> {
        let xml = sp3_app("", &format!(r#"<RelyingParty {attrs}/>"#));
        let (_dir, config) = config_from_xml(&xml);
        let mut r = Vec::new();
        structure(&config, &mut r);
        security(&config, &mut r);
        r
    }

    #[test]
    fn needs_a_name_or_type() {
        assert_outcome(
            &run_rp(r#"Name="https://idp.example.org""#),
            "XML-058",
            true,
        );
        assert_outcome(&run_rp(r#"type="EntityAttributes""#), "XML-058", true);
        assert_outcome(&run_rp(r#"type="Whatever""#), "XML-058", false);
        assert_outcome(&run_rp(r#"authType="basic""#), "XML-058", false);
    }

    #[test]
    fn back_channel_settings() {
        let r = run_rp(r#"Name="x" requireTransportAuth="false" requireConfidentiality="true""#);
        assert_outcome(&r, "SEC-140", false);
        assert_outcome(&r, "SEC-141", true);
        assert_absent(&run_rp(r#"Name="x""#), "SEC-140");
    }

    #[test]
    fn credentials_and_algorithms() {
        let r = run_rp(r#"Name="x" authType="basic" authUsername="u" authPassword="hunter2""#);
        assert_outcome(&r, "SEC-142", false);
        assert_outcome(&r, "SEC-143", false);
        // the password itself must never show up in a report
        assert!(r.iter().all(|x| !x.message.contains("hunter2")));
        assert_outcome(&run_rp(r#"Name="x" authType="TLS""#), "SEC-142", true);

        let r = run_rp(
            r#"Name="x" signing="false" encryption="true" signingAlg="http://www.w3.org/2000/09/xmldsig#rsa-sha1" digestAlg="http://www.w3.org/2001/04/xmlenc#sha256""#,
        );
        assert!(r.iter().any(|x| x.code == "SEC-144" && !x.passed));
        assert!(r.iter().any(|x| x.code == "SEC-144" && x.passed));
        assert!(r.iter().any(|x| x.code == "SEC-145" && !x.passed));
        assert!(r.iter().any(|x| x.code == "SEC-145" && x.passed));
    }
}
