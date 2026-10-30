//! Checks on content settings (`exportAssertion`, `redirectToSSL`), `acsByIndex` and the
//! discovery-style session initiators.

use crate::config::DiscoveredConfig;
use crate::model::shibboleth_config::SpVersion;
use crate::result::{CheckCategory, CheckResult, Severity};

const DOC_CONTENT_SETTINGS: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334723/ContentSettings";
const DOC_ASSERTION_EXPORT: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065335032/AssertionExport";
const DOC_SAML2_INITIATOR: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334736/SAML2+SessionInitiator";

fn host_or_path(element: &str) -> &'static str {
    if element == "Host" {
        "Host"
    } else {
        "Path"
    }
}

/// XML-062: `redirectToSSL` is a port number.
pub(super) fn structure(config: &DiscoveredConfig, results: &mut Vec<CheckResult>) {
    let Some(sc) = config.shibboleth_config.as_ref() else {
        return;
    };
    for setting in &sc.request_map_content_settings {
        let Some(value) = setting.redirect_to_ssl.as_deref() else {
            continue;
        };
        let place = setting.name.as_deref().unwrap_or("(unnamed)");
        let element = host_or_path(&setting.element);
        let ok = value.trim().parse::<u16>().is_ok_and(|p| p > 0);
        results.push(if ok {
            CheckResult::pass(
                "XML-062",
                CheckCategory::XmlValidity,
                Severity::Error,
                &format!("{element} '{place}' redirectToSSL is a port number"),
            )
            .at_element(element)
        } else {
            CheckResult::fail(
                "XML-062",
                CheckCategory::XmlValidity,
                Severity::Error,
                &format!("{element} '{place}' redirectToSSL=\"{value}\" is not a port number"),
                Some("Use the TLS port as an integer from 1 to 65535, such as 443"),
            )
            .at_element(element)
            .with_doc(DOC_CONTENT_SETTINGS)
        });
    }
}

/// XML-063 to XML-065: attributes the docs require on the discovery-style initiators.
pub(super) fn initiators(config: &DiscoveredConfig, results: &mut Vec<CheckResult>) {
    const CAT: CheckCategory = CheckCategory::XmlValidity;
    let Some(sc) = config.shibboleth_config.as_ref() else {
        return;
    };
    let page = |kind: &str| {
        match kind {
        "SAMLDS" => "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334744/SAMLDS+SessionInitiator",
        "WAYF" => "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334755/WAYF+SessionInitiator",
        _ => "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334762/Form+SessionInitiator",
    }
    };
    for init in &sc.session_initiators {
        let Some(kind) = init.initiator_type.as_deref() else {
            continue;
        };
        if !matches!(kind, "SAMLDS" | "WAYF" | "Form") {
            continue;
        }
        let id = init
            .id
            .as_deref()
            .map(|i| format!(" '{i}'"))
            .unwrap_or_default();

        // XML-063: SAMLDS and WAYF need the URL of the discovery service.
        // XML-064: Form needs the path of its HTML template.
        let (code, attr, value) = if kind == "Form" {
            ("XML-064", "template", init.template.as_deref())
        } else {
            ("XML-063", "URL", init.url.as_deref())
        };
        let missing = value.is_none_or(|v| v.trim().is_empty());
        results.push(if missing {
            CheckResult::fail(
                code,
                CAT,
                Severity::Error,
                &format!("{kind} SessionInitiator{id} has no {attr} attribute"),
                Some(if kind == "Form" {
                    "Set template to the path of the HTML page that asks for the entityID"
                } else {
                    "Set URL to the absolute address of the discovery service"
                }),
            )
            .at_element("SessionInitiator")
            .with_doc(page(kind))
        } else {
            CheckResult::pass(
                code,
                CAT,
                Severity::Error,
                &format!("{kind} SessionInitiator{id} sets {attr}"),
            )
            .at_element("SessionInitiator")
        });

        // XML-065: a discovery handler that already knows the entityID ignores the request.
        if init.entity_id.is_some() {
            results.push(
                CheckResult::fail(
                    "XML-065",
                    CAT,
                    Severity::Warning,
                    &format!("{kind} SessionInitiator{id} sets entityID, so the handler ignores requests"),
                    Some("Remove entityID from a discovery initiator, or use a SAML2 initiator if the IdP is fixed"),
                )
                .at_element("SessionInitiator")
                .with_doc(page(kind)),
            );
        } else {
            results.push(
                CheckResult::pass(
                    "XML-065",
                    CAT,
                    Severity::Warning,
                    &format!("{kind} SessionInitiator{id} leaves the entityID to the user"),
                )
                .at_element("SessionInitiator"),
            );
        }
    }
}

/// OPS-084 (`acsByIndex`) and OPS-085 (`exportAssertion` prerequisites).
pub(super) fn operational(config: &DiscoveredConfig, results: &mut Vec<CheckResult>) {
    let Some(sc) = config.shibboleth_config.as_ref() else {
        return;
    };
    const CAT: CheckCategory = CheckCategory::Operational;

    for name in &sc.acs_by_index {
        let element = if name == "SSO" {
            "SSO"
        } else {
            "SessionInitiator"
        };
        results.push(
            CheckResult::fail(
                "OPS-084",
                CAT,
                Severity::Info,
                &format!("<{name}> sets acsByIndex=\"true\""),
                Some("Remove acsByIndex. Local configuration and metadata rarely agree on the index, so the docs call it not advisable"),
            )
            .at_element(element)
            .with_doc(DOC_SAML2_INITIATOR),
        );
    }

    // Assertions are cached by default only on the 2.0 namespace.
    let caching = match sc
        .session_cache
        .as_ref()
        .and_then(|c| c.cache_assertions.as_deref())
    {
        Some(v) => v.trim() == "true",
        None => sc.sp_version == SpVersion::V2,
    };
    for setting in &sc.request_map_content_settings {
        if setting.export_assertion.as_deref().map(str::trim) != Some("true") {
            continue;
        }
        let sessions = sc.sessions.as_ref();
        let mut missing = Vec::new();
        if sessions.is_none_or(|s| s.export_location.is_none()) {
            missing.push("exportLocation on <Sessions>");
        }
        if sessions.is_none_or(|s| s.export_acl.is_none()) {
            missing.push("exportACL on <Sessions>");
        }
        if !caching {
            missing.push("cacheAssertions=\"true\" on <SessionCache>");
        }
        let place = setting.name.as_deref().unwrap_or("(unnamed)");
        let element = host_or_path(&setting.element);
        results.push(if missing.is_empty() {
            CheckResult::pass(
                "OPS-085",
                CAT,
                Severity::Warning,
                &format!("{element} '{place}' exportAssertion has the settings it needs"),
            )
            .at_element(element)
        } else {
            CheckResult::fail(
                "OPS-085",
                CAT,
                Severity::Warning,
                &format!(
                    "{element} '{place}' sets exportAssertion=\"true\" but is missing {}",
                    missing.join(", ")
                ),
                Some("Assertion export needs exportLocation and exportACL on Sessions, and an enabled cacheAssertions on SessionCache"),
            )
            .at_element(element)
            .with_doc(DOC_ASSERTION_EXPORT)
        });
    }
}

#[cfg(test)]
mod tests {
    use crate::checks::{operational, xml_validity};
    use crate::testutil::{assert_absent, assert_outcome, config_from_xml};

    fn config(sessions_attrs: &str, cache: &str, path_attrs: &str, sso_attrs: &str) -> String {
        format!(
            r#"<SPConfig xmlns="urn:mace:shibboleth:3.0:native:sp:config">{cache}
<ApplicationDefaults entityID="https://sp.example.org/shibboleth"><Sessions {sessions_attrs}><SSO entityID="https://idp.example.org/idp" {sso_attrs}>SAML2</SSO></Sessions></ApplicationDefaults>
<RequestMapper type="Native"><RequestMap><Host name="a.example.org"><Path name="x" {path_attrs}/></Host></RequestMap></RequestMapper></SPConfig>"#
        )
    }

    #[test]
    fn redirect_to_ssl_must_be_a_port() {
        let run = |v: &str| {
            let (_d, c) = config_from_xml(&config("", "", &format!(r#"redirectToSSL="{v}""#), ""));
            xml_validity::run(&c)
        };
        assert_outcome(&run("443"), "XML-062", true);
        assert_outcome(&run("0"), "XML-062", false);
        assert_outcome(&run("70000"), "XML-062", false);
        assert_outcome(&run("true"), "XML-062", false);
        let (_d, c) = config_from_xml(&config("", "", "", ""));
        assert_absent(&xml_validity::run(&c), "XML-062");
    }

    #[test]
    fn acs_by_index_is_flagged() {
        let (_d, c) = config_from_xml(&config("", "", "", r#"acsByIndex="true""#));
        assert_outcome(&operational::run(&c), "OPS-084", false);
        let (_d, c) = config_from_xml(&config("", "", "", r#"acsByIndex="false""#));
        assert_absent(&operational::run(&c), "OPS-084");
    }

    #[test]
    fn export_assertion_needs_its_prerequisites() {
        let export = r#"exportAssertion="true""#;
        let all = r#"exportLocation="/export" exportACL="127.0.0.1""#;
        let cache = r#"<SessionCache cacheAssertions="true"/>"#;
        let run = |s: &str, c: &str| {
            let (_d, cfg) = config_from_xml(&config(s, c, export, ""));
            operational::run(&cfg)
        };
        assert_outcome(&run(all, cache), "OPS-085", true);
        assert_outcome(&run(all, ""), "OPS-085", false);
        assert_outcome(&run("", cache), "OPS-085", false);
        assert_outcome(&run(r#"exportLocation="/export""#, cache), "OPS-085", false);
        let (_d, cfg) = config_from_xml(&config("", "", r#"exportAssertion="false""#, ""));
        assert_absent(&operational::run(&cfg), "OPS-085");
    }

    #[test]
    fn discovery_initiators_need_their_attributes() {
        let run = |attrs: &str| {
            let xml = format!(
                r#"<SPConfig xmlns="urn:mace:shibboleth:3.0:native:sp:config"><ApplicationDefaults entityID="https://sp.example.org/shibboleth"><Sessions><SessionInitiator {attrs}/></Sessions></ApplicationDefaults></SPConfig>"#
            );
            let (_d, c) = config_from_xml(&xml);
            xml_validity::run(&c)
        };
        assert_outcome(&run(r#"type="SAMLDS" Location="/DS""#), "XML-063", false);
        assert_outcome(
            &run(r#"type="SAMLDS" Location="/DS" URL="https://ds.example.org/""#),
            "XML-063",
            true,
        );
        assert_outcome(&run(r#"type="WAYF" Location="/W""#), "XML-063", false);
        assert_outcome(&run(r#"type="Form" Location="/F""#), "XML-064", false);
        assert_outcome(
            &run(r#"type="Form" Location="/F" template="form.html""#),
            "XML-064",
            true,
        );
        assert_outcome(
            &run(
                r#"type="SAMLDS" URL="https://ds.example.org/" entityID="https://idp.example.org/idp""#,
            ),
            "XML-065",
            false,
        );
        assert_outcome(
            &run(r#"type="SAMLDS" URL="https://ds.example.org/""#),
            "XML-065",
            true,
        );
        let saml2 = run(r#"type="SAML2" entityID="https://idp.example.org/idp""#);
        assert_absent(&saml2, "XML-063");
        assert_absent(&saml2, "XML-065");
    }
}
