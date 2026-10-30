//! Checks on element structure that the docs state as rules: how often an element may
//! appear, which attributes a plugin requires, and which values a setting takes.

use crate::config::DiscoveredConfig;
use crate::parsers::shibboleth_xml::{DEFAULTS_SINGLETONS, SPCONFIG_SINGLETONS};
use crate::result::{CheckCategory, CheckResult, Severity};

const CAT: CheckCategory = CheckCategory::XmlValidity;
const DOC_SPCONFIG: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2063695926/SPConfig";
const DOC_DEFAULTS: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2063695997/ApplicationDefaults";
const DOC_CHAINING: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334780/Chaining+SessionInitiator";
const DOC_ATTRIBUTE_CHECKER: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334881/Attribute+Checker+Handler";
const DOC_KEY_DESCRIPTOR: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334438/KeyDescriptorAttributeExtractor";
const DOC_PKIX: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065335188/PKIX+and+StaticPKIX+TrustEngines";

/// XML-066 to XML-071.
pub(super) fn structure(config: &DiscoveredConfig, results: &mut Vec<CheckResult>) {
    let Some(sc) = config.shibboleth_config.as_ref() else {
        return;
    };

    // XML-066: an ApplicationDefaults id, when present, is the string "default".
    if let Some(id) = sc.application_defaults_id.as_deref() {
        if id != "default" {
            results.push(
                CheckResult::fail(
                    "XML-066",
                    CAT,
                    Severity::Error,
                    &format!("ApplicationDefaults id=\"{id}\" must be \"default\""),
                    Some("Remove the id attribute, or set it to \"default\". Name other applications with <ApplicationOverride id>"),
                )
                .at_element("ApplicationDefaults")
                .with_doc(DOC_DEFAULTS),
            );
        }
    }

    // XML-067: elements the docs allow once.
    for (name, doc) in SPCONFIG_SINGLETONS
        .iter()
        .map(|n| (*n, DOC_SPCONFIG))
        .chain(DEFAULTS_SINGLETONS.iter().map(|n| (*n, DOC_DEFAULTS)))
    {
        let count = sc.singleton_counts.get(name).copied().unwrap_or(0);
        if count > 1 {
            results.push(
                CheckResult::fail(
                    "XML-067",
                    CAT,
                    Severity::Warning,
                    &format!("<{name}> appears {count} times, the docs allow at most one"),
                    Some("Merge the copies into one element, or remove the extras"),
                )
                .at_element(name)
                .with_doc(doc),
            );
        }
    }

    // XML-068: a Chaining initiator wraps one or more initiators.
    for init in &sc.session_initiators {
        if init.initiator_type.as_deref() == Some("Chaining") && init.children == 0 {
            results.push(
                CheckResult::fail(
                    "XML-068",
                    CAT,
                    Severity::Error,
                    "Chaining SessionInitiator has no child SessionInitiator",
                    Some("Add the initiators to run in order, or remove the Chaining initiator"),
                )
                .at_element("SessionInitiator")
                .with_doc(DOC_CHAINING),
            );
        }
    }

    // XML-069: AttributeChecker shows a template when the check fails.
    for handler in sc
        .handlers
        .iter()
        .filter(|h| h.handler_type == "AttributeChecker")
    {
        if handler.template.is_none() {
            results.push(
                CheckResult::fail(
                    "XML-069",
                    CAT,
                    Severity::Error,
                    "AttributeChecker handler has no template",
                    Some("Set template to the error page shown when the session lacks the required attributes"),
                )
                .at_element("Handler")
                .with_doc(DOC_ATTRIBUTE_CHECKER),
            );
        }
    }

    // XML-070: a KeyDescriptor extractor needs a name to put the keys under.
    if sc.key_descriptor_extractors_without_ids > 0 {
        results.push(
            CheckResult::fail(
                "XML-070",
                CAT,
                Severity::Error,
                "AttributeExtractor type=\"KeyDescriptor\" sets none of signingId, encryptionId or hashId",
                Some("Set at least one of signingId, encryptionId or hashId to the attribute name for the keys"),
            )
            .at_element("AttributeExtractor")
            .with_doc(DOC_KEY_DESCRIPTOR),
        );
    }

    // XML-071: checkRevocation takes one of three values.
    for (kind, value) in &sc.trust_engine_revocation {
        let ok = matches!(value.as_str(), "off" | "entityOnly" | "fullChain");
        if !ok {
            let kind = if kind.is_empty() { "TrustEngine" } else { kind };
            results.push(
                CheckResult::fail(
                    "XML-071",
                    CAT,
                    Severity::Error,
                    &format!("{kind} trust engine has checkRevocation=\"{value}\""),
                    Some("Use off, entityOnly or fullChain"),
                )
                .at_element("TrustEngine")
                .with_doc(DOC_PKIX),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::checks::xml_validity;
    use crate::testutil::{assert_absent, assert_outcome, config_from_xml, sp3_app};

    fn run(defaults: &str, body: &str) -> Vec<crate::result::CheckResult> {
        let (_dir, c) = config_from_xml(&sp3_app(defaults, body));
        xml_validity::run(&c)
    }

    #[test]
    fn application_defaults_id_must_be_default() {
        assert_outcome(&run(r#"id="other""#, ""), "XML-066", false);
        assert_absent(&run(r#"id="default""#, ""), "XML-066");
        assert_absent(&run("", ""), "XML-066");
    }

    #[test]
    fn repeated_singletons_are_flagged() {
        let doubled = r#"<Sessions/><Sessions/><Errors/>"#;
        let results = run("", doubled);
        assert_outcome(&results, "XML-067", false);
        assert_eq!(crate::testutil::with_code(&results, "XML-067").len(), 1);
        assert_absent(&run("", "<Sessions/><Errors/>"), "XML-067");

        let (_dir, c) = config_from_xml(
            r#"<SPConfig xmlns="urn:mace:shibboleth:3.0:native:sp:config">
<OutOfProcess/><OutOfProcess/><SessionCache/><SessionCache/>
<ApplicationDefaults entityID="https://sp.example.org/shibboleth"><Sessions/>
<ApplicationOverride id="a"><Sessions/></ApplicationOverride></ApplicationDefaults></SPConfig>"#,
        );
        let results = xml_validity::run(&c);
        assert_eq!(crate::testutil::with_code(&results, "XML-067").len(), 2);
    }

    #[test]
    fn chaining_initiator_needs_children() {
        let sessions = |inner: &str| {
            format!(
                r#"<Sessions><SessionInitiator type="Chaining" Location="/Login">{inner}</SessionInitiator></Sessions>"#
            )
        };
        assert_outcome(&run("", &sessions("")), "XML-068", false);
        assert_outcome(&run("", &sessions("\n  ")), "XML-068", false);
        assert_absent(
            &run("", &sessions(r#"<SessionInitiator type="SAML2"/>"#)),
            "XML-068",
        );
        // An initiator after a nested chain still counts for the outer one.
        let nested = sessions(
            r#"<SessionInitiator type="Chaining"><SessionInitiator type="SAML2"/></SessionInitiator><SessionInitiator type="Form" template="f.html"/>"#,
        );
        assert_absent(&run("", &nested), "XML-068");
    }

    #[test]
    fn attribute_checker_needs_a_template() {
        let sessions = |attrs: &str| {
            format!(
                r#"<Sessions><Handler type="AttributeChecker" Location="/AC" {attrs}/></Sessions>"#
            )
        };
        assert_outcome(&run("", &sessions("")), "XML-069", false);
        assert_absent(&run("", &sessions(r#"template="missing.html""#)), "XML-069");
    }

    #[test]
    fn key_descriptor_extractor_needs_an_id() {
        let ext = |attrs: &str| format!(r#"<AttributeExtractor type="KeyDescriptor" {attrs}/>"#);
        assert_outcome(&run("", &ext("")), "XML-070", false);
        assert_absent(&run("", &ext(r#"signingId="idp-key""#)), "XML-070");
        assert_absent(&run("", &ext(r#"hashId="idp-hash""#)), "XML-070");
    }

    #[test]
    fn check_revocation_values() {
        let te = |v: &str| format!(r#"<TrustEngine type="StaticPKIX" checkRevocation="{v}"/>"#);
        assert_outcome(&run("", &te("always")), "XML-071", false);
        assert_absent(&run("", &te("fullChain")), "XML-071");
        assert_absent(&run("", &te("entityOnly")), "XML-071");
        assert_absent(&run("", &te("off")), "XML-071");
    }
}
