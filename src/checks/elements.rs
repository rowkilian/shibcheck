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
const DOC_DYNAMIC: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2060616138/DynamicMetadataProvider";
const DOC_REMOTE_DYNAMIC: &str = "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2067399842/MetadataProviderRemoteDynamicCommonAttributes";
const DOC_METADATA_EXTRACTOR: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334447/MetadataAttributeExtractor";
const DOC_NETWORK_CHILDREN: &str = "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2067399851/MetadataProviderNetworkChildElements";
const DOC_ENTITY_ROLE: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2063696218/EntityRoleMetadataFilter";
const DOC_UIINFO: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2107539866/UIInfoMetadataFilter";
const DOC_SSO: &str = "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334348/SSO";
const DOC_LOGOUT: &str = "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334353/Logout";
const DOC_OUT_OF_PROCESS: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334599/OutOfProcess";
const DOC_ODBC: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334638/ODBCStorageService";
const DOC_MEMCACHE: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334640/MemcacheStorageService";
const DOC_GSSAPI: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334451/GSSAPIAttributeExtractor";
const DOC_ADFS: &str = "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065335656/ADFS";
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

    // XML-076: Sessions comes before Errors.
    if sc.errors_before_sessions {
        results.push(
            CheckResult::fail(
                "XML-076",
                CAT,
                Severity::Error,
                "<Errors> comes before <Sessions> in ApplicationDefaults",
                Some("Move <Sessions> above <Errors>; the schema fixes the order of these two"),
            )
            .at_element("Errors")
            .with_doc(DOC_DEFAULTS),
        );
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

/// XML-072 and XML-073: dynamic metadata provider settings.
pub(super) fn metadata_providers(config: &DiscoveredConfig, results: &mut Vec<CheckResult>) {
    let Some(sc) = config.shibboleth_config.as_ref() else {
        return;
    };

    // XML-072: a Dynamic provider names its URL rule with exactly one Subst or Regex.
    for mp in sc
        .metadata_providers
        .iter()
        .filter(|mp| mp.provider_type == "Dynamic")
    {
        if mp.transform_children != 1 {
            results.push(
                CheckResult::fail(
                    "XML-072",
                    CAT,
                    Severity::Error,
                    &format!(
                        "Dynamic MetadataProvider has {} <Subst> or <Regex> children, it needs exactly one",
                        mp.transform_children
                    ),
                    Some("Add one <Subst> or <Regex> that turns the entityID into the metadata URL, and remove any extra"),
                )
                .at_element("MetadataProvider")
                .with_doc(DOC_DYNAMIC),
            );
        }
    }

    // XML-074: an on-demand provider verifies the server certificate with a TrustEngine,
    // or says explicitly that it won't.
    for mp in sc
        .metadata_providers
        .iter()
        .filter(|mp| matches!(mp.provider_type.as_str(), "MDQ" | "Dynamic"))
    {
        if !mp.has_trust_engine && mp.ignore_transport.as_deref() != Some("true") {
            results.push(
                CheckResult::fail(
                    "XML-074",
                    CAT,
                    Severity::Error,
                    &format!(
                        "{} MetadataProvider{} has no <TrustEngine> and ignoreTransport is not true; the SP reports a configuration error",
                        mp.provider_type,
                        mp.label()
                    ),
                    Some("Add a <TrustEngine> (such as StaticPKIX with the CA certificate) to verify the metadata server's TLS certificate"),
                )
                .at_element("MetadataProvider")
                .with_doc(DOC_NETWORK_CHILDREN),
            );
        }
    }

    // XML-075: filters whose child elements the docs mark "one or more".
    for filter in sc.metadata_providers.iter().flat_map(|mp| &mp.filters) {
        let (child, doc) = match filter.filter_type.as_str() {
            "EntityRole" | "EntityRoleWhiteList" => ("RetainedRole", DOC_ENTITY_ROLE),
            "UIInfo" => ("Entity", DOC_UIINFO),
            _ => continue,
        };
        if !filter.child_names.iter().any(|n| n == child) {
            results.push(
                CheckResult::fail(
                    "XML-075",
                    CAT,
                    Severity::Error,
                    &format!(
                        "MetadataFilter type=\"{}\" has no <{child}> child",
                        filter.filter_type
                    ),
                    Some(if child == "RetainedRole" {
                        "List the roles to keep, such as <RetainedRole>md:IDPSSODescriptor</RetainedRole>"
                    } else {
                        "Add an <Entity> with the entityID that each <mdui:UIInfo> applies to"
                    }),
                )
                .at_element("MetadataFilter")
                .with_doc(doc),
            );
        }
    }

    // XML-073: each remote dynamic provider caches in its own directory.
    let mut seen: Vec<(&str, &str)> = Vec::new();
    for mp in &sc.metadata_providers {
        let Some(dir) = mp.cache_directory.as_deref() else {
            continue;
        };
        let key = dir.trim().trim_end_matches('/');
        if let Some((_, first)) = seen.iter().find(|(k, _)| *k == key) {
            results.push(
                CheckResult::fail(
                    "XML-073",
                    CAT,
                    Severity::Warning,
                    &format!(
                        "cacheDirectory \"{dir}\" is shared by several metadata providers ({first} and {})",
                        mp.provider_type
                    ),
                    Some("Give each metadata provider its own cacheDirectory"),
                )
                .at_element("MetadataProvider")
                .with_doc(DOC_REMOTE_DYNAMIC),
            );
        } else {
            seen.push((key, mp.provider_type.as_str()));
        }
    }
}

/// REF-044: plugins that live in an extension library need a matching `<Library>`.
pub(super) fn references(config: &DiscoveredConfig, results: &mut Vec<CheckResult>) {
    let Some(sc) = config.shibboleth_config.as_ref() else {
        return;
    };
    // (what is used, the library file stem, the process it must load into, doc)
    let mut needs: Vec<(String, &str, &str, &str)> = Vec::new();
    for kind in &sc.storage_service_types {
        match kind.as_str() {
            "ODBC" => needs.push((
                "StorageService type=\"ODBC\"".into(),
                "odbc-store",
                "OutOfProcess",
                DOC_ODBC,
            )),
            "MEMCACHE" => needs.push((
                "StorageService type=\"MEMCACHE\"".into(),
                "memcache-store",
                "OutOfProcess",
                DOC_MEMCACHE,
            )),
            _ => {}
        }
    }
    if sc.attribute_extractor_types.iter().any(|t| t == "GSSAPI") {
        needs.push((
            "AttributeExtractor type=\"GSSAPI\"".into(),
            "plugins",
            "OutOfProcess",
            DOC_GSSAPI,
        ));
    }
    if sc.uses_adfs {
        needs.push(("ADFS".into(), "adfs", "OutOfProcess", DOC_ADFS));
        needs.push(("ADFS".into(), "adfs-lite", "InProcess", DOC_ADFS));
    }
    for (used, stem, scope, doc) in needs {
        let loaded = sc.libraries.iter().any(|lib| {
            let file = lib.path.rsplit(['/', '\\']).next().unwrap_or(&lib.path);
            let file_stem = file.split('.').next().unwrap_or(file);
            file_stem == stem && (lib.scope == scope || lib.scope == "SPConfig")
        });
        let msg = format!("{used} needs the {stem} extension library loaded in <{scope}>");
        results.push(if loaded {
            CheckResult::pass("REF-044", CheckCategory::CrossReferences, Severity::Error, &msg)
        } else {
            CheckResult::fail(
                "REF-044",
                CheckCategory::CrossReferences,
                Severity::Error,
                &msg,
                Some("Add <Extensions><Library path=\"<stem>.so\" fatal=\"true\"/></Extensions> inside that element (a .dll on Windows)"),
            )
            .with_doc(doc)
        });
    }
}

/// OPS-086: the Metadata and KeyDescriptor extractors only run when
/// `metadataAttributePrefix` is set. OPS-087: explicit initiators at the shorthand
/// locations. OPS-088: the transaction log format.
pub(super) fn operational(config: &DiscoveredConfig, results: &mut Vec<CheckResult>) {
    let Some(sc) = config.shibboleth_config.as_ref() else {
        return;
    };
    const OPS: CheckCategory = CheckCategory::Operational;

    if let Some(sessions) = sc.sessions.as_ref() {
        let login_clash = sessions.has_sso
            && sc
                .session_initiators
                .iter()
                .any(|i| i.location.as_deref().map(str::trim) == Some("/Login"));
        if login_clash {
            results.push(
                CheckResult::fail(
                    "OPS-087",
                    OPS,
                    Severity::Warning,
                    "An explicit <SessionInitiator> sits at /Login, the location the <SSO> shorthand already uses",
                    Some("Give the explicit initiator another Location, or remove the <SSO> element and configure the chain yourself"),
                )
                .at_element("SessionInitiator")
                .with_doc(DOC_SSO),
            );
        }
        let logout_clash = sessions.has_logout_shorthand
            && sc
                .logout_initiators
                .iter()
                .any(|i| i.location.as_deref().map(str::trim) == Some("/Logout"));
        if logout_clash {
            results.push(
                CheckResult::fail(
                    "OPS-087",
                    OPS,
                    Severity::Warning,
                    "An explicit <LogoutInitiator> sits at /Logout, the location the <Logout> shorthand already uses",
                    Some("Give the explicit initiator another Location, or remove the <Logout> element and configure the chain yourself"),
                )
                .at_element("LogoutInitiator")
                .with_doc(DOC_LOGOUT),
            );
        }
    }

    if sc.has_out_of_process {
        results.push(if sc.out_of_process_tran_log_format.is_some() {
            CheckResult::pass(
                "OPS-088",
                OPS,
                Severity::Info,
                "OutOfProcess sets tranLogFormat",
            )
        } else {
            CheckResult::fail(
                "OPS-088",
                OPS,
                Severity::Info,
                "OutOfProcess has no tranLogFormat, so the transaction log uses the old multi-line V2 format",
                Some("Set tranLogFormat to a single-line format that your log tooling can parse; the Logging page lists the fields"),
            )
            .at_element("OutOfProcess")
            .with_doc(DOC_OUT_OF_PROCESS)
        });
    }

    if sc.metadata_attribute_prefix_set {
        return;
    }
    for kind in sc
        .attribute_extractor_types
        .iter()
        .filter(|t| matches!(t.as_str(), "Metadata" | "KeyDescriptor"))
    {
        results.push(
            CheckResult::fail(
                "OPS-086",
                CheckCategory::Operational,
                Severity::Warning,
                &format!("AttributeExtractor type=\"{kind}\" never runs without metadataAttributePrefix"),
                Some("Set metadataAttributePrefix on <ApplicationDefaults> (for example \"Meta-\"), or remove the extractor"),
            )
            .at_element("AttributeExtractor")
            .with_doc(if kind == "Metadata" {
                DOC_METADATA_EXTRACTOR
            } else {
                DOC_KEY_DESCRIPTOR
            }),
        );
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
    fn dynamic_provider_needs_one_transform() {
        let mp =
            |inner: &str| format!(r#"<MetadataProvider type="Dynamic">{inner}</MetadataProvider>"#);
        assert_outcome(&run("", &mp("")), "XML-072", false);
        assert_outcome(
            &run(
                "",
                &mp("<Subst>https://mdq.example.org/$entityID</Subst><Regex match=\"a\">b</Regex>"),
            ),
            "XML-072",
            false,
        );
        assert_absent(
            &run("", &mp("<Subst>https://mdq.example.org/$entityID</Subst>")),
            "XML-072",
        );
        assert_absent(
            &run(
                "",
                r#"<MetadataProvider type="XML" url="https://x.example.org/m.xml"/>"#,
            ),
            "XML-072",
        );
    }

    #[test]
    fn cache_directory_is_not_shared() {
        let mp = |dir: &str| {
            format!(
                r#"<MetadataProvider type="MDQ" baseUrl="https://mdq.example.org/" cacheDirectory="{dir}"/>"#
            )
        };
        assert_outcome(
            &run("", &format!("{}{}", mp("mdq"), mp("mdq/"))),
            "XML-073",
            false,
        );
        assert_absent(&run("", &format!("{}{}", mp("a"), mp("b"))), "XML-073");
        assert_absent(&run("", &mp("a")), "XML-073");
    }

    #[test]
    fn metadata_extractors_need_a_prefix() {
        use crate::checks::operational;
        let run = |defaults: &str, ext: &str| {
            let (_dir, c) = config_from_xml(&sp3_app(defaults, ext));
            operational::run(&c)
        };
        let ext = r#"<AttributeExtractor type="Metadata" path="m.xml"/>"#;
        assert_outcome(&run("", ext), "OPS-086", false);
        assert_absent(&run(r#"metadataAttributePrefix="Meta-""#, ext), "OPS-086");
        assert_absent(
            &run("", r#"<AttributeExtractor type="XML" path="a.xml"/>"#),
            "OPS-086",
        );
    }

    #[test]
    fn on_demand_providers_need_a_trust_engine() {
        let mp = |attrs: &str, inner: &str| {
            format!(
                r#"<MetadataProvider type="MDQ" baseUrl="https://mdq.example.org/" {attrs}>{inner}</MetadataProvider>"#
            )
        };
        assert_outcome(&run("", &mp("", "")), "XML-074", false);
        assert_absent(&run("", &mp(r#"ignoreTransport="true""#, "")), "XML-074");
        assert_absent(
            &run(
                "",
                &mp(
                    "",
                    r#"<TrustEngine type="StaticPKIX" certificate="ca.pem"/>"#,
                ),
            ),
            "XML-074",
        );
        // A TrustEngine inside a filter does not count for the provider.
        assert_outcome(
            &run(
                "",
                &mp(
                    "",
                    r#"<MetadataFilter type="Signature"><TrustEngine type="ExplicitKey"/></MetadataFilter>"#,
                ),
            ),
            "XML-074",
            false,
        );
        assert_absent(
            &run(
                "",
                r#"<MetadataProvider type="XML" url="https://x.example.org/m.xml"/>"#,
            ),
            "XML-074",
        );
    }

    #[test]
    fn filters_need_their_children() {
        let mp = |filter: &str| {
            format!(r#"<MetadataProvider type="XML" path="m.xml">{filter}</MetadataProvider>"#)
        };
        assert_outcome(
            &run("", &mp(r#"<MetadataFilter type="EntityRole"/>"#)),
            "XML-075",
            false,
        );
        assert_absent(
            &run(
                "",
                &mp(
                    r#"<MetadataFilter type="EntityRole"><RetainedRole>md:IDPSSODescriptor</RetainedRole></MetadataFilter>"#,
                ),
            ),
            "XML-075",
        );
        assert_outcome(
            &run(
                "",
                &mp(r#"<MetadataFilter type="UIInfo"><mdui:UIInfo/></MetadataFilter>"#),
            ),
            "XML-075",
            false,
        );
        assert_absent(
            &run(
                "",
                &mp(
                    r#"<MetadataFilter type="UIInfo"><mdui:UIInfo/><Entity>https://idp.example.org/idp</Entity></MetadataFilter>"#,
                ),
            ),
            "XML-075",
        );
    }

    #[test]
    fn sessions_come_before_errors() {
        assert_outcome(&run("", "<Errors/><Sessions/>"), "XML-076", false);
        assert_absent(&run("", "<Sessions/><Errors/>"), "XML-076");
        assert_absent(
            &run(
                "",
                r#"<Sessions/><ApplicationOverride id="a"><Errors/></ApplicationOverride>"#,
            ),
            "XML-076",
        );
    }

    fn sp_config(top: &str, body: &str) -> Vec<crate::result::CheckResult> {
        let xml = format!(
            r#"<SPConfig xmlns="urn:mace:shibboleth:3.0:native:sp:config">{top}
<ApplicationDefaults entityID="https://sp.example.org/shibboleth">{body}</ApplicationDefaults></SPConfig>"#
        );
        let (_dir, c) = config_from_xml(&xml);
        crate::checks::cross_references::run(&c, false)
    }

    #[test]
    fn extension_plugins_need_their_library() {
        let odbc = r#"<StorageService type="ODBC" id="db"><ConnectionString>DSN=x</ConnectionString></StorageService>"#;
        assert_outcome(&sp_config(odbc, ""), "REF-044", false);
        let lib = r#"<OutOfProcess><Extensions><Library path="/usr/lib64/shibboleth/odbc-store.so" fatal="true"/></Extensions></OutOfProcess>"#;
        assert_outcome(&sp_config(&format!("{lib}{odbc}"), ""), "REF-044", true);
        // The library must load into shibd, not the web server.
        let wrong =
            r#"<InProcess><Extensions><Library path="odbc-store.so"/></Extensions></InProcess>"#;
        assert_outcome(&sp_config(&format!("{wrong}{odbc}"), ""), "REF-044", false);

        let adfs =
            r#"<Sessions><SSO entityID="https://idp.example.org/idp">SAML2 ADFS</SSO></Sessions>"#;
        let results = sp_config("", adfs);
        assert_eq!(crate::testutil::with_code(&results, "REF-044").len(), 2);
        let both = r#"<OutOfProcess><Extensions><Library path="adfs.so"/></Extensions></OutOfProcess><InProcess><Extensions><Library path="adfs-lite.so"/></Extensions></InProcess>"#;
        let results = sp_config(both, adfs);
        assert!(crate::testutil::with_code(&results, "REF-044")
            .iter()
            .all(|r| r.passed));

        assert_absent(
            &sp_config("", r#"<Sessions><SSO>SAML2</SSO></Sessions>"#),
            "REF-044",
        );
    }

    #[test]
    fn explicit_initiators_avoid_the_shorthand_locations() {
        use crate::checks::operational;
        let run = |sessions: &str| {
            let (_dir, c) =
                config_from_xml(&sp3_app("", &format!("<Sessions>{sessions}</Sessions>")));
            operational::run(&c)
        };
        assert_outcome(
            &run(r#"<SSO>SAML2</SSO><SessionInitiator type="SAML2" Location="/Login"/>"#),
            "OPS-087",
            false,
        );
        assert_absent(
            &run(r#"<SSO>SAML2</SSO><SessionInitiator type="SAML2" Location="/Login2"/>"#),
            "OPS-087",
        );
        assert_absent(
            &run(r#"<SessionInitiator type="SAML2" Location="/Login"/>"#),
            "OPS-087",
        );
        assert_outcome(
            &run(r#"<Logout>SAML2</Logout><LogoutInitiator type="SAML2" Location="/Logout"/>"#),
            "OPS-087",
            false,
        );
        assert_absent(
            &run(r#"<LogoutInitiator type="SAML2" Location="/Logout"/>"#),
            "OPS-087",
        );
    }

    #[test]
    fn transaction_log_format() {
        use crate::checks::operational;
        let run = |top: &str| {
            let xml = format!(
                r#"<SPConfig xmlns="urn:mace:shibboleth:3.0:native:sp:config">{top}<ApplicationDefaults entityID="https://sp.example.org/shibboleth"/></SPConfig>"#
            );
            let (_dir, c) = config_from_xml(&xml);
            operational::run(&c)
        };
        assert_outcome(&run("<OutOfProcess/>"), "OPS-088", false);
        assert_outcome(
            &run(
                r#"<OutOfProcess tranLogFormat="%u|%s|%IDP|%i|%ac|%t|%attr|%n|%b|%E|%S|%SS|%L|%UA|%a"/>"#,
            ),
            "OPS-088",
            true,
        );
        assert_absent(&run(""), "OPS-088");
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
