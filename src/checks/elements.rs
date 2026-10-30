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
const DOC_LOGOUT_SAML2: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334796/SAML2+LogoutInitiator";
const DOC_INCLUDE: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2063696201/IncludeMetadataFilter";
const DOC_EXCLUDE: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2063696198/ExcludeMetadataFilter";
const DOC_POLICY: &str = "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334531/Policy";
const DOC_NOTIFY: &str = "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334394/Notify";
const DOC_ERRORS: &str = "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334361/Errors";
const DOC_SESSION_CACHE: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334650/SessionCache";
const DOC_ASSERTION_EXPORT: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065335032/AssertionExport";
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
    if sc.errors_before_sessions && sc.singleton_counts.get("Sessions").copied().unwrap_or(0) > 0 {
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
            let msg = if name == "Listener" {
                format!("<Listener>, <UnixListener> and <TCPListener> appear {count} times in total, the docs allow one listener")
            } else {
                format!("<{name}> appears {count} times, the docs allow at most one")
            };
            results.push(
                CheckResult::fail(
                    "XML-067",
                    CAT,
                    Severity::Warning,
                    &msg,
                    Some("Merge the copies into one element, or remove the extras"),
                )
                .at_element(name)
                .with_doc(doc),
            );
        }
    }

    // XML-077: a logout handler only acts on sessions started with its own protocol.
    if let Some(sessions) = sc.sessions.as_ref() {
        if let (Some(sso), Some(logout)) = (
            sessions.sso_protocols.as_deref(),
            sessions.logout_protocols.as_deref(),
        ) {
            let sso: Vec<&str> = sso.split_whitespace().collect();
            for proto in logout
                .split_whitespace()
                .filter(|p| *p != "Local" && !sso.contains(p))
            {
                results.push(
                    CheckResult::fail(
                        "XML-077",
                        CAT,
                        Severity::Warning,
                        &format!("<Logout> lists {proto} but <SSO> does not, so that logout handler never has a matching session"),
                        Some("Remove the protocol from <Logout>, or add it to <SSO>"),
                    )
                    .at_element("Logout")
                    .with_doc(DOC_LOGOUT_SAML2),
                );
            }
        }
    }

    // XML-078: Include and Exclude filters need something to match.
    for filter in sc.metadata_providers.iter().flat_map(|mp| &mp.filters) {
        let (child, doc, severity, effect) = match filter.filter_type.as_str() {
            "Include" | "Whitelist" => (
                "Include",
                DOC_INCLUDE,
                Severity::Error,
                "it drops every entity",
            ),
            "Exclude" | "Blacklist" => {
                ("Exclude", DOC_EXCLUDE, Severity::Warning, "it does nothing")
            }
            _ => continue,
        };
        if filter.matcher.is_none() && filter.child_names.is_empty() {
            results.push(
                CheckResult::fail(
                    "XML-078",
                    CAT,
                    severity,
                    &format!(
                        "MetadataFilter type=\"{}\" has no <{child}> child and no matcher, so {effect}",
                        filter.filter_type
                    ),
                    Some("List the entityIDs or groups as child elements, or set matcher"),
                )
                .at_element("MetadataFilter")
                .with_doc(doc),
            );
        }
    }

    // XML-079: Policy ids are unique within security-policy.xml.
    if let Some(policy) = crate::parsers::security_policy::load_for(config) {
        let mut seen = std::collections::HashSet::new();
        let mut reported = std::collections::HashSet::new();
        for id in &policy.policy.policy_ids {
            if !seen.insert(id.as_str()) && reported.insert(id.as_str()) {
                results.push(
                    CheckResult::fail(
                        "XML-079",
                        CAT,
                        Severity::Error,
                        &format!(
                            "Policy id=\"{id}\" is defined more than once in {}",
                            policy.file_name
                        ),
                        Some(
                            "Give each <Policy> a unique id; policyId references name exactly one",
                        ),
                    )
                    .with_location(&policy.file_name, None)
                    .with_doc(DOC_POLICY),
                );
            }
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
                Severity::Warning,
                "AttributeExtractor type=\"KeyDescriptor\" sets none of signingId, encryptionId or hashId, so it extracts nothing",
                Some("Set at least one of signingId, encryptionId or hashId to the attribute name for the keys, or remove the extractor"),
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
        if !mp.has_trust_engine && mp.ignore_transport.as_deref().map(str::trim) != Some("true") {
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
                    Some("Add a <TrustEngine> (such as StaticPKIX with the CA certificate) to verify the metadata server's TLS certificate. ignoreTransport=\"true\" also clears this error, but then the metadata needs a Signature filter"),
                )
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
                        "cacheDirectory \"{dir}\" is shared by several metadata providers ({first} and {}{})",
                        mp.provider_type,
                        mp.label()
                    ),
                    Some("Give each metadata provider its own cacheDirectory"),
                )
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
        // Only the ApplicationDefaults <Sessions> is compared; an override has its own handlers.
        let login_clash = sessions.has_sso_shorthand
            && sc
                .session_initiators
                .iter()
                .any(|i| !i.in_override && i.location.as_deref().map(str::trim) == Some("/Login"));
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
                .any(|i| !i.in_override && i.location.as_deref().map(str::trim) == Some("/Logout"));
        if logout_clash {
            results.push(
                CheckResult::fail(
                    "OPS-087",
                    OPS,
                    Severity::Warning,
                    "An explicit <LogoutInitiator> and the <Logout> shorthand both install a handler at /Logout",
                    Some("Give the explicit initiator another Location, or remove the <Logout> element and configure the chain yourself"),
                )
                .at_element("LogoutInitiator")
                .with_doc(DOC_LOGOUT),
            );
        }
    }

    // OPS-089: Notify only runs during logout.
    if !sc.notify_elements.is_empty() && !sc.sessions.as_ref().is_some_and(|s| s.has_logout) {
        results.push(
            CheckResult::fail(
                "OPS-089",
                OPS,
                Severity::Info,
                "<Notify> is configured but no <Logout> or <LogoutInitiator> exists, so notifications never fire",
                Some("Add <Logout>SAML2 Local</Logout> to <Sessions>, or remove the <Notify> elements"),
            )
            .at_element("Notify")
            .with_doc(DOC_NOTIFY),
        );
    }

    // OPS-090: redirectErrors replaces every template except the access one.
    if let Some(errors) = sc.errors.as_ref() {
        if errors.redirect_errors.is_some() {
            let unused: Vec<&str> = [
                ("session", &errors.session_error),
                ("metadata", &errors.metadata_error),
                ("ssl", &errors.ssl_error),
            ]
            .iter()
            .filter(|(_, v)| v.is_some())
            .map(|(n, _)| *n)
            .collect();
            if !unused.is_empty() {
                results.push(
                    CheckResult::fail(
                        "OPS-090",
                        OPS,
                        Severity::Info,
                        &format!(
                            "Errors sets redirectErrors, so the {} template{} never shown",
                            unused.join(", "),
                            if unused.len() == 1 { " is" } else { "s are" }
                        ),
                        Some("Remove the unused templates, or drop redirectErrors to use them; only the access template still applies"),
                    )
                    .at_element("Errors")
                    .with_doc(DOC_ERRORS),
                );
            }
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

/// SEC-148 and SEC-149: session recovery against assertion access, and the export
/// location host.
pub(super) fn security(config: &DiscoveredConfig, results: &mut Vec<CheckResult>) {
    let Some(sc) = config.shibboleth_config.as_ref() else {
        return;
    };
    const SEC: CheckCategory = CheckCategory::Security;

    // SEC-148: a recovered session has no assertion, so the two features clash.
    let recovery = sc
        .session_cache
        .as_ref()
        .is_some_and(|c| c.persisted_attributes.is_some());
    if recovery {
        let caching = sc
            .session_cache
            .as_ref()
            .and_then(|c| c.cache_assertions.as_deref())
            .is_some_and(|v| v.trim() == "true");
        let exporting = sc
            .request_map_content_settings
            .iter()
            .any(|s| s.export_assertion.as_deref().map(str::trim) == Some("true"));
        if caching || exporting {
            let other = match (caching, exporting) {
                (true, true) => "cacheAssertions=\"true\" and exportAssertion=\"true\"",
                (true, false) => "cacheAssertions=\"true\"",
                _ => "exportAssertion=\"true\"",
            };
            results.push(
                CheckResult::fail(
                    "SEC-148",
                    SEC,
                    Severity::Warning,
                    &format!("SessionCache persistedAttributes is combined with {other}; a recovered session carries no assertion"),
                    Some("Pick one: session recovery across nodes, or access to the raw assertion"),
                )
                .at_element("SessionCache")
                .with_doc(DOC_SESSION_CACHE),
            );
        }
    }

    // SEC-149: assertion export is unauthenticated, so keep it on the loopback.
    if let Some(location) = sc
        .sessions
        .as_ref()
        .and_then(|s| s.export_location.as_deref())
    {
        if let Some(rest) = location
            .strip_prefix("https://")
            .or_else(|| location.strip_prefix("http://"))
        {
            let host = rest.split(['/', '?', '#']).next().unwrap_or("");
            let host = host.rsplit_once(':').map_or(host, |(h, _)| h);
            let host = host.trim_start_matches('[').trim_end_matches(']');
            if !matches!(host, "localhost" | "127.0.0.1" | "::1") {
                results.push(
                    CheckResult::fail(
                        "SEC-149",
                        SEC,
                        Severity::Warning,
                        &format!("exportLocation points at {host}; the docs say a non-localhost request is open to attack"),
                        Some("Use a relative exportLocation, or an absolute one on localhost, and keep exportACL to loopback addresses"),
                    )
                    .at_element("Sessions")
                    .with_doc(DOC_ASSERTION_EXPORT),
                );
            }
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
        // Without <Sessions> there is no order to break; XML-010 reports the missing element.
        assert_absent(
            &run("", r#"<Errors supportContact="root@example.org"/>"#),
            "XML-076",
        );
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
        let adfs_results = crate::testutil::with_code(&results, "REF-044");
        assert_eq!(adfs_results.len(), 2);
        assert!(adfs_results.iter().all(|r| r.passed));
        // type="ADFS" on an initiator also counts as using the plugin.
        let typed = r#"<Sessions><SessionInitiator type="ADFS" Location="/ADFS"/></Sessions>"#;
        assert_eq!(
            crate::testutil::with_code(&sp_config("", typed), "REF-044").len(),
            2
        );

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

        // An override's shorthand does not clash with the defaults' explicit initiators.
        let (_dir, c) = config_from_xml(&sp3_app(
            "",
            r#"<Sessions><SessionInitiator type="SAML2" Location="/Login"/><LogoutInitiator type="SAML2" Location="/Logout"/></Sessions>
<ApplicationOverride id="other"><Sessions><SSO entityID="https://idp2.example.org/idp">SAML2</SSO><Logout>SAML2 Local</Logout></Sessions></ApplicationOverride>"#,
        ));
        assert_absent(&operational::run(&c), "OPS-087");
        let (_dir, c) = config_from_xml(&sp3_app(
            "",
            r#"<Sessions><SSO>SAML2</SSO></Sessions>
<ApplicationOverride id="other"><Sessions><SessionInitiator type="SAML2" Location="/Login"/></Sessions></ApplicationOverride>"#,
        ));
        assert_absent(&operational::run(&c), "OPS-087");
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
    fn dynamic_provider_also_needs_a_trust_engine() {
        assert_outcome(
            &run(
                "",
                r#"<MetadataProvider type="Dynamic"><Subst>https://mdq.example.org/$entityID</Subst></MetadataProvider>"#,
            ),
            "XML-074",
            false,
        );
        assert_outcome(
            &run(
                "",
                r#"<MetadataProvider type="XML" path="m.xml"><MetadataFilter type="EntityRoleWhiteList"/></MetadataProvider>"#,
            ),
            "XML-075",
            false,
        );
    }

    #[test]
    fn stock_layout_raises_none_of_the_structure_checks() {
        let xml = r#"<SPConfig xmlns="urn:mace:shibboleth:3.0:native:sp:config">
<OutOfProcess tranLogFormat="%u|%s|%IDP"><Extensions><Library path="plugins.so" fatal="true"/></Extensions></OutOfProcess>
<InProcess checkSpoofing="true"><ISAPI/></InProcess>
<SessionCache type="StorageService"/>
<ApplicationDefaults entityID="https://sp.example.org/shibboleth" REMOTE_USER="eppn">
  <Sessions lifetime="28800" timeout="3600" handlerSSL="true" cookieProps="https">
    <SSO entityID="https://idp.example.org/idp">SAML2</SSO>
    <Logout>SAML2 Local</Logout>
    <Handler type="MetadataGenerator" Location="/Metadata"/>
    <Handler type="Status" Location="/Status" acl="127.0.0.1 ::1"/>
    <Handler type="Session" Location="/Session"/>
  </Sessions>
  <Errors supportContact="root@example.org" helpLocation="/about.html"/>
  <MetadataProvider type="XML" validate="true" url="https://md.example.org/m.xml" backingFilePath="m.xml" maxRefreshDelay="7200">
    <MetadataFilter type="RequireValidUntil" maxValidityInterval="2419200"/>
    <MetadataFilter type="Signature" certificate="fedsigner.pem" verifyBackup="false"/>
    <MetadataFilter type="EntityRole"><RetainedRole>md:IDPSSODescriptor</RetainedRole></MetadataFilter>
  </MetadataProvider>
  <AttributeExtractor type="XML" validate="true" reloadChanges="false" path="attribute-map.xml"/>
  <AttributeFilter type="XML" validate="true" path="attribute-policy.xml"/>
  <CredentialResolver type="File" use="signing" key="sp-signing-key.pem" certificate="sp-signing-cert.pem"/>
  <ApplicationOverride id="admin" entityID="https://admin.example.org/shibboleth">
    <Sessions lifetime="28800" timeout="3600" handlerSSL="true" cookieProps="https"><SSO entityID="https://idp2.example.org/idp">SAML2</SSO></Sessions>
  </ApplicationOverride>
</ApplicationDefaults>
<SecurityPolicyProvider type="XML" validate="true" path="security-policy.xml"/>
<ProtocolProvider type="XML" validate="true" reloadChanges="false" path="protocols.xml"/>
</SPConfig>"#;
        let (_dir, c) = config_from_xml(xml);
        let results: Vec<_> = xml_validity::run(&c)
            .into_iter()
            .chain(crate::checks::operational::run(&c))
            .chain(crate::checks::cross_references::run(&c, false))
            .collect();
        for code in [
            "XML-066", "XML-067", "XML-068", "XML-069", "XML-070", "XML-071", "XML-072", "XML-073",
            "XML-074", "XML-075", "XML-076", "REF-044", "OPS-087",
        ] {
            assert!(
                !results.iter().any(|r| r.code == code && !r.passed),
                "{code} fired on the stock layout"
            );
        }
    }

    #[test]
    fn logout_protocols_come_from_sso() {
        let sessions = |inner: &str| {
            let (_dir, c) = config_from_xml(&sp3_app("", &format!("<Sessions>{inner}</Sessions>")));
            xml_validity::run(&c)
        };
        assert_outcome(
            &sessions("<SSO>SAML2</SSO><Logout>SAML2 ADFS Local</Logout>"),
            "XML-077",
            false,
        );
        assert_absent(
            &sessions("<SSO>SAML2</SSO><Logout>SAML2 Local</Logout>"),
            "XML-077",
        );
        assert_absent(&sessions("<Logout>SAML2 Local</Logout>"), "XML-077");
    }

    #[test]
    fn include_and_exclude_filters_need_content() {
        let mp = |filter: &str| {
            format!(r#"<MetadataProvider type="XML" path="m.xml">{filter}</MetadataProvider>"#)
        };
        assert_outcome(
            &run("", &mp(r#"<MetadataFilter type="Include"/>"#)),
            "XML-078",
            false,
        );
        assert_outcome(
            &run("", &mp(r#"<MetadataFilter type="Blacklist"/>"#)),
            "XML-078",
            false,
        );
        assert_absent(
            &run(
                "",
                &mp(
                    r#"<MetadataFilter type="Include"><Include>https://idp.example.org/idp</Include></MetadataFilter>"#,
                ),
            ),
            "XML-078",
        );
        assert_absent(
            &run(
                "",
                &mp(
                    r#"<MetadataFilter type="Exclude" matcher="EntityAttributes" attributeName="x" attributeValue="y"/>"#,
                ),
            ),
            "XML-078",
        );
    }

    #[test]
    fn duplicate_policy_ids_are_reported() {
        let dir = crate::testutil::TestDir::new();
        dir.write("shibboleth2.xml", &sp3_app("", r#"<Sessions/>"#));
        dir.write(
            "security-policy.xml",
            r#"<SecurityPolicies xmlns="urn:mace:shibboleth:3.0:native:sp:config">
<Policy id="default"><PolicyRule type="MessageFlow"/></Policy>
<Policy id="default"><PolicyRule type="MessageFlow"/></Policy>
<Policy id="other"><PolicyRule type="MessageFlow"/></Policy></SecurityPolicies>"#,
        );
        let results = xml_validity::run(&dir.discover());
        assert_outcome(&results, "XML-079", false);
        assert_eq!(crate::testutil::with_code(&results, "XML-079").len(), 1);
    }

    #[test]
    fn listeners_share_one_slot() {
        let (_dir, c) = config_from_xml(
            r#"<SPConfig xmlns="urn:mace:shibboleth:3.0:native:sp:config"><UnixListener address="shibd.sock"/><TCPListener address="127.0.0.1" port="1600"/>
<ApplicationDefaults entityID="https://sp.example.org/shibboleth"><Sessions/></ApplicationDefaults></SPConfig>"#,
        );
        assert_outcome(&xml_validity::run(&c), "XML-067", false);
    }

    #[test]
    fn notify_needs_logout_and_redirect_errors_hides_templates() {
        use crate::checks::operational;
        let run = |body: &str| {
            let (_dir, c) = config_from_xml(&sp3_app("", body));
            operational::run(&c)
        };
        let notify = r#"<Notify Channel="back" Location="https://app.example.org/logout"/>"#;
        assert_outcome(
            &run(&format!("<Sessions><SSO>SAML2</SSO></Sessions>{notify}")),
            "OPS-089",
            false,
        );
        assert_absent(
            &run(&format!(
                "<Sessions><SSO>SAML2</SSO><Logout>SAML2 Local</Logout></Sessions>{notify}"
            )),
            "OPS-089",
        );

        assert_outcome(
            &run(
                r#"<Sessions/><Errors redirectErrors="https://sp.example.org/error" session="sessionError.html" ssl="sslError.html"/>"#,
            ),
            "OPS-090",
            false,
        );
        assert_absent(
            &run(
                r#"<Sessions/><Errors redirectErrors="https://sp.example.org/error" access="accessError.html"/>"#,
            ),
            "OPS-090",
        );
        assert_absent(
            &run(r#"<Sessions/><Errors session="sessionError.html"/>"#),
            "OPS-090",
        );
    }

    #[test]
    fn session_recovery_and_export_location() {
        use crate::checks::security;
        let run = |cache: &str, sessions_attrs: &str, path_attrs: &str| {
            let xml = format!(
                r#"<SPConfig xmlns="urn:mace:shibboleth:3.0:native:sp:config">{cache}
<ApplicationDefaults entityID="https://sp.example.org/shibboleth"><Sessions {sessions_attrs}><SSO>SAML2</SSO></Sessions></ApplicationDefaults>
<RequestMapper type="Native"><RequestMap><Host name="a.example.org"><Path name="x" {path_attrs}/></Host></RequestMap></RequestMapper></SPConfig>"#
            );
            let (_dir, c) = config_from_xml(&xml);
            security::run(&c)
        };
        let recovery = r#"<SessionCache type="StorageService" persistedAttributes="eppn"/>"#;
        assert_outcome(
            &run(
                r#"<SessionCache type="StorageService" persistedAttributes="eppn" cacheAssertions="true"/>"#,
                "",
                "",
            ),
            "SEC-148",
            false,
        );
        assert_outcome(
            &run(recovery, "", r#"exportAssertion="true""#),
            "SEC-148",
            false,
        );
        assert_absent(&run(recovery, "", ""), "SEC-148");
        assert_absent(
            &run(
                r#"<SessionCache type="StorageService" cacheAssertions="true"/>"#,
                "",
                "",
            ),
            "SEC-148",
        );

        assert_outcome(
            &run(
                "",
                r#"exportLocation="https://app.example.org:8443/GetAssertion""#,
                "",
            ),
            "SEC-149",
            false,
        );
        assert_absent(
            &run("", r#"exportLocation="http://localhost/GetAssertion""#, ""),
            "SEC-149",
        );
        assert_absent(
            &run("", r#"exportLocation="http://[::1]:8080/GetAssertion""#, ""),
            "SEC-149",
        );
        assert_absent(&run("", r#"exportLocation="/GetAssertion""#, ""), "SEC-149");
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
