use chrono::Utc;

use crate::config::DiscoveredConfig;
use crate::model::shibboleth_config::{ShibbolethConfig, SpVersion};
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

const DOC_SAMESITE: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2093318581/SameSite";

const DOC_EXTERNAL_AUTH: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334899/External+Authentication+Handler";
const DOC_ATTR_RESOLVER_HANDLER: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334903/Attribute+Resolver+Handler";
const DOC_BACKDOOR: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334897/BackDoor";
const DOC_ERRORS: &str = "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334361/Errors";
const DOC_STATIC_DATASEALER: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2070413452/StaticDataSealer";
const DOC_VERSIONED_DATASEALER: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2070413454/VersionedDataSealer";

const DOC_INPROCESS: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2063696243/InProcess";
const DOC_ISAPI: &str = "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2063696253/ISAPI";
const DOC_LISTENER: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334609/Listener";
const DOC_NULL_SECURITY: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334892/NullSecurity+Rule";
const DOC_MESSAGE_FLOW: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334545/MessageFlow+Rule";

const DOC_SP2_WIKI: &str = "https://shibboleth.atlassian.net/wiki/spaces/SHIB2/";

const CODE_CERT_PARSE_ERROR: &str = "SEC-126";

fn doc_for(sp3_url: &str, version: SpVersion) -> &str {
    match version {
        SpVersion::V2 => DOC_SP2_WIKI,
        _ => sp3_url,
    }
}

mod application;
mod credentials;
mod handlers;
mod metadata;
mod policy;
mod sessions;
mod transport;
mod web_server;

pub fn run(config: &DiscoveredConfig) -> Vec<CheckResult> {
    let mut results = Vec::new();

    let Some(sc) = config.shibboleth_config.as_ref() else {
        return results;
    };
    let v = sc.sp_version;

    sessions::run(config, sc, v, &mut results);
    credentials::run(config, sc, v, &mut results);
    metadata::run(config, sc, v, &mut results);
    handlers::run(sc, v, &mut results);
    policy::run(config, sc, v, &mut results);
    transport::run(sc, v, &mut results);
    web_server::run(config, sc, v, &mut results);
    application::run(config, sc, v, &mut results);

    super::relying_party::security(config, &mut results);
    super::elements::security(config, &mut results);

    // Keep the report in code order, whichever group produced a result.
    results.sort_by_key(|r| {
        r.code
            .trim_start_matches("SEC-")
            .parse::<u32>()
            .unwrap_or(u32::MAX)
    });
    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{assert_absent, assert_outcome, config_from_xml, sp3_with_sessions};

    fn run_sessions(attrs: &str) -> Vec<CheckResult> {
        let (_dir, config) = config_from_xml(&sp3_with_sessions(attrs));
        run(&config)
    }

    #[test]
    fn no_config_yields_no_results() {
        let dir = crate::testutil::TestDir::new();
        assert!(run(&dir.discover()).is_empty());
    }

    #[test]
    fn handler_ssl_true_passes() {
        assert_outcome(&run_sessions(r#"handlerSSL="true""#), "SEC-001", true);
    }

    #[test]
    fn handler_ssl_false_fails() {
        assert_outcome(&run_sessions(r#"handlerSSL="false""#), "SEC-001", false);
    }

    #[test]
    fn handler_ssl_unset_fails() {
        assert_outcome(&run_sessions(""), "SEC-001", false);
    }

    #[test]
    fn https_shorthand_satisfies_secure_and_httponly_on_sp3() {
        let results = run_sessions(r#"cookieProps="https""#);
        assert_outcome(&results, "SEC-002", true);
        assert_outcome(&results, "SEC-003", true);
    }

    #[test]
    fn https_shorthand_does_not_count_on_sp2() {
        let xml = sp3_with_sessions(r#"cookieProps="https""#)
            .replace("shibboleth:3.0:", "shibboleth:2.0:");
        let (_dir, config) = config_from_xml(&xml);
        let results = run(&config);
        assert_outcome(&results, "SEC-002", false);
        assert_outcome(&results, "SEC-003", false);
    }

    #[test]
    fn explicit_flags_are_matched_case_insensitively() {
        let results = run_sessions(r#"cookieProps="; path=/; Secure; HTTPONLY""#);
        assert_outcome(&results, "SEC-002", true);
        assert_outcome(&results, "SEC-003", true);
    }

    #[test]
    fn plain_cookie_props_fail_both_flag_checks() {
        let results = run_sessions(r#"cookieProps="http""#);
        assert_outcome(&results, "SEC-002", false);
        assert_outcome(&results, "SEC-003", false);
    }

    #[test]
    fn missing_cookie_props_fails_secure_check() {
        assert_outcome(&run_sessions(""), "SEC-002", false);
    }

    #[test]
    fn failures_carry_a_suggestion_and_doc_link() {
        let results = run_sessions(r#"handlerSSL="false""#);
        let r = results.iter().find(|r| r.code == "SEC-001").unwrap();
        assert!(r.suggestion.is_some());
        assert!(r.doc_url.is_some());
    }

    #[test]
    fn samesite_in_cookie_props_is_flagged_on_sp3() {
        let results = run_sessions(r#"cookieProps="https; SameSite=None""#);
        assert_outcome(&results, "SEC-017", false);
    }

    #[test]
    fn cookie_props_without_samesite_pass_on_sp3() {
        assert_outcome(&run_sessions(r#"cookieProps="https""#), "SEC-017", true);
        assert_outcome(&run_sessions(""), "SEC-017", true);
    }

    #[test]
    fn samesite_check_is_skipped_on_sp2() {
        let xml = sp3_with_sessions(r#"cookieProps="; SameSite=None""#)
            .replace("shibboleth:3.0:", "shibboleth:2.0:");
        let (_dir, config) = config_from_xml(&xml);
        assert_absent(&run(&config), "SEC-017");
    }

    #[test]
    fn same_site_session_values() {
        for (value, passed) in [
            ("Lax", true),
            ("None", false),
            ("Strict", false),
            ("lax", false),
        ] {
            let results = run_sessions(&format!(r#"sameSiteSession="{value}""#));
            assert_outcome(&results, "SEC-127", passed);
        }
    }

    #[test]
    fn same_site_session_unset_yields_no_result() {
        assert_absent(&run_sessions(""), "SEC-127");
    }

    #[test]
    fn sessions_checks_are_skipped_without_sessions_element() {
        let xml = r#"<SPConfig xmlns="urn:mace:shibboleth:3.0:native:sp:config">
  <ApplicationDefaults entityID="https://sp.example.org/shibboleth"/>
</SPConfig>"#;
        let (_dir, config) = config_from_xml(xml);
        assert_absent(&run(&config), "SEC-001");
    }

    fn run_app(defaults_attrs: &str, body: &str) -> Vec<CheckResult> {
        let (_dir, config) = config_from_xml(&crate::testutil::sp3_app(defaults_attrs, body));
        run(&config)
    }

    #[test]
    fn data_sealer_variants() {
        let r = run_app(
            "",
            r#"<DataSealer type="Static" key="AAAAAAAAAAAAAAAAAAAAAA=="/>"#,
        );
        assert_outcome(&r, "SEC-114", false);
        let r = run_app("", r#"<DataSealer type="Versioned" path="sealer.keys"/>"#);
        assert_outcome(&r, "SEC-114", true);
        let r = run_app(
            "",
            r#"<DataSealer type="Versioned" url="https://k.example/keys"/>"#,
        );
        assert_outcome(&r, "SEC-114", false);
        let r = run_app(
            "",
            r#"<DataSealer type="Versioned" url="https://k.example/keys" backingFilePath="keys.bak"/>"#,
        );
        assert_outcome(&r, "SEC-114", true);
        assert_absent(&run_app("", ""), "SEC-114");
    }

    #[test]
    fn session_recovery_is_flagged() {
        let sealer = r#"<DataSealer type="Versioned" path="sealer.keys"/>"#;
        let with = |attrs: &str| {
            run_app(
                "",
                &format!(r#"{sealer}<SessionCache type="StorageService" {attrs}/>"#),
            )
        };
        assert_outcome(&with(r#"persistedAttributes="uid mail""#), "SEC-139", false);
        assert_outcome(&with(""), "SEC-139", true);
        assert_outcome(&with(r#"persistedAttributes=" ""#), "SEC-139", true);
        assert_absent(&run_app("", ""), "SEC-139");
    }

    #[test]
    fn loopback_handlers_need_loopback_acl() {
        for (handler, passed) in [
            (
                r#"<Handler type="ExternalAuth" Location="/Ext" acl="127.0.0.1 ::1"/>"#,
                true,
            ),
            (
                r#"<Handler type="ExternalAuth" Location="/Ext" acl="127.0.0.1 10.0.0.0/8"/>"#,
                false,
            ),
            (
                r#"<Handler type="AttributeResolver" Location="/AR" acl="192.168.1.5"/>"#,
                false,
            ),
        ] {
            let r = run_app("", &format!("<Sessions>{handler}</Sessions>"));
            assert_outcome(&r, "SEC-128", passed);
        }
        // No ACL at all is SEC-062's job
        let r = run_app(
            "",
            r#"<Sessions><Handler type="ExternalAuth" Location="/Ext"/></Sessions>"#,
        );
        assert_absent(&r, "SEC-128");
    }

    #[test]
    fn artifact_by_filesystem_is_reported() {
        assert_outcome(
            &run_app(r#"artifactByFilesystem="true""#, ""),
            "SEC-129",
            false,
        );
        assert_absent(&run_app(r#"artifactByFilesystem="false""#, ""), "SEC-129");
    }

    #[test]
    fn redirect_allow_needs_trailing_slash() {
        for (value, passed) in [
            ("https://a.example/ https://b.example:8443/", true),
            ("https://a.example", false),
            ("https://a.example/ https://b.example", false),
            ("a.example/", false),
        ] {
            let r = run_sessions(&format!(r#"redirectLimit="allow" redirectAllow="{value}""#));
            assert_outcome(&r, "SEC-130", passed);
        }
        // Pre-3.2 spelling is checked too
        let r = run_sessions(r#"redirectLimit="whitelist" redirectWhitelist="https://a.example""#);
        assert_outcome(&r, "SEC-130", false);
        assert_absent(&run_sessions(""), "SEC-130");
    }

    fn run_xml(top: &str, body: &str) -> Vec<CheckResult> {
        let xml = format!(
            r#"<SPConfig xmlns="urn:mace:shibboleth:3.0:native:sp:config">{top}
<ApplicationDefaults entityID="https://sp.example.org/shibboleth">{body}</ApplicationDefaults></SPConfig>"#
        );
        let (_dir, config) = config_from_xml(&xml);
        run(&config)
    }

    #[test]
    fn cipher_exclusions_are_not_weak_ciphers() {
        let r = run_app(r#"cipherSuites="HIGH:!aNULL:!MD5:!RC4:!3DES:!EXPORT""#, "");
        assert_outcome(&r, "SEC-097", true);
        assert_outcome(
            &run_app(r#"cipherSuites="HIGH:RC4-SHA""#, ""),
            "SEC-097",
            false,
        );
        assert_absent(&run_app("", ""), "SEC-035");
        let r = run_app(
            "",
            r#"<RelyingParty Name="https://idp.example.org/idp" cipherSuites="DES-CBC3-SHA"/>"#,
        );
        assert_outcome(&r, "SEC-097", false);
    }

    #[test]
    fn listeners_are_told_apart() {
        let r = run_xml(r#"<UnixListener address="shibd.sock"/>"#, "<Sessions/>");
        assert_absent(&r, "SEC-044");
        assert_outcome(&r, "SEC-081", true);
        let r = run_xml(
            r#"<TCPListener address="0.0.0.0" port="1600"/>"#,
            "<Sessions/>",
        );
        assert_outcome(&r, "SEC-044", false);
    }

    #[test]
    fn defaults_the_docs_give_are_not_findings() {
        // exportACL defaults to loopback.
        assert_outcome(
            &run_app("", r#"<Sessions exportLocation="/GetAssertion"/>"#),
            "SEC-059",
            true,
        );
        // ExternalAuth and AttributeResolver handlers default to a loopback acl.
        let r = run_app(
            "",
            r#"<Sessions><Handler type="ExternalAuth" Location="/EA"/><Handler type="AttributeResolver" Location="/AR" acl="10.0.0.0/8"/></Sessions>"#,
        );
        assert_outcome(&r, "SEC-062", true);
        assert_outcome(&r, "SEC-063", false);
        // RequireValidUntil defaults to 7 days.
        let r = run_app(
            "",
            r#"<MetadataProvider type="XML" path="m.xml"><MetadataFilter type="RequireValidUntil"/></MetadataProvider>"#,
        );
        assert_outcome(&r, "SEC-026", true);
        // signing defaults to conditional; only "false" is a finding.
        assert_outcome(&run_app(r#"signing="conditional""#, ""), "SEC-006", true);
        assert_outcome(&run_app("", ""), "SEC-006", true);
        assert_absent(
            &run_app("", "<Sessions><Logout>SAML2 Local</Logout></Sessions>"),
            "SEC-060",
        );
        assert_outcome(
            &run_app(
                "",
                r#"<Sessions><Logout signing="false">SAML2 Local</Logout></Sessions>"#,
            ),
            "SEC-060",
            false,
        );
    }

    #[test]
    fn per_application_comparisons() {
        let body = r#"<Sessions><SessionInitiator type="SAML2" id="a" isDefault="true" Location="/Login"/><Handler type="Session" Location="/Session"/></Sessions>
<ApplicationOverride id="other"><Sessions><SessionInitiator type="SAML2" id="b" isDefault="true" Location="/Login"/><Handler type="Session" Location="/Session"/></Sessions></ApplicationOverride>"#;
        let r = run_app("", body);
        assert_outcome(&r, "SEC-118", true);
        assert_outcome(&r, "SEC-119", true);
        let r = run_app(
            "",
            r#"<Sessions><SessionInitiator type="SAML2" id="a" isDefault="true" Location="/Login"/><SessionInitiator type="SAML2" id="b" isDefault="true" Location="/Login2"/></Sessions>"#,
        );
        assert_outcome(&r, "SEC-118", false);
    }

    #[test]
    fn override_redirect_allow_needs_redirect_limit() {
        let r = run_app(
            "",
            r#"<Sessions redirectLimit="exact"/><ApplicationOverride id="o"><Sessions redirectAllow="https://a.example.org/"/></ApplicationOverride>"#,
        );
        assert_outcome(&r, "SEC-065", false);
        let r = run_app(
            "",
            r#"<Sessions redirectLimit="exact"/><ApplicationOverride id="o"><Sessions lifetime="1"/></ApplicationOverride>"#,
        );
        assert_outcome(&r, "SEC-065", true);
    }

    #[test]
    fn export_assertion_checks_use_the_request_map() {
        let xml = |path_attrs: &str| {
            format!(
                r#"<SPConfig xmlns="urn:mace:shibboleth:3.0:native:sp:config"><!-- exportAssertion="true" -->
<ApplicationDefaults entityID="https://sp.example.org/shibboleth"><Sessions/></ApplicationDefaults>
<RequestMapper type="Native"><RequestMap><Host name="a.example.org"><Path name="x" {path_attrs}/></Host></RequestMap></RequestMapper></SPConfig>"#
            )
        };
        let (_dir, c) = config_from_xml(&xml(""));
        let r = run(&c);
        assert_outcome(&r, "SEC-034", true);
        assert_absent(&r, "SEC-050");
        let (_dir, c) = config_from_xml(&xml(r#"exportAssertion="true""#));
        let r = run(&c);
        assert_outcome(&r, "SEC-034", false);
        assert_outcome(&r, "SEC-050", false);
        let (_dir, c) = config_from_xml(&xml(r#"exportAssertion="true" requireSession="true""#));
        assert_outcome(&run(&c), "SEC-050", true);
    }

    #[test]
    fn spoof_key_and_attribute_prefix_are_parsed() {
        assert_outcome(
            &run_xml(r#"<InProcess spoofKey="k"/>"#, "<Sessions/>"),
            "SEC-036",
            true,
        );
        assert_outcome(
            &run_xml("<!-- spoofKey= -->", "<Sessions/>"),
            "SEC-036",
            false,
        );
        // IIS generates its own key.
        assert_absent(
            &run_xml("<InProcess><ISAPI/></InProcess>", "<Sessions/>"),
            "SEC-036",
        );
        assert_outcome(&run_app(r#"attributePrefix="AJP_""#, ""), "SEC-106", true);
        assert_outcome(
            &run_xml("<!-- attributePrefix= -->", "<Sessions/>"),
            "SEC-106",
            false,
        );
    }

    #[test]
    fn basic_auth_on_application_defaults() {
        let r = run_app(r#"authType="basic" authUsername="u" authPassword="p""#, "");
        assert_outcome(&r, "SEC-142", false);
        assert_outcome(&r, "SEC-143", false);
    }

    #[test]
    fn catch_all_is_reported_for_both_processes() {
        let run_top = |top: &str| {
            let xml = format!(
                r#"<SPConfig xmlns="urn:mace:shibboleth:3.0:native:sp:config">{top}<ApplicationDefaults entityID="https://sp.example.org/shibboleth"/></SPConfig>"#
            );
            let (_dir, config) = config_from_xml(&xml);
            run(&config)
        };
        assert_outcome(
            &run_top(r#"<OutOfProcess catchAll="true"/>"#),
            "SEC-121",
            false,
        );
        assert_outcome(
            &run_top(r#"<InProcess catchAll="true"/>"#),
            "SEC-121",
            false,
        );
        assert_absent(
            &run_top(r#"<OutOfProcess catchAll="false"/><InProcess/>"#),
            "SEC-121",
        );
    }

    #[test]
    fn errors_external_parameters() {
        let r = run_app("", r#"<Errors externalParameters="true"/>"#);
        assert_outcome(&r, "SEC-131", false);
        let r = run_app("", r#"<Errors externalParameters="false"/>"#);
        assert_outcome(&r, "SEC-131", true);
        assert_absent(&run_app("", "<Errors/>"), "SEC-131");
    }

    #[test]
    fn attribute_prefix_must_not_be_http() {
        assert_outcome(&run_app(r#"attributePrefix="HTTP_""#, ""), "SEC-132", false);
        assert_outcome(
            &run_app(r#"attributePrefix="http_x""#, ""),
            "SEC-132",
            false,
        );
        assert_outcome(&run_app(r#"attributePrefix="AJP_""#, ""), "SEC-132", true);
        assert_absent(&run_app("", ""), "SEC-132");
    }

    #[test]
    fn check_spoofing_disabled_is_flagged() {
        let r = run_app("", r#"<InProcess checkSpoofing="false"/>"#);
        assert_outcome(&r, "SEC-133", false);
        let r = run_app("", r#"<InProcess checkSpoofing="true"/>"#);
        assert_outcome(&r, "SEC-133", true);
        assert_absent(&run_app("", r#"<InProcess/>"#), "SEC-133");
    }

    #[test]
    fn isapi_settings() {
        let r = run_app(
            "",
            r#"<InProcess><ISAPI normalizeRequest="false"/></InProcess>"#,
        );
        assert_outcome(&r, "SEC-134", false);
        assert_absent(
            &run_app("", r#"<ISAPI normalizeRequest="true"/>"#),
            "SEC-134",
        );

        let r = run_app("", r#"<ISAPI useHeaders="true"/>"#);
        assert_outcome(&r, "SEC-135", false);
        let r = run_app(
            "",
            r#"<ISAPI><Site id="1" name="a.example" useHeaders="true"/></ISAPI>"#,
        );
        assert_outcome(&r, "SEC-135", false);
        assert_absent(
            &run_app("", r#"<ISAPI><Site id="1" name="a.example"/></ISAPI>"#),
            "SEC-135",
        );
    }

    #[test]
    fn tcp_listener_acl() {
        let r = run_app(
            "",
            r#"<TCPListener address="127.0.0.1" port="1600" acl="127.0.0.1 ::1"/>"#,
        );
        assert_outcome(&r, "SEC-136", true);
        let r = run_app(
            "",
            r#"<TCPListener address="127.0.0.1" port="1600" acl="10.0.0.0/8"/>"#,
        );
        assert_outcome(&r, "SEC-136", false);
        assert_absent(
            &run_app("", r#"<TCPListener address="127.0.0.1"/>"#),
            "SEC-136",
        );
    }

    fn run_with_policy(shib_body: &str, policy: Option<&str>) -> Vec<CheckResult> {
        let dir = crate::testutil::TestDir::new();
        dir.write("shibboleth2.xml", &crate::testutil::sp3_app("", shib_body));
        if let Some(policy) = policy {
            dir.write("security-policy.xml", policy);
        }
        run(&dir.discover())
    }

    #[test]
    fn policy_rules_in_security_policy_file() {
        let policy = r#"<SecurityPolicies>
  <Policy id="default">
    <PolicyRule type="NullSecurity"/>
    <PolicyRule type="MessageFlow" checkReplay="false"/>
  </Policy>
</SecurityPolicies>"#;
        let r = run_with_policy("", Some(policy));
        assert_outcome(&r, "SEC-137", false);
        assert_outcome(&r, "SEC-138", false);
        let hit = r.iter().find(|r| r.code == "SEC-137").unwrap();
        let loc = hit.location.as_ref().unwrap();
        assert_eq!(loc.file, "security-policy.xml");
        assert_eq!(loc.line, Some(3));
    }

    #[test]
    fn clean_policy_passes_and_missing_policy_is_not_reported() {
        let policy = r#"<SecurityPolicies><Policy id="default"><PolicyRule type="MessageFlow" checkReplay="true"/></Policy></SecurityPolicies>"#;
        let r = run_with_policy("", Some(policy));
        assert_outcome(&r, "SEC-137", true);
        assert_outcome(&r, "SEC-138", true);
        // Without security-policy.xml the inline config is still scanned
        let r = run_with_policy(r#"<PolicyRule type="NullSecurity"/>"#, None);
        assert_outcome(&r, "SEC-137", false);
    }
}
