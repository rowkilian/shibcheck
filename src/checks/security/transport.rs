use super::*;

const DOC_REMOTE_DYNAMIC: &str = "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2067399842/MetadataProviderRemoteDynamicCommonAttributes";
const DOC_ODBC_STORAGE: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334638/ODBCStorageService";

pub(super) fn run(sc: &ShibbolethConfig, v: SpVersion, results: &mut Vec<CheckResult>) {
    check_verify_host(sc, v, results);
    check_odbc_password(sc, v, results);
}

/// SEC-146: `verifyHost="false"` on a dynamic provider stops the TLS hostname check.
fn check_verify_host(sc: &ShibbolethConfig, v: SpVersion, results: &mut Vec<CheckResult>) {
    for mp in &sc.metadata_providers {
        if !matches!(mp.provider_type.as_str(), "MDQ" | "Dynamic") {
            continue;
        }
        if mp.verify_host.as_deref() == Some("false") {
            results.push(
                CheckResult::fail(
                    "SEC-146",
                    CAT,
                    Severity::Warning,
                    &format!(
                        "MetadataProvider type='{}'{} sets verifyHost=\"false\", so the TLS server name is not checked",
                        mp.provider_type,
                        mp.label()
                    ),
                    Some("Remove verifyHost=\"false\" so the certificate must match the host name"),
                )
                .with_doc(doc_for(DOC_REMOTE_DYNAMIC, v)),
            );
        } else {
            results.push(CheckResult::pass(
                "SEC-146",
                CAT,
                Severity::Warning,
                &format!(
                    "MetadataProvider type='{}'{} verifies the TLS host name",
                    mp.provider_type,
                    mp.label()
                ),
            ));
        }
    }
}

/// SEC-147: an ODBC `ConnectionString` that carries a password. The docs suggest a named
/// connection so the password stays out of a file the web server account can read.
fn check_odbc_password(sc: &ShibbolethConfig, v: SpVersion, results: &mut Vec<CheckResult>) {
    if !sc.odbc_connection_has_password {
        return;
    }
    results.push(
        CheckResult::fail(
            "SEC-147",
            CAT,
            Severity::Info,
            "ODBC ConnectionString sets a password in the configuration file",
            Some("Use a named connection from odbc.ini and keep the password there, since the web server account can read this file"),
        )
        .at_element("ConnectionString")
        .with_doc(doc_for(DOC_ODBC_STORAGE, v)),
    );
}

#[cfg(test)]
mod tests {
    use crate::checks::security::run;
    use crate::result::CheckResult;
    use crate::testutil::{assert_absent, assert_outcome, config_from_xml, sp3_app};

    fn with_body(body: &str) -> Vec<CheckResult> {
        let (_dir, config) = config_from_xml(&sp3_app("", body));
        run(&config)
    }

    #[test]
    fn verify_host_false_is_flagged_on_dynamic_providers() {
        let mdq = |attrs: &str| {
            with_body(&format!(
                r#"<MetadataProvider type="MDQ" base="https://mdq.example.org" {attrs}/>"#
            ))
        };
        assert_outcome(&mdq(r#"verifyHost="false""#), "SEC-146", false);
        assert_outcome(&mdq(r#"verifyHost="true""#), "SEC-146", true);
        assert_outcome(&mdq(""), "SEC-146", true);
        let xml = with_body(
            r#"<MetadataProvider type="XML" url="https://x.example.org/m.xml" verifyHost="false"/>"#,
        );
        assert_absent(&xml, "SEC-146");
    }

    #[test]
    fn odbc_password_is_flagged_without_storing_it() {
        let conn = |text: &str| {
            with_body(&format!(
                r#"<StorageService type="ODBC" id="db"><ConnectionString>{text}</ConnectionString></StorageService>"#
            ))
        };
        assert_outcome(
            &conn("DRIVER=MySQL;SERVER=db;UID=app;PWD=hunter2"),
            "SEC-147",
            false,
        );
        assert_outcome(&conn("DRIVER=MySQL;USER=root;password=x"), "SEC-147", false);
        assert_absent(&conn("DSN=shibboleth"), "SEC-147");
        let flagged = conn("DRIVER=MySQL;PWD=hunter2");
        assert!(flagged.iter().all(|r| !r.message.contains("hunter2")));
    }
}
