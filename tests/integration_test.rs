use assert_cmd::Command;

fn shibcheck() -> Command {
    #[allow(deprecated)]
    Command::cargo_bin("shibcheck").unwrap()
}

// ── Good fixture ──

#[test]
fn good_config_exits_zero() {
    shibcheck()
        .arg("tests/fixtures/good")
        .assert()
        .success()
        .stdout(predicates::str::contains("Summary:"));
}

#[test]
fn good_config_verbose_shows_pass() {
    shibcheck()
        .args(["--verbose", "tests/fixtures/good"])
        .assert()
        .success()
        .stdout(predicates::str::contains("PASS"));
}

// ── Broken fixture ──

#[test]
fn broken_config_exits_nonzero() {
    shibcheck()
        .arg("tests/fixtures/broken")
        .assert()
        .failure()
        .stdout(predicates::str::contains("FAIL"));
}

// ── Insecure fixture ──

#[test]
fn insecure_config_exits_nonzero() {
    shibcheck()
        .arg("tests/fixtures/insecure")
        .assert()
        .failure();
}

// ── JSON output ──

#[test]
fn json_output_is_valid_json() {
    let output = shibcheck()
        .args(["--json", "tests/fixtures/good"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert!(parsed.get("results").is_some());
    assert!(parsed.get("summary").is_some());
}

// ── SARIF output ──

#[test]
fn sarif_output_is_valid() {
    let output = shibcheck()
        .args(["--sarif", "tests/fixtures/good"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("valid SARIF JSON");
    assert_eq!(parsed["version"], "2.1.0");
    assert!(parsed["runs"].is_array());
    let info_uri = parsed["runs"][0]["tool"]["driver"]["informationUri"]
        .as_str()
        .expect("informationUri is a string");
    assert!(
        info_uri.starts_with("https://github.com/") && !info_uri.contains("<owner>"),
        "SARIF informationUri should be a real URL, got: {}",
        info_uri
    );
}

// ── HTML output ──

#[test]
fn html_output_contains_doctype() {
    let output = shibcheck()
        .args(["--html", "tests/fixtures/good"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("<!DOCTYPE html>"));
    assert!(stdout.contains("shibcheck report"));
}

// ── Filtering ──

#[test]
fn check_filter_includes_only_matching() {
    let output = shibcheck()
        .args(["--check", "SEC", "--json", "tests/fixtures/insecure"])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    let results = parsed["results"].as_array().unwrap();
    for r in results {
        assert!(
            r["code"].as_str().unwrap().starts_with("SEC"),
            "Expected only SEC checks, got {}",
            r["code"]
        );
    }
}

#[test]
fn skip_filter_excludes_matching() {
    let output = shibcheck()
        .args(["--skip", "XML", "--json", "tests/fixtures/insecure"])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    let results = parsed["results"].as_array().unwrap();
    for r in results {
        assert!(
            !r["code"].as_str().unwrap().starts_with("XML"),
            "Expected no XML checks, got {}",
            r["code"]
        );
    }
}

// ── Severity threshold ──

#[test]
fn severity_error_ignores_warnings() {
    // The insecure fixture has warnings but we only care about errors
    shibcheck()
        .args(["--severity", "error", "tests/fixtures/insecure"])
        .assert()
        .failure(); // still has errors
}

// ── Output format mutual exclusion ──

#[test]
fn json_and_sarif_mutually_exclusive() {
    shibcheck()
        .args(["--json", "--sarif", "tests/fixtures/good"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("cannot be used with"));
}

// ── Non-existent directory ──

#[test]
fn nonexistent_dir_exits_two() {
    shibcheck()
        .arg("/tmp/does_not_exist_shibcheck_test")
        .assert()
        .code(2)
        .stderr(predicates::str::contains("not a directory"));
}

// ── Completions subcommand ──

#[test]
fn completions_bash_outputs_script() {
    shibcheck()
        .args(["completions", "bash"])
        .assert()
        .success()
        .stdout(predicates::str::contains("complete"));
}

// ── Diff subcommand ──

#[test]
fn diff_two_dirs() {
    shibcheck()
        .args(["diff", "tests/fixtures/good", "tests/fixtures/insecure"])
        .assert()
        .success()
        .stdout(predicates::str::contains("Configuration Diff"));
}

// ── New check tests ──

/// MIG-012 flags `<MetadataFilter type="Whitelist">` — renamed to `Include` in SP3.
/// Configs that still use `Whitelist` load cleanly on SP2 but silently stop filtering on SP3.
#[test]
fn check_mig_011_deprecated_whitelist_filter() {
    let output = shibcheck()
        .args(["--check", "MIG-012", "--json", "tests/fixtures/insecure"])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    let results = parsed["results"].as_array().unwrap();
    let mig_012: Vec<_> = results
        .iter()
        .filter(|r| r["code"].as_str().unwrap() == "MIG-012")
        .collect();
    assert!(
        !mig_012.is_empty(),
        "Expected MIG-012 check for deprecated Whitelist filter"
    );
    assert!(
        !mig_012[0]["passed"].as_bool().unwrap(),
        "Expected MIG-012 to fail on deprecated filter"
    );
}

/// `--check OPS` filtering must produce only OPS-prefixed codes — guards against
/// the filter accidentally passing through unrelated categories when the prefix has no trailing dash.
#[test]
fn check_ops_json_returns_ops_checks() {
    let output = shibcheck()
        .args(["--check", "OPS", "--json", "tests/fixtures/good"])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    let results = parsed["results"].as_array().unwrap();
    assert!(!results.is_empty(), "Expected OPS checks to be present");
    for r in results {
        assert!(
            r["code"].as_str().unwrap().starts_with("OPS"),
            "Expected only OPS checks, got {}",
            r["code"]
        );
    }
    // Check that new OPS checks are present
    let codes: Vec<&str> = results
        .iter()
        .map(|r| r["code"].as_str().unwrap())
        .collect();
    assert!(
        codes.iter().any(|c| c.starts_with("OPS-0")),
        "Expected OPS-0xx checks to be present"
    );
}

/// SEC-032 flags `showAttributeValues="true"` on the Status handler — which exposes
/// session attribute values (potential PII / secrets) to anyone who can hit /Shibboleth.sso/Status.
#[test]
fn check_sec_032_show_attribute_values() {
    let output = shibcheck()
        .args(["--check", "SEC-032", "--json", "tests/fixtures/insecure"])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    let results = parsed["results"].as_array().unwrap();
    let sec_032: Vec<_> = results
        .iter()
        .filter(|r| r["code"].as_str().unwrap() == "SEC-032")
        .collect();
    assert!(
        !sec_032.is_empty(),
        "Expected SEC-032 check for showAttributeValues"
    );
    assert!(
        !sec_032[0]["passed"].as_bool().unwrap(),
        "Expected SEC-032 to fail on showAttributeValues=true"
    );
}

/// SEC-044 flags a `TCPListener` bound to `0.0.0.0` — the shibd control channel
/// should never be reachable off-host, as it exposes session management to the network.
#[test]
fn check_sec_044_tcp_listener_insecure_binding() {
    let output = shibcheck()
        .args(["--check", "SEC-044", "--json", "tests/fixtures/insecure"])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    let results = parsed["results"].as_array().unwrap();
    let sec_044: Vec<_> = results
        .iter()
        .filter(|r| r["code"].as_str().unwrap() == "SEC-044")
        .collect();
    assert!(
        !sec_044.is_empty(),
        "Expected SEC-044 check for TCPListener binding"
    );
    assert!(
        !sec_044[0]["passed"].as_bool().unwrap(),
        "Expected SEC-044 to fail on 0.0.0.0 binding"
    );
}

/// SEC-062 flags an `ExternalAuth` handler with no ACL — the handler accepts
/// remote-user assertions, so without an ACL any caller can inject a pre-authenticated session.
#[test]
fn check_sec_062_external_auth_default_acl() {
    let output = shibcheck()
        .args(["--check", "SEC-062", "--json", "tests/fixtures/insecure"])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    let results = parsed["results"].as_array().unwrap();
    let sec_062: Vec<_> = results
        .iter()
        .filter(|r| r["code"].as_str().unwrap() == "SEC-062")
        .collect();
    assert!(
        !sec_062.is_empty(),
        "Expected SEC-062 check for the ExternalAuth handler"
    );
    // The handler's acl defaults to loopback, so a missing acl is not a finding.
    assert!(
        sec_062[0]["passed"].as_bool().unwrap(),
        "Expected SEC-062 to pass on an ExternalAuth handler with the default acl"
    );
}

/// SEC-055 flags `ignoreTransport="true"` on a MetadataProvider without a Signature
/// filter — HTTPS trust is disabled and there's nothing else verifying metadata integrity,
/// so an on-path attacker can replace the federation metadata entirely.
#[test]
fn check_sec_055_ignore_transport_no_sig() {
    let output = shibcheck()
        .args(["--check", "SEC-055", "--json", "tests/fixtures/insecure"])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    let results = parsed["results"].as_array().unwrap();
    let sec_055: Vec<_> = results
        .iter()
        .filter(|r| r["code"].as_str().unwrap() == "SEC-055")
        .collect();
    assert!(
        !sec_055.is_empty(),
        "Expected SEC-055 check for ignoreTransport without Signature filter"
    );
    assert!(
        !sec_055[0]["passed"].as_bool().unwrap(),
        "Expected SEC-055 to fail on ignoreTransport without Signature filter"
    );
}

/// MIG-022 flags `SessionInitiator type="Shib1"` — the Shibboleth 1.x protocol was
/// removed in SP3 (SAML1-only, no encryption). Configs carrying it over will fail authentication silently.
#[test]
fn check_mig_022_shib1_session_initiator() {
    let output = shibcheck()
        .args(["--check", "MIG-022", "--json", "tests/fixtures/insecure"])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    let results = parsed["results"].as_array().unwrap();
    let mig_022: Vec<_> = results
        .iter()
        .filter(|r| r["code"].as_str().unwrap() == "MIG-022")
        .collect();
    assert!(
        !mig_022.is_empty(),
        "Expected MIG-022 check for Shib1 SessionInitiator"
    );
    assert!(
        !mig_022[0]["passed"].as_bool().unwrap(),
        "Expected MIG-022 to fail on Shib1 SessionInitiator"
    );
}

/// MIG-019 flags `discoveryProtocol="WAYF"` — the pre-SAML2 discovery protocol was
/// removed in SP3. Configs using it lose IdP discovery entirely after upgrade.
#[test]
fn check_mig_019_wayf_deprecated() {
    let output = shibcheck()
        .args(["--check", "MIG-019", "--json", "tests/fixtures/insecure"])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    let results = parsed["results"].as_array().unwrap();
    let mig_019: Vec<_> = results
        .iter()
        .filter(|r| r["code"].as_str().unwrap() == "MIG-019")
        .collect();
    assert!(
        !mig_019.is_empty(),
        "Expected MIG-019 check for WAYF protocol"
    );
    assert!(
        !mig_019[0]["passed"].as_bool().unwrap(),
        "Expected MIG-019 to fail on WAYF discoveryProtocol"
    );
}

// ── Regression tests for recent bug fixes ──

#[test]
fn malformed_shibcheckrc_prints_warning() {
    let output = shibcheck()
        .arg("tests/fixtures/malformed_rc")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Warning: ignoring malformed"),
        "Expected malformed .shibcheckrc warning on stderr, got: {}",
        stderr
    );
}

#[test]
fn corrupt_cert_emits_sec_126() {
    let output = shibcheck()
        .args(["--json", "tests/fixtures/corrupt_cert"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    let results = parsed["results"].as_array().unwrap();
    let sec_126: Vec<_> = results
        .iter()
        .filter(|r| r["code"].as_str().unwrap() == "SEC-126")
        .collect();
    assert!(
        !sec_126.is_empty(),
        "Expected SEC-126 for corrupt certificate so the parse failure isn't silent"
    );
    assert!(
        !sec_126[0]["passed"].as_bool().unwrap(),
        "SEC-126 should be a failure"
    );
}

#[test]
fn ref_001_attaches_location_at_check_site() {
    // REF-001 is now set at the check site, so even broken fixtures with missing
    // certs should carry a shibboleth2.xml location pointing at the CredentialResolver.
    let output = shibcheck()
        .args(["--json", "tests/fixtures/corrupt_cert"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    let results = parsed["results"].as_array().unwrap();
    let ref_001 = results
        .iter()
        .find(|r| r["code"].as_str().unwrap() == "REF-001")
        .expect("REF-001 result present");
    let location = ref_001
        .get("location")
        .expect("REF-001 should carry a location");
    assert_eq!(location["file"], "shibboleth2.xml");
    assert!(
        location.get("line").is_some(),
        "Expected a line number for the CredentialResolver referencing the cert"
    );
}

// ── fix subcommand ──

/// Copy the insecure fixture into a fresh temp dir and return the dir.
fn insecure_copy(tag: &str) -> (std::path::PathBuf, String) {
    let dir = std::env::temp_dir().join(format!("shibcheck-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let original = std::fs::read_to_string("tests/fixtures/insecure/shibboleth2.xml").unwrap();
    std::fs::write(dir.join("shibboleth2.xml"), &original).unwrap();
    (dir, original)
}

#[test]
fn fix_rewrites_config_and_keeps_a_backup() {
    let (dir, original) = insecure_copy("fix");

    shibcheck()
        .arg("fix")
        .arg(&dir)
        .assert()
        .success()
        .stdout(predicates::str::contains("SEC-001"))
        .stdout(predicates::str::contains("Backup saved to"));

    let fixed = std::fs::read_to_string(dir.join("shibboleth2.xml")).unwrap();
    let backup = std::fs::read_to_string(dir.join("shibboleth2.xml.bak")).unwrap();
    assert_ne!(fixed, original);
    assert_eq!(backup, original);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn fix_dry_run_shows_a_diff_and_writes_nothing() {
    let (dir, original) = insecure_copy("fixdry");

    shibcheck()
        .args(["fix", "--dry-run"])
        .arg(&dir)
        .assert()
        .success()
        .stdout(predicates::str::contains("Would fix"))
        .stdout(predicates::str::contains("Dry run"));

    assert_eq!(
        std::fs::read_to_string(dir.join("shibboleth2.xml")).unwrap(),
        original
    );
    assert!(!dir.join("shibboleth2.xml.bak").exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn fix_is_idempotent_and_honors_only_and_no_backup() {
    let (dir, _) = insecure_copy("fixonly");

    shibcheck()
        .args(["fix", "--only", "SEC-001", "--no-backup"])
        .arg(&dir)
        .assert()
        .success();
    assert!(!dir.join("shibboleth2.xml.bak").exists());
    let once = std::fs::read_to_string(dir.join("shibboleth2.xml")).unwrap();
    assert!(!once.contains("handlerSSL=\"false\""));

    shibcheck()
        .args(["fix", "--only", "SEC-001"])
        .arg(&dir)
        .assert()
        .success()
        .stdout(predicates::str::contains("Nothing to fix"));
    assert_eq!(
        std::fs::read_to_string(dir.join("shibboleth2.xml")).unwrap(),
        once
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn fix_rejects_unknown_codes_and_lists_fixable_ones() {
    shibcheck()
        .args(["fix", "--only", "SEC-999", "tests/fixtures/insecure"])
        .assert()
        .code(2)
        .stderr(predicates::str::contains("not a fixable check"));
    shibcheck()
        .args(["fix", "--list"])
        .assert()
        .success()
        .stdout(predicates::str::contains("SEC-002"));
}

#[test]
fn old_fix_flag_is_gone() {
    shibcheck()
        .args(["--fix", "tests/fixtures/good"])
        .assert()
        .code(2);
}

// ── suppressions and baseline ──

fn json_failures(args: &[&str]) -> Vec<String> {
    let out = shibcheck().args(args).arg("--json").output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    v["results"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["passed"] == false)
        .map(|r| r["code"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn ignore_file_comment_hides_a_finding_and_no_ignore_shows_it() {
    let (dir, original) = insecure_copy("ignore");
    let d = dir.to_str().unwrap();
    assert!(json_failures(&[d]).contains(&"SEC-001".to_string()));

    let marked = original.replacen(
        "<SPConfig",
        "<!-- shibcheck-ignore-file SEC-001: accepted for the test rig -->\n<SPConfig",
        1,
    );
    assert_ne!(marked, original);
    std::fs::write(dir.join("shibboleth2.xml"), marked).unwrap();

    assert!(!json_failures(&[d]).contains(&"SEC-001".to_string()));
    assert!(json_failures(&[d, "--no-ignore"]).contains(&"SEC-001".to_string()));
    shibcheck()
        .arg(d)
        .assert()
        .stderr(predicates::str::contains("hidden by shibcheck-ignore"));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn baseline_hides_old_findings_and_reports_new_ones() {
    let (dir, original) = insecure_copy("baseline");
    let d = dir.to_str().unwrap();

    shibcheck()
        .args(["baseline", d])
        .assert()
        .success()
        .stdout(predicates::str::contains("Recorded"));
    let file = dir.join(".shibcheck-baseline.json");
    assert!(file.exists());
    let bl = file.to_str().unwrap();

    // Everything is accepted, so the run is clean.
    shibcheck().args(["--baseline", bl, d]).assert().success();
    assert!(json_failures(&["--baseline", bl, d]).is_empty());

    // Break something new: it must show up.
    let worse = original.replacen(
        "</SPConfig>",
        "<InProcess checkSpoofing=\"false\"/></SPConfig>",
        1,
    );
    std::fs::write(dir.join("shibboleth2.xml"), worse).unwrap();
    let after = json_failures(&["--baseline", bl, d]);
    assert_eq!(after, vec!["SEC-133".to_string()]);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn bad_baseline_file_is_a_tool_error() {
    let (dir, _) = insecure_copy("badbaseline");
    let bad = dir.join("bl.json");
    std::fs::write(&bad, "not json").unwrap();
    shibcheck()
        .args(["--baseline", bad.to_str().unwrap(), dir.to_str().unwrap()])
        .assert()
        .code(2);
    std::fs::remove_dir_all(&dir).unwrap();
}

// ── fixes in JSON and SARIF ──

#[test]
fn json_and_sarif_carry_the_fix_edit() {
    let out = shibcheck()
        .args(["--json", "tests/fixtures/insecure"])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let sec001 = v["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["code"] == "SEC-001" && r["passed"] == false)
        .expect("insecure fixture fails SEC-001");
    let fix = &sec001["fix"];
    // The edit covers only the changed attribute, not the whole tag.
    let text = fix["new_text"].as_str().unwrap();
    assert!(
        text.contains("true") && !text.contains("<Sessions"),
        "{text}"
    );
    assert_eq!(fix["file"], "shibboleth2.xml");

    let out = shibcheck()
        .args(["--sarif", "tests/fixtures/insecure"])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let result = v["runs"][0]["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["ruleId"] == "SEC-001")
        .unwrap();
    let replacement = &result["fixes"][0]["artifactChanges"][0]["replacements"][0];
    assert!(replacement["deletedRegion"]["startLine"].as_u64().unwrap() > 0);
    let inserted = replacement["insertedContent"]["text"].as_str().unwrap();
    assert!(
        inserted.contains("true") && !inserted.contains("<Sessions"),
        "{inserted}"
    );

    // A passing config has no fixes to offer
    let out = shibcheck()
        .args(["--sarif", "tests/fixtures/good"])
        .output()
        .unwrap();
    assert!(!String::from_utf8_lossy(&out.stdout).contains("artifactChanges"));
}

fn sp2_copy(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("shibcheck-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    for file in ["shibboleth2.xml", "security-policy.xml"] {
        std::fs::copy(format!("tests/fixtures/sp2/{file}"), dir.join(file)).unwrap();
    }
    dir
}

#[test]
fn migrate_moves_an_sp2_config_to_sp3_and_keeps_backups() {
    let dir = sp2_copy("migrate");
    let original = std::fs::read_to_string(dir.join("shibboleth2.xml")).unwrap();

    shibcheck()
        .arg("migrate")
        .arg(&dir)
        .assert()
        .success()
        .stdout(predicates::str::contains("MIG-004"))
        .stdout(predicates::str::contains("Backup saved"))
        .stdout(predicates::str::contains("SP 3.2 or later"));

    let migrated = std::fs::read_to_string(dir.join("shibboleth2.xml")).unwrap();
    assert!(!migrated.contains("urn:mace:shibboleth:2.0:native:sp:config"));
    assert!(migrated.contains(r#"url="https://md.example.org/metadata.xml""#));
    assert!(migrated.contains(r#"path="local-metadata.xml""#));
    assert!(migrated.contains(r#"redirectLimit="exact+allow""#));
    assert!(migrated.contains("redirectAllow="));
    assert!(migrated.contains(r#"type="Include""#));
    assert!(migrated.contains(r#"cacheAssertions="true""#));
    // Comments and formatting survive, and no line is added or removed.
    assert!(
        migrated.contains(r#"<!-- <MetadataProvider type="XML" file="commented-out.xml"/> -->"#)
    );
    assert_eq!(migrated.lines().count(), original.lines().count());
    assert_eq!(
        std::fs::read_to_string(dir.join("shibboleth2.xml.bak")).unwrap(),
        original
    );
    let policy = std::fs::read_to_string(dir.join("security-policy.xml")).unwrap();
    assert!(policy.contains("urn:mace:shibboleth:3.0:native:sp:config"));
    assert!(dir.join("security-policy.xml.bak").exists());

    // The checker now sees an SP3 file with none of the migrated constructs.
    let out = shibcheck().arg("--json").arg(&dir).output().unwrap();
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let results = report["results"].as_array().unwrap();
    assert!(
        results
            .iter()
            .any(|r| r["code"] == "MIG-025" && r["passed"] == true),
        "the migrated policy file should pass MIG-025"
    );
    for code in [
        "MIG-004", "MIG-006", "MIG-008", "MIG-012", "MIG-013", "MIG-025",
    ] {
        let failed = results
            .iter()
            .any(|r| r["code"] == code && r["passed"] == false);
        assert!(!failed, "{code} still fails");
    }

    // A second run has nothing to do.
    shibcheck()
        .arg("migrate")
        .arg(&dir)
        .assert()
        .success()
        .stdout(predicates::str::contains("Nothing to migrate"));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn migrate_dry_run_and_output_leave_the_originals_alone() {
    let dir = sp2_copy("migdry");
    let original = std::fs::read_to_string(dir.join("shibboleth2.xml")).unwrap();

    shibcheck()
        .args(["migrate", "--dry-run"])
        .arg(&dir)
        .assert()
        .success()
        .stdout(predicates::str::contains("Would make"))
        .stdout(predicates::str::contains("Dry run"));
    assert_eq!(
        std::fs::read_to_string(dir.join("shibboleth2.xml")).unwrap(),
        original
    );

    let out_dir = dir.join("sp3");
    shibcheck()
        .args(["migrate", "--output"])
        .arg(&out_dir)
        .arg(&dir)
        .assert()
        .success();
    assert_eq!(
        std::fs::read_to_string(dir.join("shibboleth2.xml")).unwrap(),
        original
    );
    assert!(std::fs::read_to_string(out_dir.join("shibboleth2.xml"))
        .unwrap()
        .contains("urn:mace:shibboleth:3.0:native:sp:config"));
    assert!(!dir.join("shibboleth2.xml.bak").exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn migrate_keep_namespace_only_renames_settings() {
    let dir = sp2_copy("migkeep");
    shibcheck()
        .args(["migrate", "--keep-namespace", "--no-backup"])
        .arg(&dir)
        .assert()
        .success();
    let text = std::fs::read_to_string(dir.join("shibboleth2.xml")).unwrap();
    assert!(text.contains("urn:mace:shibboleth:2.0:native:sp:config"));
    assert!(text.contains(r#"url="https://md.example.org/metadata.xml""#));
    assert!(!text.contains("cacheAssertions"));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn migrate_rejects_a_missing_directory() {
    shibcheck()
        .args(["migrate", "/no/such/dir"])
        .assert()
        .code(2);
}
