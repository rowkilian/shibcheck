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

#[test]
fn check_sec_062_external_auth_no_acl() {
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
        "Expected SEC-062 check for ExternalAuth handler without ACL"
    );
    assert!(
        !sec_062[0]["passed"].as_bool().unwrap(),
        "Expected SEC-062 to fail on ExternalAuth handler without ACL"
    );
}

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
