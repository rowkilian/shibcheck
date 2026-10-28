//! Helpers for unit-testing checks against inline XML.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::config::{self, DiscoveredConfig};
use crate::result::CheckResult;

static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// A throwaway config directory, removed on drop.
pub struct TestDir {
    path: PathBuf,
}

impl TestDir {
    pub fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("shibcheck-test-{}-{}", std::process::id(), n));
        std::fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    pub fn write(&self, name: &str, content: &str) -> &Self {
        std::fs::write(self.path.join(name), content).unwrap();
        self
    }

    pub fn discover(&self) -> DiscoveredConfig {
        config::discover(&self.path).unwrap()
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Build a config directory holding only `shibboleth2.xml` and discover it.
/// The returned `TestDir` must stay alive while the config is in use.
pub fn config_from_xml(shibboleth2: &str) -> (TestDir, DiscoveredConfig) {
    let dir = TestDir::new();
    dir.write("shibboleth2.xml", shibboleth2);
    let config = dir.discover();
    (dir, config)
}

/// Wrap a `<Sessions>` element in the minimum surrounding SP3 config.
pub fn sp3_with_sessions(sessions_attrs: &str) -> String {
    format!(
        r#"<SPConfig xmlns="urn:mace:shibboleth:3.0:native:sp:config">
  <ApplicationDefaults entityID="https://sp.example.org/shibboleth">
    <Sessions {sessions_attrs}>
      <SSO entityID="https://idp.example.org/idp">SAML2</SSO>
    </Sessions>
  </ApplicationDefaults>
</SPConfig>"#
    )
}

/// All results with the given code.
pub fn with_code<'a>(results: &'a [CheckResult], code: &str) -> Vec<&'a CheckResult> {
    results.iter().filter(|r| r.code == code).collect()
}

/// Assert that `code` ran exactly once and had the expected outcome.
#[track_caller]
pub fn assert_outcome(results: &[CheckResult], code: &str, passed: bool) {
    let hits = with_code(results, code);
    assert_eq!(
        hits.len(),
        1,
        "{code}: expected exactly one result, got {}",
        hits.len()
    );
    assert_eq!(
        hits[0].passed, passed,
        "{code}: expected passed={passed}, message was {:?}",
        hits[0].message
    );
}

/// Assert that `code` produced no result at all (check not applicable).
#[track_caller]
pub fn assert_absent(results: &[CheckResult], code: &str) {
    assert!(
        with_code(results, code).is_empty(),
        "{code}: expected no result"
    );
}
