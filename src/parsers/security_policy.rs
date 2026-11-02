use std::path::PathBuf;

use quick_xml::events::Event;
use quick_xml::reader::Reader;

use super::{get_attr, local_name};
use crate::config::DiscoveredConfig;

/// Namespace of an SP2 era configuration file.
pub const SP2_NAMESPACE: &str = "urn:mace:shibboleth:2.0:native:sp:config";

/// What shibcheck reads from `security-policy.xml`.
#[derive(Debug, Default)]
pub struct SecurityPolicyFile {
    /// The root element's default namespace.
    pub namespace: Option<String>,
    /// `id` of every `<Policy>`.
    pub policy_ids: Vec<String>,
    /// Names of deprecated elements and attributes in use, each listed once.
    pub deprecated: Vec<&'static str>,
    /// An explicit `excludeDefaults="false"` or `includeDefaultBlacklist="false"`,
    /// which stops the SP from disabling its list of known weak algorithms.
    pub defaults_disabled: bool,
}

/// A parsed policy file with its name and location.
#[derive(Debug)]
pub struct LoadedPolicy {
    pub file_name: String,
    pub path: PathBuf,
    pub content: String,
    pub policy: SecurityPolicyFile,
}

/// Parse a `security-policy.xml`. A parse error returns what was read up to that point.
pub fn parse_str(xml: &str) -> SecurityPolicyFile {
    let mut policy = SecurityPolicyFile::default();
    let mut reader = Reader::from_str(xml);
    let mut first = true;
    let note = |policy: &mut SecurityPolicyFile, name: &'static str| {
        if !policy.deprecated.contains(&name) {
            policy.deprecated.push(name);
        }
    };
    while let Ok(event) = reader.read_event() {
        match event {
            Event::Start(e) | Event::Empty(e) => {
                let name = local_name(&e);
                if first {
                    first = false;
                    policy.namespace = get_attr(&e, "xmlns");
                }
                match name.as_str() {
                    "Policy" => {
                        if let Some(id) = get_attr(&e, "id") {
                            policy.policy_ids.push(id);
                        }
                    }
                    "AlgorithmWhitelist" => note(&mut policy, "AlgorithmWhitelist"),
                    "AlgorithmBlacklist" => note(&mut policy, "AlgorithmBlacklist"),
                    _ => {}
                }
                if let Some(value) = get_attr(&e, "includeDefaultBlacklist") {
                    note(&mut policy, "includeDefaultBlacklist");
                    policy.defaults_disabled |= value.trim() == "false";
                }
                if get_attr(&e, "excludeDefaults").is_some_and(|v| v.trim() == "false") {
                    policy.defaults_disabled = true;
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }
    policy
}

/// The policy file the configuration points at: the `SecurityPolicyProvider` `path`, or
/// `security-policy.xml` next to `shibboleth2.xml`. `None` when the file can't be read.
pub fn load_for(config: &DiscoveredConfig) -> Option<LoadedPolicy> {
    let path = match config
        .shibboleth_config
        .as_ref()
        .and_then(|sc| sc.security_policy_provider_path.as_ref())
    {
        Some(p) => config.resolve_path(p),
        None => config.base_dir.join("security-policy.xml"),
    };
    let content = std::fs::read_to_string(&path).ok()?;
    let file_name = path
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_default();
    let policy = parse_str(&content);
    Some(LoadedPolicy {
        file_name,
        path,
        content,
        policy,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_policy_ids_and_namespace() {
        let p = parse_str(
            r#"<SecurityPolicies xmlns="urn:mace:shibboleth:3.0:native:sp:config">
  <Policy id="default"><Rule type="MessageFlow"/></Policy>
  <Policy id="blockUnsolicited"/>
</SecurityPolicies>"#,
        );
        assert_eq!(p.policy_ids, vec!["default", "blockUnsolicited"]);
        assert_eq!(
            p.namespace.as_deref(),
            Some("urn:mace:shibboleth:3.0:native:sp:config")
        );
        assert!(p.deprecated.is_empty());
        assert!(!p.defaults_disabled);
    }

    #[test]
    fn finds_deprecated_names_once() {
        let p = parse_str(
            r#"<SecurityPolicies>
  <Policy id="default"/>
  <AlgorithmBlacklist includeDefaultBlacklist="true">a</AlgorithmBlacklist>
  <AlgorithmBlacklist>b</AlgorithmBlacklist>
  <AlgorithmWhitelist>c</AlgorithmWhitelist>
</SecurityPolicies>"#,
        );
        assert_eq!(
            p.deprecated,
            vec![
                "AlgorithmBlacklist",
                "includeDefaultBlacklist",
                "AlgorithmWhitelist"
            ]
        );
        assert!(!p.defaults_disabled);
    }

    #[test]
    fn only_an_explicit_false_disables_the_defaults() {
        let with = |attr: &str| {
            parse_str(&format!(
                r#"<SecurityPolicies><ExcludedAlgorithms {attr}>x</ExcludedAlgorithms></SecurityPolicies>"#
            ))
            .defaults_disabled
        };
        assert!(with(r#"excludeDefaults="false""#));
        assert!(with(r#"includeDefaultBlacklist="false""#));
        assert!(!with(r#"excludeDefaults="true""#));
        assert!(!with(""));
    }

    #[test]
    fn broken_xml_does_not_panic() {
        let p = parse_str("<SecurityPolicies><Policy id=\"a\"");
        assert!(p.policy_ids.is_empty());
    }
}
