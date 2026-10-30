//! `shibcheck migrate`: edits that move an SP2 configuration to the SP3 format.
//!
//! Every edit stays inside one start tag, so line numbers do not shift and the diff is
//! easy to read. Each rule comes from the SP3 documentation (UpgradingFromV2, ReleaseNotes,
//! and the pages for the elements involved). Anything that needs a decision is left alone and
//! reported as a note.

use crate::fix::{
    attr_value, find_attr, rename_attr, replace_value, set_attr, start_tags, tag_name, AppliedFix,
    FixPlan,
};
use crate::parsers::security_policy::SP2_NAMESPACE;

/// The SP3 configuration namespace.
pub const SP3_NAMESPACE: &str = "urn:mace:shibboleth:3.0:native:sp:config";

#[derive(Debug, Clone, Copy, Default)]
pub struct Options {
    /// Rename attributes and values but leave the namespace alone. The upgrade guide
    /// suggests this order: clear the deprecation warnings first, then change the namespace.
    pub keep_namespace: bool,
}

/// What migrating one file would do.
#[derive(Debug)]
pub struct Migration {
    pub plan: FixPlan,
    /// Things the tool saw but left alone, each with a line number.
    pub notes: Vec<String>,
}

impl Migration {
    pub fn is_empty(&self) -> bool {
        self.plan.applied.is_empty()
    }

    /// Every check code the applied edits address.
    pub fn codes(&self) -> Vec<&'static str> {
        let mut codes: Vec<&'static str> = Vec::new();
        for edit in &self.plan.applied {
            for code in &edit.codes {
                if !codes.contains(code) {
                    codes.push(code);
                }
            }
        }
        codes
    }
}

/// One change inside a start tag.
struct Change {
    code: &'static str,
    description: String,
}

/// Plan the edits for `shibboleth2.xml`.
pub fn plan_main(content: &str, options: Options) -> Migration {
    plan(content, options, false)
}

/// Plan the edits for `security-policy.xml`. Only the namespace changes.
pub fn plan_policy(content: &str, options: Options) -> Migration {
    plan(content, options, true)
}

fn plan(content: &str, options: Options, policy_file: bool) -> Migration {
    let tags = start_tags(content);
    let root_is_sp2 = tags
        .first()
        .is_some_and(|&(s, e)| content[s..e].contains(SP2_NAMESPACE));
    let bump = root_is_sp2 && !options.keep_namespace;

    let mut fixed = String::with_capacity(content.len());
    let mut applied = Vec::new();
    let mut notes = Vec::new();
    let mut copied = 0;

    for (index, &(start, end)) in tags.iter().enumerate() {
        let tag = &content[start..end];
        let line = content[..start].matches('\n').count() + 1;
        let mut new_tag = tag.to_string();
        let mut changes: Vec<Change> = Vec::new();

        if index == 0 && bump {
            new_tag = new_tag.replace(SP2_NAMESPACE, SP3_NAMESPACE);
            changes.push(Change {
                code: if policy_file { "MIG-025" } else { "MIG-004" },
                description: "namespace 2.0 to 3.0".to_string(),
            });
        }
        if !policy_file {
            migrate_tag(
                tag_name(tag),
                &mut new_tag,
                bump,
                line,
                &mut changes,
                &mut notes,
            );
        }

        if new_tag != tag {
            fixed.push_str(&content[copied..start]);
            fixed.push_str(&new_tag);
            copied = end;
            let mut codes: Vec<&'static str> = Vec::new();
            for c in &changes {
                if !codes.contains(&c.code) {
                    codes.push(c.code);
                }
            }
            applied.push(AppliedFix {
                codes,
                description: format!(
                    "<{}>: {}",
                    tag_name(tag),
                    changes
                        .iter()
                        .map(|c| c.description.as_str())
                        .collect::<Vec<_>>()
                        .join("; ")
                ),
                line,
                start,
                end,
                new_text: new_tag,
            });
        }
    }
    fixed.push_str(&content[copied..]);

    Migration {
        plan: FixPlan {
            original: content.to_string(),
            fixed,
            applied,
        },
        notes,
    }
}

/// Apply the per-element rules to one start tag.
fn migrate_tag(
    name: &str,
    tag: &mut String,
    bump: bool,
    line: usize,
    changes: &mut Vec<Change>,
    notes: &mut Vec<String>,
) {
    let mut rename = |tag: &mut String, from: &str, to: &str, code: &'static str| {
        if find_attr(tag, from).is_none() {
            return;
        }
        match rename_attr(tag, from, to) {
            Some(new_tag) => {
                *tag = new_tag;
                changes.push(Change {
                    code,
                    description: format!("{from} renamed to {to}"),
                });
            }
            None => notes.push(format!(
                "line {line}: <{name}> has both {from} and {to}, so {from} was left for you to remove"
            )),
        }
    };

    match name {
        "MetadataProvider" => {
            rename(tag, "file", "path", "MIG-006");
            rename(tag, "uri", "url", "MIG-013");
        }
        "Sessions" => {
            rename(tag, "redirectWhitelist", "redirectAllow", "MIG-008");
            let replacement = match attr_value(tag, "redirectLimit").as_deref().map(str::trim) {
                Some("whitelist") => Some(("whitelist", "allow")),
                Some("exact+whitelist") => Some(("exact+whitelist", "exact+allow")),
                Some("host+whitelist") => Some(("host+whitelist", "host+allow")),
                _ => None,
            };
            if let Some((old, new)) = replacement {
                if let Some(new_tag) = replace_value(tag, "redirectLimit", new) {
                    *tag = new_tag;
                    changes.push(Change {
                        code: "MIG-018",
                        description: format!("redirectLimit {old} changed to {new}"),
                    });
                }
            }
        }
        "MetadataFilter" => {
            let replacement = match attr_value(tag, "type").as_deref().map(str::trim) {
                Some("EntityRoleWhiteList") => {
                    Some(("EntityRoleWhiteList", "EntityRole", "MIG-011"))
                }
                Some("Whitelist") => Some(("Whitelist", "Include", "MIG-012")),
                Some("Blacklist") => Some(("Blacklist", "Exclude", "MIG-012")),
                _ => None,
            };
            if let Some((old, new, code)) = replacement {
                if let Some(new_tag) = replace_value(tag, "type", new) {
                    *tag = new_tag;
                    changes.push(Change {
                        code,
                        description: format!("type {old} changed to {new}"),
                    });
                }
            }
        }
        "SessionCache" if bump => {
            // cacheAssertions defaults to true in a configuration on the 2.0 namespace and to
            // false on the 3.0 namespace, so keep the old behavior explicit.
            let is_storage_service =
                attr_value(tag, "type").is_none_or(|t| t.trim() == "StorageService");
            if is_storage_service && find_attr(tag, "cacheAssertions").is_none() {
                *tag = set_attr(tag, "cacheAssertions", "true");
                changes.push(Change {
                    code: "MIG-027",
                    description: "cacheAssertions=\"true\" added to keep the SP2 default"
                        .to_string(),
                });
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const V2_ROOT: &str = r#"<SPConfig xmlns="urn:mace:shibboleth:2.0:native:sp:config" xmlns:conf="urn:mace:shibboleth:2.0:native:sp:config" clockSkew="180">"#;

    fn main(xml: &str) -> Migration {
        plan_main(xml, Options::default())
    }

    #[test]
    fn namespace_is_bumped_everywhere_in_the_root_tag() {
        let m = main(&format!("{V2_ROOT}\n</SPConfig>"));
        assert_eq!(
            m.plan.fixed,
            format!(
                "{}\n</SPConfig>",
                V2_ROOT.replace(SP2_NAMESPACE, SP3_NAMESPACE)
            )
        );
        assert_eq!(m.codes(), vec!["MIG-004"]);
    }

    #[test]
    fn keep_namespace_only_renames() {
        let xml = format!(r#"{V2_ROOT}<MetadataProvider type="XML" file="a.xml"/></SPConfig>"#);
        let m = plan_main(
            &xml,
            Options {
                keep_namespace: true,
            },
        );
        assert!(m.plan.fixed.contains(SP2_NAMESPACE));
        assert!(m.plan.fixed.contains(r#"path="a.xml""#));
    }

    #[test]
    fn metadata_provider_attributes_are_renamed() {
        let xml = format!(
            "{V2_ROOT}\n<MetadataProvider type=\"XML\" uri='https://x.example.org/m.xml' backingFile=\"b\"/>\n<MetadataProvider type=\"XML\" file=\"local.xml\"/>\n</SPConfig>"
        );
        let m = main(&xml);
        assert!(m.plan.fixed.contains("url='https://x.example.org/m.xml'"));
        assert!(m.plan.fixed.contains(r#"path="local.xml""#));
        assert!(!m.plan.fixed.contains(" uri=") && !m.plan.fixed.contains(" file="));
        assert_eq!(m.codes(), vec!["MIG-004", "MIG-013", "MIG-006"]);
    }

    #[test]
    fn a_conflicting_attribute_is_left_with_a_note() {
        let xml = format!(
            r#"{V2_ROOT}<MetadataProvider type="XML" file="a.xml" path="b.xml"/></SPConfig>"#
        );
        let m = main(&xml);
        assert!(m.plan.fixed.contains(r#"file="a.xml" path="b.xml""#));
        assert_eq!(m.notes.len(), 1);
        assert!(m.notes[0].contains("both file and path"));
    }

    #[test]
    fn sessions_and_filters_use_the_32_names() {
        let xml = format!(
            r#"{V2_ROOT}<Sessions redirectLimit="exact+whitelist" redirectWhitelist="https://a.example.org/"/>
<MetadataProvider type="XML" path="m.xml"><MetadataFilter type="Whitelist"/><MetadataFilter type="Blacklist"/><MetadataFilter type="EntityRoleWhiteList"/><MetadataFilter type="Signature"/></MetadataProvider></SPConfig>"#
        );
        let m = main(&xml);
        assert!(m
            .plan
            .fixed
            .contains(r#"redirectLimit="exact+allow" redirectAllow="https://a.example.org/""#));
        for t in ["Include", "Exclude", "EntityRole", "Signature"] {
            assert!(m.plan.fixed.contains(&format!(r#"type="{t}""#)), "{t}");
        }
        assert!(!m.plan.fixed.contains("Whitelist\"/>") && !m.plan.fixed.contains("Blacklist"));
    }

    #[test]
    fn session_cache_keeps_the_old_assertion_default() {
        let m = main(&format!(
            r#"{V2_ROOT}<SessionCache type="StorageService" cacheTimeout="3600"/></SPConfig>"#
        ));
        assert!(m
            .plan
            .fixed
            .contains(r#"<SessionCache cacheAssertions="true" type="StorageService""#));
        // Already explicit, a different type, or no namespace change: untouched.
        let set = main(&format!(
            r#"{V2_ROOT}<SessionCache cacheAssertions="false"/></SPConfig>"#
        ));
        assert!(!set.plan.fixed.contains(r#"cacheAssertions="true""#));
        let other = main(&format!(
            r#"{V2_ROOT}<SessionCache type="Custom"/></SPConfig>"#
        ));
        assert!(!other.plan.fixed.contains("cacheAssertions"));
        let kept = plan_main(
            &format!(r#"{V2_ROOT}<SessionCache/></SPConfig>"#),
            Options {
                keep_namespace: true,
            },
        );
        assert!(!kept.plan.fixed.contains("cacheAssertions"));
    }

    #[test]
    fn an_sp3_file_gets_the_renames_but_no_pin() {
        let xml = r#"<SPConfig xmlns="urn:mace:shibboleth:3.0:native:sp:config"><SessionCache/><Sessions redirectLimit="whitelist"/></SPConfig>"#;
        let m = main(xml);
        assert!(m.plan.fixed.contains(r#"redirectLimit="allow""#));
        assert!(!m.plan.fixed.contains("cacheAssertions"));
        assert_eq!(m.codes(), vec!["MIG-018"]);
    }

    #[test]
    fn comments_and_other_elements_are_not_edited() {
        let xml = format!(
            "{V2_ROOT}\n<!-- <MetadataProvider file=\"old.xml\"/> -->\n<AttributeExtractor file=\"x\"/>\n</SPConfig>"
        );
        let m = main(&xml);
        assert!(m
            .plan
            .fixed
            .contains("<!-- <MetadataProvider file=\"old.xml\"/> -->"));
        assert!(m.plan.fixed.contains(r#"<AttributeExtractor file="x"/>"#));
    }

    #[test]
    fn only_the_namespace_changes_in_the_policy_file() {
        let xml = format!(
            r#"<SecurityPolicies xmlns="{SP2_NAMESPACE}"><Policy id="default"/><MetadataProvider file="x"/></SecurityPolicies>"#
        );
        let m = plan_policy(&xml, Options::default());
        assert_eq!(
            m.plan.fixed,
            xml.replace(
                &format!(r#"xmlns="{SP2_NAMESPACE}""#),
                &format!(r#"xmlns="{SP3_NAMESPACE}""#)
            )
        );
        assert_eq!(m.codes(), vec!["MIG-025"]);
    }

    #[test]
    fn line_count_never_changes_and_a_second_run_is_a_no_op() {
        let xml = format!(
            "{V2_ROOT}\n<Sessions redirectWhitelist=\"https://a.example.org/\"/>\n<SessionCache/>\n<MetadataProvider type=\"XML\" file=\"a.xml\">\n<MetadataFilter type=\"Whitelist\"/>\n</MetadataProvider>\n</SPConfig>\n"
        );
        let first = main(&xml);
        assert_eq!(first.plan.fixed.lines().count(), xml.lines().count());
        let second = main(&first.plan.fixed);
        assert!(second.is_empty(), "{:?}", second.plan.applied);
    }

    mod properties {
        use super::*;
        use proptest::prelude::*;

        const SNIPPETS: &[&str] = &[
            r#"<MetadataProvider type="XML" file="a.xml"/>"#,
            r#"<MetadataProvider type="XML" uri="https://x.example.org/m.xml">"#,
            "</MetadataProvider>",
            r#"<MetadataFilter type="Whitelist"/>"#,
            r#"<MetadataFilter type="Blacklist"/>"#,
            r#"<Sessions redirectLimit="whitelist" redirectWhitelist="https://a.example.org/">"#,
            "</Sessions>",
            "<SessionCache/>",
            r#"<SessionCache type="StorageService" cacheAssertions="false"/>"#,
            "<!-- <MetadataProvider file=\"c.xml\"> <Sessions redirectLimit=\"whitelist\"> -->",
            "<![CDATA[ <MetadataFilter type=\"Whitelist\"> ]]>",
            "<?pi <SessionCache> ?>",
            "text &gt; with &lt; odd characters",
            "\n",
            "  ",
        ];

        fn document() -> impl Strategy<Value = String> {
            proptest::collection::vec(proptest::sample::select(SNIPPETS), 0..12)
                .prop_map(|parts| format!("{V2_ROOT}{}</SPConfig>", parts.concat()))
        }

        proptest! {
            #[test]
            fn never_panics_and_keeps_every_line(xml in document()) {
                let m = plan_main(&xml, Options::default());
                prop_assert_eq!(m.plan.fixed.lines().count(), xml.lines().count());
            }

            #[test]
            fn a_second_run_changes_nothing(xml in document()) {
                let first = plan_main(&xml, Options::default());
                let second = plan_main(&first.plan.fixed, Options::default());
                prop_assert!(second.is_empty(), "{:?}", second.plan.applied);
            }

            #[test]
            fn comments_cdata_and_instructions_survive(xml in document()) {
                let m = plan_main(&xml, Options::default());
                for decoy in SNIPPETS.iter().filter(|s| s.starts_with("<!--") || s.starts_with("<![CDATA[") || s.starts_with("<?")) {
                    prop_assert_eq!(xml.matches(decoy).count(), m.plan.fixed.matches(decoy).count());
                }
            }

            #[test]
            fn arbitrary_text_never_panics(text in ".{0,200}") {
                let _ = plan_main(&text, Options::default());
                let _ = plan_policy(&text, Options::default());
            }
        }
    }
}
