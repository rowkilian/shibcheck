use anyhow::{Context, Result};
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use std::path::Path;

use crate::model::attribute_policy::{AttributePolicy, PolicyRule};

pub fn parse(path: &Path) -> Result<AttributePolicy> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    parse_str(&content)
}

pub fn parse_str(xml: &str) -> Result<AttributePolicy> {
    let mut reader = Reader::from_str(xml);
    let mut policy = AttributePolicy::default();
    let mut current_rule_idx: Option<usize> = None;
    let mut element_stack: Vec<String> = Vec::new();

    loop {
        match reader.read_event() {
            Err(e) => {
                anyhow::bail!(
                    "XML parse error at position {}: {}",
                    reader.error_position(),
                    e
                )
            }
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) => {
                let name = local_name(&e);
                if name == "AttributeRule" {
                    if let Some(id) = get_attr(&e, "attributeID") {
                        policy.rules.push(PolicyRule {
                            attribute_id: id,
                            has_scope_match: false,
                            permit_value_rule_type: None,
                        });
                        current_rule_idx = Some(policy.rules.len() - 1);
                    }
                } else if let Some(idx) = current_rule_idx {
                    if let Some(xsi_type) = get_attr(&e, "type") {
                        if xsi_type.contains("ScopeMatchesShibMDScope") {
                            policy.rules[idx].has_scope_match = true;
                        }
                    }
                    // Capture PermitValueRule type
                    if name == "PermitValueRule" {
                        if let Some(xsi_type) = get_attr(&e, "type") {
                            if xsi_type.contains("ANY") {
                                policy.rules[idx].permit_value_rule_type = Some("ANY".to_string());
                            }
                        }
                    }
                }
                element_stack.push(name);
            }
            Ok(Event::Empty(e)) => {
                let name = local_name(&e);
                if name == "AttributeRule" {
                    if let Some(id) = get_attr(&e, "attributeID") {
                        policy.rules.push(PolicyRule {
                            attribute_id: id,
                            has_scope_match: false,
                            permit_value_rule_type: None,
                        });
                    }
                } else if let Some(idx) = current_rule_idx {
                    if let Some(xsi_type) = get_attr(&e, "type") {
                        if xsi_type.contains("ScopeMatchesShibMDScope") {
                            policy.rules[idx].has_scope_match = true;
                        }
                    }
                    if name == "PermitValueRule" {
                        if let Some(xsi_type) = get_attr(&e, "type") {
                            if xsi_type.contains("ANY") {
                                policy.rules[idx].permit_value_rule_type = Some("ANY".to_string());
                            }
                        }
                    }
                }
            }
            Ok(Event::End(_)) => {
                if let Some(name) = element_stack.pop() {
                    if name == "AttributeRule" {
                        current_rule_idx = None;
                    }
                }
            }
            _ => {}
        }
    }

    Ok(policy)
}

fn local_name(e: &quick_xml::events::BytesStart<'_>) -> String {
    let full = String::from_utf8_lossy(e.name().as_ref()).to_string();
    full.rsplit(':').next().unwrap_or(&full).to_string()
}

fn get_attr(e: &quick_xml::events::BytesStart<'_>, name: &str) -> Option<String> {
    e.attributes().filter_map(|a| a.ok()).find_map(|a| {
        let key = String::from_utf8_lossy(a.key.as_ref()).to_string();
        let local_key = key.rsplit(':').next().unwrap_or(&key);
        if local_key == name {
            Some(String::from_utf8_lossy(&a.value).to_string())
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_attribute_policy() {
        let xml = r#"
        <AttributeFilterPolicyGroup xmlns="urn:mace:shibboleth:2.0:afp">
            <AttributeFilterPolicy>
                <AttributeRule attributeID="eppn">
                    <PermitValueRule xsi:type="ANY"/>
                </AttributeRule>
                <AttributeRule attributeID="mail">
                    <PermitValueRule xsi:type="ANY"/>
                </AttributeRule>
            </AttributeFilterPolicy>
        </AttributeFilterPolicyGroup>
        "#;
        let policy = parse_str(xml).unwrap();
        assert_eq!(policy.rules.len(), 2);
        assert_eq!(policy.rules[0].attribute_id, "eppn");
        assert!(!policy.rules[0].has_scope_match);
    }

    #[test]
    fn test_parse_scope_match() {
        let xml = r#"
        <AttributeFilterPolicyGroup xmlns="urn:mace:shibboleth:2.0:afp"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <AttributeFilterPolicy>
                <AttributeRule attributeID="eppn">
                    <PermitValueRule xsi:type="ScopeMatchesShibMDScope"/>
                </AttributeRule>
                <AttributeRule attributeID="mail">
                    <PermitValueRule xsi:type="ANY"/>
                </AttributeRule>
            </AttributeFilterPolicy>
        </AttributeFilterPolicyGroup>
        "#;
        let policy = parse_str(xml).unwrap();
        assert_eq!(policy.rules.len(), 2);
        assert!(policy.rules[0].has_scope_match);
        assert!(!policy.rules[1].has_scope_match);
    }

    #[test]
    fn test_parse_permit_value_rule_type() {
        let xml = r#"
        <AttributeFilterPolicyGroup xmlns="urn:mace:shibboleth:2.0:afp"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <AttributeFilterPolicy>
                <AttributeRule attributeID="eppn">
                    <PermitValueRule xsi:type="ANY"/>
                </AttributeRule>
                <AttributeRule attributeID="affiliation">
                    <PermitValueRule xsi:type="ScopeMatchesShibMDScope"/>
                </AttributeRule>
            </AttributeFilterPolicy>
        </AttributeFilterPolicyGroup>
        "#;
        let policy = parse_str(xml).unwrap();
        assert_eq!(policy.rules.len(), 2);
        assert_eq!(
            policy.rules[0].permit_value_rule_type.as_deref(),
            Some("ANY")
        );
        assert!(policy.rules[1].permit_value_rule_type.is_none());
    }
}
