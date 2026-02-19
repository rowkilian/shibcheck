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
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                let name = local_name(&e);
                // AttributeRule elements define policy rules per attribute ID
                if name == "AttributeRule" {
                    if let Some(id) = get_attr(&e, "attributeID") {
                        policy.rules.push(PolicyRule { attribute_id: id });
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
    }
}
