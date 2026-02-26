use anyhow::{Context, Result};
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use std::path::Path;

use crate::model::attribute_map::{AttributeMap, MappedAttribute};

pub fn parse(path: &Path) -> Result<AttributeMap> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    parse_str(&content)
}

pub fn parse_str(xml: &str) -> Result<AttributeMap> {
    let mut reader = Reader::from_str(xml);
    let mut map = AttributeMap::default();
    let mut in_attribute = false;

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
                if name == "Attribute" {
                    let attr_name = get_attr(&e, "name");
                    let attr_id = get_attr(&e, "id");
                    if let (Some(name), Some(id)) = (attr_name, attr_id) {
                        map.attributes.push(MappedAttribute {
                            name,
                            id,
                            decoder_type: None,
                        });
                        in_attribute = true;
                    }
                } else if name == "AttributeDecoder" && in_attribute {
                    if let Some(xsi_type) = get_attr(&e, "type") {
                        if let Some(attr) = map.attributes.last_mut() {
                            attr.decoder_type = Some(xsi_type);
                        }
                    }
                }
            }
            Ok(Event::Empty(e)) => {
                let name = local_name(&e);
                if name == "Attribute" {
                    let attr_name = get_attr(&e, "name");
                    let attr_id = get_attr(&e, "id");
                    if let (Some(name), Some(id)) = (attr_name, attr_id) {
                        map.attributes.push(MappedAttribute {
                            name,
                            id,
                            decoder_type: None,
                        });
                    }
                } else if name == "AttributeDecoder" && in_attribute {
                    if let Some(xsi_type) = get_attr(&e, "type") {
                        if let Some(attr) = map.attributes.last_mut() {
                            attr.decoder_type = Some(xsi_type);
                        }
                    }
                }
            }
            Ok(Event::End(e)) => {
                let end_name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                let local = end_name.rsplit(':').next().unwrap_or(&end_name);
                if local == "Attribute" {
                    in_attribute = false;
                }
            }
            _ => {}
        }
    }

    Ok(map)
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
    fn test_parse_attribute_map() {
        let xml = r#"
        <Attributes xmlns="urn:mace:shibboleth:2.0:attribute-map">
            <Attribute name="urn:oid:1.3.6.1.4.1.5923.1.1.1.6" id="eppn"/>
            <Attribute name="urn:oid:0.9.2342.19200300.100.1.3" id="mail"/>
        </Attributes>
        "#;
        let map = parse_str(xml).unwrap();
        assert_eq!(map.attributes.len(), 2);
        assert_eq!(map.attributes[0].id, "eppn");
        assert_eq!(map.attributes[1].id, "mail");
        assert!(map.attributes[0].decoder_type.is_none());
    }

    #[test]
    fn test_parse_decoder_type() {
        let xml = r#"
        <Attributes xmlns="urn:mace:shibboleth:2.0:attribute-map"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <Attribute name="urn:oid:1.3.6.1.4.1.5923.1.1.1.6" id="eppn">
                <AttributeDecoder xsi:type="ScopedAttributeDecoder"/>
            </Attribute>
            <Attribute name="urn:oid:2.16.840.1.113730.3.1.241" id="displayName"/>
        </Attributes>
        "#;
        let map = parse_str(xml).unwrap();
        assert_eq!(map.attributes.len(), 2);
        assert_eq!(
            map.attributes[0].decoder_type.as_deref(),
            Some("ScopedAttributeDecoder")
        );
        assert!(map.attributes[1].decoder_type.is_none());
    }
}
