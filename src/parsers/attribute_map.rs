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
                if name == "Attribute" {
                    let attr_name = get_attr(&e, "name");
                    let attr_id = get_attr(&e, "id");
                    if let (Some(name), Some(id)) = (attr_name, attr_id) {
                        map.attributes.push(MappedAttribute { name, id });
                    }
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
    }
}
