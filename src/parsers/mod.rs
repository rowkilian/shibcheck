pub mod access_control;
pub mod attribute_map;
pub mod attribute_policy;
pub mod certificate;
pub mod security_policy;
pub mod shibboleth_xml;

use quick_xml::events::BytesStart;

/// Local (namespace-stripped) element name for a start tag.
pub(crate) fn local_name(e: &BytesStart<'_>) -> String {
    let full = String::from_utf8_lossy(e.name().as_ref()).to_string();
    full.rsplit(':').next().unwrap_or(&full).to_string()
}

/// First attribute value matching `name` (namespace-prefix agnostic), entity-decoded, or `None`.
pub(crate) fn get_attr(e: &BytesStart<'_>, name: &str) -> Option<String> {
    e.attributes().filter_map(|a| a.ok()).find_map(|a| {
        let key = String::from_utf8_lossy(a.key.as_ref()).to_string();
        let local_key = key.rsplit(':').next().unwrap_or(&key);
        if local_key == name {
            // Decode entities (&amp; in a URI, etc.); keep the raw text if it won't decode
            Some(
                a.unescape_value()
                    .map(|v| v.into_owned())
                    .unwrap_or_else(|_| String::from_utf8_lossy(&a.value).into_owned()),
            )
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use quick_xml::events::Event;
    use quick_xml::reader::Reader;

    fn attr(xml: &str, name: &str) -> Option<String> {
        let mut reader = Reader::from_str(xml);
        match reader.read_event().unwrap() {
            Event::Start(e) | Event::Empty(e) => get_attr(&e, name),
            other => panic!("unexpected event {other:?}"),
        }
    }

    #[test]
    fn get_attr_decodes_entities() {
        assert_eq!(
            attr(r#"<a uri="http://x/m?a=1&amp;b=2"/>"#, "uri").as_deref(),
            Some("http://x/m?a=1&b=2")
        );
    }

    #[test]
    fn get_attr_ignores_namespace_prefix() {
        assert_eq!(attr(r#"<a conf:id="x"/>"#, "id").as_deref(), Some("x"));
    }

    #[test]
    fn get_attr_missing_is_none() {
        assert_eq!(attr(r#"<a id="x"/>"#, "other"), None);
    }
}
