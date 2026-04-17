pub mod attribute_map;
pub mod attribute_policy;
pub mod certificate;
pub mod shibboleth_xml;

use quick_xml::events::BytesStart;

/// Local (namespace-stripped) element name for a start tag.
pub(crate) fn local_name(e: &BytesStart<'_>) -> String {
    let full = String::from_utf8_lossy(e.name().as_ref()).to_string();
    full.rsplit(':').next().unwrap_or(&full).to_string()
}

/// First attribute value matching `name` (namespace-prefix agnostic), or `None`.
pub(crate) fn get_attr(e: &BytesStart<'_>, name: &str) -> Option<String> {
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
