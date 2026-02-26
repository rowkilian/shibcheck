/// Parsed representation of attribute-map.xml
#[derive(Debug, Default)]
pub struct AttributeMap {
    pub attributes: Vec<MappedAttribute>,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct MappedAttribute {
    /// The name attribute (OID or URN)
    pub name: String,
    /// The id attribute (local name used in REMOTE_USER etc.)
    pub id: String,
    /// The xsi:type from a child <AttributeDecoder> element
    pub decoder_type: Option<String>,
}
