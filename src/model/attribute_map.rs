/// Parsed representation of attribute-map.xml
#[derive(Debug, Default)]
pub struct AttributeMap {
    pub attributes: Vec<MappedAttribute>,
}

#[derive(Debug)]
pub struct MappedAttribute {
    /// The name attribute (OID or URN)
    pub name: String,
    /// The id attribute (local name used in REMOTE_USER etc.)
    pub id: String,
}
