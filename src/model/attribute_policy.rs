/// Parsed representation of attribute-policy.xml
#[derive(Debug, Default)]
pub struct AttributePolicy {
    pub rules: Vec<PolicyRule>,
}

#[derive(Debug)]
pub struct PolicyRule {
    /// The attribute ID this rule applies to
    pub attribute_id: String,
}
