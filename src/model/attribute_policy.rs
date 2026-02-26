/// Parsed representation of attribute-policy.xml
#[derive(Debug, Default)]
pub struct AttributePolicy {
    pub rules: Vec<PolicyRule>,
}

#[derive(Debug)]
pub struct PolicyRule {
    /// The attribute ID this rule applies to
    pub attribute_id: String,
    /// Whether this rule contains a ScopeMatchesShibMDScope condition
    pub has_scope_match: bool,
    /// The xsi:type from <PermitValueRule> (e.g. "ANY")
    pub permit_value_rule_type: Option<String>,
}
