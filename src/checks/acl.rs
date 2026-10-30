//! Checks on `<AccessControl>` policies (the XML and Time plugins).
//!
//! The docs say that when processing an access control element fails, the SP installs a
//! policy that denies everything. These checks catch the mistakes that cause that, plus
//! rules that name attributes the SP never extracts.

use crate::config::DiscoveredConfig;
use crate::parsers::access_control::{self, AclNode};
use crate::result::{CheckCategory, CheckResult, Severity};

const DOC_XML_ACL: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334887/XMLAccessControl";
const DOC_AND: &str = "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065335131/AND+Rule";
const DOC_OR: &str = "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065335129/OR+Rule";
const DOC_NOT: &str = "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065335135/NOT+Rule";
const DOC_TIME: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065335084/Time+AccessControl";
const DOC_RULE: &str = "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065335141/Rule";
const DOC_RULE_REGEX: &str =
    "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065335144/RuleRegex";

const XML_ELEMENTS: &[&str] = &["Rule", "RuleRegex", "AND", "OR", "NOT"];
const RULE_ALIASES: &[&str] = &[
    "valid-user",
    "user",
    "authnContextClassRef",
    "authnContextDeclRef",
];
const TIME_OPERATORS: &[&str] = &["LT", "LE", "EQ", "GE", "GT"];

/// Is this `<AccessControl>` the XML plugin? It is when `type` is absent or `XML`.
fn is_xml_plugin(node: &AclNode) -> bool {
    node.attr("type")
        .is_none_or(|t| t.eq_ignore_ascii_case("XML"))
}

fn is_time_plugin(node: &AclNode) -> bool {
    node.attr("type")
        .is_some_and(|t| t.eq_ignore_ascii_case("Time"))
}

/// Visit every `<AccessControl>` element, including ones nested in a Chaining policy.
fn each_policy<'a>(node: &'a AclNode, visit: &mut impl FnMut(&'a AclNode)) {
    if node.name == "AccessControl" {
        visit(node);
    }
    for child in &node.children {
        each_policy(child, visit);
    }
}

fn each_node<'a>(node: &'a AclNode, visit: &mut impl FnMut(&'a AclNode)) {
    visit(node);
    for child in &node.children {
        each_node(child, visit);
    }
}

struct Problem {
    file: String,
    line: usize,
    message: String,
    suggestion: &'static str,
    doc: &'static str,
}

fn report(
    code: &str,
    severity: Severity,
    cat: CheckCategory,
    what_ok: &str,
    problems: Vec<Problem>,
    any_policy: bool,
    results: &mut Vec<CheckResult>,
) {
    if problems.is_empty() {
        if any_policy {
            results.push(CheckResult::pass(code, cat, severity, what_ok));
        }
        return;
    }
    for p in problems {
        results.push(
            CheckResult::fail(code, cat, severity, &p.message, Some(p.suggestion))
                .with_location(&p.file, Some(p.line))
                .with_doc(p.doc),
        );
    }
}

/// XML-055, XML-056 and XML-057: the shape of access control policies.
pub fn structure(config: &DiscoveredConfig, results: &mut Vec<CheckResult>) {
    let files = access_control::load_all(config);
    let (mut shape, mut time, mut missing) = (Vec::new(), Vec::new(), Vec::new());
    let (mut any_xml, mut any_time, mut any_rule) = (false, false, false);

    for file in &files {
        for root in &file.roots {
            each_policy(root, &mut |policy| {
                if is_xml_plugin(policy) {
                    any_xml = true;
                    xml_shape(policy, &file.file, &mut shape);
                }
                if is_time_plugin(policy) {
                    any_time = true;
                    time_values(policy, &file.file, &mut time);
                }
            });
            each_node(root, &mut |n| {
                if matches!(n.name.as_str(), "Rule" | "RuleRegex") {
                    any_rule = true;
                }
                if matches!(n.name.as_str(), "Rule" | "RuleRegex") && n.attr("require").is_none() {
                    missing.push(Problem {
                        file: file.file.clone(),
                        line: n.line,
                        message: format!("<{}> has no require attribute", n.name),
                        suggestion: "Set require to valid-user, user, authnContextClassRef, or the id of a mapped attribute. A policy the SP cannot process denies all access",
                        doc: if n.name == "Rule" { DOC_RULE } else { DOC_RULE_REGEX },
                    });
                }
            });
        }
    }

    report(
        "XML-055",
        Severity::Error,
        CheckCategory::XmlValidity,
        "Access control policies are well formed",
        shape,
        any_xml,
        results,
    );
    report(
        "XML-056",
        Severity::Error,
        CheckCategory::XmlValidity,
        "Time access control values are valid",
        time,
        any_time,
        results,
    );
    report(
        "XML-057",
        Severity::Error,
        CheckCategory::XmlValidity,
        "Every Rule and RuleRegex has a require attribute",
        missing,
        any_rule,
        results,
    );
}

/// The XML plugin allows exactly one rule or operator under `<AccessControl>`, at least two
/// under `AND` / `OR`, and exactly one under `NOT`.
fn xml_shape(policy: &AclNode, file: &str, problems: &mut Vec<Problem>) {
    let mut push = |line: usize, message: String, suggestion: &'static str, doc: &'static str| {
        problems.push(Problem {
            file: file.to_string(),
            line,
            message,
            suggestion,
            doc,
        });
    };
    if policy.children.len() != 1 {
        push(
            policy.line,
            format!(
                "<AccessControl> has {} rules or operators; it needs exactly one",
                policy.children.len()
            ),
            "Wrap several rules in an <AND> or <OR> element. A policy the SP cannot process denies all access",
            DOC_XML_ACL,
        );
    }
    for top in &policy.children {
        walk_operators(top, &mut push);
    }
}

fn walk_operators(
    node: &AclNode,
    push: &mut impl FnMut(usize, String, &'static str, &'static str),
) {
    if !XML_ELEMENTS.contains(&node.name.as_str()) {
        push(
            node.line,
            format!(
                "<{}> is not an element of the XML access control language",
                node.name
            ),
            "Use Rule, RuleRegex, AND, OR or NOT",
            DOC_XML_ACL,
        );
        return;
    }
    let n = node.children.len();
    match node.name.as_str() {
        "AND" if n < 2 => push(
            node.line,
            format!("<AND> has {n} child element(s); it needs two or more"),
            "Add the other rule, or use the single rule on its own",
            DOC_AND,
        ),
        "OR" if n < 2 => push(
            node.line,
            format!("<OR> has {n} child element(s); it needs two or more"),
            "Add the other rule, or use the single rule on its own",
            DOC_OR,
        ),
        "NOT" if n != 1 => push(
            node.line,
            format!("<NOT> has {n} child elements; it needs exactly one"),
            "Wrap several rules in an <AND> or <OR> inside the <NOT>",
            DOC_NOT,
        ),
        _ => {}
    }
    for child in &node.children {
        walk_operators(child, push);
    }
}

/// Valid `<Time>`-plugin content: the operator attribute, and each child's operator and value.
fn time_values(policy: &AclNode, file: &str, problems: &mut Vec<Problem>) {
    let mut bad = |line: usize, message: String, suggestion: &'static str| {
        problems.push(Problem {
            file: file.to_string(),
            line,
            message,
            suggestion,
            doc: DOC_TIME,
        });
    };
    if let Some(op) = policy.attr("operator") {
        if op != "AND" && op != "OR" {
            bad(
                policy.line,
                format!("Time access control operator is '{op}'"),
                "Use operator=\"AND\" or operator=\"OR\"",
            );
        }
    }
    for child in &policy.children {
        let text = child.text.trim();
        match child.name.as_str() {
            "TimeSinceAuthn" => {
                if !is_iso_duration(text) {
                    bad(
                        child.line,
                        format!("<TimeSinceAuthn> value '{text}' is not an ISO 8601 duration"),
                        "Use a duration such as PT1H",
                    );
                }
            }
            "Time" | "Year" | "Month" | "Day" | "Hour" | "Minute" | "Second" | "DayOfWeek" => {
                let mut parts = text.split_whitespace();
                let (op, value, extra) = (parts.next(), parts.next(), parts.next());
                let (Some(op), Some(value), None) = (op, value, extra) else {
                    bad(
                        child.line,
                        format!(
                            "<{}> needs an operator and a value, found '{text}'",
                            child.name
                        ),
                        "Write the operator (LT, LE, EQ, GE or GT), a space, then the value",
                    );
                    continue;
                };
                if !TIME_OPERATORS.contains(&op) {
                    bad(
                        child.line,
                        format!(
                            "<{}> operator '{op}' is not one of LT, LE, EQ, GE, GT",
                            child.name
                        ),
                        "Use LT, LE, EQ, GE or GT",
                    );
                }
                if let Some(problem) = time_value_problem(&child.name, value) {
                    bad(
                        child.line,
                        format!("<{}> {problem}", child.name),
                        "Fix the value",
                    );
                }
            }
            other => bad(
                child.line,
                format!("<{other}> is not an element of the Time access control plugin"),
                "Use TimeSinceAuthn, Time, Year, Month, Day, Hour, Minute, Second or DayOfWeek",
            ),
        }
    }
}

/// What is wrong with the value, if anything. Ranges are the documented ones.
fn time_value_problem(element: &str, value: &str) -> Option<String> {
    if element == "Time" {
        let ok = value.ends_with('Z') && chrono::DateTime::parse_from_rfc3339(value).is_ok();
        return (!ok)
            .then(|| format!("value '{value}' is not a UTC ISO 8601 timestamp ending in Z"));
    }
    let Ok(n) = value.parse::<i64>() else {
        return Some(format!("value '{value}' is not a whole number"));
    };
    let range = match element {
        "Month" => Some((1, 12)),
        "Hour" => Some((0, 23)),
        "DayOfWeek" => Some((0, 6)),
        _ => None,
    };
    match range {
        Some((lo, hi)) if n < lo || n > hi => {
            Some(format!("value {n} is outside the range {lo} to {hi}"))
        }
        _ => None,
    }
}

/// `P1Y2M3DT4H5M6S`, `P2W`: a leading P, then digits followed by unit letters.
fn is_iso_duration(text: &str) -> bool {
    let Some(rest) = text.strip_prefix('P') else {
        return false;
    };
    if rest.is_empty() || rest.ends_with('T') {
        return false;
    }
    let mut seen_digit = false;
    let mut in_time = false;
    for c in rest.chars() {
        match c {
            '0'..='9' | '.' => seen_digit = true,
            'T' if !in_time && !seen_digit => in_time = true,
            'Y' | 'M' | 'W' | 'D' | 'H' | 'S' if seen_digit => seen_digit = false,
            _ => return false,
        }
    }
    !seen_digit
}

/// REF-041: `require` must be an alias or the id of an attribute that attribute-map.xml defines.
pub fn references(config: &DiscoveredConfig, results: &mut Vec<CheckResult>) {
    let (Some(map), Some(sc)) = (&config.attribute_map, &config.shibboleth_config) else {
        return;
    };
    // Other extractors (Metadata, Assertion, a second XML file) create attributes this check
    // cannot see, so only judge a plain single-file setup.
    let simple = sc.attribute_extractor_types.iter().all(|t| t == "XML")
        && sc.attribute_extractor_paths.len() == 1
        && sc.attribute_extractor_paths[0].ends_with("attribute-map.xml");
    if !simple {
        return;
    }
    let known = |name: &str| {
        map.attributes
            .iter()
            .any(|a| a.id == name || a.aliases.iter().any(|x| x == name))
    };

    let files = access_control::load_all(config);
    let mut any_rule = false;
    let mut problems = Vec::new();
    for file in &files {
        for root in &file.roots {
            each_node(root, &mut |n| {
                if !matches!(n.name.as_str(), "Rule" | "RuleRegex") {
                    return;
                }
                let Some(require) = n.attr("require") else {
                    return; // XML-057
                };
                any_rule = true;
                if RULE_ALIASES.contains(&require) || known(require) {
                    return;
                }
                problems.push(Problem {
                    file: file.file.clone(),
                    line: n.line,
                    message: format!(
                        "<{}> requires '{require}', which attribute-map.xml does not define",
                        n.name
                    ),
                    suggestion: "Use the id (or an alias) of an attribute in attribute-map.xml. A rule on an unknown attribute never matches, so it denies everyone",
                    doc: if n.name == "Rule" { DOC_RULE } else { DOC_RULE_REGEX },
                });
            });
        }
    }
    if problems.is_empty() {
        if any_rule {
            results.push(CheckResult::pass(
                "REF-041",
                CheckCategory::CrossReferences,
                Severity::Warning,
                "Every access rule names an alias or a mapped attribute",
            ));
        }
        return;
    }
    for p in problems {
        results.push(
            CheckResult::fail(
                "REF-041",
                CheckCategory::CrossReferences,
                Severity::Warning,
                &p.message,
                Some(p.suggestion),
            )
            .with_location(&p.file, Some(p.line))
            .with_doc(p.doc),
        );
    }
}

/// OPS-083: the `authnContextDeclRef` alias of `<Rule>` is deprecated.
pub fn deprecations(config: &DiscoveredConfig, results: &mut Vec<CheckResult>) {
    let files = access_control::load_all(config);
    let mut any_rule = false;
    let mut found = Vec::new();
    for file in &files {
        for root in &file.roots {
            each_node(root, &mut |n| {
                if n.name != "Rule" {
                    return;
                }
                any_rule = true;
                if n.attr("require") == Some("authnContextDeclRef") {
                    found.push((file.file.clone(), n.line));
                }
            });
        }
    }
    if found.is_empty() {
        if any_rule {
            results.push(CheckResult::pass(
                "OPS-083",
                CheckCategory::Operational,
                Severity::Warning,
                "No access rule uses the deprecated authnContextDeclRef alias",
            ));
        }
        return;
    }
    for (file, line) in found {
        results.push(
            CheckResult::fail(
                "OPS-083",
                CheckCategory::Operational,
                Severity::Warning,
                "Access rule uses the deprecated authnContextDeclRef alias",
                Some("Use require=\"authnContextClassRef\" and match the class reference instead"),
            )
            .with_location(&file, Some(line))
            .with_doc(DOC_RULE),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{assert_absent, assert_outcome, config_from_xml, sp3_app};

    fn acl(body: &str) -> String {
        sp3_app("", &format!("<AccessControl>{body}</AccessControl>"))
    }

    fn all(xml: &str) -> Vec<CheckResult> {
        let (_dir, config) = config_from_xml(xml);
        let mut results = Vec::new();
        structure(&config, &mut results);
        references(&config, &mut results);
        deprecations(&config, &mut results);
        results
    }

    #[test]
    fn operators_need_enough_children() {
        let ok = all(&acl(
            r#"<AND><Rule require="valid-user"/><NOT><Rule require="user">x</Rule></NOT></AND>"#,
        ));
        assert_outcome(&ok, "XML-055", true);

        for body in [
            r#"<AND><Rule require="valid-user"/></AND>"#,
            r#"<OR><Rule require="valid-user"/></OR>"#,
            r#"<NOT><Rule require="user"/><Rule require="user"/></NOT>"#,
            r#"<Rule require="user"/><Rule require="valid-user"/>"#, // two roots
            "",                                                      // none
            r#"<Group/>"#,
        ] {
            assert_outcome(&all(&acl(body)), "XML-055", false);
        }
        assert_absent(&all(&sp3_app("", "")), "XML-055");
    }

    #[test]
    fn chaining_policies_are_not_judged_as_xml() {
        let xml = sp3_app(
            "",
            r#"<AccessControl type="Chaining" operator="AND"><AccessControl type="Time"><Hour>GE 8</Hour></AccessControl></AccessControl>"#,
        );
        let r = all(&xml);
        assert_absent(&r, "XML-055");
        assert_outcome(&r, "XML-056", true);
    }

    #[test]
    fn time_values_are_validated() {
        let time = |body: &str, attrs: &str| {
            all(&sp3_app(
                "",
                &format!(r#"<AccessControl type="Time" {attrs}>{body}</AccessControl>"#),
            ))
        };
        assert_outcome(
            &time("<Hour>GE 6</Hour><Minute>LE 30</Minute><TimeSinceAuthn>PT1H</TimeSinceAuthn><Time>LE 2030-05-24T10:00:00Z</Time>", r#"operator="OR""#),
            "XML-056",
            true,
        );
        for body in [
            "<Hour>GE 24</Hour>",
            "<Month>EQ 0</Month>",
            "<DayOfWeek>EQ 7</DayOfWeek>",
            "<Hour>AFTER 6</Hour>",
            "<Hour>6</Hour>",
            "<Hour>GE six</Hour>",
            "<TimeSinceAuthn>1 hour</TimeSinceAuthn>",
            "<Time>LE 2030-05-24T10:00:00</Time>",
            "<Weekday>EQ 1</Weekday>",
        ] {
            assert_outcome(&time(body, ""), "XML-056", false);
        }
        assert_outcome(
            &time("<Hour>GE 6</Hour>", r#"operator="XOR""#),
            "XML-056",
            false,
        );
    }

    #[test]
    fn iso_durations() {
        for ok in ["PT1H", "P1D", "P2W", "P1Y2M3DT4H5M6S", "PT0.5S"] {
            assert!(is_iso_duration(ok), "{ok}");
        }
        for bad in ["", "P", "PT", "1H", "PT1", "P1H1", "pt1h", "PTH", "P1DT"] {
            assert!(!is_iso_duration(bad), "{bad}");
        }
    }

    #[test]
    fn rules_need_require() {
        assert_outcome(
            &all(&acl(r#"<Rule require="user">x</Rule>"#)),
            "XML-057",
            true,
        );
        assert_outcome(&all(&acl(r#"<Rule>x</Rule>"#)), "XML-057", false);
        assert_outcome(&all(&acl(r#"<RuleRegex>x</RuleRegex>"#)), "XML-057", false);
    }

    #[test]
    fn deprecated_alias_is_flagged() {
        let r = all(&acl(r#"<Rule require="authnContextDeclRef">urn:x</Rule>"#));
        assert_outcome(&r, "OPS-083", false);
        assert_outcome(
            &all(&acl(r#"<Rule require="authnContextClassRef">urn:x</Rule>"#)),
            "OPS-083",
            true,
        );
    }

    #[test]
    fn unknown_attribute_in_rule() {
        let dir = std::env::temp_dir().join(format!("shibcheck-acl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let xml = sp3_app(
            "",
            r#"<AttributeExtractor type="XML" validate="true" path="attribute-map.xml"/>
<AccessControl><OR><Rule require="affiliation">a</Rule><Rule require="mail">b</Rule><Rule require="user">c</Rule></OR></AccessControl>"#,
        );
        std::fs::write(dir.join("shibboleth2.xml"), &xml).unwrap();
        std::fs::write(
            dir.join("attribute-map.xml"),
            r#"<Attributes xmlns="urn:mace:shibboleth:2.0:attribute-map">
<Attribute name="urn:oid:1" id="affiliation"/>
<Attribute name="urn:oid:2" id="eppn" aliases="mail"/>
</Attributes>"#,
        )
        .unwrap();
        let config = crate::config::discover(&dir).unwrap();
        let mut r = Vec::new();
        references(&config, &mut r);
        assert!(r.is_empty() || r.iter().all(|x| x.code == "REF-041"));
        assert_outcome(&r, "REF-041", true);

        // a rule on an attribute nobody maps
        let bad = xml.replace(r#"require="mail""#, r#"require="uid""#);
        std::fs::write(dir.join("shibboleth2.xml"), bad).unwrap();
        let config = crate::config::discover(&dir).unwrap();
        let mut r = Vec::new();
        references(&config, &mut r);
        assert_outcome(&r, "REF-041", false);

        // another extractor type means we cannot know every attribute: stay quiet
        let quiet = xml.replace(
            r#"<AttributeExtractor type="XML""#,
            r#"<AttributeExtractor type="Metadata"/><AttributeExtractor type="XML""#,
        );
        std::fs::write(
            dir.join("shibboleth2.xml"),
            quiet.replace(r#"require="mail""#, r#"require="uid""#),
        )
        .unwrap();
        let config = crate::config::discover(&dir).unwrap();
        let mut r = Vec::new();
        references(&config, &mut r);
        assert_absent(&r, "REF-041");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
