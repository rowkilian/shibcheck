//! Read `<AccessControl>` policies from shibboleth2.xml and from stand-alone policy files.
//!
//! A policy is a small tree of `Rule`, `RuleRegex`, `AND`, `OR`, `NOT` (the XML plugin) or
//! time rules. This keeps the tree as plain nodes so checks can walk it.

use quick_xml::events::{BytesStart, Event};
use quick_xml::reader::Reader;

use crate::config::DiscoveredConfig;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AclNode {
    pub name: String,
    pub attrs: Vec<(String, String)>,
    /// trimmed text directly inside the element
    pub text: String,
    pub children: Vec<AclNode>,
    /// 1-based line of the start tag
    pub line: usize,
}

impl AclNode {
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// The `<AccessControl>` elements found in one file.
#[derive(Debug)]
pub struct AclFile {
    pub file: String,
    pub roots: Vec<AclNode>,
}

fn local_name(e: &BytesStart) -> String {
    let name = String::from_utf8_lossy(e.name().as_ref()).into_owned();
    name.rsplit(':').next().unwrap_or(&name).to_string()
}

fn node_of(e: &BytesStart, line: usize) -> AclNode {
    let attrs = e
        .attributes()
        .flatten()
        .map(|a| {
            let key = String::from_utf8_lossy(a.key.as_ref()).into_owned();
            let value = a
                .unescape_value()
                .map(|v| v.into_owned())
                .unwrap_or_else(|_| String::from_utf8_lossy(&a.value).into_owned());
            (key, value)
        })
        .collect();
    AclNode {
        name: local_name(e),
        attrs,
        text: String::new(),
        children: Vec::new(),
        line,
    }
}

/// Every outermost `<AccessControl>` element in `xml`, with its whole subtree.
/// Malformed XML yields whatever was read before the error.
pub fn parse_roots(xml: &str) -> Vec<AclNode> {
    let mut reader = Reader::from_str(xml);
    let mut roots = Vec::new();
    let mut stack: Vec<AclNode> = Vec::new();
    let mut counted_to = 0usize;
    let mut line = 1usize;

    loop {
        let start = reader.buffer_position() as usize;
        let event = reader.read_event();
        // count newlines up to the start of this event
        if start > counted_to && start <= xml.len() {
            line += xml[counted_to..start].matches('\n').count();
            counted_to = start;
        }
        // the event may be preceded by whitespace that belongs to it; the tag itself starts
        // at the first '<' at or after `start`
        let tag_line = match xml[start.min(xml.len())..].find('<') {
            Some(p) => line + xml[start..start + p].matches('\n').count(),
            None => line,
        };
        match event {
            Err(_) | Ok(Event::Eof) => break,
            Ok(Event::Start(e)) => {
                if !stack.is_empty() || local_name(&e) == "AccessControl" {
                    stack.push(node_of(&e, tag_line));
                }
            }
            Ok(Event::Empty(e)) => {
                if !stack.is_empty() {
                    let node = node_of(&e, tag_line);
                    if let Some(top) = stack.last_mut() {
                        top.children.push(node);
                    }
                } else if local_name(&e) == "AccessControl" {
                    roots.push(node_of(&e, tag_line));
                }
            }
            Ok(Event::Text(t)) => {
                if let Some(top) = stack.last_mut() {
                    if let Ok(text) = t.unescape() {
                        let text = text.trim();
                        if !text.is_empty() {
                            if !top.text.is_empty() {
                                top.text.push(' ');
                            }
                            top.text.push_str(text);
                        }
                    }
                }
            }
            Ok(Event::End(_)) => {
                if let Some(done) = stack.pop() {
                    match stack.last_mut() {
                        Some(parent) => parent.children.push(done),
                        None => roots.push(done),
                    }
                }
            }
            _ => {}
        }
    }
    roots
}

/// Policies in shibboleth2.xml and in the other XML files next to it.
pub fn load_all(config: &DiscoveredConfig) -> Vec<AclFile> {
    let mut files = Vec::new();
    if let Some(xml) = config.shibboleth_xml_content.as_deref() {
        let roots = parse_roots(xml);
        if !roots.is_empty() {
            files.push(AclFile {
                file: file_name(&config.shibboleth_xml_path),
                roots,
            });
        }
    }
    for path in &config.other_xml_files {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        if !text.contains("AccessControl") {
            continue;
        }
        let roots = parse_roots(&text);
        if !roots.is_empty() {
            files.push(AclFile {
                file: file_name(path),
                roots,
            });
        }
    }
    files
}

fn file_name(path: &std::path::Path) -> String {
    path.file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_nested_rules_text_and_lines() {
        let xml = r#"<Host>
  <AccessControl>
    <AND>
      <Rule require="affiliation">staff@example.org</Rule>
      <NOT><Rule require="user">bad</Rule></NOT>
    </AND>
  </AccessControl>
</Host>"#;
        let roots = parse_roots(xml);
        assert_eq!(roots.len(), 1);
        let root = &roots[0];
        assert_eq!((root.name.as_str(), root.line), ("AccessControl", 2));
        let and = &root.children[0];
        assert_eq!(and.children.len(), 2);
        assert_eq!(and.children[0].attr("require"), Some("affiliation"));
        assert_eq!(and.children[0].text, "staff@example.org");
        assert_eq!(and.children[0].line, 4);
        assert_eq!(and.children[1].children[0].line, 5);
    }

    #[test]
    fn handles_empty_roots_prefixes_and_garbage() {
        assert_eq!(parse_roots("<a><AccessControl/></a>").len(), 1);
        let xml = r#"<ac:AccessControl xmlns:ac="urn:x"><ac:Rule require="valid-user"/></ac:AccessControl>"#;
        let roots = parse_roots(xml);
        assert_eq!(roots[0].children[0].name, "Rule");
        assert!(parse_roots("<<<").is_empty());
        assert!(parse_roots("<AccessControl><Rule").len() <= 1);
    }

    #[test]
    fn nested_policies_stay_inside_their_root() {
        let xml = r#"<AccessControl type="Chaining"><AccessControl type="Time"><Hour>GE 8</Hour></AccessControl></AccessControl>"#;
        let roots = parse_roots(xml);
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].children[0].attr("type"), Some("Time"));
        assert_eq!(roots[0].children[0].children[0].text, "GE 8");
    }
}
