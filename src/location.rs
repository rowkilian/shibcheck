/// Find the 1-based line number of the first occurrence of `needle` in `content`.
pub fn find_line(content: &str, needle: &str) -> Option<usize> {
    content
        .find(needle)
        .map(|pos| content[..pos].bytes().filter(|&b| b == b'\n').count() + 1)
}

/// Find the 1-based line number of `<element_name` optionally narrowed by an attribute value.
///
/// When `attr_name` and `attr_value` are both provided, matches the first
/// `<element_name ... attr_name="attr_value"` on the same opening tag.
pub fn find_element_line(
    content: &str,
    element_name: &str,
    attr_name: Option<&str>,
    attr_value: Option<&str>,
) -> Option<usize> {
    let tag_open = format!("<{}", element_name);

    for (byte_offset, _) in content.match_indices(&tag_open) {
        // Check the char right after the element name is a delimiter (space, >, /, newline)
        let after = byte_offset + tag_open.len();
        if after < content.len() {
            let next_char = content.as_bytes()[after];
            if next_char != b' '
                && next_char != b'\t'
                && next_char != b'\n'
                && next_char != b'\r'
                && next_char != b'>'
                && next_char != b'/'
            {
                continue; // e.g., <SessionInitiator matching <Session
            }
        }

        if let (Some(attr), Some(val)) = (attr_name, attr_value) {
            // Find the end of this opening tag (> or />)
            let tag_end = content[byte_offset..]
                .find('>')
                .map(|p| byte_offset + p)
                .unwrap_or(content.len());
            let tag_text = &content[byte_offset..tag_end];
            let needle = format!("{}=\"{}\"", attr, val);
            let needle_sq = format!("{}='{}'", attr, val);
            if !tag_text.contains(&needle) && !tag_text.contains(&needle_sq) {
                continue;
            }
        }

        let line = content[..byte_offset]
            .bytes()
            .filter(|&b| b == b'\n')
            .count()
            + 1;
        return Some(line);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_line_basic() {
        let content = "line1\nline2\nfoo bar\nline4";
        assert_eq!(find_line(content, "foo"), Some(3));
        assert_eq!(find_line(content, "line1"), Some(1));
        assert_eq!(find_line(content, "line4"), Some(4));
        assert_eq!(find_line(content, "nope"), None);
    }

    #[test]
    fn find_element_line_basic() {
        let xml = r#"<SPConfig>
  <ApplicationDefaults entityID="https://sp.example.org">
    <Sessions handlerSSL="true">
      <SSO>SAML2</SSO>
    </Sessions>
  </ApplicationDefaults>
</SPConfig>"#;
        assert_eq!(find_element_line(xml, "Sessions", None, None), Some(3));
        assert_eq!(find_element_line(xml, "SSO", None, None), Some(4));
        assert_eq!(
            find_element_line(xml, "ApplicationDefaults", None, None),
            Some(2)
        );
    }

    #[test]
    fn find_element_line_with_attr() {
        let xml = r#"<SPConfig>
  <MetadataProvider type="Chaining">
    <MetadataProvider type="XML" uri="https://idp.example.org/metadata"/>
    <MetadataProvider type="XML" path="local.xml"/>
  </MetadataProvider>
</SPConfig>"#;
        assert_eq!(
            find_element_line(xml, "MetadataProvider", Some("type"), Some("Chaining")),
            Some(2)
        );
        assert_eq!(
            find_element_line(xml, "MetadataProvider", Some("path"), Some("local.xml")),
            Some(4)
        );
    }

    #[test]
    fn find_element_no_prefix_match() {
        // <SessionInitiator should NOT match when searching for <Session
        let xml = "<Sessions>\n  <SessionInitiator type=\"SAML2\"/>\n</Sessions>";
        assert_eq!(find_element_line(xml, "Sessions", None, None), Some(1));
        assert_eq!(
            find_element_line(xml, "SessionInitiator", None, None),
            Some(2)
        );
    }
}
