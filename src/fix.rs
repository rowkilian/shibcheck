use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::model::shibboleth_config::SpVersion;
use crate::result::CheckResult;

/// Fixable check codes and what each fix does.
pub const FIXABLE: &[(&str, &str)] = &[
    ("SEC-001", "Set handlerSSL=\"true\" on <Sessions>"),
    (
        "SEC-002",
        "Add the secure flag to cookieProps on <Sessions>",
    ),
    (
        "SEC-003",
        "Add the httpOnly flag to cookieProps on <Sessions>",
    ),
    (
        "SEC-131",
        "Remove externalParameters from <Errors> (default is off)",
    ),
    (
        "SEC-133",
        "Remove checkSpoofing=\"false\" from <InProcess> (default is on)",
    ),
    (
        "SEC-134",
        "Remove normalizeRequest=\"false\" from <ISAPI> (default is on)",
    ),
];

/// One edit that was made (or, in a dry run, would be made).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedFix {
    pub codes: Vec<&'static str>,
    pub description: String,
    /// 1-based line of the element that changed
    pub line: usize,
}

/// The result of planning fixes against the text of shibboleth2.xml.
#[derive(Debug)]
pub struct FixPlan {
    pub original: String,
    pub fixed: String,
    pub applied: Vec<AppliedFix>,
}

/// Codes of failed, fixable results, in the order they first appear, without duplicates.
pub fn failed_fixable(results: &[CheckResult]) -> Vec<&'static str> {
    let mut codes = Vec::new();
    for r in results.iter().filter(|r| !r.passed) {
        if let Some((code, _)) = FIXABLE.iter().find(|(c, _)| *c == r.code) {
            if !codes.contains(code) {
                codes.push(*code);
            }
        }
    }
    codes
}

/// Plan the fixes for `codes` on the text of shibboleth2.xml. Pure: touches no files.
///
/// Edits stay inside the start tag of one element, so comments, formatting and line
/// numbers elsewhere in the file are unchanged. Only the first occurrence of each element
/// is edited, which is the one the checks read (not an `ApplicationOverride`).
pub fn plan(content: &str, codes: &[&str], version: SpVersion) -> FixPlan {
    let mut text = content.to_string();
    let mut applied = Vec::new();
    let wants = |c: &str| codes.contains(&c);

    if wants("SEC-001") {
        edit_tag(&mut text, "Sessions", &mut applied, |tag| {
            if attr_value(tag, "handlerSSL").as_deref() == Some("true") {
                return None;
            }
            Some((
                set_attr(tag, "handlerSSL", "true"),
                vec!["SEC-001"],
                "Set handlerSSL=\"true\"".to_string(),
            ))
        });
    }

    let need_secure = wants("SEC-002");
    let need_http_only = wants("SEC-003");
    if need_secure || need_http_only {
        edit_tag(&mut text, "Sessions", &mut applied, |tag| {
            let current = attr_value(tag, "cookieProps");
            let (value, codes) =
                fixed_cookie_props(current.as_deref(), need_secure, need_http_only, version)?;
            let description = format!("Set cookieProps=\"{value}\"");
            Some((set_attr(tag, "cookieProps", &value), codes, description))
        });
    }

    for (code, element, attr, bad_value) in [
        ("SEC-131", "Errors", "externalParameters", None),
        ("SEC-133", "InProcess", "checkSpoofing", Some("false")),
        ("SEC-134", "ISAPI", "normalizeRequest", Some("false")),
    ] {
        if !wants(code) {
            continue;
        }
        edit_tag(&mut text, element, &mut applied, |tag| {
            let value = attr_value(tag, attr)?;
            if bad_value.is_some_and(|b| b != value) {
                return None;
            }
            Some((
                remove_attr(tag, attr),
                vec![code],
                format!("Removed {attr}=\"{value}\""),
            ))
        });
    }

    FixPlan {
        original: content.to_string(),
        fixed: text,
        applied,
    }
}

/// Compute the new `cookieProps` value, or None when nothing needs to change.
///
/// SP3 has the `https` shorthand (secure plus httpOnly). SP2 only takes the literal cookie
/// attributes, so there the flags are spelled out.
fn fixed_cookie_props(
    current: Option<&str>,
    need_secure: bool,
    need_http_only: bool,
    version: SpVersion,
) -> Option<(String, Vec<&'static str>)> {
    let mut codes = Vec::new();
    if need_secure {
        codes.push("SEC-002");
    }
    if need_http_only {
        codes.push("SEC-003");
    }
    let sp3 = version != SpVersion::V2;
    let lower = current
        .map(|c| c.trim().to_lowercase())
        .filter(|c| !c.is_empty());

    // Not set, or only the plain "http" shorthand: replace it outright.
    if lower.is_none() || (sp3 && lower.as_deref() == Some("http")) {
        let value = if sp3 {
            "https".to_string()
        } else {
            "; path=/; secure; HttpOnly".to_string()
        };
        return Some((value, vec!["SEC-002", "SEC-003"]));
    }

    // A custom value: append only the missing flags and keep the rest.
    let current = current?.trim_end();
    let lower = lower?;
    if sp3 && lower == "https" {
        return None;
    }
    let mut value = current.to_string();
    let mut changed = Vec::new();
    if need_secure && !lower.contains("secure") {
        value.push_str("; secure");
        changed.push("SEC-002");
    }
    if need_http_only && !lower.contains("httponly") {
        value.push_str("; HttpOnly");
        changed.push("SEC-003");
    }
    if changed.is_empty() {
        None
    } else {
        Some((value, changed))
    }
}

/// Find the first `<element ...>` start tag and replace it with whatever `edit` returns.
fn edit_tag(
    text: &mut String,
    element: &str,
    applied: &mut Vec<AppliedFix>,
    edit: impl FnOnce(&str) -> Option<(String, Vec<&'static str>, String)>,
) {
    let Some((start, end)) = find_start_tag(text, element) else {
        return;
    };
    let Some((new_tag, codes, description)) = edit(&text[start..end]) else {
        return;
    };
    if new_tag == text[start..end] {
        return;
    }
    let line = text[..start].matches('\n').count() + 1;
    text.replace_range(start..end, &new_tag);
    applied.push(AppliedFix {
        codes,
        description: format!("<{element}>: {description}"),
        line,
    });
}

/// Byte range of the first start tag named `name`, skipping comments, CDATA, processing
/// instructions and the contents of quoted attribute values.
fn find_start_tag(content: &str, name: &str) -> Option<(usize, usize)> {
    let bytes = content.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'<' {
            i += 1;
            continue;
        }
        let rest = &content[i..];
        let skip_to = if rest.starts_with("<!--") {
            Some("-->")
        } else if rest.starts_with("<![CDATA[") {
            Some("]]>")
        } else if rest.starts_with("<?") {
            Some("?>")
        } else if rest.starts_with("<!") {
            Some(">")
        } else {
            None
        };
        if let Some(terminator) = skip_to {
            i += rest.find(terminator)? + terminator.len();
            continue;
        }
        let end = tag_end(content, i)?;
        let after_name = &content[i + 1..];
        let is_match = after_name.starts_with(name)
            && after_name[name.len()..]
                .chars()
                .next()
                .is_some_and(|c| c.is_whitespace() || c == '>' || c == '/');
        if is_match {
            return Some((i, end));
        }
        i = end;
    }
    None
}

/// Index just past the `>` that closes the tag starting at `start`.
fn tag_end(content: &str, start: usize) -> Option<usize> {
    let mut quote: Option<u8> = None;
    for (offset, &b) in content.as_bytes()[start..].iter().enumerate() {
        match quote {
            Some(q) if b == q => quote = None,
            Some(_) => {}
            None if b == b'"' || b == b'\'' => quote = Some(b),
            None if b == b'>' => return Some(start + offset + 1),
            None => {}
        }
    }
    None
}

/// Position of one attribute inside a start tag.
struct AttrSpan {
    /// from the whitespace before the name to just past the closing quote
    full: (usize, usize),
    /// the value between the quotes
    value: (usize, usize),
}

fn find_attr(tag: &str, name: &str) -> Option<AttrSpan> {
    let bytes = tag.as_bytes();
    // skip "<Name"
    let mut i = 1;
    while i < bytes.len() && !bytes[i].is_ascii_whitespace() && bytes[i] != b'>' && bytes[i] != b'/'
    {
        i += 1;
    }
    loop {
        let ws_start = i;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let name_start = i;
        while i < bytes.len()
            && !bytes[i].is_ascii_whitespace()
            && !matches!(bytes[i], b'=' | b'>' | b'/')
        {
            i += 1;
        }
        if i == name_start {
            return None; // reached '>' or '/>'
        }
        let attr_name = &tag[name_start..i];
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if bytes.get(i) != Some(&b'=') {
            continue; // attribute without a value; not valid XML, keep scanning
        }
        i += 1;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let quote = *bytes.get(i)?;
        if quote != b'"' && quote != b'\'' {
            return None;
        }
        let value_start = i + 1;
        let value_end = value_start + tag[value_start..].find(quote as char)?;
        i = value_end + 1;
        if attr_name == name {
            return Some(AttrSpan {
                full: (ws_start, i),
                value: (value_start, value_end),
            });
        }
    }
}

fn attr_value(tag: &str, name: &str) -> Option<String> {
    let span = find_attr(tag, name)?;
    Some(tag[span.value.0..span.value.1].to_string())
}

/// Replace the attribute's value, or insert the attribute right after the element name.
fn set_attr(tag: &str, name: &str, value: &str) -> String {
    let escaped = value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('"', "&quot;");
    if let Some(span) = find_attr(tag, name) {
        return format!(
            "{}{}{}",
            &tag[..span.value.0],
            escaped,
            &tag[span.value.1..]
        );
    }
    let name_end = tag[1..]
        .find(|c: char| c.is_whitespace() || c == '>' || c == '/')
        .map_or(tag.len(), |p| p + 1);
    format!(
        "{} {}=\"{}\"{}",
        &tag[..name_end],
        name,
        escaped,
        &tag[name_end..]
    )
}

fn remove_attr(tag: &str, name: &str) -> String {
    match find_attr(tag, name) {
        Some(span) => format!("{}{}", &tag[..span.full.0], &tag[span.full.1..]),
        None => tag.to_string(),
    }
}

/// Render the changed lines as `-old` / `+new` pairs with line numbers.
///
/// Fixes never add or remove newlines, so the two texts line up one to one.
pub fn render_diff(plan: &FixPlan) -> String {
    let mut out = String::new();
    for (n, (old, new)) in plan.original.lines().zip(plan.fixed.lines()).enumerate() {
        if old != new {
            out.push_str(&format!("{:>5} - {}\n{:>5} + {}\n", n + 1, old, n + 1, new));
        }
    }
    out
}

/// Path for a backup of `path` that does not overwrite an earlier one:
/// `shibboleth2.xml.bak`, then `.bak.1`, `.bak.2`, and so on.
pub fn backup_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".bak");
    let first = PathBuf::from(&name);
    if !first.exists() {
        return first;
    }
    (1..)
        .map(|n| PathBuf::from(format!("{}.{n}", first.display())))
        .find(|p| !p.exists())
        .expect("an unused backup name exists")
}

/// Write the fixed text, keeping a backup of the original unless `backup` is false.
/// The new file replaces the old one in a single rename, so a failure cannot leave
/// a half-written config. Returns the backup path when one was made.
pub fn write_plan(path: &Path, plan: &FixPlan, backup: bool) -> Result<Option<PathBuf>> {
    let backup_file = if backup {
        let target = backup_path(path);
        fs::write(&target, &plan.original)
            .with_context(|| format!("cannot create backup {}", target.display()))?;
        Some(target)
    } else {
        None
    };

    let mut tmp_name = path.as_os_str().to_owned();
    tmp_name.push(".shibcheck-tmp");
    let tmp = PathBuf::from(tmp_name);
    fs::write(&tmp, &plan.fixed).with_context(|| format!("cannot write {}", tmp.display()))?;
    if let Ok(meta) = fs::metadata(path) {
        let _ = fs::set_permissions(&tmp, meta.permissions());
    }
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("cannot replace {}", path.display()));
    }
    Ok(backup_file)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: &[&str] = &[
        "SEC-001", "SEC-002", "SEC-003", "SEC-131", "SEC-133", "SEC-134",
    ];

    fn fix(xml: &str, codes: &[&str], v: SpVersion) -> FixPlan {
        plan(xml, codes, v)
    }

    #[test]
    fn handler_ssl_is_set_or_inserted() {
        let p = fix(
            r#"<Sessions handlerSSL="false" lifetime="1"/>"#,
            &["SEC-001"],
            SpVersion::V3,
        );
        assert_eq!(p.fixed, r#"<Sessions handlerSSL="true" lifetime="1"/>"#);
        let p = fix(r#"<Sessions lifetime="1">"#, &["SEC-001"], SpVersion::V3);
        assert_eq!(p.fixed, r#"<Sessions handlerSSL="true" lifetime="1">"#);
        let p = fix("<Sessions>", &["SEC-001"], SpVersion::V3);
        assert_eq!(p.fixed, r#"<Sessions handlerSSL="true">"#);
    }

    #[test]
    fn single_quoted_attributes_keep_their_quotes() {
        let p = fix(
            "<Sessions handlerSSL='false'/>",
            &["SEC-001"],
            SpVersion::V3,
        );
        assert_eq!(p.fixed, "<Sessions handlerSSL='true'/>");
    }

    #[test]
    fn comments_and_cdata_are_not_edited() {
        let xml = "<!-- <Sessions handlerSSL=\"false\"> -->\n<Sessions handlerSSL=\"false\"/>";
        let p = fix(xml, &["SEC-001"], SpVersion::V3);
        assert!(p
            .fixed
            .starts_with("<!-- <Sessions handlerSSL=\"false\"> -->"));
        assert!(p.fixed.ends_with("<Sessions handlerSSL=\"true\"/>"));
        assert_eq!(p.applied[0].line, 2);
    }

    #[test]
    fn similarly_named_elements_are_not_matched() {
        let xml = r#"<SessionInitiator handlerSSL="false"/><Sessions/>"#;
        let p = fix(xml, &["SEC-001"], SpVersion::V3);
        assert!(p
            .fixed
            .contains(r#"<SessionInitiator handlerSSL="false"/>"#));
        assert!(p.fixed.contains(r#"<Sessions handlerSSL="true"/>"#));
    }

    #[test]
    fn handler_ssl_elsewhere_does_not_block_the_fix() {
        let xml = r#"<Other handlerSSL="x"/><Sessions/>"#;
        let p = fix(xml, &["SEC-001"], SpVersion::V3);
        assert!(p.fixed.contains(r#"<Sessions handlerSSL="true"/>"#));
    }

    #[test]
    fn gt_inside_a_quoted_value_does_not_end_the_tag() {
        let xml = r#"<Sessions note="a>b" handlerSSL="false"/>"#;
        let p = fix(xml, &["SEC-001"], SpVersion::V3);
        assert_eq!(p.fixed, r#"<Sessions note="a>b" handlerSSL="true"/>"#);
    }

    #[test]
    fn sp3_cookie_props_use_the_https_shorthand() {
        for current in ["", r#" cookieProps="http""#] {
            let xml = format!("<Sessions{current}/>");
            let p = fix(&xml, &["SEC-002", "SEC-003"], SpVersion::V3);
            assert_eq!(p.fixed, r#"<Sessions cookieProps="https"/>"#);
        }
    }

    #[test]
    fn sp2_cookie_props_are_spelled_out() {
        let p = fix("<Sessions/>", &["SEC-002", "SEC-003"], SpVersion::V2);
        assert_eq!(
            p.fixed,
            r#"<Sessions cookieProps="; path=/; secure; HttpOnly"/>"#
        );
    }

    #[test]
    fn empty_cookie_props_count_as_unset() {
        let p = fix(r#"<Sessions cookieProps=""/>"#, &["SEC-002"], SpVersion::V2);
        assert_eq!(
            p.fixed,
            r#"<Sessions cookieProps="; path=/; secure; HttpOnly"/>"#
        );
    }

    #[test]
    fn custom_cookie_props_get_only_the_missing_flag() {
        let xml = r#"<Sessions cookieProps="; path=/; HttpOnly"/>"#;
        let p = fix(xml, &["SEC-002"], SpVersion::V3);
        assert_eq!(
            p.fixed,
            r#"<Sessions cookieProps="; path=/; HttpOnly; secure"/>"#
        );
        let xml = r#"<Sessions cookieProps="; path=/; secure"/>"#;
        let p = fix(xml, &["SEC-003"], SpVersion::V3);
        assert_eq!(
            p.fixed,
            r#"<Sessions cookieProps="; path=/; secure; HttpOnly"/>"#
        );
        assert_eq!(p.applied[0].codes, vec!["SEC-003"]);
    }

    #[test]
    fn compliant_cookie_props_are_left_alone() {
        let xml = r#"<Sessions cookieProps="https"/>"#;
        let p = fix(xml, &["SEC-002", "SEC-003"], SpVersion::V3);
        assert!(p.applied.is_empty());
        assert_eq!(p.fixed, xml);
    }

    #[test]
    fn default_restoring_fixes_remove_the_attribute() {
        let xml = r#"<Errors externalParameters="true" supportContact="a"/><InProcess checkSpoofing="false" logger="x"/><ISAPI normalizeRequest="false"/>"#;
        let p = fix(xml, ALL, SpVersion::V3);
        assert!(p.fixed.contains(r#"<Errors supportContact="a"/>"#));
        assert!(p.fixed.contains(r#"<InProcess logger="x"/>"#));
        assert!(p.fixed.contains("<ISAPI/>"));
    }

    #[test]
    fn values_that_are_already_fine_are_not_removed() {
        let xml = r#"<InProcess checkSpoofing="true"/>"#;
        let p = fix(xml, &["SEC-133"], SpVersion::V3);
        assert!(p.applied.is_empty());
    }

    #[test]
    fn fixing_twice_changes_nothing_the_second_time() {
        let xml = "<Sessions/>\n<Errors externalParameters=\"true\"/>";
        let first = fix(xml, ALL, SpVersion::V3);
        let second = fix(&first.fixed, ALL, SpVersion::V3);
        assert!(second.applied.is_empty());
        assert_eq!(second.fixed, first.fixed);
    }

    #[test]
    fn diff_shows_changed_lines_with_numbers() {
        let xml = "<a/>\n<Sessions handlerSSL=\"false\"/>\n";
        let p = fix(xml, &["SEC-001"], SpVersion::V3);
        let diff = render_diff(&p);
        assert!(diff.contains("2 - <Sessions handlerSSL=\"false\"/>"));
        assert!(diff.contains("2 + <Sessions handlerSSL=\"true\"/>"));
        assert!(!diff.contains("<a/>"));
    }

    #[test]
    fn backups_do_not_overwrite_each_other() {
        let dir = std::env::temp_dir().join(format!("shibcheck-bak-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("shibboleth2.xml");
        fs::write(&file, "v1").unwrap();
        let p = FixPlan {
            original: "v1".into(),
            fixed: "v2".into(),
            applied: vec![],
        };
        let first = write_plan(&file, &p, true).unwrap().unwrap();
        let second = write_plan(&file, &p, true).unwrap().unwrap();
        assert_ne!(first, second);
        assert!(first.ends_with("shibboleth2.xml.bak"));
        assert_eq!(fs::read_to_string(&file).unwrap(), "v2");
        assert!(!dir.join("shibboleth2.xml.shibcheck-tmp").exists());
        fs::remove_dir_all(&dir).unwrap();
    }
}
