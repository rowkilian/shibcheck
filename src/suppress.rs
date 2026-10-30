//! Silence findings you have reviewed and accepted.
//!
//! Two mechanisms:
//! - `<!-- shibcheck-ignore SEC-133: reason -->` hides the listed checks for the element that
//!   follows the comment. `<!-- shibcheck-ignore-file SEC-017: reason -->` hides them for
//!   the whole configuration. Codes may be prefixes (`SEC`, `SEC-1`), like `--check`.
//! - A baseline file (see [`crate::baseline`]) hides findings that already existed.
//!
//! Only failed results are hidden. The caller reports how many were hidden.

use std::collections::HashMap;
use std::path::Path;

use crate::result::CheckResult;

/// Directives found in one XML file.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Directives {
    /// Codes hidden everywhere (`shibcheck-ignore-file`)
    pub file_wide: Vec<String>,
    /// `(line of the element, codes)` for `shibcheck-ignore`
    pub by_line: Vec<(usize, Vec<String>)>,
}

fn matches(codes: &[String], code: &str) -> bool {
    codes.iter().any(|p| code.starts_with(p.as_str()))
}

impl Directives {
    fn hides(&self, code: &str, line: Option<usize>) -> bool {
        matches(&self.file_wide, code)
            || line.is_some_and(|l| {
                self.by_line
                    .iter()
                    .any(|(at, codes)| *at == l && matches(codes, code))
            })
    }
}

/// Read `shibcheck-ignore` comments from XML text.
pub fn parse_directives(content: &str) -> Directives {
    let mut found = Directives::default();
    let mut pending: Vec<String> = Vec::new();
    let mut line = 1usize;
    let mut rest = content;

    while let Some(lt) = rest.find('<') {
        line += rest[..lt].matches('\n').count();
        rest = &rest[lt..];

        if let Some(after) = rest.strip_prefix("<!--") {
            let end = after.find("-->").unwrap_or(after.len());
            let body = &after[..end];
            let (file_wide, codes) = parse_comment(body);
            match (file_wide, codes) {
                (_, None) => {}
                (true, Some(codes)) => found.file_wide.extend(codes),
                (false, Some(codes)) => pending.extend(codes),
            }
            line += body.matches('\n').count();
            rest = &after[(end + 3).min(after.len())..];
            continue;
        }
        if let Some(after) = rest.strip_prefix("<![CDATA[") {
            let end = after.find("]]>").map_or(after.len(), |p| p + 3);
            line += after[..end].matches('\n').count();
            rest = &after[end..];
            continue;
        }
        let is_element = rest[1..].chars().next().is_some_and(char::is_alphabetic);
        if is_element && !pending.is_empty() {
            found.by_line.push((line, std::mem::take(&mut pending)));
        }
        rest = &rest[1..];
    }
    found
}

/// Returns `(is_file_wide, codes)`; codes is None when the comment is not a directive.
fn parse_comment(body: &str) -> (bool, Option<Vec<String>>) {
    let body = body.trim();
    let (file_wide, args) = if let Some(a) = body.strip_prefix("shibcheck-ignore-file") {
        (true, a)
    } else if let Some(a) = body.strip_prefix("shibcheck-ignore") {
        (false, a)
    } else {
        return (false, None);
    };
    // The text after ':' is the reason.
    let list = args.split(':').next().unwrap_or("");
    let codes: Vec<String> = list
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter(|c| !c.is_empty())
        .map(str::to_string)
        .collect();
    (file_wide, Some(codes).filter(|c| !c.is_empty()))
}

/// Remove failed results that a `shibcheck-ignore` comment covers.
/// Returns the remaining results and the number hidden.
pub fn apply_directives(
    results: Vec<CheckResult>,
    base_dir: &Path,
    main_xml: &Path,
) -> (Vec<CheckResult>, usize) {
    let mut cache: HashMap<String, Directives> = HashMap::new();
    let main_file = main_xml
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_default();
    let load = |file: &str| -> Directives {
        // Reading the file again for every result would be slow, so keep what we parsed.
        let path = if file == main_file {
            main_xml.to_path_buf()
        } else {
            base_dir.join(file)
        };
        std::fs::read_to_string(path)
            .map(|c| parse_directives(&c))
            .unwrap_or_default()
    };

    // File-wide comments in shibboleth2.xml also cover results that have no location.
    let global = load(&main_file);
    let mut hidden = 0;
    let kept = results
        .into_iter()
        .filter(|r| {
            if r.passed {
                return true;
            }
            let suppressed = match &r.location {
                Some(loc) => {
                    let d = cache
                        .entry(loc.file.clone())
                        .or_insert_with(|| load(&loc.file));
                    d.hides(&r.code, loc.line) || global.hides(&r.code, None)
                }
                None => global.hides(&r.code, None),
            };
            if suppressed {
                hidden += 1;
            }
            !suppressed
        })
        .collect();
    (kept, hidden)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result::{CheckCategory, Severity, SourceLocation};

    #[test]
    fn directive_targets_the_next_element() {
        let xml =
            "<a>\n  <!-- shibcheck-ignore SEC-133: test rig -->\n  <InProcess\n    x=\"1\"/>\n</a>";
        let d = parse_directives(xml);
        assert_eq!(d.by_line, vec![(3, vec!["SEC-133".to_string()])]);
        assert!(d.file_wide.is_empty());
    }

    #[test]
    fn several_codes_and_stacked_comments() {
        let xml = "<!-- shibcheck-ignore SEC-001, SEC-002 -->\n<!-- shibcheck-ignore OPS: noisy -->\n<Sessions/>";
        let d = parse_directives(xml);
        assert_eq!(
            d.by_line,
            vec![(
                3,
                vec![
                    "SEC-001".to_string(),
                    "SEC-002".to_string(),
                    "OPS".to_string()
                ]
            )]
        );
    }

    #[test]
    fn file_wide_and_unrelated_comments() {
        let xml = "<!-- just a note -->\n<!-- shibcheck-ignore-file SEC-017: legacy -->\n<a/>";
        let d = parse_directives(xml);
        assert_eq!(d.file_wide, vec!["SEC-017".to_string()]);
        assert!(d.by_line.is_empty());
    }

    #[test]
    fn a_directive_with_no_codes_does_nothing() {
        assert_eq!(
            parse_directives("<!-- shibcheck-ignore -->\n<a/>"),
            Directives::default()
        );
    }

    #[test]
    fn line_counting_survives_comments_and_cdata() {
        let xml = "<!-- a\nb -->\n<![CDATA[x\ny]]>\n<!-- shibcheck-ignore SEC-1 -->\n<Target/>";
        let d = parse_directives(xml);
        assert_eq!(d.by_line[0].0, 6);
    }

    fn failed(code: &str, line: Option<usize>) -> CheckResult {
        let mut r = CheckResult::fail(code, CheckCategory::Security, Severity::Warning, "m", None);
        r.location = Some(SourceLocation {
            file: "shibboleth2.xml".into(),
            line,
        });
        r
    }

    #[test]
    fn only_matching_failed_results_are_hidden() {
        let dir = std::env::temp_dir().join(format!("shibcheck-ign-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let xml = dir.join("shibboleth2.xml");
        std::fs::write(
            &xml,
            "<!-- shibcheck-ignore-file OPS-001 -->\n<a/>\n<!-- shibcheck-ignore SEC-133 -->\n<InProcess/>\n<Other/>\n",
        )
        .unwrap();
        let passed = CheckResult::pass("SEC-133", CheckCategory::Security, Severity::Warning, "ok");
        let results = vec![
            failed("SEC-133", Some(4)), // hidden: next element
            failed("SEC-133", Some(5)), // kept: other element
            failed("SEC-134", Some(4)), // kept: other code
            failed("OPS-001", Some(5)), // hidden: file-wide
            passed,                     // kept: passed
        ];
        let (kept, hidden) = apply_directives(results, &dir, &xml);
        assert_eq!(hidden, 2);
        assert_eq!(kept.len(), 3);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
