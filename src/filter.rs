use crate::result::CheckResult;

/// Filter check results based on --check and --skip prefixes.
///
/// `include`: if Some, only checks whose code starts with one of these prefixes are kept.
/// `exclude`: if Some, checks whose code starts with one of these prefixes are removed.
/// Include is applied first, then exclude.
pub fn apply_filters(
    results: Vec<CheckResult>,
    include: Option<&[String]>,
    exclude: Option<&[String]>,
) -> Vec<CheckResult> {
    results
        .into_iter()
        .filter(|r| {
            if let Some(prefixes) = include {
                if !prefixes.iter().any(|p| r.code.starts_with(p.as_str())) {
                    return false;
                }
            }
            if let Some(prefixes) = exclude {
                if prefixes.iter().any(|p| r.code.starts_with(p.as_str())) {
                    return false;
                }
            }
            true
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result::{CheckCategory, Severity};

    fn make_result(code: &str) -> CheckResult {
        CheckResult::pass(code, CheckCategory::Security, Severity::Error, "test")
    }

    #[test]
    fn no_filters_keeps_all() {
        let results = vec![make_result("SEC-001"), make_result("XML-001")];
        let filtered = apply_filters(results, None, None);
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn include_filter() {
        let results = vec![
            make_result("SEC-001"),
            make_result("SEC-002"),
            make_result("XML-001"),
        ];
        let include = vec!["SEC".to_string()];
        let filtered = apply_filters(results, Some(&include), None);
        assert_eq!(filtered.len(), 2);
        assert!(filtered.iter().all(|r| r.code.starts_with("SEC")));
    }

    #[test]
    fn exclude_filter() {
        let results = vec![
            make_result("SEC-001"),
            make_result("XML-001"),
            make_result("REF-001"),
        ];
        let exclude = vec!["SEC".to_string()];
        let filtered = apply_filters(results, None, Some(&exclude));
        assert_eq!(filtered.len(), 2);
        assert!(filtered.iter().all(|r| !r.code.starts_with("SEC")));
    }

    #[test]
    fn include_and_exclude_combined() {
        let results = vec![
            make_result("SEC-001"),
            make_result("SEC-002"),
            make_result("XML-001"),
        ];
        let include = vec!["SEC".to_string()];
        let exclude = vec!["SEC-002".to_string()];
        let filtered = apply_filters(results, Some(&include), Some(&exclude));
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].code, "SEC-001");
    }
}
