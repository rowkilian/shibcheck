//! A baseline records the findings that exist today so later runs report only new ones.
//!
//! Entries match on check code, file and message, not on line number, so edits elsewhere in
//! the file do not break them. A message that embeds a changing value (such as days until a
//! certificate expires) shows up as a new finding when the value changes.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::result::CheckResult;

const VERSION: u32 = 1;
pub const DEFAULT_FILE: &str = ".shibcheck-baseline.json";

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone, PartialOrd, Ord)]
pub struct Entry {
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    pub message: String,
}

impl Entry {
    fn of(r: &CheckResult) -> Self {
        Entry {
            code: r.code.clone(),
            file: r.location.as_ref().map(|l| l.file.clone()),
            message: r.message.clone(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Baseline {
    pub version: u32,
    pub entries: Vec<Entry>,
}

/// What applying a baseline did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Applied {
    /// failed results hidden because the baseline lists them
    pub hidden: usize,
    /// baseline entries that no longer match any failure
    pub stale: usize,
}

/// Record every failed result.
pub fn create(results: &[CheckResult]) -> Baseline {
    let mut entries: Vec<Entry> = results
        .iter()
        .filter(|r| !r.passed)
        .map(Entry::of)
        .collect();
    entries.sort();
    Baseline {
        version: VERSION,
        entries,
    }
}

pub fn save(baseline: &Baseline, path: &Path) -> Result<()> {
    let mut json = serde_json::to_string_pretty(baseline)?;
    json.push('\n');
    std::fs::write(path, json).with_context(|| format!("cannot write {}", path.display()))
}

pub fn load(path: &Path) -> Result<Baseline> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read baseline {}", path.display()))?;
    let baseline: Baseline = serde_json::from_str(&text)
        .with_context(|| format!("{} is not a shibcheck baseline", path.display()))?;
    if baseline.version != VERSION {
        bail!(
            "{} has baseline version {}, this shibcheck reads version {}",
            path.display(),
            baseline.version,
            VERSION
        );
    }
    Ok(baseline)
}

/// Drop failed results the baseline lists. Each entry hides one result, so a second
/// identical finding that appears later is still reported.
pub fn apply(results: Vec<CheckResult>, baseline: &Baseline) -> (Vec<CheckResult>, Applied) {
    let mut budget: HashMap<&Entry, usize> = HashMap::new();
    for e in &baseline.entries {
        *budget.entry(e).or_insert(0) += 1;
    }
    let mut applied = Applied::default();
    let kept = results
        .into_iter()
        .filter(|r| {
            if r.passed {
                return true;
            }
            let entry = Entry::of(r);
            match budget.get_mut(&entry) {
                Some(n) if *n > 0 => {
                    *n -= 1;
                    applied.hidden += 1;
                    false
                }
                _ => true,
            }
        })
        .collect();
    applied.stale = budget.values().sum();
    (kept, applied)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result::{CheckCategory, Severity, SourceLocation};

    fn failed(code: &str, msg: &str, line: usize) -> CheckResult {
        let mut r = CheckResult::fail(code, CheckCategory::Security, Severity::Warning, msg, None);
        r.location = Some(SourceLocation {
            file: "shibboleth2.xml".into(),
            line: Some(line),
        });
        r
    }

    #[test]
    fn known_findings_are_hidden_and_new_ones_stay() {
        let before = vec![failed("SEC-001", "a", 3), failed("SEC-002", "b", 4)];
        let baseline = create(&before);
        let now = vec![
            failed("SEC-001", "a", 30), // moved: still hidden
            failed("SEC-003", "c", 5),  // new
        ];
        let (kept, applied) = apply(now, &baseline);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].code, "SEC-003");
        assert_eq!(
            applied,
            Applied {
                hidden: 1,
                stale: 1
            }
        );
    }

    #[test]
    fn a_repeat_of_a_baselined_finding_is_reported() {
        let baseline = create(&[failed("SEC-001", "a", 3)]);
        let now = vec![failed("SEC-001", "a", 3), failed("SEC-001", "a", 9)];
        let (kept, applied) = apply(now, &baseline);
        assert_eq!(kept.len(), 1);
        assert_eq!(applied.hidden, 1);
    }

    #[test]
    fn passed_results_are_never_recorded() {
        let ok = CheckResult::pass("SEC-001", CheckCategory::Security, Severity::Warning, "a");
        assert!(create(&[ok]).entries.is_empty());
    }

    #[test]
    fn save_and_load_round_trip() {
        let dir = std::env::temp_dir().join(format!("shibcheck-bl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join(DEFAULT_FILE);
        let baseline = create(&[failed("SEC-001", "a", 3)]);
        save(&baseline, &file).unwrap();
        assert_eq!(load(&file).unwrap().entries, baseline.entries);

        std::fs::write(&file, r#"{"version":99,"entries":[]}"#).unwrap();
        assert!(load(&file).unwrap_err().to_string().contains("version 99"));
        std::fs::write(&file, "nope").unwrap();
        assert!(load(&file).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
