use super::collect_file_summary;
use crate::config::DiscoveredConfig;
use crate::result::{CheckCategory, CheckResult, CheckSummary, Severity};

pub fn print(results: &[CheckResult], summary: &CheckSummary, config: &DiscoveredConfig) {
    let base_dir = config.base_dir.display();

    let categories = [
        CheckCategory::XmlValidity,
        CheckCategory::CrossReferences,
        CheckCategory::Security,
        CheckCategory::Migration,
    ];

    let mut category_sections = String::new();
    for category in &categories {
        let cat_results: Vec<_> = results.iter().filter(|r| r.category == *category).collect();
        if cat_results.is_empty() {
            continue;
        }

        let passed = cat_results.iter().filter(|r| r.passed).count();
        let total = cat_results.len();

        category_sections.push_str(&format!(
            r#"<details open><summary class="category-header">{} <span class="count">{}/{} passed</span></summary><table><thead><tr><th>Status</th><th>Code</th><th>Message</th><th>Suggestion</th></tr></thead><tbody>"#,
            html_escape(&category.to_string()),
            passed,
            total,
        ));

        for result in &cat_results {
            let (badge_class, badge_text) = if result.passed {
                ("badge-pass", "PASS")
            } else {
                match result.severity {
                    Severity::Error => ("badge-error", "FAIL"),
                    Severity::Warning => ("badge-warning", "WARN"),
                    Severity::Info => ("badge-info", "INFO"),
                }
            };

            let suggestion_cell = if !result.passed {
                let mut cell = String::new();
                if let Some(ref s) = result.suggestion {
                    cell.push_str(&html_escape(s));
                }
                if let Some(ref url) = result.doc_url {
                    if !cell.is_empty() {
                        cell.push_str("<br>");
                    }
                    cell.push_str(&format!(
                        r#"<a href="{}" target="_blank" rel="noopener">docs</a>"#,
                        html_escape(url)
                    ));
                }
                cell
            } else {
                String::new()
            };

            category_sections.push_str(&format!(
                r#"<tr class="{}"><td><span class="badge {}">{}</span></td><td class="code">{}</td><td>{}</td><td>{}</td></tr>"#,
                if result.passed { "row-pass" } else { "row-fail" },
                badge_class,
                badge_text,
                html_escape(&result.code),
                html_escape(&result.message),
                suggestion_cell,
            ));
        }

        category_sections.push_str("</tbody></table></details>");
    }

    // Build files section
    let files = collect_file_summary(config);
    let mut files_section = String::new();
    if !files.is_empty() {
        files_section.push_str(
            r#"<details open><summary class="category-header">Files</summary><table><thead><tr><th>Status</th><th>Path</th><th>Kind</th></tr></thead><tbody>"#,
        );
        for file in &files {
            let (icon, row_class) = if file.found {
                ("&#x2713;", "row-pass")
            } else {
                ("&#x2717;", "row-fail")
            };
            let badge_class = if file.found {
                "badge-pass"
            } else {
                "badge-error"
            };
            files_section.push_str(&format!(
                r#"<tr class="{}"><td><span class="badge {}">{}</span></td><td class="code">{}</td><td>{}</td></tr>"#,
                row_class,
                badge_class,
                icon,
                html_escape(&file.path),
                html_escape(&file.kind),
            ));
        }
        files_section.push_str("</tbody></table></details>");
    }

    let summary_class = if summary.errors > 0 {
        "summary-error"
    } else if summary.warnings > 0 {
        "summary-warning"
    } else {
        "summary-pass"
    };

    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>shibcheck report — {base_dir}</title>
<style>
:root {{ --pass: #22c55e; --error: #ef4444; --warning: #f59e0b; --info: #3b82f6; --bg: #f8fafc; --card: #fff; --text: #1e293b; --muted: #64748b; --border: #e2e8f0; }}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; padding: 2rem; max-width: 1200px; margin: auto; }}
h1 {{ font-size: 1.5rem; margin-bottom: 0.25rem; }}
.subtitle {{ color: var(--muted); margin-bottom: 1.5rem; font-size: 0.9rem; }}
.summary {{ padding: 1rem 1.5rem; border-radius: 8px; font-weight: 600; margin-bottom: 1.5rem; }}
.summary-pass {{ background: #dcfce7; color: #166534; }}
.summary-warning {{ background: #fef9c3; color: #854d0e; }}
.summary-error {{ background: #fee2e2; color: #991b1b; }}
details {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 1rem; }}
.category-header {{ font-weight: 600; padding: 0.75rem 1rem; cursor: pointer; user-select: none; }}
.category-header .count {{ color: var(--muted); font-weight: 400; font-size: 0.85rem; }}
table {{ width: 100%; border-collapse: collapse; font-size: 0.875rem; }}
thead {{ background: var(--bg); }}
th {{ text-align: left; padding: 0.5rem 1rem; border-bottom: 2px solid var(--border); font-weight: 600; }}
td {{ padding: 0.5rem 1rem; border-bottom: 1px solid var(--border); vertical-align: top; }}
.code {{ font-family: monospace; white-space: nowrap; }}
.badge {{ display: inline-block; padding: 0.125rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 700; color: #fff; }}
.badge-pass {{ background: var(--pass); }}
.badge-error {{ background: var(--error); }}
.badge-warning {{ background: var(--warning); }}
.badge-info {{ background: var(--info); }}
.row-pass {{ opacity: 0.6; }}
a {{ color: var(--info); }}
@media print {{ body {{ padding: 0.5rem; }} details {{ break-inside: avoid; }} .row-pass {{ display: none; }} }}
</style>
</head>
<body>
<h1>shibcheck report</h1>
<p class="subtitle">{base_dir}</p>
<div class="summary {summary_class}">{total} checks &middot; {passed} passed &middot; {errors} errors &middot; {warnings} warnings &middot; {info} info</div>
{category_sections}
{files_section}
<footer style="margin-top:2rem;color:var(--muted);font-size:0.8rem;">Generated by shibcheck v{version}</footer>
</body>
</html>"##,
        base_dir = html_escape(&base_dir.to_string()),
        summary_class = summary_class,
        total = summary.total,
        passed = summary.passed,
        errors = summary.errors,
        warnings = summary.warnings,
        info = summary.info,
        category_sections = category_sections,
        files_section = files_section,
        version = env!("CARGO_PKG_VERSION"),
    );

    println!("{}", html);
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
