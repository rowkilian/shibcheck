use std::fs;
use std::path::Path;

use crate::result::CheckResult;

/// Fixable check codes and their descriptions.
const FIXABLE: &[&str] = &["SEC-001", "SEC-002", "SEC-003", "SEC-017"];

/// Returns true if any of the failed results are auto-fixable.
pub fn has_fixable(results: &[CheckResult]) -> bool {
    results
        .iter()
        .any(|r| !r.passed && FIXABLE.contains(&r.code.as_str()))
}

/// Apply safe auto-fixes to shibboleth2.xml for failed checks.
///
/// Creates a `.bak` backup before modifying the file.
/// Operates on the raw XML text (string-level patching) to avoid
/// reformatting or losing comments.
///
/// Returns a list of applied fix descriptions.
pub fn apply_fixes(results: &[CheckResult], shibboleth_xml: &Path) -> Vec<String> {
    if !shibboleth_xml.exists() {
        return vec![];
    }

    let failed_codes: Vec<&str> = results
        .iter()
        .filter(|r| !r.passed && FIXABLE.contains(&r.code.as_str()))
        .map(|r| r.code.as_str())
        .collect();

    if failed_codes.is_empty() {
        return vec![];
    }

    let original = match fs::read_to_string(shibboleth_xml) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Cannot read {}: {}", shibboleth_xml.display(), e);
            return vec![];
        }
    };

    // Create backup
    let backup = shibboleth_xml.with_extension("xml.bak");
    if let Err(e) = fs::write(&backup, &original) {
        eprintln!("Cannot create backup {}: {}", backup.display(), e);
        return vec![];
    }

    let mut content = original;
    let mut applied = Vec::new();

    // SEC-001: Add or set handlerSSL="true" on <Sessions>
    if failed_codes.contains(&"SEC-001") {
        if let Some(new) = fix_handler_ssl(&content) {
            content = new;
            applied.push("SEC-001: Set handlerSSL=\"true\" on Sessions".to_string());
        }
    }

    // SEC-002/003/017: Fix cookieProps on <Sessions>
    // These are related — we handle them together
    let needs_secure = failed_codes.contains(&"SEC-002");
    let needs_httponly = failed_codes.contains(&"SEC-003");
    let needs_samesite = failed_codes.contains(&"SEC-017");

    if needs_secure || needs_httponly || needs_samesite {
        if let Some(new) = fix_cookie_props(&content, needs_secure, needs_httponly, needs_samesite)
        {
            content = new;
            if needs_secure {
                applied.push("SEC-002: Added 'secure' to cookieProps".to_string());
            }
            if needs_httponly {
                applied.push("SEC-003: Added 'httpOnly' to cookieProps".to_string());
            }
            if needs_samesite {
                applied.push("SEC-017: Added 'SameSite=None' to cookieProps".to_string());
            }
        }
    }

    if !applied.is_empty() {
        if let Err(e) = fs::write(shibboleth_xml, &content) {
            eprintln!(
                "Cannot write {}: {} (backup at {})",
                shibboleth_xml.display(),
                e,
                backup.display()
            );
            return vec![];
        }
    }

    applied
}

/// Add or set handlerSSL="true" on the <Sessions> element.
fn fix_handler_ssl(content: &str) -> Option<String> {
    // Case 1: handlerSSL="false" → replace with true
    if content.contains("handlerSSL=\"false\"") {
        return Some(content.replace("handlerSSL=\"false\"", "handlerSSL=\"true\""));
    }
    // Case 2: <Sessions without handlerSSL → insert it
    if !content.contains("handlerSSL=") {
        if let Some(pos) = content.find("<Sessions") {
            let tag_end = pos + "<Sessions".len();
            let mut result = String::with_capacity(content.len() + 25);
            result.push_str(&content[..tag_end]);
            result.push_str(" handlerSSL=\"true\"");
            result.push_str(&content[tag_end..]);
            return Some(result);
        }
    }
    None
}

/// Add or fix cookieProps on the <Sessions> element.
fn fix_cookie_props(
    content: &str,
    need_secure: bool,
    need_httponly: bool,
    need_samesite: bool,
) -> Option<String> {
    // Build desired value: "secure; httpOnly; SameSite=None"
    // If cookieProps already exists, append missing parts
    if let Some(start) = content.find("cookieProps=\"") {
        let attr_start = start + "cookieProps=\"".len();
        let attr_end = content[attr_start..].find('"')? + attr_start;
        let current = &content[attr_start..attr_end];
        let lower = current.to_lowercase();

        let mut parts: Vec<&str> = Vec::new();
        if need_secure && !lower.contains("secure") {
            parts.push("secure");
        }
        if need_httponly && !lower.contains("httponly") {
            parts.push("httpOnly");
        }
        if need_samesite && !lower.contains("samesite") {
            parts.push("SameSite=None");
        }

        if parts.is_empty() {
            return None;
        }

        let new_value = if current.is_empty() {
            parts.join("; ")
        } else {
            format!("{}; {}", current, parts.join("; "))
        };

        let mut result = String::with_capacity(content.len() + 50);
        result.push_str(&content[..attr_start]);
        result.push_str(&new_value);
        result.push_str(&content[attr_end..]);
        Some(result)
    } else {
        // No cookieProps at all — insert on <Sessions>
        let mut value_parts = Vec::new();
        if need_secure {
            value_parts.push("secure");
        }
        if need_httponly {
            value_parts.push("httpOnly");
        }
        if need_samesite {
            value_parts.push("SameSite=None");
        }
        let value = value_parts.join("; ");

        if let Some(pos) = content.find("<Sessions") {
            let tag_end = pos + "<Sessions".len();
            let mut result = String::with_capacity(content.len() + 50);
            result.push_str(&content[..tag_end]);
            result.push_str(&format!(" cookieProps=\"{}\"", value));
            result.push_str(&content[tag_end..]);
            Some(result)
        } else {
            None
        }
    }
}
