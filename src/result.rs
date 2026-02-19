use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Error,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Warning => write!(f, "WARNING"),
            Severity::Error => write!(f, "ERROR"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckCategory {
    XmlValidity,
    CrossReferences,
    Security,
}

impl std::fmt::Display for CheckCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckCategory::XmlValidity => write!(f, "XML Validity"),
            CheckCategory::CrossReferences => write!(f, "Cross-file References"),
            CheckCategory::Security => write!(f, "Security"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CheckResult {
    pub code: String,
    pub category: CheckCategory,
    pub severity: Severity,
    pub passed: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggestion: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doc_url: Option<String>,
}

impl CheckResult {
    pub fn pass(code: &str, category: CheckCategory, severity: Severity, message: &str) -> Self {
        Self {
            code: code.to_string(),
            category,
            severity,
            passed: true,
            message: message.to_string(),
            suggestion: None,
            doc_url: None,
        }
    }

    pub fn fail(
        code: &str,
        category: CheckCategory,
        severity: Severity,
        message: &str,
        suggestion: Option<&str>,
    ) -> Self {
        Self {
            code: code.to_string(),
            category,
            severity,
            passed: false,
            message: message.to_string(),
            suggestion: suggestion.map(|s| s.to_string()),
            doc_url: None,
        }
    }

    /// Attach a documentation URL to this check result.
    pub fn with_doc(mut self, url: &str) -> Self {
        self.doc_url = Some(url.to_string());
        self
    }
}

#[derive(Debug, Serialize)]
pub struct CheckSummary {
    pub total: usize,
    pub passed: usize,
    pub errors: usize,
    pub warnings: usize,
    pub info: usize,
}

impl CheckSummary {
    pub fn from_results(results: &[CheckResult]) -> Self {
        let total = results.len();
        let passed = results.iter().filter(|r| r.passed).count();
        let failed: Vec<_> = results.iter().filter(|r| !r.passed).collect();
        let errors = failed
            .iter()
            .filter(|r| r.severity == Severity::Error)
            .count();
        let warnings = failed
            .iter()
            .filter(|r| r.severity == Severity::Warning)
            .count();
        let info = failed
            .iter()
            .filter(|r| r.severity == Severity::Info)
            .count();
        Self {
            total,
            passed,
            errors,
            warnings,
            info,
        }
    }

    pub fn has_errors(&self) -> bool {
        self.errors > 0
    }
}
