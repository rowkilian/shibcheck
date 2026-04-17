use std::path::Path;

use serde::Deserialize;

/// Configuration loaded from a `.shibcheckrc` TOML file.
///
/// Looked up first in the checked directory, then in `$HOME`.
/// CLI flags always take precedence over file values.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct RcConfig {
    pub verbose: Option<bool>,
    pub json: Option<bool>,
    pub sarif: Option<bool>,
    pub html: Option<bool>,
    pub markdown: Option<bool>,
    pub no_color: Option<bool>,
    pub check_remote: Option<bool>,
    pub check: Option<Vec<String>>,
    pub skip: Option<Vec<String>>,
    pub severity: Option<String>,
    pub fix: Option<bool>,
    pub watch: Option<bool>,
}

impl RcConfig {
    /// Load `.shibcheckrc` from the checked directory, falling back to `$HOME`.
    /// If a file is found but cannot be parsed, warns on stderr and falls through.
    pub fn load(checked_dir: &Path) -> Self {
        let candidates = [
            Some(checked_dir.join(".shibcheckrc")),
            dirs_home().map(|h| h.join(".shibcheckrc")),
        ];

        for candidate in candidates.iter().flatten() {
            let contents = match std::fs::read_to_string(candidate) {
                Ok(c) => c,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => {
                    eprintln!(
                        "Warning: failed to read {}: {}",
                        candidate.display(),
                        e
                    );
                    continue;
                }
            };
            match toml::from_str::<RcConfig>(&contents) {
                Ok(cfg) => return cfg,
                Err(e) => {
                    eprintln!(
                        "Warning: ignoring malformed {}: {}",
                        candidate.display(),
                        e
                    );
                }
            }
        }

        RcConfig::default()
    }
}

fn dirs_home() -> Option<std::path::PathBuf> {
    std::env::var_os("HOME").map(std::path::PathBuf::from)
}
