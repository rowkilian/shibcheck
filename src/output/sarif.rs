use serde::Serialize;

use super::collect_file_summary;
use crate::config::DiscoveredConfig;
use crate::result::{CheckResult, Severity};

#[derive(Serialize)]
struct SarifReport<'a> {
    #[serde(rename = "$schema")]
    schema: &'a str,
    version: &'a str,
    runs: Vec<SarifRun<'a>>,
}

#[derive(Serialize)]
struct SarifRun<'a> {
    tool: SarifTool<'a>,
    results: Vec<SarifResult>,
    artifacts: Vec<SarifArtifact>,
    #[serde(rename = "columnKind")]
    column_kind: &'a str,
}

#[derive(Serialize)]
struct SarifArtifact {
    location: SarifArtifactLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<SarifMessage>,
}

#[derive(Serialize)]
struct SarifTool<'a> {
    driver: SarifDriver<'a>,
}

#[derive(Serialize)]
struct SarifDriver<'a> {
    name: &'a str,
    #[serde(rename = "informationUri")]
    information_uri: &'a str,
    version: &'a str,
    rules: Vec<SarifRule>,
}

#[derive(Serialize)]
struct SarifRule {
    id: String,
    name: String,
    #[serde(rename = "shortDescription")]
    short_description: SarifMessage,
    #[serde(rename = "defaultConfiguration")]
    default_configuration: SarifRuleConfig,
    #[serde(rename = "helpUri", skip_serializing_if = "Option::is_none")]
    help_uri: Option<String>,
}

#[derive(Serialize)]
struct SarifRuleConfig {
    level: String,
}

#[derive(Serialize)]
struct SarifMessage {
    text: String,
}

#[derive(Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    level: String,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
}

#[derive(Serialize)]
struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    physical_location: SarifPhysicalLocation,
}

#[derive(Serialize)]
struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: SarifArtifactLocation,
}

#[derive(Serialize)]
struct SarifArtifactLocation {
    uri: String,
}

fn severity_to_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Error => "error",
        Severity::Warning => "warning",
        Severity::Info => "note",
    }
}

pub fn print(results: &[CheckResult], config: &DiscoveredConfig) {
    // Build unique rules from all results
    let mut seen_rules = std::collections::HashSet::new();
    let mut rules = Vec::new();
    for r in results {
        if seen_rules.insert(r.code.clone()) {
            rules.push(SarifRule {
                id: r.code.clone(),
                name: r.code.replace('-', ""),
                short_description: SarifMessage {
                    text: r.message.clone(),
                },
                default_configuration: SarifRuleConfig {
                    level: severity_to_level(r.severity).to_string(),
                },
                help_uri: r.doc_url.clone(),
            });
        }
    }

    // Build results (only failed checks)
    let sarif_results: Vec<SarifResult> = results
        .iter()
        .filter(|r| !r.passed)
        .map(|r| {
            let uri = config.shibboleth_xml_path.to_string_lossy().into_owned();
            let message = match &r.suggestion {
                Some(s) => format!("{} — {}", r.message, s),
                None => r.message.clone(),
            };
            SarifResult {
                rule_id: r.code.clone(),
                level: severity_to_level(r.severity).to_string(),
                message: SarifMessage { text: message },
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation { uri },
                    },
                }],
            }
        })
        .collect();

    let artifacts: Vec<SarifArtifact> = collect_file_summary(config)
        .into_iter()
        .map(|f| SarifArtifact {
            location: SarifArtifactLocation {
                uri: f.path.clone(),
            },
            description: Some(SarifMessage { text: f.kind }),
        })
        .collect();

    let report = SarifReport {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        version: "2.1.0",
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "shibcheck",
                    information_uri: "https://github.com/<owner>/shibcheck",
                    version: env!("CARGO_PKG_VERSION"),
                    rules,
                },
            },
            results: sarif_results,
            artifacts,
            column_kind: "utf16CodeUnits",
        }],
    };

    match serde_json::to_string_pretty(&report) {
        Ok(json) => println!("{}", json),
        Err(e) => eprintln!("Failed to serialize SARIF: {}", e),
    }
}
