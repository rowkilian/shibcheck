use serde::Serialize;

use crate::config::DiscoveredConfig;
use crate::result::{CheckResult, CheckSummary};

#[derive(Serialize)]
struct MetadataSource {
    provider_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    backing_file_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_directory: Option<String>,
}

#[derive(Serialize)]
struct JsonReport<'a> {
    metadata_sources: Vec<MetadataSource>,
    results: &'a [CheckResult],
    summary: &'a CheckSummary,
}

pub fn print(results: &[CheckResult], summary: &CheckSummary, config: &DiscoveredConfig) {
    let metadata_sources = config
        .shibboleth_config
        .as_ref()
        .map(|sc| {
            sc.metadata_providers
                .iter()
                .filter(|mp| mp.provider_type != "Chaining")
                .map(|mp| MetadataSource {
                    provider_type: mp.provider_type.clone(),
                    path: mp.path.clone(),
                    uri: mp.uri.clone().or_else(|| mp.url.clone()),
                    backing_file_path: mp.backing_file_path.clone(),
                    source_directory: mp.source_directory.clone(),
                })
                .collect()
        })
        .unwrap_or_default();

    let report = JsonReport {
        metadata_sources,
        results,
        summary,
    };
    match serde_json::to_string_pretty(&report) {
        Ok(json) => println!("{}", json),
        Err(e) => eprintln!("Failed to serialize JSON: {}", e),
    }
}
