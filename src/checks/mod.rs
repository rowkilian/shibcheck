pub mod cross_references;
pub mod migration;
pub mod operational;
pub mod security;
pub mod xml_validity;

use crate::config::DiscoveredConfig;
use crate::location::{find_element_line, find_line};
use crate::result::CheckResult;

pub fn run_all(config: &DiscoveredConfig, check_remote: bool) -> Vec<CheckResult> {
    let mut results = Vec::new();
    results.extend(xml_validity::run(config));
    results.extend(cross_references::run(config, check_remote));
    results.extend(security::run(config));
    results.extend(migration::run(config));
    results.extend(operational::run(config));

    // Enrich results with source locations
    annotate_locations(&mut results, config);

    results
}

/// Automatically enrich check results with file:line locations by mapping check codes
/// to the XML elements they inspect. Only annotates failed checks that don't already
/// have a location set.
fn annotate_locations(results: &mut [CheckResult], config: &DiscoveredConfig) {
    let xml = config.shibboleth_xml_content.as_deref().unwrap_or("");
    let shib_file = config
        .shibboleth_xml_path
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_else(|| "shibboleth2.xml".to_string());
    let attr_map_file = config
        .attribute_map_path
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_else(|| "attribute-map.xml".to_string());
    let attr_policy_file = config
        .attribute_policy_path
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_else(|| "attribute-policy.xml".to_string());

    for result in results.iter_mut() {
        if result.location.is_some() {
            continue; // already annotated by the check itself
        }

        let (file, line) = locate_check(&result.code, &result.message, xml, config, &shib_file, &attr_map_file, &attr_policy_file);
        if let Some(f) = file {
            result.location = Some(crate::result::SourceLocation {
                file: f.to_string(),
                line,
            });
        }
    }
}

/// Determine the file and line for a given check code by mapping it to the XML element it inspects.
fn locate_check<'a>(
    code: &str,
    message: &str,
    xml: &str,
    config: &DiscoveredConfig,
    shib_file: &'a str,
    attr_map_file: &'a str,
    attr_policy_file: &'a str,
) -> (Option<&'a str>, Option<usize>) {
    if xml.is_empty() {
        return (None, None);
    }

    // Map check codes to the primary XML element they inspect.
    // This covers the most common cases; checks on repeated elements
    // use message content to disambiguate.
    let element_hint = match code {
        // Sessions-related checks
        "SEC-001" | "SEC-002" | "SEC-003" | "SEC-017" | "SEC-019" | "SEC-020"
        | "SEC-022" | "SEC-023" | "SEC-031" | "SEC-038" | "SEC-042" | "SEC-045"
        | "SEC-058" | "SEC-059" | "SEC-061" | "SEC-066" | "SEC-067" | "SEC-068"
        | "SEC-071" | "SEC-078" | "SEC-079" | "SEC-082" | "SEC-083" | "SEC-084"
        | "SEC-092" | "OPS-040" | "OPS-041" | "OPS-060" | "OPS-061" => Some("Sessions"),

        // SSO-related checks
        "SEC-025" | "SEC-029" | "OPS-046" | "OPS-069" | "SEC-117" => Some("SSO"),

        // ApplicationDefaults-related checks
        "SEC-006" | "SEC-007" | "SEC-018" | "SEC-028" | "SEC-035" | "SEC-049"
        | "SEC-052" | "SEC-053" | "SEC-056" | "SEC-057" | "SEC-088" | "SEC-089"
        | "SEC-097" | "SEC-106" | "OPS-036" | "OPS-037" | "OPS-048" | "OPS-071"
        | "OPS-072" | "XML-021" => Some("ApplicationDefaults"),

        // Errors-related checks
        "SEC-080" | "SEC-104" | "OPS-038" | "OPS-039" | "OPS-043" | "OPS-068" => Some("Errors"),

        // MetadataProvider-related checks
        "SEC-011" | "SEC-012" | "SEC-014" | "SEC-026" | "SEC-055" | "SEC-069"
        | "SEC-070" | "SEC-073" | "SEC-122" | "SEC-123" | "OPS-042" | "OPS-047"
        | "OPS-049" | "OPS-053" => Some("MetadataProvider"),

        // CredentialResolver-related checks
        "SEC-004" | "SEC-005" | "SEC-043" | "SEC-051" | "SEC-074" | "SEC-077"
        | "SEC-091" | "SEC-095" | "OPS-051" => Some("CredentialResolver"),

        // Handler-related checks
        "SEC-015" | "SEC-032" | "SEC-033" | "SEC-046" | "SEC-047" | "SEC-062"
        | "SEC-063" | "SEC-064" | "SEC-094" | "SEC-113" | "SEC-115" => Some("Handler"),

        // SPConfig-level checks
        "SEC-024" | "XML-020" => Some("SPConfig"),
        "SEC-044" | "SEC-081" => Some("TCPListener"),
        "SEC-048" | "SEC-039" => Some("SecurityPolicyProvider"),

        // Certificate/key file checks — use message to extract file name
        "SEC-008" | "SEC-009" | "SEC-010" | "SEC-013" | "SEC-016" | "SEC-021"
        | "SEC-087" | "REF-001" | "REF-002" => {
            return locate_from_message_file(message, shib_file);
        }

        // Attribute map/policy checks
        "REF-014" | "REF-015" | "XML-017" | "OPS-063" | "SEC-108" => {
            let content = config.attribute_map_content.as_deref().unwrap_or("");
            let line = extract_attr_from_message(message)
                .and_then(|needle| find_line(content, &needle));
            return (Some(attr_map_file), line);
        }
        "SEC-085" | "SEC-112" | "OPS-064" => {
            let content = config.attribute_policy_content.as_deref().unwrap_or("");
            let line = extract_attr_from_message(message)
                .and_then(|needle| find_line(content, &needle));
            return (Some(attr_policy_file), line);
        }

        // ApplicationOverride checks
        "SEC-065" | "SEC-116" | "SEC-125" | "OPS-032" | "OPS-033" | "OPS-034"
        | "OPS-035" | "OPS-052" | "OPS-070" => {
            // Try to find the specific override by its ID from the message
            let line = extract_quoted_value(message)
                .and_then(|id| find_element_line(xml, "ApplicationOverride", Some("id"), Some(&id)));
            return (Some(shib_file), line);
        }

        // Notify checks
        "SEC-041" | "SEC-105" | "SEC-124" => Some("Notify"),

        // Logout checks
        "SEC-060" | "SEC-096" | "SEC-103" | "OPS-058" => Some("Logout"),

        // SessionInitiator checks
        "SEC-076" | "SEC-118" | "SEC-120" | "OPS-066" => Some("SessionInitiator"),

        // ContentSetting checks
        "SEC-093" | "SEC-100" | "SEC-101" | "OPS-044" | "OPS-045" | "OPS-065" => {
            // These iterate over Host/Path elements; try to find the named one
            let line = extract_quoted_value(message)
                .and_then(|name| {
                    find_element_line(xml, "Host", Some("name"), Some(&name))
                        .or_else(|| find_element_line(xml, "Path", Some("name"), Some(&name)))
                });
            return (Some(shib_file), line);
        }

        // Raw XML scanning checks — search for the pattern mentioned
        "SEC-036" => return (Some(shib_file), find_line(xml, "spoofKey=")),
        "SEC-050" => return (Some(shib_file), find_line(xml, "exportAssertion=\"true\"")),
        "SEC-072" => return (Some(shib_file), find_line(xml, "-----BEGIN")),
        "SEC-107" => return (Some(shib_file), find_line(xml, "<!--")),
        "SEC-121" => return (Some(shib_file), find_line(xml, "catchAll=\"true\"")),
        "SEC-114" => return (Some(shib_file), find_line(xml, "<DataSealer")),
        "OPS-054" => return (Some(shib_file), find_line(xml, "StorageService")),
        "OPS-055" => return (Some(shib_file), find_line(xml, "OutOfProcess").or_else(|| find_line(xml, "InProcess"))),
        "OPS-056" => return (Some(shib_file), find_line(xml, "ReplayCache")),
        "OPS-059" => return (Some(shib_file), find_line(xml, ".logger")),
        "OPS-062" => return (Some(shib_file), find_line(xml, "ArtifactMap")),
        "OPS-067" => return (Some(shib_file), find_line(xml, "AccessControl")),
        "OPS-075" => {
            let line = find_line(xml, "TODO")
                .or_else(|| find_line(xml, "FIXME"))
                .or_else(|| find_line(xml, "XXX"));
            return (Some(shib_file), line);
        }

        // XML validity checks on structure
        "XML-001" | "XML-002" | "XML-003" | "XML-004" | "XML-005" => {
            return (Some(shib_file), Some(1));
        }

        // Default: just report the file, no specific line
        _ => {
            return (Some(shib_file), None);
        }
    };

    // For element-hinted checks, look up the element in the XML
    match element_hint {
        Some(elem) => {
            let line = find_element_line(xml, elem, None, None);
            (Some(shib_file), line)
        }
        None => (Some(shib_file), None),
    }
}

/// For "direct return" raw XML pattern checks
fn locate_from_message_file<'a>(message: &str, shib_file: &'a str) -> (Option<&'a str>, Option<usize>) {
    // Certificate/key messages often contain the file name — just point to the shibboleth2.xml
    // CredentialResolver that references it
    // Try to extract a filename from the message
    let file_hint = message
        .split_whitespace()
        .find(|w| w.ends_with(".pem") || w.ends_with(".crt") || w.ends_with(".key") || w.ends_with(".p12"));
    if let Some(hint) = file_hint {
        return (Some(shib_file), None.or_else(|| {
            // We can't easily access raw XML here, so just return the file
            let _ = hint;
            None
        }));
    }
    (Some(shib_file), None)
}

/// Extract the first single-quoted value from a message (e.g., "ApplicationOverride 'admin'" -> "admin")
fn extract_quoted_value(message: &str) -> Option<String> {
    let start = message.find('\'')?;
    let rest = &message[start + 1..];
    let end = rest.find('\'')?;
    Some(rest[..end].to_string())
}

/// Extract an attribute-related needle from a message for line lookup
fn extract_attr_from_message(message: &str) -> Option<String> {
    // Try to find a quoted value that might be an attribute ID or name
    extract_quoted_value(message)
}
