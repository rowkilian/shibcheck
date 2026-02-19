use anyhow::{Context, Result};
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use std::path::Path;

use crate::model::shibboleth_config::*;

pub fn parse(path: &Path) -> Result<ShibbolethConfig> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    parse_str(&content)
}

pub fn parse_str(xml: &str) -> Result<ShibbolethConfig> {
    let mut reader = Reader::from_str(xml);
    let mut config = ShibbolethConfig::default();
    let mut element_stack: Vec<String> = Vec::new();
    let mut current_metadata_provider: Option<MetadataProvider> = None;

    loop {
        match reader.read_event() {
            Err(e) => anyhow::bail!("XML parse error at position {}: {}", reader.error_position(), e),
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) => {
                let name = local_name(&e);
                process_element(&name, &e, &element_stack, &mut config, &mut current_metadata_provider, false)?;
                element_stack.push(name);
            }
            Ok(Event::Empty(e)) => {
                let name = local_name(&e);
                process_element(&name, &e, &element_stack, &mut config, &mut current_metadata_provider, true)?;
            }
            Ok(Event::End(_)) => {
                if let Some(name) = element_stack.pop() {
                    if name == "MetadataProvider" {
                        if let Some(mp) = current_metadata_provider.take() {
                            config.metadata_providers.push(mp);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    // Push any remaining metadata provider
    if let Some(mp) = current_metadata_provider.take() {
        config.metadata_providers.push(mp);
    }

    Ok(config)
}

fn local_name(e: &quick_xml::events::BytesStart<'_>) -> String {
    let full = String::from_utf8_lossy(e.name().as_ref()).to_string();
    // Strip namespace prefix if present
    full.rsplit(':').next().unwrap_or(&full).to_string()
}

fn get_attr(e: &quick_xml::events::BytesStart<'_>, name: &str) -> Option<String> {
    e.attributes().filter_map(|a| a.ok()).find_map(|a| {
        let key = String::from_utf8_lossy(a.key.as_ref()).to_string();
        let local_key = key.rsplit(':').next().unwrap_or(&key);
        if local_key == name {
            Some(String::from_utf8_lossy(&a.value).to_string())
        } else {
            None
        }
    })
}

fn process_element(
    name: &str,
    e: &quick_xml::events::BytesStart<'_>,
    stack: &[String],
    config: &mut ShibbolethConfig,
    current_mp: &mut Option<MetadataProvider>,
    is_empty: bool,
) -> Result<()> {
    match name {
        "SPConfig" => {
            config.has_sp_config = true;
        }
        "ApplicationDefaults" => {
            config.has_application_defaults = true;
            config.entity_id = get_attr(e, "entityID");
            config.application_defaults = Some(ApplicationDefaults {
                remote_user: get_attr(e, "REMOTE_USER"),
                signing: get_attr(e, "signing"),
                encryption: get_attr(e, "encryption"),
            });
        }
        "Sessions" => {
            if parent_is(stack, "ApplicationDefaults") {
                config.sessions = Some(SessionsConfig {
                    handler_url: get_attr(e, "handlerURL"),
                    handler_ssl: get_attr(e, "handlerSSL"),
                    cookie_props: get_attr(e, "cookieProps"),
                    has_sso: false,
                    has_session_initiator: false,
                });
            }
        }
        "SSO" => {
            if let Some(ref mut sessions) = config.sessions {
                sessions.has_sso = true;
            }
        }
        "SessionInitiator" => {
            if let Some(ref mut sessions) = config.sessions {
                sessions.has_session_initiator = true;
            }
        }
        "MetadataProvider" => {
            if stack.iter().any(|s| s == "MetadataProvider") {
                // Nested MetadataProvider (chaining) - treat like top-level
            }
            let mp = MetadataProvider {
                provider_type: get_attr(e, "type").unwrap_or_default(),
                uri: get_attr(e, "uri"),
                path: get_attr(e, "path"),
                url: get_attr(e, "url"),
                filters: Vec::new(),
            };
            if is_empty {
                config.metadata_providers.push(mp);
            } else {
                *current_mp = Some(mp);
            }
        }
        "MetadataFilter" => {
            let filter = MetadataFilter {
                filter_type: get_attr(e, "type").unwrap_or_default(),
                certificate: get_attr(e, "certificate"),
                max_validity_interval: get_attr(e, "maxValidityInterval"),
                require_valid_until: get_attr(e, "requireValidUntil"),
            };
            if let Some(ref mut mp) = current_mp {
                mp.filters.push(filter);
            }
        }
        "CredentialResolver" => {
            let cr = CredentialResolver {
                resolver_type: get_attr(e, "type").unwrap_or_default(),
                use_attr: get_attr(e, "use"),
                certificate: get_attr(e, "certificate"),
                key: get_attr(e, "key"),
            };
            config.credential_resolvers.push(cr);
        }
        "AttributeExtractor" => {
            if let Some(path) = get_attr(e, "path") {
                config.attribute_extractor_paths.push(path);
            }
        }
        "AttributeFilter" => {
            // Only capture path attribute if it's the AttributeFilter element, not the filter rules
            if parent_is(stack, "ApplicationDefaults") || stack.is_empty() {
                if let Some(path) = get_attr(e, "path") {
                    config.attribute_filter_paths.push(path);
                }
            }
        }
        "Handler" => {
            if get_attr(e, "type")
                .as_deref()
                .map_or(false, |t| t.contains("StatusHandler") || t.contains("Status"))
            {
                config.status_handler = Some(StatusHandler {
                    acl: get_attr(e, "acl").or_else(|| get_attr(e, "Location").map(|_| String::new())),
                });
            }
        }
        _ => {}
    }
    Ok(())
}

fn parent_is(stack: &[String], name: &str) -> bool {
    stack.last().map_or(false, |s| s == name)
}

/// Check if XML is well-formed
pub fn check_well_formed(path: &Path) -> Result<()> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    let mut reader = Reader::from_str(&content);
    loop {
        match reader.read_event() {
            Ok(Event::Eof) => break,
            Err(e) => anyhow::bail!("XML error at position {}: {}", reader.error_position(), e),
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_config() {
        let xml = r#"
        <SPConfig xmlns="urn:mace:shibboleth:3.0:native:sp:config">
            <ApplicationDefaults entityID="https://sp.example.org/shibboleth"
                                 REMOTE_USER="eppn">
                <Sessions handlerURL="/Shibboleth.sso" handlerSSL="true"
                          cookieProps="https">
                    <SSO entityID="https://idp.example.org/idp/shibboleth">
                        SAML2
                    </SSO>
                </Sessions>
                <MetadataProvider type="XML" path="idp-metadata.xml"/>
                <CredentialResolver type="File" certificate="sp-cert.pem" key="sp-key.pem"/>
            </ApplicationDefaults>
        </SPConfig>
        "#;

        let config = parse_str(xml).unwrap();
        assert!(config.has_sp_config);
        assert!(config.has_application_defaults);
        assert_eq!(
            config.entity_id.as_deref(),
            Some("https://sp.example.org/shibboleth")
        );
        assert!(config.sessions.is_some());
        let sessions = config.sessions.as_ref().unwrap();
        assert!(sessions.has_sso);
        assert_eq!(sessions.handler_ssl.as_deref(), Some("true"));
        assert_eq!(sessions.cookie_props.as_deref(), Some("https"));
        assert_eq!(config.metadata_providers.len(), 1);
        assert_eq!(config.credential_resolvers.len(), 1);
        assert_eq!(
            config.credential_resolvers[0].certificate.as_deref(),
            Some("sp-cert.pem")
        );
    }

    #[test]
    fn test_parse_empty_xml() {
        let xml = "<root/>";
        let config = parse_str(xml).unwrap();
        assert!(!config.has_sp_config);
        assert!(!config.has_application_defaults);
    }
}
