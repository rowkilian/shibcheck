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

/// Mutable state threaded through the event loop.
#[derive(Default)]
struct ParseState {
    config: ShibbolethConfig,
    stack: Vec<String>,
    mp_stack: Vec<MetadataProvider>,
    cr_stack: Vec<CredentialResolver>,
    in_request_map: bool,
}

impl ParseState {
    fn end_element(&mut self) {
        let Some(name) = self.stack.pop() else {
            return;
        };
        match name.as_str() {
            "RequestMap" => self.in_request_map = false,
            "MetadataProvider" => {
                if let Some(mp) = self.mp_stack.pop() {
                    if let Some(parent) = self.mp_stack.last_mut() {
                        if parent.provider_type == "Chaining" {
                            parent.children_count += 1;
                        }
                    }
                    self.config.metadata_providers.push(mp);
                }
            }
            "CredentialResolver" => {
                if let Some(cr) = self.cr_stack.pop() {
                    if let Some(parent) = self.cr_stack.last_mut() {
                        if parent.resolver_type == "Chaining" {
                            parent.children_count += 1;
                        }
                    }
                    self.config.credential_resolvers.push(cr);
                }
            }
            _ => {}
        }
    }

    fn set_protocols(&mut self, target: &str, text: String) {
        if let Some(ref mut sessions) = self.config.sessions {
            match target {
                "SSO" => sessions.sso_protocols = Some(text),
                "Logout" => sessions.logout_protocols = Some(text),
                _ => {}
            }
        }
    }
}

pub fn parse_str(xml: &str) -> Result<ShibbolethConfig> {
    let mut reader = Reader::from_str(xml);
    let mut state = ParseState::default();
    // Element whose text content we need (SSO and Logout list their protocols as text)
    let mut text_target: Option<String> = None;

    loop {
        match reader.read_event() {
            Err(e) => anyhow::bail!(
                "XML parse error at position {}: {}",
                reader.error_position(),
                e
            ),
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) => {
                let name = local_name(&e);
                process_element(&name, &e, &mut state, false);
                if name == "RequestMap" {
                    state.in_request_map = true;
                }
                text_target = matches!(name.as_str(), "SSO" | "Logout" | "ConnectionString")
                    .then(|| name.clone());
                state.stack.push(name);
            }
            Ok(Event::Empty(e)) => {
                let name = local_name(&e);
                process_element(&name, &e, &mut state, true);
                text_target = None;
            }
            Ok(Event::Text(e)) => {
                if let Some(ref target) = text_target {
                    // Fall back to the raw text if it has a bad entity reference
                    let text = match e.unescape() {
                        Ok(t) => t.trim().to_string(),
                        Err(_) => String::from_utf8_lossy(e.as_ref()).trim().to_string(),
                    };
                    if target == "ConnectionString" {
                        state.config.odbc_connection_has_password |= has_password(&text);
                    } else if !text.is_empty() {
                        state.set_protocols(target, text);
                    }
                }
            }
            Ok(Event::End(_)) => {
                text_target = None;
                state.end_element();
            }
            _ => {}
        }
    }

    // Elements left open at EOF still count
    state.config.metadata_providers.append(&mut state.mp_stack);
    state
        .config
        .credential_resolvers
        .append(&mut state.cr_stack);

    Ok(state.config)
}

use super::{get_attr, local_name};

/// Whether an ODBC connection string sets a password (`PWD=` or `PASSWORD=`).
fn has_password(connection: &str) -> bool {
    connection.split(';').any(|part| {
        let key = part.split('=').next().unwrap_or("").trim();
        part.contains('=')
            && (key.eq_ignore_ascii_case("PWD") || key.eq_ignore_ascii_case("PASSWORD"))
    })
}

/// Decoded size of standard base64 text (padding and whitespace allowed), or `None` if invalid.
fn base64_len(text: &str) -> Option<usize> {
    let body: Vec<char> = text.chars().filter(|c| !c.is_whitespace()).collect();
    let data: Vec<&char> = body.iter().take_while(|c| **c != '=').collect();
    let padding = body.len() - data.len();
    if padding > 2
        || body[data.len()..].iter().any(|c| *c != '=')
        || !data
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || **c == '+' || **c == '/')
        || data.len() % 4 == 1
        || (padding > 0 && body.len() & 3 != 0)
    {
        return None;
    }
    Some(data.len() * 3 / 4)
}

fn process_element(
    name: &str,
    e: &quick_xml::events::BytesStart<'_>,
    state: &mut ParseState,
    is_empty: bool,
) {
    let ParseState {
        config,
        stack,
        mp_stack,
        cr_stack,
        in_request_map,
    } = state;
    let in_request_map = *in_request_map;

    if let Some(id) = get_attr(e, "policyId") {
        config.policy_ids_used.push(id);
    }
    if get_attr(e, "metadataAttributePrefix").is_some() {
        config.metadata_attribute_prefix_set = true;
    }
    if matches!(name, "Subst" | "Regex") && parent_is(stack, "MetadataProvider") {
        if let Some(mp) = mp_stack.last_mut() {
            mp.transform_children += 1;
        }
    }
    if get_attr(e, "acsByIndex").is_some_and(|v| v.trim() == "true") {
        config.acs_by_index.push(name.to_string());
    }
    let singleton_parent = match stack.last().map(String::as_str) {
        Some("SPConfig") => &SPCONFIG_SINGLETONS[..],
        Some("ApplicationDefaults") => &DEFAULTS_SINGLETONS[..],
        _ => &[],
    };
    if singleton_parent.contains(&name) {
        *config.singleton_counts.entry(name.to_string()).or_insert(0) += 1;
    }
    if name == "Policy" {
        if let Some(id) = get_attr(e, "id") {
            config.policy_ids_defined.push(id);
        }
    }

    match name {
        "SPConfig" => {
            config.has_sp_config = true;
            config.sp_version = match get_attr(e, "xmlns").as_deref() {
                Some("urn:mace:shibboleth:3.0:native:sp:config") => SpVersion::V3,
                Some("urn:mace:shibboleth:2.0:native:sp:config") => SpVersion::V2,
                _ => SpVersion::Unknown,
            };
            config.clock_skew = get_attr(e, "clockSkew");
        }
        "TCPListener" | "UnixListener"
            if config.tcp_listener_address.is_none() => {
                config.tcp_listener_address = get_attr(e, "address");
                config.tcp_listener_acl = get_attr(e, "acl");
            }
        "InProcess" => {
            config.in_process_check_spoofing = get_attr(e, "checkSpoofing");
        }
        "ISAPI" => {
            config.isapi_normalize_request = get_attr(e, "normalizeRequest");
            config.isapi_use_headers = get_attr(e, "useHeaders");
        }
        "Site" if get_attr(e, "useHeaders").as_deref() == Some("true") => {
            config
                .site_use_headers
                .push(get_attr(e, "id").unwrap_or_default());
        }
        "RelyingParty" => {
            config
                .relying_parties
                .push(crate::model::shibboleth_config::RelyingPartyInfo {
                    name: get_attr(e, "Name"),
                    matcher_type: get_attr(e, "type"),
                    auth_type: get_attr(e, "authType"),
                    has_auth_password: get_attr(e, "authPassword").is_some(),
                    require_transport_auth: get_attr(e, "requireTransportAuth"),
                    require_confidentiality: get_attr(e, "requireConfidentiality"),
                    signing: get_attr(e, "signing"),
                    encryption: get_attr(e, "encryption"),
                    signing_alg: get_attr(e, "signingAlg"),
                    digest_alg: get_attr(e, "digestAlg"),
                });
        }
        "SessionCache" | "ReplayCache" | "ArtifactMap" => {
            let element = match name {
                "SessionCache" => "SessionCache",
                "ReplayCache" => "ReplayCache",
                _ => "ArtifactMap",
            };
            if name == "SessionCache" {
                config.session_cache = Some(crate::model::shibboleth_config::SessionCacheInfo {
                    cache_assertions: get_attr(e, "cacheAssertions"),
                    persisted_attributes: get_attr(e, "persistedAttributes"),
                    maintain_reverse_index: get_attr(e, "maintainReverseIndex"),
                    unreliable_networks: get_attr(e, "unreliableNetworks"),
                });
            }
            for attribute in ["StorageService", "StorageServiceLite"] {
                if let Some(id) = get_attr(e, attribute) {
                    config
                        .storage_references
                        .push(crate::model::shibboleth_config::StorageReference {
                            element,
                            attribute: if attribute == "StorageService" {
                                "StorageService"
                            } else {
                                "StorageServiceLite"
                            },
                            id,
                        });
                }
            }
        }
        "ApplicationDefaults" => {
            config.has_application_defaults = true;
            config.entity_id = get_attr(e, "entityID");
            config.application_defaults_id = get_attr(e, "id");
            config.application_defaults = Some(ApplicationDefaults {
                remote_user: get_attr(e, "REMOTE_USER"),
                signing: get_attr(e, "signing"),
                encryption: get_attr(e, "encryption"),
                cipher_suites: get_attr(e, "cipherSuites"),
                home_url: get_attr(e, "homeURL"),
                signing_alg: get_attr(e, "signingAlg"),
                digest_alg: get_attr(e, "digestAlg"),
                require_transport_auth: get_attr(e, "requireTransportAuth"),
                require_confidentiality: get_attr(e, "requireConfidentiality"),
                attribute_prefix: get_attr(e, "attributePrefix"),
                artifact_by_filesystem: get_attr(e, "artifactByFilesystem"),
            });
        }
        "Sessions"
            if parent_is(stack, "ApplicationDefaults") => {
                config.sessions = Some(SessionsConfig {
                    handler_url: get_attr(e, "handlerURL"),
                    handler_ssl: get_attr(e, "handlerSSL"),
                    cookie_props: get_attr(e, "cookieProps"),
                    lifetime: get_attr(e, "lifetime"),
                    timeout: get_attr(e, "timeout"),
                    has_sso: false,
                    has_session_initiator: false,
                    has_logout: false,
                    sso_entity_id: None,
                    redirect_limit: get_attr(e, "redirectLimit"),
                    consistent_address: get_attr(e, "consistentAddress"),
                    relay_state: get_attr(e, "relayState"),
                    redirect_whitelist: get_attr(e, "redirectWhitelist"),
                    sso_discovery_url: None,
                    sso_discovery_protocol: None,
                    sso_protocols: None,
                    logout_protocols: None,
                    post_limit: get_attr(e, "postLimit"),
                    idp_history: get_attr(e, "idpHistory"),
                    idp_history_days: get_attr(e, "idpHistoryDays"),
                    check_address: get_attr(e, "checkAddress"),
                    same_site_fallback: get_attr(e, "sameSiteFallback"),
                    same_site_session: get_attr(e, "sameSiteSession"),
                    post_data: get_attr(e, "postData"),
                    post_template: get_attr(e, "postTemplate"),
                    logout_outgoing_bindings: None,
                    max_time_since_authn: get_attr(e, "maxTimeSinceAuthn"),
                    cookie_lifetime: get_attr(e, "cookieLifetime"),
                    export_acl: get_attr(e, "exportACL"),
                    export_location: get_attr(e, "exportLocation"),
                    redirect_allow: get_attr(e, "redirectAllow"),
                });
            }
        "SSO" => {
            if let Some(ref mut sessions) = config.sessions {
                sessions.has_sso = true;
                if sessions.sso_entity_id.is_none() {
                    sessions.sso_entity_id = get_attr(e, "entityID");
                }
                if sessions.sso_discovery_url.is_none() {
                    sessions.sso_discovery_url = get_attr(e, "discoveryURL");
                }
                if sessions.sso_discovery_protocol.is_none() {
                    sessions.sso_discovery_protocol = get_attr(e, "discoveryProtocol");
                }
            }
            if config.sso_authn_context_class_ref.is_none() {
                config.sso_authn_context_class_ref = get_attr(e, "authnContextClassRef");
            }
            if config.sso_ecp.is_none() {
                config.sso_ecp = get_attr(e, "ECP");
            }
            if config.sso_authn_context_comparison.is_none() {
                config.sso_authn_context_comparison = get_attr(e, "authnContextComparison");
            }
        }
        "SessionInitiator" => {
            if let Some(ref mut sessions) = config.sessions {
                sessions.has_session_initiator = true;
            }
            config
                .session_initiators
                .push(crate::model::shibboleth_config::SessionInitiatorInfo {
                    initiator_type: get_attr(e, "type"),
                    id: get_attr(e, "id"),
                    is_default: get_attr(e, "isDefault"),
                    url: get_attr(e, "URL"),
                    template: get_attr(e, "template"),
                    entity_id: get_attr(e, "entityID"),
                    depth: stack.len(),
                    children: 0,
                });
            // A nested initiator belongs to the closest enclosing one, one level up.
            if parent_is(stack, "SessionInitiator") {
                let parent_depth = stack.len() - 1;
                let n = config.session_initiators.len() - 1;
                if let Some(parent) = config.session_initiators[..n]
                    .iter_mut()
                    .rev()
                    .find(|i| i.depth == parent_depth)
                {
                    parent.children += 1;
                }
            }
        }
        "Logout" | "LogoutInitiator" => {
            if let Some(ref mut sessions) = config.sessions {
                sessions.has_logout = true;
                if sessions.logout_outgoing_bindings.is_none() {
                    sessions.logout_outgoing_bindings = get_attr(e, "outgoingBindings");
                }
            }
            config
                .logout_initiators
                .push(crate::model::shibboleth_config::LogoutInitiatorInfo {
                    initiator_type: get_attr(e, "type"),
                    signing: get_attr(e, "signing"),
                    asynchronous: get_attr(e, "asynchronous"),
                    notify_without: get_attr(e, "notifyWithout"),
                });
        }
        "MetadataProvider" => {
            let mp = MetadataProvider {
                provider_type: get_attr(e, "type").unwrap_or_default(),
                uri: get_attr(e, "uri"),
                path: get_attr(e, "path"),
                url: get_attr(e, "url"),
                backing_file_path: get_attr(e, "backingFilePath"),
                source_directory: get_attr(e, "sourceDirectory"),
                reload_interval: get_attr(e, "reloadInterval"),
                file_attr: get_attr(e, "file"),
                filters: Vec::new(),
                max_refresh_delay: get_attr(e, "maxRefreshDelay"),
                children_count: 0,
                id_attr: get_attr(e, "id"),
                validate_attr: get_attr(e, "validate"),
                ignore_transport: get_attr(e, "ignoreTransport"),
                base_url: get_attr(e, "baseUrl"),
                verify_host: get_attr(e, "verifyHost"),
                refresh_delay_factor: get_attr(e, "refreshDelayFactor"),
                min_cache_duration: get_attr(e, "minCacheDuration"),
                max_cache_duration: get_attr(e, "maxCacheDuration"),
                min_refresh_delay: get_attr(e, "minRefreshDelay"),
                cache_directory: get_attr(e, "cacheDirectory"),
                transform_children: 0,
            };
            if is_empty {
                // If there's a parent Chaining MP on the stack, increment its count
                if let Some(parent) = mp_stack.last_mut() {
                    if parent.provider_type == "Chaining" {
                        parent.children_count += 1;
                    }
                }
                config.metadata_providers.push(mp);
            } else {
                mp_stack.push(mp);
            }
        }
        "MetadataFilter" => {
            let filter = MetadataFilter {
                filter_type: get_attr(e, "type").unwrap_or_default(),
                certificate: get_attr(e, "certificate"),
                max_validity_interval: get_attr(e, "maxValidityInterval"),
                require_valid_until: get_attr(e, "requireValidUntil"),
                has_trust_engine: false,
                verify_name: get_attr(e, "verifyName"),
                verify_backup: get_attr(e, "verifyBackup"),
            };
            if let Some(mp) = mp_stack.last_mut() {
                mp.filters.push(filter);
            }
        }
        "TrustEngine" => {
            if let Some(value) = get_attr(e, "checkRevocation") {
                config
                    .trust_engine_revocation
                    .push((get_attr(e, "type").unwrap_or_default(), value));
            }
            // Inside a MetadataFilter, mark the parent filter as having a TrustEngine
            if parent_is(stack, "MetadataFilter") {
                if let Some(filter) = mp_stack.last_mut().and_then(|mp| mp.filters.last_mut()) {
                    filter.has_trust_engine = true;
                }
            }
        }
        "CredentialResolver" => {
            let cr = CredentialResolver {
                resolver_type: get_attr(e, "type").unwrap_or_default(),
                use_attr: get_attr(e, "use"),
                certificate: get_attr(e, "certificate"),
                key: get_attr(e, "key"),
                children_count: 0,
            };
            if is_empty {
                // If there's a parent Chaining CR on the stack, increment its count
                if let Some(parent) = cr_stack.last_mut() {
                    if parent.resolver_type == "Chaining" {
                        parent.children_count += 1;
                    }
                }
                config.credential_resolvers.push(cr);
            } else {
                cr_stack.push(cr);
            }
        }
        "AttributeExtractor" => {
            config
                .attribute_extractor_types
                .push(get_attr(e, "type").unwrap_or_default());
            if let Some(path) = get_attr(e, "path") {
                config.attribute_extractor_paths.push(path);
            }
            if get_attr(e, "type").as_deref() == Some("KeyDescriptor")
                && ["signingId", "encryptionId", "hashId"]
                    .iter()
                    .all(|a| get_attr(e, a).is_none())
            {
                config.key_descriptor_extractors_without_ids += 1;
            }
        }
        "AttributeFilter"
            // Only capture path attribute if it's the AttributeFilter element, not the filter rules
            if (parent_is(stack, "ApplicationDefaults") || stack.is_empty()) => {
                if let Some(path) = get_attr(e, "path") {
                    config.attribute_filter_paths.push(path);
                }
            }
        "Errors" => {
            config.errors = Some(crate::model::shibboleth_config::ErrorsConfig {
                support_contact: get_attr(e, "supportContact"),
                help_location: get_attr(e, "helpLocation"),
                style_sheet: get_attr(e, "styleSheet"),
                session_error: get_attr(e, "session"),
                access_error: get_attr(e, "access"),
                ssl_error: get_attr(e, "ssl"),
                local_logout: get_attr(e, "localLogout"),
                metadata_error: get_attr(e, "metadata"),
                global_logout: get_attr(e, "globalLogout"),
                external_parameters: get_attr(e, "externalParameters"),
            });
        }
        "SecurityPolicyProvider" => {
            config.security_policy_provider_path = get_attr(e, "path");
            config.security_policy_provider_validate = get_attr(e, "validate");
        }
        "ApplicationOverride" => {
            let id = get_attr(e, "id");
            let entity_id = get_attr(e, "entityID");
            if let Some(ref id_val) = id {
                config.application_override_ids.push(id_val.clone());
                config
                    .application_override_entity_ids
                    .push((id_val.clone(), entity_id));
            }
        }
        "Handler" => {
            let handler_type = get_attr(e, "type").unwrap_or_default();
            let location = get_attr(e, "Location");
            let show_attr_values = get_attr(e, "showAttributeValues");
            let acl = get_attr(e, "acl");

            // Keep backward-compat StatusHandler special-case
            if handler_type.contains("StatusHandler") || handler_type.contains("Status") {
                config.status_handler = Some(StatusHandler {
                    acl: acl
                        .clone()
                        .or_else(|| location.as_ref().map(|_| String::new())),
                });
            }

            config.handlers.push(HandlerInfo {
                handler_type,
                location,
                show_attribute_values: show_attr_values,
                acl,
                template: get_attr(e, "template"),
            });
        }
        "StorageService" => {
            if let Some(id) = get_attr(e, "id") {
                config.storage_service_ids.push(id);
            }
        }
        "DataSealer" => {
            config
                .data_sealers
                .push(crate::model::shibboleth_config::DataSealerInfo {
                    sealer_type: get_attr(e, "type").unwrap_or_default(),
                    has_key: get_attr(e, "key").is_some(),
                    key_bytes: get_attr(e, "key").and_then(|k| base64_len(&k)),
                    path: get_attr(e, "path"),
                    url: get_attr(e, "url"),
                    backing_file_path: get_attr(e, "backingFilePath"),
                });
        }
        "Notify" => {
            let info = crate::model::shibboleth_config::NotifyInfo {
                channel: get_attr(e, "Channel"),
                location: get_attr(e, "Location"),
            };
            if let Some(ref loc) = info.location {
                config.notify_endpoints.push(loc.clone());
            }
            config.notify_elements.push(info);
        }
        "RequestMapper" => {
            config.request_map_type = get_attr(e, "type");
        }
        "RequestMap" => {
            config.request_map_root_app_id = get_attr(e, "applicationId");
        }
        "Host" | "Path"
            if in_request_map => {
                if let Some(app_id) = get_attr(e, "applicationId") {
                    config.request_map_application_ids.push(app_id);
                }
                config.request_map_content_settings.push(
                    crate::model::shibboleth_config::ContentSetting {
                        element: name.to_string(),
                        name: get_attr(e, "name"),
                        require_session: get_attr(e, "requireSession"),
                        auth_type: get_attr(e, "authType"),
                        is_passive: get_attr(e, "isPassive"),
                        force_authn: get_attr(e, "forceAuthn"),
                        redirect_to_ssl: get_attr(e, "redirectToSSL"),
                        require_session_with: get_attr(e, "requireSessionWith"),
                        export_assertion: get_attr(e, "exportAssertion"),
                    },
                );
            }
        _ => {}
    }
}

/// Children of `<SPConfig>` the docs allow at most once.
pub(crate) const SPCONFIG_SINGLETONS: [&str; 11] = [
    "Extensions",
    "OutOfProcess",
    "InProcess",
    "DataSealer",
    "SessionCache",
    "ReplayCache",
    "ArtifactMap",
    "RequestMapper",
    "ApplicationDefaults",
    "SecurityPolicyProvider",
    "ProtocolProvider",
];

/// Children of `<ApplicationDefaults>` the docs allow at most once.
pub(crate) const DEFAULTS_SINGLETONS: [&str; 2] = ["Sessions", "Errors"];

fn parent_is(stack: &[String], name: &str) -> bool {
    stack.last().is_some_and(|s| s == name)
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

    #[test]
    fn test_parse_sessions_extended() {
        let xml = r#"
        <SPConfig xmlns="urn:mace:shibboleth:3.0:native:sp:config">
            <ApplicationDefaults entityID="https://sp.example.org/shibboleth">
                <Sessions handlerURL="/Shibboleth.sso" lifetime="28800" timeout="3600">
                    <SSO entityID="https://idp.example.org/idp/shibboleth">SAML2</SSO>
                    <Logout>SAML2 Local</Logout>
                </Sessions>
            </ApplicationDefaults>
        </SPConfig>
        "#;

        let config = parse_str(xml).unwrap();
        let sessions = config.sessions.as_ref().unwrap();
        assert_eq!(sessions.lifetime.as_deref(), Some("28800"));
        assert_eq!(sessions.timeout.as_deref(), Some("3600"));
        assert!(sessions.has_logout);
        assert_eq!(
            sessions.sso_entity_id.as_deref(),
            Some("https://idp.example.org/idp/shibboleth")
        );
    }

    #[test]
    fn test_parse_errors_element() {
        let xml = r#"
        <SPConfig xmlns="urn:mace:shibboleth:3.0:native:sp:config">
            <ApplicationDefaults entityID="https://sp.example.org/shibboleth">
                <Errors supportContact="admin@example.org"
                        helpLocation="/help"
                        styleSheet="/shibboleth-sp/main.css"
                        session="/errors/session.html"
                        access="/errors/access.html"
                        ssl="/errors/ssl.html"
                        localLogout="/errors/localLogout.html"
                        metadata="/errors/metadata.html"
                        globalLogout="/errors/globalLogout.html"/>
            </ApplicationDefaults>
        </SPConfig>
        "#;

        let config = parse_str(xml).unwrap();
        let errors = config.errors.as_ref().expect("errors should be parsed");
        assert_eq!(errors.support_contact.as_deref(), Some("admin@example.org"));
        assert_eq!(errors.help_location.as_deref(), Some("/help"));
        assert_eq!(
            errors.style_sheet.as_deref(),
            Some("/shibboleth-sp/main.css")
        );
        assert_eq!(
            errors.session_error.as_deref(),
            Some("/errors/session.html")
        );
        assert_eq!(errors.access_error.as_deref(), Some("/errors/access.html"));
        assert_eq!(errors.ssl_error.as_deref(), Some("/errors/ssl.html"));
        assert_eq!(
            errors.local_logout.as_deref(),
            Some("/errors/localLogout.html")
        );
        assert_eq!(
            errors.metadata_error.as_deref(),
            Some("/errors/metadata.html")
        );
        assert_eq!(
            errors.global_logout.as_deref(),
            Some("/errors/globalLogout.html")
        );
    }

    /// Exercises the MetadataProvider stack: a top-level `Chaining` wraps multiple child
    /// providers (XML, LocalDynamic), and nested providers each carry their own filters.
    /// The parser must push/pop the stack so nested children are attributed to their direct parent.
    #[test]
    fn test_parse_chaining_metadata_provider() {
        let xml = r#"
        <SPConfig xmlns="urn:mace:shibboleth:3.0:native:sp:config">
            <ApplicationDefaults entityID="https://sp.example.org/shibboleth">
                <MetadataProvider type="Chaining">
                    <MetadataProvider type="XML" path="idp-metadata.xml"
                                     backingFilePath="/var/cache/shib/idp-metadata.xml"/>
                    <MetadataProvider type="XML"
                                     uri="https://federation.example.org/metadata.xml"
                                     backingFilePath="/var/cache/shib/fed-metadata.xml">
                        <MetadataFilter type="Signature" certificate="fed-signer.pem"/>
                    </MetadataProvider>
                    <MetadataProvider type="LocalDynamic"
                                     sourceDirectory="/etc/shibboleth/metadata"/>
                </MetadataProvider>
            </ApplicationDefaults>
        </SPConfig>
        "#;

        let config = parse_str(xml).unwrap();
        // Chaining provider + 3 nested providers = 4 total
        assert_eq!(
            config.metadata_providers.len(),
            4,
            "Expected 4 providers (chaining + 3 nested)"
        );

        // Find the providers by type/attributes
        let xml_providers: Vec<_> = config
            .metadata_providers
            .iter()
            .filter(|mp| mp.provider_type == "XML")
            .collect();
        assert_eq!(xml_providers.len(), 2);

        // First XML provider has path and backingFilePath
        let local_mp = xml_providers.iter().find(|mp| mp.path.is_some()).unwrap();
        assert_eq!(local_mp.path.as_deref(), Some("idp-metadata.xml"));
        assert_eq!(
            local_mp.backing_file_path.as_deref(),
            Some("/var/cache/shib/idp-metadata.xml")
        );

        // Second XML provider has uri and backingFilePath
        let remote_mp = xml_providers.iter().find(|mp| mp.uri.is_some()).unwrap();
        assert_eq!(
            remote_mp.uri.as_deref(),
            Some("https://federation.example.org/metadata.xml")
        );
        assert_eq!(
            remote_mp.backing_file_path.as_deref(),
            Some("/var/cache/shib/fed-metadata.xml")
        );
        assert_eq!(remote_mp.filters.len(), 1);
        assert_eq!(
            remote_mp.filters[0].certificate.as_deref(),
            Some("fed-signer.pem")
        );

        // LocalDynamic provider has sourceDirectory
        let local_dyn = config
            .metadata_providers
            .iter()
            .find(|mp| mp.provider_type == "LocalDynamic")
            .unwrap();
        assert_eq!(
            local_dyn.source_directory.as_deref(),
            Some("/etc/shibboleth/metadata")
        );

        // Chaining provider
        let chaining = config
            .metadata_providers
            .iter()
            .find(|mp| mp.provider_type == "Chaining")
            .unwrap();
        assert_eq!(chaining.provider_type, "Chaining");
    }

    #[test]
    fn test_parse_sp_version_v3() {
        let xml = r#"
        <SPConfig xmlns="urn:mace:shibboleth:3.0:native:sp:config">
            <ApplicationDefaults entityID="https://sp.example.org/shibboleth"/>
        </SPConfig>
        "#;
        let config = parse_str(xml).unwrap();
        assert_eq!(config.sp_version, SpVersion::V3);
    }

    #[test]
    fn test_parse_sp_version_v2() {
        let xml = r#"
        <SPConfig xmlns="urn:mace:shibboleth:2.0:native:sp:config">
            <ApplicationDefaults entityID="https://sp.example.org/shibboleth"/>
        </SPConfig>
        "#;
        let config = parse_str(xml).unwrap();
        assert_eq!(config.sp_version, SpVersion::V2);
    }

    #[test]
    fn test_parse_sp_version_unknown() {
        let xml = r#"
        <SPConfig xmlns="urn:example:unknown">
            <ApplicationDefaults entityID="https://sp.example.org/shibboleth"/>
        </SPConfig>
        "#;
        let config = parse_str(xml).unwrap();
        assert_eq!(config.sp_version, SpVersion::Unknown);
    }

    #[test]
    fn test_parse_handlers() {
        let xml = r#"
        <SPConfig xmlns="urn:mace:shibboleth:3.0:native:sp:config">
            <ApplicationDefaults entityID="https://sp.example.org/shibboleth">
                <Handler type="Status" Location="/Status" acl="127.0.0.1 ::1"/>
                <Handler type="Session" Location="/Session" showAttributeValues="true"/>
                <Handler type="MetadataGenerator" Location="/Metadata"/>
            </ApplicationDefaults>
        </SPConfig>
        "#;
        let config = parse_str(xml).unwrap();
        assert_eq!(config.handlers.len(), 3);
        assert!(config.status_handler.is_some());
        assert_eq!(config.handlers[1].handler_type, "Session");
        assert_eq!(
            config.handlers[1].show_attribute_values.as_deref(),
            Some("true")
        );
        assert_eq!(config.handlers[2].handler_type, "MetadataGenerator");
    }

    #[test]
    fn test_parse_notify() {
        let xml = r#"
        <SPConfig xmlns="urn:mace:shibboleth:3.0:native:sp:config">
            <ApplicationDefaults entityID="https://sp.example.org/shibboleth">
                <Sessions handlerURL="/Shibboleth.sso">
                    <Notify Channel="back" Location="https://app.example.org/notify"/>
                    <Notify Location="https://app2.example.org/logout"/>
                    <Notify Channel="front"/>
                </Sessions>
            </ApplicationDefaults>
        </SPConfig>
        "#;
        let config = parse_str(xml).unwrap();
        // Only Location values are endpoints; Channel is kept separately
        assert_eq!(config.notify_endpoints.len(), 2);
        assert_eq!(config.notify_elements.len(), 3);
        assert_eq!(config.notify_elements[0].channel.as_deref(), Some("back"));
        assert_eq!(config.notify_elements[2].location, None);
        assert_eq!(config.notify_endpoints[0], "https://app.example.org/notify");
        assert_eq!(
            config.notify_endpoints[1],
            "https://app2.example.org/logout"
        );
    }

    /// A `<TrustEngine>` child inside a `<MetadataFilter type="Signature">` is an
    /// alternative to the `certificate` attribute (REF-026 accepts either).
    /// The parser must mark `has_trust_engine` so REF-026 doesn't false-positive on TrustEngine-only filters.
    #[test]
    fn test_parse_trust_engine_in_metadata_filter() {
        let xml = r#"
        <SPConfig xmlns="urn:mace:shibboleth:3.0:native:sp:config">
            <ApplicationDefaults entityID="https://sp.example.org/shibboleth">
                <MetadataProvider type="XML" uri="https://fed.example.org/metadata.xml">
                    <MetadataFilter type="Signature">
                        <TrustEngine type="StaticPKIX"/>
                    </MetadataFilter>
                </MetadataProvider>
            </ApplicationDefaults>
        </SPConfig>
        "#;
        let config = parse_str(xml).unwrap();
        let mp = config
            .metadata_providers
            .iter()
            .find(|m| m.provider_type == "XML")
            .unwrap();
        assert_eq!(mp.filters.len(), 1);
        assert!(mp.filters[0].has_trust_engine);
    }

    /// Mirrors the Chaining MetadataProvider pattern for CredentialResolvers:
    /// nested File resolvers must be counted both individually and as children of the Chaining
    /// parent. Guards REF-027 (Chaining with <2 children) from miscounting.
    #[test]
    fn test_parse_chaining_credential_resolver() {
        let xml = r#"
        <SPConfig xmlns="urn:mace:shibboleth:3.0:native:sp:config">
            <ApplicationDefaults entityID="https://sp.example.org/shibboleth">
                <CredentialResolver type="Chaining">
                    <CredentialResolver type="File" certificate="sp-cert1.pem" key="sp-key1.pem"/>
                    <CredentialResolver type="File" certificate="sp-cert2.pem" key="sp-key2.pem"/>
                </CredentialResolver>
            </ApplicationDefaults>
        </SPConfig>
        "#;
        let config = parse_str(xml).unwrap();
        // 3 total: Chaining + 2 children
        assert_eq!(config.credential_resolvers.len(), 3);
        let chaining = config
            .credential_resolvers
            .iter()
            .find(|cr| cr.resolver_type == "Chaining")
            .unwrap();
        assert_eq!(chaining.children_count, 2);
    }

    #[test]
    fn test_parse_new_session_attrs() {
        let xml = r#"
        <SPConfig xmlns="urn:mace:shibboleth:3.0:native:sp:config">
            <ApplicationDefaults entityID="https://sp.example.org/shibboleth">
                <Sessions handlerURL="/Shibboleth.sso"
                          postLimit="1048576"
                          idpHistory="true"
                          idpHistoryDays="7"
                          checkAddress="true">
                    <SSO entityID="https://idp.example.org"
                         authnContextClassRef="urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
                         ECP="true">SAML2</SSO>
                </Sessions>
            </ApplicationDefaults>
        </SPConfig>
        "#;
        let config = parse_str(xml).unwrap();
        let sessions = config.sessions.as_ref().unwrap();
        assert_eq!(sessions.post_limit.as_deref(), Some("1048576"));
        assert_eq!(sessions.idp_history.as_deref(), Some("true"));
        assert_eq!(sessions.idp_history_days.as_deref(), Some("7"));
        assert_eq!(sessions.check_address.as_deref(), Some("true"));
        assert_eq!(
            config.sso_authn_context_class_ref.as_deref(),
            Some("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport")
        );
        assert_eq!(config.sso_ecp.as_deref(), Some("true"));
    }

    /// Per-override entityIDs are captured as `(id, entityID)` tuples so REF-024 can
    /// detect overrides that redundantly repeat the parent entityID (a common copy-paste bug).
    #[test]
    fn test_parse_application_override_entity_ids() {
        let xml = r#"
        <SPConfig xmlns="urn:mace:shibboleth:3.0:native:sp:config">
            <ApplicationDefaults entityID="https://sp.example.org/shibboleth">
                <ApplicationOverride id="app1" entityID="https://sp.example.org/shibboleth"/>
                <ApplicationOverride id="app2" entityID="https://sp2.example.org/shibboleth"/>
            </ApplicationDefaults>
        </SPConfig>
        "#;
        let config = parse_str(xml).unwrap();
        assert_eq!(config.application_override_entity_ids.len(), 2);
        assert_eq!(config.application_override_entity_ids[0].0, "app1");
        assert_eq!(
            config.application_override_entity_ids[0].1.as_deref(),
            Some("https://sp.example.org/shibboleth")
        );
    }

    #[test]
    fn test_parse_security_policy_provider_validate() {
        let xml = r#"
        <SPConfig xmlns="urn:mace:shibboleth:3.0:native:sp:config">
            <ApplicationDefaults entityID="https://sp.example.org/shibboleth">
                <SecurityPolicyProvider path="security-policy.xml" validate="true"/>
            </ApplicationDefaults>
        </SPConfig>
        "#;
        let config = parse_str(xml).unwrap();
        assert_eq!(
            config.security_policy_provider_path.as_deref(),
            Some("security-policy.xml")
        );
        assert_eq!(
            config.security_policy_provider_validate.as_deref(),
            Some("true")
        );
    }

    #[test]
    fn test_parse_tcp_listener() {
        let xml = r#"
        <SPConfig xmlns="urn:mace:shibboleth:3.0:native:sp:config">
            <TCPListener address="127.0.0.1" port="1600"/>
            <ApplicationDefaults entityID="https://sp.example.org/shibboleth"/>
        </SPConfig>
        "#;
        let config = parse_str(xml).unwrap();
        assert_eq!(config.tcp_listener_address.as_deref(), Some("127.0.0.1"));
    }

    #[test]
    fn test_parse_unix_listener() {
        let xml = r#"
        <SPConfig xmlns="urn:mace:shibboleth:3.0:native:sp:config">
            <UnixListener address="/var/run/shibboleth/shibd.sock"/>
            <ApplicationDefaults entityID="https://sp.example.org/shibboleth"/>
        </SPConfig>
        "#;
        let config = parse_str(xml).unwrap();
        assert_eq!(
            config.tcp_listener_address.as_deref(),
            Some("/var/run/shibboleth/shibd.sock")
        );
    }

    #[test]
    fn test_parse_request_map_application_ids() {
        let xml = r#"
        <SPConfig xmlns="urn:mace:shibboleth:3.0:native:sp:config">
            <RequestMap>
                <Host name="sp.example.org" applicationId="app1"/>
                <Host name="sp2.example.org">
                    <Path name="/secure" applicationId="app2"/>
                </Host>
            </RequestMap>
            <ApplicationDefaults entityID="https://sp.example.org/shibboleth"/>
        </SPConfig>
        "#;
        let config = parse_str(xml).unwrap();
        assert_eq!(config.request_map_application_ids.len(), 2);
        assert_eq!(config.request_map_application_ids[0], "app1");
        assert_eq!(config.request_map_application_ids[1], "app2");
    }

    #[test]
    fn test_parse_home_url() {
        let xml = r#"
        <SPConfig xmlns="urn:mace:shibboleth:3.0:native:sp:config">
            <ApplicationDefaults entityID="https://sp.example.org/shibboleth"
                                 homeURL="https://sp.example.org/"/>
        </SPConfig>
        "#;
        let config = parse_str(xml).unwrap();
        let app = config.application_defaults.as_ref().unwrap();
        assert_eq!(app.home_url.as_deref(), Some("https://sp.example.org/"));
    }

    #[test]
    fn test_parse_same_site_fallback_and_post_data() {
        let xml = r#"
        <SPConfig xmlns="urn:mace:shibboleth:3.0:native:sp:config">
            <ApplicationDefaults entityID="https://sp.example.org/shibboleth">
                <Sessions handlerURL="/Shibboleth.sso"
                          sameSiteFallback="true"
                          postData="ss:mem">
                    <SSO entityID="https://idp.example.org">SAML2</SSO>
                </Sessions>
            </ApplicationDefaults>
        </SPConfig>
        "#;
        let config = parse_str(xml).unwrap();
        let sessions = config.sessions.as_ref().unwrap();
        assert_eq!(sessions.same_site_fallback.as_deref(), Some("true"));
        assert_eq!(sessions.post_data.as_deref(), Some("ss:mem"));
    }

    #[test]
    fn test_parse_logout_outgoing_bindings() {
        let xml = r#"
        <SPConfig xmlns="urn:mace:shibboleth:3.0:native:sp:config">
            <ApplicationDefaults entityID="https://sp.example.org/shibboleth">
                <Sessions handlerURL="/Shibboleth.sso">
                    <SSO entityID="https://idp.example.org">SAML2</SSO>
                    <Logout outgoingBindings="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect">SAML2 Local</Logout>
                </Sessions>
            </ApplicationDefaults>
        </SPConfig>
        "#;
        let config = parse_str(xml).unwrap();
        let sessions = config.sessions.as_ref().unwrap();
        assert_eq!(
            sessions.logout_outgoing_bindings.as_deref(),
            Some("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect")
        );
    }

    /// `children_count` drives REF-031 (Chaining with <2 children). Guards the
    /// stack-based counter from either double-counting (end-tag event races) or
    /// undercounting when nested providers also carry child elements.
    #[test]
    fn test_parse_metadata_provider_children_count() {
        let xml = r#"
        <SPConfig xmlns="urn:mace:shibboleth:3.0:native:sp:config">
            <ApplicationDefaults entityID="https://sp.example.org/shibboleth">
                <MetadataProvider type="Chaining">
                    <MetadataProvider type="XML" path="idp1.xml"/>
                    <MetadataProvider type="XML" path="idp2.xml"/>
                    <MetadataProvider type="XML" path="idp3.xml"/>
                </MetadataProvider>
            </ApplicationDefaults>
        </SPConfig>
        "#;
        let config = parse_str(xml).unwrap();
        let chaining = config
            .metadata_providers
            .iter()
            .find(|mp| mp.provider_type == "Chaining")
            .unwrap();
        assert_eq!(chaining.children_count, 3);
    }

    #[test]
    fn test_parse_session_initiator_info() {
        let xml = r#"
        <SPConfig xmlns="urn:mace:shibboleth:3.0:native:sp:config">
            <ApplicationDefaults entityID="https://sp.example.org/shibboleth">
                <Sessions handlerURL="/Shibboleth.sso">
                    <SessionInitiator type="SAML2" id="default-init" isDefault="true"/>
                    <SessionInitiator type="Shib1" id="legacy-init"/>
                </Sessions>
            </ApplicationDefaults>
        </SPConfig>
        "#;
        let config = parse_str(xml).unwrap();
        assert_eq!(config.session_initiators.len(), 2);
        assert_eq!(
            config.session_initiators[0].initiator_type.as_deref(),
            Some("SAML2")
        );
        assert_eq!(
            config.session_initiators[0].id.as_deref(),
            Some("default-init")
        );
        assert_eq!(
            config.session_initiators[0].is_default.as_deref(),
            Some("true")
        );
        assert_eq!(
            config.session_initiators[1].initiator_type.as_deref(),
            Some("Shib1")
        );
        assert!(config.session_initiators[1].is_default.is_none());
    }

    #[test]
    fn test_parse_logout_initiator_info() {
        let xml = r#"
        <SPConfig xmlns="urn:mace:shibboleth:3.0:native:sp:config">
            <ApplicationDefaults entityID="https://sp.example.org/shibboleth">
                <Sessions handlerURL="/Shibboleth.sso">
                    <LogoutInitiator type="SAML2" signing="true" asynchronous="false" notifyWithout="true"/>
                    <Logout>SAML2 Local</Logout>
                </Sessions>
            </ApplicationDefaults>
        </SPConfig>
        "#;
        let config = parse_str(xml).unwrap();
        assert_eq!(config.logout_initiators.len(), 2);
        assert_eq!(
            config.logout_initiators[0].initiator_type.as_deref(),
            Some("SAML2")
        );
        assert_eq!(config.logout_initiators[0].signing.as_deref(), Some("true"));
        assert_eq!(
            config.logout_initiators[0].asynchronous.as_deref(),
            Some("false")
        );
        assert_eq!(
            config.logout_initiators[0].notify_without.as_deref(),
            Some("true")
        );
    }

    #[test]
    fn test_parse_request_map_content_settings() {
        let xml = r#"
        <SPConfig xmlns="urn:mace:shibboleth:3.0:native:sp:config">
            <RequestMap>
                <Host name="sp.example.org" requireSession="true" authType="shibboleth">
                    <Path name="/admin" forceAuthn="true" isPassive="false"/>
                </Host>
            </RequestMap>
            <ApplicationDefaults entityID="https://sp.example.org/shibboleth"/>
        </SPConfig>
        "#;
        let config = parse_str(xml).unwrap();
        assert_eq!(config.request_map_content_settings.len(), 2);
        let host = &config.request_map_content_settings[0];
        assert_eq!(host.element, "Host");
        assert_eq!(host.name.as_deref(), Some("sp.example.org"));
        assert_eq!(host.require_session.as_deref(), Some("true"));
        assert_eq!(host.auth_type.as_deref(), Some("shibboleth"));
        let path = &config.request_map_content_settings[1];
        assert_eq!(path.element, "Path");
        assert_eq!(path.name.as_deref(), Some("/admin"));
        assert_eq!(path.force_authn.as_deref(), Some("true"));
        assert_eq!(path.is_passive.as_deref(), Some("false"));
    }

    #[test]
    fn test_parse_new_sessions_attrs() {
        let xml = r#"
        <SPConfig xmlns="urn:mace:shibboleth:3.0:native:sp:config">
            <ApplicationDefaults entityID="https://sp.example.org/shibboleth">
                <Sessions handlerURL="/Shibboleth.sso"
                          maxTimeSinceAuthn="28800"
                          cookieLifetime="86400"
                          exportACL="127.0.0.1 ::1"
                          exportLocation="/export"
                          redirectAllow="https://sp.example.org">
                    <SSO entityID="https://idp.example.org">SAML2</SSO>
                </Sessions>
            </ApplicationDefaults>
        </SPConfig>
        "#;
        let config = parse_str(xml).unwrap();
        let sessions = config.sessions.as_ref().unwrap();
        assert_eq!(sessions.max_time_since_authn.as_deref(), Some("28800"));
        assert_eq!(sessions.cookie_lifetime.as_deref(), Some("86400"));
        assert_eq!(sessions.export_acl.as_deref(), Some("127.0.0.1 ::1"));
        assert_eq!(sessions.export_location.as_deref(), Some("/export"));
        assert_eq!(
            sessions.redirect_allow.as_deref(),
            Some("https://sp.example.org")
        );
    }

    #[test]
    fn test_parse_new_app_defaults_attrs() {
        let xml = r#"
        <SPConfig xmlns="urn:mace:shibboleth:3.0:native:sp:config">
            <ApplicationDefaults entityID="https://sp.example.org/shibboleth"
                                 signingAlg="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
                                 digestAlg="http://www.w3.org/2001/04/xmlenc#sha256"
                                 requireTransportAuth="true"
                                 requireConfidentiality="true"/>
        </SPConfig>
        "#;
        let config = parse_str(xml).unwrap();
        let app = config.application_defaults.as_ref().unwrap();
        assert_eq!(
            app.signing_alg.as_deref(),
            Some("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
        );
        assert_eq!(
            app.digest_alg.as_deref(),
            Some("http://www.w3.org/2001/04/xmlenc#sha256")
        );
        assert_eq!(app.require_transport_auth.as_deref(), Some("true"));
        assert_eq!(app.require_confidentiality.as_deref(), Some("true"));
    }

    #[test]
    fn test_parse_new_metadata_provider_attrs() {
        let xml = r#"
        <SPConfig xmlns="urn:mace:shibboleth:3.0:native:sp:config">
            <ApplicationDefaults entityID="https://sp.example.org/shibboleth">
                <MetadataProvider type="XML" id="primary" validate="true" ignoreTransport="true"
                                 path="idp-metadata.xml"/>
            </ApplicationDefaults>
        </SPConfig>
        "#;
        let config = parse_str(xml).unwrap();
        let mp = config
            .metadata_providers
            .iter()
            .find(|m| m.provider_type == "XML")
            .unwrap();
        assert_eq!(mp.id_attr.as_deref(), Some("primary"));
        assert_eq!(mp.validate_attr.as_deref(), Some("true"));
        assert_eq!(mp.ignore_transport.as_deref(), Some("true"));
    }

    #[test]
    fn test_parse_new_metadata_filter_attrs() {
        let xml = r#"
        <SPConfig xmlns="urn:mace:shibboleth:3.0:native:sp:config">
            <ApplicationDefaults entityID="https://sp.example.org/shibboleth">
                <MetadataProvider type="XML" uri="https://fed.example.org/metadata.xml">
                    <MetadataFilter type="Signature" verifyName="false" verifyBackup="true"/>
                </MetadataProvider>
            </ApplicationDefaults>
        </SPConfig>
        "#;
        let config = parse_str(xml).unwrap();
        let mp = config
            .metadata_providers
            .iter()
            .find(|m| m.provider_type == "XML")
            .unwrap();
        assert_eq!(mp.filters.len(), 1);
        assert_eq!(mp.filters[0].verify_name.as_deref(), Some("false"));
        assert_eq!(mp.filters[0].verify_backup.as_deref(), Some("true"));
    }

    #[test]
    fn test_parse_request_mapper_type() {
        let xml = r#"
        <SPConfig xmlns="urn:mace:shibboleth:3.0:native:sp:config">
            <RequestMapper type="XML"/>
            <ApplicationDefaults entityID="https://sp.example.org/shibboleth"/>
        </SPConfig>
        "#;
        let config = parse_str(xml).unwrap();
        assert_eq!(config.request_map_type.as_deref(), Some("XML"));
    }

    #[test]
    fn test_parse_request_map_root_app_id() {
        let xml = r#"
        <SPConfig xmlns="urn:mace:shibboleth:3.0:native:sp:config">
            <RequestMap applicationId="custom">
                <Host name="sp.example.org"/>
            </RequestMap>
            <ApplicationDefaults entityID="https://sp.example.org/shibboleth"/>
        </SPConfig>
        "#;
        let config = parse_str(xml).unwrap();
        assert_eq!(config.request_map_root_app_id.as_deref(), Some("custom"));
    }

    mod properties {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            /// A malformed config must come back as an error or a partial config, never a panic.
            #[test]
            fn parsing_arbitrary_text_never_panics(
                doc in "(<SPConfig|<Sessions|<ApplicationDefaults|</|/>|>|\"|'|=| |\n|[a-zA-Z]|&amp;|&#x?[0-9]*;|<!--|-->|\\PC){0,60}"
            ) {
                let _ = parse_str(&doc);
            }
        }
    }
}
