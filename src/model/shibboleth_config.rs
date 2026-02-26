#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SpVersion {
    #[default]
    Unknown,
    V2,
    V3,
}

/// Parsed representation of shibboleth2.xml
#[derive(Debug, Default)]
pub struct ShibbolethConfig {
    pub has_sp_config: bool,
    pub sp_version: SpVersion,
    pub has_application_defaults: bool,
    pub entity_id: Option<String>,
    pub sessions: Option<SessionsConfig>,
    pub metadata_providers: Vec<MetadataProvider>,
    pub credential_resolvers: Vec<CredentialResolver>,
    pub attribute_extractor_paths: Vec<String>,
    pub attribute_filter_paths: Vec<String>,
    pub application_defaults: Option<ApplicationDefaults>,
    pub status_handler: Option<StatusHandler>,
    pub errors: Option<ErrorsConfig>,
    pub clock_skew: Option<String>,
    pub security_policy_provider_path: Option<String>,
    pub application_override_ids: Vec<String>,
    pub handlers: Vec<HandlerInfo>,
    pub notify_endpoints: Vec<String>,
    pub application_override_entity_ids: Vec<(String, Option<String>)>,
    pub sso_authn_context_class_ref: Option<String>,
    pub sso_ecp: Option<String>,
    pub security_policy_provider_validate: Option<String>,
    pub tcp_listener_address: Option<String>,
    pub request_map_application_ids: Vec<String>,
}

#[derive(Debug, Default)]
pub struct ApplicationDefaults {
    pub remote_user: Option<String>,
    pub signing: Option<String>,
    pub encryption: Option<String>,
    pub cipher_suites: Option<String>,
    pub home_url: Option<String>,
}

#[derive(Debug, Default)]
pub struct SessionsConfig {
    pub handler_url: Option<String>,
    pub handler_ssl: Option<String>,
    pub cookie_props: Option<String>,
    pub lifetime: Option<String>,
    pub timeout: Option<String>,
    pub has_sso: bool,
    pub has_session_initiator: bool,
    pub has_logout: bool,
    pub sso_entity_id: Option<String>,
    pub redirect_limit: Option<String>,
    pub consistent_address: Option<String>,
    pub relay_state: Option<String>,
    pub redirect_whitelist: Option<String>,
    pub sso_discovery_url: Option<String>,
    pub sso_discovery_protocol: Option<String>,
    pub sso_protocols: Option<String>,
    pub logout_protocols: Option<String>,
    pub post_limit: Option<String>,
    pub idp_history: Option<String>,
    pub idp_history_days: Option<String>,
    pub check_address: Option<String>,
    pub same_site_fallback: Option<String>,
    pub post_data: Option<String>,
    pub logout_outgoing_bindings: Option<String>,
}

#[derive(Debug)]
pub struct MetadataProvider {
    pub provider_type: String,
    pub uri: Option<String>,
    pub path: Option<String>,
    pub url: Option<String>,
    pub backing_file_path: Option<String>,
    pub source_directory: Option<String>,
    pub reload_interval: Option<String>,
    pub file_attr: Option<String>,
    pub filters: Vec<MetadataFilter>,
    pub max_refresh_delay: Option<String>,
    pub children_count: usize,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct MetadataFilter {
    pub filter_type: String,
    pub certificate: Option<String>,
    pub max_validity_interval: Option<String>,
    pub require_valid_until: Option<String>,
    pub has_trust_engine: bool,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct CredentialResolver {
    pub resolver_type: String,
    pub use_attr: Option<String>,
    pub certificate: Option<String>,
    pub key: Option<String>,
    pub children_count: usize,
}

#[derive(Debug, Default)]
pub struct StatusHandler {
    pub acl: Option<String>,
}

#[derive(Debug, Default)]
#[allow(dead_code)]
pub struct ErrorsConfig {
    pub support_contact: Option<String>,
    pub help_location: Option<String>,
    pub style_sheet: Option<String>,
    pub session_error: Option<String>,
    pub access_error: Option<String>,
    pub ssl_error: Option<String>,
    pub local_logout: Option<String>,
    pub metadata_error: Option<String>,
    pub global_logout: Option<String>,
}

#[derive(Debug)]
pub struct HandlerInfo {
    pub handler_type: String,
    pub location: Option<String>,
    pub show_attribute_values: Option<String>,
    pub acl: Option<String>,
}
