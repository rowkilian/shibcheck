/// Parsed representation of shibboleth2.xml
#[derive(Debug, Default)]
pub struct ShibbolethConfig {
    pub has_sp_config: bool,
    pub has_application_defaults: bool,
    pub entity_id: Option<String>,
    pub sessions: Option<SessionsConfig>,
    pub metadata_providers: Vec<MetadataProvider>,
    pub credential_resolvers: Vec<CredentialResolver>,
    pub attribute_extractor_paths: Vec<String>,
    pub attribute_filter_paths: Vec<String>,
    pub application_defaults: Option<ApplicationDefaults>,
    pub status_handler: Option<StatusHandler>,
}

#[derive(Debug, Default)]
pub struct ApplicationDefaults {
    pub remote_user: Option<String>,
    pub signing: Option<String>,
    pub encryption: Option<String>,
}

#[derive(Debug, Default)]
pub struct SessionsConfig {
    pub handler_url: Option<String>,
    pub handler_ssl: Option<String>,
    pub cookie_props: Option<String>,
    pub has_sso: bool,
    pub has_session_initiator: bool,
}

#[derive(Debug)]
pub struct MetadataProvider {
    pub provider_type: String,
    pub uri: Option<String>,
    pub path: Option<String>,
    pub url: Option<String>,
    pub backing_file_path: Option<String>,
    pub source_directory: Option<String>,
    pub filters: Vec<MetadataFilter>,
}

#[derive(Debug)]
pub struct MetadataFilter {
    pub filter_type: String,
    pub certificate: Option<String>,
    pub max_validity_interval: Option<String>,
    pub require_valid_until: Option<String>,
}

#[derive(Debug)]
pub struct CredentialResolver {
    pub resolver_type: String,
    pub use_attr: Option<String>,
    pub certificate: Option<String>,
    pub key: Option<String>,
}

#[derive(Debug, Default)]
pub struct StatusHandler {
    pub acl: Option<String>,
}
