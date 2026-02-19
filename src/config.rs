use anyhow::Result;
use std::path::{Path, PathBuf};

use crate::model::attribute_map::AttributeMap;
use crate::model::attribute_policy::AttributePolicy;
use crate::model::shibboleth_config::ShibbolethConfig;
use crate::parsers;

/// All discovered and parsed configuration
pub struct DiscoveredConfig {
    pub base_dir: PathBuf,
    pub shibboleth_xml_path: PathBuf,
    pub shibboleth_xml_exists: bool,
    pub shibboleth_xml_well_formed: bool,
    pub shibboleth_config: Option<ShibbolethConfig>,

    pub attribute_map_path: PathBuf,
    pub attribute_map_exists: bool,
    pub attribute_map_well_formed: bool,
    pub attribute_map: Option<AttributeMap>,

    pub attribute_policy_path: PathBuf,
    pub attribute_policy_exists: bool,
    pub attribute_policy_well_formed: bool,
    pub attribute_policy: Option<AttributePolicy>,

    /// Other XML files found in the directory (excluding the main three)
    pub other_xml_files: Vec<PathBuf>,
    /// Other XML files that failed well-formedness check
    pub other_xml_malformed: Vec<(PathBuf, String)>,
}

pub fn discover(base_dir: &Path) -> Result<DiscoveredConfig> {
    let shibboleth_xml_path = base_dir.join("shibboleth2.xml");
    let attribute_map_path = base_dir.join("attribute-map.xml");
    let attribute_policy_path = base_dir.join("attribute-policy.xml");

    let shibboleth_xml_exists = shibboleth_xml_path.exists();
    let attribute_map_exists = attribute_map_path.exists();
    let attribute_policy_exists = attribute_policy_path.exists();

    // Parse shibboleth2.xml
    let (shibboleth_xml_well_formed, shibboleth_config) = if shibboleth_xml_exists {
        match parsers::shibboleth_xml::parse(&shibboleth_xml_path) {
            Ok(config) => (true, Some(config)),
            Err(_) => (false, None),
        }
    } else {
        (false, None)
    };

    // Parse attribute-map.xml
    let (attribute_map_well_formed, attribute_map) = if attribute_map_exists {
        match parsers::attribute_map::parse(&attribute_map_path) {
            Ok(map) => (true, Some(map)),
            Err(_) => (false, None),
        }
    } else {
        (false, None)
    };

    // Parse attribute-policy.xml
    let (attribute_policy_well_formed, attribute_policy) = if attribute_policy_exists {
        match parsers::attribute_policy::parse(&attribute_policy_path) {
            Ok(policy) => (true, Some(policy)),
            Err(_) => (false, None),
        }
    } else {
        (false, None)
    };

    // Discover other XML files
    let pattern = base_dir.join("*.xml").to_string_lossy().to_string();
    let main_files: Vec<PathBuf> = vec![
        shibboleth_xml_path.clone(),
        attribute_map_path.clone(),
        attribute_policy_path.clone(),
    ];

    let mut other_xml_files = Vec::new();
    let mut other_xml_malformed = Vec::new();

    if let Ok(entries) = glob::glob(&pattern) {
        for entry in entries.filter_map(|e| e.ok()) {
            if !main_files.iter().any(|f| *f == entry) {
                other_xml_files.push(entry.clone());
                if let Err(e) = parsers::shibboleth_xml::check_well_formed(&entry) {
                    other_xml_malformed.push((entry, e.to_string()));
                }
            }
        }
    }

    Ok(DiscoveredConfig {
        base_dir: base_dir.to_path_buf(),
        shibboleth_xml_path,
        shibboleth_xml_exists,
        shibboleth_xml_well_formed,
        shibboleth_config,
        attribute_map_path,
        attribute_map_exists,
        attribute_map_well_formed,
        attribute_map,
        attribute_policy_path,
        attribute_policy_exists,
        attribute_policy_well_formed,
        attribute_policy,
        other_xml_files,
        other_xml_malformed,
    })
}
