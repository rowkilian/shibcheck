use std::fs;
use std::path::Path;

const METADATA_URL: &str = "https://mocksaml.com/api/saml/metadata";
const METADATA_FILENAME: &str = "mocksaml-metadata.xml";
const ENTITY_ID: &str = "https://saml.example.com/entityid";

pub fn run(base_dir: &Path, force: bool) -> Result<(), String> {
    if !base_dir.is_dir() {
        return Err(format!("'{}' is not a directory", base_dir.display()));
    }

    let output_path = base_dir.join(METADATA_FILENAME);

    if output_path.exists() && !force {
        return Err(format!(
            "'{}' already exists. Use --force to overwrite.",
            output_path.display()
        ));
    }

    eprintln!("Fetching metadata from {} ...", METADATA_URL);

    let body = ureq::get(METADATA_URL)
        .call()
        .map_err(|e| format!("Failed to fetch metadata: {}", e))?
        .into_body()
        .read_to_string()
        .map_err(|e| format!("Failed to read response body: {}", e))?;

    fs::write(&output_path, &body)
        .map_err(|e| format!("Failed to write {}: {}", output_path.display(), e))?;

    eprintln!("Saved metadata to {}", output_path.display());
    eprintln!();
    eprintln!("Add the following to your shibboleth2.xml:");
    eprintln!();
    eprintln!("  <MetadataProvider type=\"XML\" path=\"{}\"/>", METADATA_FILENAME);
    eprintln!();
    eprintln!("  <SSO entityID=\"{}\">", ENTITY_ID);
    eprintln!("    SAML2");
    eprintln!("  </SSO>");

    Ok(())
}
