# Changelog

All notable changes to shibcheck are documented in this file.

## [Unreleased]

### Added
- REF-010: Local metadata files are validated for SAML root element (`EntityDescriptor` or `EntitiesDescriptor`)
- REF-011: Key files are validated as PEM-encoded private keys
- REF-012: Duplicate `MetadataProvider` sources are detected
- REF-013: `<Errors>` template file paths are checked for existence
- SEC-016: Private key files are checked for restrictive Unix permissions (not world/group-readable)
- XML-016: `entityID` is validated as an absolute URI (`https://`, `http://`, or `urn:`)
- XML-017: `attribute-map.xml` is checked for at least one attribute mapping
- XML-018: `handlerURL` is validated to start with `/`
- XML-019: Presence of `<Logout>` or `<LogoutInitiator>` element is checked
- REF-014: Duplicate attribute IDs in `attribute-map.xml` are detected
- REF-015: Duplicate attribute names (OIDs/URNs) in `attribute-map.xml` are detected
- REF-016: `<SSO>` `entityID` is cross-referenced against loaded local metadata
- SEC-017: `cookieProps` is checked for `SameSite` attribute (modern browser compatibility)
- SEC-018: `entityID` using HTTP instead of HTTPS is flagged
- SEC-019: `Sessions` `lifetime` is checked for reasonable values (not 0, not > 24h)
- SEC-020: `Sessions` `timeout` is checked for reasonable values (not 0, not > 8h)
- `<Sessions>` `lifetime` and `timeout` attribute parsing
- `<Logout>` and `<LogoutInitiator>` element presence parsing
- `<SSO>` `entityID` attribute parsing
- `<Errors>` element parsing from `shibboleth2.xml`
- `--check-remote` CLI flag to fetch and validate remote metadata URLs (REF-009)
  - Checks HTTP reachability (Error on failure)
  - Validates XML well-formedness (Warning on malformed)
  - Verifies SAML metadata root element (`EntityDescriptor` or `EntitiesDescriptor`)
- `backingFilePath` attribute parsing on `MetadataProvider` elements
  - REF-003 now reports Info-level if the backing file is missing (auto-created on first fetch)
- `sourceDirectory` attribute parsing for `LocalDynamicMetadataProvider`
  - REF-003 now reports Error-level if the source directory does not exist

### Fixed
- Nested (chaining) `MetadataProvider` parsing: inner providers no longer overwrite the outer provider. All providers in a `<MetadataProvider type="Chaining">` block are now captured individually.
- `MetadataFilter` elements now correctly attach to the innermost open provider.

## [0.1.0] - Initial release

### Added
- XML validity checks (XML-001 to XML-015)
- Cross-file reference checks (REF-001 to REF-008)
- Security best-practice checks (SEC-001 to SEC-015)
- `--json` output for scripting and CI
- `-v` verbose mode to show passed checks
- `--no-color` flag for piped output
- Certificate expiry and key-size validation
- Attribute map / attribute policy cross-referencing
