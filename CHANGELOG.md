# Changelog

All notable changes to shibcheck are documented in this file.

## [Unreleased]

### Added
- File summary section in all output formats (terminal, JSON, HTML, SARIF) showing which files were found and which were not. Lists primary config files, certificates, keys, metadata, backing files, attribute extractors/filters, security policy, and error templates.
- `init-test-idp` subcommand: fetches [mocksaml.com](https://mocksaml.com) metadata and prints the XML snippet to add to `shibboleth2.xml` for quick test IdP setup
- SP version detection from `<SPConfig xmlns="...">` namespace (`SpVersion::V2`, `V3`, or `Unknown`)
- XML-020: Informational check reporting detected SP version (SP2 flagged as end-of-life)
- XML-021: Warning when `REMOTE_USER` is not set on `ApplicationDefaults`
- REF-017: Warning when a remote `MetadataProvider` has no `backingFilePath` (SP cannot start if remote source is unavailable)
- SEC-021: Certificate-key mismatch detection (compares RSA modulus between certificate and private key)
- Version-aware documentation URLs: SP2 configs now link to the SHIB2 wiki instead of SP3 pages

### Changed
- SEC-002/SEC-003: `cookieProps="https"` shorthand is now only treated as secure/httpOnly on SP3 (fixes false-positive pass on SP2)
- SEC-017: Suggestion text is version-aware; SP2 users are told SameSite is not supported in cookieProps
- XML-019: Suggestion text is version-aware (SP3 suggests `<Logout>`, SP2 suggests `<LogoutInitiator>`)

### Previously Added
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
