# Changelog

All notable changes to shibcheck are documented in this file.

## [Unreleased]

### Added
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
