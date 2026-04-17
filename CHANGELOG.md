# Changelog

All notable changes to shibcheck are documented in this file.

## [0.8.0]

### Fixed
- `.shibcheckrc` `no_color` and `watch` flags were silently ignored. Both are now honored (CLI flags still take precedence).
- Malformed `.shibcheckrc` files now print a warning on stderr; previously they were silently replaced with defaults.
- SARIF output `informationUri` was a `<owner>` placeholder. Now wired to the real repository URL (via `CARGO_PKG_REPOSITORY`).
- JSON and SARIF serialization failures now propagate as a non-zero exit code (2) with a clear error, instead of printing to stderr while exiting 0.
- Certificate `notBefore` / `notAfter` timestamps that fell outside `DateTime<Utc>`'s representable range previously coerced silently to `1970-01-01`, making expiry checks wrong. Out-of-range dates now surface as a parse error.
- Added explicit 15s `timeout_global` for remote metadata fetches (`REF-009`) and `init-test-idp`; federation metadata is capped at 64 MiB. Previously a hung remote could stall the tool.
- Cert-parse failures in `SEC-008` / `SEC-013` (expiry, key size) and `SEC-021` (cert/key match) no longer silently drop their results — new **SEC-126** warning surfaces the parse failure and notes which checks were skipped. Non-RSA pairs now cleanly skip `SEC-021` via a dedicated `CertKeyMatch::SkippedNonRsa` outcome.
- `SEC-011` signature-filter detection no longer matches a stray lowercase `"signature"` that Shibboleth itself would reject at load time.
- `REF-001` (cert), `REF-002` (key), and `REF-003` (metadata path) now handle absolute paths correctly on all platforms via a shared `DiscoveredConfig::resolve_path` helper. `security.rs` user-controlled path sites were updated to the same helper.

### Changed
- `REF-001`, `REF-002`, `REF-003` now attach their `file:line` source location at the check site (pointing at the CredentialResolver / MetadataProvider that references the file), instead of relying on the message-regexing fallback in `annotate_locations`. The fallback still handles the other ~150 checks; those will be migrated incrementally.
- `src/checks/migration.rs` rewritten as a `(code, fn)` registry (`CheckFn = fn(&DiscoveredConfig, &ShibbolethConfig) -> Vec<CheckResult>`) instead of a single 700-line `run()`. Each of the 24 MIG checks is now a standalone function. First proof-of-concept for the wider check-registry refactor.
- `run_multi` now honors per-directory `rc.no_color`.
- Watch mode surfaces tool-error exit codes (exit 2) from the run closure instead of silently discarding them.
- SARIF output streams through `stdout.lock()` / `to_writer_pretty` instead of `println!`-ing a serialized string.

### Internal
- New `src/http.rs` with `build_agent(timeout)`; both remote-fetch sites reuse it. `check_remote_metadata` now takes `&Agent`, so a single agent is built per run instead of one per URL.
- Hoisted `local_name` / `get_attr` XML parser helpers into `src/parsers/mod.rs`; three parsers previously duplicated them.
- `Cargo.toml` now sets `repository = "https://github.com/rowkilian/shibcheck"`.
- Added regression tests: malformed rc warning, SEC-126 on corrupt cert, REF-001 location at check site, SARIF `informationUri` is a real URL.

## [0.7.0]

### Added
- `--markdown` output format: generates a Markdown report with tables per category, severity badges, locations, and doc links. Also configurable via `.shibcheckrc` with `markdown = true`.
- GitHub Action (`action.yml`): reusable composite action that downloads the correct binary, runs checks, and optionally uploads SARIF to GitHub Code Scanning.
- README: documented all output formats (Markdown, SARIF, HTML, JSON), `.shibcheckrc` configuration file reference, and GitHub Action usage with examples.

## [0.6.1]

### Fixed
- XML-029: False positives on MetadataProviders using the `file` attribute (SP2-era local metadata). The `file` attribute is now recognized as a valid data source alongside `path`, `url`, `uri`, and `sourceDirectory`.

### Improved
- Per-provider identification in check messages: all MetadataProvider-related checks now include the provider's URI, file, path, or ID in the message so each finding is distinguishable when multiple providers are configured.
- Location resolution for MetadataProviders: the `-->` file:line annotation now points to the correct provider instead of always showing the first one.
- Smart location resolution for repeated elements (MetadataProvider, CredentialResolver, Handler) uses message content to find the specific element in the XML.

## [0.6.0]

### Added
- REF-034: Warning when local metadata `validUntil` has expired
- REF-035: Info when local metadata `validUntil` expires within 30 days
- OPS-032: Info when `ApplicationOverride` defines own `<Sessions>` (replaces parent, not merged)
- OPS-033: Info when `ApplicationOverride` defines own `<Errors>` (replaces parent)
- OPS-034: Info when `ApplicationOverride` defines own `<CredentialResolver>` (replaces parent)
- OPS-035: Info when `ApplicationOverride` defines own `<MetadataProvider>` (replaces parent)
- SEC-065: Warning when `ApplicationOverride` `<Sessions>` is missing `redirectLimit` (not inherited)
- SEC-066: Info when `idpHistory` is enabled (leaks IdP usage pattern to client via cookie)
- SEC-067: Info when `maxTimeSinceAuthn` not set on Sessions (stale authentications accepted)
- SEC-068: Info when `cookieLifetime` exceeds session `lifetime` (cookie persists beyond session)
- SEC-069: Warning when `RequireValidUntil` MetadataFilter is explicitly disabled
- SEC-070: Error when `SignatureMetadataFilter` has no certificate and no TrustEngine
- SEC-071: Info when `checkAddress` explicitly set to `false` (IP consistency checking disabled)
- SEC-072: Error when inline private key material detected in `shibboleth2.xml`
- SEC-073: Info when remote `MetadataProvider` `maxRefreshDelay` exceeds 24 hours
- SEC-074: Info when no encryption `CredentialResolver` configured
- SEC-075: Info when `NameIDFormat` uses `emailAddress` (PII in NameID)
- SEC-076: Warning when `SessionInitiator` uses SAML1 protocol
- SEC-077: Info when signing and encryption share the same certificate
- SEC-078: Info when `idpHistoryDays` exceeds 365 (long tracking window)
- SEC-079: Info when `sameSiteFallback` enabled (extra cookie surface area)
- SEC-080: Info when `Errors` `supportContact` exposes a direct email address
- SEC-081: Info when `TCPListener` used without explicit address
- SEC-082: Warning when SSO protocols include SAML1
- SEC-083: Info when logout outgoing binding uses GET/Redirect (tokens in URL)
- SEC-084: Warning when `relayState` uses plain HTTP
- SEC-085: Warning when attribute policy uses wildcard scope matching
- SEC-086: Warning when metadata backing file is world-writable
- SEC-087: Warning when certificate file is world-writable
- SEC-088: Warning when `signing` explicitly set to `false` on ApplicationDefaults
- SEC-089: Warning when `encryption` explicitly set to `false` on ApplicationDefaults
- SEC-090: Info when ECP (Enhanced Client/Proxy) is enabled
- SEC-091: Warning when CredentialResolver has key but no certificate
- SEC-092: Info when deprecated `redirectWhitelist` attribute is used
- SEC-093: Warning when content setting has `authType="shibboleth"` but `requireSession="false"`
- SEC-094: Warning when Handler Location is at root path `/`
- SEC-095: Info when no signing CredentialResolver configured
- SEC-096: Info when asynchronous LogoutInitiator has signing disabled
- SEC-097: Warning when `cipherSuites` contains weak algorithms (RC4, DES, 3DES, MD5, NULL, EXPORT, ANON)
- SEC-098: Info when SignatureMetadataFilter has `verifyBackup="false"`
- SEC-099: Info when PostData cache is enabled (sensitive form data on disk)
- SEC-100: Info when `forceAuthn` explicitly set to `false` on content settings
- SEC-101: Info when `isPassive="true"` combined with `requireSession="true"` (silent auth failure)
- SEC-102: Info when RequestMapper type is `Native` (access control via web server config)
- SEC-103: Info when LogoutInitiator has `notifyWithout` set (skips some notifications)
- SEC-104: Info when Errors `helpLocation` uses plain HTTP
- SEC-105: Info when more than 5 Notify endpoints configured (broad notification surface)
- SEC-106: Info when no `attributePrefix` set (header name collision risk)
- SEC-107: Warning when XML comments contain sensitive keywords (password, secret, token)
- SEC-108: Warning when attribute map maps to security-sensitive header names (REMOTE_USER, HTTP_AUTHORIZATION)
- SEC-109: Info when `clockSkew` is set to 0 (may reject valid assertions)
- SEC-110: Warning when `security-policy.xml` references weak algorithms outside blacklists
- SEC-111: Info when error template paths are absolute URLs (external redirect on error)
- SEC-112: Warning when scoped attributes have `PermitValueRule type="ANY"` without scope validation
- SEC-113: Warning when `DiagnosticService` handler has no ACL
- SEC-114: Warning when `DataSealer` configured without explicit `keyStorePath`
- SEC-115: Info when informational handlers at default `Shibboleth.sso` paths lack ACL
- SEC-116: Warning when `ApplicationOverride` `entityID` uses HTTP instead of HTTPS
- SEC-117: Info when SSO `discoveryProtocol` is WAYF (outdated)
- SEC-118: Warning when multiple `SessionInitiator` elements marked as default
- SEC-119: Warning when duplicate handler `Location` paths detected
- SEC-120: Warning when `SessionInitiator` uses `Shib1` type (legacy SAML1)
- SEC-121: Info when `OutOfProcess` has `catchAll="true"` (masks errors)
- SEC-122: Warning when remote `MetadataProvider` has no `MetadataFilter` elements at all
- SEC-123: Warning when `SignatureMetadataFilter` certificate fetched over plain HTTP
- SEC-124: Warning when `Notify` endpoint loops back to SP handler
- SEC-125: Info when `ApplicationOverride` `entityID` is same as parent (redundant)
- OPS-036: Info when `homeURL` not set on `ApplicationDefaults` (no fallback landing page)
- OPS-037: Warning when `homeURL` appears to be a placeholder (example.org, localhost)
- OPS-038: Info when no custom error pages configured in `<Errors>`
- OPS-039: Info when `helpLocation` not set on `<Errors>`
- OPS-040: Info when session `lifetime` not explicitly set
- OPS-041: Info when session `timeout` not explicitly set
- OPS-042: Warning when remote `MetadataProvider` has no `MetadataFilter` children (metadata not validated)
- OPS-043: Info when `Errors` `styleSheet` not set (unstyled error pages)
- OPS-044: Info when no `Host` or `Path` has `requireSession="true"` (SP not enforcing sessions)
- OPS-045: Info when `redirectToSSL` not set on any content settings (no HTTP→HTTPS redirect)
- OPS-046: Info when `discoveryURL` is set without explicit `discoveryProtocol`
- OPS-047: Info when `MetadataProvider` does not set `validate="true"` (schema validation disabled)
- OPS-048: Info when `signingAlg` or `digestAlg` not explicitly set on `ApplicationDefaults`
- OPS-049: Info when `RequireValidUntil` MetadataFilter lacks `maxValidityInterval`
- OPS-050: Info when no `AttributeExtractor` path configured
- OPS-051: Warning when multiple `CredentialResolver` elements lack `use` attribute
- OPS-052: Info when more than 3 `ApplicationOverride` elements defined (complexity warning)
- OPS-053: Info when local `MetadataProvider` has no `reloadInterval`
- OPS-054: Info when no `StorageService` configured (sessions lost on restart)
- OPS-055: Info when no `OutOfProcess` or `InProcess` extensions configured
- OPS-056: Info when no `ReplayCache` configured (assertion replay protection)
- OPS-057: Info when SSO protocols not explicitly specified in `<SSO>` element
- OPS-058: Info when Logout protocols not explicitly specified in `<Logout>` element
- OPS-059: Info when no logging configuration detected
- OPS-060: Info when `consistentAddress` not explicitly set on `Sessions`
- OPS-061: Info when `handlerURL` uses non-standard path (requires matching web server config)
- OPS-062: Info when no `ArtifactMap` configured (artifact resolution state in-memory only)
- OPS-063: Info when `attribute-map.xml` has fewer than 3 attributes (may be incomplete)
- OPS-064: Info when attribute policy uses `PermitValueRule type="ANY"` without additional filtering
- OPS-065: Info when multiple `Host` elements in `RequestMap` (multi-vhost awareness)
- OPS-066: Info when `SessionInitiator` elements lack `id` attribute (cannot be deep-linked)
- OPS-067: Info when no `AccessControl` elements configured
- OPS-068: Info when logout is enabled but no localLogout/globalLogout error pages configured
- OPS-069: Info when `authnContextClassRef` not set on `SSO` (no authentication strength requirement)
- OPS-070: Info when `ApplicationOverride` has no explicit `entityID` (inherits parent)
- OPS-071: Info when `cipherSuites` not set on `ApplicationDefaults` (TLS uses system defaults)
- OPS-072: Warning when `homeURL` does not start with `/` or `https://`
- OPS-073: Info when multiple `AttributeExtractor` or `AttributeFilter` paths configured (complexity)
- OPS-074: Info when no `AttributeChecker` handler configured (no pre-access attribute validation)
- OPS-075: Warning when configuration contains `TODO`/`FIXME`/`XXX` comments (incomplete setup)
- OPS-076: Info when `DiscoveryFeed` handler is enabled (exposes trusted IdP list)
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
