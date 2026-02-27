# shibcheck

Shibboleth SP configuration checker. Validates `shibboleth2.xml` and related files in a directory, checking XML validity, cross-file references, and security best practices. Reports findings with severity levels, actionable suggestions, and links to the [Shibboleth SP3 wiki](https://shibboleth.atlassian.net/wiki/spaces/SP3/).

## Installation

```bash
cargo install --path .
```

Or build and run directly:

```bash
cargo build --release
./target/release/shibcheck /etc/shibboleth
```

## Usage

```bash
# Check current directory
shibcheck

# Check a specific directory
shibcheck /etc/shibboleth

# Show all checks (including passed)
shibcheck -v /etc/shibboleth

# JSON output
shibcheck --json /etc/shibboleth

# Disable colors (for piping)
shibcheck --no-color /etc/shibboleth

# Fetch and validate remote metadata URLs
shibcheck --check-remote /etc/shibboleth
```

### Test IdP Setup

Use `init-test-idp` to set up [mocksaml.com](https://mocksaml.com) as a test Identity Provider:

```bash
# Fetch mocksaml.com metadata and get the config snippet
shibcheck init-test-idp /etc/shibboleth

# Overwrite an existing metadata file
shibcheck init-test-idp --force /etc/shibboleth
```

This downloads the mocksaml.com metadata to `mocksaml-metadata.xml` in the target directory and prints the `<MetadataProvider>` and `<SSO>` elements to add to your `shibboleth2.xml`.

## Exit Codes

| Code | Meaning |
|------|---------|
| `0`  | All checks passed (no errors) |
| `1`  | One or more errors found |
| `2`  | Tool failure (e.g., directory not found) |

## Checks Reference

200+ checks across five categories.

### XML Validity (XML-001 to XML-047)

| Code | Description | Severity |
|------|-------------|----------|
| XML-001 | `shibboleth2.xml` exists | Error |
| XML-002 | `shibboleth2.xml` is well-formed XML | Error |
| XML-003 | `attribute-map.xml` exists | Warning |
| XML-004 | `attribute-map.xml` is well-formed XML | Error |
| XML-005 | `attribute-policy.xml` exists | Info |
| XML-006 | `attribute-policy.xml` is well-formed XML | Error |
| XML-007 | `SPConfig` root element present | Error |
| XML-008 | `ApplicationDefaults` element present | Error |
| XML-009 | `entityID` attribute set | Error |
| XML-010 | `Sessions` element present | Error |
| XML-011 | At least one `SSO` or `SessionInitiator` | Error |
| XML-012 | `handlerURL` set on `Sessions` | Info |
| XML-013 | At least one `MetadataProvider` | Error |
| XML-014 | At least one `CredentialResolver` | Warning |
| XML-015 | Other XML files well-formed | Warning |
| XML-016 | `entityID` is a valid absolute URI | Warning |
| XML-017 | `attribute-map.xml` has at least one attribute mapping | Warning |
| XML-018 | `handlerURL` starts with `/` | Warning |
| XML-019 | `Logout` or `LogoutInitiator` element present | Info |
| XML-020 | SP version detected from `SPConfig` `xmlns` | Info |
| XML-021 | `REMOTE_USER` attribute set on `ApplicationDefaults` | Warning |
| XML-022 | `Errors` element has `supportContact` attribute | Warning |
| XML-023 | `SSO` has `entityID` or `discoveryURL` | Warning |
| XML-024 | `SSO` has both `entityID` and `discoveryURL` (entityID wins) | Info |
| XML-025 | `SecurityPolicyProvider` file exists | Error |
| XML-026 | No duplicate `ApplicationOverride` id | Error |
| XML-027 | `SSO` protocol text contains valid values | Warning |
| XML-028 | `Logout` protocol text contains valid values | Warning |
| XML-029 | `MetadataProvider` has a data source (path/url/uri/sourceDirectory) | Error |
| XML-030 | File `CredentialResolver` has both certificate and key | Warning |
| XML-031 | `Errors` element configured | Info |
| XML-032 | `Errors` element has `helpLocation` attribute | Info |
| XML-033 | `MetadataProvider` type is recognized | Error |
| XML-034 | `CredentialResolver` type is recognized | Error |
| XML-035 | `MetadataFilter` type is recognized | Warning |
| XML-036 | `Logout` includes `Local` protocol for fallback | Info |
| XML-037 | ECP support status on `SSO` | Info |
| XML-038 | `SSO` `authnContextClassRef` is a valid URI | Warning |
| XML-039 | `SSO` `discoveryProtocol` is a recognized value | Warning |
| XML-040 | `RequestMap` `applicationId` references | Info |
| XML-041 | `ApplicationOverride` has `entityID` attribute | Warning |
| XML-042 | `Errors` template file exists on disk | Warning |
| XML-043 | `Logout` `outgoingBindings` attribute | Info |
| XML-044 | `MetadataProvider` has `validate` attribute (schema validation) | Info |
| XML-045 | `isPassive="true"` combined with `requireSession="true"` | Warning |
| XML-046 | `requireSession="true"` without `authType` | Warning |
| XML-047 | `RequestMapper` `type="XML"` (web server directives ignored) | Info |

### Cross-file References (REF-001 to REF-033)

| Code | Description | Severity |
|------|-------------|----------|
| REF-001 | `CredentialResolver` certificate file exists | Error |
| REF-002 | `CredentialResolver` key file exists | Error |
| REF-003 | `MetadataProvider` local file/directory/backingFile exists | Error |
| REF-004 | `MetadataFilter` certificate file exists | Warning |
| REF-005 | `AttributeExtractor` path exists | Warning |
| REF-006 | `AttributeFilter` path exists | Warning |
| REF-007 | Attribute policy IDs match attribute map IDs | Warning |
| REF-008 | `REMOTE_USER` attributes defined in attribute map | Warning |
| REF-009 | Remote metadata URL reachable and valid SAML (`--check-remote`) | Error |
| REF-010 | Local metadata file contains valid SAML root element | Warning |
| REF-011 | Key file is a valid PEM private key | Warning |
| REF-012 | No duplicate `MetadataProvider` sources | Warning |
| REF-013 | `Errors` template file paths exist | Info |
| REF-014 | No duplicate attribute IDs in `attribute-map.xml` | Warning |
| REF-015 | No duplicate attribute names in `attribute-map.xml` | Info |
| REF-016 | `SSO` `entityID` found in loaded metadata | Warning |
| REF-017 | Remote `MetadataProvider` has `backingFilePath` | Warning |
| REF-018 | `SecurityPolicyProvider` file exists | Error |
| REF-019 | Logging config files exist (`shibd.logger`, `native.logger`) | Info |
| REF-020 | `MetadataFilter` Signature certificate is valid PEM | Warning |
| REF-021 | `MetadataFilter` Signature certificate not expired | Warning |
| REF-022 | `postTemplate` file exists | Info |
| REF-024 | `ApplicationOverride` `entityID` same as parent (redundant) | Info |
| REF-025 | `AttributeDecoder` type is recognized | Warning |
| REF-026 | Signature `MetadataFilter` has certificate or `TrustEngine` | Warning |
| REF-027 | Chaining `CredentialResolver` has >= 2 children | Info |
| REF-028 | No deprecated `eduPersonTargetedID` OID mapping | Info |
| REF-029 | Policy rule for scoped attribute uses scope validation | Warning |
| REF-030 | `RequestMap` `applicationId` references valid `ApplicationOverride` | Warning |
| REF-031 | Chaining `MetadataProvider` has >= 2 children | Info |
| REF-032 | `MetadataProvider` `ignoreTransport="true"` has compensating Signature filter | Warning |
| REF-033 | `RequestMap` root `applicationId` is `"default"` | Warning |

### Security (SEC-001 to SEC-065)

| Code | Description | Severity |
|------|-------------|----------|
| SEC-001 | `handlerSSL="true"` on `Sessions` | Warning |
| SEC-002 | `cookieProps` includes `secure` | Warning |
| SEC-003 | `cookieProps` includes `httpOnly` | Warning |
| SEC-004 | Signing credentials configured | Warning |
| SEC-005 | Encryption credentials configured | Warning |
| SEC-006 | `signing` attribute on `ApplicationDefaults` | Info |
| SEC-007 | `encryption` attribute on `ApplicationDefaults` | Info |
| SEC-008 | Certificate not expired | Error |
| SEC-009 | Certificate expiring within 30 days | Warning |
| SEC-010 | Certificate not yet valid | Error |
| SEC-011 | Metadata signature validation configured | Warning |
| SEC-012 | `RequireValidUntil` metadata filter configured | Info |
| SEC-013 | Certificate key size >= 2048 bits | Warning |
| SEC-014 | No plaintext HTTP metadata URLs | Warning |
| SEC-015 | Status handler ACL configured | Info |
| SEC-016 | Private key file not world-readable (Unix) | Warning |
| SEC-017 | `cookieProps` includes `SameSite` attribute | Info |
| SEC-018 | `entityID` uses HTTPS | Info |
| SEC-019 | `Sessions` `lifetime` is reasonable | Info |
| SEC-020 | `Sessions` `timeout` is reasonable | Info |
| SEC-021 | Certificate and private key match | Error |
| SEC-022 | `redirectLimit` not set to `"none"` (open redirect) | Warning |
| SEC-023 | `consistentAddress` not explicitly `"false"` | Info |
| SEC-024 | `clockSkew` does not exceed 600s | Warning |
| SEC-025 | `SSO` protocols do not include SAML1 | Info |
| SEC-026 | `maxValidityInterval` present and <= 30 days | Info |
| SEC-027 | `security-policy.xml` has algorithm blacklist/filter | Warning |
| SEC-028 | `entityID` is not a placeholder | Warning |
| SEC-029 | `SSO` `discoveryURL` uses HTTPS | Warning |
| SEC-030 | Config files not world-writable (Unix) | Warning |
| SEC-031 | `relayState` storage is server-side | Info |
| SEC-032 | No handler has `showAttributeValues="true"` | Warning |
| SEC-033 | Sensitive handlers have ACL restrictions | Info |
| SEC-034 | `exportAssertion` not enabled | Warning |
| SEC-035 | `cipherSuites` contains no weak ciphers (RC4/DES/NULL/EXPORT) | Warning |
| SEC-036 | `spoofKey` configured | Warning |
| SEC-038 | `postLimit` is non-zero and <= 10 MB | Info |
| SEC-039 | `SecurityPolicyProvider` has `validate="true"` | Info |
| SEC-040 | `security-policy.xml` does not disable default algorithm blacklist | Warning |
| SEC-041 | `Notify` endpoints use HTTPS | Warning |
| SEC-042 | `handlerURL` does not use plaintext HTTP | Warning |
| SEC-043 | Signing and encryption `CredentialResolver` use separate keys | Warning |
| SEC-044 | `TCPListener` binds to localhost | Warning |
| SEC-045 | `redirectLimit` explicitly set on `Sessions` | Info |
| SEC-046 | `MetadataGenerator` handler has ACL restriction | Warning |
| SEC-047 | `DiscoveryFeed` handler has ACL restriction | Warning |
| SEC-048 | `SecurityPolicyProvider` configured | Warning |
| SEC-049 | `homeURL` uses HTTPS and is not a placeholder | Info |
| SEC-050 | `exportAssertion="true"` has `requireSession="true"` | Warning |
| SEC-051 | Chaining `CredentialResolver` has children | Error |
| SEC-052 | `signingAlg` does not use SHA-1 | Warning |
| SEC-053 | `digestAlg` does not use SHA-1 | Warning |
| SEC-054 | `SignatureMetadataFilter` `verifyName` not disabled | Warning |
| SEC-055 | `MetadataProvider` `ignoreTransport="true"` has Signature filter | Warning |
| SEC-056 | `requireTransportAuth` not set to `"false"` | Warning |
| SEC-057 | `requireConfidentiality` not set to `"false"` | Warning |
| SEC-058 | `exportACL` restricted to localhost | Warning |
| SEC-059 | `exportLocation` has restrictive `exportACL` | Warning |
| SEC-060 | `LogoutInitiator` has `signing` attribute | Warning |
| SEC-061 | `redirectLimit` allow-list has `redirectAllow` set | Warning |
| SEC-062 | `ExternalAuth` handler has ACL | Warning |
| SEC-063 | `AttributeResolver` handler has ACL | Warning |
| SEC-064 | Handler ACL does not contain broad CIDR (`0.0.0.0/0`, `::/0`) | Info |
| SEC-065 | `ApplicationOverride` `<Sessions>` has `redirectLimit` set | Warning |

### Operational (OPS-001 to OPS-035)

| Code | Description | Severity |
|------|-------------|----------|
| OPS-001 | `supportContact` is not a placeholder | Warning |
| OPS-002 | `MetadataProvider` `reloadInterval` within 5 min – 24 hr | Info |
| OPS-003 | Session `lifetime` >= `timeout` | Info |
| OPS-004 | `REMOTE_USER` does not use mutable attributes | Info |
| OPS-005 | Scoped attributes have scope validation in `attribute-policy.xml` | Warning |
| OPS-006 | Remote `MetadataProvider` has `maxRefreshDelay` | Info |
| OPS-007 | `idpHistory` enabled with `idpHistoryDays` set | Info |
| OPS-008 | `attribute-map.xml` contains scoped attributes | Info |
| OPS-009 | `MetadataGenerator` handler not enabled | Info |
| OPS-010 | `Notify` endpoints configured for logout notification | Info |
| OPS-011 | `supportContact` looks like a valid email | Info |
| OPS-012 | `REMOTE_USER` has single attribute (no fallback chain) | Info |
| OPS-013 | `clockSkew` explicitly set | Info |
| OPS-014 | `TransportOption` TLS constraints configured | Info |
| OPS-015 | `reloadChanges` set on external XML resources | Info |
| OPS-016 | `sameSiteFallback` set on `Sessions` | Info |
| OPS-017 | `relayState` configured on `Sessions` | Info |
| OPS-018 | `postData` configured on `Sessions` | Info |
| OPS-019 | Remote `MetadataProvider` has `reloadInterval` | Info |
| OPS-020 | `supportContact` has no redundant `mailto:` prefix | Info |
| OPS-021 | `AttributeFilter` element configured | Info |
| OPS-022 | `maxTimeSinceAuthn` set on `Sessions` | Info |
| OPS-023 | `cookieLifetime` not set (session-scoped cookies) | Info |
| OPS-024 | `MetadataProvider` has `id` in multi-provider setup | Info |
| OPS-025 | `LogoutInitiator` `notifyWithout` set | Info |
| OPS-026 | `LogoutInitiator` `asynchronous` set to `"false"` | Info |
| OPS-027 | Multiple `SessionInitiator` elements have explicit `isDefault` | Info |
| OPS-028 | `forceAuthn="true"` not at `Host` scope | Info |
| OPS-029 | `SignatureMetadataFilter` `verifyBackup` not disabled | Info |
| OPS-030 | `cipherSuites` disables TLSv1 and TLSv1.1 | Info |
| OPS-031 | `DataSealer` does not use `type="Static"` | Info |
| OPS-032 | `ApplicationOverride` own `<Sessions>` replaces parent | Info |
| OPS-033 | `ApplicationOverride` own `<Errors>` replaces parent | Info |
| OPS-034 | `ApplicationOverride` own `<CredentialResolver>` replaces parent | Info |
| OPS-035 | `ApplicationOverride` own `<MetadataProvider>` replaces parent | Info |

### Migration (MIG-001 to MIG-024)

MIG-001 through MIG-010 only fire for SP2 configs. MIG-011+ fire on both V2 and V3.

| Code | Description | Severity |
|------|-------------|----------|
| MIG-001 | SP2 configuration detected — upgrade recommended | Warning |
| MIG-002 | SP2-style `SessionInitiator` found; SP3 uses `SSO` | Info |
| MIG-003 | SP2-style logout config found; SP3 uses `Logout` | Info |
| MIG-004 | `SPConfig` uses SP2 namespace URI | Warning |
| MIG-005 | No `signing`/`encryption` attributes — SP3 defaults differ | Info |
| MIG-006 | `MetadataProvider` uses deprecated `file` attribute | Warning |
| MIG-007 | `attribute-policy.xml` uses deprecated SP2 namespace | Info |
| MIG-008 | `Sessions` uses deprecated `redirectWhitelist` | Info |
| MIG-009 | `AttributeResolver` with `subjectMatch` (SP2 pattern) | Info |
| MIG-010 | `MetadataProvider` uses deprecated `Provider` attribute | Warning |
| MIG-011 | `MetadataFilter` type `EntityRoleWhiteList` deprecated | Warning |
| MIG-012 | `MetadataFilter` type `Whitelist`/`Blacklist` deprecated | Warning |
| MIG-013 | `MetadataProvider` uses deprecated `uri` attribute | Info |
| MIG-014 | Configuration contains deprecated constructs | Info |
| MIG-015 | `Sessions` uses deprecated `checkAddress` attribute | Info |
| MIG-016 | SP3 config has leftover SP2 handler declarations | Info |
| MIG-017 | `MetadataGenerator` present (disabled by default in SP 3.4+) | Info |
| MIG-018 | `redirectLimit="whitelist"` is a deprecated value | Warning |
| MIG-019 | `SSO` `discoveryProtocol="WAYF"` deprecated | Warning |
| MIG-020 | `MetadataProvider` `legacyOrgNames="true"` deprecated | Warning |
| MIG-021 | `attribute-map.xml` `aliases` attribute deprecated | Info |
| MIG-022 | `SessionInitiator` `type="Shib1"` or `"WAYF"` (legacy) | Warning |
| MIG-023 | `SSO` `defaultACSIndex`/`acsIndex` deprecated in SP3 | Info |
| MIG-024 | `ApplicationOverride` `Sessions` missing `handlerSSL`/`cookieProps` (not inherited) | Warning |

## Output

By default, only failed checks are shown. Use `-v` to see all checks including passed ones.

Terminal output is color-coded:
- **Red** — Error (FAIL)
- **Yellow** — Warning (WARN)
- **Blue** — Info (INFO)
- **Green** — Passed (PASS, verbose only)

Failed checks include a suggestion line and a link to the relevant Shibboleth SP3 documentation.

### File Summary

A file summary is displayed after the check results, showing which files were read and which were not found:

```
── Files ──
  ✓ shibboleth2.xml         (config)
  ✓ attribute-map.xml       (attribute map)
  ✗ attribute-policy.xml    (attribute policy)
  ✓ sp-cert.pem             (certificate)
  ✓ sp-key.pem              (key)
  ✓ idp-metadata.xml        (metadata)
  ✗ idp-metadata-cache.xml  (backing file)
  ✓ idp-signing.pem         (metadata certificate)
```

The summary covers primary config files, certificates, keys, metadata files, backing files, attribute extractors/filters, security policy, and error templates. Files are resolved relative to the checked directory.

### JSON Output

With `--json`, output is a JSON object:

```json
{
  "results": [
    {
      "code": "XML-001",
      "category": "xml_validity",
      "severity": "error",
      "passed": true,
      "message": "shibboleth2.xml exists"
    },
    {
      "code": "SEC-001",
      "category": "security",
      "severity": "warning",
      "passed": false,
      "message": "handlerSSL is not explicitly set",
      "suggestion": "Set handlerSSL=\"true\" on <Sessions> to require HTTPS",
      "doc_url": "https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334342/Sessions"
    }
  ],
  "summary": {
    "total": 38,
    "passed": 35,
    "errors": 1,
    "warnings": 2,
    "info": 0
  },
  "files": [
    { "path": "shibboleth2.xml", "found": true, "kind": "config" },
    { "path": "attribute-policy.xml", "found": false, "kind": "attribute policy" }
  ]
}
```

## Building from Source

Requires Rust 1.70+.

```bash
git clone <repo-url>
cd shibcheck
cargo build --release
```

Run tests:

```bash
cargo test
```
