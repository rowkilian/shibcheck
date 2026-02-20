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

## Exit Codes

| Code | Meaning |
|------|---------|
| `0`  | All checks passed (no errors) |
| `1`  | One or more errors found |
| `2`  | Tool failure (e.g., directory not found) |

## Checks Reference

### XML Validity (XML-001 to XML-019)

| Code | Description | Severity | Documentation |
|------|-------------|----------|---------------|
| XML-001 | `shibboleth2.xml` exists | Error | [SPConfig](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2063695926/SPConfig) |
| XML-002 | `shibboleth2.xml` is well-formed XML | Error | [SPConfig](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2063695926/SPConfig) |
| XML-003 | `attribute-map.xml` exists | Warning | [XMLAttributeExtractor](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334421/XMLAttributeExtractor) |
| XML-004 | `attribute-map.xml` is well-formed XML | Error | [XMLAttributeExtractor](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334421/XMLAttributeExtractor) |
| XML-005 | `attribute-policy.xml` exists | Info | [AttributeFilter](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334516/AttributeFilter) |
| XML-006 | `attribute-policy.xml` is well-formed XML | Error | [AttributeFilter](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334516/AttributeFilter) |
| XML-007 | `SPConfig` root element present | Error | [SPConfig](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2063695926/SPConfig) |
| XML-008 | `ApplicationDefaults` element present | Error | [ApplicationDefaults](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2063695997/ApplicationDefaults) |
| XML-009 | `entityID` attribute set | Error | [ApplicationDefaults](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2063695997/ApplicationDefaults) |
| XML-010 | `Sessions` element present | Error | [Sessions](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334342/Sessions) |
| XML-011 | At least one `SSO` or `SessionInitiator` | Error | [SSO](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334348/SSO) |
| XML-012 | `handlerURL` set on `Sessions` | Warning | [Sessions](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334342/Sessions) |
| XML-013 | At least one `MetadataProvider` | Error | [MetadataProvider](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2060616124/MetadataProvider) |
| XML-014 | At least one `CredentialResolver` | Warning | [CredentialResolver](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334414/CredentialResolver) |
| XML-015 | Other XML files well-formed | Warning | — |
| XML-016 | `entityID` is a valid absolute URI | Warning | [ApplicationDefaults](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2063695997/ApplicationDefaults) |
| XML-017 | `attribute-map.xml` has at least one attribute mapping | Warning | [XMLAttributeExtractor](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334421/XMLAttributeExtractor) |
| XML-018 | `handlerURL` starts with `/` | Warning | [Sessions](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334342/Sessions) |
| XML-019 | `Logout` or `LogoutInitiator` element present | Info | [Sessions](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334342/Sessions) |

### Cross-file References (REF-001 to REF-016)

| Code | Description | Severity | Documentation |
|------|-------------|----------|---------------|
| REF-001 | `CredentialResolver` certificate file exists | Error | [CredentialResolver](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334414/CredentialResolver) |
| REF-002 | `CredentialResolver` key file exists | Error | [CredentialResolver](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334414/CredentialResolver) |
| REF-003 | `MetadataProvider` local file exists | Error | [MetadataProvider](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2060616124/MetadataProvider) |
| REF-004 | `MetadataFilter` certificate file exists | Warning | [MetadataFilter](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2063696193/MetadataFilter) |
| REF-005 | `AttributeExtractor` path exists | Warning | [XMLAttributeExtractor](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334421/XMLAttributeExtractor) |
| REF-006 | `AttributeFilter` path exists | Warning | [AttributeFilter](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334516/AttributeFilter) |
| REF-007 | Attribute policy IDs match attribute map IDs | Warning | [XMLAttributeExtractor](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334421/XMLAttributeExtractor) |
| REF-008 | `REMOTE_USER` attributes defined in attribute map | Warning | [AttributeAccess](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065335257/AttributeAccess) |
| REF-009 | Remote metadata URL reachable and valid SAML metadata (`--check-remote`) | Error/Warning | [MetadataProvider](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2060616124/MetadataProvider) |
| REF-010 | Local metadata file contains valid SAML root element | Warning | [MetadataProvider](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2060616124/MetadataProvider) |
| REF-011 | Key file is a valid PEM private key | Warning | [CredentialResolver](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334414/CredentialResolver) |
| REF-012 | No duplicate `MetadataProvider` sources | Warning | [MetadataProvider](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2060616124/MetadataProvider) |
| REF-013 | `Errors` template file paths exist | Info | [Errors](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334308/Errors) |
| REF-014 | No duplicate attribute IDs in `attribute-map.xml` | Warning | [XMLAttributeExtractor](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334421/XMLAttributeExtractor) |
| REF-015 | No duplicate attribute names in `attribute-map.xml` | Info | [XMLAttributeExtractor](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334421/XMLAttributeExtractor) |
| REF-016 | `SSO` `entityID` found in loaded metadata | Warning | [MetadataProvider](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2060616124/MetadataProvider) |

### Security (SEC-001 to SEC-020)

| Code | Description | Severity | Documentation |
|------|-------------|----------|---------------|
| SEC-001 | `handlerSSL="true"` | Warning | [Sessions](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334342/Sessions) |
| SEC-002 | `cookieProps` includes `secure` | Warning | [Sessions](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334342/Sessions) |
| SEC-003 | `cookieProps` includes `httpOnly` | Warning | [Sessions](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334342/Sessions) |
| SEC-004 | Signing credentials configured | Warning | [CredentialResolver](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334414/CredentialResolver) |
| SEC-005 | Encryption credentials configured | Warning | [CredentialResolver](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334414/CredentialResolver) |
| SEC-006 | `signing` attribute on `ApplicationDefaults` | Info | [SigningEncryption](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334379/SigningEncryption) |
| SEC-007 | `encryption` attribute on `ApplicationDefaults` | Info | [SigningEncryption](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334379/SigningEncryption) |
| SEC-008 | Certificate not expired | Error | [CredentialResolver](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334414/CredentialResolver) |
| SEC-009 | Certificate expiring within 30 days | Warning | [CredentialResolver](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334414/CredentialResolver) |
| SEC-010 | Certificate not yet valid | Error | [CredentialResolver](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334414/CredentialResolver) |
| SEC-011 | Metadata signature validation configured | Warning | [SignatureMetadataFilter](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2063696211/SignatureMetadataFilter) |
| SEC-012 | `RequireValidUntil` metadata filter | Info | [RequireValidUntilMetadataFilter](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2063696214/RequireValidUntilMetadataFilter) |
| SEC-013 | Certificate key size >= 2048 bits | Warning | [CredentialResolver](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334414/CredentialResolver) |
| SEC-014 | No plaintext HTTP metadata URLs | Warning | [MetadataProvider](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2060616124/MetadataProvider) |
| SEC-015 | Status handler ACL configured | Info | [Status Handler](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334870/Status+Handler) |
| SEC-016 | Private key file not world-readable (Unix) | Warning | [CredentialResolver](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334414/CredentialResolver) |
| SEC-017 | `cookieProps` includes `SameSite` attribute | Info | [Sessions](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334342/Sessions) |
| SEC-018 | `entityID` uses HTTPS (prefer over HTTP) | Info | [ApplicationDefaults](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2063695997/ApplicationDefaults) |
| SEC-019 | `Sessions` `lifetime` is reasonable | Info | [Sessions](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334342/Sessions) |
| SEC-020 | `Sessions` `timeout` is reasonable | Info | [Sessions](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334342/Sessions) |

## Output

By default, only failed checks are shown. Use `-v` to see all checks including passed ones.

Terminal output is color-coded:
- **Red** — Error (FAIL)
- **Yellow** — Warning (WARN)
- **Blue** — Info (INFO)
- **Green** — Passed (PASS, verbose only)

Failed checks include a suggestion line and a link to the relevant Shibboleth SP3 documentation.

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
  }
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
