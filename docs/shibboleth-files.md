# Shibboleth SP File Reference

A reference for all standard files found in a Shibboleth SP configuration directory (typically `/etc/shibboleth/`). shibcheck uses this knowledge to classify files in its [file summary](#file-summary-in-shibcheck) output.

## Configuration Files

### `shibboleth2.xml` (required)

The primary configuration file. Its `<SPConfig>` root element controls all aspects of the SP: daemon and web server module settings, request mapping, session handling, metadata providers, credential resolvers, error pages, and security policy. The filename remains `shibboleth2.xml` even in SP3 to ease upgrades.

- **Namespace:** `urn:mace:shibboleth:3.0:native:sp:config` (SP3) or `urn:mace:shibboleth:2.0:native:sp:config` (SP2)
- **Loaded by:** shibd daemon and web server module (mod_shib / ISAPI)
- **Docs:** [SPConfig](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2063695926/SPConfig)

### `attribute-map.xml` (required)

Maps SAML attributes from Identity Providers to local environment variables / headers accessible by web applications. Each `<Attribute>` element maps a SAML attribute name to a local `id` using an `AttributeDecoder` (e.g., `StringAttributeDecoder`, `ScopedAttributeDecoder`).

- **Root element:** `<Attributes xmlns="urn:mace:shibboleth:2.0:attribute-map">`
- **Referenced by:** `<AttributeExtractor type="XML" path="attribute-map.xml"/>` in `shibboleth2.xml`
- **Docs:** [XMLAttributeExtractor](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334421/XMLAttributeExtractor)

### `attribute-policy.xml` (recommended)

Defines attribute filtering rules that control which incoming attribute values are accepted. Used for scope validation on scoped attributes, blocking self-asserted values from open IdPs, and enforcing enumerated value sets.

- **Root element:** `<afp:AttributeFilterPolicyGroup>`
- **Referenced by:** `<AttributeFilter type="XML" path="attribute-policy.xml"/>` in `shibboleth2.xml`
- **Docs:** [XMLAttributeFilter](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2072543324/XMLAttributeFilter)

### `security-policy.xml` (recommended)

Externalizes security processing rules for SAML protocols. Controls which security checks are performed (message signing, TLS requirements) and allows algorithm blacklisting in response to vulnerabilities. Reloadable at runtime.

- **Root element:** `<SecurityPolicies>`
- **Referenced by:** `<SecurityPolicyProvider type="XML" validate="true" path="security-policy.xml"/>` in `shibboleth2.xml`
- **Docs:** [SecurityPolicyProvider](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334523/SecurityPolicyProvider)

## Error Templates

HTML templates displayed to users when the SP encounters errors or completes logout flows. Configured via the `<Errors>` element inside `<ApplicationDefaults>` in `shibboleth2.xml`. All are optional -- the SP ships working defaults.

**Docs:** [Errors](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334361/Errors)

| File | `<Errors>` attribute | When displayed |
|------|---------------------|----------------|
| `sessionError.html` | `session` | General SSO/session errors (assertion failures, decryption errors, session creation issues) |
| `accessError.html` | `access` | Authorization failures -- user authenticated but does not meet access control rules |
| `sslError.html` | `ssl` | Non-SSL requests that cannot be safely redirected to HTTPS (e.g., POST with `redirectToSSL`) |
| `metadataError.html` | `metadata` | Metadata-related errors (IdP metadata not found or invalid) |
| `localLogout.html` | `localLogout` | Displayed after local-only logout when no return URL is known |
| `globalLogout.html` | `globalLogout` | Displayed after global (single) logout when no return URL is known |
| `partialLogout.html` | `partialLogout` | Displayed when a non-local logout finishes with incomplete or erroneous status |

The `<Errors>` element also supports `supportContact` (email shown on error pages), `logoLocation`, and `styleSheet` (CSS URL) attributes.

## Handler Templates

HTML templates used by specific SP handlers for SAML protocol interactions and user-facing pages.

### `postTemplate.html`

Auto-submitting HTML form that replays POST data preserved across the SSO redirect. After authentication completes, this template re-submits the original form data to the target URL.

- **Referenced by:** `<Sessions postTemplate="postTemplate.html">` in `shibboleth2.xml`
- **Requires:** `postData="ss:mem"` or similar on `<Sessions>` to activate POST data preservation
- **Docs:** [Sessions](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334337/Sessions)

### `bindingTemplate.html`

HTML form used for SAML HTTP-POST binding. When the SP sends an AuthnRequest via POST (rather than redirect), this template generates an auto-submitting form carrying the SAML message to the IdP.

- **Referenced by:** `template` attribute on `<SessionInitiator type="SAML2">`
- **Docs:** [SAML2 SessionInitiator](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334736/SAML2+SessionInitiator)

### `discoveryTemplate.html`

A local HTML form prompting the user to enter or select their Identity Provider's entityID. Used as a simple built-in discovery page when no external Discovery Service is configured.

- **Referenced by:** `template` attribute on `<SessionInitiator type="Form">`
- **Docs:** [Form SessionInitiator](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334762/Form+SessionInitiator)

### `attrChecker.html`

Notification page displayed by the AttributeChecker handler when required attributes are missing from a user's session. Tells users their IdP did not release necessary attributes.

- **Referenced by:** `template` attribute on `<Handler type="AttributeChecker">`
- **Triggered via:** `sessionHook="/Shibboleth.sso/AttrChecker"` on `<ApplicationDefaults>`
- **Docs:** [Attribute Checker Handler](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334881/Attribute+Checker+Handler)

## Logger Configuration Files

The SP uses log4shib (a log4cpp fork) with log4j-style property syntax. The daemon and web server module use separate logger configs.

**Docs:** [Logging](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334602/Logging)

### `shibd.logger`

Logging for the **out-of-process** shibd daemon -- the component handling SAML processing, assertion decryption, metadata management, and attribute resolution. Output goes to `shibd.log` by default.

- **Referenced by:** `<OutOfProcess logger="shibd.logger">` in `shibboleth2.xml` (default since SP 2.4)
- **Log location:** `/var/log/shibboleth/shibd.log` (Linux), `C:\opt\shibboleth-sp\var\log\shibboleth\shibd.log` (Windows)
- **Key log categories:** `OpenSAML.MessageDecoder`, `Shibboleth.AttributeResolver`, `XMLTooling.SecurityHelper`

### `native.logger`

Logging for the **in-process** web server module (Apache mod_shib or IIS ISAPI). Covers request mapping, content settings, and module-level operations.

- **Referenced by:** `<InProcess logger="native.logger">` in `shibboleth2.xml` (default since SP 2.4)
- **Log location:** `/var/log/shibboleth/native.log` (Linux)

### `console.logger`

Alternative logger that directs output to **stdout/stderr** instead of files. Useful for running shibd in the foreground for debugging or in containerized environments (Docker, Kubernetes).

- **Referenced by:** `<OutOfProcess logger="console.logger">` or `<InProcess logger="console.logger">`

### `syslog.logger`

Alternative logger that directs output to **syslog** (Unix). Uses `LocalSyslogAppender` from log4shib with configurable facility, syslog name, and optional remote syslog host.

- **Referenced by:** `<OutOfProcess logger="syslog.logger">` or `<InProcess logger="syslog.logger">`

## Utility Files

### `upgrade.xsl`

XSLT stylesheet for converting SP 1.x configuration (`shibboleth.xml`) to SP 2.x format (`shibboleth2.xml`). A migration convenience tool, not required for SP operation.

```bash
xsltproc upgrade.xsl shibboleth.xml > shibboleth2.xml
```

> **Note:** This stylesheet is limited and cannot handle complex configurations. It is intended as a starting point, not a reliable automated upgrade. It does **not** handle SP2-to-SP3 migration, which requires manual namespace and attribute changes.

- **Docs:** [UpgradingFromV2](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2067400004/UpgradingFromV2)

## File Summary in shibcheck

shibcheck classifies every file in the checked directory in its output:

| Icon | Meaning |
|------|---------|
| `✓` (green) | Found -- referenced by configuration or recognized as a standard SP file |
| `✗` (red) | Not found -- referenced by configuration but missing from disk |
| `?` (yellow) | Unused -- present on disk but not referenced and not a recognized SP file |

Files are labeled with a **kind** describing their role:

| Kind | Examples |
|------|----------|
| `config` | `shibboleth2.xml` |
| `attribute map` | `attribute-map.xml` |
| `attribute policy` | `attribute-policy.xml` |
| `security policy` | `security-policy.xml` |
| `certificate` | `sp-cert.pem` |
| `key` | `sp-key.pem` |
| `metadata` | `idp-metadata.xml` |
| `backing file` | `idp-metadata-cache.xml` |
| `metadata certificate` | `idp-signing.pem` |
| `error template` | `accessError.html`, `sessionError.html`, `sslError.html`, `metadataError.html` |
| `logout template` | `localLogout.html`, `globalLogout.html`, `partialLogout.html` |
| `post template` | `postTemplate.html` |
| `binding template` | `bindingTemplate.html` |
| `discovery template` | `discoveryTemplate.html` |
| `attribute checker` | `attrChecker.html` |
| `logger config` | `shibd.logger`, `native.logger`, `console.logger`, `syslog.logger` |
| `upgrade stylesheet` | `upgrade.xsl` |
| `unused` | Any file not matching the above |
