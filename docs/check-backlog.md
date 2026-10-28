# Check backlog

Check ideas found by reading the Shibboleth SP3 documentation (https://shibboleth.atlassian.net/wiki/spaces/SP3) that shibcheck does not implement yet. Page ids are in the URL after `/pages/`.

These came from a first pass over the docs. Each idea cites a page, but treat the condition as a lead: re-read the page before you build the check. Items marked **needs parsing** need a new field in `src/model/shibboleth_config.rs`.

## Security

| Idea | Page (id) | Notes |
|------|-----------|-------|
| `InProcess` `checkSpoofing="false"` | InProcess (2063696243), SpoofChecking (2065335299) | Doc: do not disable without a strong reason. Needs parsing. |
| ISAPI `useHeaders="true"` (also on `Site`), `normalizeRequest="false"` | ISAPI (2063696253), Site (2063696262) | Needs parsing. |
| `NullSecurity` policy rule in use | NullSecurity Rule (2065334892) | Doc: do not use in production. Needs a security-policy scan. |
| `MessageFlow` `checkReplay="false"`, `Bearer` `checkValidity="false"` / `checkRecipient="false"` | MessageFlow Rule (2065334545), Bearer Rule (2065334558) | Needs a security-policy scan. |
| Remote `url` on a reloadable non-metadata resource without `certificate`, `TrustEngine` or `CredentialResolver` | ReloadableConfiguration (2063695928), ReloadableConfigurationAttributes (2067399914) | Doc: the SP does not verify the transport, so sign the file. Needs parsing. |
| `REMOTE_ADDR` content setting overriding the client address | ContentSettings (2065334723) | Needs a header that clients cannot spoof. Needs parsing. |
| `MDQ` / `Dynamic` provider `verifyHost="false"` | MetadataProviderRemoteDynamicCommonAttributes (2067399842) | Needs parsing. |
| ODBC `ConnectionString` containing a password | ODBCStorageService (2065334638) | Needs parsing. |
| ODBC storage in use (SQL injection advisory for SP < 3.5.1) | SecurityAdvisories (2067399654) | The SP version is not visible in the config. |
| `RelyingParty` / `authType="basic"` over cleartext; SEC-056 and SEC-057 for `RelyingParty` | RelyingParty (2065334363) | Needs a `RelyingParty` model. |
| `SPConfig` `allowedSchemes` adding `javascript`, `data`, `file` | SPConfig (2063695926) | The page does not list risky schemes; keep severity low. |
| `TCPListener` `acl` beyond loopback | TCPListener (2065334618) | Needs parsing. |
| `PKIX` / `StaticPKIX` trust engine in use, or no explicit trust engine | ReleaseNotes (2065335693), TrustEngine (2063695951) | Needs application-level `TrustEngine` parsing. |
| `MetadataGenerator` handler signing with SHA-1 defaults | Metadata Generation Handler (2065334858) | Needs handler attributes. |
| `persistedAttributes` (session recovery) bypasses timeout and logout | SessionCache (2065334650) | Needs `SessionCache` parsing. |
| `authnContextClassRef` requested but not enforced by an access rule | Requiring Multi-Factor Authentication (2114781453) | The Apache or IIS config is outside the XML, so keep it Info. |

## XML validity

| Idea | Page (id) | Notes |
|------|-----------|-------|
| `Handler` without `type` or `Location`; unknown handler type | HandlerCommonAttributes (2067399676) | Parsed already. |
| `AttributeChecker` handler without `template` | Attribute Checker Handler (2065334881) | Needs handler attributes. |
| `SAMLDS` / `WAYF` initiator without `URL`; `Form` initiator without `template` | SAMLDS (2065334744), WAYF (2065334755), Form (2065334762) | Needs initiator attributes. |
| Discovery-type initiator with a fixed `entityID` | Same pages | Doc: the handler silently ignores the request. |
| Explicit `AssertionConsumerService`, `SingleLogoutService`, `ArtifactResolutionService`: missing `Location` / `Binding`, unknown binding, duplicate `index` | ACSCommonAttributes (2067399700), SingleLogoutCommonAttributes (2067399796) | These elements are not parsed. |
| Duplicate singleton elements (`Extensions`, `OutOfProcess`, `InProcess`, `DataSealer`, `SessionCache`, `RequestMapper`, a second `Sessions` or `Errors`) | SPConfig (2063695926), ApplicationDefaults (2063695997) | Needs element counts. |
| `ApplicationDefaults` `id` must be `default`; `Sessions` then `Errors` must come first | ApplicationDefaults (2063695997) | Needs element order. |
| `ApplicationOverride` nested in another override | ApplicationDefaults (2063695997) | Cardinality table. |
| Access control structure: `AND` / `OR` with fewer than 2 children, `NOT` with other than 1, bad `Time` operators | AND Rule (2065335131), NOT Rule (2065335135), Time AccessControl (2065335084) | Doc: a malformed rule installs a deny-all policy. |
| `Path` names with uppercase, `Host` without `name`, overlapping sibling `Path` elements | Path (2065335408), HowToRequestMap (2065335006) | Needs a request-map tree. |
| `Chaining` initiator with no children | Chaining SessionInitiator (2065334780) | Needs child counts. |
| `TrustEngine` `type` and `checkRevocation` values | TrustEngine (2063695951), PKIX pages (2065335188) | Needs parsing. |
| `DataSealer` `Static` key length (16, 24 or 32 bytes after base64 decoding) | StaticDataSealer (2070413452) | `has_key` is parsed; the key text is not. |
| `Dynamic` provider needs exactly one `Subst` or `Regex` child; `MDQ` / `Dynamic` without `TrustEngine` and without `ignoreTransport` | DynamicMetadataProvider (2060616138), MetadataProviderNetworkChildElements (2067399851) | Needs child names. |
| `refreshDelayFactor` outside 0 to 1, `minCacheDuration` above `maxCacheDuration` | XMLMetadataProvider (2063696005), MetadataProviderDynamicCommonAttributes (2067399841) | Needs parsing. |
| Metadata filters missing required children (`EntityRole` without `RetainedRole`, `UIInfo` without `Entity`) | EntityRoleMetadataFilter (2063696218), UIInfoMetadataFilter (2107539866) | Needs filter children. |
| `signing` / `encryption` values outside `conditional`, `true`, `false`, `front`, `back` | SigningEncryption (2065334379) | Only some elements are parsed. |
| File `CredentialResolver` `use` outside `signing`, `TLS`, `encryption` | FileCredentialResolver (2065335213) | `use_attr` is parsed. |
| `KeyDescriptor` extractor with none of `signingId`, `encryptionId`, `hashId` | KeyDescriptorAttributeExtractor (2065334438) | Needs extractor attributes. |
| Content setting values: `redirectToSSL` range, `encoding`, boolean values | ContentSettings (2065334723) | Needs parsing. |

## Cross-file references

| Idea | Page (id) | Notes |
|------|-----------|-------|
| `SessionCache` / `ReplayCache` / `ArtifactMap` `StorageService` names an undefined id; duplicate `StorageService` ids | StorageService (2065334626), ReplayCache (2065334677) | `storage_service_ids` is parsed; add the references. |
| `persistedAttributes` without a `DataSealer` | SessionCache (2065334650) | Needs `SessionCache` parsing. |
| `Rule` `require` names an attribute that is not in `attribute-map.xml` | Rule (2065335141), RuleRegex (2065335144) | Needs access-rule parsing. |
| `requireSessionWith` names a `SessionInitiator` id that does not exist | ContentSettings (2065334723) | Needs a content-setting field. |
| Plugin used without its extension library (`ODBC`, `memcache`, `GSSAPI`, `ADFS`) | ODBCStorageService (2065334638), ADFS (2065335656) | Needs `Extensions` / `Library` parsing. |
| `ExternalApplicationOverrides` path and `<applicationId>-override.xml` files | ExternalApplicationOverrides (2070413604) | Also lets REF-030 stop reporting those ids as missing. |
| `policyId` names a policy missing from `security-policy.xml` | CSRF (2096693787) | Needs the security-policy parse. |
| Remote `Key` / `Certificate` / `DataSealer` url without `backingFilePath` | CredentialCommonAttributes (2067399713) | Needs parsing. |
| Shared `cacheDirectory` between dynamic providers | MetadataProviderRemoteDynamicCommonAttributes (2067399842) | Needs parsing. |

## Operational

| Idea | Page (id) | Notes |
|------|-----------|-------|
| `exportAssertion` without `exportLocation`, `exportACL` or `cacheAssertions` | AssertionExport (2065335032) | Needs content-setting parsing. |
| `Cookie` initiator without `idpHistory="true"` | Cookie SessionInitiator (2065334760) | Parsed already. |
| `acsByIndex="true"` | SAML2 SessionInitiator (2065334736) | Doc: not advisable. |
| Explicit initiator at the shorthand's `/Login` or `/Logout` location | SSO (2065334348) | Needs initiator `Location`. |
| `maintainReverseIndex="false"` while SAML2 logout is on | SessionCache (2065334650) | Needs `SessionCache` parsing. |
| `unreliableNetworks` with `consistentAddress="false"` | SessionCache (2065334650) | Needs parsing. |
| `OutOfProcess` without `tranLogFormat`; `InProcess` `catchAll` | OutOfProcess (2065334599), InProcess (2063696243) | Extends SEC-121. |
| `Metadata` / `KeyDescriptor` extractor without `metadataAttributePrefix` | MetadataAttributeExtractor (2065334447) | Needs extractor type. |
| IIS `Site` hygiene (missing `Site`, extra `port` / `scheme`) | Site (2063696262), Upgrading Older ISAPI Configuration (2060615835) | Needs parsing. |
| Config files missing from `docs/shibboleth-files.md`: `protocols.xml`, `seckeygen`, `keygen`, `sp-signing-*.pem`, `sp-encrypt-*.pem` | ConfigurationFileSummary (2067400308) | Documentation, plus the file summary classifier. |

## Migration

| Idea | Page (id) | Notes |
|------|-----------|-------|
| `security-policy.xml` still on the SP2 namespace | UpgradingFromV2 (2067400004) | Needs the root `xmlns` of that file. |
| `file` / `uri` instead of `path` / `url` on plugins other than `MetadataProvider` | ReleaseNotes (2065335693) | Only `MetadataProvider` is covered by MIG-006 and MIG-013. |
| V2 config with `cacheAssertions` unset (default changes to `false` under the V3 namespace) | ReleaseNotes (2065335693) | Needs `SessionCache` parsing. |
| Deprecated `AlgorithmWhitelist`, `AlgorithmBlacklist`, `includeDefaultBlacklist` | SecurityPolicies (2065334425), ExcludedAlgorithms (2065334583) | Needs a security-policy scan. |
| Deprecated `authnContextDeclRef` rule alias | Rule (2065335141) | Needs access-rule parsing. |
