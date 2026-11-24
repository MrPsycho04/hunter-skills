---
name: bbhunt-saml
description: "Unified methodology for saml.. Unified from 2 upstream skills (cbh, hunting). For authorized security testing only."
agent_created: true
---

# Saml — unified methodology

> **Unified skill.** Built from 2 upstream skills across cbh, hunting. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### A. Discovery checklist — concrete places, params, headers, flows to look

- Find every SAML handler: POSTs carrying `SAMLResponse` to the ACS (`/saml/acs`, `/sso/saml`, `/Shibboleth.sso`, `/_layouts/`, `/cgi/samlauth`), plus signed `AuthnRequest`, `LogoutRequest` and `AttributeQuery` endpoints. Use SAMLExtractor over a subdomain list; install SAML Raider in Burp.
- Decode the full transport chain before analyzing: URL decode → Base64 decode → raw inflate. Keep a legitimate signed baseline response for every test.
- Fingerprint the library where possible (error text, headers, known vendor build) and map to the current parser-differential CVEset: ruby-saml CVE-2024-45409, CVE-2025-25291/25292 (REXML vs Nokogiri), php-saml/xmlseclibs void-canonicalization CVEs, NetScaler CVE-2026-8452 etc.
- Enumerate the full assertion context the SP should enforce: signature scope (Response vs Assertion), `Destination`, `AudienceRestriction`, `InResponseTo`, `NotBefore`/`NotOnOrAfter`, `StatusCode=Success`, `Issuer`, `SubjectConfirmationData/Recipient`, `NameID`, `AuthnContext`, role AttributeStatements. Mutate each independently.
- Look for flaw sources of valid signatures: publicly available signed IdP metadata (`?sign=true`), signed error responses, and WS-Federation metadata — PortSwigger's 2025 "Fragile Lock" shows these suffice once signature consumption is broken.
- Inspect injection/extension points that survive schema validation: `Extensions` and `StatusDetail` (they appear before the Signature element), `RelayState` reflection sinks, `error`/logout `base`/`return_to` URL params

### Signals and surfaces

### Attack Surface

```bash
# Find SAML endpoints
cat recon/$TARGET/urls.txt | grep -iE "saml|sso|login.*redirect|oauth|idp|sp"
# Key endpoints: /saml/acs (assertion consumer service), /sso/saml, /auth/saml/callback
```

### Techniques, payloads and bypasses

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- Signature stripping: remove every `<ds:Signature>` or empty the `SignatureValue` — some SPs treat "no signature" as "nothing to verify" and fail open. Compare valid baseline, corrupted signature, and fully unsigned variants.
- XSW1–XSW8 (HackTricks/PortSwigger/Somorovsky): wrap the signed assertion in a new evil root; use a detached signature; add a sibling evil Assertion; nest the original inside the evil one; put the copy inside `Extensions` (XSW7, works against OpenSAML) or another lax element (XSW8). Use SAML Raider to apply variants.
- Attribute pollution (Fragile Lock): `<samlp:Response ID="attack" samlp:ID="ID">` — libxml2 `xmlGetProp`/Nokogiri `node['ID']` ignores namespaces and resolves by simple name with order-dependent, undefined results; REXML chooses the opposite order. Desynchronize which element is verified vs consumed.
- REXML namespace confusion without DTDs: `<Signature xml:xmlns='http://www.w3.org/2000/09/xmldsig#'/>` hides/shows Signature nodes differently across parsers; wrap a fake signature in `<Extensions>` with `xml:xmlns='#other'` nesting.
- Void Canonicalization Golden SAML Response: `xmlns:ns="1"` (relative URI) makes libxml2 canonicalization fail; Nokogiri returns an empty string, so the digest is the SHA-256 of empty string `47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=`. With a reused IdP signature, the response passes signature validation regardless of assertion claims.
- Canonicalization-vs-application text differentials: `<saml:NameID><?p not-an-?>admin@example.

### Validation and proof

### C. Validation / proof bar — how to confirm and avoid false positives

- Reach a protected resource as a *known existing* federated user. Auto-provisioning an unknown `NameID` yields an authenticated-looking but unusable session; prefer `DOMAIN\Administrator` or `user@domain` when local usernames are blocked.
- Require `StatusCode=Success` on the same verified response; a signed error response must not authorize an assertion found elsewhere in the document.
- Distinguish a missing signature from a bad signature — acceptance of only the fully unsigned variant proves a fail-open validator branch, not broken cryptography.
- For CVE patch oracles, use the non-destructive fixed-length probes with a control request; identical results for probe and control mean INCONCLUSIVE, not PATCHED. Never length-sweep a production appliance (crash/session-creation branches exist).
- Do not count edits to display name/locale or theoretical XML changes; the auth-decision-changing step (NameID, AuthnContext, role AttributeStatement, or session issuance) is the gate.
- Confirm parser-dependent results against the actual library/version and re-test with a second clean session; preserve the exact SAMLResponse and the protected-resource response as evidence.

- A session issued for an auto-provisioned unknown user is not proof — resume with a known, existing federated account and access a protected resource as that identity.
- Verify the final identity after parsing: some SPs canonicalize or restrict NameID (e.g. reject values containing `@` or `\`), so a forged admin string may be accepted but r

### Escalation and related chains

### Related Skills & Chains

- **`account-takeover`** — SAML XSW with absent audience-restriction validation is the canonical SP-impersonation-of-admin chain. Chain primitive: XSW1 attack relocates signed assertion to a secondary position + injects evil assertion with `NameID=admin@target.com` in primary position + SP processes first assertion (the evil one) + SP doesn't validate `<AudienceRestriction>` so an assertion intended for IdP-A is accepted by SP-B → admin ATO across federated tenant boundary.
- **`auth-bypass`** — SAML signature-stripping is the textbook auth-bypass pattern; this skill provides the SAML mechanics, auth-bypass provides the broader bypass-discipline. Chain primitive: capture valid SAMLResponse → regex-strip `<ds:Signature>` element entirely → modify `<NameID>` to admin → re-encode base64 → POST to `/saml/acs` → SP wantAssertionsSigned=false silently accepts → admin session issued without any cryptographic challenge.
- **`oauth-oidc`** — SAML-fronted OAuth issuers turn assertion-level bugs into token-level ATO. Chain primitive: SP issues OAuth bearer tokens after SAML assertion validation + XSW alters NameID to admin → SP's token endpoint issues OAuth token bearing admin claims → all downstream OAuth-scoped APIs (admin API, billing API, user-management API) grant admin access from a single forged assertion.
- **`xxe`** — SAML assertions ARE XML; XXE in the assertion parser is a separate chain on top of XSW. Chain primitive: SAML parser without `disallow-doctype-decl` + `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` in assertion + `<Name

### Related Skills & Chains

- **`hunt-ato`** — SAML XSW with absent audience-restriction validation is the canonical SP-impersonation-of-admin chain. Chain primitive: XSW1 attack relocates signed assertion to a secondary position + injects evil assertion with `NameID=admin@target.com` in primary position + SP processes first assertion (the evil one) + SP doesn't validate `<AudienceRestriction>` so an assertion intended for IdP-A is accepted by SP-B → admin ATO across federated tenant boundary.
- **`hunt-auth-bypass`** — SAML signature-stripping is the textbook auth-bypass pattern; this skill provides the SAML mechanics, hunt-auth-bypass provides the broader bypass-discipline. Chain primitive: capture valid SAMLResponse → regex-strip `<ds:Signature>` element entirely → modify `<NameID>` to admin → re-encode base64 → POST to `/saml/acs` → SP wantAssertionsSigned=false silently accepts → admin session issued without any cryptographic challenge.
- **`hunt-oauth`** — SAML-fronted OAuth issuers turn assertion-level bugs into token-level ATO. Chain primitive: SP issues OAuth bearer tokens after SAML assertion validation + XSW alters NameID to admin → SP's token endpoint issues OAuth token bearing admin claims → all downstream OAuth-scoped APIs (admin API, billing API, user-management API) grant admin access from a single forged assertion.
- **`hunt-xxe`** — SAML assertions ARE XML; XXE in the assertion parser is a separate chain on top of XSW. Chain primitive: SAML parser without `disallow-doctype-decl` + `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` in assertion +

### Tools and wordlists

### Tools

```bash
# SAMLRaider (Burp extension) — automated XSW testing
# BApp Store → SAMLRaider → intercept SAMLResponse → SAML Raider tab

# Manual workflow:
echo "BASE64_SAML" | base64 -d > saml.xml
# Edit saml.xml
base64 -w0 saml.xml  # Re-encode
# URL-encode the result before sending as SAMLResponse parameter
```

## Source skills merged into this topic

- `hunting` — `saml`
- `cbh` — `hunt-saml`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `bbhunt-methodology` — orchestrator, state machine and class router
