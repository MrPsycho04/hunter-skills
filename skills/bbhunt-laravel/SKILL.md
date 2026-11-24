---
name: bbhunt-laravel
description: "Hunt debug leakage, Telescope/Horizon exposure, Ignition RCE, signed-URL manipulation and queue-worker flaws. Unified from 2 upstream skills (cbh, hunting). For authorized security testing only."
agent_created: true
---

# Laravel-specific vulnerability hunting — unified methodology

> **Unified skill.** Built from 2 upstream skills across cbh, hunting. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### A. Discovery checklist — concrete fingerprints, endpoints, headers, CVEs to look for

- **APP_KEY reuse is the dominant 2024–2026 pattern.** Synacktiv + GitGuardian (July 2025) harvested **267,952 APP_KEYs** from public sources and **625,059 `XSRF-TOKEN` ciphers** from 672,481 public Laravel sites; ~**3.56%** of keys could be recovered without ever touching the target, and ~1,091 hosts were still one request away from CVE-2018-15133 RCE. Top reused keys are vendor defaults (UltimatePOS, XPanel, Invoice Ninja `RR++yx2rJ9kdxbdh3+AmbHLDQu+Q76i++co9Y8ybbno=`, Snipe-IT `3ilviXqB9u6DX1NRcyWGJ+sjySF+H18CPDGb3+IVwMQ=`, the legacy `SomeRandomString` / `SomeRandomStringOf32CharsExactly` defaults). Hash any discovered key against these corpora first.
- **The cookie pair is a free ciphertext oracle.** A default Laravel install always sets `XSRF-TOKEN` (immutable name) and `<app>_session` (e.g. `laravel_session`) on its first non-redirect response, even unauthenticated. Each value is a base64 JSON blob `{iv, value, mac, tag}` — that is a valid `Encrypter` cipher you can feed to an offline key brute-forcer. A decrypted plaintext starting with `s:`/`a:`/`O:` means deserialization is reachable.
- **Specific CVE-bearing products to fingerprint:**
  - **CVE-2024-55555 — Invoice Ninja** (pre-auth `GET /route/{hash}` calls `decrypt($hash)`); default key shipped in `.env.example`.
  - **CVE-2024-48987 — Snipe-IT** (`XSRF-TOKEN` decrypted + unserialized when `Passport::withCookieSerialization()` is set).
  - **CVE-2024-55556 — Crater** (`SESSION_DRIVER=cookie`, 40-char cookie name, e.g. `DqN

### Signals and surfaces

### Crown Jewel Targets

Laravel debug mode enabled in production = instant RCE via Ignition (CVE-2021-3129).

**Highest-value findings:**
- **Ignition RCE (CVE-2021-3129)** — `APP_DEBUG=true` + Laravel < 8.4.2 → `/_ignition/execute-solution` RCE without auth
- **Telescope dashboard** — `/telescope` exposes full request/response logs, DB queries, Redis commands, scheduled jobs, environment variables
- **Horizon dashboard** — `/horizon` exposes queue job details, failed jobs with full payloads (may contain API keys, PII)
- **Signed URL manipulation** — if `URL::signedRoute` validates wrong params → bypass signed URL → unauthorized actions
- **.env exposure** — `APP_KEY` leaked → decrypt all encrypted cookies → forge session → ATO

---

### Techniques, payloads and bypasses

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- **Turn any single default install into a fleet RCE.** Collect the `XSRF-TOKEN` cipher from the target, run `laravel_crypto_killer.py bruteforce -v <cipher>` against a wordlist of known public/default APP_KEYs, then `decrypt -k <key> -v <cipher>` to confirm plaintext. A matched key on a second host proves the reused-secret class across the estate.
- **Gadget → encrypt → replay** (the full Synacktiv chain):
```
php8.2 phpggc Laravel/RCE13 system id -b -f
./laravel_crypto_killer.py encrypt -k <APP_KEY> -v "$(phpggc ...)"
curl -s http://TARGET/route/<ciphertext>            # Invoice Ninja
curl -s -H "Cookie: XSRF-TOKEN=<ciphertext>" http://TARGET/login   # Snipe-IT
```
- **Cookie-session variant (Crater):** decrypt the random-name session cookie; it decodes to `<hash>|<JSON>` where the JSON `data` field holds PHP serialized data. Pass the pre-pipe hash to `laravel_crypto_killer.py encrypt ... -sc <hash>` so the forged cookie preserves the session binding, then send it together with `laravel_session`.
- **phpggc chain choice matters by PHP/Laravel version:** `Laravel/RCE9` (PHP 7.4, Snipe-IT), `Laravel/RCE13` (PHP 8.2, Invoice Ninja), `Laravel/RCE15` (session-cookie QUEUE chain). Use `test-gc-compatibility.py` from phpggc to confirm the gadget still lands on the target's installed versions — Laravel ships many working chains even in current releases.
- **No-key paths:** if key recovery fails, go for `APP_DEBUG=true` (Whoops/Ignition) → CVE-2021-3129, or CVE-2025-34060-style stream-filter PHP wrappers

### Validation and proof

### Validation

✅ Ignition RCE: `id` command output returned in response
✅ Telescope: API responses contain DB queries with credentials or user tokens
✅ APP_KEY: Forged session cookie accepted, returns another user's profile
✅ Mass assignment: `is_admin: true` accepted, account now has admin privileges

**Severity:**
- Ignition RCE: Critical
- Telescope/Horizon with sensitive data: High
- .env with APP_KEY: Critical
- Mass assignment to admin: Critical

---

### C. Validation / proof bar — how to confirm and avoid false positives

- **Decryption is not exploitation.** Report "APP_KEY recovered and valid" only when you also show a decrypted cookie whose plaintext contains serialized data (`s:`/`a:`/`O:`) *and* a deserialization sink you can reach. Synacktiv's research explicitly notes the decrypt function is safe if the caller passes `$unserialize=false` or the app has no reachable gadget.
- **Proof of RCE = command output or OOB callback**: `uid=... gid=...` in the response body (as in the published Invoice Ninja / Crater PoCs), a DNS/HTTP hit on a unique Collaborator subdomain, or a file written to a known web-accessible path. A 200 response alone is not proof.
- **Default-key caveat:** if the target ships a known default key but the app has been patched so the vulnerable `decrypt()` call site no longer exists (CVE-2024-48987/55555/55556 are all patched), the key alone is an info-leak/config finding, not RCE. Verify the specific vulnerable route/cookie behavior on the target.
- **Brute-force hygiene:** a "cracked key" that decrypts to a plain string with no serialized marker is a valid key but **not** an RCE path — record it as credential exposure and keep hunting for a sink. `nounours` classifies each result as CBC/GCM and flags whether a serialization pattern matched; use that flag, not the key hit, as the severity driver.
- **Environment-override CVE-2024-52301:** a changed banner or Whoops page after `?--env=local` confirms env manipulation, but severity depends on what the alternate config exposes (debug, seeded creds, we

### Validation

✅ Ignition RCE: `id` command output returned in response
✅ Telescope: API responses contain DB queries with credentials or user tokens
✅ APP_KEY: Forged session cookie accepted, returns another user's profile
✅ Mass assignment: `is_admin: true` accepted, account now has admin privileges

**Severity:**
- Ignition RCE: Critical
- Telescope/Horizon with sensitive data: High
- .env with APP_KEY: Critical
- Mass assignment to admin: Critical

### Escalation and related chains

### Chain Table

| Laravel finding | Chain to | Impact |
|----------------|----------|--------|
| Debug mode ON | CVE-2021-3129 Ignition RCE | Critical RCE |
| Telescope accessible | Read API keys, DB queries, env vars | High - credential theft |
| Horizon accessible | Read failed job payloads | High - PII/token exfil |
| .env exposed with APP_KEY | Forge session cookie → ATO | Critical ATO |
| Signed URL bypass | Unauthorized actions (unsubscribe any user, etc.) | Medium-High |
| Mass assignment | Set is_admin=true → privilege escalation | Critical |

---

## Source skills merged into this topic

- `hunting` — `laravel`
- `cbh` — `hunt-laravel`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `bbhunt-methodology` — orchestrator, state machine and class router
