---
name: bbhunt-brute-force
description: "Hunt login/OTP/token brute force, credential stuffing and enumeration via error, status and timing differences. Unified from 2 upstream skills (cbh, hunting). For authorized security testing only."
agent_created: true
---

# Weak rate-limiting and brute-force hunting — unified methodology

> **Unified skill.** Built from 2 upstream skills across cbh, hunting. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### Autonomous Testing Priority

**Work within your turn budget — prioritize signal over volume.**

You cannot brute-force millions of combinations in automated testing. Focus on two things: (1) credential spraying with the most likely candidates, and (2) detecting whether rate limiting exists at all.

**Strategy:**
1. Identify the login endpoint and the expected parameter names (username/email, password).
2. Try weak/default credentials likely for the target context — default admin credentials for the app's stack, simple passwords for test environments, credentials visible elsewhere on the app (e.g. usernames exposed in profiles, default passwords in documentation).
3. After 3-5 failed attempts, check for rate-limit signals (429 status, "too many attempts" message, CAPTCHA appearance, account lockout message). Absence of these = rate limiting is missing = vulnerability.
4. Use form-encoding for traditional login forms, JSON for REST API login endpoints.

**What to look for as success:**
- Session token or JWT in the response body or Set-Cookie header
- Redirect to authenticated dashboard
- Response body that differs from the failed-login baseline

**Username enumeration (separate finding):** Try a known-valid username vs a random one. If the error message differs ("Wrong password" vs "User not found") or response time differs → user enumeration vulnerability, even without a successful login.

---

### Web-Research Methodology Additions (2026)

Research basis: HackTricks "Rate Limit Bypass" (endpoint variants, blank characters, header forging, HTTP/2 multiplexing, GraphQL aliases, batch endpoints, WebSocket/gRPC, CDN sharding) plus PortSwigger's Turbo Intruder / reCAPTCHA race research (last-byte synchronisation). These extend the four-state classification already in this skill — keep that classification and add the probes below.

### A. Discovery checklist — concrete places, params, headers, flows to look

- **Endpoint variants before anything else:** `/api/v3/sign-up`, `/Sign-up`, `/SignUp`, `/signup`, `/api/v1/sign-up`, `/api/sign-up`. A bypass here means canonicalization/routing happens after the rate-limit decision.
- **Method and body-surface variations:** POST→GET/PUT/PATCH, form→JSON→multipart, POST params moved to query string, trailing blank chars on the OTP/code.
- **Blank/delimiter candidates on the counter key:** `%00`, `%0d%0a`, `%0d`, `%0a`, `%09`, `%0c`, `%20` appended to the code or email — the app may trim while the limiter keys on the raw value.
- **IP-origin headers, individually and doubled:** `X-Originating-IP`, `X-Forwarded-For`, `X-Remote-IP`, `X-Remote-Addr`, `X-Client-IP`, `X-Host`, `X-Forwarded-Host`, `X-Real-IP`, `CF-Connecting-IP`, `True-Client-IP`; also two `X-Forwarded-For` lines and comma-joined values.
- **Non-IP limiter keys:** `User-Agent`, device ID, cookies, and especially the anti-CSRF cookie + form-token *pair*. Rotating only the cookie may 500; rotating both changes the quota.
- **Normalisation oracles:** percent-encoded emails (`e%78ample@em%61il.com`), NUL suffix (`example@x.com%00`), duplicate params (`?code=1&email=a@x&email=b@x`).
- **API-gateway shaping:** ignored parameters (`/resetpwd?someparam=1`) creating a fresh quota bucket; path+parameter composite keys.
- **Non-HTTP transports:** `/v2/batch` and array bodies, GraphQL aliases, WebSocket upgrade paths, gRPC streaming methods, HTTP/2 multiplexing.
- **Windows:** `X-RateLimit-Reset`-style headers (fix

### Signals and surfaces

### Crown Jewel Targets

OTP brute force (6-digit = 1,000,000 combinations) with no effective rate limit = Critical ATO bypass.

**Highest-value chains:**
- **OTP / 2FA brute → MFA bypass → ATO** — no effective rate limit on `/verify-otp`, full 000000–999999 keyspace reachable
- **Password-reset token brute** — short/predictable/non-expiring tokens + no rate limit → ATO (the Instagram 2019 case combined a 6-digit reset code, no rate limit per request-source, and IP rotation to make 10^6 tractable)
- **Username/email enumeration → targeted credential stuffing** — valid/invalid distinguishable by response string, status code, or timing, then sprayed with breach corpora
- **Coupon / gift-card / referral code brute** — no rate limit on code validation → financial impact
- **ReDoS** — attacker-controlled input hits a catastrophic-backtracking regex → CPU exhaustion → DoS

---

### Techniques, payloads and bypasses

### Phase 4 — IP / Source Rotation Bypass

```bash
# Per-IP limits are bypassable when the app trusts a client-controlled source header.
# Rotate the header EVERY request; if the 429 you hit in Phase 1 disappears → broken limit.
HEADERS=( "X-Forwarded-For" "X-Real-IP" "X-Originating-IP" "X-Client-IP" \
          "X-Remote-IP" "X-Forwarded" "Forwarded-For" "CF-Connecting-IP" "True-Client-IP" )
for i in $(seq 1 60); do
  RAND_IP="$(shuf -i 1-254 -n1).$(shuf -i 1-254 -n1).$(shuf -i 1-254 -n1).$(shuf -i 1-254 -n1)"
  ARGS=(); for h in "${HEADERS[@]}"; do ARGS+=(-H "$h: $RAND_IP"); done
  RESP=$(curl -s "${ARGS[@]}" -X POST "https://$TARGET/api/login" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"test@$TARGET\",\"password\":\"wrong$i\"}" -o /dev/null -w "%{http_code}")
  echo "Attempt $i (IP $RAND_IP): $RESP"
done
# Also try: multiple comma-joined XFF values ("1.2.3.4, 5.6.7.8"), and appending your real IP
# AFTER a spoofed one — some parsers take first, some last.
# CONFIRM the bypass: re-run Phase 1 WITHOUT rotation to show the 429 returns. The delta is the proof.
```

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- **Single-packet / last-byte synchronisation.** Burp Repeater 2023.9+ "send group in parallel" uses last-byte sync for HTTP/1 and the single-packet attack for HTTP/2 (20-30 requests in one TCP packet). Turbo Intruder gates: `engine.queue(req, gate='race1')` … `engine.openGate('race1')`; the research benchmark measured ~0.7ms spread vs 2.7ms for naive threads. This is the reliable way to beat per-window counters.
- **HTTP/2 multiplexing with connection reuse** — `seq | xargs curl` starts many connections and does NOT prove this; use `h2load -n 100 -c 1 -m 100 -d post.json https://target/api/v2/verify` or Turbo Intruder with `requestsPerConnection` 100-1000.
- **GraphQL alias amplification** (one HTTP request, many resolver calls if throttling counts requests): `mutation { a: verify(code:"111111"){token} b: verify(code:"222222"){token} ... }`. Read per-alias results — the response has a single HTTP status.
- **Bulk/batch endpoint wrapping:** `[{"path":"/login","method":"POST","body":{...}}, ...]` where the limiter guards only legacy endpoints.
- **Wrapper-dependent accounting:** one protocol wrapper (e.g. SOAP) sets the `auth.failed` attribute while another (GraphQL) calls the same handler without it — per-source counters never increment.
- **WebSocket / gRPC after the handshake:** edge WAFs may inspect only the upgrade; flood guesses as messages (`websocat`, `grpcurl -d @` streaming).
- **Fixed-window boundary burst** using `X-RateLimit-Reset`: maximum burst just before reset plus another immediat

### Validation and proof

### Validation — false-positive discipline

Before writing the report, each must hold:

- **OTP/login "no rate limit"**: confirmed against ALL FOUR states — not just absence of `429`.
  Shadow-throttle seed test passed (the known-good value still authenticates under burst load).
  Latency and body-size were monitored, not only status code.
- **Full-keyspace claim**: severity is justified by the *reachability math* (throughput × code-lifetime
  vs 10^6), not by a 101-code probe. State the numbers in the report.
- **Enumeration**: difference is reproducible across ≥20 samples and is a *server-state* difference
  (valid vs invalid user), not a server-policy artifact (e.g. a generic "if this email exists we sent…"
  message is NOT enumeration). For timing, compare medians of many samples, never single requests.
- **IP-rotation bypass**: proven by toggling rotation off and showing the `429` returns. The delta IS
  the proof; one fast run alone is not.
- **Token entropy**: backed by an actual measurement (Burp Sequencer effective-bits, `ent`, or a
  demonstrated counter/timestamp structure), not "looks short".
- **ReDoS**: super-linear (doubling) latency growth with a benign-control comparison; linear ≠ ReDoS.
- **Scope/impact**: did you reach a real outcome (authenticated session, leaked account list, DoS)?
  A rate-limit gap with no reachable impact is informational, not Medium.

**Severity:**
- Effective brute of OTP/MFA/reset-code → demonstrated ATO path: **Critical**
- No login rate limit + working credential-stuffing/IP-bypass: **High**
- Predictable security token (measure

### C. Validation / proof bar — how to confirm and avoid false positives

- Keep the four-state table and shadow-throttle seed test — necessary, not sufficient.
- **Prove the bypass is causal:** show the 429 returns when rotation/aliasing/multiplexing is disabled, then disappears when enabled. One clean fast run is not proof.
- **Prove the transport claim:** a multiplexing finding must show one connection (`h2load -c 1`, Turbo Intruder connection counters), not N curl processes.
- **Prove per-alias/batch results** from response fields, not the single HTTP status code.
- **Keyspace math for OTP severity:** state throughput × code-lifetime vs 10^6; a 101-code probe proves acceptance only. Don't exhaust a third party's keyspace.
- **Lockout DoS proof:** the legitimate owner's *correct* credentials must be refused after attacker-triggered failures; observe the unlock mechanism and whether privileged accounts are exempt.
- **Scope:** proxy networks, PoP sharding, and large bursts require explicit authorization; use tester-controlled infrastructure, never open proxies.

- **False-negative guard:** a "no 429" result must survive the shadow-throttle seed test at a known-good position under load; canned bodies are a throttle.
- **Quota-delta evidence:** record remaining quota before/after each rotation probe; a bypass that doesn't change the counter is not proven.
- **429-returns test:** disable the bypass and show the limit reappears — the delta is the proof.
- **Timing evidence:** a super-linear latency curve on ReDoS needs a same-length benign control; linear growth is just a slo

### Escalation and related chains

### Chain Table

| Finding | Chain to | Impact |
|---------|----------|--------|
| No effective rate limit on OTP (full 10^6 reachable) | MFA bypass → ATO | Critical |
| Password-reset code brute + IP rotation | Reset → ATO (Instagram-2019 class) | Critical |
| No rate limit on login + enumeration | Credential stuffing with breach corpus | High |
| IP bypass via X-Forwarded-For et al. | Every per-IP limit on the app defeated | High |
| Predictable / low-entropy reset token | Token guess within validity window → ATO | High |
| ReDoS on a public input field | Single-request CPU exhaustion → DoS | Medium–High |
| Hard lockout triggerable by attacker | Targeted account DoS (lock victim out) | Medium |

---

## Source skills merged into this topic

- `hunting` — `brute-force`
- `cbh` — `hunt-brute-force`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `bbhunt-methodology` — orchestrator, state machine and class router
