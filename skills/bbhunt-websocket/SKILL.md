---
name: bbhunt-websocket
description: "Hunt cross-site WebSocket hijacking, weak Origin checks, per-message auth gaps and namespace/room authorization. Unified from 2 upstream skills (cbh, hunting). For authorized security testing only."
agent_created: true
---

# WebSocket vulnerability hunting — unified methodology

> **Unified skill.** Built from 2 upstream skills across cbh, hunting. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### A. Discovery checklist — concrete places, params, headers, flows to look

- Treat the **whole connection as attack surface**: the HTTP upgrade handshake, the per-message protocol, and the long-lived session state. PortSwigger Research (Sept 2025) stresses that most tooling "gives up the moment a protocol upgrade occurs," hiding broken access control, race conditions, and SQLi.
- Fingerprint the transport in the handshake: `Upgrade: websocket`, `Sec-WebSocket-Version: 13`, `Sec-WebSocket-Protocol` subprotocols, `Origin`, `Cookie`, and any token in the URL query (`?token=`, `?sid=`). Record which of these carries identity.
- **CSWSH preconditions checklist** (OWASP/HackTricks/Include Security 2025): (1) authentication is cookie-based, (2) cookie is `SameSite=None` (or otherwise sent cross-site), (3) no/weak `Origin` validation on the handshake, (4) no per-message token/authentication. If identity comes from a first-message token or a non-cookie header, a foreign page cannot reuse the victim's session just by opening a socket — deprioritize CSWSH.
- Test `Origin` exactly like a browser would: WSTG warns a standalone WS client can set any `Origin`, so a successful connect from `wscat` proves nothing. From your logged-in browser, load a page you control and run `new WebSocket("wss://target/socket")`. Try the exact allowlisted origin plus bypass shapes: `https://attackerallowed.example`, `https://allowed.example.attacker.test`, unexpected port, `http` vs `https`, IDNA/punycode twin, and `Origin: null` from a sandboxed iframe. The server must parse scheme+host+port, not substr

### Signals and surfaces

### Crown Jewel Targets

CSWSH (Cross-Site WebSocket Hijacking) with a cookie-authenticated handshake and no CSRF/per-connection token = High–Critical (real-time exfil of any logged-in victim's data).

**Highest-value chains:**
- **CSWSH → data exfil / ATO** — handshake authenticates via ambient cookie, no CSRF token, Origin not enforced → attacker page opens WS as the victim and streams their messages/PII/tokens. If the stream carries a session/refresh/CSRF token, this escalates to ATO.
- **No per-message auth** — HTTP/handshake auth present but individual WS frames are not re-authorized → privileged messages accepted (`deleteUser`, `getSecretConfig`).
- **Message tampering** — modify in-flight frames (price, qty, userId, amount) in trading/game/checkout apps → financial fraud.
- **socket.io namespace / room authz bypass** — connect to a privileged namespace or join another user's room without a permission check → cross-tenant real-time exfil.
- **Handshake-layer Upgrade smuggling** — a malformed `Upgrade`/`Connection`/`Sec-WebSocket-*` handshake makes the front proxy and origin disagree on whether an upgrade occurred → request-smuggling tunnel.

---

### Phase 5 — socket.io / SignalR / Phoenix Namespace & Room Authz Bypass

Engine.IO/socket.io is a protocol layered over the raw WebSocket. Packet prefixes (Engine.IO `4`=MESSAGE wrapping socket.io `0`=CONNECT, `1`=DISCONNECT, `2`=EVENT) carry namespace/room intent. Authorization must be checked when joining; often it isn't.

```bash
# 1) Open the raw socket.io WebSocket (Engine.IO v4)
wscat -c "wss://$TARGET/socket.io/?EIO=4&transport=websocket" \
  --header "Cookie: session=YOUR_SESSION"

# 2) Respond to the server's Engine.IO OPEN ('0{...}') so the connection lives,
#    then CONNECT to a namespace with a socket.io CONNECT packet.
#    CORRECT packet to join the /admin namespace:  40/admin,
#       4 = Engine.IO MESSAGE,  0 = socket.io CONNECT,  /admin, = namespace
#    (NOT a ?nsp= query param — see Phase 7. NOT 42 — 42 is MESSAGE+EVENT.)
# > 40/admin,
#    Server replies 40/admin,{"sid":"..."} on success, or 44/admin,{...} (error)
#    on rejection. A 40 success to a privileged namespace as a low/no-priv
#    user is the bug.

# 3) Once in a namespace, emit an EVENT (42) to join another user's room:
# > 42/admin,["join",{"room":"user_999_private"}]
# > 42["subscribe",{"channel":"admin_events"}]      # root namespace
#    Watch for 42 EVENT frames carrying ANOTHER user's data.
```

**Validate:** distinguish *connected to namespace* from *received privileged data*. The finding is confirmed only when you receive `42` event frames containing data belonging to a different tenant/user, or a privileged emit produces a verifiable server-side effect. A `40/admin` ack with no s

### Techniques, payloads and bypasses

### Business Logic Abuse: State Machine Bypass & Rate Limit Evasion

Stateful protocols (e.g., a trading platform expecting `connect → authenticate → verify_balance → place_order`) may accept messages out of order or skip prerequisites. Test: (a) **state skip**: connect and immediately send `place_order` without `authenticate` or `verify_balance` first — many stacks don't enforce strict ordering if individual message validation is missing, (b) **high-frequency spam**: send identical or high-volume messages rapidly to bypass WS-layer rate limits (different from HTTP rate limits) — test 100s of messages/second to see if the server throttles, returns 429, or closes the connection. If it accepts and processes all, this can abuse business logic (e.g., many small payments to bypass amount caps, or rapid subscriptions to exhaust resources).

---

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- **WebSocket Turbo Intruder (PortSwigger, 2025)** two components:
  - *Turbo Intruder*: thousands of messages/sec over one persistent socket with Python `queue_websockets` / `handle_outgoing_message` / `handle_incoming_message`; engines `BURP`, `TURBO`, `THREADED`.
  - *HTTP Middleware*: wrap a WS connection in a local HTTP endpoint so any HTTP scanner (Burp Pro, sqlmap-style tools) can send POST bodies as WS messages:
    ```
    POST /proxy?url=https%3A%2F%2Ftarget%2Fchat HTTP/1.1
    Host: 127.0.0.1:9000

    {"message":"hi"}
    ```
    Ideal for SQLi/auth bypass/command injection hidden behind the WS layer.
- Noise filtering example (keep only the user you care about):
  ```python
  @MatchRegex(r'{"user":"Hal Pline"')
  def handle_incoming_message(websocket_message):
      results_table.add(websocket_message)
  ```
- **Socket.IO automation** — force `EIO=4`, send CONNECT, handle ping/pong:
  ```python
  connection = websocket_connection.create(
      upgrade_request.withUpdatedParameters(HttpParameter.urlParameter("EIO", "4")))
  connection.queue('40')
  connection.queue('42["message","hello"]')
  @PingPong("2", "3")
  def handle_incoming_message(m): ...
  ```
- **WS server-side prototype pollution** via Socket.IO's Express underpinnings: pollute the greeting property with `{"__proto__":{"initialPacket":"Polluted"}}`; changed initial greeting proves it. Chain to the full server-side PP detection toolkit (status/json spaces/OAST) from the prototype-pollution skill.
- **WebSocket race conditio

### Validation and proof

### Validation (mandatory before reporting)

- ✅ **CSWSH:** attacker-origin PoC HTML, opened with a *different* victim account logged in, must **receive that victim's data** (verified by a unique planted marker / distinct PII) and exfil it to **Collaborator/OAST**. A bare `101` from a foreign Origin is NOT a finding.
- ✅ **No per-message auth:** privileged frame produces a **verifiable server-side effect** (state change confirmed via a second channel / REST API), not merely "accepted".
- ✅ **Message tampering:** tampered value **persists server-side** (confirmed via order/balance API), not just echoed in the UI.
- ✅ **Namespace/room bypass:** received **`42` event frames with another user's data**, not just a `40` namespace ack.
- ✅ **Upgrade smuggling:** desync proven by timing/differential probe **and** real-world impact, **OAST-confirmed**. No single-response guesses.
- ❌ Reject: a 101 alone, an accepted-but-ignored frame, a self-echoed message, a connected-but-empty namespace, or any "confirmed" claim lacking out-of-band/cross-account proof.

**Severity:**
- CSWSH leaking session/refresh token → ATO: **Critical**
- CSWSH → real-time session-data theft: **High**
- No auth on admin/privileged WS actions: **Critical**
- Financial message tampering (server-confirmed): **Critical**
- Namespace/room subscription bypass (cross-tenant): **High**

### C. Validation / proof bar — how to confirm and avoid false positives

- A **101 handshake from a foreign `Origin` is only a candidate**, not CSWSH. OWASP/WSTG/PortSwigger all insist on proving the socket can *read* authenticated data or *perform* an authenticated state change from the attacker page. The server may still reject frames or require a first-message token.
- Browser baseline matters (Include Security 2025): `SameSite=Lax` (Chrome default since 2020) and implicit-Lax two-minute grace do **not** apply to WS handshakes — CSWSH needs explicit `SameSite=None`; Firefox Total Cookie Protection blocks it even then; Chrome 3P-cookie blocking/Incognito may also block. A PoC that only works with third-party cookies enabled and protections disabled must say so; don't overclaim severity.
- Use a real browser for the Origin test, not a programmable client. Also test with browser deviations: IDNA, `null` origin, port mismatch — a regex bypass must be demonstrated with a value a real browser can emit.
- For message-authz findings, use two accounts: A's token must reach B's data/actions. No-cookie frames being processed only matter if the endpoint is supposed to require auth — health/status echo sockets are intentionally public.
- For Turbo Intruder races: capture a before/after state (balance, coupon count, token consumption count) and at least one successful collision; a single anomalous frame is noise. Apply the race-condition skill's statistical-sampling bar.
- For prototype pollution via Socket.IO: show the changed greeting/behavior **and** a non-destructive second-order

### Escalation and related chains

### Chain Table

| WS finding | Chain to | Impact |
|-----------|----------|--------|
| CSWSH + token in stream | Steal session/refresh/CSRF token from victim frames | ATO (Critical) |
| CSWSH confirmed | Subscribe to victim channels, exfil to OAST | Real-time data theft (High) |
| No per-message auth | Send admin/privileged frames | Privilege escalation (Critical) |
| Message tampering | Modify price/amount/userId, confirm server-side | Financial fraud (Critical) |
| Namespace/room authz bypass | Join other tenant's room, read `42` events | Cross-tenant exfil (High) |
| Handshake Upgrade smuggling | Tunnel HTTP past WAF/authz, OAST-confirmed | Smuggling → SSRF/cache poison (High–Critical) |

---

### Tools and wordlists

### Tools

```bash
npm install -g wscat                 # CLI WS client (raw + socket.io)
brew install websocat                # alt client; supports text/binary + autoreconnect
# Burp Suite Pro: WebSockets history (intercept/edit/replay), HTTP Request
#   Smuggler extension (handshake-upgrade smuggling), Collaborator for OAST proof.
# Burp MCP: get_proxy_websocket_history / get_proxy_websocket_history_regex to
#   enumerate frames; generate_collaborator_payload + get_collaborator_interactions
#   to prove out-of-band receipt from a CSWSH/smuggling PoC.
```

---

## Source skills merged into this topic

- `hunting` — `websocket`
- `cbh` — `hunt-websocket`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `references/upstream-assets/` — 1 companion files (payload/technique references, scripts, validators and schemas) from the contributing skills
- `../../upstream/` — complete unmodified archives of all five source repositories
- `bbhunt-methodology` — orchestrator, state machine and class router
