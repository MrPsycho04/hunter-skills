---
name: bbhunt-race-condition
description: "Use for check-then-act flows: balances, limits, coupons, invites, quotas, one-time tokens and status transitions under parallel requests. Unified from 3 upstream skills (cbh, h1skills, hunting). Plus evidence from all 15,259 disclosed HackerOne reports. For authorized security testing only."
agent_created: true
---

# Race Conditions and TOCTOU — unified methodology

> **Unified skill.** Built from 3 upstream skills across cbh, h1skills, hunting and the local HackerOne corpus. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Corpus-backed method (this class)

1. Identify check-then-act pairs: read a balance/limit, decide, then write. The gap is the race window.
2. Prepare two accounts and a measurable state delta (money, count, quota, one-time use).
3. Synchronize parallel requests (same timing barrier) and repeat enough times to distinguish a race from a fluke.
4. Use a harmless counter or test object first; never race against real money outside the program's sandbox.
5. Capture the state before and after with exact request timing; prove the invariant was violated.
6. Test idempotency keys and lock behaviour; report the missing control, not the tool that found it.

### Signals

- A balance/limit is checked and then updated in separate operations
- Single-use token or coupon
- State transitions with no idempotency key

### Kill criteria

- Result is explainable by normal sequential processing.
- Single successful attempt with no reproducible parallel evidence.
- State change affects only your own test data with no security consequence.

### Escalation chains

- Race on limit -> repeated benefit -> financial/quota bypass.
- Race on one-time token -> token reuse -> auth impact.

### Veteran tip

A race is a finding only when the invariant violation is demonstrated with a state delta — timing noise is not impact.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### Quick wins

Start here. These are the highest-yield tests for this class.

- Identify check-then-act flows: balance, quota, coupon, invite, vote, refund.
- Fire parallel requests with last-byte sync or HTTP/2 single-packet attack.
- Test idempotency keys and database constraints.
- Look for partial-state windows in multi-step workflows.

### Deeper checklist

- Identify check-then-act flows: balance, quota, coupon, invite, vote, refund.
- Fire parallel requests with last-byte sync or HTTP/2 single-packet attack.
- Test idempotency keys and database constraints for bypass.
- Look for partial-state windows in multi-step workflows.
- Measure the resulting over-spend/over-claim precisely.
- Keep request volume controlled and reproducible.

### Step-by-Step Hunting Methodology

1. **Enumerate one-time or limited-use actions** — Map every endpoint that enforces a "once per user", "limited quantity", or "deduct balance" constraint. These are your primary targets.

2. **Understand the state machine** — For each target action, identify: (a) what state is read, (b) what state is written, (c) what validation sits between read and write. The gap between read and write is your window.

3. **Capture a clean baseline request** — Perform the action once legitimately with Burp Suite intercepting. Confirm you get the expected single-use behavior (e.g., coupon marked used, vote counted once).

4. **Set up parallel request tooling** — Use one of:
   - Burp Suite Repeater → "Send group in parallel" (Turbo Intruder for HTTP/2 single-packet attacks)
   - Turbo Intruder with `engine=Engine.BURP2` for last-byte sync
   - `curl` with `&` backgrounding
   - Python `threading` or `asyncio` with pre-built connections

5. **Execute the race** — Send 10–50 identical requests simultaneously. Key technique: **pre-connect and buffer all requests, release the final byte of all simultaneously** (single-packet attack when HTTP/2 is available).

6. **Analyze responses** — Look for:
   - Multiple `200 OK` where only one should succeed
   - Duplicate success messages
   - Database constraint errors (signals the race worked but hit the last-line-of-defense)
   - Inconsistent response times (one fast, rest slow = serialized; all same speed = parallel processing)

7. **Verify the effect** — Check the actual state: Was the credit applied twice? Did

### Race-window estimation methodology

Before firing the attack, estimate the race window. This determines whether you need single-packet at all, and how many concurrent requests to send.

1. Issue a **single** request to the target endpoint. Capture the response time on the wire: `T_single`.
2. Issue **two sequential** requests. Capture both response times: `T_seq1`, `T_seq2`.
3. Issue **two concurrent** requests over the same connection (via HTTP/2 multiplex or HTTP/1.1 pipeline). Capture both: `T_par1`, `T_par2`.
4. If `T_par1 ≈ T_par2 ≈ T_single`, the server handles both in parallel — race window is `min(T_par1, T_par2)`, single-packet helps a lot.
5. If `T_par2 ≈ T_par1 + T_single`, the server serialises — race window is whatever happens between sequential workers; single-packet helps less but still wins over TCP jitter.
6. For PIN / OTP / coupon-redemption endpoints, expect `T_single` to be 10–100 ms (DB query latency). The race window inside the server is typically < 1 ms (the gap between `SELECT` and `UPDATE` on the same row).
7. **N rule of thumb:** start with `N = 30` concurrent requests for single-packet h2. Increase to 100+ if the target's `T_single` is < 10 ms (very fast endpoint = larger pre-buffer needed to overflow the worker pool). Up to **10,000** with Flatt's first-sequence-sync extension (see below).

### A. Discovery checklist — concrete places, params, headers, flows to look

- Map candidates with PortSwigger's **three-question collision filter** (from "Smashing the state machine"): (1) *How is state stored?* Prefer persistent server-side DB state; skip pure client-side state (e.g. emailed JWT resets). (2) *Are we editing or appending?* Editing an existing record (change primary email, flip balance) has high collision potential; append-only actions mostly yield limit overruns. (3) *What is the operation keyed on?* You need two operations using the **same key** (same session ID, same user ID, same filename) — parallel resets for two different userids touch different rows and will never collide.
- Build an **endpoint × object inventory**: for each security-relevant object (users, sessions, orders, vouchers, API keys), list every endpoint that reads or writes it. Password reset = reset-init + reset-complete + registration + profile-edit + login (all touch the users table). The collision hides between these endpoints, not inside one.
- **Hidden multi-step sequences (sub-states)**: a single request can transition through a temporary privileged state and exit before completion. Classic example — login sets `session['userid']` *before* `session['enforce_mfa']=True`, leaving a window where the user is logged in but MFA is not enforced. Pair the login request with a direct request to `/my-account` / admin API in the same batch.
- Look for **deferred collisions**: PortSwigger found email-change races that worked with a 20-minute gap between the two requests. These produce no imm

### Signals and surfaces

### Signal

- Reports: **97** · paid: **18**
- Median bounty **$510** · p90 **$5,000** · max **$15,250** · total **$37,946**
- Median upvotes **26**

### Where it pays

| Program | Reports | Bounty | Upvotes |
|---|---|---|---|
| Shopify | 4 | $15,750 | 394 |
| Internet Bug Bounty | 7 | $8,960 | 113 |
| Cosmos | 1 | $5,000 | 61 |
| Tools for Humanity | 1 | $3,000 | 95 |
| InnoGames | 1 | $2,000 | 137 |
| Mail.ru | 4 | $1,000 | 116 |
| Pornhub | 1 | $520 | 13 |
| HackerOne | 11 | $500 | 1136 |

### Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`coupon` `withdraw` `transfer` `invite` `vote` `refund` `balance` `quota` `limit`

### Crown Jewel Targets

Race conditions are high-severity findings because they break financial, access control, and integrity assumptions that defenders rarely stress-test. Highest payouts come from:

- **Monetary/credit systems** — double-spending gift cards, coupons, referral bonuses, promotional credits, wallet balances
- **Vote/reputation manipulation** — upvoting the same content multiple times, gaming leaderboards or trending algorithms
- **Account limits bypass** — exceeding free-tier quotas, bypassing "one per user" restrictions on invites, trial activations, or API key generation
- **Privilege escalation** — racing role assignment or permission checks during user creation/upgrade flows
- **Deletion bypass** — reading or exfiltrating data during a narrow window between "marked for deletion" and "actually deleted"
- **Payment flows** — charging a card once but receiving multiple fulfillments

**Best-paying asset types:** Fintech apps, SaaS platforms with credit/subscription models, social platforms with reputation systems, e-commerce checkout flows, OAuth/SSO token endpoints.

---

### Response Headers That Signal Race-Prone Backends

```
X-RateLimit-*        # rate limiting exists, but may not be atomic
X-Request-Id         # each request independently tracked
No Cache-Control     # stateful ops not idempotent
```

### Tech Stack Signals

- **Ruby on Rails** without `with_lock` / `lock!` — ActiveRecord doesn't lock by default
- **Node.js** with async/await chains — non-atomic DB reads then writes
- **PHP** without `SELECT ... FOR UPDATE` — common in legacy codebases
- **Microservices** — inter-service calls introduce natural TOCTOU windows
- **Redis counters** without Lua scripts or `INCR` atomicity checks
- **Message queues** — idempotency keys often missing

---

### Techniques, payloads and bypasses

### Payloads & probes

- Single-packet attack: 20-30 requests in one HTTP/2 packet
- Last-byte sync: hold final byte, release together
- Repeat the same coupon/withdrawal across parallel connections

### Bypass tricks

- Bypass rate limits by racing before the counter commits.
- Use different sessions/accounts to hit shared resources.
- Combine with limit/refund logic for financial impact.

### Techniques from real reports

One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.

- **Race Condition allows to redeem multiple times gift cards which leads to free "money"** — `#759247` · Reverb.com · $0 · ▲308
  > - Now set the external HTTP header `x-request: %s` - This is needed by the turbo intruder
- **Ability to bypass partner email confirmation to take over any store given an employee email** — `#300305` · Shopify · $15,250 · ▲273
  > Visit `https://partners.shopify.com/[ID]/managed stores`, add the store, and you now have access.
- **Race condition in performing retest allows duplicated payments** — `#429026` · HackerOne · $0 · ▲240
  > Right click the request in Burp Suite and select `Copy as curl command`.
- **Client-Side Race Condition using Marketo, allows sending user to data-protocol in Safari when form without onSuccess is submitted on www.hackerone.com** — `#381356` · HackerOne · $0 · ▲154
  > However, if the `onSuccess` doesn't exist or returns `true`, the parameter called `followUpUrl` will instead be sent to `location.href`.
- **Race Condition leads to undeletable group member** — `#604534` · HackerOne · $0 · ▲153
  > - Join using the invitation link on the second account and intercept the request:
- **Bypassing HackerOne 2FA due to race condition** — `#2598548` · HackerOne · $0 · ▲139
  > When a user canceled one reset request, the remaining requests would stay active, potentially leading to unauthorized 2FA removal after 24 hours.
- **Race Conditions in Popular reports feature.** — `#146

### Payload fragments observed

Recurring payloads from this class's writeups. Adapt, don't paste blindly.

| Seen | Fragment |
|---:|---|
| 9× | `Curl_dnscache_add_negative()` |
| 5× | `Curl_dnscache_add()` |
| 5× | `std::fs::remove_dir_all()` |
| 5× | `Curl_fopen()` |
| 4× | `Curl_hash_add()` |
| 4× | `Curl_hsts_save()` |
| 3× | `data:` |
| 3× | `stat()` |
| 3× | `dnscache_lock()` |
| 3× | `dnscache_add_addr()` |
| 3× | `Curl_hsts_parse()` |
| 3× | `curlx_gmtime()` |
| 3× | `Curl_close()` |
| 2× | `x-request: %s` |
| 2× | `Buffer.from()` |
| 2× | `share->cookies` |
| 2× | `remove_dir_all()` |
| 2× | `hsts_out()` |
| 2× | `--hsts <file>` |
| 1× | `https://sandbox.reverb.com/<lang>/redeem` |

### Ability to bypass partner email confirmation to take over any store given an employee email

`#300305` · Shopify · $15,250 · critical · 2018-02-07 · ▲273
> It's possible to take over any store account through partners given an employee email address. This is possible because I found a way to confirm arbitrary emails. I don't know the Shopify ecosystem well enough to know the other ramifications of such a bug.

### Common Root Causes

1. **Check-Then-Act without atomic operations** — Developer reads state (`if voucher.used == false`), then writes state (`voucher.update(used: true)`) in two separate database operations. Any thread can read the same "unused" state before either writes.

2. **Missing database-level locking** — Using ORM methods like `find` or `filter` instead of `SELECT ... FOR UPDATE`. The fix is one line but developers don't think about concurrency.

3. **Optimistic concurrency without version checking** — Systems increment counters or mark records without checking if the record changed since it was read.

4. **Microservice TOCTOU** — Service A validates eligibility, Service B executes the action. No shared atomic transaction spans both services.

5. **Client-side "protection"** — Developers disable the button in JavaScript after first click, assuming that prevents duplicate submissions. Server-side logic is never hardened.

6. **Counter increments outside transactions** — `votes_count += 1; save()` instead of an atomic SQL `UPDATE SET votes = votes + 1 WHERE id = ?`.

7. **Async background jobs** — Eligibility checked synchronously, fulfillment done asynchronously. A second request passes the check before the first job completes.

8. **Caching without invalidation** — Cached "has user voted?" check returns stale `false` during a cache miss window when the first write hasn't propagated yet.

---

_...and 4 more sections in `references/unified-method.md`._

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

### Gate 0 Validation

Before writing the report, confirm all three:

1. **What can the attacker DO right now?**
   Can you demonstrate — with screenshots or logs — that the same one-time action succeeded more than once? (e.g., vote count shows +2 from one user, credit balance shows double-credit, coupon shows redeemed twice)

2. **What does the victim LOSE?**
   Is there concrete, measurable harm? Financial loss (credits issued in excess), integrity loss (manipulated rankings/votes), or security loss (access granted beyond entitlement)? "The counter went up twice" is only valid if that counter has real-world value.

3. **Can it be reproduced in 10 minutes from scratch?**
   Can you write a 20-line script, run it against a fresh test account, and reliably demonstrate the duplicate effect at least 3/5 attempts? If it requires perfect timing you cannot reliably control, the exploitability claim is weak.

---

### Wireshark validation

To confirm your attack tool is genuinely producing one-packet sync (vs accidentally fragmenting):

1. Capture the loopback or your egress interface during the attack: `sudo tcpdump -i lo0 -w race.pcap port 443` (or interface 0).
2. Open in Wireshark, filter `tls and tcp.port == 443`.
3. Find the TLS record containing the END_STREAM flush. It should contain **N H2 DATA frames with END_STREAM set, in one TLS record, in one TCP segment.**
4. If you see N TLS records or N TCP segments, your tool is sequencing. The race window is your inter-segment gap — typically too wide.

The Turbo Intruder `engine=Engine.BURP2` implementation guarantees single-packet delivery on HTTP/2 targets when the request body fits in MTU. For larger bodies, see the "Race-window estimation" subsection below.

### C. Validation / proof bar — how to confirm and avoid false positives

- Always **benchmark sequentially first**. Without a baseline you cannot recognize a clue, and you will misread normal behavior as a race. Capture both baseline and parallel result tables.
- Prove with **at least one success plus N over-quota/stale-state confirmations**, and verify the *business outcome*, not just multiple `200 OK`s: coupon count increased, balance credited N×, voucher row still valid, MFA gate actually bypassed. Watch for the subtle case where state looks correct (voucher REDEEMED) but the side effect applied repeatedly — that's still a finding.
- Replay the minimal 2-request version at least a few times and record the success rate. A one-off anomaly under a 30-request burst may be server jitter, not a deterministic race. Apply the skill's Statistical-Sampling gate.
- Confirm the collision uses a **shared key** (same session/user/object). Two different records changing concurrently is normal parallelism, not a vulnerability.
- Rule out session locking before concluding "not vulnerable": repeat with distinct session cookies. Rule out client-side-only state: if the whole flow is a signed JWT emailed to the user, there's nothing to race server-side.
- For MFA/sub-state claims, prove access to a genuinely authenticated, sensitive endpoint — reaching a neutral page is not impact. For deferred collisions, correlate the second-order observation (email content, changed settings) back to the exact prior request pair.
- **DoS caution**: high-rate race tooling (HTTP/3 >100k rps, first-sequence-

### Escalation and related chains

### Escalation chains

- Race -> double spend.
- Race -> multiple invites/rewards.
- Race -> limit bypass.

### Related Skills & Chains

- **`logic-and-design`** — Race conditions are the "concurrency arm" of every business-logic state machine. Chain primitive: business logic (coupon/promo) + race-condition single-packet attack → coupon redeemed N times → direct financial loss.
- **`mfa-and-passwords`** — OTP-expiry windows and replay protection are classic race targets. Chain primitive: race + MFA-validate endpoint → bypass OTP expiry by submitting N concurrent validations within the validity window.
- **`account-takeover`** — Race conditions on password reset, email change, and account creation enable persistent ATO. Chain primitive: race on email-change endpoint + atomic-update missing → swap victim email + read reset token before user notice.
- **`api-misconfig`** — Wallet/balance/credit endpoints without atomic UPDATE are double-spend candidates. Chain primitive: race + atomic-update missing → double-spend balance → withdraw N× user balance.
- **`security-arsenal`** — Load the Turbo Intruder single-packet template, h2.cl smuggling for atomic submit, and `curl --next` parallel multi-request patterns.
- **`triage-validation`** — Apply the Statistical-Sampling gate: a single anomalous response is noise; require 1 successful + N duplicate / over-quota / stale-state demonstrations with response screenshots before reporting.

### Related Skills & Chains

- **`hunt-business-logic`** — Race conditions are the "concurrency arm" of every business-logic state machine. Chain primitive: business logic (coupon/promo) + race-condition single-packet attack → coupon redeemed N times → direct financial loss.
- **`hunt-mfa-bypass`** — OTP-expiry windows and replay protection are classic race targets. Chain primitive: race + MFA-validate endpoint → bypass OTP expiry by submitting N concurrent validations within the validity window.
- **`hunt-ato`** — Race conditions on password reset, email change, and account creation enable persistent ATO. Chain primitive: race on email-change endpoint + atomic-update missing → swap victim email + read reset token before user notice.
- **`hunt-api-misconfig`** — Wallet/balance/credit endpoints without atomic UPDATE are double-spend candidates. Chain primitive: race + atomic-update missing → double-spend balance → withdraw N× user balance.
- **`security-arsenal`** — Load the Turbo Intruder single-packet template, h2.cl smuggling for atomic submit, and `curl --next` parallel multi-request patterns.
- **`triage-validation`** — Apply the Statistical-Sampling gate: a single anomalous response is noise; require 1 successful + N duplicate / over-quota / stale-state demonstrations with response screenshots before reporting.

### Tools and wordlists

### Tools

`Burp Turbo Intruder` · `race-the-web` · `custom scripts`

### Wordlists

Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.

| File | Entries |
|---|---:|
| `~/.local/share/hackerone-reports/wordlists/paths_race-condition.txt` | 61 |
| `~/.local/share/hackerone-reports/wordlists/params_race-condition.txt` | 36 |
| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |
| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |

```sh
W=~/.local/share/hackerone-reports/wordlists
ffuf -u https://target/FUZZ -w $W/paths_race-condition.txt \
     -mc all -fc 404 -fs 0 -rate 40
ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_race-condition.txt \
     -mr 'canary|error|invalid|not found' -rate 40
```

### Nuclei

No reliable scanner. Use Turbo Intruder single-packet or last-byte sync on check-then-act flows.

```sh
nuclei -u https://target -tags race-condition \
       -severity low,medium,high,critical -rl 40 -o nuclei_race-condition.txt
# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'
```

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

### Firing a race — two primitives (tooling-agnostic)

Winning a race needs requests that arrive in the *same* narrow window — sequential sends never
work. Use a single-packet / synchronized-send tool: **Burp Repeater** "Send group in parallel"
(HTTP/2 single-packet attack), **Turbo Intruder** (`engine=Engine.BURP2`, `gate` sync), or any
client that can flush N requests simultaneously. Two shapes:

- **Identical-copies race** — fire N IDENTICAL copies of one request at once (limit-overrun:
  double-spend a coupon/gift-card, exceed a one-per-user quota). Success = ≥2 of the N return 2xx.
- **Different-requests race (partial construction)** — fire a LIST of DIFFERENT requests in one
  synchronized window, repeated over several rounds. For register-then-confirm / TOCTOU races
  where the object exists in a usable state mid-creation. Example (email-verification bypass —
  register an arbitrary email, then confirm it through the construction window with a blank token):
  ```
  Request A:  POST /register   body: csrf=<csrf>&username=hacker&email=anything@exploit.net&password=pw
  Request B:  GET  /confirm    params: token=   (empty)
  Fire A and B together, repeat ~20 rounds.
  ```
  Get a fresh CSRF from `GET /register` first, then fire the batch. After it succeeds, log in as the
  new account and perform the objective (e.g. a state-changing admin action such as deleting a user).
  The blank-token confirm wins during the window where the user row exists but its verification
  token isn't set yet.

### Grep Patterns for Source Code Auditing

```bash
# Look for read-then-write without locking
grep -rn "find_by\|where.*first" --include="*.rb" | grep -v "lock"
grep -rn "SELECT.*WHERE" --include="*.php" | grep -v "FOR UPDATE"

# JavaScript async without atomicity
grep -rn "await.*get\|await.*find" --include="*.js" -A2 | grep "await.*update\|await.*save"

# Python Django ORM without select_for_update
grep -rn "\.get(\|\.filter(" --include="*.py" | grep -v "select_for_update"
```

## Source skills merged into this topic

- `h1skills` — `hackerone-race-condition`
- `hunting` — `race-condition`
- `cbh` — `hunt-race-condition`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `references/evidence.md` — corpus technique frequencies, parameters, case studies and payload bank
- `bbhunt-methodology` — orchestrator, state machine and class router
