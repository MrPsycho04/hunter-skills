# Unified upstream methodology

Collected from every contributing repository skill. Deduplicated by content hash; full originals are preserved in `references/upstream-*.md`.

## Signals and surfaces

### In-scope justification

The program OOS list excludes "Rate limiting or brute-force issues on **non-authentication** endpoints." `[endpoint name]` is the canonical authentication endpoint — it accepts a password/token/OTP and returns whether it matches the user's stored credential. By definition this is an authentication primitive. The OOS clause's "non-authentication" qualifier therefore does NOT apply.
```

### In-scope justification

This is not a "debug information" finding. The [persisted-query allowlist | introspection gate | etc.] is acting as an authorization control on the [GraphQL surface | API tree | etc.]. The bypass converts that gate into a no-op — multiple [mutations | endpoints] become reachable that the official clients cannot invoke. The schema disclosure is incidental; the impact is **mutation-surface unlock**, not information leakage.
```

### In-scope justification

The program OOS list excludes "User Enumeration issues with **low-risk and insignificant** information being enumerated." The data leaked here is **neither low-risk nor insignificant**: it includes the matched user's [full real first name, last name, profile photo / SSN last 4 / phone number / etc.]. Real-[name | identity | etc.] knowledge is the same data class that gates the program's own [account-recovery flows / fraud-investigation interviews / support-call verification], which means this lookup directly defeats one of the program's own anti-fraud controls. This is PII disclosure, not handle enumeration.
```

### In-scope justification

This finding is exploitable end-to-end as demonstrated in the PoC: [one-sentence summary of the proven exploitation path]. The PoC includes [N HTTP requests with redacted cookies | N screenshots | a sanitized HAR file | etc.] showing the attacker's session [reading victim data | changing victim credentials | etc.]. The OOS clause for "theoretical issues that are not exploitable, or can not be demonstrated as exploitable" does not apply.
```

## Techniques, payloads and bypasses

### Root Cause

[Exact code snippet showing the vulnerable code with comments]

## Escalation and related chains

### Related Skills & Chains

- **`triage-validation`** — When deciding whether to write a report at all. Workflow primitive: NEVER open this skill before `triage-validation`'s 7-Question Gate passes; a finding that fails the gate should be killed, not written up.
- **`bugcrowd-reporting`** — When the target is a Bugcrowd program. Workflow primitive: this skill's body template is the foundation; `bugcrowd-reporting` overlays VRT selection, severity-request paragraph, OOS-clause rebuttals on top.
- **`evidence-hygiene`** — When PoC screenshots / HARs are being attached to the report. Workflow primitive: every artifact referenced in the "Supporting Materials" / "Proof of Concept" section gets routed through `evidence-hygiene` for cookie + PII redaction before attachment.
- **`redteam-report-template`** — When the engagement is an external red team (NOT bug bounty). Workflow primitive: confirm engagement mode via `bb-methodology` PART 0; if red-team, swap this skill out for `redteam-report-template` (different audience, different structure: Subject / Observations / Description / Impact / Recommendation / PoC).

---

### 5. Chained Findings — Cross-Reference Strategy

Many high-impact findings are chains of two or more standalone primitives (oracle + missing step-up = ATO). Bugcrowd's program rule: *"Submit one vulnerability per report. If multiple vulnerabilities must be chained to demonstrate impact, you may include them together, but please clearly explain the chain."*

### 5.1 Filing strategy for chains

1. **Identify the highest-severity chained outcome** (typically the one that maps to a P1/P2 example in the program's Focus Areas).
2. **File the chain primitives FIRST** as separate reports — each at its standalone severity (typically P3/P4). A submission's UUID only exists *after* it is filed, so the primitives must exist before anything can reference them. Leave the cross-reference line in each primitive's body as a placeholder for now.
3. **File the chain consumer** — the report whose body describes the full ATO/RCE/etc. impact at the chained severity (e.g., P1). Because the primitives already exist, fill in their real UUIDs in the consumer's "Chain partners" block (per §5.2).
4. **Edit each primitive after filing the consumer** to backfill the consumer's UUID: *"Chain partner: submission [UUID] for the full impact narrative."* (The reference is bidirectional, so one report must be edited after the other is filed — Bugcrowd allows post-submission edits to the description body.)

### Chain partners (filed as separate reports)

- **submission [UUID-1]** — [primitive 1: e.g., `me.verify_password` no rate limit]
- **submission [UUID-2]** — [primitive 2: e.g., GraphQL APQ allowlist bypass]

These primitives have independent fix surfaces and are filed separately per the program's "one fix = one bounty" rule. The chained impact described here requires both primitives to be exploited end-to-end.
```

In each primitive's body:

```markdown

### Chain context

This finding is the [N]th of [M] independent primitives that together produce [impact, e.g., "permanent account takeover from a stolen session cookie"]. The full chain narrative and the chained severity (P1) are documented in submission [UUID]. This standalone report is at P3 reflecting the primitive's individual impact.
```

### Related Skills & Chains

- **`report-writing`** — Always load this skill alongside `bugcrowd-reporting`. Workflow primitive: `report-writing` provides the body skeleton; this skill layers VRT selection + severity-request paragraph + OOS-clause rebuttals on top of that skeleton.
- **`triage-validation`** — When deciding if a Bugcrowd-bound finding will pass triage. Workflow primitive: 7Q gate runs first; only validated findings reach this skill for VRT mapping.
- **`evidence-hygiene`** — When attaching screenshots / HARs to a Bugcrowd submission. Workflow primitive: Bugcrowd's private attachment system requires redacted evidence; route everything through `evidence-hygiene` before clicking attach.
- **`security-arsenal`** — When the PoC step needs payloads cited verbatim. Workflow primitive: the "Steps to Reproduce" section in this skill's report bodies pulls exact payloads from `security-arsenal` so the triager can paste-and-run.
- **`bb-methodology`** — When confirming engagement mode is bug-bounty (not red-team). Workflow primitive: PART 0 of `bb-methodology` answers "bug bounty?"; if yes AND the target is Bugcrowd, this skill becomes the reporting overlay.

## Additional notes

### THE MOST IMPORTANT RULE

> **Never use "could potentially" or "could be used to" or "may allow".**
> Either it does the thing or it doesn't. If you haven't proved it, don't claim it.

```
BAD:  "This vulnerability could potentially allow an attacker to access user data."
GOOD: "An attacker can access any user's order history by changing the user_id
       parameter to the target user's ID. I confirmed this using two test accounts:
       attacker@test.com (ID 123) successfully retrieved victim@test.com (ID 456)
       orders, including their shipping address and payment method last 4 digits."
```

---

### TITLE FORMULA

```
[Bug Class] in [Exact Endpoint/Feature] allows [attacker role] to [impact] [victim scope]
```

**Good titles (specific, impact-first):**
```
IDOR in /api/v2/invoices/{id} allows authenticated user to read any customer's invoice data
Missing auth on POST /api/admin/users allows unauthenticated attacker to create admin accounts
Stored XSS in profile bio field executes in admin panel — allows privilege escalation
SSRF via image import URL parameter reaches AWS EC2 metadata service
Race condition in coupon redemption allows same code to be used unlimited times
```

**Bad titles (vague, useless to triager):**
```
IDOR vulnerability found
Broken access control
XSS in user input
Security issue in API
Unauthorized access to user data
```

---

### Summary

[One paragraph: what the bug is, where it is, what an attacker can do. Be specific.
Include: endpoint, method, parameter, data exposed, required access level.]

Example: "The `/api/users/{user_id}/orders` endpoint does not verify that the
authenticated user owns the requested user_id. An attacker can enumerate any
user's order history, including PII (email, address, phone) and purchase history,
by incrementing the user_id parameter. No privileges beyond a standard free
account are required."

### Vulnerability Details

**Vulnerability Type:** IDOR / Broken Object Level Authorization
**CVSS 3.1 Score:** 6.5 (Medium) — AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N
**Affected Endpoint:** GET /api/users/{user_id}/orders

### Steps to Reproduce

**Environment:**
- Attacker account: attacker@test.com, user_id = 123
- Victim account: victim@test.com, user_id = 456
- Target: https://target.com

**Steps:**

1. Log in as attacker@test.com, obtain Bearer token

2. Send the following request:

```
GET /api/users/456/orders HTTP/1.1
Host: target.com
Authorization: Bearer ATTACKER_TOKEN_HERE
```

3. Observe response:

```json
{
  "orders": [
    {"id": 789, "items": [...], "email": "victim@test.com", "address": "123 Main St..."}
  ]
}
```

The response contains victim's full order history and PII despite being requested
by a different user.

### Impact

An authenticated attacker can enumerate all user orders by iterating user_id values.
This exposes: full name, email, shipping address, purchase history, and payment
method (last 4). With ~100K users, this represents a mass PII breach affecting
all registered users. Exploitation requires only a free account and takes minutes
with a simple loop.

### Recommended Fix

Add server-side ownership verification:
```python
if order.user_id != current_user.id:
    raise Forbidden()
```

### Supporting Materials

[Screenshot showing attacker's session returning victim's order data]
[Video walkthrough if available]
```

---

### BUGCROWD REPORT TEMPLATE

```markdown
# [IDOR] User order history accessible without authorization via /api/users/{id}/orders

**VRT Category:** Broken Access Control > IDOR > P2

### Description

[Same impact-first paragraph as HackerOne summary]

### Steps to Reproduce

[Same structured steps — exact HTTP requests, exact responses]

### Proof of Concept

[Screenshot/video showing the actual impact]

### Expected vs Actual Behavior

**Expected:** 403 Forbidden when user_id does not match authenticated user
**Actual:** 200 OK with victim's full order data

### Severity Justification

P2 (High) — Direct read access to other users' PII. Affects all user accounts.
No user interaction required. Exploitable by any authenticated user.
Automated enumeration could exfil all [N] user records in minutes.

### Remediation

Add ownership verification: `if order.user_id != current_user.id: raise 403`
```

---

### INTIGRITI REPORT TEMPLATE

```markdown
# [Bug Class]: [Exact Impact] in [Endpoint/Feature]

### Description

[Impact-first paragraph. Start with what an attacker can do, not with how you found it.
Include: endpoint, method, parameter, data exposed, required privileges.]

### Steps to Reproduce

**Environment:**
- Attacker: email=attacker@test.com (standard account, no special role)
- Victim: email=victim@test.com
- Tested: [date]

**Reproduction steps:**

1. [Login as attacker / visit URL / send request]

2. Send the following HTTP request:

\```http
METHOD /endpoint HTTP/1.1
Host: target.com
Authorization: Bearer ATTACKER_TOKEN
Content-Type: application/json

{"param": "victim_id_here"}
\```

3. Observe response contains victim's private data:

\```json
{"email": "victim@test.com", "address": "123 Main St", ...}
\```

### Impact

[Specific, quantified impact. What data, how many users, what can attacker do.]

CVSS 3.1 Score: X.X ([Severity]) — AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N

### Remediation

[1-3 sentence concrete fix. Include code if helpful.]

### Attachments

[Screenshot or Loom video showing the impact — Intigriti triagers prefer video for complex bugs]
```

**Intigriti-specific notes:**
- Title format: `[Bug Class]: [One-line impact]` (no formula required, but keep it specific)
- Severity is set by you: Critical/High/Medium/Low/Exceptional
- CVSS 3.1 is standard (CVSS 4.0 also accepted on newer programs)
- PoC video is valued much more than screenshot alone — record with Loom
- Safe harbor: Intigriti enforces it, be comfortable going slightly aggressive with testing

---

### IMMUNEFI REPORT TEMPLATE

```markdown
# [Bug Class] — [Protocol Name] — [Severity]

### Summary

[One paragraph with: root cause, affected function, economic impact, attack cost.
Include numbers where possible: "attacker can drain $X in Y transactions."]

### Vulnerability Details

**Contract:** `VulnerableContract.sol`
**Function:** `claimRedemption()`
**Bug Class:** Accounting State Desynchronization
**Severity:** Critical

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
// Foundry PoC — run: forge test --match-test test_exploit -vvvv

contract ExploitTest is Test {
    // ... full working exploit
}
```

### Impact

[Quantified: "Attacker can drain X% of TVL = $Y at current rates.
Requires $Z gas. Attack is repeatable."]

### Recommended Fix

[Specific code change with before/after]
```

---

### Formula

```
CVSS = f(AV, AC, PR, UI, S, C, I, A)
```

### Metric Quick Picks

| Metric | Value | Weight | When |
|---|---|---|---|
| **Attack Vector (AV)** | Network | +0.85 | Via internet |
| | Local | +0.55 | Local access needed |
| **Attack Complexity (AC)** | Low | +0.77 | Repeatable |
| | High | +0.44 | Race/timing needed |
| **Privileges Required (PR)** | None | +0.85 | No login |
| | Low | +0.62 | Regular user account |
| | High | +0.27 | Admin account |
| **User Interaction (UI)** | None | +0.85 | No victim action |
| | Required | +0.62 | Victim must click |
| **Scope (S)** | Changed | higher | Affects browser/OS/other |
| | Unchanged | lower | Stays in app |
| **Confidentiality (C)** | High | +0.56 | All data exposed |
| | Low | +0.22 | Limited data |
| **Integrity (I)** | High | +0.56 | Can modify any data |
| **Availability (A)** | High | +0.56 | Crashes service |

### Typical Scores by Bug Class

| Bug | Typical CVSS | Severity |
|---|---|---|
| IDOR (read PII) | 6.5 | Medium |
| IDOR (write/delete) | 7.5 | High |
| Auth bypass → admin | 9.8 | Critical |
| Stored XSS (any user) | 5.4–8.8 | Med–High |
| SQLi (data exfil) | 8.6 | High |
| SSRF (cloud metadata) | 9.1 | Critical |
| Race condition (double spend) | 7.5 | High |
| GraphQL auth bypass | 8.7 | High |
| JWT none algorithm | 9.1 | Critical |

---

### Critical (P1)

- Full account takeover of any user without interaction
- Remote code execution
- SQLi with ability to dump/modify entire DB
- Auth bypass to admin panel
- SSRF to cloud metadata → IAM credentials exfil

### High (P2)

- Mass PII exposure (email, phone, SSN, payment data)
- Privilege escalation from user to admin
- SSRF reaching internal services (data returned)
- Stored XSS executing for all users of sensitive feature
- Payment bypass / financial loss without limit

### Medium (P3)

- IDOR on specific user's non-critical data
- XSS on low-sensitivity page requiring victim interaction
- CSRF on important but non-critical action
- Rate limit bypass on OTP (with effort demonstrated)

### Low (P4)

- Information disclosure (non-sensitive, no PII)
- Clickjacking on sensitive action WITH working PoC
- CORS on limited data

---

### SEVERITY SELF-ASSESSMENT

Each YES raises severity:
```
1. Exposes PII / health / financial data of other users?        → +1 severity
2. Allows account takeover or privilege escalation?             → +2 severity
3. Requires ZERO user interaction from victim?                  → +1 severity
4. Affects ALL users (not specific condition)?                  → +1 severity
5. Remotely exploitable with no internal network access?        → baseline for High+
```

---

### DOWNGRADE COUNTERS

| Program Says | Counter With |
|---|---|
| "Requires authentication" | "Attacker needs only a free account — no special role or permission" |
| "Limited impact" | "Affects [N] users / exposes [PII type] / $[amount] at risk" |
| "Already known" | "Show me the report number — I searched hacktivity and found none" |
| "By design" | "Show me the documentation stating this is intended behavior" |
| "Low CVSS" | "CVSS doesn't capture business impact — attacker can extract [X] in [Y] minutes" |
| "Not exploitable" | "Here is the exact response showing victim's data returned to attacker session" |

---

### THE 60-SECOND PRE-SUBMIT CHECKLIST

```
[ ] Title follows formula: [Class] in [endpoint] allows [actor] to [impact]
[ ] First sentence states exact impact in plain English
[ ] Steps to Reproduce has exact HTTP request (copy-paste ready)
[ ] Response showing the bug is included (screenshot or JSON body)
[ ] Two test accounts used — not just one account testing itself
[ ] CVSS score calculated and included
[ ] Recommended fix is 1-2 sentences (not a lecture)
[ ] No typos in endpoint paths or parameter names
[ ] Report is < 600 words — triagers skim long reports
[ ] Severity claimed matches impact described — don't overclaim
[ ] Never used "could potentially" or "may allow"
[ ] PoC is reproducible by triager from a fresh state
```

---

### CVSS 4.0 QUICK REFERENCE (newer programs)

CVSS 4.0 replaced CVSS 3.1 in November 2023. Some newer programs require it.

### Key Differences from CVSS 3.1

| Metric | CVSS 3.1 | CVSS 4.0 |
|---|---|---|
| Attack Vector | Network/Adjacent/Local/Physical | Same |
| Attack Complexity | Low/High | Low/High |
| **NEW**: Attack Requirements | (didn't exist) | None/Present (replaces some PR/UI) |
| Privileges Required | None/Low/High | Same |
| User Interaction | None/Required | None/Passive/Active |
| Scope | Unchanged/Changed | REMOVED |
| **NEW**: Sub-Impact metrics | (didn't exist) | Vulnerable/Subsequent system impact |

### CVSS 4.0 Score Examples

| Finding | CVSS 4.0 Score | Vector |
|---|---|---|
| Unauthenticated RCE | 10.0 | CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H |
| IDOR read PII, auth required | 6.9 | CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N |
| Stored XSS, admin views it | 8.2 | CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N |
| SSRF → cloud metadata | 8.7 | CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:H/SI:H/SA:N |

### Quick CVSS 4.0 Calculator

```
Use: https://www.first.org/cvss/calculator/4.0
Key fields:
  VC/VI/VA = Vulnerable System Confidentiality/Integrity/Availability
  SC/SI/SA = Subsequent System (downstream impact)
  AT = None (no special condition) | Present (race/specific config needed)
  UI = None | Passive (victim visits URL) | Active (victim takes explicit action)
```

**Practical rule**: If program uses CVSS 4.0 and you don't know the vector, use the calculator and include the full string starting with `CVSS:4.0/AV:...`. Programs cannot dispute a valid vector string.

---

### HUMAN TONE GUIDELINES

**Write to a person, not a system:**
- Triagers are tired. Get to the impact in sentence 1.
- Use "I" not "the researcher" — you found it, own it
- Short paragraphs, bullet points for steps
- Hyperlink relevant docs if needed

**Escalation language (when payout is being downgraded):**
```
"This vulnerability does not require any special privileges — only a free account."
"The exposed data includes [PII type], which is subject to GDPR requirements."
"An attacker can automate this with a simple loop — all [N] records in minutes."
"This is exploitable externally without network access to any internal system."
"The impact is equivalent to a full data breach of [feature/data type]."
```

**Avoid:**
- Jargon the triager might not know
- 5-paragraph explanations of what IDOR is (they know)
- Theoretical chains ("could be combined with X to...")
- Passive voice ("it was observed that...")
- Qualifying language ("seems to," "appears to")

---

### STEPS TO REPRODUCE FORMAT (triager-optimized)

```markdown
**Setup:**
- Account A (attacker): email=attacker@test.com, ID=111
- Account B (victim): email=victim@test.com, ID=222
- Both created via normal registration — no special access

**Steps:**

1. Log in as Account A
2. Send this request (replace `111` with victim ID `222`):

\```
GET /api/v2/resource/222 HTTP/1.1
Host: target.com
Authorization: Bearer ACCOUNT_A_TOKEN
\```

3. Response contains Account B's private data:

\```json
{"id": 222, "email": "victim@test.com", "name": "Victim User", "address": "..."}
\```

**Expected:** 403 Forbidden
**Actual:** 200 OK with victim's private data
```

---

### Operator Notes (Claude-BugHunter)

> Engagement-derived additions to the vendored foundation. Wisdom from real
> authorized engagements + Phase 2 verification across this repo's 31+
> skill-area live tests. The upstream methodology covers the WHAT; this
> layer covers the WHEN-IT-ACTUALLY-WORKS and the FAILURE-MODES.

### Title formula in practice

`<asset> | <bug class> | <impact>` — three components, no fluff. Triagers read titles in roughly three seconds and use them to order the queue.

- BAD: "Interesting finding on /api/users"
- BAD: "IDOR vulnerability in API"
- GOOD: "Authenticated IDOR on /api/users/{uid} -> admin email + role disclosure"
- GOOD: "Unauthenticated SSRF on /preview?url= -> AWS metadata 169.254.169.254 reachable"

The bad titles get opened last. The good titles get opened first. Same finding, different queue position, different triage day, different payout speed.

### What triagers actually read

Their reading sequence on a fresh report:

1. **Title** (3 seconds)
2. **First paragraph of impact / summary** (15 seconds)
3. **The curl command or HTTP request block** (30 seconds)
4. **Reproduction steps** (only if the first three were convincing)
5. **Everything else** (only on follow-up review)

Optimize the top of the report ruthlessly. Save narrative for the middle. Triagers who are convinced by step 3 will rubber-stamp the rest; triagers who aren't convinced by step 3 won't read step 5.

### CVSS 3.1 vs Bugcrowd VRT vs H1 default severity

These three systems disagree about 30% of the time. The most common gap: a finding that scores CVSS 7.x (High) maps to Bugcrowd P4 (Low) or H1 Medium-default. When the platform default rates lower than CVSS:

1. **File the severity-request paragraph as the first body section.** Bugcrowd respects this. (See `bugcrowd-reporting` for the canonical template.)
2. **Anchor the request in CVSS vector string + business impact, not feelings.** "CVSS 3.1 AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N = 7.5 High because Confidentiality:High applies to cross-tenant data exposure."
3. **Cite the platform's own VRT entry** that matches your finding. Don't argue against the platform; route within it.

An authorized bug-bounty engagement saw P4-default findings escalated to P3 via the severity-request paragraph. The escalation isn't automatic — you have to ask, with grounded reasoning, in the first body section.

### Evidence rotation

Everything in the submission body is logged forever by the platform. Operate accordingly:

- Use throwaway test accounts created specifically for the engagement.
- Rotate cookies / tokens after each submission (don't reuse the cookie that's pasted in the report).
- Never paste production cookies, real user emails, or real PII into the report body — redact in the PoC step.
- Screenshots of admin panels: blur the user list, blur the URL bar if it contains tokens.

Cross-link `evidence-hygiene` for the full capture-and-redact protocol.

### Templates by platform — when they differ

| Platform | Tone | Required Structure | Severity Mechanism |
|---|---|---|---|
| HackerOne | Narrative | Summary -> Steps -> Impact -> Suggested fix | Triager-set, contestable |
| Bugcrowd | Structured | Severity request -> VRT category -> Title -> Body -> Remediation | VRT-default + manual override paragraph |
| Intigriti | Between | Summary -> PoC -> Impact -> Recommendation | Researcher-proposed, triager-confirmed |
| Immunefi | PoC-first | Working PoC code -> Walkthrough -> Impact -> Severity | Foundry/Hardhat code is the primary deliverable |

Picking the wrong template style costs validity. A narrative-heavy Bugcrowd report misses the VRT mapping the triager needs; a structured H1 report reads as terse and gets follow-up questions that delay payout.

### The single biggest report-writing mistake

Claiming an attack works "in theory" or "could be chained to [bigger impact]" without demonstrating it. Triage-validation Q6 (impact beyond technically possible) kills these on the validation side; report-writing has to mirror it on the writing side.

Two valid paths:

1. **Show concrete impact end-to-end.** Capture the chain on a test account. Paste the full request/response sequence. Done.
2. **Downgrade the severity claim to match what you actually demonstrated.** "IDOR on /api/users/{uid} reading email + role" is real and reportable; "IDOR chained to potential admin takeover" is not until you demonstrate the takeover.

Pick one. Never split the difference with "could potentially" or "may allow" — those phrases are the triager's signal that the report is theoretical, and theoretical reports get N/A.
- **`bb-methodology`** — When Phase 5's report-writing step starts. Workflow primitive: Phase 5 calls `/report` which loads this skill for the platform-specific template (H1 / Bugcrowd / Intigriti / Immunefi).

### 1. VRT Category Selection — Search & Fallback Strategy

Bugcrowd's submission form requires a single VRT (Vulnerability Rating Taxonomy) selection. The dropdown's default severity is bound to the chosen node — pick wrong and the form auto-suggests a lower priority (often P4) when the actual impact is P3 or P2.

> Note: VRT default severities are not fixed constants. Bugcrowd revises the VRT schema across versions, and individual programs can remap defaults via their own priority configuration. The P-values shown in the examples below (e.g., "No Rate Limiting on Form → Login" defaulting to P4) are the typical baseline at time of writing — always read the severity the *current* form actually auto-suggests for *this* program rather than assuming the value here.

### 1.1 Search hierarchy (try in order, pick the highest-severity match that still describes the bug)

For any finding, search the VRT dropdown with these terms in this order:

1. **The bug's primary class** — e.g., `IDOR`, `XSS`, `SSRF`, `auth bypass`, `2FA bypass`
2. **The data category exposed** — e.g., `PII`, `sensitive data exposure`, `disclosure of secrets`
3. **The control bypassed** — e.g., `broken access control`, `authentication bypass`
4. **The endpoint type** — e.g., `no rate limiting on form > login`, `no rate limiting on form > change password`
5. **The generic parent node** — e.g., `Server Security Misconfiguration > Other`, `Broken Access Control > Other`

### 1.2 Pick the highest-severity match that still accurately describes the bug

Never select a VRT that misrepresents the bug just to get a higher default severity. Triagers will reassign and may flag the misrepresentation. The discipline is: pick the most specific *accurate* VRT, then use §2 (Manual Severity Override) if the default is wrong.

### 1.3 Common mappings worth knowing

| Finding type | First-choice VRT | Fallback |
|---|---|---|
| ATO via missing 2FA on password change | Broken Authentication & Session Management → Second Factor Authentication (2FA/MFA) → Bypass | Broken Auth → Authentication Bypass → Other |
| Password oracle without rate limit | Broken Authentication & Session Management → Authentication Bypass → Other | Server Security Misconfiguration → No Rate Limiting on Form → Login |
| GraphQL introspection / APQ allowlist bypass | Server Security Misconfiguration → Other (justify in body) | Broken Access Control → Other |
| Username → real name PII enumeration | Sensitive Data Exposure → PII Leakage / Disclosure of Secrets → Non-Corporate User | Broken Access Control → Other |
| State desync on security-sensitive action | Application-Level DoS → Other (with state-desync framing) | Server Security Misconfiguration → Other |
| Email/SMS pumping on auth-flow endpoint | Server Security Misconfiguration → No Rate Limiting on Form → Email-Triggering / SMS-Triggering | Server Security Misconfiguration → No Rate Limiting on Action |
| Token brute-force (email-change OTP, password reset) | Broken Authentication → Authentication Bypass → Other | Server Security Misconfiguration → No Rate Limiting on Action |

### 1.4 If no good VRT exists

Pick `Server Security Misconfiguration → Other` or `Broken Access Control → Other` and **lead the description body with a "VRT mapping note"** explaining why the chosen node is the closest available match and what the bug actually is.

---

### 2. Manual Severity Override

Bugcrowd's form lets you manually set Technical Severity *separate from the VRT default*. The form text itself states: *"A severity rating suggested by the VRT is not guaranteed to be the severity rating applied to your submission."*

### 2.1 When to override

Override the VRT default when:
- The chained outcome is a higher severity than the standalone bug class (chain → ATO)
- The VRT category is approximate and its default doesn't reflect the actual impact class
- The program's own Focus Areas explicitly list this outcome at a higher severity than VRT's default
- The data class exposed is more sensitive than the VRT's example uses (e.g., real-name PII vs. handle enumeration)

### 2.2 How to override (form mechanics)

1. Select the VRT that most accurately describes the bug (per §1)
2. Note the auto-suggested severity (P4, P3, etc.)
3. In the **Technical Severity** field, manually pick the severity you're requesting
4. Add a **Severity Request** paragraph as the FIRST section of the description body (per §3)

### 2.3 Don't over-claim

P1 inflation is the fastest way to lose triager trust. Reserve P1 for ATO without interaction, RCE, mass PII exfiltration, fund theft, and similar Critical-bucket impacts. If the chain to P1 requires a separate stolen-cookie premise, file the standalone primitive at P3 and discuss the chain explicitly with cross-references (per §4).

---

### 3. Severity-Request Paragraph — Always First in the Body

When the VRT default underrates impact, the FIRST section of the description body should be a severity-request paragraph. This is the first thing the triager reads and it pre-empts the auto-close that often happens when triagers see "P4" in the form.

### Severity request — please review carefully before applying VRT default

The closest VRT category for this finding is "[chosen VRT]," which Bugcrowd defaults to **P[N] ($X-$Y in [program]'s rubric)**. **I am requesting evaluation at P[M] [standalone | in chain with submission XXXX]** for the following reasons:

1. **[Impact axis 1]** — [specific reason this finding exceeds the VRT default's example]
2. **[Impact axis 2]** — [specific reason, often citing the program's own Focus Areas]
3. **[Impact axis 3]** — [specific reason, often comparing to historical bounty payouts for the same data class]

[Optional: one paragraph contrasting the VRT default's typical example with this finding's actual impact, e.g., "P4 = No Rate Limiting on Login Form" applies to ordinary login pages where brute force is bounded by lockout policies; this endpoint has neither lockout nor throttle.]
```

### Severity request — please review carefully before applying VRT default

The closest VRT category for this finding is "No Rate Limiting on Form → Login," which Bugcrowd defaults to **P4 ($XX–$YY in this program's rubric)**. **I am requesting evaluation at P3 standalone, P2 in chain with submission XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX** for the following reasons:

1. **[Endpoint] is a password-disclosure oracle, not a generic rate-limit gap.** The endpoint returns true/false for a supplied password — combined with cookie theft, it is the exact primitive an attacker uses to learn the victim's *durable* credential from a stolen *transient* session.
2. **The chained outcome is "Account Takeover,"** explicitly listed under the program → Focus Areas → Critical (P1) examples. This finding is one of two independent links that make that chain work; the other is submission XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX.
3. **The two findings have independent fix surfaces.** Per the program's "one fix = one bounty" rule they should be evaluated as two separate findings whose chain raises the joint severity.

The "P4 = No Rate Limiting on Login Form" default applies to ordinary login pages where brute-force is bounded by lockout policies. This endpoint has neither lockout nor throttle, and the result of brute force is the *user's actual password* (not a session) — making the impact significantly higher than the default VRT severity assumes.
```

### 3.3 Tone guidelines

- Open with *"Severity request — please review carefully before applying VRT default"* (literal phrase). Triagers recognize this and don't auto-close.
- Use **bold** sparingly; one or two phrases per reason at most.
- Never use "could potentially" or "may allow" — these are downgrade-bait.
- Cite the program's own Focus Areas / accepted-impact list by exact name.
- Cross-reference linked submissions by full submission ID (UUID format).

---

### 4. OOS-Clause Rebuttals — Templates

Bugcrowd triagers sometimes auto-close findings by mapping them to an OOS clause without reading the report. Pre-empt this by including an **In-scope justification** section that quotes the OOS clause and explains why your finding doesn't fit it.

### 4.1 "Rate limiting on non-authentication endpoints" rebuttal

When the finding is on an authentication endpoint (login, password change, password verify, OTP verify, token validate):

```markdown

### 4.2 "Debug information disclosure" rebuttal (for schema/introspection findings)

When the finding involves schema disclosure that's actually a control bypass (e.g., GraphQL allowlist bypass exposing the mutation surface):

```markdown

### 4.3 "User enumeration with low-risk information" rebuttal

When the finding leaks more than just "this handle/email exists":

```markdown

### 4.4 "Theoretical issues / not exploitable" rebuttal

When the finding's exploitability has been demonstrated end-to-end:

```markdown

### 4.5 If you don't have end-to-end proof

If you only have an "API behavior" observation without a fully demonstrated exploitation path, the finding is theoretical. Don't file it. Capture the missing evidence (delivery confirmation, token-format inspection, cross-account victim data in response, etc.) and re-evaluate. Filing theoretical findings damages researcher reputation on the platform.

---

### 5.2 Cross-reference template

In the chain consumer's body, near the top:

```markdown

### 5.3 What NOT to do

- Don't paste the entire chain narrative into every primitive's body. Cross-reference instead.
- Don't claim each primitive is independently P1 — overclaiming damages credibility for all linked reports.
- Don't ask for a single combined bounty for the chain. The program's "one fix = one bounty" rule means each independent fix surface is a separate bounty. Frame the chain as a severity-amplifier, not a merge request.

---

### 6. Target Selection — QA vs. Production

Programs that scope both production and QA assets (e.g., `app.target.com` vs. `app-qa.target.com`) require careful target selection.

### 6.1 Picking the right target dropdown entry

| If you tested... | Pick this target | Why |
|---|---|---|
| Production app/API | The production target | Most accurate; signals the impact landed on real users |
| QA app/API (per program rules for non-US researchers) | The QA target (e.g., `Sign In - (QA)`, `Enrollment - (QA)`) | Accurate per program rules; signals friendly tester |
| QA but no specific QA target exists | Closest matching production target with a clear QA disclaimer in the body | Triager will reassign correctly if needed |
| Cross-asset finding (multiple targets affected) | The asset where the bug originates / has the highest impact | Add list of other affected targets in the body |

### Notes for triagers

- Tested in the QA environment ([qa-host]) per the program's instruction for non-US researchers / per the program's QA-testing scope.
- Production may enforce additional controls that QA does not — please confirm whether the same resolver code path runs on production.
- All testing limited to my own QA test account; no other accounts were interacted with.
- Selected target: `[chosen-target]`. Selected VRT: `[chosen-VRT]`. Both selected as closest available matches; please reassign if more appropriate options exist.
```

---

### 7. Researcher-Side Hygiene (Bugcrowd-specific)

These are program-rule items that affect submission quality even though they're not part of the report body itself.

### 7.1 Account email — Bugcrowdninja alias

Most Bugcrowd-managed programs ask researchers to use their `@bugcrowdninja.com` alias as the account email on the target. This flags traffic as friendly-tester to the target's fraud team. Steps:

1. Sign up for the target using your Bugcrowd alias (looks like `username@bugcrowdninja.com`)
2. If you already have an account, update the email to the alias before testing
3. If the program offers a contact path for multi-account testing, use that to coordinate additional aliased accounts (`alias+test1@bugcrowdninja.com`, etc.)
4. Document the alias in the report's "Notes for triagers" section so the triager can correlate test traffic in their logs

### 7.2 Account-state restoration after PoC

After demonstrating any state-changing action (password change, email change, device removal, money transfer):

1. Restore the account to its pre-PoC state immediately (e.g., revert the password to what it was)
2. Document the restoration in the report — *"Account state was restored immediately after the PoC."*
3. If restoration is impossible (e.g., a sent email cannot be unsent), document the residual state honestly

### 7.3 Cookie / session rotation after submission

After submitting any report that includes session-cookie-derived evidence:

1. Log out and log back in to rotate the session cookie
2. Any cookie value visible in screenshots / HARs you submitted is now dead
3. Optionally, rotate the test-account password to a fresh value not used elsewhere — that way passwords visible in PoC screenshots are also dead

### 7.4 If the test account gets locked

1. Don't create a second account to bypass the lock — that looks like fraud
2. Email the program-specific contact (if provided) with your Bugcrowd username and the report ID
3. Wait for the program team to unblock you; testing during the lock period damages credibility

---

### 8. Submission-Order Strategy for Multi-Finding Engagements

When you have multiple findings from a single engagement, the order matters.

### 8.1 Recommended order

1. **Chain primitives before their consumer.** A consumer references the primitives' report UUIDs, which only exist once the primitives are filed (see §5.1). File the best-evidenced primitive first to lock your timestamp, then the rest of the chain's primitives.
2. **The chain consumer next** — fill in the real primitive UUIDs, then edit each primitive to backfill the consumer's UUID (Bugcrowd allows post-submission body edits).
3. **Standalone P3 findings next.** Order by quality of evidence: best-evidenced first, riskier (OOS-adjacent) findings later.
4. **OOS-risky findings last.** By the time these land, you've established a credible track record on this engagement.

### 8.2 Tracking submission IDs

Maintain a simple text file with each submission's UUID, severity, and one-line description. You'll reference these IDs across reports and during any subsequent triager dialogue.

### 8.3 What to avoid

- Don't file all findings in a single batch within minutes. Triagers see this as low-effort spam.
- Don't file an OOS-risky finding before a clean P3 from the same engagement. The clean one establishes credibility; the risky one benefits from being read in that context.
- Don't disclose any findings publicly until the program explicitly says it's OK. Bugcrowd's confidentiality applies to both unresolved AND resolved issues.

---

### 9. Pairing with Other Skills

| For this question / task | Use this skill |
|---|---|
| "Should I report this finding at all?" | `triage-validation` (7-Question Gate) |
| "What's the report body template for Bugcrowd?" | `report-writing` |
| "What VRT do I pick?" | This skill (`bugcrowd-reporting`) §1 |
| "How do I argue for higher severity?" | This skill §2-3 |
| "How do I rebut an OOS objection?" | This skill §4 |
| "How do I redact cookies / PII in screenshots?" | `evidence-hygiene` |
| "Where do I find the payload for this exploitation step?" | `security-arsenal` |
| "Where do I find recon probes for this asset class?" | `offensive-osint` |

---

### Notes on usage

This skill is small and focused. It does NOT duplicate content from `report-writing` (per-platform templates, CVSS scoring, downgrade counters, 60-second pre-submit checklist) — load both skills together when filing a Bugcrowd report. The two skills' content composes naturally because their boundaries are clean: `report-writing` is the body templates, `bugcrowd-reporting` is the program-specific tactics layered on top.

---
