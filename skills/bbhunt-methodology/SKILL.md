---
name: bbhunt-methodology
description: "Master methodology and orchestrator for authorized bug-bounty and web security hunting. Use at the START of any hunt, when switching targets, when unsure what to do next, when choosing which vulnerability-class skill to load, and when an agent is drifting into shallow or theoretical work. Routes scope to recon to surface map to one class at a time to validation to chaining to report. Grounded in all 15,259 disclosed HackerOne reports and field-tested top-hunter playbooks. Trigger words: bug bounty, hunt, security testing, authorized pentest, find vulnerabilities, where do I start, what next, methodology."
agent_created: true
---

# Bug-bounty hunt methodology (orchestrator)

This skill is the **conductor**, not another checklist. It decides *what to do next*, keeps a written state, loads exactly one class skill at a time, and refuses to let the run dissolve into unfocused probing. Every class skill is a **slice** of this methodology; this file is the whole.

**Evidence base:** all 15,259 publicly disclosed HackerOne reports in `~/.local/share/hackerone-reports/`. Every disclosed report is a valid, triaged finding. **Payment is not validity** — in most classes only 14–24% of valid reports paid a bounty; zero-bounty writeups are first-class evidence and are mined alongside paid ones. Reference playbooks: Cloudflare `security-audit-skill` (coverage ledger, independent verifier), `MrPsycho04/hackerone-skills`, `Hunting-Agent`, `Research-Skills`, `elementalsouls/Claude-BugHunter`, plus the operator's local hunt notes.

## 0. Non-negotiable contract

- **Scope is a wall.** Read the program brief before the first request. Record in scope / out of scope / known-issues / rate-limit in `scope.md`. An out-of-scope host ends that branch — it never widens it.
- **Deliverable is a reproducible defect, not an exploit.** Prove enough impact for the owner to act; go no further. No destructive testing, no data beyond what the proof needs.
- **Authorization is asserted by the operator.** If it is not explicit, stop and ask. Never probe a target "just to see".
- **Real user, no unusual actions.** The standing question: *can an attacker do this right now against a real user who took no unusual actions, and does it cause real harm?* If no → kill the lead and move on.

## 1. The state file (anti-drift mechanism)

Create one hunt folder per target. All decisions are written down; the agent re-reads it at every turn. **If context is lost, the state file is the single source of truth.**

```
hunts/<target>/
├── scope.md          # in/out, known issues, rate limits, rules of engagement
├── state.md          # CURRENT PHASE, active class, next action, decisions
├── ledger.json       # coverage units + checks + verdicts (Cloudflare style)
├── surface.md        # hosts, endpoints, params, roles, object IDs, tech stack
├── findings/         # one file per candidate, with verdict
├── evidence/         # sanitized request/response pairs, screenshots
└── notes.md          # negative results, ideas, handoff notes
```

`state.md` must always contain these four lines at the top:

```
PHASE: RECON | CLASS: none | NEXT: <one concrete action> | BLOCKED: <none|reason>
```

**Anti-drift rules**

1. Never hold the plan only in your head. Write `NEXT` before you stop a turn; read it before you start the next.
2. Work **one vulnerability class at a time**. Finish or explicitly park the current class before loading another.
3. A "maybe" is a `needs_validation` record with an exact unresolved fact — never a finding, never silently dropped.
4. Consecutive identical failures (3+) → change approach, do not increase volume. Record the failure signature in `notes.md`.
5. No path is "found" until its response differs from a recorded control. Capture the soft-404 / 403 baseline per host first.
6. If a branch produces nothing after the time box, mark the ledger unit `covered-negative` and move. Do not spiral.
7. When the operator asks "what next?", answer by reading `state.md` and `ledger.json`, then name the single next unit — never invent a new broad plan.

## 2. Phase machine

Non-linear: validation can send you back to recon, and a chain can reopen a killed primitive. But **the written phase always advances deliberately**.

| Phase | Goal | Exit artifact | Skill |
|---|---|---|---|
| 0 SCOPE | Bound the test, record rules & known issues | `scope.md` | `bbhunt-recon` |
| 1 RECON | Assets, live hosts, soft-404 control, tech, JS, API surface | `surface.md`, `ledger.json` | `bbhunt-recon` |
| 2 SELECT | Pick highest-value class for this surface | `state.md` CLASS + NEXT | this file §3 |
| 3 HUNT | Execute exactly one class playbook | candidate in `findings/` | `bbhunt-<class>` |
| 4 VALIDATE | Prove real impact or kill | verdict + exact evidence | `bbhunt-validate` |
| 5 CHAIN | Turn low primitives into ATO / RCE / data access | chain record | `bbhunt-chains` |
| 6 REPORT | Tight, reproducible, redacted submission | final report | `bbhunt-report` |

**Time boxes** (adjust to program size, never silently extend): 404/403 baseline 5 min per host; one class on one surface 20–40 min; stalled target 60 min → switch context; one recon rabbit hole 15 min → log and move.

## 3. Class router — which slice to load

Match observed **surface** to class. Load the named skill; do not load several at once.

| Observed signal | Load |
|---|---|
| Reflected/stored input, HTML/JS context, markdown, admin-visible field | `bbhunt-xss` |
| URL fetcher, webhook, image/PDF import, link preview, `url=`/`webhook=` | `bbhunt-ssrf` |
| SQL errors, `id=` numeric params, ORM/query builders, time delays | `bbhunt-sqli` |
| Object IDs, user/tenant IDs, cross-account reads or writes, export | `bbhunt-idor` / `bbhunt-authz-bypass` |
| Login, session, reset, OTP, password, account recovery | `bbhunt-auth-bypass`, `bbhunt-mfa-and-passwords`, `bbhunt-session` |
| OAuth params, `redirect_uri`, SAML, JWT, IdP flow | `bbhunt-oauth-oidc`, `bbhunt-crypto-and-secrets` |
| Shell-out, eval, template render, upload+execute, deserialization | `bbhunt-rce`, `bbhunt-ssti`, `bbhunt-deserialization` |
| File name/path/download/export params, archives | `bbhunt-path-traversal`, `bbhunt-file-upload` |
| Debug files, tokens, secrets, public buckets, verbose errors, PII | `bbhunt-info-disclosure` |
| Money, limits, coupons, workflows, state machines, multi-step flows | `bbhunt-logic-and-design` |
| Token-less state change, cross-origin form, GET side effects | `bbhunt-csrf` |
| `next=`, `return=`, `redirect_uri`, Location header | `bbhunt-open-redirect` |
| XML/SOAP/SAML upload, DOCTYPE, SVG/DOCX import | `bbhunt-xxe` |
| Proxy/CDN, duplicate Content-Length, Transfer-Encoding | `bbhunt-request-smuggling`, `bbhunt-web-cache` |
| Balance/quantity/limit check-then-act, parallel requests | `bbhunt-race-condition` |
| Header/URL reflection, CRLF, response splitting | `bbhunt-crlf-injection` |
| CNAME to unclaimed service, dangling DNS | `bbhunt-subdomain-takeover` |
| `__proto__`, `constructor.prototype`, JSON merge | `bbhunt-prototype-pollution` |
| GraphQL endpoint, introspection, mutations | `bbhunt-graphql` |
| Native app, APK/IPA, deep links, WebView | `bbhunt-mobile`, `bbhunt-memory-corruption` |
| LLM feature, agent tools, prompt/markdown output | `bbhunt-llm-ai` |
| Unbounded loops, expensive queries, cost amplifiers | `bbhunt-dos` |
| Nothing matches | `bbhunt-other` |

When two skills match (GraphQL IDOR, OAuth open redirect), load the **root-cause** class first and consult the second only for its escalation section.

## 4. Corpus precedents — do this before deep testing

For the chosen class and technology, read 3–5 real writeups. This is the highest-leverage 10 minutes in the run: it reveals what the program rewards and what others missed.

```sh
H1=~/.local/share/hackerone-reports/h1.py
python3 $H1 search "<feature or param>" --class <class> --limit 10
python3 $H1 search "<technology>" --min-upvotes 50 --limit 10
python3 $H1 show <report_id> --full
python3 $H1 stats --class <class>
```

Search by program name, framework (`rails`, `graphql`, `nextjs`), parameter (`redirect_uri`, `file`), or symptom (`verbose error`, `race`). **Do not filter to paid reports** — most valid findings pay nothing. Use bounty and upvotes only to rank which writeups to read first.

## 5. Coverage ledger (why single runs miss half the bugs)

Create `ledger.json` units from the surface map: one unit per host × feature × class that is plausibly in scope. Each unit records `checks[]`, `verdict` (`covered-positive` / `covered-negative` / `needs-validation` / `not-covered`), evidence path, and last-touched time. A repeat run should target `not-covered` and `needs-validation` units, not redo everything.

Rules borrowed from Cloudflare's harness:
- A source-grounded lead with an unresolved fact stays `needs_validation`; it is never promoted and never called "hardening".
- The agent that validates a candidate is a **fresh pass** that tries to disprove it. Same-agent confirmation is not confirmation.
- Severity requires **observed impact**, not deviation from a checklist. Defense-in-depth gaps are not vulnerabilities when another layer actually stops the attack.
- Multiple runs are additive: a single pass typically finds about half of what repeated passes find.

## 6. Top-hunter operating rules

- **Impact-first**: before testing a surface, ask "if auth broke here, what would an attacker get?" If nothing valuable → deprioritize the surface.
- **T-shaped**: deep in one class, broad awareness of all. Rotate depth, not attention.
- **Two-eye**: systematic checklist passes alternating with anomaly detection (watch for anything the app does that surprises you).
- **Understand the app as a user** before fuzzing it. Business purpose explains developer shortcuts.
- **A → B cluster hunting**: a confirmed primitive is a signal to test sibling endpoints and different bug classes nearby. One bug pays; chains pay 3–10×. See `bbhunt-chains`.
- **Prefer less-saturated classes**: business logic, race, cache, OAuth chains, CI/CD, mobile, LLM tooling. XSS/SSRF have the most competition.
- **Negative results are deliverables**: a logged, reasoned negative prevents re-work. Never erase a dead end.
- **Rate limits are part of scope**: honor requests/second across all tools, threads and agents combined.

## 7. Kill list — stop immediately

Do not write up, do not keep probing:

| Pattern | Why |
|---|---|
| Theoretical exploit with a stack of preconditions | Not reachable in reality |
| Self-XSS, self-IDOR, actions only you can trigger | No victim |
| Open redirect with no OAuth/phishing chain | No impact |
| DNS-only SSRF callback, no data or internal access | Unproven |
| Missing security header / version banner alone | Best practice, not a defect |
| Source map with no secret | No impact |
| Info already public in the web UI | Not a disclosure |
| Informational "could be abused if…" | Build the chain or drop it |
| Out-of-scope asset, even if obviously vulnerable | Scope is a wall |

## 8. Handoff / resumption

At the end of every turn, update `state.md` with `PHASE`, `CLASS`, `NEXT`, `BLOCKED`, append one line to `notes.md` (what changed, what was ruled out), and save any candidate with an explicit verdict. A new agent (or the same one after compaction) must be able to resume from these files alone.

## References

- `references/hunter-playbook.md` — top-hunter mindset, time budgets, 403/soft-404 control checks, negative-result template, and corpus evidence by class.
- `scripts/new_hunt.py` — scaffold `scope.md`, `state.md`, `ledger.json`, `surface.md`, `notes.md` for a target.

## Companion skills

`bbhunt-recon` · `bbhunt-validate` · `bbhunt-chains` · `bbhunt-report` · `bbhunt-<class>` (34 corpus-backed class slices). Load only what the current phase needs.

## Full unified skill catalog (96 skills)

Every topic below is a unified skill: all matching upstream repo skills merged and deduplicated, with full originals preserved in each skill's `references/`. Corpus-backed topics also carry mined evidence from all 15,259 disclosures.

**Orchestration & phases:** `bbhunt-methodology`, `bbhunt-recon`, `bbhunt-validate`, `bbhunt-chains`, `bbhunt-report`, `bbhunt-code-audit`, `bbhunt-dispatch`

**Corpus-backed vulnerability classes:** `bbhunt-xss`, `bbhunt-info-disclosure`, `bbhunt-rce`, `bbhunt-authz-bypass`, `bbhunt-auth-bypass`, `bbhunt-logic-and-design`, `bbhunt-idor`, `bbhunt-crypto-and-secrets`, `bbhunt-csrf`, `bbhunt-open-redirect`, `bbhunt-ssrf`, `bbhunt-sqli`, `bbhunt-path-traversal`, `bbhunt-mfa-and-passwords`, `bbhunt-clickjacking`, `bbhunt-crlf-injection`, `bbhunt-session`, `bbhunt-request-smuggling`, `bbhunt-subdomain-takeover`, `bbhunt-deserialization`, `bbhunt-dos`, `bbhunt-race-condition`, `bbhunt-account-takeover`, `bbhunt-file-upload`, `bbhunt-mobile`, `bbhunt-xxe`, `bbhunt-oauth-oidc`, `bbhunt-web-cache`, `bbhunt-prototype-pollution`, `bbhunt-graphql`, `bbhunt-ssti`, `bbhunt-llm-ai`, `bbhunt-memory-corruption`, `bbhunt-other`

**Web / API / protocol specialisms:** `bbhunt-cors`, `bbhunt-host-header`, `bbhunt-jwt-crypto`, `bbhunt-nosqli`, `bbhunt-saml`, `bbhunt-grpc`, `bbhunt-websocket`, `bbhunt-html-injection`, `bbhunt-dom`, `bbhunt-api-misconfig`, `bbhunt-shadow-api`, `bbhunt-spa-api`, `bbhunt-source-leak`, `bbhunt-js-collect`, `bbhunt-js-analyze`, `bbhunt-security-arsenal`, `bbhunt-exceptional-conditions`

**Framework / platform specialisms:** `bbhunt-nextjs`, `bbhunt-nodejs`, `bbhunt-springboot`, `bbhunt-laravel`, `bbhunt-aspnet`, `bbhunt-sharepoint`, `bbhunt-k8s`, `bbhunt-ldap`, `bbhunt-ntlm-info`, `bbhunt-tls-network`, `bbhunt-cicd`, `bbhunt-cloud-misconfig`, `bbhunt-cloud-iam-deep`, `bbhunt-supply-chain-attack-recon`, `bbhunt-fintech-graphql`, `bbhunt-rag-vector`

**Recon / red-team / reporting / other:** `bbhunt-web2-recon`, `bbhunt-recon-scope-triage`, `bbhunt-osint-methodology`, `bbhunt-offensive-osint`, `bbhunt-redteam-mindset`, `bbhunt-evidence-hygiene`, `bbhunt-exploit-completion`, `bbhunt-mid-engagement-ir-detection`, `bbhunt-bugcrowd-reporting`, `bbhunt-redteam-report-template`, `bbhunt-bb-local-toolkit`, `bbhunt-brute-force`, `bbhunt-captcha-bypass`, `bbhunt-forgot-password`, `bbhunt-apk-redteam-pipeline`, `bbhunt-ios-redteam-pipeline`, `bbhunt-okta-attack`, `bbhunt-m365-entra-attack`, `bbhunt-enterprise-vpn-attack`, `bbhunt-vmware-vcenter-attack`, `bbhunt-web3-audit`, `bbhunt-meme-coin-audit`

## Unified upstream methodology

All 6 contributing upstream skills from cbh, h1skills, hunting are merged and deduplicated in `references/unified-method.md`; full originals are preserved as `references/upstream-*.md`.
