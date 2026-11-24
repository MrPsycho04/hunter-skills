---
name: bbhunt-redteam-mindset
description: "Mindset corrections that separate offensive testing from defensive assessment. Unified from 2 upstream skills (cbh, hunting). For authorized security testing only."
agent_created: true
---

# Red-team operator discipline — unified methodology

> **Unified skill.** Built from 2 upstream skills across cbh, hunting. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Unified upstream methodology (deduplicated)

### Techniques, payloads and bypasses

### Mindset correction #7 — Multi-technique cross-validation

For every "vulnerable" finding, prove via 2+ techniques:

| Vuln class | Primary | Cross-check |
|---|---|---|
| Time-based blind SQLi | SLEEP() differential | Different SLEEP variants (3 distinct payloads min) |
| Boolean blind SQLi | Body-size differential | Different boolean comparisons |
| Error-based SQLi | Error message reflection | UPDATEXML + EXTRACTVALUE both |
| RCE | Command output reflection | OOB callback (interactsh DNS) |
| LFI | File content reflection | Different file paths, different encodings |
| SSRF | Internal-only response | OOB callback (interactsh DNS) |
| Valid credential (M365) | ROPC + AADSTS53003 | SAML SSO browser flow + ConvergedConditionalAccess page |
| Auth bypass | Logged-in landing page | Session cookie persistence on subsequent request |

A single signal can be coincidence (network jitter, server hiccup, cache). Two distinct signals from the same root cause is definitive.

---

### Escalation and related chains

### "Stop at PoC" means stop ESCALATING, not stop TESTING.

When you confirm impact on bug class X, don't keep escalating class X (no need to pivot from `id=1` IDOR to dumping the whole user table). But classes Y and Z have not been tested yet. Run Y. Then Z. Then the rest of the Pattern Library.

### Related Skills & Chains

- **`recon-scope-triage`** — Before the "aggressive default, probe every live surface" directive can be applied safely, you must know which surfaces are actually the target's. Engagement flow: ASM/recon dataset received → `recon-scope-triage` clears namespace-collision noise + soft-404 false positives → only owned, verified assets enter the test queue. Skipping this wastes the engagement on other companies' assets (and risks attacking innocent third parties).
- **`spa-api`** — Operationalizes the "harvest JS bundles" cadence line into a full play: SPA JS → backend API map → unauthenticated broken-access-control testing. On a real engagement this play (not any scanner) found the apex Critical. Engagement flow: live SPA/`console`/`app`/`api` host identified → `spa-api` → test each route family unauthenticated against a gated-sibling control.
- **`dispatch`** — Once mindset is loaded, the `/hunt` command needs a mode answer (redteam vs wapt, blackbox vs greybox) before it routes to platform-specific skills. Engagement flow: red-team mindset triggered → confirm engagement mode (`bug-bounty` vs red-team vs pentest per project memory) → invoke `/hunt` → `dispatch` loads the right cluster (M365 / SharePoint / VPN / vCenter / APK).
- **`mid-engagement-ir-detection`** — Red-team mindset says "behavior changes ARE findings"; this skill operationalizes that. Engagement flow: red-team engagement underway → baseline established at session start → response patterns shift mid-test → `mid-engagement-ir-detection` captures the SOC-patch state as a NEW finding (d

### Related Skills & Chains

- **`recon-scope-triage`** — Before the "aggressive default, probe every live surface" directive can be applied safely, you must know which surfaces are actually the target's. Engagement flow: ASM/recon dataset received → `recon-scope-triage` clears namespace-collision noise + soft-404 false positives → only owned, verified assets enter the test queue. Skipping this wastes the engagement on other companies' assets (and risks attacking innocent third parties).
- **`hunt-spa-api`** — Operationalizes the "harvest JS bundles" cadence line into a full play: SPA JS → backend API map → unauthenticated broken-access-control testing. On a real engagement this play (not any scanner) found the apex Critical. Engagement flow: live SPA/`console`/`app`/`api` host identified → `hunt-spa-api` → test each route family unauthenticated against a gated-sibling control.
- **`hunt-dispatch`** — Once mindset is loaded, the `/hunt` command needs a mode answer (redteam vs wapt, blackbox vs greybox) before it routes to platform-specific skills. Engagement flow: red-team mindset triggered → confirm engagement mode (`bug-bounty` vs red-team vs pentest per project memory) → invoke `/hunt` → `hunt-dispatch` loads the right cluster (M365 / SharePoint / VPN / vCenter / APK).
- **`mid-engagement-ir-detection`** — Red-team mindset says "behavior changes ARE findings"; this skill operationalizes that. Engagement flow: red-team engagement underway → baseline established at session start → response patterns shift mid-test → `mid-engagement-ir-detection` captures the SOC-patch state

## Source skills merged into this topic

- `hunting` — `redteam-mindset`
- `cbh` — `redteam-mindset`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `bbhunt-methodology` — orchestrator, state machine and class router
