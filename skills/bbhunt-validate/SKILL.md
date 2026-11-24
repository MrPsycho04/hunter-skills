---
name: bbhunt-validate
description: "The gate before writing any bug-bounty report: seven-question test, proof-of-impact standards, independent disproof pass, severity reasoning and kill list. Use whenever a candidate finding appears, before drafting a report, or when deciding whether a lead is real. Prevents theoretical, self-only, and best-practice findings."
agent_created: true
---

# Triage and validation

This is the gate between "I found something odd" and "this is a finding". It runs at **phase 4** of `bbhunt-methodology` and can be re-entered from any class skill.

## The seven questions

Ask all seven. One `NO` kills the candidate unless the question can be answered by one more bounded test.

1. Can an attacker trigger this **right now** with a real request against a real user?
2. Is the impact on the program's accepted impact list (or clearly in scope)?
3. Is the exact asset in scope?
4. Does it work without privileges an attacker cannot realistically obtain?
5. Is this documented/intended behaviour, a known issue, or already disclosed?
6. Can impact be **demonstrated**, not just described as theoretically possible?
7. Is it absent from the never-submit list below?

## Proof standards by claim

| Claim | Minimum proof |
|---|---|
| Cross-user data access | Two accounts; read/write of a specific other-user object with exact IDs and redacted response |
| Authentication bypass | Unauthenticated request reaching an authenticated-only function with observable state change or data |
| Account takeover | Control of another account's session/reset/email without their action; show the exact step where their action was absent |
| SSRF | OAST callback **plus** internal reachability signal (response body, status, or timing); DNS-only is not enough |
| RCE / code execution | Command output, file created in a sandbox, or callback with command-specific marker; no destructive action |
| Secret / credential leak | Demonstrate what the credential unlocks; a key string alone is not a finding |
| Open redirect | Chain to OAuth code/token theft, credential phishing on a trusted origin, or equivalent harm |
| Race / logic abuse | Reproducible sequence with timing and the resulting state delta; one lucky hit is a lead, not proof |
| DoS | Bounded, non-destructive demonstration within program rules; never sustain an attack |

## Independent disproof pass

A fresh pass must try to **disprove** the candidate:

- Re-derive the baseline. Is the "different" response actually the soft-404/edge control?
- Check whether the data was already public in the UI (incognito, unauthenticated view).
- Check changelog, docs, design notes, deployment config, or feature flags for intended behaviour.
- Check whether a different layer already blocks the attack — if so, this is hardening, not a vulnerability.
- Minimumimize the PoC to the smallest request that still proves the point. If minimization breaks it, the impact was incidental.

Record the verdict with the exact unresolved fact. `needs_validation` is allowed: one sentence naming **the single missing fact**. It is never a severity, never "mediumish".

## Severity reasoning

Severity = likelihood × demonstrated impact, in the program's context. Not a checklist score. Downgrade for: privileged prerequisites, restricted scope, requires victim to take unusual actions, no real data/money/authority affected. Upgrade for: unauthenticated, cross-tenant, repeatable at scale, financial or identity impact.

## Never-submit list

- Self-XSS, self-IDOR, actions only the attacker can trigger against themselves.
- Missing security headers, version banners, cookie flags without a demonstrated attack path.
- Open redirect with no chain.
- Blind SSRF with a callback only.
- Source maps without secrets; `.git` directories with no usable content.
- Informational "could theoretically be abused"; dead code; unreachable bugs.
- Out-of-scope assets, third-party hosted pages, or known issues listed by the program.
- Duplicate of an existing disclosure — check the corpus before submitting.

## Verdict record

```
candidate: <slug>
verdict: confirmed | needs_validation | rejected
proof: <sanitized request/response or exact observation>
impact: <real harm, quantified>
unresolved_fact: <needs_validation only>
disproof_attempts: <what was tried to break it>
severity: <only for confirmed, with reasoning>
```

## References

- `references/validation-matrix.md` — extended false-positive catalogue, severity decision guide, and corpus examples of valid-but-unpaid findings that still taught a technique.

## Unified upstream methodology

All 3 contributing upstream skills from cbh, hunting, research are merged and deduplicated in `references/unified-method.md`; full originals are preserved as `references/upstream-*.md`.
