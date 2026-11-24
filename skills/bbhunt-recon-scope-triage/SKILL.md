---
name: bbhunt-recon-scope-triage
description: "Separate target-owned assets from namespace-collision noise before testing. Unified from 2 upstream skills (cbh, hunting). For authorized security testing only."
agent_created: true
---

# Recon ownership triage — unified methodology

> **Unified skill.** Built from 2 upstream skills across cbh, hunting. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Unified upstream methodology (deduplicated)

### Escalation and related chains

### Related Skills & Chains

- **`triage-validation`** — asset-ownership triage (this skill) precedes finding-validity triage (the 7-Question Gate). Ownership first, then validity.
- **`redteam-mindset`** — "aggressive default" means probe every *owned* live surface; this skill defines which surfaces are owned so persistence isn't wasted on collisions.
- **`spa-api`** — once an API host passes ownership triage, this is how you test it.
- **`offensive-osint` / `osint-methodology`** — feed ownership anchors (verified domains, tenant brand, dev accounts) from OSINT into this triage.

### Related Skills & Chains

- **`triage-validation`** — asset-ownership triage (this skill) precedes finding-validity triage (the 7-Question Gate). Ownership first, then validity.
- **`redteam-mindset`** — "aggressive default" means probe every *owned* live surface; this skill defines which surfaces are owned so persistence isn't wasted on collisions.
- **`hunt-spa-api`** — once an API host passes ownership triage, this is how you test it.
- **`offensive-osint` / `osint-methodology`** — feed ownership anchors (verified domains, tenant brand, dev accounts) from OSINT into this triage.

## Source skills merged into this topic

- `hunting` — `recon-scope-triage`
- `cbh` — `recon-scope-triage`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `bbhunt-methodology` — orchestrator, state machine and class router
