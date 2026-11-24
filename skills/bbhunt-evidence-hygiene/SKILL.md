---
name: bbhunt-evidence-hygiene
description: "Unified methodology for evidence hygiene.. Unified from 2 upstream skills (cbh, hunting). For authorized security testing only."
agent_created: true
---

# Evidence Hygiene — unified methodology

> **Unified skill.** Built from 2 upstream skills across cbh, hunting. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Unified upstream methodology (deduplicated)

### Escalation and related chains

### Related Skills & Chains

- **`report-writing`** — When evidence is redacted and ready for the report body. Workflow primitive: after redaction passes the pre-screenshot checklist, hand off to `report-writing` for the platform-specific report template (H1 / Bugcrowd / Intigriti / Immunefi).
- **`bugcrowd-reporting`** — When the redacted evidence is destined for Bugcrowd specifically. Workflow primitive: redacted screenshots + sanitized HARs become attachments referenced in `bugcrowd-reporting`'s VRT-mapped submission body.
- **`triage-validation`** — When deciding which evidence is required at all. Workflow primitive: `triage-validation` says "you need a 5-screenshot PoC for password-change-without-step-up"; this skill says "here's how to capture and redact those 5 screenshots cleanly."
- **`security-arsenal`** — When the payload that produced the evidence is being documented. Workflow primitive: the payload (from `security-arsenal`) goes in the report verbatim; its output / response (handled by this skill) gets cookie / PII redacted before screenshotting.
- **`bb-methodology`** — When Phase 5 (Validate & Report) needs evidence captured. Workflow primitive: Phase 5's evidence-capture step routes through this skill before the report is drafted.

## Source skills merged into this topic

- `hunting` — `evidence-hygiene`
- `cbh` — `evidence-hygiene`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `bbhunt-methodology` — orchestrator, state machine and class router
