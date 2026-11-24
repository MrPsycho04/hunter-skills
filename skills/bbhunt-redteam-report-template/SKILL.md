---
name: bbhunt-redteam-report-template
description: "Subject, Observations, Description, Impact, Recommendation and PoC structure for external engagements. Unified from 2 upstream skills (cbh, hunting). For authorized security testing only."
agent_created: true
---

# Client-facing red-team report template — unified methodology

> **Unified skill.** Built from 2 upstream skills across cbh, hunting. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Unified upstream methodology (deduplicated)

### Escalation and related chains

### Related Skills & Chains

- **`triage-validation`** — This template ingests findings that have ALREADY passed the 7-Question Gate. Engagement flow: every finding through `triage-validation` first → only validated findings → `redteam-report-template` packaging. Skipping triage produces a deliverable padded with informational noise that erodes client trust.
- **`evidence-hygiene`** — The DOCX with 16 embedded screenshots only works if evidence was captured systematically throughout the engagement. Engagement flow: `evidence-hygiene` discipline at session start → timestamped, organized screenshot folder → `redteam-report-template` consumes that folder to populate Evidence blocks.
- **`redteam-mindset`** — The Subject / Observations / Description / Impact / Recommendation / PoC structure assumes the operator already thinks like a red-teamer (impact-first, blast-radius framing). Engagement flow: `redteam-mindset` loaded at engagement start → findings collected with red-team framing baked in → `redteam-report-template` produces deliverable without rewriting every Impact section.
- **`mid-engagement-ir-detection`** — Defensive-action findings (SOC patches mid-test, new IPS rules deployed, account lockouts triggered by external attacker) are first-class findings in red-team deliverables. Engagement flow: `mid-engagement-ir-detection` captures behavior-change events → each becomes its own Subject in the deliverable, framed as "client capability observation" not as "bug we missed."
- **`report-writing`** + **`bugcrowd-reporting`** — Bug-bounty platform reports use DIFFERENT struct

## Source skills merged into this topic

- `hunting` — `redteam-report-template`
- `cbh` — `redteam-report-template`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `../../upstream/` — complete unmodified archives of all five source repositories
- `bbhunt-methodology` — orchestrator, state machine and class router
