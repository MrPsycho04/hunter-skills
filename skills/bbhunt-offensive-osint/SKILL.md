---
name: bbhunt-offensive-osint
description: "Probe/regex/dork arsenal for authorized external reconnaissance. Unified from 2 upstream skills (cbh, hunting). For authorized security testing only."
agent_created: true
---

# Offensive OSINT arsenal — unified methodology

> **Unified skill.** Built from 2 upstream skills across cbh, hunting. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Unified upstream methodology (deduplicated)

### Escalation and related chains

### Related Skills & Chains

- **`web2-recon`** — When the arsenal needs to be executed against a live host set. Workflow primitive: this skill provides the probe paths and wordlists; `web2-recon` runs the actual subfinder → dnsx → httpx → katana pipeline that consumes them.
- **`osint-methodology`** — When this skill's concrete probes need a planning framework. Workflow primitive: `osint-methodology` is the planning skeleton (5-stage pipeline, asset graph, findings rubric); this skill is the operational arsenal that fills each stage with curl one-liners and regexes.
- **`subdomain-takeover`** — When this skill's subdomain enumeration finds stale CNAMEs. Workflow primitive: subdomains discovered via §27 / `references/recon-stack.md` get auto-routed to `subdomain-takeover` for takeover validation.
- **`cloud-misconfig`** — When this skill's cloud-bucket enum surfaces listable buckets / Firebase / actuator endpoints. Workflow primitive: §39 attack-path hints (listable bucket, /actuator/env, open Elasticsearch) hand off to `cloud-misconfig` for exploitation.
- **`m365-entra-attack`** / **`okta-attack`** — When identity-fabric fingerprinting finds Entra/Okta. Workflow primitive: `references/identity-fabric.md` fingerprints the IdP; matched platform skill (loaded by `dispatch`) takes over for active enumeration.

### Related Skills & Chains

- **`web2-recon`** — When the arsenal needs to be executed against a live host set. Workflow primitive: this skill provides the probe paths and wordlists; `web2-recon` runs the actual subfinder → dnsx → httpx → katana pipeline that consumes them.
- **`osint-methodology`** — When this skill's concrete probes need a planning framework. Workflow primitive: `osint-methodology` is the planning skeleton (5-stage pipeline, asset graph, findings rubric); this skill is the operational arsenal that fills each stage with curl one-liners and regexes.
- **`hunt-subdomain`** — When this skill's subdomain enumeration finds stale CNAMEs. Workflow primitive: subdomains discovered via §27 / `references/recon-stack.md` get auto-routed to `hunt-subdomain` for takeover validation.
- **`hunt-cloud-misconfig`** — When this skill's cloud-bucket enum surfaces listable buckets / Firebase / actuator endpoints. Workflow primitive: §39 attack-path hints (listable bucket, /actuator/env, open Elasticsearch) hand off to `hunt-cloud-misconfig` for exploitation.
- **`m365-entra-attack`** / **`okta-attack`** — When identity-fabric fingerprinting finds Entra/Okta. Workflow primitive: `references/identity-fabric.md` fingerprints the IdP; matched platform skill (loaded by `hunt-dispatch`) takes over for active enumeration.

### Tools and wordlists

### 6. General OSINT (curated tool refs)

- [OSINT Bookmarks](https://tools.myosint.training/) — comprehensive bookmarks.
- [OSINT Framework](https://osintframework.com/) — tool/resource directory.
- [IntelTechniques Tools](https://inteltechniques.com/tools/) — investigative suite.
- [Bellingcat Toolkit](https://www.bellingcat.com/resources/2024/09/24/bellingcat-online-investigations-toolkit/) — investigative journalism.
- [CyberSudo OSINT Toolkit](https://docs.google.com/spreadsheets/d/1EC0sKA_W9znzsxUt0wye9UYtyATXw5m8) — OSINT websites list.
- [Google Dorks](https://dorksearch.com/) — efficient Google searching.
- [Distributed Denial of Secrets](https://ddosecrets.com/) — leaked datasets.
- [Country-Specific Resources](https://digitaldigging.org/osint/) — country-targeted OSINT.


---

## Source skills merged into this topic

- `hunting` — `offensive-osint`
- `cbh` — `offensive-osint`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `bbhunt-methodology` — orchestrator, state machine and class router
