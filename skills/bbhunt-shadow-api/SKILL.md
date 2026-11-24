---
name: bbhunt-shadow-api
description: "Enumerate API version history and undocumented paths, then test them for missing authentication. Unified from 2 upstream skills (cbh, hunting). For authorized security testing only."
agent_created: true
---

# Shadow and zombie API discovery — unified methodology

> **Unified skill.** Built from 2 upstream skills across cbh, hunting. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### A. Discovery checklist — concrete artifacts, endpoints, patterns, tools to look for

- **Classify before testing (OWASP API9:2023):** shadow = active but undocumented; zombie = deprecated but still reachable; orphan = no accountable owner; rogue = created outside approved architecture. Categories overlap — a route can be both shadow and orphan. CWE-1059 is the reference weakness.
- **Path-based versioning sweep:** `for v in v1 v2 v3 v4 beta alpha internal legacy old 2022-01-01 2023-01-01 2024-01-01; do curl -s -o /dev/null -w "%{http_code} /api/$v/" ...; done`. Also date-style versions (`/api/2023-01-01/`) and `/beta`, `/internal`, `/legacy` prefixes.
- **Header/subdomain versioning:** `X-API-Version: 1`, `Accept: application/vnd.company.v1+json`; subdomains `api-v1`, `api-v2`, `apiv1`, `apiv2`, `legacy-api`, `old-api`, `internal-api`, `staging-api`. Anything but 404/connection-refused (200, 401, 403) means the version is live.
- **Every reachable spec, not just the linked one:** `openapi.json`, `swagger.json`, `v1/swagger.json`, `v2/swagger.json`, `v3/api-docs`, `api-docs.json`, `swagger/v1/swagger.json`, `.well-known/openapi.json`. Diff `info.version` fields — one version implies others exist.
- **Wayback Machine (key shadow-API source):** CDX queries for `*swagger*` and `*openapi*` with `collapse=urlkey`; an old spec often remains indexed after the live link is removed.
- **Five signal sources (Safeguard/OWASP):** gateway & load-balancer logs (methods/paths receiving real traffic), route tables in source (Express routers, Flask blueprints, Spring `@RequestMapping`), 

### Techniques, payloads and bypasses

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- **Spec-to-spec diff:** `jq -r '.paths | keys[]' v1-swagger.json | sort > /tmp/v1_paths.txt`; same for v2; `comm -23 /tmp/v1_paths.txt /tmp/v2_paths.txt` = in v1 only. Confirm each against the v1 base URL; a non-404 route documented only in the old spec is a zombie candidate.
- **Behavioral diff, not shape diff:** send payloads that behave differently under old vs new logic — weaker auth, missing rate limit, lax validation, extra response fields (PII/internal IDs). Cosmetic field renames are Informational only.
- **The OWASP canonical scenario:** rate limiting implemented in a separate component in front of `api.socialnetwork...` but *not* on `beta.api.socialnetwork...` — brute-force a 6-digit reset token against the beta host. Also: old versions connected to the same production database expose admin functions or unpatched CVEs.
- **Alias check before claiming regression:** confirm the old endpoint is not simply a proxy/alias to the current implementation; send a discriminator payload that would actually behave differently under the two code paths.
- **Deprecation-message false positive:** a `200` serving only "this API version is deprecated, use v2" is not a finding — confirm the underlying operation still executes.
- **Client-app extraction:** browse with highest-privilege account, capture XHR/fetch calls, compare with the spec; for SPAs extract path-shaped strings from the bundle, including admin/internal/feature-flagged routes the UI never calls.
- **Use Nuclei/ffuf/feroxbuster** with API wor

### Validation and proof

### C. Validation / proof bar — how to confirm and avoid false positives

- **The finding is the security-relevant regression**, not the version string. Severity scale: auth/rate-limit/validation regression High; extra PII/internal fields Medium–High; behaviorally identical Informational.
- Prove the endpoint is genuinely unmanaged: no inventory entry, no owner, no gateway/WAF coverage — a documented-but-untested internal route is not automatically shadow.
- Confirm reachability from the attacker's network position and demonstrate one concrete impact (read cross-tenant data, bypass rate limit, reach admin function). Stop at PoC; do not dump production datasets.
- Check that a different status code alone is not evidence — compare bodies and successful operations with controlled accounts (admin baseline vs low-privilege vs anonymous).
- Avoid claiming "zombie" just because traffic is low or a spec says deprecated; require confirmed deprecation intent plus ongoing reachability/callability.
- Keep the internal inventory itself sensitive — it maps hosts, environments, owners, and data classification; separate public docs from the internal register.

- **Runtime-signal alerts worth mining (NHI Mgmt 2026):** traffic to routes/hosts not in the inventory, calls to deprecated versions after sunset, enumeration of `/v1`/`/beta`/`/internal`, new DNS records or certificates for API hostnames, and docs endpoints answering from outside.
- **Spec accuracy metric:** share of APIs whose live routes match their specification — a low value is the attacker's advantage; a high value is the goal 

### Escalation and related chains

### Related Skills & Chains

- **`api-misconfig`** — owns exploitation once a spec or endpoint is in hand (mass
  assignment, JWT attacks, OData, Swagger-chain attacks). This skill hands it a sharper target:
  "here's a zombie endpoint with weaker validation than the current one."
- **`subdomain-takeover`** — owns host/subdomain-level discovery (`api-v1.target.com` as its own
  host, potential takeover). This skill owns what happens once you're inside a given host's
  version surface.
- **`info-disclosure`** — JS-bundle grep for internal/undocumented calls; reused here
  specifically for version-diffing rather than secret extraction.
- **`apk-redteam-pipeline`** / **`ios-redteam-pipeline`** — mobile builds routinely hardcode an
  older API version; every mobile-sourced endpoint is a version-diff candidate.
- **`brute-force`** — a rate-limit regression found here is only a complete finding once
  chained to actual brute-forceable impact (login, OTP, enumeration).

### Related Skills & Chains

- **`hunt-api-misconfig`** — owns exploitation once a spec or endpoint is in hand (mass
  assignment, JWT attacks, OData, Swagger-chain attacks). This skill hands it a sharper target:
  "here's a zombie endpoint with weaker validation than the current one."
- **`hunt-subdomain`** — owns host/subdomain-level discovery (`api-v1.target.com` as its own
  host, potential takeover). This skill owns what happens once you're inside a given host's
  version surface.
- **`hunt-source-leak`** — JS-bundle grep for internal/undocumented calls; reused here
  specifically for version-diffing rather than secret extraction.
- **`apk-redteam-pipeline`** / **`ios-redteam-pipeline`** — mobile builds routinely hardcode an
  older API version; every mobile-sourced endpoint is a version-diff candidate.
- **`hunt-brute-force`** — a rate-limit regression found here is only a complete finding once
  chained to actual brute-forceable impact (login, OTP, enumeration).

## Source skills merged into this topic

- `hunting` — `shadow-api`
- `cbh` — `hunt-shadow-api`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `bbhunt-methodology` — orchestrator, state machine and class router
