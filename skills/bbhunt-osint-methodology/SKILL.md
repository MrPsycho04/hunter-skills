---
name: bbhunt-osint-methodology
description: "Plan and run OSINT for authorized external reconnaissance with asset graphs and time budgeting. Unified from 2 upstream skills (cbh, hunting). For authorized security testing only."
agent_created: true
---

# OSINT planning methodology — unified methodology

> **Unified skill.** Built from 2 upstream skills across cbh, hunting. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### 12. API & Auth-Map Methodology

Modern targets expose REST, GraphQL, and undocumented internal APIs. The OSINT goal is to enumerate them, classify them, and rank by attack interest.

### 24.3 Multi-Engine Corpus Run Methodology

Running a large dork corpus across multiple engines:

- **Pluggable engines** — wrap each engine (DDG, Bing, Brave, SerpAPI, Yandex, Baidu) behind a common interface. Default DDG (keyless); fall back to others when keys available.
- **Per-engine rate-limiting** — each engine has its own quota and ban posture. Use a token bucket per engine.
- **Result classification** — URL-signature → title-hint → snippet-regex pipeline. Output: `(severity, category, confidence)`.
- **Dedup by URL** — different engines surface duplicates.
- **Confidence rule** — snippet-only = TENTATIVE.
- **Persistence** — corpus DB so re-runs across engagements deduplicate.

### Signals and surfaces

### 7.5 Pipeline Priority Order (highest signal density first)

When budget is constrained, work in this order:

1. **Breaches** — infostealer logs (HudsonRock Cavalier free tier) + HIBP + DeHashed. Highest ROI for red teams; often gives valid plaintext creds for corp SSO. Requires emails as input.
2. **GitHub recon** — code-search dorks. Finds AWS keys, Slack tokens, JWT secrets, `.env` files. Fastest path to cloud pivot.
3. **Nuclei misconfig sweep** — exposed admin panels, CVEs with public POCs.
4. **Cloud buckets** — permutate company name + subdomain stems. Listable bucket = CRITICAL.
5. **Ports** — Shodan InternetDB first (free, keyless). VPN concentrators, RDP, Jenkins, GitLab-CE, Elasticsearch are the high-value pivot points.
6. **Email OSINT** — feeds breaches; feeds phishing list.
7. **Web tech / WAF / screenshots** — triage thousands of hosts; know the stack before probing.
8. **Wayback** — archived JS often has hard-coded keys; archived endpoints reveal removed admin/dev paths.
9. **DNS deep + email security** — SPF/DMARC gaps enable email spoofing; TXT verification tokens reveal SaaS tenancies.
10. **Certificates** — CT-log timeline catches forgotten subdomains; weak ciphers = cheap findings.
11. **ASN + reverse DNS** — corporate IP space hosts unadvertised infra.
12. **WHOIS** — registrant PII reveals adjacent corp assets.
13. **Typosquat** — actively-registered squats are findings; unregistered ones go on the phishing-domain shortlist.
14. **Security headers** — low standalone value but required for client reports.

### 14. Mobile Attack Surface

Mobile apps are often the weakest link.

### 15.5 Adjacent cloud signals

Extract AWS account-ID from S3 region/error responses. GCP project ID from GCS error responses. Azure tenant ID from blob URL patterns.

---

### Techniques, payloads and bypasses

### 15.3 Probe technique

- HEAD first. Status code 200/301 = exists; 403 = exists, private; 404 = skip.
- If exists, GET on bucket root. Listable XML/JSON listing → **CRITICAL**.

### 27. WAF / CDN Bypass & Origin Discovery

Web targets are increasingly behind Cloudflare / Akamai / Fastly / AWS CloudFront. The CDN itself is hard to attack; the **origin server** is often softly defended. Six techniques to find it.

### Validation and proof

### 28.3 Validation discipline

- **Validate** = run a single read-only proof (e.g., a version banner check, a static-page fetch that confirms the vulnerable component) **without** triggering exploitation.
- **Do NOT** run the actual exploit unless the rules of engagement explicitly permit. Many bug bounty programs forbid PoC execution against production.
- For client engagements: deliver the prioritized list with reproduction commands but defer actual exploitation to a follow-on assessment if needed.

### Escalation and related chains

### 9.6 Severity escalation rules

- HSTS missing on auth/login/SSO/admin path → **MED → HIGH**.
- Wildcard CORS + credentials → **MED → HIGH**.
- Wildcard CORS + sensitive endpoint → **LOW → MED**.
- API endpoint with score ≥70 on the interest rubric (companion skill §20) → at least **HIGH**.
- Domain breach severity ≥10 employees → **CRITICAL** regardless of stale-data caveats.
- Vendor product version matches CISA KEV entry → **CRITICAL**.
- DMARC `p=reject` + SPF strict + DKIM rotated → no escalation; well-postured.

---

### Related Skills & Chains

- **`offensive-osint`** — When the methodology needs to be executed with concrete probes. Workflow primitive: this skill is the planning skeleton (5-stage pipeline, asset graph, findings rubric); `offensive-osint` is the operational arsenal that fills each stage with curl one-liners, wordlists, and regexes.
- **`web2-recon`** — When asset discovery moves from planning to running. Workflow primitive: after this skill's §7 pipeline is scoped, `web2-recon` runs the subfinder → dnsx → httpx → katana commands and produces the URL set.
- **`subdomain-takeover`** — When the asset graph surfaces stale CNAMEs. Workflow primitive: §8 Asset Graph entries with CNAME pointing to S3 / GitHub Pages / Heroku / Shopify / Azure auto-route to `subdomain-takeover` for takeover validation.
- **`cloud-misconfig`** — When the asset graph surfaces exposed buckets / actuators / Firebase. Workflow primitive: §15 Cloud Attack Surface findings (open S3, /actuator/env, /firebaseio.com/.json) hand off to `cloud-misconfig` for exploitation.
- **`bb-methodology`** — When the engagement mode is bug-bounty rather than pure recon. Workflow primitive: this skill's §10 bug-bounty pivot modes are the bridge; once mode is confirmed, `bb-methodology` PART 0 + 5-phase workflow takes over.

### Related Skills & Chains

- **`offensive-osint`** — When the methodology needs to be executed with concrete probes. Workflow primitive: this skill is the planning skeleton (5-stage pipeline, asset graph, findings rubric); `offensive-osint` is the operational arsenal that fills each stage with curl one-liners, wordlists, and regexes.
- **`web2-recon`** — When asset discovery moves from planning to running. Workflow primitive: after this skill's §7 pipeline is scoped, `web2-recon` runs the subfinder → dnsx → httpx → katana commands and produces the URL set.
- **`hunt-subdomain`** — When the asset graph surfaces stale CNAMEs. Workflow primitive: §8 Asset Graph entries with CNAME pointing to S3 / GitHub Pages / Heroku / Shopify / Azure auto-route to `hunt-subdomain` for takeover validation.
- **`hunt-cloud-misconfig`** — When the asset graph surfaces exposed buckets / actuators / Firebase. Workflow primitive: §15 Cloud Attack Surface findings (open S3, /actuator/env, /firebaseio.com/.json) hand off to `hunt-cloud-misconfig` for exploitation.
- **`bb-methodology`** — When the engagement mode is bug-bounty rather than pure recon. Workflow primitive: this skill's §10 bug-bounty pivot modes are the bridge; once mode is confirmed, `bb-methodology` PART 0 + 5-phase workflow takes over.

### Tools and wordlists

### 24.1 Tools

Hunchly, Kasm Workspaces, ArchiveBox, SingleFileZ.

## Source skills merged into this topic

- `hunting` — `osint-methodology`
- `cbh` — `osint-methodology`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `references/upstream-assets/` — 3 companion files (payload/technique references, scripts, validators and schemas) from the contributing skills
- `references/unified-method.md` — includes 2 merged companion methodology documents
- `../../upstream/` — complete unmodified archives of all five source repositories
- `bbhunt-methodology` — orchestrator, state machine and class router
