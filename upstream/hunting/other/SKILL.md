---
name: other
description: >-
  Hunt miscellaneous vulnerability classes. Use when a finding does not fit a specific class or when exploring newer bug categories. Backed by 1,226 disclosed HackerOne reports.
---

# Other & emerging classes

1,226 disclosed reports did not fit a primary class. Use this as a discovery index: classify the root cause, then open the closest class skill.

**Reference files (load on demand):**

- `references/payloads.md` — payload banks, probes, wordlists, Nuclei templates, observed parameters
- `references/techniques.md` — quick wins, bypasses, real-report techniques, deeper checklists

## Approach

- Classify the root cause before choosing a playbook.
- Search the corpus for similar titles and technologies.
- Read the closest class skill and adapt its checklist.

## Search
```sh
python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class other
```

---

## Web-Research Methodology Additions (2026)

> Fresh-source pass: PortSwigger's Black Hat/DEF CON 2025 "HTTP/1.1 must die" research, Cloudflare Pingora CVE-2025-4366, Akamai CVE-2025-32094, Bugcrowd TE.0, and 2025-2026 emerging-vector writeups. This skill is a discovery index — these are the 2025-2026 classes most likely to arrive as "doesn't fit anywhere," each with the closest class skill to route to.

### A. Discovery checklist — concrete surfaces, inputs, configs to look for

1. **The HTTP desync family is the biggest source of "new" classes.** Evolution timeline from PortSwigger (Aug 2025): CL.TE/TE.CL (2019) → H2.CL/H2.TE (2021) → CL.0 / H2.0 / client-side desync (2022) → **TE.0** (2024, dechunking) → **TE.TE chunk extensions** (2025) → **0.CL** (2025) → **Expect-based** (2025). There are now four length interpretations in play: `CL` (Content-Length), `TE` (Transfer-Encoding), `0` (implicit zero), `H2` (HTTP/2's built-in length). HTTP/2 *downgrading* at the front-end introduces the fourth interpretation and is worse than end-to-end HTTP/1.1.
2. **Real 2025 CDN incidents to model:**
   - **Cloudflare Pingora CVE-2025-4366** — HTTP/1.1 parsing bug when caching enabled: on a cache hit the body-consumption logic was skipped, leaving unread body bytes that could be formed into a smuggled request. Exposed ~24,000,000 sites; $7,000 bounty.
   - **Akamai CVE-2025-32094** — Expect-based CL.0; 74 separate bounties totaling **$221,000**, plus $9,000 to the researcher; 65 days to fully resolve.
   - **Netlify** — CL.0 response-queue poisoning streaming other tenants' responses; **T-Mobile** 0.CL via vanilla Expect ($12,000); **GitLab** obfuscated `Expect: y 100-continue` 0.CL — 27,000 requests to capture another user's bug-bounty report video ($7,000); **LastPass** `auth.lastpass.com` CL.0 via leading-space Expect ($5,000). One research run exceeded **$350,000** in bounties.
   - **TE.0 via GCP Load Balancer** (Bugcrowd 2024) — affected thousands of Google Cloud sites including Identity-Aware Proxy; $8,500.
3. **Other 2025-2026 stragglers worth a grep:** Zimbra **CVE-2025-68645** LFI via `/h/rest?f=../../...` (CISA KEV Jan 2026 → route to `path-traversal`); elixir-mint HTTP request splitting; vishing + adversary-in-the-middle (AiTM) SSO compromise (ShinyHunters, Jan 2026 → route to `auth-bypass`/`account-takeover`); zero-click media-download chains in messaging apps (Project Zero, Jan 2026 → `memory-corruption`).
4. **Tooling to have ready:** **HTTP Request Smuggler v3.0** (Burp extension) for parser-discrepancy detection, `smuggler.py` for spray-and-pray, `http-garden` for differential HTTP server/proxy fuzzing, and Turbo Intruder with `0cl-find-offset.py` for injected-header-length discovery.
5. **Classification discipline (this skill's core job).** Write one line of root cause, then route: parser desync → `request-smuggling`; cache-served poison → `web-cache`; LLM output/tool abuse → `llm-ai`; auth state machine → `auth-bypass`; money mutation → `fintech-graphql`; native parser crash → `memory-corruption`. If none fits, keep it here WITH a reproducible PoC.

### B. Techniques & bypasses — specific actionable techniques/payload shapes

1. **Detect parser discrepancies instead of brittle payloads.** Send a partially masked Host header (`Xost: target`) and look for a response that cannot be produced by a normal Host, an omitted Host, or an arbitrary masked header:
   - **V-H** = masked header visible to front-end, hidden from back-end.
   - **H-V** = hidden from front-end, visible to back-end.
   Only the *difference* in responses matters — specific status codes are irrelevant and often misleading.
2. **V-H → CL.0 desync.** Hide Content-Length from the back-end:
   ```
   GET /style.css HTTP/1.1
   Host: target
   Foo: bar
    Content-Length: 23

   GET /404 HTTP/1.1
   X: y
   ```
   If the front-end rejects GET requests with a body, switch the method to **OPTIONS**. CL.0 is preferred over TE.CL because WAFs rarely block it.
3. **H-V on IIS behind AWS ALB.** Classic CL.TE is blocked by AWS "Desync Guardian"; Thomas Stacey bypassed it with **H2.TE**. Even with that fixed, header smuggling still enables IP spoofing and sometimes full auth bypass. Self-hosted fix: set `routing.http.drop_invalid_header_fields.enabled` and `routing.http.desync_mitigation_mode = strictest`. Lesson: adopting a cloud proxy imports another company's technical debt into your threat model.
4. **0.CL deadlock → early-response gadget.** 0.CL normally deadlocks (front-end buffers the payload, back-end waits for the body). Escape requires a gadget that makes the back-end respond before the body arrives: nginx static files, server-level redirects, or the Windows reserved-name quirk — requesting `/con` (CON/PRN/AUX/NUL/COM1…) makes IIS respond early and leave the connection open. No viable gadget was found for Apache. PortSwigger reports that suspicious "400 Bad Request" responses ("Mystery 400" in Request Smuggler) were likely 0.CL all along.
5. **0.CL → CL.0 double-desync.** Three stages: (1) a 0.CL request poisons the connection, (2) the poisoned connection weaponizes a second request into CL.0, (3) the malicious prefix poisons the victim's request. Use `0cl-find-offset.py` to learn the front-end's injected-header length — but those headers often contain the client IP, which breaks replication for triagers. Reliability trick: most servers *append* headers at the end, so start the smuggled request before them. Then apply standard CL.0 techniques (e.g. the HEAD technique to serve malicious JavaScript).
6. **Expect-based desync.** Try `Expect: 100-continue`, obfuscated `Expect: y 100-continue`, and leading-space/newline variants (`Expect:\n 100-continue`). Effects seen: 0.CL, CL.0, HEAD responses mis-parsed → upstream 504, memory fragments disclosed in a second `100 Continue` block, secret keys leaked, and **response header-removal bypass** (Expect creates a second header block, exposing internal headers like Netlify's `X-Bb-Account-Id`, `X-Nf-Cache-Key`; Netlify called this "provided by design").
7. **Response Queue Poisoning (RQP)** for low-traffic targets: queue two requests after the poison and harvest the shifted responses. Inherent race condition — GitLab needed 27,000 attempts. Prefer a redirect/XSS/desync gadget when available.
8. **Zimbra LFI shape (route to `path-traversal`):** `GET /h/rest?f=../../conf/localconfig.xml` → database credentials; `/etc/passwd`, `/proc/self/environ`, `nginx.conf`, `keystore.jks`.

### C. Validation / proof bar — how to confirm and avoid false positives (confabulation is NOT a finding for AI classes)

1. **Desync is not proven by a weird status code or a timeout.** Confirm with a deterministic oracle: a time-delay on a subsequent victim request, or a unique/victim-specific response that cannot be produced without the desync. Classic timeout-based detection is heavily fingerprinted and blocked by WAFs; prefer parser-discrepancy detection.
2. **RQP needs a specific verifiable artifact** — the GitLab case proved impact by capturing *another user's vulnerability-report video*. Random cross-user responses with no identifiable content are noise, not proof.
3. **Cache poisoning must show a poisoned response actually served to a different visitor.** The Cloudflare case was notable because the desync was internal and hijacked arbitrary third-party sites — show the cross-tenant/cross-site delivery, not just that you can inject a header.
4. **Header disclosure via Expect needs a masked internal value**, not just a version banner (banners are more compliance noise than critical; Netlify explicitly declined the banner case).
5. **Don't report theoretical protocol observations.** PortSwigger notes that findings like "this server accepts a single LF as a line terminator" are harmless for direct access and rarely pay; they become valuable only when you demonstrate exploitation behind a specific front-end.
6. **Keep the standard proof bar for out-of-class findings.** A finding with no clean class still needs a reproducible state change, an OOB callback, or a verifiable cross-user artifact. Confabulation is an AI-class concern; the protocol analogue is "the scanner said desync" — require the differential response or victim impact.
7. **Route, don't squat.** Once a finding maps cleanly to an existing class skill, hand it off with the PoC and let that skill's validation bar govern the report. This index exists to prevent misses, not to become a dumping ground.

### D. Sources — numbered list of URLs you actually fetched

1. https://portswigger.net/research/http1-must-die (Black Hat/DEF CON 2025: V-H/H-V discrepancies, CL.0, 0.CL deadlock + `/con` gadget, double-desync, Expect-based attacks, case studies, $350K+ bounties; webfetched)
2. https://blog.cloudflare.com/resolving-a-request-smuggling-vulnerability-in-pingora (Cloudflare Pingora CVE-2025-4366, cache-hit body consumption, ~24M sites)
3. https://www.securityweek.com/new-http-request-smuggling-attacks-impacted-cdns-major-orgs-millions-of-websites/ (Akamai CVE-2025-32094, T-Mobile/GitLab/Netlify bounties, $276K reported)
4. https://www.bugcrowd.com/blog/unveiling-te-0-http-request-smuggling-discovering-a-critical-vulnerability-in-thousands-of-google-cloud-websites/ (TE.0 via GCP Load Balancer, IAP bypass, $8,500)
5. https://portswigger.net/web-security/request-smuggling (request-smuggling overview and research index)
6. https://www.intigriti.com/researchers/blog/hacking-tools/top-4-new-attack-vectors-in-web-application-targets (2025-2026 emerging vectors, LLM prompt injection first among them)
