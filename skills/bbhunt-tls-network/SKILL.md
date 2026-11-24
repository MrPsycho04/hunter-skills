---
name: bbhunt-tls-network
description: "Hunt downgrade, weak ciphers, certificate issues, SPF/DKIM/DMARC gaps and AXFR. Unified from 2 upstream skills (cbh, hunting). For authorized security testing only."
agent_created: true
---

# TLS, DNS and network misconfiguration hunting — unified methodology

> **Unified skill.** Built from 2 upstream skills across cbh, hunting. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### A. Discovery checklist — concrete places, params, headers, infra signals to look

- Anchor findings to OWASP Top 10:2025 — Security Misconfiguration rose to A02 and Cryptographic Failures is A04. Most TLS/DNS items are Info/Low alone; only report where you can show concrete spoofing, internal-topology disclosure, or a claimable resource.
- TLS surface: `testssl.sh` / `sslyze` for protocol versions, cipher suites, renegotiation, and known CVEs. A successful handshake only proves a cipher is *offered*; it is not by itself an exploitable finding. Note TLS 1.0/1.1 still negotiable, weak/deprecated ciphers, and missing forward secrecy.
- HSTS: check `Strict-Transport-Security` on the apex **and** all critical subdomains (login, api, auth, www). `max-age=31536000; includeSubDomains; preload` is the target. Check that HTTP redirects immediately to HTTPS. Missing HSTS is only meaningful with a plausible downgrade/MITM position.
- Certificate hygiene: expiry, chain completeness, hostname mismatch, wildcard scope, and CT-log new entries (crt.sh). CT can reveal recently issued certs for services not in your asset list — new subdomains to investigate.
- DNS: enumerate authoritative NS for every zone, then attempt AXFR against **every** nameserver — primaries are often hardened while secondaries are not. Try `dig axfr @<ns> <zone>`, IPv6 (`dig -6`), and verify TCP/53 reachability. A successful transfer returns internal hostnames, staging/admin/CI hosts.
- Email auth: collect SPF/DKIM/DMARC. Flag `+all` / `all` (pass-everything), DMARC `p=none` (monitor-only), and >10 DNS lookups in 

### Signals and surfaces

### Phase 7 — CAA Records (recon signal only — NOT a reportable finding)

```bash
# CAA records DECLARE which CAs the domain owner permits to issue certs.
dig CAA $TARGET +short
dig CAA "*.$TARGET" +short
```

**Do NOT report "missing CAA" as a vulnerability.** This is the most common false positive in this class. Correct framing:

- A **missing CAA record does not let any attacker obtain a certificate.** It only means the owner has not *opted into* restricting which CAs may issue. With or without CAA, an attacker still needs to pass Domain Control Validation (HTTP-01 / DNS-01 / email) — which requires already controlling the domain, DNS, or web root.
- The "fraudulent issuance" scenario requires **CA compromise or social-engineering a CA** into mis-issuing. That is out of scope for essentially every bug-bounty program and is not something you can demonstrate. CAA enforcement is a CA-side control, not an attacker-facing surface.
- CAA is **Info-tier hardening at most**, and routinely closed as Won't-Fix / OOS. Mention it in a recon notes appendix if at all; never file it standalone.

**Where CAA recon IS useful (no finding, just intel):** the `issue`/`issuewild` values tell you which CA the org uses (e.g. `letsencrypt.org`, `digicert.com`, `amazon.com`). That hints at automation (ACME) and at where a *real* takeover (Phase 6.5 dangling records) could let you mint a valid cert via DCV because you'd control the host.

---

### Techniques, payloads and bypasses

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- AXFR enumeration one-liner:
  ```
  for ns in $(dig +short NS target.com); do dig @$ns axfr target.com; done
  ```
  Alternative checks: `nslookup -type=axfr`, `dig -6 @ns axfr`, and testing public anycast resolvers (`dig @1.1.1.1 axfr`) where misconfigured.
- Lame-delegation proof (read the parent-side referral, not cached child data):
  ```
  dig @<parent-ns> delegated.example.com NS +norecurse +noall +authority
  dig @<delegated-ns> delegated.example.com SOA +norecurse +noall +comments +answer +authority
  ```
  `REFUSED`, `SERVFAIL`, timeouts, or a non-authoritative answer without `aa`/`SOA` = broken delegation, but that alone does **not** prove claimability — validate provider ownership rules separately.
- SPF spoofability heuristic: `v=spf1 +all` = pass-everything; `~all`/`-all` with a proper IP list = not spoofable from arbitrary IPs. DMARC `p=none` = no enforcement; `p=quarantine`/`reject` with alignment = protected.
- DKIM selector brute force: `dig TXT <selector>._domainkey.<domain>` across a common-selector wordlist; a live key confirms signing but a dangling provider CNAME is the actual weakness.
- CT-driven discovery: query crt.sh for `%.<domain>`, diff against your known subdomains, then feed new names into CNAME/AXFR/takeover checks.
- HSTS preload nuance: inclusion in the preload list is a one-way door — removing a domain is slow. Treat "missing preload" as hardening advice, not a vulnerability.
- Dangling CNAME claim demonstration (authorized test domains only): show that the pr

### Phase 8 — mTLS Bypass Attempts

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
- Distinguish *server policy* from *ser

### Validation and proof

### Validation

Each finding ships only with the proof listed — never the `dig`/header output alone.

- **Subdomain takeover:** you registered the dangling resource and served a unique canary over `https://sub.target.com/` with valid TLS. Screenshot + canary string. (Tear down after.)
- **mTLS bypass:** spoofed client-verify header returns *privileged* data/action that the cert-required path otherwise denies. Burp request/response pair.
- **AXFR:** zone transfer returns internal hostnames/IPs from an authoritative NS. Full transcript.
- **DMARC spoof:** swaks-sent mail with `From: @target.com` **delivered to a real Inbox** (not Spam), raw `Authentication-Results` headers attached. A bounce or Spam landing = no finding.
- **HSTS missing:** only reportable with a working downgrade PoC capturing a victim cookie over plaintext — otherwise it is best-practice noise.

**Severity (conservative — matches the Chain Table):**
- Subdomain takeover (claimed): High (Critical at OAuth/SSO redirect or shared session cookie)
- mTLS bypass to authed functionality: High
- AXFR returning internal hosts: Medium
- DMARC spoof delivered-to-inbox: Medium (often OOS — verify scope)
- HSTS missing on auth (with downgrade PoC): Low–Medium; without PoC: Info
- Weak cipher support without decrypt PoC: Info–Low
- Missing security headers / missing CAA only: Info (usually do not file)

**Pre-submission scope gate:** before filing ANY item here, confirm the program does not list it as out of scope (email-auth, missing-headers, weak-TLS-without-exploit, and CAA are commonly OOS). Quote the in-scope line i

### C. Validation / proof bar — how to confirm and avoid false positives

- DMARC spoofability is a **receiver** decision. Reading `p=none` is a heuristic, not proof. Send a spoofed mail from an authorized tester account and confirm **inbox delivery** (not spam/quarantine) on a receiver the program actually uses (check MX). Otherwise do not claim spoofing.
- AXFR: a full zone transfer with internal hostnames is concrete. A `REFUSED` or empty transfer is not a finding. If only some NS are lame, control/interception may be intermittent — say so.
- A dangling CNAME is a lead until you show the provider signals the name is claimable **and** you can claim it on a test basis. Platform verification records (Azure `asuid`, GitHub Pages TXT) can block the claim — check before reporting.
- TLS: differentiate "weak cipher offered" from a downgrade attack path. Without a MITM position or a client that negotiates the weak suite, most TLS configuration issues are informational.
- HSTS: "missing HSTS" without an actionable downgrade scenario gets rejected as best-practice noise. Pair it with mixed content, cookie injection over HTTP, or an active network position.
- CT/CAA: never report CAA absence or "new cert in CT" as a standalone bug. Use them as leads for asset discovery or misissued-cert investigation.
- For any DNS record change demonstration, lower TTL first, verify propagation from multiple vantage points, and restore state afterward. Do not claim a domain or publish records for production infrastructure without written authorization.

- Verify AXFR over TCP specifically — many f

### Escalation and related chains

### Chain Table

Severities below are calibrated to what triage actually accepts. They are deliberately conservative; do not inflate them in a report.

| TLS/DNS finding | Realistic standalone severity | Notes / what raises it |
|----------------|------|------|
| Dangling-CNAME subdomain takeover (claimed + canary served) | **High** | Critical if at OAuth `redirect_uri`/SSO or sharing `.target.com` session cookies |
| mTLS / client-cert bypass reaching authed functionality | **High** | Must show privileged data/action, not just a 200 |
| AXFR returning internal hosts/IPs | **Medium** | Recon value; pairs with internal-service findings |
| Spoofable DMARC, **delivered to a real inbox** (PoC headers) | **Medium** | Often OOS — check scope; Inbox (not Spam) + delivered required. *Reading `p=none` from `dig` alone = Info, do not file* |
| Heartbleed / live memory leak with captured secrets | **High–Critical** | Only with an actual dump containing keys/cookies |
| Missing HSTS on auth subdomain | **Low / Info** | NOT High — exploitation needs an active MitM position you cannot demonstrate remotely; report only with a working downgrade-capture PoC |
| Weak cipher *support* (RC4/3DES/SWEET32) with no decrypt PoC | **Info / Low** | Hardening only; frequently OOS |
| Missing CAA | **Info (do not file)** | Absence does not enable issuance; not attacker-demonstrable |

---

### Tools and wordlists

### Tools

```bash
# testssl.sh — comprehensive TLS audit
brew install testssl
testssl.sh $TARGET

# sslyze — Python TLS scanner
pip3 install sslyze

# MXToolbox for email security
curl -s "https://mxtoolbox.com/api/v1/Lookup/spf?argument=$TARGET" 2>/dev/null

# dmarc-inspector
curl -s "https://dmarcian.com/dmarc-inspector/?domain=$TARGET" 2>/dev/null
```

---

## Source skills merged into this topic

- `hunting` — `tls-network`
- `cbh` — `hunt-tls-network`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `bbhunt-methodology` — orchestrator, state machine and class router
