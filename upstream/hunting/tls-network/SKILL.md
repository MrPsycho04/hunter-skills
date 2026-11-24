---
name: tls-network
description: "Hunt TLS/SSL and DNS misconfigurations — missing HSTS (downgrade attack), weak cipher suites, expired/invalid certificates, mTLS bypass, missing SPF/DKIM/DMARC (email spoofing), DNS Zone Transfer (AXFR), dangling CNAME subdomain takeover, CAA records. Most of these are Info/Low on their own — this skill is opinionated about which findings actually pay (spoofable DMARC with delivered-to-inbox proof, AXFR returning internal hosts, dangling-CNAME takeover) versus which get rejected as best-practice noise (missing CAA, missing HSTS with no MitM position). Use during recon to find infrastructure weaknesses, and to TRIAGE them honestly before reporting."
---

# HUNT-TLS-NETWORK — TLS/SSL & DNS Security

**Reference files (load on demand):**

- `references/techniques.md` — quick wins, bypasses, real-report techniques, deeper checklists

## Reality Check (Read First)

Most findings in this class are **Info/Low and routinely rejected** as "best-practice" / "missing-hardening" by triage. This skill exists to stop you wasting a submission. Two questions before you report anything here:

1. **Is there a real victim and a real action?** "Missing HSTS" is not a vulnerability — *demonstrated session-cookie capture from a victim you MitM'd* is. "Missing CAA" is never a vulnerability you can demonstrate.
2. **Does the program accept it?** Many programs explicitly list missing SPF/DMARC, missing security headers, weak ciphers without exploit, and CAA as **out of scope**. Read scope first; quote the in-scope line in your report.

**What actually pays in this class (in order):**
- **Dangling-CNAME / dangling-A subdomain takeover** — you control content on `target.com` subdomain. Real impact, real bounty. (Owned in depth by `subdomain-takeover`; covered here for the TLS/DNS recon angle.)
- **Spoofable DMARC, proven by delivered-to-inbox email** — not "p=none exists" but an actual mail from `ceo@target.com` landing in a real inbox with a passing/none DMARC verdict in the headers.
- **DNS AXFR returning internal hosts** — full internal hostname/IP map. Concrete recon value, often Medium.
- **mTLS / client-cert bypass on an internal service** — reaching authenticated-only functionality without the cert. Real auth bypass = High.
- **Exploited TLS weakness with a working decrypt/MitM PoC** — almost never achievable remotely in 2024-2026 against a patched stack; see Phase 1 caveats.

**What does NOT pay (do not report standalone):** missing CAA, missing HSTS with no MitM PoC, missing security headers alone, weak-cipher *support* without an exploit, self-signed cert on a non-prod host, TLS 1.0/1.1 *enabled* without a downgrade victim.

---

## Phase 1 — TLS/SSL Audit

```bash
# Quick TLS test with testssl.sh
brew install testssl
testssl.sh --fast $TARGET 2>/dev/null | grep -E "CRITICAL|HIGH|MEDIUM|OK|NOT" | head -30

# Or use sslyze (Python)
pip3 install sslyze
python3 -m sslyze $TARGET --json_out /tmp/sslyze_$TARGET.json 2>/dev/null
cat /tmp/sslyze_$TARGET.json | python3 -m json.tool | grep -i "vulnerability\|insecure\|error" | head -20

# Check certificate expiry and chain
echo | openssl s_client -connect $TARGET:443 -servername $TARGET 2>/dev/null | \
  openssl x509 -noout -dates -subject -issuer 2>/dev/null

# Check for weak ciphers manually (a successful handshake = the cipher is OFFERED, not exploitable)
openssl s_client -connect $TARGET:443 -cipher RC4-SHA 2>/dev/null | grep -i "cipher\|handshake"
openssl s_client -connect $TARGET:443 -cipher DES-CBC3-SHA 2>/dev/null | grep -i "cipher\|handshake"

# Protocol downgrade surface — TLS 1.0/1.1 still negotiable?
openssl s_client -connect $TARGET:443 -tls1   2>/dev/null | grep -E "Protocol|Cipher"
openssl s_client -connect $TARGET:443 -tls1_1 2>/dev/null | grep -E "Protocol|Cipher"
```

**Accuracy / triage notes — do not over-claim TLS bugs:**

- **Offered ≠ exploitable.** testssl/sslyze flagging RC4, 3DES, or TLS 1.0 means the server *negotiates* it. That is a hardening finding, **not** a demonstrated decrypt. Without a PoC it is Info/Low and frequently OOS.
- **SWEET32 (CVE-2016-2183)** — 3DES birthday attack. Requires a long-lived TLS session, an on-path attacker, and ~hundreds of GB / hours of same-key traffic. Realistically un-demonstrable in a bug bounty; report only the *support* of 3DES, expect Low/Info.
- **POODLE (CVE-2014-3566)** — SSLv3 CBC padding oracle. Needs **SSLv3 actually enabled**; almost no modern stack offers it. Confirm with `testssl.sh --poodle` (or `nmap --script ssl-poodle`) — modern OpenSSL 3.x dropped the `-ssl3` flag. If SSLv3 won't negotiate, there is no POODLE.
- **FREAK (CVE-2015-0204)** and **DROWN (CVE-2016-0800)** — require export-grade RSA / a shared SSLv2 endpoint respectively. Both are pre-conditions you must *prove present*, not assume. DROWN needs SSLv2 reachable on *some* host sharing the cert/key — scan for SSLv2 with `testssl.sh --drown` (or `nmap --script sslv2-drown`) across the cert's SAN list before claiming it; modern OpenSSL has no `-ssl2` flag.
- **Heartbleed (CVE-2014-0160)** — if you genuinely find an unpatched OpenSSL 1.0.1 leaking memory, that *is* High/Critical with a real PoC (dump containing keys/cookies). Verify with `testssl.sh --heartbleed` and capture leaked bytes; this is the rare TLS bug worth a full report.

---

## Phase 2 — HSTS Check

```bash
# Check HSTS header on main domain and all subdomains
curl -sI "https://$TARGET/" | grep -i "strict-transport-security"
# Expected: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload

# Check critical subdomains (login, api, auth)
for sub in login auth api account pay www; do
  HSTS=$(curl -sI "https://$sub.$TARGET/" 2>/dev/null | grep -i "strict-transport-security")
  if [ -z "$HSTS" ]; then
    echo "[!] MISSING HSTS: https://$sub.$TARGET/"
  else
    echo "[OK] $sub.$TARGET: $HSTS"
  fi
done

# Check HTTP (non-HTTPS) redirect
curl -sI "http://$TARGET/" | grep -i "location"
# Should redirect to HTTPS immediately

# HSTS preload check
curl -s "https://hstspreload.org/api/v2/status?domain=$TARGET" | python3 -m json.tool 2>/dev/null
```

---

## Phase 3 — DNS Zone Transfer (AXFR)

```bash
# Find nameservers
dig NS $TARGET +short

# Attempt zone transfer on each nameserver
for NS in $(dig NS $TARGET +short); do
  echo "=== Trying AXFR from $NS ==="
  dig AXFR $TARGET @$NS 2>/dev/null | grep -v "^;" | head -30
done

# Zone transfer via alternative tools
host -t AXFR $TARGET $(dig NS $TARGET +short | head -1) 2>/dev/null | head -30
nmap -sn --script dns-zone-transfer $TARGET 2>/dev/null | head -30

# If AXFR succeeds → full internal hostname map
# Look for: internal IPs, staging servers, admin hostnames, CI/CD servers
```

---

## Phase 4 — Email Security (SPF/DKIM/DMARC)

```bash
# Check SPF record
dig TXT $TARGET +short | grep "v=spf1"
# Missing SPF → potential email spoofing

# Check DMARC
dig TXT _dmarc.$TARGET +short
# Missing DMARC → attacker can send as @target.com with no enforcement

# Check DKIM selectors (common: default, google, mail, k1)
for selector in default google mail k1 selector1 selector2 s1 s2 dkim; do
  RESULT=$(dig TXT $selector._domainkey.$TARGET +short 2>/dev/null)
  [ -n "$RESULT" ] && echo "DKIM selector found: $selector → $RESULT"
done

# --- Spoofability evaluation (heuristic only; PROOF is the swaks test below) ---
SPF=$(dig +short TXT $TARGET | tr -d '"' | grep -i "v=spf1")
DMARC=$(dig +short TXT _dmarc.$TARGET | tr -d '"' | grep -i "v=DMARC1")

# SPF "+all" / "all" with no qualifier = pass-everything = spoofable from any IP
echo "$SPF" | grep -Eq '[+ ]all($|[^-~?])' && echo "[CRITICAL] SPF passes all senders (+all)"
echo "$SPF" | grep -q "~all" && echo "[INFO] SPF softfail (~all) — may still deliver to inbox"
[ -z "$SPF" ] && echo "[INFO] No SPF record"

# Correct DMARC-absence check: test the variable for emptiness, do NOT pipe dig|wc -c
if [ -z "$DMARC" ]; then
  echo "[INFO] No DMARC record (no published policy)"
else
  POLICY=$(echo "$DMARC" | grep -oiE 'p=[a-z]+' | head -1)
  echo "[INFO] DMARC present: $POLICY"
  echo "$POLICY" | grep -qi "p=none" && echo "  -> p=none: monitors only, does NOT block spoofed mail"
  echo "$POLICY" | grep -qiE "p=(quarantine|reject)" && echo "  -> enforcing policy: spoofing likely blocked at receiver"
fi
```

**Why the original `dig ... | wc -c | grep '^1$'` check was broken:** empty `dig +short` output is a zero-length string; piped through `wc -c` it usually yields `0`, and the surrounding newline handling is shell-dependent, so the `^1$` match misfires both ways. Always capture into a variable and test `[ -z "$VAR" ]`.

### Spoofability is a RECEIVER decision, not a record-reading exercise

Do not report "missing DMARC = email spoofing" from `dig` output alone. DMARC `p=none` (or absent) means the **sending domain published no enforcement** — but the **receiving** mail provider (Gmail, M365, the program's own MX) may still junk or reject your spoof based on SPF, its own heuristics, or ARC. The only proof that survives triage is a **message you delivered to a real inbox**.

```bash
# PROOF: send a spoofed mail and confirm INBOX delivery (use a tester account you own)
# Use an account on the receiver the program actually uses (check their MX: dig MX $TARGET)
swaks --to your-tester@gmail.com \
      --from "CEO <ceo@$TARGET>" \
      --header "Subject: [TEST] DMARC spoof PoC for $TARGET" \
      --body "Authorized bug-bounty test. Spoofed from-domain: $TARGET" \
      --server <an-smtp-relay-you-control-or-localhost>
```

**Confirmation gate — a spoof PoC is only valid if you can show:**
1. The message landed in **Inbox** (not Spam/Junk), screenshot the folder.
2. The raw headers: `Authentication-Results:` showing `dmarc=none|fail` AND the mail was still **delivered** (not bounced). A bounce or a Spam-folder landing is NOT a finding — note it and move on.
3. The visible `From:` shows `@$TARGET` to the recipient (header-from spoof, the one that matters for phishing), not just an `envelope-from` trick.

Severity is **Medium at best**, and only if delivered-to-inbox. Many programs mark email-auth findings OOS outright — check scope first.

---

## Phase 5 — Security Headers Audit

```bash
# Check all security headers
HEADERS=$(curl -sI "https://$TARGET/")

# Check each critical header
for HEADER in "Strict-Transport-Security" "Content-Security-Policy" "X-Frame-Options" \
              "X-Content-Type-Options" "Referrer-Policy" "Permissions-Policy"; do
  RESULT=$(echo "$HEADERS" | grep -i "$HEADER")
  if [ -z "$RESULT" ]; then
    echo "[MISSING] $HEADER"
  else
    echo "[OK] $HEADER: $RESULT"
  fi
done

# Automated security headers check
curl -s "https://securityheaders.com/?q=https://$TARGET&followRedirects=on" | \
  grep -oP "grade-\K[A-F+]" | head -3
```

---

## Phase 6 — Certificate Transparency (Subdomain Discovery)

```bash
# crt.sh — certificate transparency logs
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | \
  python3 -m json.tool 2>/dev/null | grep "name_value" | \
  grep -oP '"name_value": "\K[^"]+' | \
  sed 's/\*\.//g' | sort -u > recon/$TARGET/ct-subdomains.txt

echo "[+] CT subdomains found: $(wc -l < recon/$TARGET/ct-subdomains.txt)"

# Compare with existing subdomain list
comm -23 <(sort recon/$TARGET/ct-subdomains.txt) \
         <(sort recon/$TARGET/subdomains.txt 2>/dev/null) | head -20
# New entries = recently issued certs = new services to investigate
```

---

## Phase 6.5 — Dangling Records → Subdomain Takeover (the finding that actually pays)

This is the highest-impact item in the whole skill. A CNAME/A record pointing at a deprovisioned third-party resource (S3 bucket, Azure CDN/App Service, GitHub Pages, Heroku, Fastly, etc.) lets you claim that resource and serve content from `*.target.com`. Full depth lives in `subdomain-takeover`; here is the TLS/DNS-recon entry point.

```bash
# For each subdomain from CT logs, resolve the CNAME chain and check for a live origin
while read sub; do
  CNAME=$(dig +short CNAME "$sub" | head -1)
  [ -z "$CNAME" ] && continue
  CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "https://$sub/" 2>/dev/null)
  echo "$sub -> $CNAME  [http $CODE]"
done < recon/$TARGET/ct-subdomains.txt | tee recon/$TARGET/cname-map.txt

# Flag CNAMEs that point at known takeoverable providers, then confirm the
# fingerprint string in the body (e.g. "NoSuchBucket", "There isn't a GitHub Pages site here",
# "Fastly error: unknown domain", "The specified bucket does not exist", Azure "Web App - Unavailable").
```

**Validation gate — a takeover claim requires you to actually claim it:**
1. Confirm the dangling target is **unregistered/claimable** (the S3 bucket name is free, the Heroku app does not exist, etc.) — the provider error fingerprint alone is necessary but NOT sufficient.
2. **Register the resource yourself** and serve a unique canary file, e.g. `https://$sub/<random>.txt` returning a string only you know. Screenshot it served over the victim subdomain with valid TLS.
3. Tear it down immediately after PoC; never leave attacker-controlled content live on the target's domain.

Impact: cookie scope theft (cookies set for `.target.com`), OAuth `redirect_uri`/CORS-trust abuse, phishing on a trusted origin. Typically **High** (Critical if it sits at an OAuth/SSO redirect or shares session cookies).

---

## Phase 7 — CAA Records (recon signal only — NOT a reportable finding)

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

## Chain Table

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

## Tools

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

## Validation

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

**Pre-submission scope gate:** before filing ANY item here, confirm the program does not list it as out of scope (email-auth, missing-headers, weak-TLS-without-exploit, and CAA are commonly OOS). Quote the in-scope line in your report.

## Web-Research Methodology Additions (2026)

### A. Discovery checklist — concrete places, params, headers, infra signals to look
- Anchor findings to OWASP Top 10:2025 — Security Misconfiguration rose to A02 and Cryptographic Failures is A04. Most TLS/DNS items are Info/Low alone; only report where you can show concrete spoofing, internal-topology disclosure, or a claimable resource.
- TLS surface: `testssl.sh` / `sslyze` for protocol versions, cipher suites, renegotiation, and known CVEs. A successful handshake only proves a cipher is *offered*; it is not by itself an exploitable finding. Note TLS 1.0/1.1 still negotiable, weak/deprecated ciphers, and missing forward secrecy.
- HSTS: check `Strict-Transport-Security` on the apex **and** all critical subdomains (login, api, auth, www). `max-age=31536000; includeSubDomains; preload` is the target. Check that HTTP redirects immediately to HTTPS. Missing HSTS is only meaningful with a plausible downgrade/MITM position.
- Certificate hygiene: expiry, chain completeness, hostname mismatch, wildcard scope, and CT-log new entries (crt.sh). CT can reveal recently issued certs for services not in your asset list — new subdomains to investigate.
- DNS: enumerate authoritative NS for every zone, then attempt AXFR against **every** nameserver — primaries are often hardened while secondaries are not. Try `dig axfr @<ns> <zone>`, IPv6 (`dig -6`), and verify TCP/53 reachability. A successful transfer returns internal hostnames, staging/admin/CI hosts.
- Email auth: collect SPF/DKIM/DMARC. Flag `+all` / `all` (pass-everything), DMARC `p=none` (monitor-only), and >10 DNS lookups in SPF. Check DKIM selectors `default, google, mail, k1, selector1, selector2`. Also check dangling `rua`/`ruf`, DKIM CNAMEs, MTA-STS and TLS-RPT destinations.
- CAA is recon signal only — never report missing CAA as a finding.
- Dangling records: for every CNAME/A/NS/MX, verify the target still belongs to the org. NS/lame delegation is higher impact than CNAME because it hands over the whole zone. Cross-reference the subdomain-takeover skill for provider fingerprints.

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
- Dangling CNAME claim demonstration (authorized test domains only): show that the provider returns its own "no such bucket / unknown domain / not found" fingerprint and that an account can register the same name. For NS, demonstrate authoritative control with a random TXT record you publish — only with explicit permission, since it can disrupt production DNS.

### C. Validation / proof bar — how to confirm and avoid false positives
- DMARC spoofability is a **receiver** decision. Reading `p=none` is a heuristic, not proof. Send a spoofed mail from an authorized tester account and confirm **inbox delivery** (not spam/quarantine) on a receiver the program actually uses (check MX). Otherwise do not claim spoofing.
- AXFR: a full zone transfer with internal hostnames is concrete. A `REFUSED` or empty transfer is not a finding. If only some NS are lame, control/interception may be intermittent — say so.
- A dangling CNAME is a lead until you show the provider signals the name is claimable **and** you can claim it on a test basis. Platform verification records (Azure `asuid`, GitHub Pages TXT) can block the claim — check before reporting.
- TLS: differentiate "weak cipher offered" from a downgrade attack path. Without a MITM position or a client that negotiates the weak suite, most TLS configuration issues are informational.
- HSTS: "missing HSTS" without an actionable downgrade scenario gets rejected as best-practice noise. Pair it with mixed content, cookie injection over HTTP, or an active network position.
- CT/CAA: never report CAA absence or "new cert in CT" as a standalone bug. Use them as leads for asset discovery or misissued-cert investigation.
- For any DNS record change demonstration, lower TTL first, verify propagation from multiple vantage points, and restore state afterward. Do not claim a domain or publish records for production infrastructure without written authorization.

- Verify AXFR over TCP specifically — many firewalls permit UDP/53 but block TCP/53, and a UDP-only test yields a false negative.
- Audit split-horizon DNS: query authoritative and internal resolvers separately. Internal views often leak hostnames the public view hides.
- Check `DNSKEY`/`DS`/RRSIG state when DNSSEC is enabled: a mismatched DS at the registrar makes the whole zone appear non-existent (self-inflicted DoS) — a reliability finding, not a security one.
- Enumerate PTR records for in-scope IP ranges — reverse DNS often exposes internal naming conventions and host roles.
- Check MTA-STS (`_mta-sts`) and TLS-RPT (`_tls-rpt`) TXT records and their reporting hosts; dangling report destinations create silent visibility gaps.
- HSTS: check that the `includeSubDomains` claim does not break a genuinely HTTP-only internal subdomain — an operational caveat worth noting in remediation.
- Certificate lifecycle: look for certs issued for hostnames no longer in DNS (CT -> DNS diff) — often forgotten services still reachable by IP or SNI.
- For TLS 1.0/1.1 negotiation, use a client that enforces modern policy and record exact cipher suite strings from `testssl.sh` output for the report.
- Check HSTS on the canonical redirect hop itself; a missing header on the 301 leaves a downgrade window on first contact.
- Email spoofing proof must use a tester account on an in-scope receiver: capture `Authentication-Results` and confirm `spf=pass`/`dmarc=pass` is not coming from an SPF `+all`.
- When a zone transfer returns internal hostnames, pivot each through CT/passive DNS and port scanning to find reachable staging/admin hosts — the real impact multiplier.
- Avoid reporting expired certificates alone unless a live service is still serving them; renewal failures are usually an ops ticket, not a security bug.

### D. Sources — numbered list of URLs you actually fetched
1. https://www.digicert.com/blog/dns-misconfigured
2. https://top10.owasp.org/2025/en
3. https://www.cisa.gov/news-events/alerts/2015/04/13/dns-zone-transfer-axfr-requests-may-leak-domain-information
4. https://www.cobalt.io/vulnerability-wiki/v14-config/misconfigured-dns
5. https://cyberfurl.com/research/dns-misconfiguration-report-2026
6. https://www.ionix.io/writing-center/how-to-detect-dangling-dns-and-prevent-subdomain-takeovers-in-2026
7. https://powerdmarc.com/dangling-dns-records-subdomain-takeover
