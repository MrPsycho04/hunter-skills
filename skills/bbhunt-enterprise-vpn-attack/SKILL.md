---
name: bbhunt-enterprise-vpn-attack
description: "Hunt external SSL VPN and remote-access appliances across major vendors. Unified from 2 upstream skills (cbh, hunting). For authorized security testing only."
agent_created: true
---

# Enterprise VPN appliance attack matrix — unified methodology

> **Unified skill.** Built from 2 upstream skills across cbh, hunting. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### A. Discovery checklist — concrete fingerprints, endpoints, headers, CVEs, misconfigs to look for

- **Ivanti Connect Secure — the 2026 zero-day chain (CISA KEV Oct 13/30 2026).** Three CVEs chained for unauth RCE + credential theft: **CVE-2026-104935** (auth bypass by spoofing, CWE-290, CVSS 8.6, remote unauth command execution; affects ICS <25.1.3.0 / 25.1.1.1+ / 25.1.2.2+ / 22.8R2.4+; 22.7.x NOT affected), **CVE-2026-111357** (missing auth for critical function → local priv esc, CWE-306/862/345, CVSS 8.8), **CVE-2026-118527** (predictable filenames → arbitrary upload, CWE-340, CVSS 4.3). Earlier 2025 KEVs: **CVE-2025-22457** (stack overflow) and **CVE-2025-0282** (stack overflow; RESURGE malware variant undermines mitigations). **Critical detection caveat: Ivanti's Integrity Checker Tool may not detect CVE-2026-104935 exploitation — commands execute in memory; CISA requires network + memory forensics.** EoL: 22.8 on 2027-01-31.
- **Citrix NetScaler ADC/Gateway — Sept-Oct 2026 zero-day cluster.** **CVE-2026-88771** (improper input validation → unauth RCE, CVSS 9.5, no preconditions — all deployments; KEV 9/27/26), **CVE-2026-88772** (memory overflow → RCE/DoS, affects **DTLS enabled on VPN vServer** — default on; KEV 9/27/26), **CVE-2026-88773** (HTTP request smuggling via HTTP URL-based policy expression), **CVE-2026-88774** (feature policy bypass), **CVE-2026-88775/76/77** (memory overflows with gateway/AAA vServer, Oracle LB vServer, or non-HTTP L7 LB/CS/CGNAT configs), **CVE-2026-88778** (TCP ISN prediction when Enhanced ISN Generation disabled), **CVE-2026-88779**

### Techniques, payloads and bypasses

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

Chain priority for reporting: **Ivanti 104935 + 111357 + 118527** (unauth RCE → local priv esc → persistence upload) and **Citrix 88771 → 88779** (RCE → forced reboot to re-detonate injected code) are the two multi-CVE chains that turn a "patched" appliance into a con

### Validation and proof

### C. Validation / proof bar — how to confirm and avoid false positives

- **Never prove a VPN CVE by crashing or writing to the appliance.** These are critical-infrastructure devices: use version/build fingerprint + configuration precondition + (where available) non-destructive indicators. CISA's KEV entries with "forensic triage required" mean you must hunt for prior compromise (memory/network forensics, IOCs) *in addition to* checking patch state.
- **Patch-status traps:** Ivanti 22.7.x is NOT affected by 104935 but is EoL; Citrix patches for 88771-88778 do NOT cover 88779/107406; Cisco ArcaneDoor persistence survives the Sept 2025 fixed release. A "patched" banner is therefore not proof of safety — document each specific CVE applicability.
- **Configuration gates are the finding, not the CVE number:** secondary auth on a tunnel group (Cisco 76418), DTLS on VPN vServer (Citrix 88772), fabric on `allowaccess` (Fortinet 25249), pass-through modules (analogous to Okta checks). If the config is absent, downgrade to Informational.
- **Do not trust single-path 404s:** keep the existing "test 3+ CVEs per vendor" rule; vendors backport fixes without bumping version strings.
- **If a CVE is confirmed, assume breach:** CISA/Ivanti guidance is factory reset + rebuild cloud/virtual images + reissue all certs/API keys/passwords + reset domain creds twice and revoke Kerberos tickets in hybrid deployments. Capture this as a remediation note in the report; "we patched" is not containment for in-memory or FXOS-resident tradecraft.

### Escalation and related chains

### Related Skills & Chains

- **`rce`** — Every major VPN appliance (Pulse Secure, Fortinet, Citrix, Ivanti, Palo Alto) has shipped pre-auth path-traversal-to-RCE in the last 24 months. Chain primitive: VPN appliance CVE (e.g., Ivanti ICS CVE-2024-21887, Citrix Bleed CVE-2023-4966, Fortinet CVE-2024-21762) → `rce` pre-auth path traversal → arbitrary file write into web-root → request the file → web-shell as `root` → VPN config + LDAP bind credentials extracted.
- **`saml`** — VPN SAML SP misconfig persists even on fully-patched appliances. Chain primitive: appliance patched against latest CVE but `/saml/metadata` reachable → IdP fingerprinted → `saml` XSW or comment-injection against IdP → forged assertion → VPN session established without password/MFA.
- **`vmware-vcenter-attack`** — Post-VPN-foothold the natural next pivot is vCenter. Chain primitive: VPN web-shell → cred extraction from VPN appliance config (LDAP bind, RADIUS shared secret) → reuse against internal vCenter → if scope permits, `vmware-vcenter-attack` → datacenter takeover.
- **`ntlm-info`** — Some VPN appliances expose anonymous NTLM on management paths. Chain primitive: VPN admin portal NTLM Type-2 capture → `ntlm-info` AV_PAIR decode → internal AD forest name → `m365-entra-attack` Entra spray on synced tenant.
- **`mid-engagement-ir-detection`** + **`redteam-report-template`** — VPN appliance CVE exploitation is high-noise; SOC patches fast. Chain primitive: confirmed CVE → baseline capture via `mid-engagement-ir-detection` → if appliance updates mid-test, capture the patched-state as a SECOND finding 

### Related Skills & Chains

- **`hunt-rce`** — Every major VPN appliance (Pulse Secure, Fortinet, Citrix, Ivanti, Palo Alto) has shipped pre-auth path-traversal-to-RCE in the last 24 months. Chain primitive: VPN appliance CVE (e.g., Ivanti ICS CVE-2024-21887, Citrix Bleed CVE-2023-4966, Fortinet CVE-2024-21762) → `hunt-rce` pre-auth path traversal → arbitrary file write into web-root → request the file → web-shell as `root` → VPN config + LDAP bind credentials extracted.
- **`hunt-saml`** — VPN SAML SP misconfig persists even on fully-patched appliances. Chain primitive: appliance patched against latest CVE but `/saml/metadata` reachable → IdP fingerprinted → `hunt-saml` XSW or comment-injection against IdP → forged assertion → VPN session established without password/MFA.
- **`vmware-vcenter-attack`** — Post-VPN-foothold the natural next pivot is vCenter. Chain primitive: VPN web-shell → cred extraction from VPN appliance config (LDAP bind, RADIUS shared secret) → reuse against internal vCenter → if scope permits, `vmware-vcenter-attack` → datacenter takeover.
- **`hunt-ntlm-info`** — Some VPN appliances expose anonymous NTLM on management paths. Chain primitive: VPN admin portal NTLM Type-2 capture → `hunt-ntlm-info` AV_PAIR decode → internal AD forest name → `m365-entra-attack` Entra spray on synced tenant.
- **`mid-engagement-ir-detection`** + **`redteam-report-template`** — VPN appliance CVE exploitation is high-noise; SOC patches fast. Chain primitive: confirmed CVE → baseline capture via `mid-engagement-ir-detection` → if appliance updates mid-test, capture the patc

### Tools and wordlists

### Nuclei templates for fast triage

Nuclei has high-quality templates for most of the above CVEs. Single command sweeps:

```bash
nuclei -u https://target/ \
  -tags vpn,cisco-asa,fortinet,citrix,palo-alto,pulse-secure,sonicwall,f5 \
  -severity high,critical -rl 5
```

Add `-as` (auto-scan) for broader vuln coverage but slower.

---

## Source skills merged into this topic

- `hunting` — `enterprise-vpn-attack`
- `cbh` — `enterprise-vpn-attack`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `bbhunt-methodology` — orchestrator, state machine and class router
