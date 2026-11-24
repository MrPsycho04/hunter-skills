---
name: bbhunt-vmware-vcenter-attack
description: "Hunt version-specific exploit chains across vCenter, Workspace ONE and Aria. Unified from 2 upstream skills (cbh, hunting). For authorized security testing only."
agent_created: true
---

# VMware vSphere and vCenter attack chain — unified methodology

> **Unified skill.** Built from 2 upstream skills across cbh, hunting. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### A. Discovery checklist — concrete fingerprints, endpoints, headers, CVEs, misconfigs to look for

- **2024-2026 KEV additions to the CVE matrix above (check every external vCenter against these):**
  - **CVE-2024-37079 / CVE-2024-37080** — DCERPC heap-overflow → RCE, CVSS 9.8 (VMSA-2024-0012); Broadcom confirmed in-the-wild exploitation; **CISA KEV added 2026-01-23** (due 2026-02-13). Affects vCenter 8.0 < 8.0 U2d/U1e, 7.0 < 7.0 U3r, VCF 4.x/5.x. This is the direct successor to CVE-2023-34048 on the same DCE/RPC attack surface.
  - **CVE-2025-22224 / 22225 / 22226** — ESXi/Workstation/Fusion 0-day chain (VMSA-2025-0004, Mar 2025): TOCTOU → OOB write → code as VMX (9.3), arbitrary kernel write → sandbox escape (8.2, **ransomware-known in KEV**), HGFS OOB read → memory leak (7.1). Requires local admin *inside a VM* — a post-foothold finding, not pre-auth network RCE; don't overstate it as external.
  - **CVE-2025-41244** — Aria Operations + VMware Tools local privilege escalation via unsafe privilege actions (KEV 2025-10-30).
  - **CVE-2026-59309 + CVE-2026-59310** — VMSA-2026-0006 (Jul 29 2026): vCenter Directory Service **auth bypass** (9.8) and **Syslog server directory traversal → unauth RCE** (9.8), no workarounds. **KEV 2026-08-18, flagged known-ransomware-use, 3-day federal deadline.** QUIRSO counted **361 victim IPs in 47 countries**, first exploitation 5 days after disclosure; attackers deployed the `reverse_ssh` framework for outbound C2. Fixed builds: 9.1.0.0300, 9.0.2.0100, 8.0 U3k / 8.0 U2f express patch.
  - **CVE-2026-123890** — vCenter Directory Service **

### Techniques, payloads and bypasses

### 5. CVE-2022-22972 — Workspace ONE Access / Identity Manager / vRealize Automation Host-header authentication bypass

- **Affected:** Workspace ONE Access 21.08.0.1; Identity Manager 3.3.3–3.3.6; vRealize Automation 7.6 (and downstream Cloud Foundation bundles).
- **Attack flow:** Manipulate the HTTP `Host` header during local-domain login flow; the server routes its internal validation request to the attacker-controlled hostname → returns admin session without legitimate credentials.
- **Root cause:** Host header used unvalidated as the target for the internal auth-validation request — classic SSRF-into-self with trust elevation.
- **Disclosure:** Reported by Bruno López of Innotec Security; VMware advisory VMSA-2022-0014 published 2022-05-18. **CISA Emergency Directive 22-03** (2022-05-18) ordered all U.S. federal civilian agencies to patch or remove affected VMware installations by 2022-05-24 — the same agencies that had just been told the same thing for CVE-2022-22954 six weeks earlier. Year discovered 2022, patched 2022.
- **References:** https://www.vmware.com/security/advisories/VMSA-2022-0014.html ; https://www.cisa.gov/news-events/directives/ed-22-03-mitigate-vmware-vulnerabilities ; https://www.rapid7.com/blog/post/2022/05/19/cve-2022-22972-critical-authentication-bypass-in-vmware-workspace-one-access-identity-manager-and-vrealize-automation/ ; https://www.assetnote.io/resources/research/understanding-cve-2022-22972-vmware-workspace-one-access-auth-bypass

### 8. CVE-2024-37085 — ESXi Active Directory integration "ESX Admins" auth bypass (ransomware-favorite)

- **Affected:** ESXi 7.0 < ESXi70U3q-24585291, ESXi 8.0 < ESXi80U3-24022510; vCenter-managed clusters where ESXi is joined to AD.
- **Attack flow:** Attacker with sufficient AD rights creates (or re-creates after deletion) a group literally named `ESX Admins` and adds an account. ESXi auto-grants every member full admin rights without checking that the group existed at join time. End-to-end: AD foothold → group create → SSH/API root on every domain-joined ESXi host → mass VM encryption.
- **Root cause:** Hard-coded trust of group name `ESX Admins` with no domain-scoped identity validation.
- **Disclosure:** Reported by Microsoft Threat Intelligence; advisory VMSA-2024-0013 published 2024-06-25. **Microsoft Security Blog** documents pre-patch exploitation by **Storm-0506 (Black Basta), Storm-1175, Octo Tempest, and Manatee Tempest** ransomware operators — including a confirmed Black Basta deployment at a North American engineering firm. **CISA KEV:** added 2024-07-30. Year discovered 2024 (exploited as 0-day), patched 2024.
- **References:** https://www.vmware.com/security/advisories/VMSA-2024-0013.html ; https://www.microsoft.com/en-us/security/blog/2024/07/29/ransomware-operators-exploit-esxi-hypervisor-vulnerability-for-mass-encryption/ ; https://www.rapid7.com/blog/post/2024/07/30/vmware-esxi-cve-2024-37085-targeted-in-ransomware-campaigns/ ; https://thehackernews.com/2024/07/vmware-esxi-flaw-exploited-by.html

### Bonus: CVE-2022-31656 — Workspace ONE Access / Identity Manager / vRealize Automation auth bypass (post-22972 follow-up)

- **Affected:** Same product matrix as 22954/22972. Workspace ONE Access 21.08.x; Identity Manager 3.3.3–3.3.6; vRealize Automation 7.6.
- **Attack flow:** Network-only actor obtains admin without authenticating; chained with CVE-2022-31659 (auth'd RCE) the pair yields pre-auth admin RCE — the spiritual successor to the 22954+22972 pair.
- **Root cause:** Local-domain auth flow trusted a parameter that could be supplied without prior auth.
- **Disclosure:** Reported by **PetrusViet** of VNG Security; advisory VMSA-2022-0021 published 2022-08-02. PetrusViet released chain writeup + PoC. Year 2022.
- **References:** https://www.vmware.com/security/advisories/VMSA-2022-0021.html ; https://www.greynoise.io/blog/vmware-workspace-one-vulnerabilities-cve-2022-31656-and-cve-2022-31659 ; https://attackerkb.com/topics/RuMGC8Q1pE/cve-2022-31656

---

### B. Techniques & bypasses — specific actionable techniques/payload shapes

```bash
TARGET=vcenter.target.com
# Build fingerprint (do this BEFORE any CVE-specific probe)
curl -sk "https://$TARGET/sdk/vimServiceVersions.xml" | head -20
curl -sk "https://$TARGET/api/appliance/system/version" | jq .
curl -sk "https://$TARGET/ui/login" | grep -oE 'build[^"]{0,40}|[0-9]\.[0-9]\.[0-9]\.[0-9]{5,}'
echo | openssl s_client -connect "$TARGET:443" -servername "$TARGET" 2>/dev/null \
  | openssl x509 -noout -text | grep -A1 "Subject Alt"

# Detection-only reachability checks for the 2026 pair (NO exploit payloads)
curl -sk -o /dev/null -w "syslog traversal endpoint: %{http_code}\n" \
  "https://$TARGET/websso/SAML2/Metadata/vsphere.local"   # if 200, SP metadata is public intel
nc -zv "$TARGET" 2012 && echo "DCE/RPC port 2012 reachable — CVE-2026-123890 precondition"
# Compare observed build against fixed builds listed in section A; anything older = candidate.

# Post-auth: existing MOB/REST enumeration + datastore credential hunt still applies:
curl -sk -H "vmware-api-session-id: $TOKEN" "https://$TARGET/folder?dsName=datastore1&dcPath=Datacenter"
```

Priority chain to document: **CVE-2026-59310 (unauth RCE) → `reverse_ssh` persistence → (if AD-integrated) CVE-2024-37085 `ESX Admins` group → mass VM encryption**. The 2023-34048 and 2024-37079 DCE/RPC flaws are the same port-2012 surface and are often present together on stale builds.

### Validation and proof

### 9. CVE-2024-22273 — ESXi / Workstation / Fusion / vCenter storage controller OOB read/write

- **Note on the original ticket:** This CVE was listed in the brief as "Aria SSRF," but the actual NVD record describes an **ESXi/vCenter storage controller out-of-bounds read/write**, not an Aria SSRF. The closest Aria SSRF-adjacent issue in the 2024 cycle is **CVE-2023-34063** (VMSA-2024-0001) — Aria Automation missing access control allowing authenticated cross-org access; CVSSv3 9.9. Both are cited so the matrix is technically accurate.
- **Affected (CVE-2024-22273):** ESXi 7.0/8.0, Workstation 17.x, Fusion 13.x. vCenter Server packaged variants. Requires VM-local access with storage controllers enabled.
- **Attack flow:** VM with storage controllers enabled can issue crafted I/O to trigger OOB read/write on the host → information disclosure or DoS of the host (escape not directly demonstrated). CVSS 8.1 (Important).
- **Root cause:** Missing bounds check in the storage controller emulation path.
- **Disclosure:** Reported by Hao Zheng (@zhz) and Jiaqing Huang (@s0duku) of TianGong Team, Legendsec @ Qi'anxin Group. Advisory VMSA-2024-0011 published 2024-05-21. Year discovered 2024, patched 2024.
- **References:** https://www.vmware.com/security/advisories/VMSA-2024-0011.html ; https://nvd.nist.gov/vuln/detail/CVE-2024-22273 ; https://www.rapid7.com/db/vulnerabilities/vmsa-2024-0011-cve-2024-22273/
- **Aria-specific companion — CVE-2023-34063 (VMSA-2024-0001):** Aria Automation 8.11.x–8.14.x missing access control — authenticated actor obtains unauthorized cross-organization 

### C. Validation / proof bar — how to confirm and avoid false positives

- **Build-level proof, not banner-level:** record the exact running build, the exact fixed build from the Broadcom advisory, and the KEV entry (with added date / ransomware flag). "vCenter is on the internet" alone is Informational per the existing severity table.
- **Preconditions matter:** 2025-22224/25/26 need VM-local admin (not external pre-auth); 2026-41709 needs an already-admin session (anti-forensics impact); 2026-887xx-style SAML issues need SAML configured. Grade per reachability, not CVE CVSS.
- **Two clocks:** CISA/Quirso explicitly note patching does not evict an attacker who entered before the patch. Where a KEV entry requires forensic triage (BOD 26-04), hunt for `reverse_ssh`, unexpected outbound SSH, and DCE/RPC anomalies as a separate deliverable item.
- **Scope guard stays absolute:** keep the existing "external-only boundary check" — vCenter reachable *only* through VPN is the user's internal work. Flag internet-exposed instances only.
- **Do not execute file-upload/RCE PoCs without explicit sign-off** (existing rule). For 2026-123890, note the fake-PoC-repo noise: never import an unreviewed public exploit against client infra; validate against the advisory's affected/fixed table and Mandiant/GTIG IoCs instead.
- **Severity:** current-patch vCenter = Informational; missing patch with public/KEV RCE = Critical (virtualization plane); 2026-59310 with ransomware flag = same-day callout; 2026-41709 = Medium as a standalone logging gap, High when chained with observed Warp Panda activi

### Escalation and related chains

### Related Skills & Chains

- **`saml`** — vCenter Workspace ONE / VMware Identity Manager publishes SAML SP metadata at `/SAAS/API/1.0/GET/metadata/idp.xml` and consumes assertions at predictable ACS URLs. Chain primitive: vCenter SAML SP metadata reachable → IdP fingerprinted → `saml` XSW1-XSW8 against the federating IdP → forged assertion with `userPrincipalName=administrator@vsphere.local` → SP-impersonation as vCenter admin → full virtualization-plane takeover.
- **`rce`** — VMware's high-impact CVE catalog (CVE-2021-21972, CVE-2021-21985, CVE-2022-22954, CVE-2023-20887) is almost entirely pre-auth RCE. Chain primitive: vCenter version fingerprint via SSL banner or `/ui/login` body → confirm patch level missing → `rce` deserialization/SSTI gadget from the matching CVE PoC → `root` on vCenter appliance → API-token mint → cluster-wide VM control.
- **`enterprise-vpn-attack`** — VPN compromise + vCenter on internal-only is a natural post-VPN pivot, but external-only engagement scope sometimes forbids it. Chain primitive: VPN appliance CVE → foothold inside corp network → if scope permits, `vmware-vcenter-attack` becomes reachable on internal-only vCenter → datacenter takeover.
- **`m365-entra-attack`** — Some VMware deployments federate vCenter SSO to Entra. Chain primitive: vCenter SSO discovery → AuthURL points to `login.microsoftonline.com` → `m365-entra-attack` Entra ATO on `administrator@vsphere.local` synced identity → SAML assertion → vCenter admin without ever brute-forcing vCenter SSO.
- **`mid-engagement-ir-detection`** — VMware vSAN/vCenter alerting is sensiti

### Related Skills & Chains

- **`hunt-saml`** — vCenter Workspace ONE / VMware Identity Manager publishes SAML SP metadata at `/SAAS/API/1.0/GET/metadata/idp.xml` and consumes assertions at predictable ACS URLs. Chain primitive: vCenter SAML SP metadata reachable → IdP fingerprinted → `hunt-saml` XSW1-XSW8 against the federating IdP → forged assertion with `userPrincipalName=administrator@vsphere.local` → SP-impersonation as vCenter admin → full virtualization-plane takeover.
- **`hunt-rce`** — VMware's high-impact CVE catalog (CVE-2021-21972, CVE-2021-21985, CVE-2022-22954, CVE-2023-20887) is almost entirely pre-auth RCE. Chain primitive: vCenter version fingerprint via SSL banner or `/ui/login` body → confirm patch level missing → `hunt-rce` deserialization/SSTI gadget from the matching CVE PoC → `root` on vCenter appliance → API-token mint → cluster-wide VM control.
- **`enterprise-vpn-attack`** — VPN compromise + vCenter on internal-only is a natural post-VPN pivot, but external-only engagement scope sometimes forbids it. Chain primitive: VPN appliance CVE → foothold inside corp network → if scope permits, `vmware-vcenter-attack` becomes reachable on internal-only vCenter → datacenter takeover.
- **`m365-entra-attack`** — Some VMware deployments federate vCenter SSO to Entra. Chain primitive: vCenter SSO discovery → AuthURL points to `login.microsoftonline.com` → `m365-entra-attack` Entra ATO on `administrator@vsphere.local` synced identity → SAML assertion → vCenter admin without ever brute-forcing vCenter SSO.
- **`mid-engagement-ir-detection`** — VMware vSAN/vCenter

### Tools and wordlists

### Tooling

- **`vCenter-Exploit` collection** (multiple PoCs on GitHub for 21972, 21985, 22005)
- **`Greenbone/openvas-scanner` VMware NASL plugins** — version detection
- **`nuclei`** templates: `vmware-vcenter-*.yaml`, `cve-2021-21972.yaml`, `cve-2022-22954.yaml`
- **`Metasploit`** modules: `exploit/multi/http/vmware_vcenter_*`

---

## Source skills merged into this topic

- `hunting` — `vmware-vcenter-attack`
- `cbh` — `vmware-vcenter-attack`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `bbhunt-methodology` — orchestrator, state machine and class router
