# Upstream source: ntlm-info (hunting)

Original path: `/tmp/h1res_MrPsycho04_Hunting-Agent/ntlm-info/SKILL.md`

---

---
name: ntlm-info
description: "Hunt NTLM/Negotiate information disclosure on internet-reachable IIS/SharePoint/Exchange. Anonymous NTLM Type-2 challenge capture leaks NetBIOS domain, internal DNS forest, computer name, AD timestamp via AV_PAIRS structure. Default Windows-installer hostnames (WIN-XXXXXXXXXXX pattern) signal lazy provisioning. Use when target advertises `WWW-Authenticate: NTLM` or `Negotiate` headers anonymously."
---

**Reference files (load on demand):**

- `references/payloads.md` — payload banks, probes, wordlists, Nuclei templates, observed parameters
- `references/techniques.md` — quick wins, bypasses, real-report techniques, deeper checklists

## Crown Jewel Targets

NTLM info disclosure is a **Medium-severity finding when chained to context** — the leak itself is intentional protocol behavior (RFC-compliant NTLMSSP challenge), but on internet-exposed enterprise infrastructure it provides exact reconnaissance for the next stage of an attack. Highest-value targets:

- **Internet-reachable IIS / SharePoint / Exchange / OWA** with dual-auth (Forms + NTLM, or NTLM + Kerberos)
- **Citrix NetScaler / VMware Horizon View** internet-facing gateways with NTLM-backed AD auth
- **Lync / Skype for Business / Teams On-Prem** edge servers
- **WSUS / Windows Update Services** with NTLM-protected admin paths
- **CIFS-style fileshare proxies** (HCL Sametime, IBM Notes Domino) that proxy NTLM
- **Legacy SharePoint farms** that left NTLM enabled on the public-zone IIS binding

**What makes this pay:**
- Internal AD domain disclosure (parent-forest mapping, e.g. `customer.parent-corp.example` → tenant inside corporate-AD tree)
- Default-Windows-hostname disclosure (`WIN-XXXXXXXXXXX` pattern signals rushed provisioning → likely default service-account passwords)
- Timestamp leak (used in NTLMv2 hash cracking acceleration)
- Direct attack-map enrichment for credential spraying combined with `auth-bypass` Legacy-Protocol Matrix

---

## Attack Surface Signals

**Response headers signaling NTLM availability:**
```
WWW-Authenticate: NTLM
WWW-Authenticate: Negotiate
WWW-Authenticate: NTLM, Negotiate
WWW-Authenticate: Negotiate, NTLM
```

**URL patterns where NTLM is commonly exposed:**
```
/_api/web/CurrentUser                  (SharePoint REST)
/_vti_bin/*.asmx                       (SharePoint legacy SOAP)
/EWS/Exchange.asmx                     (Exchange Web Services)
/Autodiscover/Autodiscover.xml         (Exchange autodiscover)
/owa/                                  (Outlook Web App)
/Microsoft-Server-ActiveSync           (ActiveSync)
/PowerShell                            (Exchange Mgmt Shell over HTTPS)
/api/v3/                               (TeamCity, Atlassian)
/wsus/                                 (Windows Server Update Services)
/manager/html                          (some Tomcat behind IIS)
/iisstart.htm                          (default IIS, sometimes reveals NTLM upstream)
```

**Tech-stack signals:**
- IIS on the public internet (almost always NTLM-capable, even if Forms is the front)
- SharePoint Web Front End (almost always dual-auth Forms + NTLM)
- Exchange edge transport
- Server header `Microsoft-HTTPAPI/2.0`, `Microsoft-IIS/*`, `IIS/*`

---

## Step-by-Step Hunting Methodology

1. **Probe every anonymous endpoint for `WWW-Authenticate: NTLM`.** Send a vanilla GET and inspect response headers. If NTLM is offered, proceed.

2. **Send a valid NTLMSSP Type-1 message anonymously.** The Type-1 base64 below requests NetBIOS-domain and Workstation info from the server:
   ```
   Authorization: NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==
   ```
   This is the standard test Type-1 with negotiate flags `NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_NEGOTIATE_OEM | NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_ALWAYS_SIGN | NTLMSSP_NEGOTIATE_KEY_EXCH | NTLMSSP_NEGOTIATE_56 | NTLMSSP_NEGOTIATE_128 | NTLMSSP_NEGOTIATE_TARGET_INFO`. The `OS Version` field (`06 01 B1 1D 00 00 00 0F`) is Windows 7 build 7601 — accepted by virtually every NTLM responder.

3. **Use a keep-alive raw socket, not Python requests / curl one-shot.** Most HTTP libraries close the connection between the Type-1 send and Type-2 reception. Use one of:
   - Burp Repeater with `Connection: keep-alive` set explicitly
   - Burp `mcp__burp__send_http1_request` (handles keep-alive natively)
   - Python raw `socket` + `ssl.wrap_socket` (see Payload section)

4. **Parse the Type-2 challenge from the `WWW-Authenticate: NTLM <base64>` response header.** Base64-decode the value. The structure is NTLMSSP per MS-NLMP:
   - Bytes 0-7: literal `NTLMSSP\0`
   - Bytes 8-11: MessageType = `\x02\x00\x00\x00`
   - Bytes 12-19: TargetName SecurityBuffer (len, alloc, offset)
   - Bytes 20-23: NegotiateFlags
   - Bytes 24-31: Server Challenge (8 bytes — useful for offline cracking)
   - Bytes 40-47: TargetInfo SecurityBuffer (len, alloc, offset)
   - TargetInfo body: `AV_PAIRS` array of (AvId u16, AvLen u16, Value)

5. **Decode the AV_PAIRS.** The AvIds you care about:
   - `1` = NetBIOS Computer Name
   - `2` = NetBIOS Domain Name
   - `3` = DNS Computer Name (FQDN of the responding server)
   - `4` = DNS Domain Name (the AD domain)
   - `5` = DNS Tree Name (the AD forest root)
   - `7` = Timestamp (FILETIME, useful for NTLMv2 hash relay / cracking)
   - `9` = Target Name (in newer NTLMSSP)

6. **Map findings to severity tier:**
   - Internet-exposed + default `WIN-XXXXXXXXXXX` hostname + corporate-AD-tree disclosure → **Medium**
   - Internet-exposed + named-server hostname (`SPWEB01.corp.example`) + corporate-AD-tree → **Low-Medium**
   - Intranet-only + any disclosure → **Informational**
   - Combine with `auth-bypass` Legacy-Protocol Matrix findings on the same host → **upgrade the auth-bypass finding's severity** since the attacker has UPN/SAM format ready

7. **Check the timestamp.** If `AV[7]` returns a current FILETIME within ~5s of `Date:` header, the system clock is synced — useful intel for Kerberos golden-ticket forging (out of bug-bounty scope but red-team relevant).

8. **Cross-reference with subdomain enum.** The DNS Tree name often reveals the *parent forest* — e.g. `customer.parent-corp.example` reveals the customer is a sub-domain INSIDE corporate-parent AD, not a separate tenant. This is a privacy / topology-disclosure escalation that programs sometimes accept as Medium.

---

## Common Root Causes

1. **Dual-auth IIS bindings on the public zone.** Administrators leave NTLM enabled on the public-facing IIS site even when Forms auth is the intended entry point. Internal users get SSO; external attackers get the AD topology leak.

2. **Default IIS Application Pool identity left as `ApplicationPoolIdentity`.** Combined with default hostname, signals provisioning never went past first-boot.

3. **Server never renamed from Windows-installer-generated hostname.** Microsoft's default `WIN-XXXXXXXXXXX` 11-character pattern is the immediate tell. Sometimes also `WORKGROUP\WIN-...` in older boxes.

4. **Sub-domain joined to corporate forest without zone-isolation.** European-integrator case: a a European importer's SharePoint test environment is a child domain inside a corporate global AD, disclosed via NTLM DNS Tree Name. The customer probably intends `customer.parent-corp.example` to be operationally separate but the NTLM Type-2 reveals the forest membership to anyone who probes.

5. **IIS Extended Protection NOT enabled.** When `<system.webServer><security><authentication><windowsAuthentication extendedProtection>` is `None` (the default), the NTLM challenge is sent to any anonymous client. When set to `Required`, NTLM is restricted to authenticated callers — and the AV-pair leak is mitigated.

6. **No `WindowsAuthentication` removed from `applicationHost.config` for internet-exposed sites.** SharePoint Central Admin sometimes leaves this enabled even when SP zone configuration only enables Forms.

---

## Gate 0 Validation

Before writing the report, confirm:

1. **What can the attacker do RIGHT NOW with this disclosure?**
   - Internet-exposed + default hostname + corporate forest disclosed → **Medium**: attacker has UPN format for `auth-bypass` matrix probes, plus knows server has likely-default service accounts.
   - Intranet-only or only NetBIOS name → **Informational**.

2. **Does the program accept information-disclosure findings without a chained impact?**
   - Many programs (Microsoft, large enterprise VDPs) DO accept this when the leaked info includes internal AD topology.
   - Many programs (Shopify, GitHub) reject info disclosure without a chained impact.
   - Read the program scope before submitting; if borderline, chain with a Tier-A finding from `auth-bypass`.

3. **Can you reproduce in <5 minutes from a fresh shell?**
   - The Python snippet above is the canonical reproduction. Include it verbatim in the report.

---

## Real Impact Examples

### Scenario A — Enterprise SharePoint inside parent corporate AD

Target: `https://target-portal.example/` — a enterprise dealer portal (test mirror) operated by a system integrator.

Sending the anonymous Type-1 message to `/_api/web/CurrentUser` returned a Type-2 challenge whose AV_PAIRS decoded to:

```
NetBIOS Domain Name:    <CustomerName>
NetBIOS Computer Name:  WIN-XXXXXXXXXXX
DNS Domain Name:        customer.parent-corp.example
DNS Computer Name:      WIN-XXXXXXXXXXX.customer.parent-corp.example
DNS Tree Name:          customer.parent-corp.example
Timestamp:              2026-05-13T15:55:37.922Z
```

Three escalation paths:
1. **Default Windows-installer hostname (`WIN-XXXXXXXXXXX`)** — server was never renamed after OS install; strong signal of lazy provisioning. Likely default service-account passwords on the SQL backend, default WSUS config, etc.
2. **Sub-domain inside corporate-parent AD (`customer.parent-corp.example`)** — the customer is a child domain inside <ParentCorp>'s global Active Directory. A compromise of this test farm has potential cross-trust to corporate-parent.
3. **UPN format known** — combined with `auth-bypass`'s discovery of an anonymous brute-force endpoint on `/_vti_bin/Authentication.asmx`, the attacker has both the credential format (`firstname.lastname@customer.parent-corp.example` or `<CustomerName>\firstname.lastname`) and the unlimited submission endpoint.

Reported severity: **Medium**, with a note that the chain with the Authentication.asmx anonymous brute-force makes the combined attack Critical.

### Scenario B — Exchange edge with NTLM-protected EWS

Target: `https://mail.example.com/EWS/Exchange.asmx`. Type-1 probe returns Type-2 with DNS Tree Name `corp.example.com` and DNS Computer Name `MAIL01.corp.example.com`. Confirms the Exchange edge is domain-joined to corporate AD (rather than running in a DMZ-isolated AD). For an attacker with the matching `mfa-and-passwords` / `auth-bypass` chain, the leaked UPN format and server-name format accelerate credential spraying by removing the recon step. Reported severity: Low-Medium depending on program.

### Scenario C — Intranet-only intentional leak (not a finding)

Target: `https://intranet.corp.example` (clearly internal, behind VPN). Type-1 returns full AV-pair set. Not reportable — this is intended NTLM behavior on intranet, and the disclosure is to authenticated VPN users who already see the same data via `nltest /dsgetdc:corp.example.com`. Recognize and drop.

---

## Related Skills & Chains

- **`sharepoint`** — SharePoint farms emit anonymous Type-2 challenges on `/_vti_bin/` by default; this is one of the most reliable ways to get internal AD topology. Chain primitive: SharePoint discovered → NTLM Type-2 capture on `/_vti_bin/Lists.asmx` → `ntlm-info` AV_PAIR decode → internal forest name → `m365-entra-attack` ROPC spray on Entra tenant tied to that forest.
- **`m365-entra-attack`** — Leaked NetBIOS domain + UPN suffix is the missing piece for a credible password spray. Chain primitive: NTLM Type-2 yields `corp.example.com` DNS tree → cross-reference Entra tenant via `https://login.microsoftonline.com/corp.example.com/.well-known/openid-configuration` → `m365-entra-attack` AADSTS error-differential username enumeration on resolved tenant.
- **`aspnet`** — IIS sites running ASP.NET frequently expose NTLM on management paths. Chain primitive: NTLM Type-2 on `/owa/`, `/ecp/`, `/rpc/`, `/aspnet_client/` → confirm IIS + ASP.NET version → `aspnet` ViewState / `.axd` enumeration on same host.
- **`offensive-osint`** — The hostname pattern `WIN-XXXXXXXXXXX` signals lazy provisioning and predicts other weak hygiene. Chain primitive: NTLM Type-2 returns default-installer hostname → flag as low-maturity environment → `offensive-osint` deep recon (cert transparency, GitHub leakage, breach corpus correlation) is high-yield on this org.
- **`triage-validation`** — Most NTLM info-disclosure findings die at the 7-Question Gate on "is this exploitable" — pure topology disclosure is Low/Informational. Chain primitive: pull every NTLM-info finding through `triage-validation` BEFORE writing it up; only report if (a) leaks UPN format that accelerates spray, or (b) leaks production hostname mapping (`redteam-report-template` for the chain-narrative).

## Web-Research Methodology Additions (2026)

### A. Discovery checklist — concrete places, params, headers, infra signals to look
- Find endpoints that advertise NTLM/Negotiate anonymously. The trigger is a response header `WWW-Authenticate: NTLM` or `WWW-Authenticate: Negotiate` (often both) on an unauthenticated request. Typical hosts: internet-facing IIS, SharePoint, Exchange/OWA/EWS, EDR/VPN admin portals, RDWeb.
- Probe both HTTP and HTTPS, common subdomains (`owa.`, `mail.`, `exchange.`, `vpn.`, `sharepoint.`, `sps.`, `autodiscover.`), and paths (`/`, `/owa`, `/ews`, `/rpc/rpcproxy.dll`, `/_layouts/`, `/api/`). Note `Server: Microsoft-IIS/...`, `MicrosoftSharePointTeamServices`, or `X-MS-InvokeApp` fingerprints.
- The leak is in the NTLM **Type 2 (challenge)** message, returned before any credentials are supplied. Do not send a Type 3 — you only need the anonymous Type 1 -> Type 2 exchange.
- Understand the wire fields you are decoding (per davenport's NTLM reference): `NTLMSSP` signature (0x4e544c4d53535000), message type `0x02000000`, Target Name security buffer, Flags, 8-byte Challenge, Context, and the Target Information block (AV_PAIRS).
- AV_PAIRS subblock types worth extracting: type 1 = NetBIOS server name, type 2 = NetBIOS domain name, type 3 = DNS server name (FQDN), type 4 = DNS domain name, type 5 = parent DNS domain, type 0 = terminator. Also capture the OS Version structure (major/minor/build) and Negotiate flags.
- Record the exact strings: NetBIOS domain, DNS forest/domain, computer name, FQDN, OS build. Default `WIN-XXXXXXXXXXX` hostnames signal lazy provisioning. Map whether the domain matches the parent corporate AD (the finding that actually pays) or is a standalone/intranet-only name (usually not a finding).
- Cross-check related 2025-2026 NTLM issues for context (not the same as Type-2 info disclosure): CVE-2025-24054 / CVE-2025-21377 NTLM hash disclosure via `.library-ms` / `.url` files, CVE-2025-33073 NTLM reflection (SYSTEM on non-SMB-signed hosts), and Exchange MRSProxy pre-auth NTLM relay (CVE-2026-62911). These show NTLM exposure is actively exploited — useful impact framing.

### B. Techniques & bypasses — specific actionable techniques/payload shapes
- Manual Type 1 probe — send an unauthenticated NTLM negotiate and read the challenge from `WWW-Authenticate: NTLM <base64>`:
  ```
  GET / HTTP/1.1
  Host: target
  Authorization: NTLM TlRMTVNTUAABAAAAA7IAAAoACgApAAAACgAKACMAAAA...
  ```
  (The base64 is a minimal Type 1; tools below generate it for you.)
- Nmap NSE — the fastest first pass:
  ```
  nmap -sS -v --script=ntlm-info target.com
  ```
- Burp: right-click the 401 response -> "NTLM Challenge Decoder" (or use the NTLMSSP parser in Burp) to render NetBIOS/DNS names and OS build from the Type 2 blob.
- Python helper (pattern from published writeups):
  ```
  python3 ntlm_challenger.py <target>
  ```
  Implement with a raw socket/HTTP request: send Type 1, base64-decode the `WWW-Authenticate` Type 2, walk the security buffers at offsets 12 (Target Name) and 40 (Target Information), then iterate the AV_PAIRS. Minimal Type 1 bytes: `4e544c4d535350000100000002020000`.
- Decode the Target Information block manually: each subblock is `type (2 bytes LE) | length (2 bytes LE) | UTF-16LE value`; e.g. `02000c00` = NetBIOS domain name, 12 bytes of UTF-16LE follow. Decode to Unicode, not OEM.
- For M365/Entra or ADFS-hosted surfaces, note that NTLM info disclosure can coexist with SAML/WS-Fed endpoints — the leaked internal domain is a useful input to identity attacks, but keep this finding scoped to the leak itself.

### C. Validation / proof bar — how to confirm and avoid false positives
- The bar is concrete decoded internal identifiers: a corporate NetBIOS/DNS domain, FQDN, OS build, or machine name that is not otherwise public. A bare `WWW-Authenticate: NTLM` header with an empty/minimal Target Information block is not a finding.
- Reproduce with a clean, unauthenticated request (no cookies, no Authorization beyond the Type 1) so triage sees the same challenge. Include the raw Type 2 base64 and the decoded field table in the report.
- Classify the domain:
  - internal AD name matching the parent corporate domain + high-value server (SharePoint/Exchange/VPN) -> Low/Medium recon disclosure that pays when chained.
  - generic/internet-facing standalone name, intranet-only name, or intentionally published partner-extranet domain -> usually not a finding.
- Do NOT report the related NTLM CVEs as present just because NTLM is offered. Capturing a *hash* requires a coerce/relay primitive (file, UNC path, SMB listener); Type-2 info disclosure only leaks server metadata. Keep the claim narrow.
- SMB signing / EPA / Extended Protection status is a separate assessment — do not infer relayability from a Type-2 response alone.
- Defense framing: disable NTLM where possible (Kerberos-only), restrict anonymous NTLM handshake at the edge, remove legacy IIS/SharePoint/Exchange exposure, and enable SMB signing/EPA to blunt relay. Note that the Type-2 leak is inherent to NTLM, so removal of exposure is the real fix.

- Capture the raw base64 Type 2 and decode locally; Burp's decoder is convenient but you need byte offsets to confirm the parser read the right security buffer.
- Check Negotiate flags in the challenge: `Negotiate Target Info (0x00800000)` means AV_PAIRS are present; `Target Type Domain (0x00010000)` vs `Target Type Server (0x00020000)` changes how you interpret the Target Name.
- OS build extraction: the 8-byte OS Version structure at the end of Type 2 gives major/minor/build — e.g. `0x0501280a...` = build 2600. Map builds to OS/SP in the report.
- Probe multiple endpoints: the same IIS box may leak a different NetBIOS domain on `/owa` vs `/ews` (different application pools/domains), strengthening the topology claim.
- If the host answers `WWW-Authenticate: Negotiate` with a Kerberos-only ticket and no NTLM, there is no Type 2 to decode — record that as a negative, not a finding.
- The challenge value itself is random and not sensitive; the disclosure is the server-supplied names and version, not the challenge bytes.
- Correlation: if the leaked domain matches names from AXFR, CT certs, or SAML/OIDC metadata already collected, state the cross-source confirmation — it defeats "public information" dismissals.
- For SharePoint, check whether the leaked domain corresponds to the farm account's AD; the July 2026 SharePoint attack analysis shows how NTLM challenges get relayed toward SQL and farm service accounts post-compromise.
- Some proxies strip `WWW-Authenticate` on the first 401 but leave the Type 2 in a second 401 after a malformed Type 1 — test both challenges.

### D. Sources — numbered list of URLs you actually fetched
1. https://davenport.sourceforge.net/ntlm.html
2. https://medium.com/@vashuvats/sensitive-information-disclosure-via-ntlm-authentication-on-public-facing-iis-server-b13d0c5f1f3a
3. https://www.vaadata.com/en/blog/understanding-ntlm-authentication-and-ntlm-relay-attacks
4. https://research.checkpoint.com/2025/cve-2025-24054-ntlm-exploit-in-the-wild
5. https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025
6. https://www.praetorian.com/blog/cve-2025-33073-ntlm-reflection-one-hop
7. https://www.tenable.com/plugins/nessus/342664
