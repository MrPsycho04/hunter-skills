---
name: bbhunt-ntlm-info
description: "Hunt internet-reachable IIS/SharePoint/Exchange NTLM Negotiate information leakage. Unified from 2 upstream skills (cbh, hunting). For authorized security testing only."
agent_created: true
---

# NTLM information disclosure hunting — unified methodology

> **Unified skill.** Built from 2 upstream skills across cbh, hunting. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### Step-by-Step Hunting Methodology

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
   - Bytes 24-31: Server Challenge (8 bytes — useful for offline 

### A. Discovery checklist — concrete places, params, headers, infra signals to look

- Find endpoints that advertise NTLM/Negotiate anonymously. The trigger is a response header `WWW-Authenticate: NTLM` or `WWW-Authenticate: Negotiate` (often both) on an unauthenticated request. Typical hosts: internet-facing IIS, SharePoint, Exchange/OWA/EWS, EDR/VPN admin portals, RDWeb.
- Probe both HTTP and HTTPS, common subdomains (`owa.`, `mail.`, `exchange.`, `vpn.`, `sharepoint.`, `sps.`, `autodiscover.`), and paths (`/`, `/owa`, `/ews`, `/rpc/rpcproxy.dll`, `/_layouts/`, `/api/`). Note `Server: Microsoft-IIS/...`, `MicrosoftSharePointTeamServices`, or `X-MS-InvokeApp` fingerprints.
- The leak is in the NTLM **Type 2 (challenge)** message, returned before any credentials are supplied. Do not send a Type 3 — you only need the anonymous Type 1 -> Type 2 exchange.
- Understand the wire fields you are decoding (per davenport's NTLM reference): `NTLMSSP` signature (0x4e544c4d53535000), message type `0x02000000`, Target Name security buffer, Flags, 8-byte Challenge, Context, and the Target Information block (AV_PAIRS).
- AV_PAIRS subblock types worth extracting: type 1 = NetBIOS server name, type 2 = NetBIOS domain name, type 3 = DNS server name (FQDN), type 4 = DNS domain name, type 5 = parent DNS domain, type 0 = terminator. Also capture the OS Version structure (major/minor/build) and Negotiate flags.
- Record the exact strings: NetBIOS domain, DNS forest/domain, computer name, FQDN, OS build. Default `WIN-XXXXXXXXXXX` hostnames signal lazy provisioning. Map whether the domain matches

### Step-by-Step Hunting Methodology

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
   - Bytes 24-31: Server Challenge (8 bytes — useful for offline 

### Signals and surfaces

### Crown Jewel Targets

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

### Attack Surface Signals

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

### Crown Jewel Targets

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
- Direct attack-map enrichment for credential spraying combined with `hunt-auth-bypass` Legacy-Protocol Matrix

---

### Techniques, payloads and bypasses

### Common Root Causes

1. **Dual-auth IIS bindings on the public zone.** Administrators leave NTLM enabled on the public-facing IIS site even when Forms auth is the intended entry point. Internal users get SSO; external attackers get the AD topology leak.

2. **Default IIS Application Pool identity left as `ApplicationPoolIdentity`.** Combined with default hostname, signals provisioning never went past first-boot.

3. **Server never renamed from Windows-installer-generated hostname.** Microsoft's default `WIN-XXXXXXXXXXX` 11-character pattern is the immediate tell. Sometimes also `WORKGROUP\WIN-...` in older boxes.

4. **Sub-domain joined to corporate forest without zone-isolation.** European-integrator case: a a European importer's SharePoint test environment is a child domain inside a corporate global AD, disclosed via NTLM DNS Tree Name. The customer probably intends `customer.parent-corp.example` to be operationally separate but the NTLM Type-2 reveals the forest membership to anyone who probes.

5. **IIS Extended Protection NOT enabled.** When `<system.webServer><security><authentication><windowsAuthentication extendedProtection>` is `None` (the default), the NTLM challenge is sent to any anonymous client. When set to `Required`, NTLM is restricted to authenticated callers — and the AV-pair leak is mitigated.

6. **No `WindowsAuthentication` removed from `applicationHost.config` for internet-exposed sites.** SharePoint Central Admin sometimes leaves this enabled even when SP zone configuration only enables Forms.

---

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

### Payload & Detection Patterns

**Generic NTLM Type-1 anonymous probe (curl + raw socket fallback):**
```bash
# Most one-shot curl runs DON'T return Type-2 because the connection closes.
# Use this as a quick probe to confirm NTLM is offered:
curl -sk -I -H "Authorization: NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==" \
  "https://target.example/_api/web/CurrentUser" 2>&1 | grep -i "WWW-Authenticate"
```

**Burp `send_http1_request` (recommended for full Type-2 capture):**
```
GET /_api/web/CurrentUser HTTP/1.1
Host: target.example
Authorization: NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==
Connection: keep-alive
User-Agent: Mozilla/5.0

```

**Python raw socket + AV_PAIR decoder:**
```python
import socket, ssl, base64, struct, re
from datetime import datetime, timezone

HOST = "target.example"
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

s = ctx.wrap_socket(socket.create_connection((HOST, 443)), server_hostname=HOST)
s.sendall(
    f"GET /_api/web/CurrentUser HTTP/1.1\r\n"
    f"Host: {HOST}\r\n"
    "Authorization: NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==\r\n"
    "User-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n".encode()
)
data = b""
while True:
    chunk = s.recv(8192)
    if not chunk: break
    data += chunk
    if b"\r\n\r\n" in data: break

m = re.search(rb"WWW-Authenticate:\s*NTLM\s+([A-Za-z0-9+/=]{20,})", data, re.I)
if m:
    b = base64.b64decode(m.group(1).decode("ascii"))
    assert b[:8] == b"NTLMSSP\x00"
    tn_len, _, tn_off = struct.unpack_fr

### Bypass Techniques

This skill describes a disclosure leak, not an authentication bypass. The "bypass" question is: *how do defenders block this AV-pair leak while still allowing legitimate NTLM auth?*

| Defense | Effectiveness |
|---|---|
| **Disable NTLM on the public IIS binding entirely** (Forms-only) | Best — eliminates the surface |
| **IIS Extended Protection = Required** | Restricts NTLM challenge to authenticated callers; AV-pair leak mitigated |
| **Reverse-proxy strip `WWW-Authenticate` from anonymous responses** | Sometimes works but breaks legitimate clients |
| **Rate-limit the Type-1 → Type-2 endpoint** | Doesn't prevent disclosure, only slows enumeration |
| **Rename the Windows host from `WIN-XXXXXXXXXXX`** | Removes the "lazy provisioning" tell; doesn't stop the leak |
| **Move the SP/Exchange farm to a child AD with no cross-trust to corporate** | Mitigates the *forest disclosure*; doesn't stop the leak |

For the attacker: there's no "bypass" needed — the leak is the finding.

---

### Validation and proof

### Gate 0 Validation

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

### C. Validation / proof bar — how to confirm and avoid false positives

- The bar is concrete decoded internal identifiers: a corporate NetBIOS/DNS domain, FQDN, OS build, or machine name that is not otherwise public. A bare `WWW-Authenticate: NTLM` header with an empty/minimal Target Information block is not a finding.
- Reproduce with a clean, unauthenticated request (no cookies, no Authorization beyond the Type 1) so triage sees the same challenge. Include the raw Type 2 base64 and the decoded field table in the report.
- Classify the domain:
  - internal AD name matching the parent corporate domain + high-value server (SharePoint/Exchange/VPN) -> Low/Medium recon disclosure that pays when chained.
  - generic/internet-facing standalone name, intranet-only name, or intentionally published partner-extranet domain -> usually not a finding.
- Do NOT report the related NTLM CVEs as present just because NTLM is offered. Capturing a *hash* requires a coerce/relay primitive (file, UNC path, SMB listener); Type-2 info disclosure only leaks server metadata. Keep the claim narrow.
- SMB signing / EPA / Extended Protection status is a separate assessment — do not infer relayability from a Type-2 response alone.
- Defense framing: disable NTLM where possible (Kerberos-only), restrict anonymous NTLM handshake at the edge, remove legacy IIS/SharePoint/Exchange exposure, and enable SMB signing/EPA to blunt relay. Note that the Type-2 leak is inherent to NTLM, so removal of exposure is the real fix.

- Capture the raw base64 Type 2 and decode locally; Burp's decoder is convenient but 

### Gate 0 Validation

Before writing the report, confirm:

1. **What can the attacker do RIGHT NOW with this disclosure?**
   - Internet-exposed + default hostname + corporate forest disclosed → **Medium**: attacker has UPN format for `hunt-auth-bypass` matrix probes, plus knows server has likely-default service accounts.
   - Intranet-only or only NetBIOS name → **Informational**.

2. **Does the program accept information-disclosure findings without a chained impact?**
   - Many programs (Microsoft, large enterprise VDPs) DO accept this when the leaked info includes internal AD topology.
   - Many programs (Shopify, GitHub) reject info disclosure without a chained impact.
   - Read the program scope before submitting; if borderline, chain with a Tier-A finding from `hunt-auth-bypass`.

3. **Can you reproduce in <5 minutes from a fresh shell?**
   - The Python snippet above is the canonical reproduction. Include it verbatim in the report.

---

### Escalation and related chains

### Related Skills & Chains

- **`sharepoint`** — SharePoint farms emit anonymous Type-2 challenges on `/_vti_bin/` by default; this is one of the most reliable ways to get internal AD topology. Chain primitive: SharePoint discovered → NTLM Type-2 capture on `/_vti_bin/Lists.asmx` → `ntlm-info` AV_PAIR decode → internal forest name → `m365-entra-attack` ROPC spray on Entra tenant tied to that forest.
- **`m365-entra-attack`** — Leaked NetBIOS domain + UPN suffix is the missing piece for a credible password spray. Chain primitive: NTLM Type-2 yields `corp.example.com` DNS tree → cross-reference Entra tenant via `https://login.microsoftonline.com/corp.example.com/.well-known/openid-configuration` → `m365-entra-attack` AADSTS error-differential username enumeration on resolved tenant.
- **`aspnet`** — IIS sites running ASP.NET frequently expose NTLM on management paths. Chain primitive: NTLM Type-2 on `/owa/`, `/ecp/`, `/rpc/`, `/aspnet_client/` → confirm IIS + ASP.NET version → `aspnet` ViewState / `.axd` enumeration on same host.
- **`offensive-osint`** — The hostname pattern `WIN-XXXXXXXXXXX` signals lazy provisioning and predicts other weak hygiene. Chain primitive: NTLM Type-2 returns default-installer hostname → flag as low-maturity environment → `offensive-osint` deep recon (cert transparency, GitHub leakage, breach corpus correlation) is high-yield on this org.
- **`triage-validation`** — Most NTLM info-disclosure findings die at the 7-Question Gate on "is this exploitable" — pure topology disclosure is Low/Informational. Chain primitive: pull every NTLM-info finding t

### Related Skills & Chains

- **`hunt-sharepoint`** — SharePoint farms emit anonymous Type-2 challenges on `/_vti_bin/` by default; this is one of the most reliable ways to get internal AD topology. Chain primitive: SharePoint discovered → NTLM Type-2 capture on `/_vti_bin/Lists.asmx` → `hunt-ntlm-info` AV_PAIR decode → internal forest name → `m365-entra-attack` ROPC spray on Entra tenant tied to that forest.
- **`m365-entra-attack`** — Leaked NetBIOS domain + UPN suffix is the missing piece for a credible password spray. Chain primitive: NTLM Type-2 yields `corp.example.com` DNS tree → cross-reference Entra tenant via `https://login.microsoftonline.com/corp.example.com/.well-known/openid-configuration` → `m365-entra-attack` AADSTS error-differential username enumeration on resolved tenant.
- **`hunt-aspnet`** — IIS sites running ASP.NET frequently expose NTLM on management paths. Chain primitive: NTLM Type-2 on `/owa/`, `/ecp/`, `/rpc/`, `/aspnet_client/` → confirm IIS + ASP.NET version → `hunt-aspnet` ViewState / `.axd` enumeration on same host.
- **`offensive-osint`** — The hostname pattern `WIN-XXXXXXXXXXX` signals lazy provisioning and predicts other weak hygiene. Chain primitive: NTLM Type-2 returns default-installer hostname → flag as low-maturity environment → `offensive-osint` deep recon (cert transparency, GitHub leakage, breach corpus correlation) is high-yield on this org.
- **`triage-validation`** — Most NTLM info-disclosure findings die at the 7-Question Gate on "is this exploitable" — pure topology disclosure is Low/Informational. Chain primitive: pull every

## Source skills merged into this topic

- `hunting` — `ntlm-info`
- `cbh` — `hunt-ntlm-info`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `bbhunt-methodology` — orchestrator, state machine and class router
