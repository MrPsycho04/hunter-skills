# CRLF / Header Injection — HackerOne field guide — Technique reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete technique.

---

## Quick wins



Start here. These are the highest-yield tests for this class.



- Inject %0d%0a into params reflected in headers, redirects, or filenames.

- Test header injection for XSS, cache poisoning, and smuggling.

- Check email header injection in contact/notification forms.



## Bypass tricks



- Double encoding and unicode line separators.

- Use header folding and whitespace variations.



## Deeper checklist



- Inject `%0d%0a` into params reflected in headers, redirects, or filenames.

- Test header injection for XSS, cache poisoning, and request smuggling.

- Try encoded variants and unicode line separators.

- Check email header injection in contact/notification forms.

- Demonstrate header control or response splitting.



## Techniques from real reports



One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.



- **CRLF injection** — `#446271` · X / xAI · $0 · ▲439

  > https://ads.twitter.com/subscriptions/mobile/landing?ref=gl-tw-tw-promote-mode?t=%0d%0atest:tested

- **HTTP Response Header Injection in shopify/pitchfork + Rack 3** — `#2279572` · Shopify · $800 · ▲136

  > Header injection succeeds in case of `r\n` and `\n`.

- **CRLF injection leads to internal XSS on PangleGlobal** — `#2189960` · TikTok · $0 · ▲97

  > A cross-site scripting vulnerability was found on a Pangle endpoint due to CRLF injection on the 'file name' parameter.

- **CRLF to XSS & Open Redirection** — `#2012519` · TikTok · $0 · ▲97

  > This could have led to Reflective XSS (Cross-Site Scripting) to gain access to a user's cookies, or the ability to send users to unauthorized webpages ending in "tiktok.com" via an open redirect.

- **Creating malformed URLs via new line character in-between two URLs leads to misrepresented hyperlinks in Tweets/DMs** — `#712979` · X / xAI · $0 · ▲96

  > This allows an attacker to create realistic looking phishing URLs via combining `attacker.com` + `%0d` + `website.com`.

- **Grafana RCE via SMTP server parameter injection** — `#1200647` · Aiven Ltd · $5,000 · ▲72

  > Using this CRLF-injection, the `rendering args` of grafana image renderer can be modified which leads to code execution on the Grafana server.

- **jitsi-meet: Prosody/Jigasi missing header whitelist in mod_filter_iq_rayo allows arbitrary SIP header injection and Caller ID spoofing** — `#3789570` · 8x8 · $100 · ▲72

  > The Prosody filter implemented an incomplete blocklist that stripped only three specific internal header names (`X-outbound-call-initiator-user`, `X-outbound-call-initiator-group`, and `JvbRoomName` on visitor nodes) from client-supplied Rayo `<dial ` IQ…

- **Host Header Injection - internal.qa.delivery.indrive.com** — `#2076786` · inDrive · $0 · ▲66

  > User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36

- **Security bug https://bugzilla.mozilla.org/oauth/authorize - CRLF Header injection via "redirect_uri" parameter** — `#2147132` · Mozilla · $200 · ▲61

  > or (with true redirect): https://bugzilla.mozilla.org/oauth/authorize?client id=&redirect uri=\\name.tld%0d%0axxx:something&response type=code

- **HTTP Response Splitting (CRLF injection) in report_story** — `#52042` · X / xAI · $0 · ▲59

  > https://twitter.com/i/safety/report story?next view=report story start&source=reporttweet&reported user id=1&reporter user id=1&is media=true&is promoted=true&reported tweet id=%E5%98%8A%E5%98%8DSet-Cookie:%20test

- **Host Header Injection leads to Open Redirect and Content Spoofing or Text Injection.** — `#1444675` · Omise · $300 · ▲50

  > When an application does not properly handle user-supplied data, an attacker can supply content to a web application, typically via a parameter value, that is reflected back to the user.

- **CRLF Injection in `--proxy-header` allows extra HTTP headers (CWE-93)** — `#3133379` · curl · $0 · ▲42

  > There is a bug in `curl` where a user can inject new HTTP headers into a proxy request by using special characters in the `--proxy-header` option.

- **[m.airbnb.com] CRLF Injection** — `#197279` · Airbnb · $2,500 · ▲37

  > By using a URL-escaped character sequence, bobrov was able to inject HTTP headers into the responses of some redirects on the m.airbnb.com domain.

- **Host Header injection in oslo.io (using X-Forwarded-For header) leading to email spoofing** — `#1072277` · Logitech · $0 · ▲37

  > https://portswigger.net/web-security/host-header

- **Subdomain Takeover via Host Header Injection on www.█████** — `#2188240` · U.S. Dept Of Defense · $0 · ▲35

  > `curl -skS https://www.███████ --header "Host: ███.netlify.app"`

- **CRLF injection on www.starbucks.com** — `#858650` · Starbucks · $0 · ▲34

  > curl -i 'https://www.starbucks.com/email-prospecttg9wh%0d%0aset-cookie:foo%0d%0a%0d%0a4t6uf?requesturl=/responsibility/global-report/policies' -d 'newsletter signup email=&newsletter signup zipcode=&newsletter placement=footer' --http1.1

- **Host header injection that bypassed protection and allowed accessing multiple subdomains** — `#1783015` · Urban Company · $500 · ▲33

  > Areas affected: [App/ Website + URL/Location] https://www.urbancompany.com and it allowed accessing otherwise inaccessible subdomains https://av.urbancompany.com , https://ims.urbancompany.com , https://mesh.urbancompany.com

- **CRLF and XSS stored on ton.twitter.com** — `#191380` · X / xAI · $1,680 · ▲32

  > https://ton.twitter.com/1.1/ton/data/dm/809353163740483587/809353151434330112/O5hEYiOt.jpg%2523.html%E5%98%8A%E5%98%8Dset-cookie%3A%20auth…

- **CRLF INJECTION** — `#1038594` · U.S. General Services Administration · $0 · ▲32

  > Vulnerable url - https://www.epay.fas.gsa.gov/%0D%0ASet-Cookie:crlfinjection=crlfinjection

- **SSL options ISSUERCERT, EC_CURVES and CRLFILE silently ignored by non-OpenSSL backends** — `#3516974` · curl · $0 · ▲31

  > The bugs affect both libcurl applications (via `curl easy setopt()`) and curl command line users (via `--curves` and `--crlfile` flags).

- **ZMQ RPC Log Injection and Untrusted Payload Persistence** — `#3621606` · Monero · $0 · ▲30

  > Introduction point: commit 77986023c3 in src/rpc/daemon handler.cpp (`MDEBUG("Handling RPC request: " << request);`).

- **HTTP Response Splitting (CRLF injection) due to headers overflow** — `#53843` · X / xAI · $0 · ▲30

  > I would like to report another HTTP Response Splitting vulnerability caused by header fields "overflow" that allows attackers to inject arbitrary headers in the response.

- **SMTP Command Injection in Appointment Emails via Newlines** — `#1509216` · Nextcloud · $0 · ▲27

  > Next, a confirmation email with a confirmation link is sent to the user who booked the slot via `/var/www/nextcloud/apps/calendar/lib/Service/Appointments/BookingService.php` using the SMTP connection.

- **Host Header Injection** — `#1098948` · Kartpay · $0 · ▲27

  > For example Joomla used to write Host header to every page without HTML Encoding like this: <link href=”http:// SERVER['HOST']” which led to cross site scripting.

- **Reflected XSS using Header Injection** — `#297203` · Semrush · $0 · ▲25

  > GET /billing-admin/profile/subscription/?l=de HTTP/1.1

- **HTTP/3 Protocol Smuggling and Header Injection via CRLF in QPACK value conversion** — `#3479203` · curl · $0 · ▲24

  > Pollution of `curl easy header` API: Applications using the structured headers API to copy headers from one request to another will unwittingly propagate the malicious payload, spreading the attack deeper into internal networks.

- **CRLF Injection at vpn.bitstrips.com** — `#237357` · Snapchat · $0 · ▲24

  > As can be seen in the response, the server will issue a Set-Cookie header with an arbitrary value and that cookie will be set on the client.

- **SMTP header injection via C-escape `\r` in the recipient display name** — `#3913007` · Nextcloud · $0 · ▲23

  > `$headers['To']`; `:384` hands it to `Mail mime`; `program/lib/Roundcube/rcube.php:1802`

- **[newscdn.starbucks.com] CRLF Injection, XSS** — `#192749` · Starbucks · $0 · ▲23

  > After sending the request through FireFox this query is saved in cache and using a small trick can be made to work it in another browser.

- **SMTP Command Injection in iCalendar Attachments to Emails via Newlines** — `#1516377` · Nextcloud · $0 · ▲22

  > Setup `/var/www/nextcloud/3rdparty/swiftmailer/swiftmailer/lib/classes/Swift/Transport/AbstractSmtpTransport.php` to log SMTP commands.



## Case studies



### CRLF injection

`#446271` · X / xAI · $0 · medium · 2019-12-25 · ▲439

> Hello twiiter security team, on the domain ads.twitter.com http response splitting is vulnerability. PoC: https://ads.twitter.com/subscriptions/mobile/landing?ref=gl-tw-tw-promote-mode?t=%0d%0atest:tested Impact an attacker can set new header



### CRLF Injection in urllib

`#590020` · Internet Bug Bounty · $1,000 · medium · 2020-05-06 · ▲341

> Hi. I found CRLF Injection a few months ago. Please refer my bug issue. https://bugs.python.org/issue35906 Thank you Impact lead to SSRF. e.g. can exploit a internal redis server to send arbitrary packet data including ascii and non-ascii.



### HTTP Response Header Injection in shopify/pitchfork + Rack 3

`#2279572` · Shopify · $800 · low · 2025-03-27 · ▲136

> I have confirmed HTTP response header injection and XSS in combination of pitchfork + Rack 3. Here's where the problem is in the code. https://github.com/Shopify/pitchfork/blob/v0.10.0/lib/pitchfork/http response.rb L23C1-L33C8 When using Rack 3, \n contained in value will be displayed as is in the output.



### CRLF injection leads to internal XSS on PangleGlobal

`#2189960` · TikTok · $0 · medium · 2023-10-31 · ▲97

> A cross-site scripting vulnerability was found on a Pangle endpoint due to CRLF injection on the 'file name' parameter. This was caused by the reflection of user-supplied data without appropriate HTML escaping or output encoding and could have resulted in a JavaScript payload being injected into the above endpoint and executed within the context of the another user's browser. This vulnerability has been resolved.



### CRLF to XSS & Open Redirection

`#2012519` · TikTok · $0 · high · 2023-08-16 · ▲97

> Due to inadequate input validation, it could have been possible to inject CRLF (HTTP Response Splitting) into the parameter " hack redirect now " on a TikTok seller endpoint. This could have led to Reflective XSS (Cross-Site Scripting) to gain access to a user's cookies, or the ability to send users to unauthorized webpages ending in "tiktok.com" via an open redirect. This vulnerability has been resolved.



## Query the corpus



```sh

python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class crlf-injection --limit 20

python3 ~/.local/share/hackerone-reports/h1.py stats --class crlf-injection

python3 ~/.local/share/hackerone-reports/h1.py show <id> --full

```



Search by technology, endpoint, parameter, or program. Examples:



```sh

python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class crlf-injection

python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class crlf-injection --min-bounty 1000

```
