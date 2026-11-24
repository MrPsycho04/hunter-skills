# Evidence appendix — Cross-Site Request Forgery

Mined from all **541 valid disclosed reports** for this class (93 paid, 17% — payment is not validity).

## Technique frequency (all valid writeups)

| Item | Count |
|---|---:|
| encoding / double-encode / null byte | 83 |
| Content-Type / body-format switch | 78 |
| header injection (Host / X-Forwarded / etc.) | 73 |
| intercept & replay request in Burp | 56 |
| two-account / cross-account replay | 52 |
| XML / SOAP / SAML / XXE | 50 |
| HTTP method / verb tampering | 49 |
| DOM / HTML source inspection | 46 |
| admin / privileged-role context | 44 |
| file upload / filename / extension | 41 |
| cache / CDN / unkeyed header | 36 |
| webhook / OAuth / SAML / integration abuse | 32 |
| public source-code / repo review | 22 |
| subdomain / DNS / cert-transparency recon | 22 |
|  HosT/absolute-URL reset poisoning | 20 |
| redirect chain / Location header | 17 |
| internal service / port / container | 16 |
| unauthenticated / removed-cookie test | 14 |
| OAST / DNS / HTTP callback proof | 12 |
| second-order / stored / blind delivery | 12 |
| JWT / token / base64 decode | 11 |
| parameter pollution / duplicate keys | 8 |
| swap object ID / parameter value | 7 |
| employee / developer public info | 7 |
| fuzzing / wordlist brute force | 7 |
| third-party data / paste / breach reuse | 6 |
| cloud metadata / IAM abuse | 5 |
| WAF / sanitizer / filter bypass | 5 |
| browser DevTools / network tab | 4 |
| replay / modify a captured request | 4 |
| error message / stack trace probing | 4 |
| verbose debug / framework fingerprint | 3 |
| parser confusion / normalization | 3 |
| race / concurrency / timing | 3 |
| JS bundle / source-map inspection | 2 |
| API docs / Swagger / introspection | 2 |
| mass assignment / extra request fields | 2 |
| template injection (SSTI) | 2 |
| response diff / status / length comparison | 1 |
| public bucket / storage exposure | 1 |
| git history / exposed .git | 1 |
| search-engine dorking | 1 |

## Tools mentioned

| Item | Count |
|---|---:|
| browser | 86 |
| burp | 52 |
| devtools | 42 |
| source-code-review | 20 |
| burp-repeater | 6 |
| curl | 5 |
| burp-intruder | 3 |
| javascript-debugging | 3 |
| python | 2 |
| beautifier | 1 |
| nmap | 1 |
| git | 1 |

## Bypass primitives

| Item | Count |
|---|---:|
| content-type | 132 |
| bypass | 45 |
| open redirect | 13 |
| bypassing | 12 |
| bypassed | 8 |
| same-site | 7 |
| content type | 4 |
| url encoded | 4 |
| %00 | 2 |
| bypasses | 2 |
| double slash | 2 |
| blind | 2 |
| http method | 2 |
| %0d%0a | 1 |
| bypassable | 1 |
| bypasss | 1 |
| transfer-encoding | 1 |
| chunked | 1 |
| null value | 1 |
| normalize | 1 |
| uppercase | 1 |
| url-encode | 1 |
| url-encoded | 1 |
| null byte | 1 |
| same site | 1 |

## Impact language

| Item | Count |
|---|---:|
| token | 671 |
| password | 282 |
| admin | 147 |
| account takeover | 43 |
| payment | 39 |
| localhost | 22 |
| credential | 22 |
| unauthorized | 19 |
| secret | 16 |
| sensitive information | 11 |
| rce | 4 |
| full access | 3 |
| api key | 3 |
| privilege escalation | 3 |
| exfiltrate | 2 |
| arbitrary file | 2 |
| funds | 2 |
| financial | 1 |
| ato | 1 |
| sensitive data | 1 |

## Parameters observed

| Item | Count |
|---|---:|
| type | 299 |
| name | 282 |
| value | 277 |
| action | 64 |
| class | 58 |
| method | 54 |
| domain | 42 |
| src | 21 |
| charset | 20 |
| max-age | 12 |
| utmcsr | 12 |
| utmccn | 12 |
| utmcmd | 12 |
| __utmz | 10 |
| path | 10 |
| href | 9 |
| samesite | 9 |
| csrftoken | 8 |
| token | 8 |
| email | 8 |
| placeholder | 7 |
| utmcct | 7 |
| param1 | 7 |
| json | 7 |
| rel | 6 |
| param2 | 6 |
| __utma | 6 |
| password | 6 |
| _ga | 5 |
| enctype | 5 |

## Recurring approach patterns

- **5×** with a little help of social engineering like sending a link via email chat an attacker may trick the users of a web application into executing actions of the attacker s choosing
  - e.g. With a little help of social engineering (like sending a link via email/chat), an attacker may trick the users of a web application into executing actions of the attacker's choosing.
- **2×** korprit was able to demonstrate this vulnerability by crafting a specially formatted webpage
  - e.g. @korprit was able to demonstrate this vulnerability by crafting a specially formatted webpage.
- **2×** description during my search in this domain i found it vulnerable to csrf so i tried to escalate it account takeover and i succeed impact account takeover via csrf system host s affected product s and version s cve numbers steps to reproduce vulnerable domain and endpoint
  - e.g. **Description:** During my search in this domain I found it vulnerable to CSRF so I tried to escalate it Account takeover and I succeed ## Impact Account takeover via CSRF ## System Host(s) ███████ ## Affected Product(s) and Version(s) ## CVE Numbers ## Steps to Reproduce Vulnerable domain and endpo
- **1×** hi i have found a flash content type sniff vulnerability could allow attackers get user s team auth2 tokens
  - e.g. Hi, I have found a flash content type sniff vulnerability could allow attackers get user's team auth2 tokens.
- **1×** link while approving and reviewing a phrase you are able to send set a message
  - e.g. Link: while approving and reviewing a phrase, you are able to send/set a message.
- **1×** an attacker would need to guess the order id by sending some a lot of requests
  - e.g. An attacker would need to guess the order ID by sending some (a lot of) requests.
- **1×** i am security researcher and i pen test your website and i found there is click jacking attack and csrf attack can be done
  - e.g. i am security researcher and i pen test your website( and i found there is click jacking attack and CSRF attack can be done.
- **1×** to achieve the same session token is not verified while changing account setting s which result in account takeover description i have found that while changing setting session token is not verified so an attacker can basically plot a csrf attack which would change the default email of the user and this would led to account takeover
  - e.g. To achieve the same, Session Token is not Verified while changing Account Setting's which Result In account Takeover Description:- I have found that while changing Setting Session token is not verified .So an attacker can basically plot a CSRF attack which would change the default email of the user 
- **1×** hey there i found out that an attacker can use the password reset link to forge requests because there is no csrf token in that particular request to validate that request
  - e.g. Hey there I found out that an attacker can use the password reset link to forge requests because there is no CSRF token in that particular request to validate that request.
- **1×** hello i m not sure it s intentional or somehow you missed it i noticed that when user follow people on vimeo csrf token of the request doesn t change at all
  - e.g. Hello, i'm not sure it's intentional or somehow you missed it, I noticed that when User follow people on Vimeo, CSRF token of the request doesn't change at all.
- **1×** brief i have discovered a way to issue api calls on behalf of other users
  - e.g. **Brief** I have discovered a way to issue API calls on behalf of other users.
- **1×** i have only created a proof of concept for safari tested on newest version on osx but there is a big chance that this is possible from other browsers and other plugins too
  - e.g. I have only created a proof-of-concept for Safari (tested on newest version on OSX), but there is a big chance that this is possible from other browsers (and other plugins) too.
- **1×** during research of vimeo com i found that you are using anti csrf token against csrf attack
  - e.g. During research of vimeo.com I found that you are using anti-csrf token against csrf attack.
- **1×** hi i have noticed that when the account verification fails here due to an error the csrf token is being leaked via get method like so the authenticity token is being stored in the web browser history and can be retrieved by a malicious attacker in order to mount a successful csrf attack against the victim
  - e.g. Hi, I have noticed that when the account verification fails here : due to an error, the CSRF token is being leaked via GET method like : So the authenticity token is being stored in the web browser history and can be retrieved by a malicious attacker in order to mount a successful CSRF attack agains
- **1×** while testing website i have found interesting issue
  - e.g. While testing website i have found interesting issue.
- **1×** hello i found a info disclosure vulnerability
  - e.g. Hello, I found a info disclosure vulnerability.
- **1×** and i found that id is id is id is id is i attached photos from burp repeater to be more explicit
  - e.g. And I found that : >ID 1 is ██████ ID 514755 is ████████ ID 514775 is █████ ID 514764 is ███████ I attached photos from burp repeater to be more explicit.
- **1×** here was my initial email hello i ve been playing with getting rails apps to send csrf tokens to the wrong domains and i found a few problems
  - e.g. Here was my initial email: > Hello, > I've been playing with getting Rails apps to send CSRF tokens to the wrong domains and I found a few problems.
- **1×** vulnerability description the application unifi v3 uses json requests to add edit save delete configuration options on the administrative web interface but the application has an insufficient cross site request forgery protection in place by only checking whether the referer header is present and if its actual value matches the host where the system is running default
  - e.g. VULNERABILITY DESCRIPTION ----------- The application UniFi v3.2.10 uses JSON requests to add/edit/save/delete configuration options on the administrative web-interface, but the application has an insufficient Cross-Site Request Forgery protection in place by only checking whether the Referer Header
- **1×** this could be done using vimeo api i used the access token of ios vimeo app an attacker could remotely add and delete the videos in watchlater list of any user with out any permission of user
  - e.g. This could be done using vimeo api .I used the access token of IOS vimeo app .An attacker could remotely add and delete the videos in watchlater list of any user with out any permission of user.
- **1×** hey guys i just found an csrf token fixation in facebook store app which is an offical shopify app link the csrf bug which connects attacker s facebook account to victim s shopify account
  - e.g. hey guys i just found an csrf token fixation in facebook store app which is an offical shopify app link >> The CSRF bug which connects attacker's Facebook account to victim's shopify account.
- **1×** now if we open the products page we can see the product status changed
  - e.g. Now if we open the [products page]( we can see the product status changed.
- **1×** to prevent this the application should first check to see if the url specified is a valid image extension before sending the actual get request to the remote site
  - e.g. To prevent this, the application should first check to see if the URL specified is a valid image extension before sending the actual GET request to the remote site.
- **1×** hi i m found bug csrf it is possible to add album by attacker on onpatient com steps to verify
  - e.g. **Hi** I'm Found Bug CSRF It is Possible To Add Album By Attacker on onpatient.com Steps to verify ---- * .

## Case studies (full excerpts)

### 1497169 — CSRF protection bypass in GitHub Enterprise management console
GitHub · $10000 · high · https://hackerone.com/reports/1497169

A path traversal vulnerability was identified in GitHub Enterprise Server management console that allowed the bypass of CSRF protections. This could potentially lead to privilege escalation. To exploit this vulnerability, an attacker would need to target a user that was actively logged into the management console. This vulnerability affected all versions of GitHub Enterprise Server prior to 3.5 and was fixed in versions 3.1.19, 3.2.11, 3.3.6, 3.4.1. [CVE-2022-23732](

### 2326194 — Argo CD CSRF leads to Kubernetes cluster compromise
Internet Bug Bounty · $4660 · high · https://hackerone.com/reports/2326194

GHSA: It's been publicly known for years that all of Argo CD API is vulnerable to Cross-Site Request Forgery (CSRF). We assume the team haven't made it a priority because of the lack of evidence to support it's a severe vulnerability. Modern browsers implement the Lax SameSite cookie attribute to prevent CSRF, but it is not foolproof. The samesite attribute is rendered useless if the origin is on the same parent domain as the target. We spin up a sample environment with Argo CD v2.8.2 to test this. An attacker controls contents of ​​marketing.victim.com (via Stored XSS, for example) and wants to target argocd.internal.victim.com. The following proof of concept allows the attacker to create a pod with admin privileges on the Kubernetes cluster via Argo CD. This piece of JavaScript is injected on the ​​marketing.victim.com homepage: Where repoURL points to a repository with the yaml definition like: Then wait. An employee logged-in to argocd.internal.victim.com, when visiting marketing.victim.com, will lead to Kubernetes cluster compromise. This is made possible because: - Argo CD does not respect the Content-Type header. If it did, the request would have triggered a preflight CORS request on "application/json" CT and the attack fails. - The attacker needs zero knowledge to craft a valid json. The cluster location, project name… are available by default. ## Impact Kubernetes clus

### 450796 — XSSI on refer.xoom.com allows stealing email addresses and posting to Twitter on behalf of victim
PayPal · $3500 · medium · https://hackerone.com/reports/450796

Due to a cross-origin configuration, the application at refer.xoom.com could be embedded in script tags on other websites. If a malicious site were open in the same browser as refer.xoom.com, the malicious site could see and extract data from the referral page. This included the email addresses being used and, in extreme cases, tokens allowing Xoom access to post on a user’s Twitter. Any Twitter activity was limited, clearly marked as posted by Xoom, and could be mitigated by the user at any time by deauthorizing access. This did not affect any session or financial data and was limited to the referral page.

### 1122408 — CSRF on /api/graphql allows executing mutations through GET requests
GitLab · $3370 · high · https://hackerone.com/reports/1122408

Mutations are `edit` or `create` queries used in Graphql. Gitlab prevents CSRF in this functionality by sending a POST request with a X-CSRF-Token header. The bug I found here was that, when we send a GET request, the backend does not expect the X-CSRF-Token header. Using this, an attacker could leverage this to bypass the existing CSRF protection ### Code for Testing This exploit would create a snippet named `Tesssst Snippet` on the user's account. ### Steps to Reproduce 1. Host this file 2. Login to gitlab 3. Open the link to that html 4. Check the snippets for the logged in user. ### Impact The attacker could control bypass the existing CSRF check on the graphql endpoint. ### POC Attached the request and response screenshot ### What is the expected *correct* behavior? The backend must check the existence of csrf tokens for GET requests as well. ## Impact The attacker could control bypass the existing CSRF check on the graphql endpoint.

### 805073 — Periscope iOS app CSRF in follow action due to deeplink
X / xAI · $2940 · low · https://hackerone.com/reports/805073

Summary This issue is mainly in the Periscope iOS app against CSRF follow action using deeplink. as the report #583987 the CSRF work on iOS app POC 1 QR code to follow periscope profile `pscp://user/periscopeco/follow ` ███████ POC2 by kunal94 video █████████ ## Impact CSRF Follow against any user in periscope iOS app

### 1010522 — [CSRF] TikTok Careers Portal Account Takeover
TikTok · no bounty (valid finding) · high · https://hackerone.com/reports/1010522

A missing CSRF protection and open redirect vulnerability was reported in the TikTok Careers portal single sign on flow which is used by applicants to apply for TikTok positions. This flaw was quickly remediated and does not impact TikTok.com or mobile application. We thank @lauritz for reporting this vulnerability to our team and for confirming the resolution. I wrote a short [blog post]( that covers this report. If you have any feedback, feel free to ping me at [Twitter]( 🙂

### 807924 — CSRF on connecting Paypal as Payment Provider
Shopify · no bounty (valid finding) · medium · https://hackerone.com/reports/807924

Hi, I think there is a weak csrf protection on adding paypal as the payment provider, but the protection is not good. When user try to add paypal as payment provider, they will make this GET request ` The `merchantId` belongs to your store only, and the base64 decoded value is `1583030504:010f06db85734b485ed095c45af1cfe7` which is obviously too long to brute force, I'll say it is a pretty good way to mitigate CSRF, however there is one catch. This value is fixed, i.e. if someone who previously was an admin of this store before, then he/she can take advantage of this fixed value for CSRF protection, and perfomr CSRF attack on victim to connect victim's payment provider to their Paypal order. Or this value is leaked somewhere, then the store owner is forever vulnerable to CSRF attack ## Steps to reproduce - Visit if there is already paypal account connected, disconnect it first - Then click the link Acitivate paypal express checkout - In the link, jot down the value of merchantId, this merchantId belongs to your store only, in order to connect your store to victim's store, you'll need this parameter, it looks like this `MTU4MzAzMDUwNDowMTBmMDZkYjg1NzM0YjQ4NWVkMDk1YzQ1YWYxY2ZlNw%3D%3D` - Finally, visit this link with merchantId replaced with the value you got from above step (replace YOUTSUBDOMAIN and REPLACEME) ` Here in `5NS8DHQCFGT84` is the attacker's paypal merchant id, so af

## Field playbook (unedited)

### quick

- Find state-changing requests and check for anti-CSRF tokens and SameSite cookies.
- Remove the token, blank it, reuse another session's token, and try a fixed token.
- Try GET, form POST, text/plain JSON, multipart, and method override.
- Check email/password change, OAuth consent, and login CSRF.
- Look for subdomain XSS or cookie scope that enables CSRF.

### payloads

- Form -> `<form action=https://target/email method=POST><input name=email value=attacker@x>`
- JSON -> `<form enctype=text/plain><input name='{"email":"attacker@x","x":"' value='"}'>`
- GET -> `<img src=https://target/settings?email=attacker@x>`
- Method override -> `_method=POST` in a GET/form request

### bypass

- Token not bound to session; token from another account accepted.
- SameSite=Lax bypass via top-level GET or 2-minute window.
- CORS misconfig allowing credentialed cross-origin requests.
- Bypass token check by changing content-type or removing the parameter.

### surface

- email
- password
- change
- delete
- transfer
- invite
- settings
- oauth
- consent

### tools

- Burp CSRF PoC generator
- browser devtools
- mitmproxy

### chain

- CSRF -> email change -> ATO.
- CSRF -> OAuth link -> ATO.
- CSRF + XSS -> worm.

## Corpus search commands

```sh
python3 ~/.local/share/hackerone-reports/h1.py stats --class csrf
python3 ~/.local/share/hackerone-reports/h1.py search "<feature or param>" --class csrf --limit 10
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```
