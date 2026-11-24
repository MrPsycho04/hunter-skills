# Evidence appendix — OAuth and OIDC Flaws

Mined from all **40 valid disclosed reports** for this class (8 paid, 20% — payment is not validity).

## Technique frequency (all valid writeups)

| Item | Count |
|---|---:|
| webhook / OAuth / SAML / integration abuse | 15 |
| admin / privileged-role context | 11 |
| internal service / port / container | 9 |
| public source-code / repo review | 7 |
| two-account / cross-account replay | 6 |
| redirect chain / Location header | 5 |
| second-order / stored / blind delivery | 4 |
| HTTP method / verb tampering | 3 |
| file upload / filename / extension | 3 |
| git history / exposed .git | 3 |
| WAF / sanitizer / filter bypass | 3 |
|  HosT/absolute-URL reset poisoning | 3 |
| XML / SOAP / SAML / XXE | 2 |
| cache / CDN / unkeyed header | 2 |
| header injection (Host / X-Forwarded / etc.) | 2 |
| error message / stack trace probing | 2 |
| JWT / token / base64 decode | 2 |
| subdomain / DNS / cert-transparency recon | 2 |
| swap object ID / parameter value | 1 |
| verbose debug / framework fingerprint | 1 |
| Content-Type / body-format switch | 1 |
| DOM / HTML source inspection | 1 |
| encoding / double-encode / null byte | 1 |
| fuzzing / wordlist brute force | 1 |
| race / concurrency / timing | 1 |
| mass assignment / extra request fields | 1 |

## Tools mentioned

| Item | Count |
|---|---:|
| curl | 9 |
| source-code-review | 7 |
| python | 4 |
| git | 3 |
| browser | 2 |
| devtools | 1 |

## Bypass primitives

| Item | Count |
|---|---:|
| bypass | 10 |
| bypasses | 6 |
| bypassing | 4 |
| blind | 3 |
| open redirect | 2 |
| content-type | 2 |
| bypassed | 2 |
| allowlist | 2 |
| %0d%0a | 1 |

## Impact language

| Item | Count |
|---|---:|
| password | 88 |
| token | 61 |
| admin | 46 |
| credential | 41 |
| secret | 18 |
| remote code execution | 6 |
| unauthorized | 4 |
| account takeover | 3 |
| localhost | 3 |
| sensitive information | 2 |
| full access | 1 |
| sensitive data | 1 |

## Parameters observed

| Item | Count |
|---|---:|
| realm | 6 |
| nonce | 6 |
| algorithm | 4 |
| domain | 4 |
| x01host | 3 |
| res | 3 |
| code | 3 |
| host | 2 |
| curlopt_proxyport | 2 |
| username | 2 |
| uri | 2 |
| response | 2 |
| redirect_url | 1 |
| voice | 1 |
| url | 1 |
| user[soh]host | 1 |
| soh]host | 1 |
| soh]port | 1 |
| soh]auth | 1 |
| req1_res | 1 |
| req2_res | 1 |
| digest_fresh_second | 1 |
| matches_host | 1 |
| bxl1c2vyom15cgfzcw | 1 |

## Recurring approach patterns

- **1×** hi i noticed that the redirect uri used to redirect users to any location on the page passes in all data into a header location without any validation
  - e.g. Hi, I noticed that the `redirect_uri` used to redirect users to any location on the page, passes in all data into a `header("Location..` without any validation.
- **1×** hi i found that you are using a weak password policy
  - e.g. Hi, I found that you are using a weak password policy!
- **1×** done ps the same occurs when you intercept no photo option ps2 i could not execute code through this but i thought it was a valid report because i tried to upload txt files in upload photo options and it was not allowed
  - e.g. Done Ps: The same occurs when you intercept "no photo" option Ps2: I could not execute code through this, but i thought it was a valid report because i tried to upload .txt files in "upload photo" options and it was not allowed.
- **1×** i found a way to confirm arbitrary emails and after confirming arbitrary email in myshopify com user is able to integrate with other shopify store that shares the same email address by setting a master password for all of the stores if the owner hasn t integrated before effectively taking over every shopify stores by knowing just the owner s email address
  - e.g. I found a way to confirm arbitrary emails, and after confirming arbitrary email in *.myshopify.com, user is able to **integrate** with other Shopify store that shares the same email address by setting a master password for all of the stores(if the owner hasn't integrated before), effectively taking 
- **1×** what happened in was i was too excited and didn t take a step further to try to takeover merchant s account even they have sso setup and after reading the comment an important mitigating factor was that this bug only affected user accounts which had not yet adopted our single login system
  - e.g. What happened in #791775 was, I was too excited and didn't take a step further to try to takeover merchant's account even they have SSO setup, and after reading the comment `An important mitigating factor was that this bug only affected user accounts which had not yet adopted our single login system
- **1×** users sso provider accounts remain secure and after that cache period of up to hour any user attempting to sign in with sso will be required to reauthorize courier s oauth application before logging in successfully again
  - e.g. Users' SSO provider accounts remain 100% secure and after that cache period of up to 1 hour, any user attempting to sign in with SSO will be required to reauthorize Courier's OAuth application before logging in successfully again.
- **1×** there is nothing stopping a rogue application from hijacking your deep link by also registering to the same scheme and then obtaining access to the data your link contains
  - e.g. There is nothing stopping a rogue application from hijacking your deep link by also registering to the same scheme and then obtaining access to the data your link contains.
- **1×** i created a malicious android app which is able to intercept the authorization code see poc
  - e.g. I created a malicious Android app which is able to intercept the authorization code (see PoC).
- **1×** i have discovered that it is possible to bypass this restriction
  - e.g. I have discovered that it is possible to bypass this restriction.
- **1×** during my testing the restriction on oauth token is being voided once the victim authenticates and completes the email verification regardless of the ip difference between the attacker and the victim
  - e.g. During my testing, the restriction on `/oauth/token` is being voided once the victim authenticates and completes the email verification regardless of the IP difference between the attacker and the victim.
- **1×** browser os and or app version used during testing firefox browser bit windows
  - e.g. - Browser, OS and/or app version used during testing: Firefox Browser 140.0.2 (64-bit), Windows.
- **1×** summary i found an incomplete fix variant of cve in curl
  - e.g. ## Summary: I found an incomplete-fix variant of CVE-2026-7168 in curl 8.20.0.
- **1×** i checked the claims against the curl production source reproduced both option paths on two independent sanitizer enabled builds and reviewed public curl issues and advisories for duplicates
  - e.g. I checked the claims against the curl 8.22.0 production source, reproduced both option paths on two independent sanitizer-enabled builds, and reviewed public curl issues and advisories for duplicates.

## Case studies (full excerpts)

### 3423013 — page.line.me Open Redirect Leading to OAuth Authorization Code Exposure and Access Token Compromise
LY Corporation · $1000 · high · https://hackerone.com/reports/3423013

An open redirect vulnerability was identified in page.line.me because redirect destinations were not properly restricted to trusted domains. By abusing this behavior within an OAuth 2.0 authorization flow, an attacker could cause the authorization response to be sent to an attacker-controlled endpoint. This could expose the authorization code issued after successful user authentication, which may then be exchanged for a valid access token. As a result, the vulnerability could lead to unauthorized access to the victim’s account, allowing an attacker to perform actions with the victim’s privileges.

### 1700734 — Shop App - Attacker is able to intercept authorization code during authentication (OAuth) and is able to get access to Microsoft Outlook email account
Shopify · $900 · low · https://hackerone.com/reports/1700734

## Summary: ### Deep linking Mobile apps have a unique vulnerability that is non-existent in the web: deep linking. Deep linking is a way of sending data directly to a native application from an outside source. A deep link looks like app:// where app is your app scheme and anything following the // could be used internally to handle the request. Deep links are NOT secure and you should never send any sensitive information in them. The reason deep links are not secure is because there is no centralized method of registering URL schemes. As an application developer, you can use almost any url scheme you choose by configuring it in Xcode for iOS or adding an intent on Android. There is nothing stopping a rogue application from hijacking your deep link by also registering to the same scheme and then obtaining access to the data your link contains. ### Shop app - Microsoft Outlook Oauth flow and the vulnerability The **Shop App** allows users to connect to their Microsoft Outlook account to import orders from the emails (via OAuth flow). Therefore, the custom url scheme `shopapp://` is used for transmitting the authorization code at the end of the Oauth flow to the Shop App, which finally can be used to exchange the the authorization code with a valid session token from Microsoft. Another (malicious) app is also able to claim the **same url scheme** and can intercept the authorizati

### 107877 — API: Bug in method auth.signup , дающий возможность бесконечно звонить
VK.com · $500 · severity n/a · https://hackerone.com/reports/107877

Отсутствие flood-контроля в api методе регистрации, что давало возможность отправлять массово смс или звонить на произвольный номер. В API Найдена уязвимость дающая бесконечно звонить и слать смс , лимит запросов можно было обойти. (найдена практически такая же уязвимость , как и в репорте ДАЮЩАЯ БЕСКОНЕЧНО ЗВОНИТЬ , но тут выплата 300$ , а там 500$) На вопрос почему так ? - ответа не последовало. UPD , ПЕРЕСМОТРЕЛИ НАГРАДУ ПЕРЕД ОТКРЫТИЕМ РЕПОРТА ПУБЛИЧНО i die ███████████████████████████ ███████▀▀▀░░░░░░░▀▀▀███████ ████▀░░░░░░░░░░░░░░░░░▀████ ███│░░░░░░░░░░░░░░░░░░░│███ ██▌│░░░░░░░░░░░░░░░░░░░│▐██ ██░└┐░░░░░░░░░░░░░░░░░┌┘░██ ██░░└┐░░░░░░░░░░░░░░░┌┘░░██ ██░░┌┘▄▄▄▄▄░░░░░▄▄▄▄▄└┐░░██ ██▌░│██████▌░░░▐██████│░▐██ ███░│▐███▀▀░░▄░░▀▀███▌│░███ ██▀─┘░░░░░░░▐█▌░░░░░░░└─▀██ ██▄░░░▄▄▄▓░░▀█▀░░▓▄▄▄░░░▄██ ████▄─┘██▌░░░░░░░▐██└─▄████ █████░░▐█─┬┬┬┬┬┬┬─█▌░░█████ ████▌░░░▀┬┼┼┼┼┼┼┼┬▀░░░▐████ █████▄░░░└┴┴┴┴┴┴┴┘░░░▄█████ ███████▄░░░░░░░░░░░▄███████ ██████████▄▄▄▄▄▄▄██████████ ███████████████████████████

### 1551591 — CVE-2022-27776: Auth/cookie leak on redirect
Internet Bug Bounty · $480 · low · https://hackerone.com/reports/1551591

## Summary: curl/libcurl can be coaxed to leak Authorization / Cookie headers by redirecting request to http:// URL on the same host. Successful exploitation requires that the attacker can either Man-in-the-Middle the connection or can access the traffic at the recipient side (for example by redirecting to a non-privileged port such as 9999 on the same host). ## Steps To Reproduce: 1. Configure for example Apache2 to perform redirect with mod_rewrite: ... the attacker could also use `.htpasswd` file to do so. 2. Set up netcat to listen for the incoming secrets: `while true; do echo -ne 'HTTP/1.1 404 nope\r\nContent-Length: 0\r\n\r\n' | nc -v -l -p 9999; done` 3. `curl-L -H "Authorization: secrettoken" -H "Cookie: secretcookie" The redirect will be followed, and the confidential headers sent over insecure HTTP to the specified port: The attack could also use HTTPS and a valid certificate, In this case the leaked headers are of course only be visible to the listening http server. This vulnerability is quite similar to `CVE-2022-27774` and the fix is similar too: If the protocol or port number differs from the original request strip the Authorization and Cookie headers. This bug appears to be at: - - ## Impact Leak of Authorization and/or Cookie headers.

### 1784162 — OAuth2 "authorization_code" is valid indefinetly
Nextcloud · $100 · low · https://hackerone.com/reports/1784162

Your OAuth2 endpoint is not at all following best practices. When the authorization_code is generated it is stored without a timeout. Now according to 10 minutes is recommended. As the goal is that is gets used almost directly or not at all. Now there is a debate maybe to have on the 10 minutes. But there is kind of a big difference between 10 minutes and no timeout at all. ## Impact An attacker that obtains this code could possibly easily redeem it in the future. Or an attacker could just keep trying codes.

### 791775 — Email Confirmation Bypass in myshop.myshopify.com that Leads to Full Privilege Escalation to Any Shop Owner by Taking Advantage of the Shopify SSO
Shopify · no bounty (valid finding) · critical · https://hackerone.com/reports/791775

I told Pete I would take a look at Spotify, hi Pete. ## Summary It's possible to take over any store account through bypassing the email confirmation step in *.myshopify.com. I found a way to confirm arbitrary emails, and after confirming arbitrary email in *.myshopify.com, user is able to **integrate** with other Shopify store that shares the same email address by setting a master password for all of the stores(if the owner hasn't integrated before), effectively taking over every Shopify stores by knowing just the owner's email address. After signing up a new Shopify instance in and start the free trial, user can change their email address to a new email address before confirming the one they used to sign up. The bug is that Shopify email system mistakenly send the confirmation link of the new email address, to the one that is used to signed up. And the result is user can confirm arbitrary email address. And the next step is taking over other user's Shopify instance by taking advantage of the SSO. ## Quick check If you check and see the email address of the owner, it is ngalog@hackerone.com, which I obviously would never be able to validate otherwise {F711349} ## steps to reproduce - Visit and signup a free trial with an email address, say attacker@gmail.com that you can receive emails - after entering the fields to enter the store, on top right corner, click your name and go 

### 796956 — Able to Takeover Merchants Accounts Even They Have Already Setup SSO, After Bypassing the Email Confirmation
Shopify · no bounty (valid finding) · medium · https://hackerone.com/reports/796956

Able to Takeover Merchants Accounts Even They Have Already Setup SSO, After Bypassing the Email Confirmation ## Summary This report is based on the scenario that email confirmation has been bypassed already, like shown in #791775. What happened in #791775 was, I was too excited and didn't take a step further to try to takeover merchant's account even they have SSO setup, and after reading the comment `An important mitigating factor was that this bug only affected user accounts which had not yet adopted our single login system. `, I know I have to find a way to bypass that to prove my point. ## Description For merchant that have accounts already setup SSO, even attacker has bypassed the email confirmation, they would have no ways to takeover the rest of the accounts of the merchant, because they will need to enter the master password of the merchant in the process of merging accounts. Let me illustrate this in graphs, in this example, the merchant that has SSO already setup is `ngalog+1@wearehackerone.com`, the attacker sign-up a store h48ngalog.myshopify.com, with email `ngalog+1@wearehackeorne.com` Stage 1. First, for whatever reason, maybe a new feature appeared that allows attacker to bypass email confirmation again or an old bug bypass, that as an attacker with ngalog+1@wearehackerone.com confirmed, he should see this in the shop {F716958} Stage 2. Then, when attacker click

## Field playbook (unedited)

### quick

- Test redirect_uri: suffix, path traversal, open redirect, localhost, custom schemes.
- Test state for CSRF and missing binding to the session.
- Try code reuse, code swapping between clients, and PKCE downgrade.
- Check account linking for takeover via unverified email or provider mixups.

### payloads

- `redirect_uri=https://target.com.evil.com` `redirect_uri=https://target.com%2f@evil.com`
- `redirect_uri=https://target.com/callback/../../evil`
- `response_type=token` `scope=openid profile email`
- `state=` empty/reused; `nonce=` missing

### bypass

- Open redirect on an allowlisted callback domain.
- Exploit parser differences in redirect_uri validation.
- Reuse authorization codes across clients or after use.

### surface

- redirect_uri
- state
- nonce
- code
- client_id
- scope
- response_type

### tools

- Burp
- oauth-misconfig
- jwt_tool

### chain

- OAuth redirect -> token theft -> ATO.
- Account linking -> ATO.

## Corpus search commands

```sh
python3 ~/.local/share/hackerone-reports/h1.py stats --class oauth-oidc
python3 ~/.local/share/hackerone-reports/h1.py search "<feature or param>" --class oauth-oidc --limit 10
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```
