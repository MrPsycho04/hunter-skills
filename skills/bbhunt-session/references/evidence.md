# Evidence appendix — Session Management Flaws

Mined from all **112 valid disclosed reports** for this class (18 paid, 16% — payment is not validity).

## Technique frequency (all valid writeups)

| Item | Count |
|---|---:|
| unauthenticated / removed-cookie test | 14 |
| admin / privileged-role context | 14 |
|  HosT/absolute-URL reset poisoning | 13 |
| cache / CDN / unkeyed header | 11 |
| encoding / double-encode / null byte | 10 |
| second-order / stored / blind delivery | 9 |
| header injection (Host / X-Forwarded / etc.) | 9 |
| HTTP method / verb tampering | 9 |
| race / concurrency / timing | 9 |
| public source-code / repo review | 8 |
| two-account / cross-account replay | 8 |
| intercept & replay request in Burp | 7 |
| Content-Type / body-format switch | 7 |
| OAST / DNS / HTTP callback proof | 6 |
| internal service / port / container | 6 |
| third-party data / paste / breach reuse | 5 |
| webhook / OAuth / SAML / integration abuse | 5 |
| file upload / filename / extension | 5 |
| replay / modify a captured request | 4 |
| cloud metadata / IAM abuse | 4 |
| fuzzing / wordlist brute force | 4 |
| subdomain / DNS / cert-transparency recon | 3 |
| deserialization / gadget chain | 2 |
| swap object ID / parameter value | 2 |
| response diff / status / length comparison | 2 |
| API docs / Swagger / introspection | 2 |
| employee / developer public info | 2 |
| XML / SOAP / SAML / XXE | 2 |
| template injection (SSTI) | 2 |
| DOM / HTML source inspection | 2 |
| browser DevTools / network tab | 1 |
| WAF / sanitizer / filter bypass | 1 |
| verbose debug / framework fingerprint | 1 |
| parameter pollution / duplicate keys | 1 |
| JWT / token / base64 decode | 1 |
| parser confusion / normalization | 1 |

## Tools mentioned

| Item | Count |
|---|---:|
| browser | 19 |
| devtools | 16 |
| burp | 9 |
| source-code-review | 7 |
| curl | 7 |
| burp-repeater | 3 |
| python | 3 |
| zap | 1 |
| javascript-debugging | 1 |
| burp-intruder | 1 |
| burp-collaborator | 1 |
| collaborator/oast | 1 |

## Bypass primitives

| Item | Count |
|---|---:|
| bypass | 13 |
| content-type | 10 |
| bypassing | 4 |
| bypasses | 3 |
| bypassed | 2 |
| whitelist | 1 |

## Impact language

| Item | Count |
|---|---:|
| password | 238 |
| token | 113 |
| credential | 17 |
| admin | 14 |
| unauthorized | 14 |
| full access | 9 |
| sensitive information | 8 |
| localhost | 8 |
| secret | 6 |
| financial | 4 |
| account takeover | 3 |
| payment | 2 |
| data leak | 2 |
| unauthorised | 2 |
| sensitive data | 2 |
| privilege escalation | 1 |
| exfiltrate | 1 |
| api key | 1 |

## Parameters observed

| Item | Count |
|---|---:|
| valid_until | 5 |
| charset | 3 |
| in_header | 3 |
| max-age | 2 |
| rel | 2 |
| curlopt_ssl_verifypeer | 2 |
| rtp_len | 2 |
| size | 2 |
| download_done | 2 |
| state | 2 |
| jsessionid | 1 |
| xsrf-token | 1 |
| src | 1 |
| steps | 1 |
| summary | 1 |
| response | 1 |
| headers | 1 |
| act | 1 |
| hostname | 1 |
| cert | 1 |
| verifyerror | 1 |
| password | 1 |
| browser | 1 |
| chrome] | 1 |
| link | 1 |
| aip | 1 |
| jid | 1 |
| gjid | 1 |
| cid | 1 |
| tid | 1 |

## Recurring approach patterns

- **2×** summary while conducting my researching i discovered that the application failure to invalidate session after password
  - e.g. ## Summary: While conducting my researching I discovered that the application Failure to invalidate session after password.
- **1×** hackerone fails to expire the session cookie from the server side even when the user logs off upon clicking sign out from the application
  - e.g. Hackerone fails to expire the session cookie from the server side even when the user logs off upon clicking "Sign-Out" from the application.
- **1×** to reproduce this vulnerability open chrome and download edit this cookie ad don now open and log in now goto edit this cookie addon and click export all cookies by clicking this we get the cookie copied in clipboard
  - e.g. To reproduce this vulnerability 1.open chrome and download edit this cookie ad-don 2.now open and log in 3.now goto edit this cookie addon and click export all cookies ...by clicking this we get the cookie copied in clipboard..
- **1×** an attacker could exploit this issue by for example tricking a user into clicking on a link to a page with the following html code img src when the user visits the page the browser will send a request to www irccloud com over an unencrypted connection note the http instead of https containing the session cookie
  - e.g. An attacker could exploit this issue by (for example) tricking a user into clicking on a link to a page with the following HTML code: <img src=" When the user visits the page, the browser will send a request to www.irccloud.com, over an unencrypted connection (note the **http** instead of **https**)
- **1×** as a result of this report we rethought how we handled password changes and we decided to invalidate all sessions on a password change reset to protect from this possible problem
  - e.g. As a result of this report, we rethought how we handled password changes, and we decided to invalidate all sessions on a password change/reset to protect from this possible problem.
- **1×** hey i ve found a session management in help nextcloud com which can lead to session takeover
  - e.g. Hey, I've found a session management in help.nextcloud.com, which can lead to session takeover!
- **1×** hi i don t know is it a valid vulnerability under your program but i found it
  - e.g. Hi, I don't know is it a valid vulnerability under your program but I found it.
- **1×** i have found a way to change the value of the cookie this error can be used to leave off the application to a particular user to log on again the attacker would have to cause the victim to visit a particular link
  - e.g. I have found a way to change the value of the cookie, this error can be used to: Leave off the application to a particular user to log on again, the attacker would have to cause the victim to visit a particular link.
- **1×** i observed session tokens remaining valid even hours after being issued
  - e.g. I observed session tokens remaining valid even 72 hours after being issued.
- **1×** authenticate to via the gmail oauth function receiving a valid session cookie from www urbandictionary com and then sign out by clicking
  - e.g. Authenticate to ` via the Gmail OAuth function, receiving a valid session cookie from `www.urbandictionary.com`, and then "sign out" by clicking ` 1.
- **1×** description since the certificate is only valid through herokuapp com the domain is sending a warning message about mitm attacks
  - e.g. # Description Since the certificate is only valid through *.herokuapp.com the domain is sending a warning message about MITM attacks.
- **1×** also i discovered that privilege escalation is possible it is possible to attack another user account in some cases
  - e.g. Also, i discovered, that privilege escalation is possible (it is possible to attack another user account in some cases).
- **1×** the problem is that the cookies stored on the browser are not getting expired after logging out from the platform and from github as well
  - e.g. The problem is that the cookies stored on the browser are not getting expired after logging out from the platform and from Github as well.
- **1×** i found a broken authentitication vuln poc create a account confirm your email now request a password reset for your account
  - e.g. I found a broken authentitication vuln POC: 1- Create a account 2- Confirm your email 3- Now request a password reset for your account.
- **1×** i also did not fully investigate if there is a way to trigger the socket close event with no error which would skip the session eviction and turn this into a reliable bypass
  - e.g. I also did not fully investigate if there is a way to trigger the socket ‘close’ event with no error which would skip the session eviction and turn this into a 100% reliable bypass.
- **1×** hello team i am hemant patidar working as a security researcher and i found a bug in your site
  - e.g. ##Hello Team, I am Hemant Patidar working as a security researcher and I found a bug in your site.
- **1×** report of bug is as follows description while conducting my research i discovered that the application failure to invalidate the session after the password change
  - e.g. Report of bug is as follows:- ##Description: While conducting my research I discovered that the application Failure to invalidate the session after the password change.
- **1×** steps to reproduce add details for how we can reproduce the issue through manual testing only login to your urbancompany account using your mobile number with the otp received
  - e.g. ## Steps To Reproduce: (Add details for how we can reproduce the issue through manual testing only) 1.Login to your UrbanCompany account using your mobile number with the OTP received.
- **1×** while conducting my research i discovered that the application failed to validate session after password change
  - e.g. While conducting my research I discovered that the application Failed to validate session after password change.
- **1×** hi i would like to report session management issue to you while testing i found that we can easily invite or we can easily perform invite related action even we logged out from the the account
  - e.g. Hi, I would like to report session management issue to you, while testing i found that we can easily invite or we can easily perform invite related action, even we logged out from the the account.
- **1×** i didn t checked the other functionality under session management but this can prove the session won t expired after the account admin logout from his account
  - e.g. I didn't checked the other functionality under session management but this can prove the session won't expired after the account admin logout from his account.
- **1×** that time i revoked app access from the old reddit com and i checked my app and as expected i was not able to use the account in my app
  - e.g. That time, I revoked app access from the old.reddit.com and i checked my app and as expected i was not able to use the account in my app.
- **1×** after days i was checking the chat invites feature on the web and after some time i turned on the internet on my mobile and got a reddit invitation accept notification
  - e.g. After 2 days I was checking the chat invites feature on the web and after some time I turned on the internet on my mobile and got a Reddit "invitation accept" notification.
- **1×** i clicked on that and i was surprised that i was able to use the previously revoked user account again in the reddit app
  - e.g. I clicked on that and I was surprised that I was able to use the previously revoked user account again in the Reddit app.

## Case studies (full excerpts)

### 1547684 — Disconnecting an external login provider does not revoke session
Shopify · $1600 · medium · https://hackerone.com/reports/1547684

Hi team, Summary: attacker could create a backdoor using google login function.if an attacker stole the login password of victims throught any means. attacker could connect his/her google account and create a backdoor and attacker login with google if the victim disconnect attacker session did not expire and still get access beacuse of no session expire after disconnected with google account .attacker could still connect his google account again. Steps To Reproduce: 1. attacker stole the login password of victims throught any means - {{attacker prespective}} 2. attacker could connect his/her google account {{attacker prespective}} 3. attacker login with google authentication {{attacker prespective}} 4. victim disconnect attacker session did not expire and still get access beacuse of no session expire in the attacker browser after disconnected with google account {{victims prespective}} 5. attacker could still connect his google account again. {{attacker prespective}} POC video attached in this report ## Impact no session expire after disconnected with google account an attacker can still logined to the victim account .thus an attacker could create a backdoor in victim account to login even if the victims changes the password attacker has a backdoor way to login to the account .

### 347748 — Improper session handling on web browsers
X / xAI · $560 · medium · https://hackerone.com/reports/347748

> NOTE! Thanks for submitting a report! Please replace *all* the [square] sections below with the pertinent details. Remember, the more detail you provide, the easier it is for us to triage and respond quickly, so be sure to take your time filling out the report! **Summary:** Sessions are not properly logged out/ Information Leak **Description:** I have two accounts that I control from my mobile Browser , As a concept of Session handling by browsers at a time one can only use one account with proper mapping of session and generated cookies . But when someone send DM or other data for my logged out account i still get web Notifications , where i can read the DM of that logged out account . All the Testing is done on Chrome Browser of my phone , I have video for the same ## Steps To Reproduce: (Add details for how we can reproduce the issue) 1. login with multiple accounts in Twitter one by one , saving your credentials for future 2. Enable web push notifications for twitter 3 now as a normal scenario login to one account and ask your friend to send you DM on account other account which is not logged in 4 . you can see the DM in the android notifications for websites that saying notification for mobile.twitter.com and DM displayed ## Impact : session mishandling leading to my private data leak , on clicking the notification my cookies of one account is being taken with the reques

### 1162443 — No Session Expiry after log-out, attacker can reuse the old cookies
Shopify · $500 · low · https://hackerone.com/reports/1162443

Hi, There is no session expiry after log-out which can help an attacker to take-over the full account by reusing it. **Reproduction Steps** 1. Go to and click on Sign In 2. Continue with Google Account 3. Use "EditThisCookie" Extension to export the cookies 4. Once you logged in - click on "EditThisCookie" Extension and export the cookies 5. Now open another browser and import those cookies - you can able to login an account by using cookies 6. Logout from your first browser - it should logout from another browser as well. 7. Now, login again with your google account - This time use old cookies. 8. By using old cookies, you can able to login victim's account. (Whenever victim's session is active) Please find the attached POC video ████████ ## Impact **Attack Scenario:** If a malicious user gets the victim's cookies by exploiting any vulnerability, he can log in to victim's account . Whenever the victim's session is active an attacker can login victim's account by using old cookies. **Impact:** If a malicious user gets the cookies by exploiting any vulnerability, he can log in to the victim's account.

### 417382 — Revoking user session in https://hackerone.com/settings/sessions does not revoke the GraphQL query session
HackerOne · $500 · low · https://hackerone.com/reports/417382

Hi Team, **Summary:** I have found an Insufficient Session Expiration on implementation of the new `Revoke user session` feature of HackerOne here: **Description:** The new __REVOKE__ session feature will destroy the session of the selected device, that means any request that requires authorization should not work (`POST`, `GET`) __BUT__ i have observed that you forgot the `GraphQL` query request, i can still query sensitive information despite i already revoke my current session and this can result a __sensitive information disclosure__ ### Steps To Reproduce 1. Login to hackerone.com 2. Go to sensitive page and capture the `GraphQL` request , on my case i captured the bounty settings `{"query":"query User_bounty_settings_page... etc` on this end point: 3. Send the GraphQL request to repeater 4. Go to and click `Revoke` to destroy the current session 5. You will be logout to your account, means session destroyed 6. Go back to burp repeater and click `Go` to repeat the graphql request 7. Observed that you can still query the graphql `User_bounty_settings_page`, and it will disclosed the reports that was rewarded, including the amounts, report title, payment method used and other sensitive information. __Below is my sample GraphQL query and response after revoking the session:__ __Response:__ __PoC screenshot below:__ █████ ## Impact Insufficient Session Expiration can result to

### 390126 — Узнаем несколько цифр номера телефона юзера (можно флудить смс), всего раз узнав его remixsid и его ид юзера, и установка оффлайна юзерам.
VK.com · $300 · high · https://hackerone.com/reports/390126

Недостаточные проверки сессии. Было можно узнать часть номера телефона юзера и отправлять ему смс с ссылкой на приложение ( всего раз узнав его `remixsid`, вне зависимости сколько раз были ресетнуты сессии. Самый давний валидный для этой темы `remixsid` был давности ~ май 2016 года. Была возможность имея только ид юзера установить ему статус "оффлайн" (т.е. был в сети 1 сек назад и тд) и сбросить ему queue-ключи, что принудительно вызывало `/notifier.php?act=a_get_key` где был рейт лимит на получение ключей, таким образом можно было отключить юзеру queue серв (нотифиер, не тот что `imv4`, а `queuev4` - те реалтайм события не приходили, кроме тех что в личку идут)

### 837729 — Session works after logout from Shopify account and password of online store is displayed
Shopify · no bounty (valid finding) · low · https://hackerone.com/reports/837729

When a user creates a Shopify Lite Plan account, in the product creation stage when the account has not been upgraded, the store's password is enabled such that any visitor who wants to access the store is required to enter password before being granted access to view the products listed in the online store. When a logout request has been made and response has been received/displayed that logout is successful, session still works when is entered in the browser url address bar; the resulting Shopify page displays the password required to enter the store which is supposed to be visible to only the admin and those who have been sent this password. Please see the PoC attached. ## Impact Third party can view the listed products and also exploit the user session vulnerability.

### 3475626 — Session Cookie Leakage via Static Header Field in WebViewerFragment
LinkedIn · no bounty (valid finding) · high · https://hackerone.com/reports/3475626

Hello LinkedIn Security Team, I was able to identify a vulnerability in the `WebViewerFragment` that can lead to leaking the user's cookies to a threat actor. Below, I will explain the finding and provide a PoC. ## Summary A static field (`CUSTOM_HEADERS`) in `WebViewerFragment` persists cookies across different URL loads, allowing an attacker to chain multiple weaknesses to exfiltrate a victim's LinkedIn session cookies to an attacker-controlled server. ## Root Cause While the exploitation is complex, the root cause is simple. In the `loadUrl` method of the vulnerable fragment: The method retrieves cookies for the URL. If cookies exist, they are added to `WebViewerFragment.CUSTOM_HEADERS`. ### The Problem `WebViewerFragment.CUSTOM_HEADERS` is a **static field that is never cleared** between loads. This means: 1. If the vulnerable fragment opens website A (which has cookies), those cookies are stored in `CUSTOM_HEADERS` 2. If website B is subsequently opened and has no saved cookies, the cookies from website A are still present in `CUSTOM_HEADERS` and will be sent to website B **Attack Flow:** 1. Victim opens ` in the Fragment → LinkedIn cookies are saved to `CUSTOM_HEADERS` 2. Victim opens the attacker's website in the Fragment → The LinkedIn cookies already in `CUSTOM_HEADERS` are leaked to the attacker ## Exploitation Chain There is no deep-link that directly opens the vulne

## Field playbook (unedited)

### quick

- Check cookie flags: Secure, HttpOnly, SameSite, scope, lifetime.
- Test fixation and rotation on login/logout/privilege change.
- Test revocation after password change or logout.
- Look for predictable tokens and JWT weaknesses.

### payloads

- Set-Cookie -> `; SameSite=None` without Secure
- Fixate -> `PHPSESSID=attacker` before login
- Reuse -> old token after logout/password change

### bypass

- Cross-subdomain cookie leakage.
- Token in URL/Referer.

### surface

- cookie
- session
- token
- jwt
- remember
- logout

### tools

- Burp
- jwt_tool
- browser devtools

### chain

- Session fixation -> ATO.
- Token leak -> session hijack.

## Corpus search commands

```sh
python3 ~/.local/share/hackerone-reports/h1.py stats --class session
python3 ~/.local/share/hackerone-reports/h1.py search "<feature or param>" --class session --limit 10
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```
