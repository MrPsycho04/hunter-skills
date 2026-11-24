---
name: bbhunt-session
description: "Use for session fixation, non-invalidation on logout/password/email change, weak session IDs, and session lifetime/revocation issues. Unified from 3 upstream skills (cbh, h1skills, hunting). Plus evidence from all 15,259 disclosed HackerOne reports. For authorized security testing only."
agent_created: true
---

# Session Management Flaws — unified skill

> **Complete merged skill.** Everything from 3 upstream skills across cbh, h1skills, hunting and the local HackerOne corpus is contained in this file. Unmodified originals remain in `references/` for provenance only.

## Corpus evidence — 112 valid HackerOne reports (18 paid / 16%)

Every disclosed report is valid; payment is an impact signal, not a validity test.

### Techniques ranked across ALL valid reports

| Technique | Reports |
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

### Parameters observed in writeups

`valid_until` (5), `charset` (3), `in_header` (3), `max-age` (2), `rel` (2), `curlopt_ssl_verifypeer` (2), `rtp_len` (2), `size` (2), `download_done` (2), `state` (2), `jsessionid` (1), `xsrf-token` (1), `src` (1), `steps` (1), `summary` (1), `response` (1), `headers` (1), `act` (1), `hostname` (1), `cert` (1), `verifyerror` (1), `password` (1), `browser` (1), `chrome]` (1), `link` (1), `aip` (1), `jid` (1), `gjid` (1), `cid` (1), `tid` (1)

### Bypass primitives observed

`bypass` (13), `content-type` (10), `bypassing` (4), `bypasses` (3), `bypassed` (2), `whitelist` (1)

### Impact language observed

`password` (238), `token` (113), `credential` (17), `admin` (14), `unauthorized` (14), `full access` (9), `sensitive information` (8), `localhost` (8), `secret` (6), `financial` (4), `account takeover` (3), `payment` (2), `data leak` (2), `unauthorised` (2), `sensitive data` (2), `privilege escalation` (1), `exfiltrate` (1), `api key` (1)

### Case studies — full excerpts (paid and unpaid)

#### [1547684](https://hackerone.com/reports/1547684) — Disconnecting an external login provider does not revoke session

Shopify · $1600 · medium

Hi team, Summary: attacker could create a backdoor using google login function.if an attacker stole the login password of victims throught any means. attacker could connect his/her google account and create a backdoor and attacker login with google if the victim disconnect attacker session did not expire and still get access beacuse of no session expire after disconnected with google account .attacker could still connect his google account again. Steps To Reproduce: 1. attacker stole the login password of victims throught any means - {{attacker prespective}} 2. attacker could connect his/her google account {{attacker prespective}} 3. attacker login with google authentication {{attacker prespective}} 4. victim disconnect attacker session did not expire and still get access beacuse of no session expire in the attacker browser after disconnected with google account {{victims prespective}} 5. attacker could still connect his google account again. {{attacker prespective}} POC video attached in this report ## Impact no session expire after disconnected with google account an attacker can still logined to the victim account .thus an attacker could create a backdoor in victim account to login even if the victims changes the password attacker has a backdoor way to login to the account .

#### [347748](https://hackerone.com/reports/347748) — Improper session handling on web browsers

X / xAI · $560 · medium

> NOTE! Thanks for submitting a report! Please replace *all* the [square] sections below with the pertinent details. Remember, the more detail you provide, the easier it is for us to triage and respond quickly, so be sure to take your time filling out the report! **Summary:** Sessions are not properly logged out/ Information Leak **Description:** I have two accounts that I control from my mobile Browser , As a concept of Session handling by browsers at a time one can only use one account with proper mapping of session and generated cookies . But when someone send DM or other data for my logged out account i still get web Notifications , where i can read the DM of that logged out account . All the Testing is done on Chrome Browser of my phone , I have video for the same ## Steps To Reproduce: (Add details for how we can reproduce the issue) 1. login with multiple accounts in Twitter one by one , saving your credentials for future 2. Enable web push notifications for twitter 3 now as a normal scenario login to one account and ask your friend to send you DM on account other account which is not logged in 4 . you can see the DM in the android notifications for websites that saying notification for mobile.twitter.com and DM displayed ## Impact : session mishandling leading to my private data leak , on clicking the notification my cookies of one account is being taken with the reques

#### [1162443](https://hackerone.com/reports/1162443) — No Session Expiry after log-out, attacker can reuse the old cookies

Shopify · $500 · low

Hi, There is no session expiry after log-out which can help an attacker to take-over the full account by reusing it. **Reproduction Steps** 1. Go to and click on Sign In 2. Continue with Google Account 3. Use "EditThisCookie" Extension to export the cookies 4. Once you logged in - click on "EditThisCookie" Extension and export the cookies 5. Now open another browser and import those cookies - you can able to login an account by using cookies 6. Logout from your first browser - it should logout from another browser as well. 7. Now, login again with your google account - This time use old cookies. 8. By using old cookies, you can able to login victim's account. (Whenever victim's session is active) Please find the attached POC video ████████ ## Impact **Attack Scenario:** If a malicious user gets the victim's cookies by exploiting any vulnerability, he can log in to victim's account . Whenever the victim's session is active an attacker can login victim's account by using old cookies. **Impact:** If a malicious user gets the cookies by exploiting any vulnerability, he can log in to the victim's account.

#### [417382](https://hackerone.com/reports/417382) — Revoking user session in https://hackerone.com/settings/sessions does not revoke the GraphQL query session

HackerOne · $500 · low

Hi Team, **Summary:** I have found an Insufficient Session Expiration on implementation of the new `Revoke user session` feature of HackerOne here: **Description:** The new __REVOKE__ session feature will destroy the session of the selected device, that means any request that requires authorization should not work (`POST`, `GET`) __BUT__ i have observed that you forgot the `GraphQL` query request, i can still query sensitive information despite i already revoke my current session and this can result a __sensitive information disclosure__ ### Steps To Reproduce 1. Login to hackerone.com 2. Go to sensitive page and capture the `GraphQL` request , on my case i captured the bounty settings `{"query":"query User_bounty_settings_page... etc` on this end point: 3. Send the GraphQL request to repeater 4. Go to and click `Revoke` to destroy the current session 5. You will be logout to your account, means session destroyed 6. Go back to burp repeater and click `Go` to repeat the graphql request 7. Observed that you can still query the graphql `User_bounty_settings_page`, and it will disclosed the reports that was rewarded, including the amounts, report title, payment method used and other sensitive information. __Below is my sample GraphQL query and response after revoking the session:__ __Response:__ __PoC screenshot below:__ █████ ## Impact Insufficient Session Expiration can result to

#### [390126](https://hackerone.com/reports/390126) — Узнаем несколько цифр номера телефона юзера (можно флудить смс), всего раз узнав его remixsid и его ид юзера, и установка оффлайна юзерам.

VK.com · $300 · high

Недостаточные проверки сессии. Было можно узнать часть номера телефона юзера и отправлять ему смс с ссылкой на приложение ( всего раз узнав его `remixsid`, вне зависимости сколько раз были ресетнуты сессии. Самый давний валидный для этой темы `remixsid` был давности ~ май 2016 года. Была возможность имея только ид юзера установить ему статус "оффлайн" (т.е. был в сети 1 сек назад и тд) и сбросить ему queue-ключи, что принудительно вызывало `/notifier.php?act=a_get_key` где был рейт лимит на получение ключей, таким образом можно было отключить юзеру queue серв (нотифиер, не тот что `imv4`, а `queuev4` - те реалтайм события не приходили, кроме тех что в личку идут)

#### [837729](https://hackerone.com/reports/837729) — Session works after logout from Shopify account and password of online store is displayed

Shopify · no bounty — still valid · low

When a user creates a Shopify Lite Plan account, in the product creation stage when the account has not been upgraded, the store's password is enabled such that any visitor who wants to access the store is required to enter password before being granted access to view the products listed in the online store. When a logout request has been made and response has been received/displayed that logout is successful, session still works when is entered in the browser url address bar; the resulting Shopify page displays the password required to enter the store which is supposed to be visible to only the admin and those who have been sent this password. Please see the PoC attached. ## Impact Third party can view the listed products and also exploit the user session vulnerability.

#### [3475626](https://hackerone.com/reports/3475626) — Session Cookie Leakage via Static Header Field in WebViewerFragment

LinkedIn · no bounty — still valid · high

Hello LinkedIn Security Team, I was able to identify a vulnerability in the `WebViewerFragment` that can lead to leaking the user's cookies to a threat actor. Below, I will explain the finding and provide a PoC. ## Summary A static field (`CUSTOM_HEADERS`) in `WebViewerFragment` persists cookies across different URL loads, allowing an attacker to chain multiple weaknesses to exfiltrate a victim's LinkedIn session cookies to an attacker-controlled server. ## Root Cause While the exploitation is complex, the root cause is simple. In the `loadUrl` method of the vulnerable fragment: The method retrieves cookies for the URL. If cookies exist, they are added to `WebViewerFragment.CUSTOM_HEADERS`. ### The Problem `WebViewerFragment.CUSTOM_HEADERS` is a **static field that is never cleared** between loads. This means: 1. If the vulnerable fragment opens website A (which has cookies), those cookies are stored in `CUSTOM_HEADERS` 2. If website B is subsequently opened and has no saved cookies, the cookies from website A are still present in `CUSTOM_HEADERS` and will be sent to website B **Attack Flow:** 1. Victim opens ` in the Fragment → LinkedIn cookies are saved to `CUSTOM_HEADERS` 2. Victim opens the attacker's website in the Fragment → The LinkedIn cookies already in `CUSTOM_HEADERS` are leaked to the attacker ## Exploitation Chain There is no deep-link that directly opens the vulne

### Recurring approach patterns from real reports

- 2× summary while conducting my researching i discovered that the application failure to invalidate session after password
- 1× hackerone fails to expire the session cookie from the server side even when the user logs off upon clicking sign out from the application
- 1× to reproduce this vulnerability open chrome and download edit this cookie ad don now open and log in now goto edit this cookie addon and click export all cookies by clicking this we get the cookie copied in clipboard
- 1× an attacker could exploit this issue by for example tricking a user into clicking on a link to a page with the following html code img src when the user visits the page the browser will send a request to www irccloud com over an unencrypted connection note the http instead of https containing the session cookie
- 1× as a result of this report we rethought how we handled password changes and we decided to invalidate all sessions on a password change reset to protect from this possible problem
- 1× hey i ve found a session management in help nextcloud com which can lead to session takeover
- 1× hi i don t know is it a valid vulnerability under your program but i found it
- 1× i have found a way to change the value of the cookie this error can be used to leave off the application to a particular user to log on again the attacker would have to cause the victim to visit a particular link
- 1× i observed session tokens remaining valid even hours after being issued
- 1× authenticate to via the gmail oauth function receiving a valid session cookie from www urbandictionary com and then sign out by clicking
- 1× description since the certificate is only valid through herokuapp com the domain is sending a warning message about mitm attacks
- 1× also i discovered that privilege escalation is possible it is possible to attack another user account in some cases
- 1× the problem is that the cookies stored on the browser are not getting expired after logging out from the platform and from github as well
- 1× i found a broken authentitication vuln poc create a account confirm your email now request a password reset for your account
- 1× i also did not fully investigate if there is a way to trigger the socket close event with no error which would skip the session eviction and turn this into a reliable bypass
- 1× hello team i am hemant patidar working as a security researcher and i found a bug in your site
- 1× report of bug is as follows description while conducting my research i discovered that the application failure to invalidate the session after the password change
- 1× steps to reproduce add details for how we can reproduce the issue through manual testing only login to your urbancompany account using your mobile number with the otp received
- 1× while conducting my research i discovered that the application failed to validate session after password change
- 1× hi i would like to report session management issue to you while testing i found that we can easily invite or we can easily perform invite related action even we logged out from the the account
- 1× i didn t checked the other functionality under session management but this can prove the session won t expired after the account admin logout from his account
- 1× that time i revoked app access from the old reddit com and i checked my app and as expected i was not able to use the account in my app
- 1× after days i was checking the chat invites feature on the web and after some time i turned on the internet on my mobile and got a reddit invitation accept notification
- 1× i clicked on that and i was surprised that i was able to use the previously revoked user account again in the reddit app

## Corpus-backed method (this class)

1. Capture session identifiers at pre-login, post-login, after privilege change, and after logout; check for regeneration and revocation.
2. Test whether a session can be fixed by planting a known identifier before authentication.
3. Attempt reuse after each lifecycle event (logout, password change, email change, admin reset, MFA disable).
4. Inspect identifier entropy/structure and server-side session storage assumptions.
5. Prove that an attacker with a stolen/old session retains access they should have lost.

### Signals

- Session cookie not regenerated at login
- Old session still works after logout or password change
- Predictable or unsigned session identifiers
- Account/email change does not terminate other sessions

### Kill criteria

- Session correctly regenerated and invalidated at every boundary.
- Old token reuse needs credentials an attacker does not have.

### Escalation chains

- Session fixation -> authenticated session -> account access.
- Stale session -> access after password reset -> persistence.

### Probes

- Replay pre-auth cookie after login; replay cookie after logout and after password change; inspect Set-Cookie sequence.

### Veteran tip

The most useful evidence is a timeline of which token worked at which lifecycle event.

## Unified upstream methodology (complete, deduplicated)

### Discovery and hunting method

### Quick wins

Start here. These are the highest-yield tests for this class.

- Check cookie flags: Secure, HttpOnly, SameSite, scope, lifetime.
- Test fixation and rotation on login/logout/privilege change.
- Test revocation after password change or logout.
- Look for predictable tokens and JWT weaknesses.

### Deeper checklist

- Check cookie flags: Secure, HttpOnly, SameSite, scope, and lifetime.
- Test session fixation and rotation on login/logout/privilege change.
- Test token revocation and reuse after password change or logout.
- Look for predictable tokens and JWT weaknesses.
- Check cross-subdomain cookie leakage.
- Demonstrate session hijack or persistence.

### Autonomous Testing Priority

**Missing HttpOnly on cookies is auto-detected — focus your active testing on lifecycle invalidation (higher impact).**

**Pattern 1 — Session survives logout (most common high-value finding):**
1. Login and note the session token/cookie value
2. Call the logout endpoint (`/logout`, `POST /api/logout`, etc.)
3. Try to use the OLD session token to access a protected resource (`/api/me`, `/dashboard`, `/account`)
4. If 200 with user data → session not invalidated on logout = ATO persistence

**Pattern 2 — Session not regenerated on login (session fixation):**
1. GET any page to receive a pre-authentication session token/cookie
2. POST valid credentials to the login endpoint
3. Compare the session token BEFORE and AFTER login
4. If the token is unchanged → session fixation vulnerability

**Pattern 3 — Session survives password change:**
1. Login → record session A value
2. Change the password via the account settings endpoint
3. Replay session A on a protected endpoint
4. If 200 → token not rotated on credential change = persistent ATO (critical chain when combined with XSS/cookie theft)

**Content-type:** Login and session endpoints vary — use `application/json` for REST APIs, `application/x-www-form-urlencoded` for traditional web forms. Try both if the first returns an unexpected response.

**Proof:** A protected-resource 200 response (with user data) using a session token that should have been invalidated confirms the finding.

---

# HUNT-SESSION — Session Management

### Step-by-Step Hunting Methodology

> **Two-session rule.** Every invalidation/fixation claim is proven with TWO concrete sessions captured by a real flow — attacker **A** and victim **B** — never with hardcoded placeholder strings. Helpers below capture real cookies from `curl`'s Netscape jar.

```bash
TARGET=target.com
JAR_A=$(mktemp); JAR_B=$(mktemp)

# Robust session-cookie extractor: handles #HttpOnly_ prefix lines and any
# cookie name (sid/JSESSIONID/connect.sid/PHPSESSID/...). Prints name=value.
get_cookie () {  # $1=jar  $2=name-regex (default: common session names)
  local jar="$1" re="${2:-session|sid|sess|JSESSIONID|connect\.sid|PHPSESSID|laravel_session}"
  awk -v re="$re" '
    /^#HttpOnly_/ { sub(/^#HttpOnly_/,""); }   # strip jar HttpOnly marker
    /^#/ { next }                              # skip remaining comments
    NF>=7 && $6 ~ re { print $6"="$7 }         # field6=name field7=value
  ' "$jar" | tail -1
}
```

### A. Discovery checklist — concrete places, params, headers, flows to look

- Inventory every session-bearing artifact: auth cookie(s), `remember-me`/persistent cookie, refresh token, JWT access token, SSO session cookie, password-reset token, CSRF token, and any opaque session ID in a URL (`?sid=`, `?session=`, path segments). PortSwigger classifies session-in-URL as CWE-598/CWE-384 and notes leakage via browser history, logs, and `Referer`.
- Record cookie attributes for each: `Secure`, `HttpOnly`, `SameSite`, `Domain`, `Path`, `Expires`/`Max-Age`, `__Host-`/`__Secure-` prefixes. Multiple cookies with the same name but different `Path` (Snyk 2026 OAuth case) create a path-scope confusion primitive.
- Determine regeneration points: compare the session token before login, after login, after privilege change, after password change, and after email change. Logout must invalidate server-side state, not just clear the browser cookie.
- Test refresh-token flows from SPAs/mobile apps: collect the full `POST /oauth/token` with `grant_type=refresh_token` and watch whether each exchange returns a *new* refresh token (rotation) and whether old ones are revoked.
- Use Burp Sequencer on a large sample of session tokens (PortSwigger/Burp testing workflow: "Analyzing session token generation") to check entropy; decode opaque tokens (Base64/JSON) for timestamp+username construction.
- Look for session-handling rules that auto-re-login during fuzzing (Burp "Maintaining an authenticated session") — a token that stays valid after the app tries to log you out is a signal.
- Enumerate sibling subdomains and cloud/CDN assets: a subdomain takeover can yield a cookie scoped to `.domain.com` (Uber/Roblox/Ubiquiti pattern), and dangling DNS plus a broad cookie scope is a session-theft primitive.

- Compare the token issued at login with the one issued after a privilege change (role promotion, admin impersonation, assuming a sub-account). A token whose claims/subject do not change may retain stale privileges.
- Check whether logout is client-only: clear the cookie in the browser but replay the original `Cookie` header in Repeater. Still-valid server state = improper invalidation even if the UI logs out.
- Look for parallel sessions: if logging in on device B does not invalidate device A, a stolen cookie has a long useful lifetime; record how many concurrent sessions are allowed and whether a "log out all devices" control exists.
- Test password/email change with a stale session: the old session should be killed; if it survives, the change did not revoke the attacker's access (a common ATO persistence primitive).
- Inspect `Set-Cookie` for `__Host-`/`__Secure-` prefixes and `Domain` scoping; a session cookie scoped to `.example.com` is exposed to every sibling subdomain, including any that can be taken over.
- Check SSO session linkage: an IdP session that remains valid after the app-side logout can silently re-authenticate the user on the next `/sso/callback` — test by replaying a fresh authorization code after logout.
- Note session timeout semantics: absolute vs idle timeout, and whether the server enforces it (a cookie with `Expires` in the future but a short server-side TTL is fine; a long server TTL with short browser expiry is a weaker but not always reportable issue).
- Look for session IDs in logs, error messages, `Referer`, and browser history (PortSwigger CWE-598) — these are theft vectors that make an otherwise strong token exploitable.
- Check whether the app accepts a session token in multiple locations (cookie, header, query, body) — a token accepted via `?sid=` can be planted or leaked through a URL.

### Signals and surfaces

### Signal

- Reports: **150** · paid: **22**
- Median bounty **$100** · p90 **$540** · max **$1,600** · total **$6,140**
- Median upvotes **11**

### Where it pays

| Program | Reports | Bounty | Upvotes |
|---|---|---|---|
| Shopify | 8 | $2,100 | 553 |
| HackerOne | 13 | $1,000 | 293 |
| WePay | 2 | $600 | 6 |
| X / xAI | 1 | $560 | 19 |
| Internet Bug Bounty | 4 | $540 | 123 |
| Open-Xchange | 1 | $300 | 11 |
| VK.com | 1 | $300 | 10 |
| Visma Public | 2 | $200 | 23 |

### Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`cookie` `session` `token` `jwt` `remember` `logout`

### Crown Jewel Targets

Session fixation leading to admin hijack = Critical. Session surviving a password change = High-to-Critical (persistent ATO from a stolen cookie that the victim believes they revoked by resetting their password).

**Highest-value chains:**
- **Session fixation** — server accepts a session ID set by the client and does NOT regenerate it on login → attacker pre-plants an ID, victim authenticates, attacker rides the now-authenticated session → persistent ATO.
- **No invalidation on logout** — old token still works after `/logout` → theft window never closes.
- **No invalidation on password / email change** — a stolen session survives the victim's "I think I was hacked, let me reset" → persistent ATO. This is the single highest-paid session bug class.
- **Refresh-token reuse without rotation-detection** — a leaked refresh token mints fresh access tokens forever; no reuse-detection means the legitimate user's later refresh does NOT revoke the attacker's branch.
- **Predictable / low-entropy session ID** — sequential, timestamp- or userId-derived IDs → brute-force or compute other users' sessions.
- **JWT-as-session with no `exp` / no revocation list** — stolen JWT = permanent access; logout is cosmetic.

---

### Attack Surface Signals

```
Set-Cookie: session=...            # name varies: sid, JSESSIONID, connect.sid,
                                   # PHPSESSID, ASP.NET_SessionId, laravel_session, _csrf
/login /logout /api/login /oauth/token
/auth/refresh /api/token/refresh   # refresh-token rotation surface
/account/change-password /settings/email
?sid= ?session= in URL             # session-in-URL → leaks via Referer/logs (finding)
```
```
# Header signals worth flagging immediately:
Set-Cookie: session=abc; Path=/                 # no HttpOnly/Secure/SameSite
Set-Cookie: session=abc; SameSite=None          # None without Secure = rejected by modern browsers, but flag
Set-Cookie: __Host-sess=...; Secure; Path=/     # GOOD — hard to fixate
Sec-Session-Registration: ...                   # DBSC in play → test downgrade
```

---

### Techniques, payloads and bypasses

### Payloads & probes

- Set-Cookie -> `; SameSite=None` without Secure
- Fixate -> `PHPSESSID=attacker` before login
- Reuse -> old token after logout/password change

### Bypass tricks

- Cross-subdomain cookie leakage.
- Token in URL/Referer.

### Techniques from real reports

One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.

- **Session works after logout from Shopify account and password of online store is displayed** — `#837729` · Shopify · $0 · ▲157
  > When a logout request has been made and response has been received/displayed that logout is successful, session still works when
- **H1514 Session Fixation on multiple shopify-built apps on *.shopifycloud.com and *.shopifyapps.com** — `#423136` · Shopify · $0 · ▲144
  > Attacker uses XSS on .shopifycloud.com and writes the cookie scoped to all subdomain to victim `document.cookie=' flow session=EVIL;domain=.shopifycloud.com;path=/';`
- **Session Cookie Leakage via Static Header Field in WebViewerFragment** — `#3475626` · LinkedIn · $0 · ▲131
  > A static field (`CUSTOM HEADERS`) in `WebViewerFragment` persists cookies across different URL loads, allowing an attacker to chain multiple weaknesses to exfiltrate a victim's LinkedIn session cookies to an attacker-controlled server.
- **No Session Expiry after log-out, attacker can reuse the old cookies** — `#1162443` · Shopify · $500 · ▲87
  > Now open another browser and import those cookies - you can able to login an account by using cookies
- **Insufficient session expiration in the **com.shopify.ping** android app** — `#1172205` · Shopify · $0 · ▲63
  > More specifically, after the user provides the required credentials, an access token will be fetched from the server at accounts.shopify.com/oauth/token.
- **Session Persistence Designed to Keep Users Logged In Across Multiple Devices (Intended Behaviour)** — `#3161827` · Shopify · $0 · ▲63
  > An attacker with access to the session cookie prior to logout can reuse the same cookie to re-authenticate, effectively bypassing the logout process and regaining access to the account.
- **Apache Airflow Fab Provider: Application does not invalidate session after password change via Airflow cli** — `#3073507` · Internet Bug Bounty · $0 · ▲57
  > When a user changes his password by visiting `/resetmypassword` form, the application terminates all the existing sessions.
- **Improper Session Invalidation – Auto Sign-In Without Credentials After Logout (Affects Chrome & Firefox)** — `#3101207` · Dust · $0 · ▲56
  > - Set cache-control headers to prevent session restoration via back/forward navigation.
- **ABLE TO TRICK THE VICTIM INTO USING A CRAFTED EMAIL ADDRESS FOR A PARTICULAR  SESSION AND THEN LATER TAKE BACK THE ACCOUNT** — `#1357013` · Mattermost · $0 · ▲49
  > https://hackerone.cloud.mattermost.com/signup user complete/?d={"display name":"\u003ch1\u003ea","email":"██████████","name":"main"}&t=cqtkyznxn8e43yagt9fjcsrc4nh6yoqq914in3zg4ykj1jkjbc9bippckjikj4cw
- **Revoking user session in https://hackerone.com/settings/sessions does not revoke the GraphQL query session** — `#417382` · HackerOne · $500 · ▲47
  > I have found an Insufficient Session Expiration on implementation of the new `Revoke user session` feature of HackerOne here: https://hackerone.com/settings/sessions
- **HackerOne Code: a live password reset token reaches Datadog RUM, and the same session records the account it unlocks** — `#4071670` · HackerOne · $200 · ▲45
  > | Reset endpoint | `POST /api/v1/password-reset`, fields `token`, `email`, `password` |
- **Logout Bypass Vulnerability in Hiro.so** — `#3062299` · Hiro · $150 · ▲45
  > Session Hijacking Risk – If an attacker tricks a user into logging out (via CSRF or social engineering), the victim may assume they are logged out while the attacker retains access.
- **Broken Authentication and Session Management Flaw After Change Password and Logout** — `#634488` · Omise · $0 · ▲45
  > [https://www.owasp.org/index.php?title=Broken Authentication and Session Management&setlang=en](https://www.owasp.org/index.php?title=Broken Authentication and Session Management&setlang=en)
- **Lack of session expiration after password reset on TikTok Careers Portal** — `#997127` · TikTok · $50 · ▲38
  > A lack of session expiration following a password reset on the TikTok Careers Portal does not automatically log out a user on another device/browser.
- **curl Missing Sec-WebSocket-Accept Verification Enables MITM WebSocket Session Hijacking** — `#3917775` · curl · $0 · ▲37
  > Run: `python3 poc.py 8766` then in another terminal: `curl -v ws://127.0.0.1:8766/`
- **HTTPS Agent TLS session reuse skips hostname verification across identity policies (incomplete fix of CVE-2026-48934)** — `#3812439` · Node.js · $0 · ▲37
  > An incomplete fix has been identified in Node.js: HTTPS Agent TLS session reuse skips hostname verification across identity policies (incomplete fix of CVE-2026-48934).
- **Session Timeout Does Not Enforce Re-Authentication on AWS Access Portal** — `#2800511` · AWS VDP · $0 · ▲36
  > What type of Amazon AWS account(s) is needed to verify or reproduce this vulnerability?: Amazon AWS account(s) needed to reproduce: An AWS account using AWS SSO with a session timeout policy in place.
- **Improper Session management can cause account takeover[https://micropurchase.18f.gov]** — `#263873` · GSA Bounty · $0 · ▲36
  > Once you are logged in Then Use "BurpSuite" or any other Utility to get the cookies of that session ( "EditThisCookie" Chrome Extension can be used and in a Case of an Attacker he can Use Any Sort Of cookie Stealing Script or Cookies Spoofing Utility to get…
- **Broken Authentication and session management OWASP A2** — `#284` · HackerOne · $0 · ▲36
  > 2) Copy the cookies using Edit this cookie extension when you are logged in using "Import Cookies" option of the extension.
- **Broken Authentication Session Token Bug** — `#948345` · Courier · $0 · ▲35
  > Now log out from your account and request for password reset code for your account .
- **Node.js: TLS session reuse can lead to hostname verification bypass** — `#811502` · Node.js · $0 · ▲29
  > [fwilhelm@fwilhelm node]$ ../node/node-v13.9.0-linux-x64/bin/node poc.js
- **Replayable Password Change Request Across Sessions.** — `#3269777` · Malwarebytes · $0 · ▲28
  > The report describes a vulnerability in the password change endpoint (PUT /authentication/password) that allows for replay attacks.
- **Session Not Expire / 2FA Bypass** — `#2469706` · HackerOne · $0 · ▲28
  > attacker add victim cookies using http://www.editthiscookie.com addon to own browser {{attacker perspective}}
- **Broken Authentication and Session Management** — `#17474` · Phabricator · $0 · ▲26
  > 3) Login using the same password back and update your email address to "b@x.com" and verify the same.
- **Bypassing 2FA with conventional session management - open.rocket.chat** — `#1701378` · Rocket.Chat · $0 · ▲25
  > https://infosecwriteups.com/how-i-couldve-bypassed-the-2fa-security-of-instagram-once-again-43c05cc9b755
- **Improper session management** — `#737` · HackerOne · $100 · ▲24
  > When a request with an invalid authenticity token is received, the user is logged out (tested for updating user's profile, which is available here: https://hackerone.com/diekatze/profile/edit) and the user receives a new session cookie, which is not…
- **CVE-2024-0853: OCSP verification bypass with TLS session reuse** — `#2341063` · Internet Bug Bounty · $0 · ▲24
  > Original Report:https://hackerone.com/reports/2298922
- **Broken Authentication and session management OWASP A2** — `#449671` · Liberapay · $0 · ▲24
  > You can also login to my account (admin.101) temp account via this cookies/request.
- **libcurl: Integer truncation in curl_easy_ssls_import() causes TLS sessions to never expire** — `#3658049` · curl · $0 · ▲23
  > In `Curl ssl session unpack()` (`lib/vtls/vtls spack.c:311`), the `valid until` field is read as `uint64 t` and cast directly to `curl off t` (`int64 t`) with no bounds check — so a crafted blob encoding `valid until = 0xFFFFFFFFFFFFFFFF` produces `valid…
- **Session not expired on logout** — `#353` · HackerOne · $100 · ▲22
  > Replay the request captured in step 3 and notice it displays the proper response.

### Payload fragments observed

Recurring payloads from this class's writeups. Adapt, don't paste blindly.

| Seen | Fragment |
|---:|---|
| 5× | `rtsp_connect()` |
| 5× | `$\x00\x00\x10` |
| 3× | `Curl_ws_accept()` |
| 3× | `Curl_ssl_scache_take()` |
| 3× | `rtsp_filter_rtp()` |
| 3× | `rtsp_done()` |
| 2× | `(valid_until > 0) && (valid_until < now)` |
| 2× | `(-1 > 0) = FALSE` |
| 2× | `curl_easy_ssls_export()` |
| 2× | `valid_until < 0` |
| 2× | `match_ssl_primary_config()` |
| 2× | `SSL_connect()` |
| 2× | `rtspc->in_header = FALSE` |
| 2× | `rtspc->buf` |
| 2× | `curl -c cookies.txt -b cookies.txt https://somesite.tld:9999/` |
| 2× | `ssl_peer_key_build()` |
| 2× | `peer->origin->scheme->family` |
| 1× | `document.cookie='_flow_session=EVIL;domain=.shopifycloud.com;path=/';` |
| 1× | `javascript://www.linkedin.com/%0aalert(1)` |
| 1× | `javascript://www.linkedin.com/%0aalert(1)?renderContext=trustVerificationDeeplink` |

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- Session fixation: set a known `PHPSESSID`/`JSESSIONID` in the victim (via URL param, hidden form field, or subdomain cookie injection), let them authenticate, then reuse the pre-set ID. Failure to regenerate on login = CWE-384.
- No invalidation: replay the old cookie after logout, after password change, and after email change; a persistent ATO results if the server accepts it. HackerOne reports #3101207 (auto sign-in without credentials after logout) and #3120790 (captured login response replay) are public precedents.
- Predictable token: decode your own cookie, deduce the formula (e.g. `base64(user|timestamp)` or unsalted `md5(password)`), then brute-force another user's cookie offline — bypassing login rate limits because cookie guesses hit a different endpoint.
- Refresh-token abuse (HackTricks + Auth0 2025 detection catalog): redeem RT1 → get RT2; redeem RT1 again (must fail); redeem RT2 (with proper reuse detection it must also fail because the whole token family is revoked). If RT2 still works, there is no rotation-based replay detection. Also check unused RTs after logout/password change/app revocation.
- Sender-constrained token downgrade: take a DPoP-bound token and send `Authorization: Bearer <TOKEN>` with no `DPoP` header, replay an old `iat` proof, reuse a proof with the wrong `htm`/`htu`, or sign with a key not matching `cnf.jkt`. For mTLS tokens, call the API with no client certificate.
- Path-scope cookie confusion: if the app sets `_access_cookie` for `/` and for sensitive subpaths, an attacker can plant a cookie at a broader path so the victim's browser sends the attacker's token to critical endpoints while using their own elsewhere.
- Token-in-URL/Referer chain: place the session ID in a GET URL, then induce a navigation to a third party so the `Referer` leaks it; combine with open redirect/analytics for collection.
- Race the refresh or reset state with HTTP/2 single-packet requests (PortSwigger Turbo Intruder `engine=Engine.BURP2`, `concurrentConnections=1`, `gate='1'` / `openGate('1')`).

- Cookie tossing / subdomain injection: if a sibling subdomain is takeover-able or has a cookie-writing XSS, set `Domain=.example.com` for the app's session cookie name and try to pin a known session ID (session fixation via cookie shadowing).
- JWT-as-session without revocation: capture a valid JWT, log out, then replay it; if accepted, there is no server-side revocation list or token version check.
- Session-puzzle/CSRF-token reuse: if the CSRF token is derived from the session ID or is static, combine with fixation to force a state-changing action in the victim's session.
- Idle-timeout bypass: keep the session alive by sending harmless background requests (e.g. `/api/heartbeat`) that an attacker can trigger from a victim's browser via `img` tags, extending an otherwise short window.
- Parallel-request locking bypass: if PHP's session handler serializes requests, send each attack request with a *different* valid session token (or `?PHPSESSID=` variant) so the lock does not serialize them — PortSwigger's race-condition guidance on session-based locking.
- Refresh-token race: fire two parallel `grant_type=refresh_token` requests with the same RT. Depending on rotation logic, both may succeed or one may revoke the other — record which, as this is both a test and a detection signal.
- Device-bound session downgrade: if the app advertises DBSC/DPoP/mTLS, replay the token without the binding proof on every API host and version, since enforcement lives at each resource server.
- XSS → session theft chain: with an XSS primitive, check whether the session cookie is HttpOnly; if not, exfiltrate it via `document.cookie` to a Collaborator and replay from your browser to prove account access.
- Remember-me cookie brute: collect your own persistent cookie across several logins with different timestamps, derive the formula, then brute another user's — this bypasses login throttles because it hits a different validation path.

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

### Phase 2 — Invalidation on Logout

```bash
# A logs in for real (fresh jar), capture A's live session.
curl -s -L -c "$JAR_A" -X POST "https://$TARGET/api/login" \
  -H 'Content-Type: application/json' \
  -d '{"email":"attacker@example.com","password":"CorrectHorse1"}' -o /dev/null
A=$(get_cookie "$JAR_A"); echo "A=$A"

# Baseline: what does an authenticated /api/me look like for A? (capture body, not just code)
BEFORE=$(curl -s -L -b "$JAR_A" "https://$TARGET/api/me")

# Logout A.
curl -s -L -b "$JAR_A" -X POST "https://$TARGET/api/logout" -o /dev/null

# Replay A's OLD cookie value explicitly (do NOT reuse the jar — logout may have
# overwritten it). Compare body + code against the authenticated baseline.
AFTER=$(curl -s -L -H "Cookie: $A" "https://$TARGET/api/me" -w '\n[%{http_code}]')
echo "AFTER: $AFTER"
```
**FP discipline (mandatory):**
- Don't trust the status code. A cached/edge 200 or a generic SPA shell returns 200 for everyone. **Body-diff** `AFTER` against `BEFORE` — the finding is only real if `AFTER` still contains A's *unique identity marker* (email, user-id, CSRF token, account name).
- Confirm with a **negative control**: a random/garbage cookie value must NOT return the same authenticated body. If garbage also yields 200 with user data, the endpoint isn't session-gated and there's no finding here.
- Re-test after a **short delay** and from a **different IP** — some servers lazily expire on next access or pin sessions to IP.

### Phase 3 — Invalidation on Password / Email Change (persistent-ATO core)

```bash
# This is the real two-session flow. A = attacker holding a stolen/old session.
# B = the victim who changes their password believing it revokes access.
# (In a real engagement A is a session you legitimately captured for a TEST account
#  that you also control as B — never use a real third party.)

# 1) Log the TEST account in as session A, capture it.
curl -s -L -c "$JAR_A" -X POST "https://$TARGET/api/login" \
  -H 'Content-Type: application/json' \
  -d '{"email":"victim@example.com","password":"OldPass!1"}' -o /dev/null
SESSION_A=$(get_cookie "$JAR_A"); echo "SESSION_A=$SESSION_A"
BEFORE=$(curl -s -L -H "Cookie: $SESSION_A" "https://$TARGET/api/profile")

# 2) Log the SAME account in as session B (separate jar = "the victim's browser").
curl -s -L -c "$JAR_B" -X POST "https://$TARGET/api/login" \
  -H 'Content-Type: application/json' \
  -d '{"email":"victim@example.com","password":"OldPass!1"}' -o /dev/null

# 3) Victim (session B) changes the password.
curl -s -L -b "$JAR_B" -X POST "https://$TARGET/api/change-password" \
  -H 'Content-Type: application/json' \
  -d '{"old_password":"OldPass!1","new_password":"BrandNew!2"}' -o /dev/null

# 4) THE TEST: replay the OLD SESSION_A captured in step 1.
AFTER=$(curl -s -L -H "Cookie: $SESSION_A" "https://$TARGET/api/profile" -w '\n[%{http_code}]')
echo "AFTER pw-change: $AFTER"
```
**Decision + FP discipline:**
- Finding is confirmed only if `AFTER` returns 200 **and** the body still carries the account's unique data (body-diff vs `BEFORE`). A bare 200 on a public/SPA route is not proof.
- Run the **garbage-cookie negative control** again to prove the endpoint is session-gated.
- Repeat the identical flow for **email-change** (`/settings/email`) and for **logout-all-devices** — apps frequently invalidate the *acting* session (B) but not *sibling* sessions (A). That sibling-survival is the exact persistent-ATO primitive `account-takeover` chains.
- **Severity gate:** if the change-password endpoint also lacks a current-password / MFA step-up (per `mfa-and-passwords`), A can pivot from read-only to full takeover → escalate.

### Validation (house FP discipline)

Before claiming ANY session finding:
- **Two real sessions, not placeholders** — every fixation/invalidation claim uses A and B captured by the `curl` flows above.
- **Body-diff, never status-only** — a 200 means nothing without the account's unique identity marker present in the body, diffed against the authenticated baseline.
- **Negative control** — a garbage/random cookie must FAIL where your "surviving" cookie succeeds; otherwise the endpoint isn't session-gated and it's a non-finding.
- **Cache/edge check** — re-request with a cache-buster and from a second IP; rule out an edge-cached or IP-pinned 200.
- **OOB for theft chains** — when the impact depends on exfiltrating a cookie/token (XSS, SSRF, log leak), confirm receipt out-of-band (Collaborator) rather than asserting it.
- **Static-vs-state** — `HttpOnly`/`Secure`/`SameSite` absence is a *policy* observation; only report as High once paired with a real exploit primitive (XSS, network-MITM, CSRF). Standalone attribute gaps are Low/Informational.

**Severity:**
- Session fixation → admin/SSO takeover: **Critical**
- No invalidation on password/email change, or refresh-token reuse without detection: **High → Critical** (escalate if MFA/step-up also absent)
- Predictable/duplicate session ID: **High**
- No invalidation on logout: **Medium → High** (depends on theft vector)
- Missing `HttpOnly`/`SameSite` standalone: **Low/Informational** until chained

### C. Validation / proof bar — how to confirm and avoid false positives

- Use TWO real sessions (attacker A + victim B). Body-diff every 200 response; show a live authenticated action as B from A's starting position, not merely an accepted cookie.
- For theft chains, require out-of-band confirmation (Collaborator hit with the token) or a demonstrated login as the victim; a leaked cookie that is HttpOnly/secure-scoped and never delivered anywhere is not a finding.
- Rotation/reuse: honor documented grace periods — an overlap window is legitimate (Auth0 false-positive note). Only claim missing reuse detection after RT2 works *outside* any grace window; confirm family revocation by testing both tokens.
- Fixation requires showing the victim actually authenticates on the attacker-chosen ID; a cookie you set but the server ignores is not fixation.
- Cookie-attribute-only findings (missing `HttpOnly`/`SameSite` with no theft vector) are Low/Informational until chained.
- Redact session cookies and other-user PII in the PoC; preserve raw Set-Cookie headers in evidence but mask values.

- Prove fixation with a full walkthrough: seed the token, have the victim log in, then use the token from a browser that never saw their credentials. Showing that the token is merely accepted post-login is not enough.
- For "no invalidation" findings, replay at three points — logout, password change, and email change — and note each result; a control that works at only one point is still a finding but the impact differs.
- Verify the stale token still accesses *sensitive* data, not just a static page; session handling often serves cached public content even after logout.
- When reporting refresh-token reuse detection failures, show RT1 failed on second use AND RT2 still worked, then re-check after a short interval to exclude an intentional grace window.
- For token-in-URL, require an actual third-party Referer or log entry containing the token — "it was in the URL" alone is a best-practice observation, not a demonstrated leak.
- Sequencer results need enough samples and a valid token format; a "weak" score on a token with a large random component can be a tooling artifact — confirm with manual inspection/decode.
- Distinguish a stolen session from a legitimately shared one: use two accounts you control and show the attacker never possessed the victim's password or OTP.
- Re-test all findings in a clean browser profile to eliminate cached cookies, service-worker state, and HSTS/cookie-jar artifacts from the proof.
- Redact all session cookie values, JWTs, and other-user PII in screenshots; keep only the cookie name and enough prefix to identify the token.

### Phase 3 — Invalidation on Password / Email Change (persistent-ATO core)

```bash
# This is the real two-session flow. A = attacker holding a stolen/old session.
# B = the victim who changes their password believing it revokes access.
# (In a real engagement A is a session you legitimately captured for a TEST account
#  that you also control as B — never use a real third party.)

# 1) Log the TEST account in as session A, capture it.
curl -s -L -c "$JAR_A" -X POST "https://$TARGET/api/login" \
  -H 'Content-Type: application/json' \
  -d '{"email":"victim@example.com","password":"OldPass!1"}' -o /dev/null
SESSION_A=$(get_cookie "$JAR_A"); echo "SESSION_A=$SESSION_A"
BEFORE=$(curl -s -L -H "Cookie: $SESSION_A" "https://$TARGET/api/profile")

# 2) Log the SAME account in as session B (separate jar = "the victim's browser").
curl -s -L -c "$JAR_B" -X POST "https://$TARGET/api/login" \
  -H 'Content-Type: application/json' \
  -d '{"email":"victim@example.com","password":"OldPass!1"}' -o /dev/null

# 3) Victim (session B) changes the password.
curl -s -L -b "$JAR_B" -X POST "https://$TARGET/api/change-password" \
  -H 'Content-Type: application/json' \
  -d '{"old_password":"OldPass!1","new_password":"BrandNew!2"}' -o /dev/null

# 4) THE TEST: replay the OLD SESSION_A captured in step 1.
AFTER=$(curl -s -L -H "Cookie: $SESSION_A" "https://$TARGET/api/profile" -w '\n[%{http_code}]')
echo "AFTER pw-change: $AFTER"
```
**Decision + FP discipline:**
- Finding is confirmed only if `AFTER` returns 200 **and** the body still carries the account's unique data (body-diff vs `BEFORE`). A bare 200 on a public/SPA route is not proof.
- Run the **garbage-cookie negative control** again to prove the endpoint is session-gated.
- Repeat the identical flow for **email-change** (`/settings/email`) and for **logout-all-devices** — apps frequently invalidate the *acting* session (B) but not *sibling* sessions (A). That sibling-survival is the exact persistent-ATO primitive `hunt-ato` chains.
- **Severity gate:** if the change-password endpoint also lacks a current-password / MFA step-up (per `hunt-mfa-bypass`), A can pivot from read-only to full takeover → escalate.

### Escalation and related chains

### Escalation chains

- Session fixation -> ATO.
- Token leak -> session hijack.

### Chain Table

| Session finding | Chain to | Impact |
|----------------|----------|--------|
| Session fixation (forced `__Host-`-less cookie) | Trick admin/SSO user into authenticating on planted ID | Admin session takeover (Critical) |
| No logout/password-change invalidation | `xss`/`dom` cookie theft → replay surviving session | Persistent ATO past victim's reset |
| Refresh token, no reuse-detection | Leaked RT (SSRF/log/bundle) → infinite access-token minting | Persistent ATO, survives password change |
| `SameSite=Lax` only | Sibling-subdomain top-level nav (CVE-2024-22424 class) → CSRF | State change / login-CSRF → fixation |
| JWT no `exp`/`jti` | Stolen token, no server revocation | Permanent access |
| DBSC downgrade accepted | Steal plain cookie despite device-binding | Defeats the only theft mitigation |
| Predictable ID | Compute/brute another user's session | Cross-user ATO |

---

### Chain Table

| Session finding | Chain to | Impact |
|----------------|----------|--------|
| Session fixation (forced `__Host-`-less cookie) | Trick admin/SSO user into authenticating on planted ID | Admin session takeover (Critical) |
| No logout/password-change invalidation | `hunt-xss`/`hunt-dom` cookie theft → replay surviving session | Persistent ATO past victim's reset |
| Refresh token, no reuse-detection | Leaked RT (SSRF/log/bundle) → infinite access-token minting | Persistent ATO, survives password change |
| `SameSite=Lax` only | Sibling-subdomain top-level nav (CVE-2024-22424 class) → CSRF | State change / login-CSRF → fixation |
| JWT no `exp`/`jti` | Stolen token, no server revocation | Permanent access |
| DBSC downgrade accepted | Steal plain cookie despite device-binding | Defeats the only theft mitigation |
| Predictable ID | Compute/brute another user's session | Cross-user ATO |

---

### Tools and wordlists

### Tools

`Burp` · `jwt_tool` · `browser devtools`

### Wordlists

Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.

| File | Entries |
|---|---:|
| `~/.local/share/hackerone-reports/wordlists/paths_session.txt` | 70 |
| `~/.local/share/hackerone-reports/wordlists/params_session.txt` | 57 |
| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |
| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |

```sh
W=~/.local/share/hackerone-reports/wordlists
ffuf -u https://target/FUZZ -w $W/paths_session.txt \
     -mc all -fc 404 -fs 0 -rate 40
ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_session.txt \
     -mr 'canary|error|invalid|not found' -rate 40
```

### Nuclei

Check cookie flags and token lifecycle by hand; scanner coverage is thin.

```sh
nuclei -u https://target -tags cookie,session,jwt,token \
       -severity low,medium,high,critical -rl 40 -o nuclei_session.txt
nuclei -u https://target -t ~/nuclei-templates/http/misconfiguration \
       -rl 40 -o nuclei_session_misconfiguration.txt
# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'
```

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

### Sources and related reading

### Query the corpus

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class session --limit 20
python3 ~/.local/share/hackerone-reports/h1.py stats --class session
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```

Search by technology, endpoint, parameter, or program. Examples:

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class session
python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class session --min-bounty 1000
```

### Related

- `hackerone-auth-bypass` (989 reports)
- `hackerone-csrf` (541 reports)
- `hackerone-mfa-and-passwords` (285 reports)

### Related

- `auth-bypass` (989 reports)
- `csrf` (541 reports)
- `mfa-and-passwords` (285 reports)

### D. Sources — numbered list of URLs you actually fetched

1. https://portswigger.net/burp/documentation/desktop/testing-workflow/vulnerabilities/session-management
2. https://auth0.com/blog/refresh-token-security-detecting-hijacking-and-misuse-with-auth0
3. https://hacktricks.wiki/en/pentesting-web/oauth-to-account-takeover.html
4. https://portswigger.net/web-security/race-conditions

### Additional notes

### Parameters observed

`proto` · `title` · `setlang` · `renderContext` · `batch_time` · `environmentId` · `action` · `shop` · `verificationUrl` · `sentry_key` · `utm_swu` · `ddsource` · `ddtags` · `demo_param` · `usp` · `password` · `id` · `commit` · `_ga` · `tenantId`

### Session works after logout from Shopify account and password of online store is displayed

`#837729` · Shopify · $0 · low · 2020-04-27 · ▲157
> When a user creates a Shopify Lite Plan account, in the product creation stage when the account has not been upgraded, the store's password is enabled such that any visitor who wants to access the store is required to enter password before being granted access to view the products listed in the online store.

### H1514 Session Fixation on multiple shopify-built apps on *.shopifycloud.com and *.shopifyapps.com

`#423136` · Shopify · $0 · n/a · 2019-04-25 · ▲144
> As the policy pointed out XSS on .shopifycloud.com and .shopifyapps.com are N/A. That means finding XSS on them should be fairly trivial. Anyway after the XSS on embedded SDK I started to think what I can do with it. I played around some other shopify-built apps and discovered that some of them use signed session and the other use session id. Looking further I realized some which use session id do not generate a new session id after logging in.

### Session Cookie Leakage via Static Header Field in WebViewerFragment

`#3475626` · LinkedIn · $0 · high · 2026-03-17 · ▲131
> A static field (CUSTOM HEADERS) in WebViewerFragment persists cookies across different URL loads, allowing an attacker to chain multiple weaknesses to exfiltrate a victim's LinkedIn session cookies to an attacker-controlled server.

### No Session Expiry after log-out, attacker can reuse the old cookies

`#1162443` · Shopify · $500 · low · 2024-05-01 · ▲87
> Hi, There is no session expiry after log-out which can help an attacker to take-over the full account by reusing it. Reproduction Steps 1. Go to https://exchangemarketplace.com/ and click on Sign In 2. Continue with Google Account 3. Use "EditThisCookie" Extension to export the cookies 4. Once you logged in - click on "EditThisCookie" Extension and export the cookies 5.

### Insufficient session expiration in the **com.shopify.ping** android app

`#1172205` · Shopify · $0 · low · 2021-11-26 · ▲63
> It was identified that despite a logout action will be taken by the user at the com.shopify.ping application, the authentication token is not invalidated which allows fully recovery of the initially acquired session. More specifically, after the user provides the required credentials, an access token will be fetched from the server at accounts.shopify.com/oauth/token.

### Grounding — patterns that shaped each phase

No invented CVE/report IDs below. These are the *named, publicly-documented* patterns this skill encodes:

- **Session fixation, login-CSRF, no-regeneration-on-auth** — OWASP WSTG-SESS-03 / WSTG-SESS-01; the classic ACROS / Mitja Kolšek session-fixation paper. Highest-impact variant: fixing the session of an SSO/admin user.
- **SameSite=Lax sibling-subdomain CSRF reaching session state** — Argo CD **CVE-2024-22424** (Lax cookies sent on top-level cross-site navigations from a sibling subdomain). Use this when a session cookie relies on `SameSite=Lax` as its only CSRF defence.
- **Refresh-token rotation & automatic reuse-detection** — the Auth0/IETF OAuth-Security-BCP model: a rotated refresh token, if replayed, must invalidate the *entire token family*. Absence = the core bug to prove.
- **Device Bound Session Credentials (DBSC)** — the W3C/Chrome DBSC draft binds a session to a TPM/device key. Test the *downgrade*: does the server still accept a non-bound cookie when the DBSC challenge is stripped?
- **Cookie attribute hardening** — OWASP WSTG-SESS-02; `__Host-`/`__Secure-` prefixes per RFC 6265bis. Missing `HttpOnly` is only a finding when a real XSS/DOM sink exists (chain with `xss`/`dom`).
- **Entropy** — NIST SP 800-63B requires ≥64 bits of entropy in a session identifier. Treat anything decodable to a counter/timestamp/userId as a finding regardless of length.

Cross-refs: ATO chaining → `account-takeover`; JWT alg/kid tampering → `api-misconfig`; OAuth code/state flaws → `oauth-oidc`; CSRF mechanics → `csrf`; cookie-theft sinks → `xss` / `dom`.

---

### Phase 1 — Session Fixation (regeneration-on-login)

```bash
# Step 1: grab a pre-auth session the SERVER hands an anonymous client.
curl -s -L -c "$JAR_A" "https://$TARGET/login" -o /dev/null
PRE=$(get_cookie "$JAR_A"); echo "pre-auth: $PRE"

# Step 1b (stronger): can we FORCE an arbitrary ID? attacker-chosen value.
FIX="session=AAAAdeadbeefAAAA"

# Step 2: authenticate while CARRYING the pre-auth/forced cookie (reuse same jar).
curl -s -L -c "$JAR_A" -b "$JAR_A" -X POST "https://$TARGET/login" \
  -d "username=attacker@example.com&password=CorrectHorse1" -o /dev/null
POST=$(get_cookie "$JAR_A"); echo "post-auth: $POST"

# DECISION:
#  - If $POST == $PRE (value unchanged across the auth boundary) AND that value
#    now returns authenticated data → FIXATION. The server reused the anon ID.
#  - If the forced $FIX value is accepted and authenticates → CRITICAL fixation
#    (attacker controls the ID; no email/XSS needed to plant it).
AUTH=$(curl -s -L -b "$JAR_A" "https://$TARGET/api/me")
echo "$AUTH" | head -c 200
```
**FP guard:** a value *change* is not automatically safe — some apps rotate the readable cookie but keep a stable server-side session keyed by a second cookie. Diff the FULL `Set-Cookie` set and confirm the *old* value is genuinely dead (Phase 2). Also confirm `/api/me` returns *your* identity, not a generic 200/landing page.

### Phase 4 — Cookie Attribute Analysis

```bash
curl -sI -L "https://$TARGET/" | grep -i '^set-cookie'
```
- **HttpOnly** missing → cookie reachable via `document.cookie`. Only a finding **chained to a real XSS/DOM sink** (`xss`/`dom`) — note it, don't report standalone as High.
- **Secure** missing → cookie sent over cleartext HTTP; pair with `tls-network` (downgrade/HSTS-gap) for a network-attacker chain.
- **SameSite** missing/`None` → CSRF reachability; `SameSite=Lax` is bypassable via sibling-subdomain top-level navigation (Argo CD **CVE-2024-22424** class) → hand to `csrf`.
- **`__Host-` / `__Secure-` prefix absent** → the session can be overwritten/fixated from a subdomain or non-secure context; its presence largely kills cookie-fixation, so flag the *absence* as the precondition for Phase 1.

### Phase 5 — Session-ID Entropy

```bash
# Collect a LARGE sample (200+) of freshly-issued IDs. -L is required: a 302
# /login often sets the cookie on the redirect target, not the first response.
N=200; SAMP=$(mktemp)
for i in $(seq 1 $N); do
  J=$(mktemp)
  curl -s -L -c "$J" "https://$TARGET/login" -o /dev/null
  get_cookie "$J" | cut -d= -f2- >> "$SAMP"
  rm -f "$J"
done
sort "$SAMP" | uniq -d | head            # duplicates = catastrophic (re-use)
awk '{print length($0)}' "$SAMP" | sort -n | uniq -c   # length distribution
```
Then analyse, don't eyeball:
- **Sequential / monotonic** — `sort -n` the decoded values; a steady +1/+N delta = predictable.
- **Decodable structure** — `base64 -d` / hex-decode each ID and look for embedded `userId`, unix timestamps, or PIDs.
- **Bit entropy** — feed the raw bytes to `ent` or `dieharder`; NIST SP 800-63B wants ≥64 bits. 10 samples is far too few to claim anything — gather hundreds.
- **FP guard:** a long random-*looking* token is not proof of strength; only structural decode + a large-sample entropy estimate is. Conversely a short token with high per-char entropy may still be fine — measure, don't count characters.

### Phase 6 — JWT-as-Session

```bash
JWT="eyJ..."        # captured from Authorization: Bearer or a cookie
# Decode header + payload safely (base64url padding fix).
b64url(){ local s="${1//-/+}"; s="${s//_//}"; printf '%s' "$s===" | base64 -d 2>/dev/null; }
b64url "$(cut -d. -f1 <<<"$JWT")" | jq .   # header: alg, kid
b64url "$(cut -d. -f2 <<<"$JWT")" | jq .   # claims: exp, iat, sub, jti
```
- **`exp` missing or years out** → no expiry. **`jti` missing** → server cannot maintain a revocation list → logout can't truly revoke.
- **Revocation test:** logout, then replay the *same* JWT against `/api/me`. If it still returns the user → tokens are not server-revocable; this is the JWT-session persistence finding. Body-diff to avoid a cached 200.
- **Tampering (alg/kid/key-confusion) is owned by `api-misconfig`** — hand off `jwt_tool $JWT -T` / `-X a` there rather than duplicating it.

### Phase 7 — Refresh-Token Rotation & Reuse-Detection

```bash
# 1) Obtain a refresh token (login or /oauth/token), then rotate it once.
RT1=$(curl -s -L -X POST "https://$TARGET/api/login" \
  -H 'Content-Type: application/json' \
  -d '{"email":"victim@example.com","password":"OldPass!1"}' | jq -r '.refresh_token')

# 2) Use RT1 to mint a new access token — server SHOULD return a rotated RT2.
R2=$(curl -s -L -X POST "https://$TARGET/auth/refresh" \
  -H 'Content-Type: application/json' -d "{\"refresh_token\":\"$RT1\"}")
RT2=$(jq -r '.refresh_token' <<<"$R2"); echo "rotated? RT1!=RT2 -> $([ "$RT1" != "$RT2" ] && echo yes || echo NO-ROTATION)"

# 3) REUSE-DETECTION test: replay the OLD RT1 again (simulating the leaked token).
REPLAY=$(curl -s -L -X POST "https://$TARGET/auth/refresh" \
  -H 'Content-Type: application/json' -d "{\"refresh_token\":\"$RT1\"}" -w '\n[%{http_code}]')
echo "RT1 replay: $REPLAY"

# 4) Then confirm RT2 was KILLED by the replay (correct BCP behaviour invalidates
#    the whole family). If RT2 still works after RT1 was replayed → no family-revocation.
curl -s -L -X POST "https://$TARGET/auth/refresh" \
  -H 'Content-Type: application/json' -d "{\"refresh_token\":\"$RT2\"}" -w '\n[%{http_code}]'
```
**Findings:** no rotation (RT1==RT2) = a long-lived stealable credential; rotation **without** reuse-detection (RT1 replay still mints tokens, or RT2 survives the replay) = the leaked-token-persistence bug per the OAuth Security BCP. **OOB note:** if you suspect a leaked RT via SSRF/log/JS-bundle, confirm the token's reach with `ssrf`/`info-disclosure`, not by guessing.

### Phase 8 — OAuth/SSO Session Linkage & DBSC Downgrade

```bash
# SSO linkage: after IdP callback, is the app session bound to the IdP session?
#  - Log out at the IdP only; replay the app session cookie. Still 200 with user
#    data → app session outlives the IdP session (single-logout gap).
# DBSC downgrade: if responses carry Sec-Session-Registration / Sec-Session-Id,
#  strip the device-bound proof header and replay the plain cookie:
curl -s -L -H "Cookie: $A" "https://$TARGET/api/me" -w '\n[%{http_code}]'
#  If the plain (non-bound) cookie is still accepted → device-binding is advisory,
#  not enforced → a stolen cookie defeats DBSC entirely.
```
Hand OAuth `state`/`redirect_uri`/code-injection to `oauth-oidc`; this phase only covers the *session-layer* binding.

---

### Grounding — patterns that shaped each phase

No invented CVE/report IDs below. These are the *named, publicly-documented* patterns this skill encodes:

- **Session fixation, login-CSRF, no-regeneration-on-auth** — OWASP WSTG-SESS-03 / WSTG-SESS-01; the classic ACROS / Mitja Kolšek session-fixation paper. Highest-impact variant: fixing the session of an SSO/admin user.
- **SameSite=Lax sibling-subdomain CSRF reaching session state** — Argo CD **CVE-2024-22424** (Lax cookies sent on top-level cross-site navigations from a sibling subdomain). Use this when a session cookie relies on `SameSite=Lax` as its only CSRF defence.
- **Refresh-token rotation & automatic reuse-detection** — the Auth0/IETF OAuth-Security-BCP model: a rotated refresh token, if replayed, must invalidate the *entire token family*. Absence = the core bug to prove.
- **Device Bound Session Credentials (DBSC)** — the W3C/Chrome DBSC draft binds a session to a TPM/device key. Test the *downgrade*: does the server still accept a non-bound cookie when the DBSC challenge is stripped?
- **Cookie attribute hardening** — OWASP WSTG-SESS-02; `__Host-`/`__Secure-` prefixes per RFC 6265bis. Missing `HttpOnly` is only a finding when a real XSS/DOM sink exists (chain with `hunt-xss`/`hunt-dom`).
- **Entropy** — NIST SP 800-63B requires ≥64 bits of entropy in a session identifier. Treat anything decodable to a counter/timestamp/userId as a finding regardless of length.

Cross-refs: ATO chaining → `hunt-ato`; JWT alg/kid tampering → `hunt-api-misconfig`; OAuth code/state flaws → `hunt-oauth`; CSRF mechanics → `hunt-csrf`; cookie-theft sinks → `hunt-xss` / `hunt-dom`.

---

### Phase 4 — Cookie Attribute Analysis

```bash
curl -sI -L "https://$TARGET/" | grep -i '^set-cookie'
```
- **HttpOnly** missing → cookie reachable via `document.cookie`. Only a finding **chained to a real XSS/DOM sink** (`hunt-xss`/`hunt-dom`) — note it, don't report standalone as High.
- **Secure** missing → cookie sent over cleartext HTTP; pair with `hunt-tls-network` (downgrade/HSTS-gap) for a network-attacker chain.
- **SameSite** missing/`None` → CSRF reachability; `SameSite=Lax` is bypassable via sibling-subdomain top-level navigation (Argo CD **CVE-2024-22424** class) → hand to `hunt-csrf`.
- **`__Host-` / `__Secure-` prefix absent** → the session can be overwritten/fixated from a subdomain or non-secure context; its presence largely kills cookie-fixation, so flag the *absence* as the precondition for Phase 1.

### Phase 6 — JWT-as-Session

```bash
JWT="eyJ..."        # captured from Authorization: Bearer or a cookie
# Decode header + payload safely (base64url padding fix).
b64url(){ local s="${1//-/+}"; s="${s//_//}"; printf '%s' "$s===" | base64 -d 2>/dev/null; }
b64url "$(cut -d. -f1 <<<"$JWT")" | jq .   # header: alg, kid
b64url "$(cut -d. -f2 <<<"$JWT")" | jq .   # claims: exp, iat, sub, jti
```
- **`exp` missing or years out** → no expiry. **`jti` missing** → server cannot maintain a revocation list → logout can't truly revoke.
- **Revocation test:** logout, then replay the *same* JWT against `/api/me`. If it still returns the user → tokens are not server-revocable; this is the JWT-session persistence finding. Body-diff to avoid a cached 200.
- **Tampering (alg/kid/key-confusion) is owned by `hunt-api-misconfig`** — hand off `jwt_tool $JWT -T` / `-X a` there rather than duplicating it.

### Phase 7 — Refresh-Token Rotation & Reuse-Detection

```bash
# 1) Obtain a refresh token (login or /oauth/token), then rotate it once.
RT1=$(curl -s -L -X POST "https://$TARGET/api/login" \
  -H 'Content-Type: application/json' \
  -d '{"email":"victim@example.com","password":"OldPass!1"}' | jq -r '.refresh_token')

# 2) Use RT1 to mint a new access token — server SHOULD return a rotated RT2.
R2=$(curl -s -L -X POST "https://$TARGET/auth/refresh" \
  -H 'Content-Type: application/json' -d "{\"refresh_token\":\"$RT1\"}")
RT2=$(jq -r '.refresh_token' <<<"$R2"); echo "rotated? RT1!=RT2 -> $([ "$RT1" != "$RT2" ] && echo yes || echo NO-ROTATION)"

# 3) REUSE-DETECTION test: replay the OLD RT1 again (simulating the leaked token).
REPLAY=$(curl -s -L -X POST "https://$TARGET/auth/refresh" \
  -H 'Content-Type: application/json' -d "{\"refresh_token\":\"$RT1\"}" -w '\n[%{http_code}]')
echo "RT1 replay: $REPLAY"

# 4) Then confirm RT2 was KILLED by the replay (correct BCP behaviour invalidates
#    the whole family). If RT2 still works after RT1 was replayed → no family-revocation.
curl -s -L -X POST "https://$TARGET/auth/refresh" \
  -H 'Content-Type: application/json' -d "{\"refresh_token\":\"$RT2\"}" -w '\n[%{http_code}]'
```
**Findings:** no rotation (RT1==RT2) = a long-lived stealable credential; rotation **without** reuse-detection (RT1 replay still mints tokens, or RT2 survives the replay) = the leaked-token-persistence bug per the OAuth Security BCP. **OOB note:** if you suspect a leaked RT via SSRF/log/JS-bundle, confirm the token's reach with `hunt-ssrf`/`hunt-source-leak`, not by guessing.

### Phase 8 — OAuth/SSO Session Linkage & DBSC Downgrade

```bash
# SSO linkage: after IdP callback, is the app session bound to the IdP session?
#  - Log out at the IdP only; replay the app session cookie. Still 200 with user
#    data → app session outlives the IdP session (single-logout gap).
# DBSC downgrade: if responses carry Sec-Session-Registration / Sec-Session-Id,
#  strip the device-bound proof header and replay the plain cookie:
curl -s -L -H "Cookie: $A" "https://$TARGET/api/me" -w '\n[%{http_code}]'
#  If the plain (non-bound) cookie is still accepted → device-binding is advisory,
#  not enforced → a stolen cookie defeats DBSC entirely.
```
Hand OAuth `state`/`redirect_uri`/code-injection to `hunt-oauth`; this phase only covers the *session-layer* binding.

---

## Companion methodology (complete, deduplicated)

Full text of every non-SKILL.md methodology document from the contributing skills.

### Companion: hunting / references/payloads.md

# Session — Combined Field Guide — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

## Payloads & probes



- Set-Cookie -> `; SameSite=None` without Secure

- Fixate -> `PHPSESSID=attacker` before login

- Reuse -> old token after logout/password change



## Payload fragments observed



Recurring payloads from this class's writeups. Adapt, don't paste blindly.



| Seen | Fragment |

|---:|---|

| 5× | `rtsp_connect()` |

| 5× | `$\x00\x00\x10` |

| 3× | `Curl_ws_accept()` |

| 3× | `Curl_ssl_scache_take()` |

| 3× | `rtsp_filter_rtp()` |

| 3× | `rtsp_done()` |

| 2× | `(valid_until > 0) && (valid_until < now)` |

| 2× | `(-1 > 0) = FALSE` |

| 2× | `curl_easy_ssls_export()` |

| 2× | `valid_until < 0` |

| 2× | `match_ssl_primary_config()` |

| 2× | `SSL_connect()` |

| 2× | `rtspc->in_header = FALSE` |

| 2× | `rtspc->buf` |

| 2× | `curl -c cookies.txt -b cookies.txt https://somesite.tld:9999/` |

| 2× | `ssl_peer_key_build()` |

| 2× | `peer->origin->scheme->family` |

| 1× | `document.cookie='_flow_session=EVIL;domain=.shopifycloud.com;path=/';` |

| 1× | `javascript://www.linkedin.com/%0aalert(1)` |

| 1× | `javascript://www.linkedin.com/%0aalert(1)?renderContext=trustVerificationDeeplink` |



## Parameters observed



`proto` · `title` · `setlang` · `renderContext` · `batch_time` · `environmentId` · `action` · `shop` · `verificationUrl` · `sentry_key` · `utm_swu` · `ddsource` · `ddtags` · `demo_param` · `usp` · `password` · `id` · `commit` · `_ga` · `tenantId`



## Wordlists



Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.



| File | Entries |

|---|---:|

| `~/.local/share/hackerone-reports/wordlists/paths_session.txt` | 70 |

| `~/.local/share/hackerone-reports/wordlists/params_session.txt` | 57 |

| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |

| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |



```sh

W=~/.local/share/hackerone-reports/wordlists

ffuf -u https://target/FUZZ -w $W/paths_session.txt \

     -mc all -fc 404 -fs 0 -rate 40

ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_session.txt \

     -mr 'canary|error|invalid|not found' -rate 40

```



## Nuclei



Check cookie flags and token lifecycle by hand; scanner coverage is thin.



```sh

nuclei -u https://target -tags cookie,session,jwt,token \

       -severity low,medium,high,critical -rl 40 -o nuclei_session.txt

nuclei -u https://target -t ~/nuclei-templates/http/misconfiguration \

       -rl 40 -o nuclei_session_misconfiguration.txt

# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'

```



Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

### Companion: hunting / references/techniques.md

# Session — Combined Field Guide — Technique reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete technique.

---

## Quick wins



Start here. These are the highest-yield tests for this class.



- Check cookie flags: Secure, HttpOnly, SameSite, scope, lifetime.

- Test fixation and rotation on login/logout/privilege change.

- Test revocation after password change or logout.

- Look for predictable tokens and JWT weaknesses.



## Bypass tricks



- Cross-subdomain cookie leakage.

- Token in URL/Referer.



## Deeper checklist



- Check cookie flags: Secure, HttpOnly, SameSite, scope, and lifetime.

- Test session fixation and rotation on login/logout/privilege change.

- Test token revocation and reuse after password change or logout.

- Look for predictable tokens and JWT weaknesses.

- Check cross-subdomain cookie leakage.

- Demonstrate session hijack or persistence.



## Techniques from real reports



One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.



- **Session works after logout from Shopify account and password of online store is displayed** — `#837729` · Shopify · $0 · ▲157

  > When a logout request has been made and response has been received/displayed that logout is successful, session still works when

- **H1514 Session Fixation on multiple shopify-built apps on *.shopifycloud.com and *.shopifyapps.com** — `#423136` · Shopify · $0 · ▲144

  > Attacker uses XSS on .shopifycloud.com and writes the cookie scoped to all subdomain to victim `document.cookie=' flow session=EVIL;domain=.shopifycloud.com;path=/';`

- **Session Cookie Leakage via Static Header Field in WebViewerFragment** — `#3475626` · LinkedIn · $0 · ▲131

  > A static field (`CUSTOM HEADERS`) in `WebViewerFragment` persists cookies across different URL loads, allowing an attacker to chain multiple weaknesses to exfiltrate a victim's LinkedIn session cookies to an attacker-controlled server.

- **No Session Expiry after log-out, attacker can reuse the old cookies** — `#1162443` · Shopify · $500 · ▲87

  > Now open another browser and import those cookies - you can able to login an account by using cookies

- **Insufficient session expiration in the **com.shopify.ping** android app** — `#1172205` · Shopify · $0 · ▲63

  > More specifically, after the user provides the required credentials, an access token will be fetched from the server at accounts.shopify.com/oauth/token.

- **Session Persistence Designed to Keep Users Logged In Across Multiple Devices (Intended Behaviour)** — `#3161827` · Shopify · $0 · ▲63

  > An attacker with access to the session cookie prior to logout can reuse the same cookie to re-authenticate, effectively bypassing the logout process and regaining access to the account.

- **Apache Airflow Fab Provider: Application does not invalidate session after password change via Airflow cli** — `#3073507` · Internet Bug Bounty · $0 · ▲57

  > When a user changes his password by visiting `/resetmypassword` form, the application terminates all the existing sessions.

- **Improper Session Invalidation – Auto Sign-In Without Credentials After Logout (Affects Chrome & Firefox)** — `#3101207` · Dust · $0 · ▲56

  > - Set cache-control headers to prevent session restoration via back/forward navigation.

- **ABLE TO TRICK THE VICTIM INTO USING A CRAFTED EMAIL ADDRESS FOR A PARTICULAR  SESSION AND THEN LATER TAKE BACK THE ACCOUNT** — `#1357013` · Mattermost · $0 · ▲49

  > https://hackerone.cloud.mattermost.com/signup user complete/?d={"display name":"\u003ch1\u003ea","email":"██████████","name":"main"}&t=cqtkyznxn8e43yagt9fjcsrc4nh6yoqq914in3zg4ykj1jkjbc9bippckjikj4cw

- **Revoking user session in https://hackerone.com/settings/sessions does not revoke the GraphQL query session** — `#417382` · HackerOne · $500 · ▲47

  > I have found an Insufficient Session Expiration on implementation of the new `Revoke user session` feature of HackerOne here: https://hackerone.com/settings/sessions

- **HackerOne Code: a live password reset token reaches Datadog RUM, and the same session records the account it unlocks** — `#4071670` · HackerOne · $200 · ▲45

  > | Reset endpoint | `POST /api/v1/password-reset`, fields `token`, `email`, `password` |

- **Logout Bypass Vulnerability in Hiro.so** — `#3062299` · Hiro · $150 · ▲45

  > Session Hijacking Risk – If an attacker tricks a user into logging out (via CSRF or social engineering), the victim may assume they are logged out while the attacker retains access.

- **Broken Authentication and Session Management Flaw After Change Password and Logout** — `#634488` · Omise · $0 · ▲45

  > [https://www.owasp.org/index.php?title=Broken Authentication and Session Management&setlang=en](https://www.owasp.org/index.php?title=Broken Authentication and Session Management&setlang=en)

- **Lack of session expiration after password reset on TikTok Careers Portal** — `#997127` · TikTok · $50 · ▲38

  > A lack of session expiration following a password reset on the TikTok Careers Portal does not automatically log out a user on another device/browser.

- **curl Missing Sec-WebSocket-Accept Verification Enables MITM WebSocket Session Hijacking** — `#3917775` · curl · $0 · ▲37

  > Run: `python3 poc.py 8766` then in another terminal: `curl -v ws://127.0.0.1:8766/`

- **HTTPS Agent TLS session reuse skips hostname verification across identity policies (incomplete fix of CVE-2026-48934)** — `#3812439` · Node.js · $0 · ▲37

  > An incomplete fix has been identified in Node.js: HTTPS Agent TLS session reuse skips hostname verification across identity policies (incomplete fix of CVE-2026-48934).

- **Session Timeout Does Not Enforce Re-Authentication on AWS Access Portal** — `#2800511` · AWS VDP · $0 · ▲36

  > What type of Amazon AWS account(s) is needed to verify or reproduce this vulnerability?: Amazon AWS account(s) needed to reproduce: An AWS account using AWS SSO with a session timeout policy in place.

- **Improper Session management can cause account takeover[https://micropurchase.18f.gov]** — `#263873` · GSA Bounty · $0 · ▲36

  > Once you are logged in Then Use "BurpSuite" or any other Utility to get the cookies of that session ( "EditThisCookie" Chrome Extension can be used and in a Case of an Attacker he can Use Any Sort Of cookie Stealing Script or Cookies Spoofing Utility to get…

- **Broken Authentication and session management OWASP A2** — `#284` · HackerOne · $0 · ▲36

  > 2) Copy the cookies using Edit this cookie extension when you are logged in using "Import Cookies" option of the extension.

- **Broken Authentication Session Token Bug** — `#948345` · Courier · $0 · ▲35

  > Now log out from your account and request for password reset code for your account .

- **Node.js: TLS session reuse can lead to hostname verification bypass** — `#811502` · Node.js · $0 · ▲29

  > [fwilhelm@fwilhelm node]$ ../node/node-v13.9.0-linux-x64/bin/node poc.js

- **Replayable Password Change Request Across Sessions.** — `#3269777` · Malwarebytes · $0 · ▲28

  > The report describes a vulnerability in the password change endpoint (PUT /authentication/password) that allows for replay attacks.

- **Session Not Expire / 2FA Bypass** — `#2469706` · HackerOne · $0 · ▲28

  > attacker add victim cookies using http://www.editthiscookie.com addon to own browser {{attacker perspective}}

- **Broken Authentication and Session Management** — `#17474` · Phabricator · $0 · ▲26

  > 3) Login using the same password back and update your email address to "b@x.com" and verify the same.

- **Bypassing 2FA with conventional session management - open.rocket.chat** — `#1701378` · Rocket.Chat · $0 · ▲25

  > https://infosecwriteups.com/how-i-couldve-bypassed-the-2fa-security-of-instagram-once-again-43c05cc9b755

- **Improper session management** — `#737` · HackerOne · $100 · ▲24

  > When a request with an invalid authenticity token is received, the user is logged out (tested for updating user's profile, which is available here: https://hackerone.com/diekatze/profile/edit) and the user receives a new session cookie, which is not…

- **CVE-2024-0853: OCSP verification bypass with TLS session reuse** — `#2341063` · Internet Bug Bounty · $0 · ▲24

  > Original Report:https://hackerone.com/reports/2298922

- **Broken Authentication and session management OWASP A2** — `#449671` · Liberapay · $0 · ▲24

  > You can also login to my account (admin.101) temp account via this cookies/request.

- **libcurl: Integer truncation in curl_easy_ssls_import() causes TLS sessions to never expire** — `#3658049` · curl · $0 · ▲23

  > In `Curl ssl session unpack()` (`lib/vtls/vtls spack.c:311`), the `valid until` field is read as `uint64 t` and cast directly to `curl off t` (`int64 t`) with no bounds check — so a crafted blob encoding `valid until = 0xFFFFFFFFFFFFFFFF` produces `valid…

- **Session not expired on logout** — `#353` · HackerOne · $100 · ▲22

  > Replay the request captured in step 3 and notice it displays the proper response.



## Case studies



### Session works after logout from Shopify account and password of online store is displayed

`#837729` · Shopify · $0 · low · 2020-04-27 · ▲157

> When a user creates a Shopify Lite Plan account, in the product creation stage when the account has not been upgraded, the store's password is enabled such that any visitor who wants to access the store is required to enter password before being granted access to view the products listed in the online store.



### H1514 Session Fixation on multiple shopify-built apps on *.shopifycloud.com and *.shopifyapps.com

`#423136` · Shopify · $0 · n/a · 2019-04-25 · ▲144

> As the policy pointed out XSS on .shopifycloud.com and .shopifyapps.com are N/A. That means finding XSS on them should be fairly trivial. Anyway after the XSS on embedded SDK I started to think what I can do with it. I played around some other shopify-built apps and discovered that some of them use signed session and the other use session id. Looking further I realized some which use session id do not generate a new session id after logging in.



### Session Cookie Leakage via Static Header Field in WebViewerFragment

`#3475626` · LinkedIn · $0 · high · 2026-03-17 · ▲131

> A static field (CUSTOM HEADERS) in WebViewerFragment persists cookies across different URL loads, allowing an attacker to chain multiple weaknesses to exfiltrate a victim's LinkedIn session cookies to an attacker-controlled server.



### No Session Expiry after log-out, attacker can reuse the old cookies

`#1162443` · Shopify · $500 · low · 2024-05-01 · ▲87

> Hi, There is no session expiry after log-out which can help an attacker to take-over the full account by reusing it. Reproduction Steps 1. Go to https://exchangemarketplace.com/ and click on Sign In 2. Continue with Google Account 3. Use "EditThisCookie" Extension to export the cookies 4. Once you logged in - click on "EditThisCookie" Extension and export the cookies 5.



### Insufficient session expiration in the **com.shopify.ping** android app

`#1172205` · Shopify · $0 · low · 2021-11-26 · ▲63

> It was identified that despite a logout action will be taken by the user at the com.shopify.ping application, the authentication token is not invalidated which allows fully recovery of the initially acquired session. More specifically, after the user provides the required credentials, an access token will be fetched from the server at accounts.shopify.com/oauth/token.



## Query the corpus



```sh

python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class session --limit 20

python3 ~/.local/share/hackerone-reports/h1.py stats --class session

python3 ~/.local/share/hackerone-reports/h1.py show <id> --full

```



Search by technology, endpoint, parameter, or program. Examples:



```sh

python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class session

python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class session --min-bounty 1000

```

## Corpus wordlists (mined)

### `params_session.txt`

```text
proto
title
setlang
renderContext
batch_time
environmentId
action
shop
verificationUrl
sentry_key
utm_swu
ddsource
ddtags
demo_param
usp
password
id
commit
tenantId
act
platform
sessionId
__form__
__dialog__
new
email
__submit__
__wflow__
__ajax__
__metablock__
template
tcpg
change-password
return_url
fsid
_v
aip
ni
_s
dl
ul
de
dt
sd
sr
vp
je
ec
ea
el
_u
jid
gjid
cid
tid
_gid
_r
```

### `paths_session.txt`

```text
/login
/password-reset
/myaccount/
/my/account
/wp-admin/admin-ajax.php
/Pe4R-am2
/xmlrpc.php
/accounts/passwords
/auth/callback
/admin/apps/flow
/robots.txt
/products/canvas
/oauth/userinfo
/api/v1/logout
/thread/yw535346rk766ybzpqtvrl36sjj789st
/resetmypassword
/signup_user_complete/
/api/30/csp-report/
/api/v1/password-reset
/dash/scans/1/
/oauth/callback
/api/v2/rum
/forgot-password
/uLFJUJ3CnQQ
/api/tls.html
/authentication/password
/admin.101/edit/username
/index.php/s/Ezn3dOeZ28Hph57
/index.php/s/Ezn3dOeZ28Hph57/download
/index.php/s/Ezn3dOeZ28Hph57/authenticate
/account
/download/edgemax
/accounts/profile/
/hc/
/CN=poc.local
/bug.php
/v0/me
/version.txt
/auth/logout
/handle.save.php
/users.php
/handle.php
/studio/invitations
/mobile
/notifier.php
/es/help
/accounts/reset/
/settings/account
/go/x-2xxxxx-f8xx7
/auth/login
/blog/web-security-zone/what-is-session-fixation/
/user/user_name/edit
/settings/user/(username
/page/email/
/settings/user/(username)/page/email/
/signin
/wp-admin/
/settings/password/
/settings/security/
/security/two-step-authentication/
/j/collect
/rt/riders/1ad0f5c1-1ac0-4c2c-a34a-36f267d7ae6f/dispatch-view
/login/en
/docs/http-cookies.html
/loginhelper
/good-file
/path/to/patched-source
/path/to/patched-build
/path/to/curl-8.23.0
/path/to/curl-8.23.0-build
```

## Source skills merged into this topic

- `h1skills` — `hackerone-session`
- `hunting` — `session`
- `cbh` — `hunt-session`

## Provenance

- `references/unified-method.md` — same deduplicated union as this file, for tooling
- `references/upstream-*.md` — unmodified original SKILL.md from each repo
- `references/upstream-assets/` — 2 companion files
- `../../upstream/` — complete unmodified archives of all five source repositories
- `bbhunt-methodology` — orchestrator, state machine and class router
