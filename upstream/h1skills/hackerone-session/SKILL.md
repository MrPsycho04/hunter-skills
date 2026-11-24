---
name: hackerone-session
description: >-
  Hunt session flaws. Use when testing cookies, tokens, logout, fixation, and concurrent sessions. Backed by 150 disclosed HackerOne reports.
---

# Session Management — HackerOne field guide

Built from **150** publicly disclosed HackerOne reports (2014–2026). Corpus: `~/.local/share/hackerone-reports/`.

## Signal

- Reports: **150** · paid: **22**
- Median bounty **$100** · p90 **$540** · max **$1,600** · total **$6,140**
- Median upvotes **11**

## Where it pays

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

## Quick wins

Start here. These are the highest-yield tests for this class.

- Check cookie flags: Secure, HttpOnly, SameSite, scope, lifetime.
- Test fixation and rotation on login/logout/privilege change.
- Test revocation after password change or logout.
- Look for predictable tokens and JWT weaknesses.

## Payloads & probes

- Set-Cookie -> `; SameSite=None` without Secure
- Fixate -> `PHPSESSID=attacker` before login
- Reuse -> old token after logout/password change

## Bypass tricks

- Cross-subdomain cookie leakage.
- Token in URL/Referer.

## Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`cookie` `session` `token` `jwt` `remember` `logout`

## Tools

`Burp` · `jwt_tool` · `browser devtools`

## Escalation chains

- Session fixation -> ATO.
- Token leak -> session hijack.

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

## Related

- `hackerone-auth-bypass` (989 reports)
- `hackerone-csrf` (541 reports)
- `hackerone-mfa-and-passwords` (285 reports)

## Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.
