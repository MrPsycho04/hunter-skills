---
name: hackerone-mfa-and-passwords
description: >-
  Hunt MFA bypass, OTP flaws, and password policy issues. Use when testing 2FA, recovery codes, and login throttling. Backed by 285 disclosed HackerOne reports.
---

# MFA, OTP & Password Attacks — HackerOne field guide

Built from **285** publicly disclosed HackerOne reports (2014–2026). Corpus: `~/.local/share/hackerone-reports/`.

## Signal

- Reports: **285** · paid: **60**
- Median bounty **$500** · p90 **$3,000** · max **$10,000** · total **$64,056**
- Median upvotes **16**

## Where it pays

| Program | Reports | Bounty | Upvotes |
|---|---|---|---|
| HackerOne | 20 | $11,000 | 1156 |
| Mail.ru | 31 | $10,307 | 1731 |
| Uber | 7 | $8,000 | 115 |
| Shopify | 5 | $5,500 | 194 |
| Nextcloud | 31 | $4,000 | 586 |
| VK.com | 5 | $3,850 | 73 |
| Eternal | 5 | $3,250 | 153 |
| Superhuman (formerly Grammarly) | 3 | $2,500 | 273 |

## Quick wins

Start here. These are the highest-yield tests for this class.

- Test OTP brute force limits, reuse, expiry, and response leakage.
- Try MFA bypass via direct navigation, API calls, and remember-me tokens.
- Check backup-code generation and storage.
- Test password reset/change for missing current-password checks.

## Payloads & probes

- OTP -> `000000`, reuse old code, race multiple codes
- MFA -> call the post-MFA endpoint directly
- Password -> `password[]=x`, type juggling
- Enumeration -> response length/timing variants

## Bypass tricks

- Bypass step-up auth by replaying a privileged session.
- Use unicode/whitespace variants of the password.

## Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`otp` `mfa` `2fa` `password` `reset` `recovery` `backup`

## Tools

`Burp` · `Turbo Intruder` · `ffuf`

## Escalation chains

- MFA bypass -> ATO.
- OTP brute -> ATO.

## Deeper checklist

- Test OTP brute force limits, reuse, expiry, and response leakage.
- Try MFA bypass by direct navigation, API calls, and remember-me tokens.
- Check backup-code generation and storage.
- Test password reset and change flows for missing current-password checks.
- Look for user enumeration via timing and error messages.
- Prove bypass into a protected account or area.

## Techniques from real reports

One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.

- **Improper Authentication - any user can login as other user with otp/logout & otp/login** — `#921780` · Snapchat · $0 · ▲972
  > - Attacker performs `/scauth/otp/login` request with username equal victim's username, and the token obtained on previous step.
- **Change phone number OTP flaw leads to any phone number takeover** — `#2588329` · inDrive · $2,000 · ▲241
  > When an user requests a phone number change inside the app, it will send a 4 digit code but if you place 0000, it will accept any number and update it into the app!!
- **Hacker can bypass 2FA requirement and reporter blacklist through embedded submission form** — `#418767` · HackerOne · $10,000 · ▲208
  > BYPASS: Get the `Embedded Submission` URL on their [policy page](https://hackerone.com/parrot sec): i get this - https://hackerone.com/0a1e1f11-257e-4b46-b949-c7151212ffbb/embedded submissions/new
- **2FA Bypass leads to  impersonation of legimate users** — `#2885636` · Drugs.com · $0 · ▲207
  > Go to https://www.drugs.com/account/register/ and create an account using an email you own.
- **TikTok 2FA Bypass** — `#1247108` · TikTok · $1,564 · ▲194
  > A vulnerability was found where a user would be able to bypass 2FA if logging in and redirecting back on a UK TikTok Seller URL.
- **Previously created sessions continue being valid after MFA activation** — `#667739` · Superhuman (formerly Grammarly) · $0 · ▲176
  > I found one issue related to your 2FA system on https://account.grammarly.com/security
- **Web Authentication Endpoint Credentials Brute-Force Vulnerability** — `#127844` · HackerOne · $0 · ▲161
  > The following successful brute-force attack of 10.001 passwords (https://github.com/danielmiessler/SecLists/blob/master/Passwords/10k most common.txt appended with the real password) against test account ██████:Geniaal2!!
- **Enable 2FA without verifying the email** — `#649533` · Moneybird · $0 · ▲149
  > Attacker sign up with victim email (Email verification will be sent to victim email).
- **Bypassing HackerOne 2FA due to race condition** — `#2598548` · HackerOne · $0 · ▲139
  > When a user canceled one reset request, the remaining requests would stay active, potentially leading to unauthorized 2FA removal after 24 hours.
- **Business Logic Error – Bypass of OTP Verification During Signup on hover.com** — `#3255473` · Tucows (VDP) · $0 · ▲135
  > By omitting the code parameter entirely from the signup request, the backend completes the registration and returns a valid session.
- **Yet Another OTP code Leaked in the API Response** — `#2635315` · MTN Group · $0 · ▲135
  > This is much similar to my report here(https://hackerone.com/reports/2633888) , except it affects a different domain.
- **Adding phone number to profile By OTP brute forcing** — `#3265780` · CoinMate.io · $100 · ▲114
  > Step2: So enter any OTP in the OTP filed and intercept the request in the burp-suite, Then send the intercepted request to burp intruder.
- **Claiming the listing of a non-delivery restaurant through OTP manipulation** — `#1330529` · Eternal · $3,250 · ▲108
  > Here by changing the `verificationCode` - (Otp received on Attacker Mobile in response of Request :1 )& `requestId` (Response of request:1) and `resId` to Victim Restaurant.
- **2FA requirement bypass when inviting team members** — `#3356149` · Omise · $0 · ▲105
  > Use a Burp extension ( Match and Replace) to change the client-side flag `false → true`.
- **Bypass a fix for report #708013** — `#1363672` · Shopify · $3,500 · ▲102
  > Observe that you have bypassed the limit though the email is still valid (to prove it try `{email: \"█████ \", password: \"███\" }` and get the token)
- **Email OTP/2FA Bypass** — `#2315420` · Drugs.com · $0 · ▲100
  > The application has a functionality of 2FA by email OTP so i can bypass that 2FA and got the access of application without having any access of victim account.
- **2FA bypass possible on https://authsvc.singlestore.com** — `#3329361` · SingleStore · $0 · ▲96
  > CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N/CR:H/IR:H/AR:H
- **Password not checked when disabling 2FA on HackerOne** — `#587910` · HackerOne · $0 · ▲95
  > when I was submitted a report to a program that request `2FA` ON, I notice that if you try to disable this option will ask for `backup code - password` and if you enter a random password in the request filed and a correct `backup code` it will be successfully…
- **Improper Authentication Throttling Allows Attacker-Controlled Account Lockouts** — `#3160210` · Lichess · $0 · ▲92
  > Because the system does not verify the request origin or impose intelligent rate-limiting tied to session/IP/fingerprint, an attacker can intentionally lock out legitimate users — impacting their access to the application.
- **Account takeover w/o interaction for a user that doesn't have 2fa enabled via 2fa linking and improper auth at /api/2fa/verify** — `#810880` · Helium · $0 · ▲92
  > Register an account `user2`, register at https://console.helium.com, perform a 2FA request but with ID from `user1`.
- **Session Doesn't expire after 2fa and also other session can change passsword** — `#2234736` · SideFX · $300 · ▲90
  > I found one issue related to your 2FA system on https://sidefx.com
- **“email” MFA mode allows bypassing MFA from victim’s device when the device trust is not expired** — `#665722` · Superhuman (formerly Grammarly) · $2,500 · ▲82
  > When we turn on the MFA and we have the user and password of the user, it is possible bypass the MFA only changing some values the endpoint POST `auth.grammarly.com//v3/api/login`
- **OTP code Leaked in API Response** — `#2633888` · MTN Group · $0 · ▲81
  > The application https://corporate.admyntec.co.za allows users to sign up for device insurance.
- **Information disclosure -> 2fa bypass -> POST exploitation** — `#1276373` · Algolia · $0 · ▲76
  > - There will be 2 buttons : "Revoke" and "Renew", click on "Renew" and intercept that request using proxy like burp suite
- **Weak Rate Limiting Controls in the (LOGIN) page Expose System to Brute Force and DoS Attacks** — `#3085889` · Lichess · $0 · ▲74
  > =================================================================================
- **Able to blocking users with 2fa from login into their accounts by just knowing the SteamID** — `#1179232` · CS Money · $300 · ▲70
  > By changing the steamID cookie on confirm 2fa code request, I am able to block the login of an account with 2fa for 5 minutes (300 seconds).
- **Enable 2FA without verifying the email** — `#3016540` · XVIDEOS · $0 · ▲70
  > After that, Navigate to: https://www.xvideos.com/account/security
- **Bypassing the victim's phone number OTP in the account recovery process on the https://hackerone.com/settings/auth/setup_account_recovery** — `#2501984` · HackerOne · $0 · ▲67
  > First, create an account recovery request using your own phone number and successfully enable account recovery with that same number.
- **Two-factor authentication enforcement bypass** — `#1050244` · Nextcloud · $750 · ▲64
  > https://github.com/nextcloud/server/blob/1762a409f954fd9a66e7572704ea9ba7813601b4/core/templates/twofactorselectchallenge.php
- **Brute Force of fabric-ca server admin account** — `#411364` · Linux Foundation Decentralized Trust · $0 · ▲61
  > - Listening 0.0.0.0:7054(easily discoved and can be reached)

## Payload fragments observed

Recurring payloads from this class's writeups. Adapt, don't paste blindly.

| Seen | Fragment |
|---:|---|
| 2× | `> POST /users/sign_in HTTP/1.1 / > Host: 159.xxx.xxx.xxx / > ... / > ----------1881604860 / > Content-Disposition: form-data; name="user[otp` |
| 2× | `{{temaplte:38dhs_admins_only_header.html}}` |
| 1× | `{email: \"█████ \", password: \"███\" }` |
| 1× | `POST /login/confirm HTTP/1.1 / Host: cs.money / Content-Length: 28 / Connection: close / Cookie: steamid=<victim_steam_id>; / {"token":"foo` |
| 1× | `HTTP/1.1 400 Bad Request / Content-Encoding: gzip / Content-Type: application/json; charset=utf-8 / Date: Tue, 31 Jan 2017 17:45:43 GMT / X-` |
| 1× | `Throttler\sleepDelay` |
| 1× | `{"username":"admin"}` |
| 1× | `/api/system/verification-codes/[0-9]{6}` |
| 1× | `{"password":"<NEW PASSWORD>","code":"<BRUTEFORCED SMS TOKEN>","securityCode":"<RETRIEVED SECURITY CODE>"}` |
| 1× | `<methodName> system.listMethods </methodName>` |
| 1× | `curl -u "RANDOM1:RANDOM2" -X PROPFIND https://server/public.php/webdav` |
| 1× | `[...]OCA\\\\DAV\\\\Connector\\\\Sabre\\\\Auth->validateUserPass('matthes', '***THE_PASSWORD***')[...]` |
| 1× | `/php/restaurantSmsHandler.php?type=app-download-sms&mobile_no=<NUMBER>&csrf_token=<TOKEN>` |
| 1× | `/php/restaurantSmsHandler.php?type=order-app-download-sms&mobile_no=<NUMBER>&csrf_token=<TOKEN>` |
| 1× | `/php/restaurantSmsHandler.php?type=app-download-sms&mobile_no=[8127410000,8317030000,...]&csrf_token=<TOKEN>` |
| 1× | `$ curl --globoff 'http://localhost:3000/api/v1/gems?api_key[]=key1&api_key[]=key2' / > Access Denied. Please sign up for an account at https` |
| 1× | `SecureRandom.hex (32)` |
| 1× | `$response->throttle()` |
| 1× | `using the way ''{{temaplte:38dhs_admins_only_header.html}}'' in 'create new' via 'preview feature', nothing. The other variable name, which` |
| 1× | `{id:"2"}` |

## Parameters observed

`password` · `username` · `template` · `authenticity_token` · `invite_code` · `commit` · `hash` · `phone` · `token` · `api_key[]` · `id` · `next` · `_method` · `type` · `mobile_no` · `csrf_token` · `data` · `uuid` · `redirect` · `product`

## Case studies

### Improper Authentication - any user can login as other user with otp/logout & otp/login
`#921780` · Snapchat · $0 · critical · 2021-09-03 · ▲972
> '/scauth/otp/droid/logout' request contains user id parameter. Usually it is equal to current user user id, but if an attacker passes user id of victim account he can login as victim. I will demonstrate the problem on two accounts. Victim: ███ Attacker: ██████████ - Attacker perform a usuall login to attacker's personal account.

### Bruteforce password recovery code
`#743545` · Bumble · $0 · n/a · 2020-01-18 · ▲258
> It's possible to bruteforce recovery code from SMS as iOS application doesn't have limits for incorrect inputs. I have tried 50+ different combinations until I reached code from SMS.

### Change phone number OTP flaw leads to any phone number takeover
`#2588329` · inDrive · $2,000 · critical · 2024-10-09 · ▲241
> Dear Indrive, Ive found another valid report, the app allows any user to change the app phone number, but a flaw within the otp allows any number to be added into the account! When an user requests a phone number change inside the app, it will send a 4 digit code but if you place 0000, it will accept any number and update it into the app!!

### Hacker can bypass 2FA requirement and reporter blacklist through embedded submission form
`#418767` · HackerOne · $10,000 · medium · 2018-10-31 · ▲208
> A program owner can enforce the hackers to setup the two-factor authentication before submitting new reports to their program here: https://hackerone.com/parrot sec/submission requirements (see below image) {F355169} The Parrot Sec program has this feature enabled to enforce the hackers to setup 2FA before submitting reports. I removed my 2FA to test and it is good that i was block from submitting new reports (see below image) {F355168} ---

### 2FA Bypass leads to  impersonation of legimate users
`#2885636` · Drugs.com · $0 · high · 2025-03-14 · ▲207
> Hello team, I have discovered a logic flaw in the authentication system that allows an attacker (User A) to impersonate a legitimate user (User B) who has not yet registered. By abusing the email change functionality and bypassing 2FA, the attacker can retain access to the account until the legitimate user resets their password.

## Wordlists

Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.

| File | Entries |
|---|---:|
| `~/.local/share/hackerone-reports/wordlists/paths_mfa-and-passwords.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/params_mfa-and-passwords.txt` | 75 |
| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |
| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |

```sh
W=~/.local/share/hackerone-reports/wordlists
ffuf -u https://target/FUZZ -w $W/paths_mfa-and-passwords.txt \
     -mc all -fc 404 -fs 0 -rate 40
ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_mfa-and-passwords.txt \
     -mr 'canary|error|invalid|not found' -rate 40
```

## Nuclei

Test OTP brute-force limits, reuse, and direct post-MFA endpoint access manually.

```sh
nuclei -u https://target -tags auth-bypass,default-login,token-spray,login \
       -severity low,medium,high,critical -rl 40 -o nuclei_mfa-and-passwords.txt
nuclei -u https://target -t ~/nuclei-templates/http/default-logins \
       -rl 40 -o nuclei_mfa-and-passwords_default-logins.txt
nuclei -u https://target -t ~/nuclei-templates/http/token-spray \
       -rl 40 -o nuclei_mfa-and-passwords_token-spray.txt
# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'
```

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

## Query the corpus

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class mfa-and-passwords --limit 20
python3 ~/.local/share/hackerone-reports/h1.py stats --class mfa-and-passwords
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```

Search by technology, endpoint, parameter, or program. Examples:

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class mfa-and-passwords
python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class mfa-and-passwords --min-bounty 1000
```

## Related

- `hackerone-auth-bypass` (989 reports)
- `hackerone-account-takeover` (262 reports)

## Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.
