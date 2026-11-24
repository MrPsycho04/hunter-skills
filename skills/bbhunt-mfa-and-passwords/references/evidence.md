# Evidence appendix — MFA, OTP and Password-Recovery Flaws

Mined from all **159 valid disclosed reports** for this class (29 paid, 18% — payment is not validity).

## Technique frequency (all valid writeups)

| Item | Count |
|---|---:|
| fuzzing / wordlist brute force | 51 |
| intercept & replay request in Burp | 31 |
| admin / privileged-role context | 21 |
| encoding / double-encode / null byte | 19 |
| Content-Type / body-format switch | 18 |
| public source-code / repo review | 15 |
| header injection (Host / X-Forwarded / etc.) | 14 |
| two-account / cross-account replay | 9 |
| cache / CDN / unkeyed header | 9 |
| HTTP method / verb tampering | 8 |
| XML / SOAP / SAML / XXE | 6 |
| third-party data / paste / breach reuse | 5 |
| DOM / HTML source inspection | 5 |
| parameter pollution / duplicate keys | 5 |
| internal service / port / container | 5 |
| subdomain / DNS / cert-transparency recon | 5 |
| file upload / filename / extension | 5 |
| response diff / status / length comparison | 4 |
|  HosT/absolute-URL reset poisoning | 4 |
| race / concurrency / timing | 4 |
| second-order / stored / blind delivery | 4 |
| JWT / token / base64 decode | 4 |
| WAF / sanitizer / filter bypass | 3 |
| API docs / Swagger / introspection | 3 |
| error message / stack trace probing | 2 |
| JS bundle / source-map inspection | 2 |
| OAST / DNS / HTTP callback proof | 2 |
| parser confusion / normalization | 2 |
| git history / exposed .git | 2 |
| template injection (SSTI) | 2 |
| search-engine dorking | 1 |
| verbose debug / framework fingerprint | 1 |
| redirect chain / Location header | 1 |
| webhook / OAuth / SAML / integration abuse | 1 |
| browser DevTools / network tab | 1 |
| swap object ID / parameter value | 1 |
| cloud metadata / IAM abuse | 1 |
| public bucket / storage exposure | 1 |
| employee / developer public info | 1 |

## Tools mentioned

| Item | Count |
|---|---:|
| burp-intruder | 25 |
| burp | 24 |
| source-code-review | 15 |
| browser | 12 |
| curl | 6 |
| python | 6 |
| devtools | 4 |
| sqlmap | 2 |
| beautifier | 1 |
| burp-repeater | 1 |
| ffuf | 1 |
| javascript-debugging | 1 |
| burp-collaborator | 1 |
| collaborator/oast | 1 |

## Bypass primitives

| Item | Count |
|---|---:|
| bypass | 39 |
| content-type | 25 |
| bypassed | 14 |
| blacklist | 4 |
| content type | 3 |
| bypassing | 2 |
| second order | 2 |
| out-of-band | 1 |
| transfer-encoding | 1 |
| chunked | 1 |
| blind | 1 |
| polyglot | 1 |
| normalizer | 1 |
| null byte | 1 |

## Impact language

| Item | Count |
|---|---:|
| password | 345 |
| admin | 139 |
| token | 95 |
| secret | 37 |
| credential | 34 |
| account takeover | 14 |
| localhost | 8 |
| unauthorized | 8 |
| payment | 6 |
| funds | 3 |
| sensitive data | 3 |
| api key | 2 |
| financial | 1 |
| privilege escalation | 1 |

## Parameters observed

| Item | Count |
|---|---:|
| username | 5 |
| password | 4 |
| template | 3 |
| name | 3 |
| class | 2 |
| invite_code | 2 |
| token | 2 |
| response | 2 |
| max-age | 2 |
| age | 2 |
| version | 1 |
| attempts | 1 |
| minutes | 1 |
| hours | 1 |
| utf8 | 1 |
| _method | 1 |
| authenticity_token | 1 |
| commit | 1 |
| type | 1 |
| mobile_no | 1 |
| csrf_token | 1 |
| eyjpzci6mn0 | 1 |
| session | 1 |
| user | 1 |
| uuid | 1 |
| eyjpzci6mh0 | 1 |
| preview_markup | 1 |
| preview_data | 1 |
| phpmyadmin | 1 |
| action | 1 |

## Recurring approach patterns

- **2×** by sending a very long password characters usually this problem is caused by a vulnerable password hashing implementation
  - e.g. By sending a very long password (1.000.000 characters) Usually this problem is caused by a vulnerable password hashing implementation.
- **1×** it was enabled for over hours since i was told it didn t exist but i stumbled upon the link and then saw all my sms messages on a web page
  - e.g. It was enabled for over 24 hours since I was told it didn't exist but I stumbled upon the link and then saw all my SMS messages on a web page.
- **1×** i saw two authentication code text messages on my phone for the two fraudulent bitcoin purchases of and to max out the daily limit
  - e.g. I saw two authentication code text messages on my phone for the two fraudulent bitcoin purchases of $666.28 and $333.17 to max out the $1,000 daily limit.
- **1×** i have found similar easy way to bruteforce invite codes but in different manner
  - e.g. I have found similar & easy way to bruteforce invite codes but in different manner .
- **1×** invited you to make money with your car h1 another devastating thing i have found here is invite codes are already public in google which if an attacker uses he can ride with uber always for free with invites codes new account
  - e.g. invited you to make money with your car.</h1> Another devastating thing i have found here is 1680 invite codes are already public in Google , which if an attacker uses he can ride with Uber always for free with invites codes / new account .
- **1×** i didn t used any of the invite codes
  - e.g. I didn't used any of the invite codes .
- **1×** i also took a quick look at and noticed there is no reference to this coming up
  - e.g. I also took a quick look at and noticed there is no reference to this coming up.
- **1×** description 2fa in short testing out your 2fa implementation i noticed that there is limited protection against brute forcing
  - e.g. #Description ###2FA In short, testing out your 2FA implementation, I noticed that there is limited protection against brute forcing.
- **1×** password guessing in addition to the above i noticed that there is also limited protection against guessing a password
  - e.g. ###Password Guessing In addition to the above, I noticed that there is also limited protection against guessing a password.
- **1×** based on other systems i ve tested potential mitigations include 2fa only allow attempts at a token after different attempts at different tokens lock the user account and email the victim password brute forcing once an account is locked do not validate the password of a user i hope this helps
  - e.g. Based on other systems I've tested, potential mitigations include: ###2FA - Only allow 3 attempts at a token - After 3 different attempts at 3 different tokens, lock the user account and email the victim ###Password Brute Forcing - Once an account is locked, do not validate the password of a user I 
- **1×** set up a proxy server i used burp
  - e.g. Set up a proxy server (i used burp) 5.
- **1×** in my case i added upto time and it hit into my mail box upto time
  - e.g. In my case i added upto 300 time and it hit into my mail box upto 300 time.
- **1×** as in report a security researcher discovered that following another change from report we used the wrong encoding for the manually entered secret
  - e.g. As in report #260491, a security researcher discovered that following another change (from report #259415), we used the wrong encoding for the manually entered secret.
- **1×** it accomplishes this by opening connections to the target web server and sending a partial request
  - e.g. It accomplishes this by opening connections to | the target web server and sending a partial request.
- **1×** the researcher found a method to brute force the 2fa code request in the www ubnt com login page
  - e.g. The researcher found a method to brute-force the 2FA code request in the www.ubnt.com login page.
- **1×** stats api token can be generated at i ve used my profile and and my token to check brute force the correct token returned with ok status impact an attacker could view the stats of an user
  - e.g. Stats api token can be generated at I've used my profile and and my token to check brute force The correct token returned with 200 ok status ## Impact An attacker could view the stats of an user
- **1×** i have found that type checking for api key is insufficient in rubygems org s source code
  - e.g. I have found that type checking for `api_key` is insufficient in rubygems.org's source code.
- **1×** references finally the references i used for this report you might consider checking this also for even more ways to fortify your web application
  - e.g. #### REFERENCES Finally the references i used for this report, you might consider checking this also for even more ways to fortify your web application.
- **1×** url i have tried to recover the password for some emails test test com exists teste teste com br does not exists after i clicked the reset my password s button the website informed that the email did not exist
  - e.g. URL: I have tried to recover the password for some emails: test@test.com (exists) teste@teste.com.br (does not exists) After I clicked the "reset my password"'s button, the website informed that the email did not exist.
- **1×** i have tried different combinations until i reached code from sms
  - e.g. I have tried 50+ different combinations until I reached code from SMS.
- **1×** i was able to validate that the login of hotornot is vulnerable to bruteforcing
  - e.g. I was able to validate that The Login of HotorNot is Vulnerable to BruteForcing .
- **1×** summary i tried to guess on my account
  - e.g. ## Summary I tried to guess on my account.
- **1×** i sent out nearly requests and i was virtually banned on request about
  - e.g. I sent out nearly 1,000 requests, and I was virtually banned on request about 120.
- **1×** but when i changed my ip and tried logging in i was logged into the account without any additional checks description your web authentication endpoint post currently protects against credentials brute force attacks only by requests rate limiting based on ip
  - e.g. But when I changed my IP and tried logging in, I was logged into the account without any additional checks ## Description:* Your web authentication endpoint, (POST), currently protects against credentials brute-force attacks only by requests rate-limiting based on IP.

## Case studies (full excerpts)

### 125505 — Possibility to brute force invite codes in riders.uber.com
Uber · $5000 · severity n/a · https://hackerone.com/reports/125505

When adding new promotion codes for free rides, one could brute force invitation codes since there is no protection against brute force attacks. When going to payment page, it's possible to apply promotion code. If we intercept this request, we can brute force codes, since there is no captcha or limit for tries. In the pictures bellow, we can see the brute force in question with 3 types of different responses that allow us, to see if the code is valid, expired or invalid. Responses length: * 1951 - Valid code * 1931 - Not valid * 1921 - Code Expired Because there is a option to customize codes, and since all the codes that are customized begin with uber, we were able drop the time of the brute force, to a more practical attack. Finally, we could use a code to get a free ride. An attacker could use this vulnerability to ride in uber for free, creating multiple accounts, each one using one code.

### 1363672 — Bypass a fix for report #708013
Shopify · $3500 · medium · https://hackerone.com/reports/1363672

## Summary: `customerAccessTokenCreate` mutation in the Storefront API does not correctly throttle login attempts. An issue in similar report was already fixed, however, there is still a bypass. ## Steps To Reproduce: 1. Grab a Storefront API Token (I got it from the Buy Button App) 2. Make a request to the Storefront GraphQL endpoint (you can use mine): The actual creds are ███████ - █████████ 3. Send requests until you get `Login attempt limit exceeded` 4. Add a whitespace at the end of email. 5. Observe that you have bypassed the limit though the email is still valid (to prove it try `{email: \"█████ \", password: \"███\" }` and get the token) Video PoC: ███████ ##Possible remediation: Consider whitespace as a character. I would also recommend to try some other stuff like empty character ( and null byte in different forms. ## Supporting Material: I hope I don't need to write too much about the attack scenario, PoC script for bruteforce and Impact as the very same report was already accepted. ## Impact If the brute force attack succeeds, the attacker will gain access to user's Shopify account, including contact information and order history.

### 125707 — Possibility to enumerate and bruteforce promotion codes in Uber iOS App
Uber · $3000 · medium · https://hackerone.com/reports/125707

Due to the lack of rate limiting on the promo code redemption endpoint, it was possible to enumerate promo codes. The response also leaked metadata about the user, including the country of the user, their name and profile photo. Thanks, @r0t! Uber has a feature in the iOS app to apply a promotion code right after we register an account. Since there was no protection against brute force attacks, we were able to enumerate promotion codes, like in report #125505. This is a similar bug but leaks more information than #125505: * Promo code value * Country * Inviter’s name * Inviter’s picture

### 178293 — Misconfiguration in Two Factor Authorisation
Shopify · $1500 · severity n/a · https://hackerone.com/reports/178293

Hey There seems to be a weird misconfiguration which leads to bypass of two factor authorisation #### Scenario 1. Let's assume you have setup Two Factor Authorisation with Google Authenticator 2. You now activate `Google Apps` from `Login services` at 3. Now your try to "Sign In with Google" ` What's weird is no two factor code is required and you directly land in Admin Panel #### Issue Issue here is Two Factor Authorisation is disabled as soon as you "Sign In with Google" and now you cannot even enable it because you can't see any Two Factor Authenticator Tab in Accounts And now when you try to simple login with correct credentials you can access Admin Panel without Two Factor Code from Google Authenticator at ` Also there is no indication to via mail or notification that Two Factor Authorisation has been disabled when Two Factor Authorisation is disabled While it shouldn't be disabled in the first place

### 100509 — Pre-generation of 2FA secret/backup codes seems like an unnecessary risk
HackerOne · $1000 · severity n/a · https://hackerone.com/reports/100509

If you manage to get a malicious script running in HackerOne, requesting ` and parsing out the two factor authentication form will yield either… - the 2FA secret key and backup codes that *will* be used if 2FA is enabled for the first time this session - the backup codes that *will* be used if 2FA is already being used and the codes are regenerated during this session While *activating* 2FA or *confirming* backup codes regeneration requires knowledge of the user's password/TOTP code, reading the values out from the DOM does not (again, provided that you've compromised the user's session and are running script in their domain) A theoretical attack might play out like this: - A victim clicks a link or something in HackerOne which triggers XSS (which seems unlikely, but …) - The XSS makes a request to ` to obtain the victim's potential 2FA secret and backup codes. Possibly the attacker is able to abuse a password manager's behavior to obtain the victim's username/password at this point. - Because of the strange behavior that occurred when they clicked the link, the victim possibly closes and re-opens the window (in an attempt to stop whatever the script is doing) and then enables 2FA on their account - The attacker would now know the 2FA secret and backup codes that are currently being used for the victim's account While achieving this attack seems rather unlikely, it seems that i

### 743545 — Bruteforce password recovery code
Bumble · no bounty (valid finding) · severity n/a · https://hackerone.com/reports/743545

## Summary It's possible to bruteforce recovery code from SMS as iOS application doesn't have limits for incorrect inputs. I have tried 50+ different combinations until I reached code from SMS. ## Steps To Reproduce 1. Click "Use another option" on application startup view 1. Enter your phone number 1. Click "Forgotten number" 1. Click "OK" on pop-up window 1. Bruteforce 4 digits code ## PoC video ## Mitigation 1. Limit quantity of attempts to enter recovery code 1. Don't store recovery code on target device to compare it with user's input ## Details Devices: Iphone SE (13.2), Iphone 6s (12.4) App: Bumble (5.140.0) ## Impact Account takeover.

### 587910 — Password not checked when disabling 2FA on HackerOne
HackerOne · no bounty (valid finding) · low · https://hackerone.com/reports/587910

Hi, when I was submitted a report to a program that request `2FA` ON, I notice that if you try to disable this option will ask for `backup code - password` and if you enter a random password in the request filed and a correct `backup code` it will be successfully disabled the `2FA` without check if the password was correct or not. #PoC 1. go to your account and activate the `2FA` from `/settings/auth` 2. after active this option click on `Disabled` icon beside `Two-factor authentication`. 3. a new window will open asking for `Authentication or backup code - Password` to confirm the disabled. {F494646} 4. in the first box enter a valid `Authentication or backup code` and in the password filed enter any random/wrong password and click save. 5. the option will be disabled successful without check the validation of the password. #graphql Request ## Impact user can disable `Two-factor authentication` without entering a valid password

## Field playbook (unedited)

### quick

- Test OTP brute force limits, reuse, expiry, and response leakage.
- Try MFA bypass via direct navigation, API calls, and remember-me tokens.
- Check backup-code generation and storage.
- Test password reset/change for missing current-password checks.

### payloads

- OTP -> `000000`, reuse old code, race multiple codes
- MFA -> call the post-MFA endpoint directly
- Password -> `password[]=x`, type juggling
- Enumeration -> response length/timing variants

### bypass

- Bypass step-up auth by replaying a privileged session.
- Use unicode/whitespace variants of the password.

### surface

- otp
- mfa
- 2fa
- password
- reset
- recovery
- backup

### tools

- Burp
- Turbo Intruder
- ffuf

### chain

- MFA bypass -> ATO.
- OTP brute -> ATO.

## Corpus search commands

```sh
python3 ~/.local/share/hackerone-reports/h1.py stats --class mfa-and-passwords
python3 ~/.local/share/hackerone-reports/h1.py search "<feature or param>" --class mfa-and-passwords --limit 10
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```
