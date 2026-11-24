# Evidence appendix — Authentication Bypass

Mined from all **989 valid disclosed reports** for this class (197 paid, 20% — payment is not validity).

## Technique frequency (all valid writeups)

| Item | Count |
|---|---:|
| admin / privileged-role context | 162 |
| encoding / double-encode / null byte | 107 |
| Content-Type / body-format switch | 98 |
| header injection (Host / X-Forwarded / etc.) | 86 |
| two-account / cross-account replay | 84 |
| webhook / OAuth / SAML / integration abuse | 78 |
| cache / CDN / unkeyed header | 75 |
| HTTP method / verb tampering | 73 |
| public source-code / repo review | 72 |
|  HosT/absolute-URL reset poisoning | 67 |
| unauthenticated / removed-cookie test | 63 |
| internal service / port / container | 63 |
| file upload / filename / extension | 60 |
| subdomain / DNS / cert-transparency recon | 60 |
| intercept & replay request in Burp | 56 |
| fuzzing / wordlist brute force | 46 |
| XML / SOAP / SAML / XXE | 43 |
| JWT / token / base64 decode | 40 |
| employee / developer public info | 36 |
| race / concurrency / timing | 34 |
| DOM / HTML source inspection | 31 |
| second-order / stored / blind delivery | 30 |
| redirect chain / Location header | 28 |
| cloud metadata / IAM abuse | 28 |
| OAST / DNS / HTTP callback proof | 25 |
| parameter pollution / duplicate keys | 21 |
| third-party data / paste / breach reuse | 21 |
| error message / stack trace probing | 19 |
| WAF / sanitizer / filter bypass | 16 |
| public bucket / storage exposure | 16 |
| swap object ID / parameter value | 15 |
| API docs / Swagger / introspection | 14 |
| JS bundle / source-map inspection | 14 |
| response diff / status / length comparison | 11 |
| replay / modify a captured request | 10 |
| verbose debug / framework fingerprint | 7 |
| parser confusion / normalization | 7 |
| browser DevTools / network tab | 6 |
| git history / exposed .git | 6 |
| deserialization / gadget chain | 4 |
| archive / Wayback endpoint discovery | 4 |
| mass assignment / extra request fields | 2 |
| template injection (SSTI) | 1 |

## Tools mentioned

| Item | Count |
|---|---:|
| browser | 86 |
| source-code-review | 62 |
| curl | 50 |
| burp | 45 |
| devtools | 40 |
| python | 24 |
| burp-repeater | 18 |
| burp-intruder | 16 |
| javascript-debugging | 11 |
| git | 10 |
| beautifier | 2 |
| ffuf | 1 |
| interactsh | 1 |

## Bypass primitives

| Item | Count |
|---|---:|
| bypass | 236 |
| content-type | 195 |
| bypassed | 34 |
| bypassing | 33 |
| whitelist | 19 |
| race condition | 18 |
| open redirect | 15 |
| bypasses | 15 |
| unicode | 14 |
| %0d%0a | 13 |
| trailing dot | 8 |
| blacklist | 4 |
| normalization | 4 |
| blind | 4 |
| allowlist | 4 |
| %00 | 3 |
| uppercase | 3 |
| bypassable | 3 |
| url encoded | 2 |
| url encode | 2 |
| transfer-encoding | 2 |
| chunked | 2 |
| out-of-band | 2 |
| url-encoded | 2 |
| null byte | 2 |
| lowercase | 2 |
| bypasspoc | 2 |
| case-sensitive | 2 |

## Impact language

| Item | Count |
|---|---:|
| token | 984 |
| password | 965 |
| admin | 505 |
| credential | 256 |
| secret | 113 |
| unauthorized | 103 |
| localhost | 65 |
| account takeover | 40 |
| payment | 36 |
| sensitive information | 27 |
| full access | 18 |
| api key | 13 |
| pii | 12 |
| sensitive data | 11 |
| rce | 11 |
| financial | 10 |
| arbitrary file | 7 |
| privilege escalation | 6 |
| internal network | 5 |
| exfiltration | 4 |

## Parameters observed

| Item | Count |
|---|---:|
| name | 28 |
| charset | 21 |
| class | 20 |
| path | 13 |
| type | 13 |
| _ga | 13 |
| max-age | 12 |
| email | 11 |
| __utma | 10 |
| __utmz | 10 |
| utmcsr | 10 |
| utmccn | 10 |
| utmcmd | 10 |
| href | 9 |
| __utmb | 9 |
| __utmc | 9 |
| action | 8 |
| utf8 | 8 |
| _secure_admin_session_id | 8 |
| session | 7 |
| token | 7 |
| _gat | 7 |
| content | 7 |
| auth | 7 |
| utmcct | 6 |
| authenticity_token | 6 |
| vuid | 6 |
| _shopify_s | 6 |
| _shopify_y | 6 |
| phone | 6 |

## Recurring approach patterns

- **2×** i ve found a authorization issue in coinbase
  - e.g. I've found a authorization issue in coinbase!
- **1×** however the authenticated session cookie used by a user before logging out is still active
  - e.g. However, the authenticated session cookie used by a user before logging out is still active.
- **1×** i took a look at live install of phabricator and noticed that the user gets automatically logged in after clicking the password recovery link this link is sent to the user s mail
  - e.g. I took a look at live install of Phabricator ( and noticed, that the user gets automatically logged in after clicking the password recovery link (this link is sent to the user's mail).
- **1×** hi i ve found a way to circumvent redirect uri restrictions imposed by the web application using domain suffix subdomain technique
  - e.g. Hi, I've found a way to circumvent redirect_uri restrictions imposed by the web application using domain-suffix/subdomain technique.
- **1×** i created an oauth application under that has oauth redirect uri configured to so technically allowed request shall be denied request shall be surprisingly if i point the redirect uri to see mx suffix the endpoint will be accepted infact endpoint like will be accepted too
  - e.g. I created an OAuth application under That has OAuth redirect_uri configured to So technically Allowed Request shall be : Denied Request shall be: Surprisingly If I point the redirect_uri to (see .mx suffix) the endpoint will be accepted, infact endpoint like will be accepted too.
- **1×** step scrape s3 i wrote a rough poc that scrapes s3 and shows the found exports not something i d use just something i wrote for demonstration purposes feel free to use the team id and name i mentioned before to check it out
  - e.g. #Step 2: scrape S3 I wrote a rough PoC that scrapes S3 and shows the found exports (not something I'd use, just something I wrote for demonstration purposes -- feel free to use the team ID and name I mentioned before to check it out).
- **1×** i should also mention that i haven t looked through all the files but any sensitive file with the protection class set to anything other than nsfileprotectioncomplete would be extractable from the iphone without requiring the passcode
  - e.g. I should also mention that I haven't looked through all the files, but any sensitive file with the Protection class set to anything other than NSFileProtectionComplete would be extractable from the iPhone without requiring the passcode.
- **1×** hi i found a brute forcing attacking on your website
  - e.g. Hi, I found a Brute forcing attacking on your website.
- **1×** i am tested invalid credentials and no account lockout was detected this means it s vuln to brute forcing attack
  - e.g. I am tested 10 invalid credentials and no account lockout was detected.This means it's vuln to Brute forcing attack.
- **1×** you should able to see previous page and not only previous page but also viewed pages in the portal by clicking back back button thanks hari
  - e.g. you should able to see previous page and not only previous page but also viewed pages in the portal by clicking back back button Thanks Hari
- **1×** i read the bug of melvin and i also try to bypass this so i made a bypassing tehcnique but didnt work but i think i found a bug this is the screen shot when a user authorizes their twitter to connect with the url above they will encounter that error
  - e.g. I read the bug of @melvin and I also try to bypass this so I made a bypassing tehcnique but didnt work But I think I found a bug This is the Screen shot: When a user authorizes their twitter to connect with the URL above they will encounter that error.
- **1×** under advanced settings users have the ability to protect their wallet by requiring two factor confirmation when sending bitcoins
  - e.g. Under advanced settings, users have the ability to protect their wallet by requiring two-factor confirmation when sending bitcoins.
- **1×** personally i have configured my account with the most secure option which requires two factor confirmation when sending any amount of bitcoins
  - e.g. Personally, I have configured my account with the most secure option, which requires two factor confirmation when sending any amount of bitcoins.
- **1×** i have tried showing all the three issues in the poc please let me know if you need the poc video as i can t upload it here because of some issues
  - e.g. I have tried showing all the three issues in the POC, please let me know if you need the POC video as i can't upload it here because of some issues.
- **1×** because i was able to set my password which is really common and anyone can hack it
  - e.g. Because I was able to set my password 123456 which is really common and anyone can hack it.
- **1×** i found that you are using x csrf token as a protection against csrf attacks
  - e.g. I found that you are using X/Csrf token as a protection against CSRF attacks.
- **1×** explaination suppose at hrs i used password reset options of mavenlink and got a token on my email lets call it token01 but i didnot use it
  - e.g. **Explaination** Suppose at 09:00 hrs I used password reset options of mavenlink and got a token on my email.Lets call it token01.But i didnot use it.
- **1×** and at hrs i used again the password reset option and got a new token which is token02
  - e.g. And at 09:04 hrs I used again the password reset option and got a new token,which is token02.
- **1×** attack scenario suppose i am an attacker and i got access to the recovery email option of your mavenlink account i logged in to ur recovery email suppose that is user gmail com then i used the forget password option of your mavenlink email i will get one password reset token
  - e.g. **Attack Scenario** Suppose I am an attacker and I got access to the recovery email option of your mavenlink account.I logged in to ur recovery email (suppose that is user@gmail.com).Then I used the forget password option of your mavenlink email.I will get one password reset token.
- **1×** hello i found another bug on hackerone
  - e.g. Hello, I found another bug on hackerone.
- **1×** i tried this one on my account only
  - e.g. I tried this one on my account only.
- **1×** hey i was able to replay a cookie of a current active session and hijack that by replaying the cookie
  - e.g. Hey I was able to replay a cookie of a current active session and hijack that by replaying the cookie.
- **1×** although i have managed to do with the other ones waiting for your reply
  - e.g. Although i have managed to do with the other ones :) Waiting for your reply
- **1×** i have found content spoofing vulnerable in slack at stripe integrations vulnerability is exploitable to all users proof of concept regards jayson zabate
  - e.g. I have found Content Spoofing Vulnerable in Slack at `Stripe Integrations` vulnerability is exploitable to all users ###Proof of concept: ` Regards, Jayson Zabate

## Case studies (full excerpts)

### 739737 — Token leak in security challenge flow allows retrieving victim's PayPal email and plain text password
PayPal · $15300 · high · https://hackerone.com/reports/739737

A bug was identified whereby sensitive, unique tokens were being leaked in a JS file used by the recaptcha implementation. In certain cases, a user must solve a CAPTCHA challenge after authenticating. When the security challenge is completed, the authentication request is replayed to log in. The exposed tokens were used in the POST request to solve the CAPTCHA. The researcher identified a method by which a user, starting from a malicious site, could expose the security challenge token to a third party via a cross-site script inclusion (XSSI) attack. If the user then followed a login link from the malicious site and entered their credentials, the malicious third party could complete the security challenge, triggering the authentication request replay and exposing the user's password. This exposure only occurred if a user followed a login link from a malicious site, similar to a phishing page. PayPal implemented additional controls on the security challenge request to prevent token reuse, which resolved the issue, and no evidence of abuse was found. Full write-up available here:

### 2443228 — Account Takeover via Authentication Bypass in TikTok Account Recovery
TikTok · $12000 · critical · https://hackerone.com/reports/2443228

An improper authentication mechanism in TikTok's account recovery process could have been used for account takeovers on Android devices. There was no evidence of exploitation and this vulnerability has now been completely fixed. We thank @xtt0k for reporting this to our team and confirming its remediation. I identified a critical vulnerability in one of TikTok's endpoints that permitted unauthorized changes to user accounts due to improper parameter handling. This flaw could have allowed a TikTok account to be taken over by knowing the account username. I appreciate TikTok's swift action in resolving this issue and their generous bounty.

### 976603 — Ability to DOS any organization's SSO and open up the door to account takeovers
Superhuman (formerly Grammarly) · $10500 · high · https://hackerone.com/reports/976603

**Summary:** There's an interesting issue I've spent quite a few days trying to escalate but can't figure out. The impact at this point is that I can DOS any SSO integration making it so nobody in that organization can login. I can also get users to inadvertently SSO into my attacker organization, and then take over their account from there. For existing accounts this would require a victim to click "join", however I think that's likely given the fact that they are SSOing for the first time expecting to join an organization. The strange behavior and why I think it *might* be possible to escalate further, is that I can have you authenticate against one SSO instance, but have you get added to a completely separate one. So that means there is some sketchy logic which can potentially allow an attacker to authenticate against their own SSO instance, and get added to someone else's organization. I'm not sure if it's possible to get this with zero user interaction, but I will keep trying and update the report if I figure out a way. The bug stems from the fact that you can create an `entityId` identical to that of another organization **except** with a space ` ` at the end. The application logic then prioritizes that new entityId to add the user to after authenticating against the correct one. So if you have `myentity` as the legitimate entity, and an attacker sets their entity to `mye

### 173551 — password reset token leaking allowed for ATO of an Uber account
Uber · $10000 · critical · https://hackerone.com/reports/173551

With an email address for a valid Uber account, it was possible to take over that account because the reset token was exposed in the response of a password reset HTTP request. This meant an attacker could initiate password reset for an account and immediately receive the reset token for that account. We consider the security of our user's data top priority, so we were very interested in this report. Furthermore, @procode701 was a pleasure to work with and we look forward to more reports in the future.

### 136169 — OneLogin authentication bypass on WordPress sites
Uber · $10000 · severity n/a · https://hackerone.com/reports/136169

First, I'm sorry about reporting another WordPress bug (my intention was just to check if WP-OneLogin stores any sensitive info that could be used to attack OneLogin on your other websites). #Overview# The *.uber.com WordPress sites use OneLogin SAML-SSO instead of the normal WordPress login. The WordPress plugin shipped by OneLogin has a bug which allows anyone to login without a password or other authentication. The attacker can supply a username, email adress, name, and a role. If the username doesn't already exist in the WordPress database, then the plugin will create a new user (if the provisioning setting is on, which it was on the two sites I tested). It looks like in order to gain administrator privileges the attacker has to guess some information - a role name such as "administrator", or the email address or username of an existing administrator. #PoC# I tried this on two sites. On eng.uber.com I couldn't guess a correct role name, user name, or email address to get administrator privileges and therefore was able to create only a "subscriber" level account. On newsroom.uber.com the role name apparently was simply "administrator" so I got that privilege on the system. Some other plugin settings may affect this behavior too. #Reproducing# An example shell script: ~~~~ sh #!/bin/sh xml=`base64 response.xml` curl -v ' \ --data "RelayState=/wp-login.php" --data-urlencode "S

### 921780 — Improper Authentication - any user can login as other user with otp/logout & otp/login
Snapchat · no bounty (valid finding) · critical · https://hackerone.com/reports/921780

'/scauth/otp/droid/logout' request contains user_id parameter. Usually it is equal to current user user_id, but if an attacker passes user_id of victim account he can login as victim. I will demonstrate the problem on two accounts. Victim: ███ Attacker: ██████████ - Attacker perform a usuall login to attacker's personal account. - Attacker performs `/scauth/otp/droid/logout` but instead of attacker's user_id, attacker provides victim's user_id request response Notice an attacker replaced user_id with victim's user_id and the server responded with victim's user_id and given us otp token. Now let's login with the token. - Attacker performs `/scauth/otp/login` request with username equal victim's username, and the token obtained on previous step. response An attacker successfully performed login as victim. Victim's user_id can be easily obtained with friends request. I've attached the following: - a screencast to showcase the problem. - burp project ████ - logout+login raw requests exported from burp - a python script to perform the attack I've tested this bug only on my personal accounts. ███████ ███ █████████ ## Impact An attacker is able to login as any user.

### 129873 — Bypassing Digits origin validation which leads to account takeover
X / xAI · no bounty (valid finding) · severity n/a · https://hackerone.com/reports/129873

Hi, I would like to report an important issue that affects websites that has integrated "Signin with Digits" , leading to potential account takeover. #Detail In Digits architecture, the data communication channel between Digits and customer's site relies on *postMessage()*. In order to prevent malicious websites prevent themselves to be the legit Digits website and send arbitrary commands to the customer's websites, an origin validation is in place in the SDK. Specifically, the code that's responsible to perform the validation is as follow: **File: In short, the event origin is checked against Digits' origin in this line:`-1 !== this.config.get("sdk_host").search(t.origin)`, which is the same as `-1 !== " In essence, it looks for the occurrence of Digit's origin from sender's origin. The way the validation is done is however flawed. According to the [docs of String.prototype.search()]( the method takes a regular repression object instead of a string. If anything other than regexp is passed, it will get implicitly converted into a regexp. In this case, `t.origin` which is a string is converted into a regexp. In regular expression, a dot (.) is treated as a wildcard. In other words, any character of Digits' origin can be replaced with a dot. An attacker can take advantage of it and use a special domain instead of the official one to bypass the validation, such as `www.d.gits.co` 

## Field playbook (unedited)

### quick

- Test password reset: token entropy, reuse, expiry, host-header poisoning, email enumeration.
- Attack JWT: alg=none, key confusion, weak secret, kid/jku injection, missing signature.
- Probe OAuth/SSO redirect_uri, state, nonce, and account-linking flows.
- Try type juggling and NoSQL/SQLi in login and OTP endpoints.
- Check registration verification: email/phone reuse, unicode normalization, duplicate identities.

### payloads

- JWT -> `{"alg":"none"}`, HS256 with public key as secret, `kid=../../dev/null`
- NoSQL -> `{"user":"admin","pass":{"$ne":null}}`
- Type juggling -> `password[]=x`, `otp=0e12345`, `true` vs `"true"`
- Header tricks -> `X-Forwarded-Host: evil`, `Host: evil`, `X-Original-URL: /admin`

### bypass

- Reset token leaked via Referer, shared cache, logs, or email link scanner.
- Response manipulation: change `success:false` to true, remove error checks.
- Case/unicode normalization of emails and usernames.
- Session fixation and missing token rotation after login.

### surface

- email
- username
- password
- otp
- code
- token
- reset
- next
- redirect_uri
- state
- saml
- jwt

### tools

- jwt_tool
- hashcat
- Burp
- ffuf
- nuclei

### chain

- Reset poisoning -> ATO.
- JWT forgery -> admin access.
- OAuth redirect -> token theft.

## Corpus search commands

```sh
python3 ~/.local/share/hackerone-reports/h1.py stats --class auth-bypass
python3 ~/.local/share/hackerone-reports/h1.py search "<feature or param>" --class auth-bypass --limit 10
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```
