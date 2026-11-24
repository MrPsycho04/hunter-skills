# Evidence appendix — Business Logic and Secure-Design Flaws

Mined from all **931 valid disclosed reports** for this class (134 paid, 14% — payment is not validity).

## Technique frequency (all valid writeups)

| Item | Count |
|---|---:|
| encoding / double-encode / null byte | 132 |
| public source-code / repo review | 96 |
| Content-Type / body-format switch | 95 |
| header injection (Host / X-Forwarded / etc.) | 91 |
| intercept & replay request in Burp | 83 |
| admin / privileged-role context | 83 |
| subdomain / DNS / cert-transparency recon | 77 |
| HTTP method / verb tampering | 74 |
| file upload / filename / extension | 73 |
| cache / CDN / unkeyed header | 73 |
| two-account / cross-account replay | 61 |
|  HosT/absolute-URL reset poisoning | 52 |
| internal service / port / container | 48 |
| XML / SOAP / SAML / XXE | 42 |
| race / concurrency / timing | 38 |
| DOM / HTML source inspection | 33 |
| webhook / OAuth / SAML / integration abuse | 31 |
| error message / stack trace probing | 29 |
| JWT / token / base64 decode | 27 |
| second-order / stored / blind delivery | 26 |
| fuzzing / wordlist brute force | 26 |
| parameter pollution / duplicate keys | 25 |
| WAF / sanitizer / filter bypass | 22 |
| OAST / DNS / HTTP callback proof | 20 |
| unauthenticated / removed-cookie test | 16 |
| cloud metadata / IAM abuse | 15 |
| JS bundle / source-map inspection | 14 |
| API docs / Swagger / introspection | 13 |
| employee / developer public info | 13 |
| verbose debug / framework fingerprint | 10 |
| mass assignment / extra request fields | 10 |
| public bucket / storage exposure | 10 |
| parser confusion / normalization | 10 |
| third-party data / paste / breach reuse | 9 |
| redirect chain / Location header | 9 |
| swap object ID / parameter value | 9 |
| deserialization / gadget chain | 6 |
| browser DevTools / network tab | 5 |
| response diff / status / length comparison | 5 |
| replay / modify a captured request | 5 |
| search-engine dorking | 3 |
| git history / exposed .git | 3 |
| template injection (SSTI) | 3 |
| archive / Wayback endpoint discovery | 1 |

## Tools mentioned

| Item | Count |
|---|---:|
| browser | 106 |
| source-code-review | 76 |
| curl | 65 |
| burp | 64 |
| devtools | 52 |
| burp-intruder | 41 |
| javascript-debugging | 24 |
| python | 16 |
| burp-repeater | 10 |
| git | 10 |
| burp-collaborator | 4 |
| collaborator/oast | 4 |
| ffuf | 2 |
| nmap | 1 |
| amass | 1 |
| beautifier | 1 |
| sqlmap | 1 |
| shodan | 1 |
| decompiler | 1 |

## Bypass primitives

| Item | Count |
|---|---:|
| content-type | 157 |
| bypass | 118 |
| crlf | 28 |
| bypassing | 27 |
| bypassed | 26 |
| race condition | 24 |
| %00 | 14 |
| content type | 14 |
| unicode | 13 |
| host header | 12 |
| blind | 11 |
| open redirect | 11 |
| whitelist | 10 |
| null byte | 7 |
| chunked | 7 |
| trailing dot | 7 |
| blacklist | 6 |
| transfer-encoding | 6 |
| bypasses | 6 |
| %0d%0a | 4 |
| same-site | 4 |
| backslash | 3 |
| http method | 3 |
| uppercase | 2 |
| parameter pollution | 2 |
| lowercase | 2 |
| second order | 2 |
| normalize | 2 |

## Impact language

| Item | Count |
|---|---:|
| password | 504 |
| token | 327 |
| admin | 238 |
| payment | 134 |
| secret | 109 |
| credential | 85 |
| sensitive information | 33 |
| sensitive data | 27 |
| localhost | 22 |
| funds | 15 |
| unauthorized | 14 |
| account takeover | 13 |
| financial | 13 |
| rce | 13 |
| remote code execution | 9 |
| exfiltration | 7 |
| api key | 6 |
| arbitrary code | 5 |
| arbitrary file | 3 |
| privilege escalation | 3 |

## Parameters observed

| Item | Count |
|---|---:|
| max-age | 25 |
| name | 17 |
| charset | 15 |
| path | 14 |
| class | 12 |
| expires | 11 |
| mode | 11 |
| src | 9 |
| email | 9 |
| type | 8 |
| lang | 7 |
| domain | 6 |
| amount | 6 |
| curlopt_ssl_verifypeer | 6 |
| verifypeer | 6 |
| value | 5 |
| csrftoken | 5 |
| sessionid | 4 |
| limit | 4 |
| start_of_line | 4 |
| __cfduid | 4 |
| _ga | 4 |
| rel | 4 |
| target | 4 |
| persist | 4 |
| token | 3 |
| style | 3 |
| optimizelysegments | 3 |
| optimizelyenduserid | 3 |
| optimizelybuckets | 3 |

## Recurring approach patterns

- **2×** e g by modifying etc hosts en wikipedia org
  - e.g. e.g., by modifying `/etc/hosts`: `127.0.0.1 en.wikipedia.org`.
- **2×** i noticed when we hit the reset password request endpoint too many times via some proxy for e g burp there is no rate limit on that endpoint and you can spam the email with s of requests and resend even more password reset emails to the users as there is no rate limiting on that
  - e.g. I noticed when we hit the /reset-password-request/ endpoint too many times via some proxy for e.g:- (Burp) there is no rate limit on that endpoint and you can spam the email with 100's of requests and resend even more password reset emails to the users as there is no rate limiting on that.
- **2×** i was able to take control of this bucket and put my own content onto it
  - e.g. I was able to take control of this bucket and put my own content onto it.
- **1×** i used some other penetration tester s email address to create an account on hackerone and i choosed the username to be something erotic i know that users account will not be created untill they click on the confirmation key
  - e.g. I used some other penetration tester's email address to create an account on hackerone.And I choosed the username to be "something_erotic" I know that users account will not be created untill they click on the confirmation key.
- **1×** you are right google is indexing browsers cache for search results after i reported the bug to facebook they added noindex and nofollow tags to all sensitive pages
  - e.g. You are right.Google is indexing browsers cache for search results.After I reported the bug to facebook,they added noindex and nofollow tags to all sensitive pages.
- **1×** i tried to change my email address on hackerone com and when i tried adding null bytes it was being accepted by hackerone com
  - e.g. I tried to change my email address on hackerone.com.And when I tried adding null Bytes,it was being accepted by hackerone.com.
- **1×** i am registered wth and i tried to change my email address to and guess what this address was granted as an email address
  - e.g. I am registered wth ███ and I tried to change my email address to ████%00 And guess what,this address was granted as an email address.
- **1×** i was able to upload an executable and i got a message saying it was successfully uploaded
  - e.g. I was able to upload an executable and I got a message saying it was successfully uploaded.
- **1×** i found wildcard dns enabled on your server
  - e.g. I found wildcard DNS enabled on your server.
- **1×** for example after logging into an application and a session token is set using a cookie then verify it is tagged using the secure flag
  - e.g. For example, after logging into an application and a session token is set using a cookie, then verify it is tagged using the ";secure" flag.
- **1×** i have tried to input incorrect password and i have not been lockout tried the corrct password in the 21st time and it login successfully
  - e.g. I have tried to input 20 incorrect password and I have not been lockout, tried the corrct password in the 21st time and it login successfully.
- **1×** i have found that you are leaking via the referrer the reset password link
  - e.g. I have found that you are leaking via the referrer the reset password link.
- **1×** i was able to use the token for more than attempts
  - e.g. I was able to use the token for more than 5 attempts.
- **1×** i have found out that an attacker can perform brute force attack on your login panel because there is no rate limitation to prevent this attack
  - e.g. I have found out that an attacker can perform brute force attack on your login panel because there is no rate limitation to prevent this attack.
- **1×** the hyperlink to my userid will be the same as that of an existing user whose uuid value i have used
  - e.g. The hyperlink to my userid will be the same as that of an existing user whose uuid value I have used.
- **1×** hey guys i put this down as a 2nd bug as it may have been overlooked from the previous report and i figured it d be easier to track a fix and add comments separately
  - e.g. Hey guys, I put this down as a 2nd bug as it may have been overlooked from the previous report and I figured it'd be easier to track a fix and add comments separately...
- **1×** i tried card payments also with valid info and they too failed
  - e.g. I tried card payments also with valid info and they too failed.
- **1×** hey there i found out that you have missing x frame header which allows click jacking in your website
  - e.g. Hey there I found out that you have missing X-frame header which allows click jacking in your website
- **1×** hello there is an option on digitalsellz user dashboard called delete account i tried to used this feature i deleted my account with two simple clicks
  - e.g. Hello, There is an option on DigitalSellz USER DASHBOARD called "Delete Account" I tried to used this feature, i deleted my account with two simple clicks.
- **1×** i tried to login again and found out my profile is not been deleted every information i added is still there like i never tried to delete it
  - e.g. i tried to login again and found out my profile is not been deleted, every information i added is still there, like i never tried to delete it.
- **1×** i decided to report it but thought lets try this delete account feature after adding any product on my account
  - e.g. I decided to report it but thought lets try this "Delete Account" feature after adding any product on my account.
- **1×** so i added a test product and than deleted my account
  - e.g. so I added a TEST product and than deleted my account.
- **1×** this is a very low severity issue that i just found out in your password policy
  - e.g. This is a very low severity issue that i just found out in your password policy.
- **1×** remediation on updating the email address under account settings it should be verified by sending a confirmation link
  - e.g. Remediation: On updating the email address under Account Settings, it should be verified by sending a confirmation link.

## Case studies (full excerpts)

### 894569 — An attacker can run pipeline jobs as arbitrary user
GitLab · $12000 · critical · https://hackerone.com/reports/894569

### Summary An attacker can run arbitrary pipeline jobs as a `victim` user. This means the attacker can access the user private repositories, member only repositories, registry, etc... by using the victim `CI_JOB_TOKEN` token. > This is only my recent research and I wanted to report it as soon as possible. I will update the report with more information later on. ### Steps to reproduce VICTIM: - Sign in to a GitLab instance as a *Victim user* - Create an arbitrary private repository with some private files. (We will steal this repo as a poc.) ATTACKER ACCOUNT 1: - Sign in to a GitLab instance as a *Attacker1 user* - Create a new project using the following settings: - Project Name: `poc` - Visibility Level : `public` - Check the `Initialize repository with a README` checkbox - Add a new `.gitlab-ci.yml` file to the project > We will mirror this repository and update the `.gitlab-ci.yml` file later on to trigger the CI/CD job. ATTACKER ACCOUNT 2: - Sign in / Register to a GitLab instance as a *Attacker2 user* - Create a new public group called as `test` - Create a new project inside the `test` group using the following settings: - Project Name: `poc` - Visibility Level : `public` - Go to `Project settings` => `Repository` => `Mirroring repositories` - Set `Git repository URL` to the previously created repository by the *Attacker1 user* - Set `Mirror direction` to `Pull` - Check t

### 1295844 — Modify in-flight data to payment provider Smart2Pay
Valve · $7500 · critical · https://hackerone.com/reports/1295844

I have found vulnerability which allows attacker to generate steam wallet balance. Firstly you will have to change yours steam account email to something like (I will explain why in next steps, amount100 is the important part): brixamount100abc@█████ Then go to and click add add funds. Proceed to payment and select any payment which uses Smart2Pay payment method (przelewy24 in my country). Click next steps as you would do with normal transaction. Intercept POST request to You should see request like that We cant change parameters as there is Hash field with signature, however signature is generated like that hash(ALL_FIELDS_NAMES_VALUES_CONTACTED) For this request it will look like that: `hash(MerchantID1102MerchantTransactionID█████Amount2000.....)` So with our special email we can move parameters in a way that will change amount for us For example, we can change original `Amount=2000` to `Amount2=000` and after contacting it still will be `Amount2000` Then we can change email from `CustomerEmail=brixamount100abc%40████` to `CustomerEmail=brix&amount=100&ab=c%40█████████` by this we are adding new field amount with our value. new request should look like that: Then just pay 1 $ and you should get your money on steam wallet in few hours/days those are some transactions made with this metod: 2███████3 2████9 and this is account i was testing everything on: ## Impact I think impa

### 1849626 — Fee discounts can be redeemed many times, resulting in unlimited fee-free transactions
Stripe · $5000 · medium · https://hackerone.com/reports/1849626

## Summary: Hi there, first off, I am an actual Stripe customer using Stripe for my real business, so I used my actual Stripe account to test this (as there is no other way). I realize this is not ideal but hope you understand given the unique scenario! I was recently offered a fee discount of $20,000 on Stripe transactions. Stripe Support applied the offer to my account, and I was shown a prompt to accept the fee discount in my dashboard. I decided I should try and look for a race condition in this acceptance. So, I used Burp Turbo Intruder to race the request that accepts the fee discount, `/ajax/accept_fee_discount_offer` (forgot to take screenshot as I did not think it would work!). It seems a race was not even needed though, as I called it 30 times and 30 fee discounts were immediately applied to my account! As a result, I now have $600,000 of fee-free processing applied to my account. Obviously, this is not ideal for Stripe as you only intended to offer me $20,000! I believe you could keep calling this endpoint if you wanted to, you just need a valid `fdo_` ID. ████ ## Impact Unlimited fee-free discounts. This will cost Stripe about 3% of each discount, so $600 each time a $20k discount is abused.

### 1543159 — Able to approve admin approval and change effective status without adding payment details .
Reddit · $5000 · high · https://hackerone.com/reports/1543159

## Summary: In you can create campaign under which you can create ads , once you create new campaign , it is on pending stage and will not be delivered unless you add payment details and is reviewed by admin and approved according to what it says here . But changing the value of admin_approval to APPROVED and effective_status to ACTIVE , the ads is approved and thus we receive the confirmation email from reddit ads that our ads is approved . ## Impact: Can bypass the review process and change the ads status to approve and active without payment process . ## Steps To Reproduce: [add details for how we can reproduce the issue] 1. Create a campaign from 1. Go to you will see a table list that shows your ads and campaign , there the status is stated as PENDING . And we know according to what reddit says , our ads needs to get reviewed by reddit members , but updating the value from api changes our status to ACTIVE . Hence ad is successfully delivered . POC video is attached . ███████ ## Supporting Material/References: * [attachment / reference] ## Impact Can bypass the review process and change the ads status to approve and active without payment process .

### 815085 — Account creation with invalid email addresses / email is accepting % and %0d%0a line termination chars
HackerOne · $3750 · low · https://hackerone.com/reports/815085

**Summary:** Hackerone SignUp feature is misconfigured with email parameter. Email address parameter is accepting % and %0d%0a character along with genuine email address. Using this technique hackerone user account can be created but cannot be verified as there is not possible to verify those invalid email accounts. Basically random use of invalid email address, attacker can create multiple accounts. **Description:** As email address field always being verified with any special character (except @ and .) but here email is accepting % and line termination char %0d%0a ### Steps To Reproduce 1. SignUp with new hacker account 2. Use email address adding with character like % or %0d%0a, account will be created and you will get a account creation message ████ ███████ {F742080} 3. Even if you try now to login using same above email and password then you will get same message for account is already created and need to verify email █████ 4. You can not use the same invalid email again, as it will show an error of reuse of that invalid email address ## Impact >>Garbage value can be stored in database using user account signup form >>Multiple account can be created, just like if any use has real account with his email address, then also account can be created by adding %0d%0a or % char >>Account is created using invalid email address, but can not be used

### 423467 — H1514 Ability to MiTM Shopify PoS Session to Takeover Communications
Shopify · no bounty (valid finding) · medium · https://hackerone.com/reports/423467

Hi @iv-rodriguez, After a decent amount more digging and research, I must disagree with you on the "expecting to work offline" portion. The code actually specifically listens on all local interfaces (`0.0.0.0`) and the wifi network address is specifically used in the QR code connection string, as shown here in `com.shopify.pos.customerview.server.CustomerViewWebSocketServer::getConnectionString()` in the `com.shopify.pos` app: This can also be seen from netstat on the device: In addition to this, the main point of this attack is to show how a merchant can abuse this functionality to cause extra charges to the customer, unknowingly. I was able to build a relay server for the WebSocket and could snoop on the raw messages without any issue. Using an ARP spoofing attack it would be possible to MiTM the WebSocket between the real server and the customer while on the same network. At this point, you still need to obtain the initial public key that is in the QR code. This can be done by forcing the client to accept a new one by altering the message types to contain a new receiverPublicKey. This faulty logic can be seen here in `com.shopify.pos.customerview.common.crypto.ClientCryptoProtocol::receiveMessageFromServer()` in the `com.shopify.pos.customerview` app: Normally, when the customer view initially connects to the server, the public key and nonce from the QR code are stored from 

### 1133118 — Hackerone is not properly deleting user id
HackerOne · no bounty (valid finding) · medium · https://hackerone.com/reports/1133118

**Summary:** Long ago, i had an account on hackerone that is now deleted. I used the alias email provided by h1 to sigbup on a site for bug testing. To my surprise, i receive an email to my account routed from an alias email that should not exist. **Description:** ### Steps To Reproduce 1. SignUp on H1 2. Use h1 alias email to signup on some website 3. Delete h1 account and the email still exists ### Optional: Your Environment (Browser version, Device, etc) * ### Optional: Supporting Material/References (Screenshots) * as you can see.the email i just received. You can check your database that **█████** dont exist in your database coz I deleted the account long back..but you can see the email address . ███████ ## Impact Privacy concern

## Field playbook (unedited)

### quick

- Model the intended state machine, then skip/reorder/replay steps.
- Test negative values, zero, decimals, rounding, and currency confusion in money flows.
- Replay one-time actions: coupons, invites, refunds, withdrawals, votes, trials.
- Check seat/limit counting and plan changes for proration and cancellation abuse.
- Look for trust in client-supplied price, role, plan, timestamp, or status.

### payloads

- Quantity -> `-1`, `0`, `0.001`, `1e9`, `NaN`, very long decimals
- Price -> change `price=100` to `price=1`, remove the field, send array
- State -> `status=approved`, `paid=true`, `step=3` out of order
- Race -> parallel redeem of the same coupon/withdrawal

### bypass

- Skip payment by calling the fulfillment endpoint directly.
- Abuse currency/rounding with fractional quantities.
- Reuse idempotency keys or omit them.
- Exploit trial reset via email aliases, domains, or deleted accounts.

### surface

- quantity
- price
- amount
- coupon
- discount
- plan
- trial
- refund
- withdraw
- balance
- limit
- seat

### tools

- Burp
- Turbo Intruder
- custom scripts
- mitmproxy

### chain

- Logic flaw -> free goods/credit.
- Limit bypass -> resource abuse.
- Refund abuse -> financial loss.

## Corpus search commands

```sh
python3 ~/.local/share/hackerone-reports/h1.py stats --class logic-and-design
python3 ~/.local/share/hackerone-reports/h1.py search "<feature or param>" --class logic-and-design --limit 10
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```
