# Evidence appendix — Race Conditions and TOCTOU

Mined from all **65 valid disclosed reports** for this class (14 paid, 22% — payment is not validity).

## Technique frequency (all valid writeups)

| Item | Count |
|---|---:|
| race / concurrency / timing | 43 |
| intercept & replay request in Burp | 17 |
| encoding / double-encode / null byte | 14 |
| public source-code / repo review | 14 |
| cache / CDN / unkeyed header | 12 |
| internal service / port / container | 11 |
| Content-Type / body-format switch | 10 |
| header injection (Host / X-Forwarded / etc.) | 10 |
| two-account / cross-account replay | 7 |
| admin / privileged-role context | 7 |
| subdomain / DNS / cert-transparency recon | 6 |
| file upload / filename / extension | 6 |
| OAST / DNS / HTTP callback proof | 5 |
| API docs / Swagger / introspection | 4 |
| webhook / OAuth / SAML / integration abuse | 3 |
| employee / developer public info | 3 |
| parameter pollution / duplicate keys | 3 |
| error message / stack trace probing | 3 |
| HTTP method / verb tampering | 2 |
| fuzzing / wordlist brute force | 2 |
| response diff / status / length comparison | 2 |
| second-order / stored / blind delivery | 1 |
| browser DevTools / network tab | 1 |
| unauthenticated / removed-cookie test | 1 |
| XML / SOAP / SAML / XXE | 1 |
| cloud metadata / IAM abuse | 1 |
| third-party data / paste / breach reuse | 1 |
| JWT / token / base64 decode | 1 |
| JS bundle / source-map inspection | 1 |
| deserialization / gadget chain | 1 |

## Tools mentioned

| Item | Count |
|---|---:|
| curl | 16 |
| burp | 12 |
| source-code-review | 12 |
| browser | 10 |
| burp-intruder | 10 |
| devtools | 7 |
| python | 3 |
| burp-collaborator | 1 |
| collaborator/oast | 1 |
| burp-repeater | 1 |
| git | 1 |
| javascript-debugging | 1 |

## Bypass primitives

| Item | Count |
|---|---:|
| race condition | 68 |
| content-type | 14 |
| bypassing | 7 |
| bypass | 5 |
| bypassed | 3 |
| url-encode | 1 |
| blind | 1 |

## Impact language

| Item | Count |
|---|---:|
| token | 48 |
| credential | 19 |
| payment | 10 |
| rce | 8 |
| localhost | 6 |
| password | 5 |
| sensitive data | 5 |
| admin | 3 |
| arbitrary file | 2 |
| remote code execution | 2 |
| arbitrary code | 2 |
| cloud metadata | 1 |
| privilege escalation | 1 |
| sensitive information | 1 |
| secret | 1 |

## Parameters observed

| Item | Count |
|---|---:|
| charset | 5 |
| max-age | 4 |
| curl_stub_gss_creds | 2 |
| refcount | 2 |
| defid | 1 |
| direction | 1 |
| key | 1 |
| good | 1 |
| stream | 1 |
| ref_count | 1 |
| cookies | 1 |
| dcurl_use_openssl | 1 |

## Recurring approach patterns

- **1×** the researcher was able to find a misconfiguration in the captcha mechanism which allowed him to reuse any captcha and bypass the uniquness of the same
  - e.g. The researcher was able to find a misconfiguration in the captcha mechanism which allowed him to reuse any captcha and bypass the uniquness of the same .
- **1×** i tested it tonight and was able to authenticate two accounts on one invite for my test company test22 simply by clicking the accept button quickly in two separate browsers with two separately logged in users
  - e.g. I tested it tonight and was able to authenticate two accounts on one invite for my test company, test22 simply by clicking the accept button quickly in two separate browsers with two separately logged in users.
- **1×** for example i found the code dallas20
  - e.g. For example, I found the code 'dallas20'.
- **1×** hi i want to report an issue that i have found on when a user wants to up vote or down vote a term he simply presses on the up or down button
  - e.g. Hi, I want to report an issue that I have found on when a user wants to up vote or down vote a term he simply presses on the up or down button.
- **1×** each user can up vote or down vote a term only once but i have found that if a parallel threads do the process of up voting then multiple requests will be accepted
  - e.g. each user can up vote or down vote a term only once, but I have found that if a parallel threads do the process of up voting then multiple requests will be accepted.
- **1×** i discovered that the federalist api doesn t have rate limiting in place and executes any amount of request to the endpoint in parallel mode
  - e.g. I discovered that the Federalist API doesn't have rate limiting in place, and executes any amount of request to the endpoint in parallel mode.
- **1×** this is possible because i found a way to confirm arbitrary emails
  - e.g. This is possible because I found a way to confirm arbitrary emails.
- **1×** i tested that functionality and confirmed how it works
  - e.g. I tested that functionality and confirmed how it works.
- **1×** i realized that if you can somehow create a partner account with a business email that matched that of an employee you would be able to take over their employee account then convert it to a collaborator
  - e.g. I realized that if you can somehow create a partner account with a business email that matched that of an employee, you would be able to take over their employee account, then convert it to a collaborator.
- **1×** i tried it a couple times with two unique users sometimes its a race ie times sometimes its a little lower depends on load and latency
  - e.g. I tried it a couple times with two unique users, sometimes its a 100% race, ie 50 times 100 = 5000, sometimes its a little lower, depends on load and latency.
- **1×** i only tried it twice to be sure not to dos
  - e.g. i only tried it twice to be sure not to DOS.
- **1×** tool used during poc to the poc i used race the web available at with this tool we can send the requests faster than we could with burp intruder
  - e.g. ### Tool Used During PoC To the PoC I used "Race The Web", available at: With this tool we can send the requests faster than we could with Burp Intruder.
- **1×** supporting material references screenshots the outcome is shown below f385429 i ve used the trivial flag times and earned invitations
  - e.g. ### Supporting Material/References (Screenshots) The outcome is shown below: {F385429} I've used the Trivial Flag 70 times and earned 2 invitations.
- **1×** note i ve created a new user to do this poc
  - e.g. ### Note I've created a new user to do this PoC.
- **1×** hello description i have found that there is no limit in the number of requests in place of adding suggest which may exploit the vulnerability of the attacker to send a large number of suggestions for example send a million suggest may lead to cause a problem to the server steps to reproduce
  - e.g. ###Hello ###Description : ####I have found that there is no limit in the number of requests in place of adding suggest, which may exploit the vulnerability of the attacker to send a large number of suggestions, for example, send a million suggest may lead to cause a problem to the server ###Steps To
- **1×** i did it for parallel requests and i was able to add myself times to that group f505223 now try deleting the user from first account group leader
  - e.g. I did it for 5 parallel requests and I was able to add myself 2 times to that group: {F505223} - Now try deleting the user from first account(group leader).
- **1×** the researcher found that the server side code for handling the unlike function for community pages was vulnerable to a race condition
  - e.g. The researcher found that the server-side code for handling the "unlike" function for community pages was vulnerable to a race condition.
- **1×** but when user choose to get free day premium he can click get free badoo premium and can enjoy free premium for three days here i found a race condition vulnerability through which i was able to get more than three days of premium
  - e.g. But when user choose to get free 3 day premium he can click `Get free Badoo Premium` and can enjoy free premium for three days, Here i found a race condition vulnerability through which i was able to get more than three days of premium.
- **1×** before clicking get free badoo premium turn intercept on in your burp suite and then click get free badoo premium intercept this post webapi phtml server promo accepted select any parameter value right click send it to turbo inturer
  - e.g. Before clicking `Get free Badoo Premium` turn intercept On in your burp suite and then click `Get free Badoo Premium` intercept this `POST /webapi.phtml?SERVER_PROMO_ACCEPTED ` select any parameter value > right click > send it to turbo inturer.
- **1×** we ve found out that the program s should be able to send feedback only once per report which is very logical
  - e.g. We've found out that the program's should be able to send feedback only once per report which is very logical.
- **1×** the researcher found a race condition to artificially inflate the upvotes of user comments in the restaurant s review section
  - e.g. The researcher found a Race Condition to artificially inflate the upvotes of user comments in the Restaurant's review section
- **1×** i found a race condition issue at the v2 seats endpoint
  - e.g. I found a race condition issue at the `/v2/seats` endpoint.
- **1×** later we noticed that security reports are accepted via the hackerone program
  - e.g. Later we noticed that security reports are accepted via the HackerOne program.
- **1×** summary we were testing an application and we found a race condition bug in the faucet implementation of starport
  - e.g. ## Summary: We were testing an application and we found a race condition bug in the faucet Implementation of Starport.

## Case studies (full excerpts)

### 300305 — Ability to bypass partner email confirmation to take over any store given an employee email
Shopify · $15250 · critical · https://hackerone.com/reports/300305

I told Pete I would take a look at Spotify, hi Pete. **Summary** It's possible to take over any store account through partners given an employee email address. This is possible because I found a way to confirm arbitrary emails. I don't know the Shopify ecosystem well enough to know the other ramifications of such a bug. On #270981 you wrote: > The intention was that, when a partner already had a valid user account on the store, their collaborator account request could be accepted automatically, with the user account converted into a collaborator account. I tested that functionality and confirmed how it works. I realized that if you can somehow create a partner account with a business email that matched that of an employee, you would be able to take over their employee account, then convert it to a collaborator. The problem is that business accounts need emails to be validated, but this can be bypassed with a race condition. The bug works by hitting the email validation endpoint for an email you own, at the same time as changing your email to a victim's. It might take a few tries, but eventually your email will be changed and be validated due to not (properly) using a DB transaction. **Steps to reproduce** 1. Create a store account and invite an employee. 2. Accept the employee invite (maybe not necessary I didn't test). 3. Login to or create a partner account as the attacker. 4

### 1438052 — Race condition in faucet when using starport
Cosmos · $5000 · critical · https://hackerone.com/reports/1438052

Hi team, I and Aditya sent this bug over email on Wed, 29 Dec, 17:45 IST. Later we noticed that security reports are accepted via the HackerOne program. So, I am sending a copy of the bug report here. ## Summary: We were testing an application and we found a race condition bug in the faucet Implementation of Starport. ## Steps To Reproduce: 1. Start a starport with the below configuration. Note the "coins_max" has been set to 11 tokens and hence a user cannot fetch more after the 11 token limits. 2. Now call the request manually with 5 tokens per request as in our configuration after 2 requests and 10 tokens in total Alice won't be able to fetch more tokens from the faucet Now we can confirm Alice cannot have more than 11 tokens. 3. Now regenerate the server and instead of sending a single request send a concurrent request to fetch tokens in Alice address. We used 50 requests concurrently. {F1563051} 4. Now when we check Alice balance it is 30 which should have not been more than 11 {F1563052} We believe the root cause of the issues is the go mapping which is not advised for concurrency ## Supporting Material/References: ## Impact A malicious user can send concurrent requests to fetch more tokes from faucets than the "max-credit limit" which allows.

### 1520931 — Time-of-check to time-of-use vulnerability in the std::fs::remove_dir_all() function of the Rust standard library
Internet Bug Bounty · $4000 · high · https://hackerone.com/reports/1520931

The implementation of [`std::fs::remove_dir_all()`]( in the Rust standard library is vulnerable to a time-of-check to time-of-use link replacement attack. This applies to all versions of Rust before 1.58.1. ### Vulnerability details The [documentation of `std::fs::remove_dir_all()`]( guarantees that the function does not follow symbolic links: > Removes a directory at this path, after removing all its contents. Use carefully! > This function does not follow symbolic links and it will simply remove the symbolic link itself. The vulnerable implementation for Windows is in [library/std/src/sys/windows/fs.rs]( For other platforms it is in [library/std/src/sys_common/fs.rs]( Both use a `remove_dir_all_recursive()` helper function which does the actual recursion and deletion. It opens directory by the given path and iterates the directory entries. For each directory entry it checks if the entry is a directory and recurses into it if it is. If it is not it is deleted using `std::fs::remove_file()`. On the way back up the now empty directories are deleted using `std::fs::remove_dir()` There are two problems with this implementation if the attacker has write access to a directory which is being deleted by the privileged process: 1. The type of a directory entry is checked and it is being recursed into if it is a directory. There is a short time window between the check and the opening o

### 2110030 — Race Condition Enables Bypassing Verification Check
Tools for Humanity · $3000 · high · https://hackerone.com/reports/2110030

A race condition was discovered in the WorldID platform that could enable bypassing the verification check limits under certain conditions. The issue resided in the enforcement of maximum allowed verifications, which was not properly synchronized across parallel requests to the cloud backend service. The fix implemented enforcement of the maximum verifications in the database, making it the source of truth for state. This ensures that only one successful request per nullifier use can occur, even if parallel requests are attempted simultaneously. The vulnerability only affected certain cloud-backed verification flows, not on-chain WorldID applications.

### 2078571 — [curl] CVE-2023-32001: fopen race condition
Internet Bug Bounty · $2480 · medium · https://hackerone.com/reports/2078571

Hello, I'm reporting for CVE-2023-32001 on curl which was resolved in last Wednesday's curl release. ### Vulnerability explanation: As we can see in the following curl code (line 59-61 ): There is a race condition between the moment "stat(filename, &sb)" is executed and the moment " fopen(filename, FOPEN_WRITETEXT);" is executed. This leads to undesirable behavior such as an attacker tricking a privileged user to overwrite protected files, or since this function (Curl_fopen) is also used for storing cookies an attacker could trick another user to send those cookies that might be very sensible to a file fully owned and controlled by the attacker. ###POC/Steps to reproduce: Before we start, I will be using a little program called "rename". Which simply swaps atomically the names of two files to be able to showcase this race condition. Here is its code : Open two terminals, with two different users. One will be the attacker terminal and the other the victim. In both POCs, the victim will want to execute a command such as "curl --cookie-jar a google.com" thinking the file "a" doesn't exist. ###A) Exploiting this vulnerability to trick a user to overwrite a file they own: Assume the current directory of both attacker(selmelc) and victim (root) looks like this The attacker executes ./rename a b, which will not stop to swap the name of the directory "b" and the symlink "a". The victim

### 429026 — Race condition in performing retest allows duplicated payments
HackerOne · no bounty (valid finding) · medium · https://hackerone.com/reports/429026

## Summary There exists a race condition in performing retests. By executing multiple requests to confirm a retest at the same time, a malicious user is paid multiple times for the retest. This allows for stealing money from HackerOne, which could go unnoticed by both HackerOne and the attacker (me). ## Steps to Reproduce 1. Receive a retest request email from HackerOne. 2. Intercept the request to retest the email. Right click the request in Burp Suite and select `Copy as curl command`. 3. Execute the request on the command line in the form `(request) & (request) & ...`. In testing, I executed the command 5 times. 4. Scroll to the bottom of The payment will appear under the `Retest payments` sections and may be repeated. 5. Wait a few weeks. If successful, a callback from HackerOne will be received (in this case from @michiel): {F366191} 6. Check your bank account statements. Observe that a $500 payment was sent from HackerOne 2 weeks ago, demonstrating that the race condition was successful: {F366192} ## Impact This allows an attacker to exploit the retesting feature to steal many times more money. Given that this went unnoticed by both the attacker and HackerOne for over 2 weeks, this has the potential to be exploited multiple times to steal money from HackerOne.

### 604534 — Race Condition leads to undeletable group member
HackerOne · no bounty (valid finding) · low · https://hackerone.com/reports/604534

Hi, **Summary:** There exists a Race Condition in which the user can add themselves twice to a group which will make them unremovable from group. They themselves cannot remove themselves from the group as well as the group leader cannot remove that user from the group. Ofcourse this is a low severity as that malicious user first needs to have a valid invitation link, but nevertheless this leads to permanent membeship of group so this needs to be fixed in my opinion. ### Steps To Reproduce We need two accounts to reproduce this. - First account will be leader account - Second account will be a normal account. - Create a group from the first account and create an invitation link. - Join using the invitation link on the second account and intercept the request: Repeat the above requests in parallel. I did it for 5 parallel requests and I was able to add myself 2 times to that group: {F505223} - Now try deleting the user from first account(group leader). No matter how much you try, you won't be able to delete it. This would lead to a state where the group leader will have to delete the group and create a new group if he wants the malicious user to get removed. Thanks, Yash ## Impact Irremovable/permanent member of the group. Even the group leader cannot remove that user.

## Field playbook (unedited)

### quick

- Identify check-then-act flows: balance, quota, coupon, invite, vote, refund.
- Fire parallel requests with last-byte sync or HTTP/2 single-packet attack.
- Test idempotency keys and database constraints.
- Look for partial-state windows in multi-step workflows.

### payloads

- Single-packet attack: 20-30 requests in one HTTP/2 packet
- Last-byte sync: hold final byte, release together
- Repeat the same coupon/withdrawal across parallel connections

### bypass

- Bypass rate limits by racing before the counter commits.
- Use different sessions/accounts to hit shared resources.
- Combine with limit/refund logic for financial impact.

### surface

- coupon
- withdraw
- transfer
- invite
- vote
- refund
- balance
- quota
- limit

### tools

- Burp Turbo Intruder
- race-the-web
- custom scripts

### chain

- Race -> double spend.
- Race -> multiple invites/rewards.
- Race -> limit bypass.

## Corpus search commands

```sh
python3 ~/.local/share/hackerone-reports/h1.py stats --class race-condition
python3 ~/.local/share/hackerone-reports/h1.py search "<feature or param>" --class race-condition --limit 10
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```
