# Evidence appendix — Miscellaneous Vulnerabilities

Mined from all **1226 valid disclosed reports** for this class (246 paid, 20% — payment is not validity).

## Technique frequency (all valid writeups)

| Item | Count |
|---|---:|
| public source-code / repo review | 189 |
| encoding / double-encode / null byte | 146 |
| admin / privileged-role context | 144 |
| internal service / port / container | 139 |
| file upload / filename / extension | 107 |
| header injection (Host / X-Forwarded / etc.) | 101 |
| Content-Type / body-format switch | 94 |
| HTTP method / verb tampering | 91 |
| subdomain / DNS / cert-transparency recon | 88 |
| cache / CDN / unkeyed header | 86 |
| WAF / sanitizer / filter bypass | 65 |
| DOM / HTML source inspection | 63 |
| race / concurrency / timing | 62 |
| webhook / OAuth / SAML / integration abuse | 51 |
| fuzzing / wordlist brute force | 49 |
| intercept & replay request in Burp | 49 |
| XML / SOAP / SAML / XXE | 48 |
| parser confusion / normalization | 48 |
| employee / developer public info | 47 |
| second-order / stored / blind delivery | 47 |
| parameter pollution / duplicate keys | 46 |
| unauthenticated / removed-cookie test | 44 |
| two-account / cross-account replay | 43 |
| error message / stack trace probing | 41 |
| JWT / token / base64 decode | 40 |
| OAST / DNS / HTTP callback proof | 39 |
| third-party data / paste / breach reuse | 37 |
| API docs / Swagger / introspection | 29 |
|  HosT/absolute-URL reset poisoning | 25 |
| redirect chain / Location header | 22 |
| git history / exposed .git | 20 |
| response diff / status / length comparison | 20 |
| template injection (SSTI) | 19 |
| JS bundle / source-map inspection | 17 |
| public bucket / storage exposure | 17 |
| verbose debug / framework fingerprint | 16 |
| deserialization / gadget chain | 16 |
| cloud metadata / IAM abuse | 15 |
| browser DevTools / network tab | 13 |
| replay / modify a captured request | 10 |
| search-engine dorking | 6 |
| swap object ID / parameter value | 6 |
| mass assignment / extra request fields | 5 |
| archive / Wayback endpoint discovery | 3 |

## Tools mentioned

| Item | Count |
|---|---:|
| source-code-review | 171 |
| curl | 135 |
| browser | 99 |
| python | 61 |
| devtools | 57 |
| burp | 52 |
| git | 48 |
| burp-intruder | 19 |
| javascript-debugging | 15 |
| ffuf | 11 |
| sqlmap | 10 |
| burp-collaborator | 8 |
| collaborator/oast | 8 |
| burp-repeater | 6 |
| beautifier | 5 |
| jq | 4 |
| shodan | 3 |
| decompiler | 3 |
| nmap | 3 |
| nuclei | 2 |

## Bypass primitives

| Item | Count |
|---|---:|
| content-type | 209 |
| bypass | 194 |
| unicode | 69 |
| content type | 58 |
| bypassing | 40 |
| bypassed | 32 |
| blind | 30 |
| bypasses | 23 |
| open redirect | 21 |
| whitelist | 20 |
| lowercase | 19 |
| %00 | 14 |
| uppercase | 14 |
| host header | 12 |
| blacklist | 10 |
| %0d%0a | 10 |
| null byte | 10 |
| normalize | 10 |
| normalization | 8 |
| second order | 8 |
| chunked | 7 |
| normalized | 7 |
| percent-encoded | 7 |
| url encoded | 6 |
| parameter pollution | 6 |
| url-encode | 5 |
| allowlist | 5 |
| homoglyph | 5 |

## Impact language

| Item | Count |
|---|---:|
| password | 1016 |
| admin | 908 |
| token | 533 |
| secret | 397 |
| credential | 392 |
| localhost | 108 |
| payment | 56 |
| sensitive information | 41 |
| unauthorized | 34 |
| rce | 29 |
| privilege escalation | 20 |
| arbitrary code | 19 |
| sensitive data | 19 |
| remote code execution | 18 |
| arbitrary file | 16 |
| funds | 12 |
| exfiltrate | 11 |
| exfiltration | 11 |
| pii | 11 |
| financial | 8 |

## Parameters observed

| Item | Count |
|---|---:|
| href | 23 |
| path | 22 |
| max-age | 20 |
| src | 17 |
| target | 17 |
| charset | 17 |
| name | 15 |
| rel | 15 |
| domain | 14 |
| realm | 14 |
| mode | 11 |
| nonce | 11 |
| type | 10 |
| expires | 10 |
| filename | 10 |
| url | 9 |
| username | 9 |
| sid | 9 |
| _gid | 8 |
| __cfduid | 8 |
| auth | 8 |
| native_ca_store | 8 |
| _ga | 7 |
| user | 6 |
| class | 6 |
| csrftoken | 6 |
| uuid | 6 |
| host | 6 |
| verifypeer | 6 |
| ismap | 5 |

## Recurring approach patterns

- **4×** because of this endpoint we used we cannot see the request information which may degrade a defenders ability to track down an adversary
  - e.g. Because of this endpoint we used, we cannot see the request information which may degrade a defenders ability to track down an adversary.
- **3×** when megan is not working she enjoys competing in ctfs reading baking playing music geocaching and being with her family and friends
  - e.g. When Megan is not working, she enjoys competing in CTFs, reading, baking, playing music, geocaching, and being with her family and friends.
- **3×** as a result of this an adversary can perform api calls using these endpoints and evade the logging of their ip address operating system information
  - e.g. As a result of this, an adversary can perform API calls using these endpoints and evade the logging of their IP address/operating system information.
- **2×** i personally tried many times with wrong password even though no account lockout was detected
  - e.g. I personally tried many times with wrong password even though no account lockout was detected.
- **2×** i just successfully created an account robots txt which results in a profile path of and results in an bugged account as accessing account settings etc is impossible
  - e.g. I just successfully created an account robots.txt which results in a profile path of and results in an bugged account as accessing account settings etc is impossible.
- **2×** i only created it for testing purpose
  - e.g. I only created it for testing purpose.
- **2×** i m because i hacker found bug because i report this bug i want to report a bug and because want some so please because you are telling me how much you pay money so i give you bug
  - e.g. I'm because I hacker found bug because I report this bug I want to report a bug and because want some $$$$ so please because you are telling me how much you pay money so I give you bug.
- **2×** as i understood injected content script could successfully emit events to background page only if popup was initiated earlier
  - e.g. As I understood: injected content script could successfully emit events to background page only if popup was initiated earlier.
- **2×** readme the harm i have identified in twitter s cropping algorithm is under representation bias
  - e.g. Readme: The harm I have identified in Twitter's cropping algorithm is Under-representation Bias.
- **2×** the previous parser before 1aea05a6c26 had while isblank ptr ptr before parsing each attribute which correctly skipped htab
  - e.g. The previous parser (before `1aea05a6c26`) had `while(ISBLANK(*ptr)) ptr++;` before parsing each attribute, which correctly skipped HTAB.
- **2×** i would have liked to report this sooner before was out but i ve only managed to finish this now and i still have a lot of other curl cves to fix for the debian package
  - e.g. I would have liked to report this sooner, before 8.23.0 was out, but I've only managed to finish this now and I still have a lot of other curl CVEs to fix for the Debian package.
- **1×** we found several possible scenarios with different impact levels
  - e.g. We found several possible scenarios with different impact levels: 1.
- **1×** in particular we found that the fallback host for all akamai servers allow proxying to attacker servers
  - e.g. In particular, we found that the fallback host for all Akamai servers allow proxying to attacker servers.
- **1×** however even if the attacker controlled page or xss is only present on the attacker s account a dns attacker can always force his session on the client before sending him to his malicious page
  - e.g. However, even if the attacker controlled page or XSS is only present on the attacker's account, a DNS attacker can always force his session on the client before sending him to his malicious page.
- **1×** we found several instances of this attack most notably on websites that allow user to store files on their accounts
  - e.g. We found several instances of this attack, most notably on websites that allow user to store files on their accounts.
- **1×** this is by far the most widespread behavior we found several thousand such servers by sending requests to web servers for hosts covered by their certificate but not served locally
  - e.g. This is by far the most widespread behavior - we found several thousand such servers by sending requests to web servers for hosts covered by their certificate but not served locally.
- **1×** i was browsing through the pages and suddenly i saw this at my notification screenshot the two yahoo bug notification are definitely not mine as i ve not reported any bugs to yahoo while the slack s report is mine
  - e.g. I was browsing through the pages and suddenly I saw this at my notification: Screenshot: ███ The two yahoo bug notification are definitely not mine as I've not reported any bugs to Yahoo, while the Slack's report is mine.
- **1×** hi i just found that it s possible to create titleless and non closable bugs by prepending values for the report title and report vulnerability information parameters with characters respectively
  - e.g. Hi, I just found that it's possible to create titleless and non-closable bugs by prepending values for the 'report[title]' and 'report[vulnerability_information]' parameters with '%00' characters respectively.
- **1×** i have noticed your has address and this may lead to same site scripting
  - e.g. I have noticed your has address 127.0.0.1 and this may lead to "Same- Site" Scripting.
- **1×** this vulnerability affects attack details i tested invalid credentials and no account lockout was detected
  - e.g. This vulnerability affects Attack details I tested 10 invalid credentials and no account lockout was detected.
- **1×** affected sites i ve tested the top websites on wikipedia s somewhat out of date copy of the alexa toplist after unifying www google domains into a single entry and of them proved to be vulnerable
  - e.g. Affected sites ============== I've tested the 35 top websites on Wikipedia's (somewhat out of date) copy of the Alexa [toplist]( (after unifying www.google.* domains into a single entry), and 16 (~45%) of them proved to be vulnerable.
- **1×** python and are susceptible to arbitrary process memory reading by a user or adversary due to a bug in the json module caused by insufficient bounds checking
  - e.g. Python 2 and 3 are susceptible to arbitrary process memory reading by a user or adversary due to a bug in the _json module caused by insufficient bounds checking.
- **1×** ehy i have found a bug in twitter site but isn t in scope the site but i have decided to report because i think that you will consider it at our discretion
  - e.g. Ehy, I have found a bug in twitter site but isn't in scope (the site) but I have decided to report because I think that you will consider it at our discretion!
- **1×** hello i found another bug on here any hacker can find out all registered users on wordpress com
  - e.g. Hello, I found another bug on Here any hacker can find out all registered users on wordpress.com.

## Case studies (full excerpts)

### 1087489 — Github access token exposure
Shopify · $50000 · critical · https://hackerone.com/reports/1087489

While dissecting an application made by one of your employees I found his GitHub Personal Access Token (PAT), he's a member of the org with pull and push access to all of your repositories. As a proof I can tell you that on the repo github.com/Shopify/shopify at commit hash `cea9c273391d` the sha512 of the README.md is `69750574bec56c1f1052db3471252b1daacdc9dda9f6d5332a3400a847fa413ec1caf19ef0b5501f18a5a76c232e7210d5f3b91c24c9439f4e0f64c02d6db824`. ## Impact Read and write access to all your private github repositories.

### 3018307 — Groups module can halt chain when handling a proposal with malicious group weights
Cosmos · $15000 · high · https://hackerone.com/reports/3018307

### Summary of Impact After having a look into the patch for I discovered a very similar bug. The original error was due to a divide by zero at when the total power was zero. The patch prevented groups from having zero power and also added a guard to the division: The issue is that there are other ways that `Quo` can fail, such as if the exponent of the resulting value is out of range: Since there are no limits on group member weight, it's possible to trigger this failure by having two members with weights of `"1e-50000"` and `"1e50000"`. If the user with the tiny weight votes yes, `yesCount.Quo(totalPowerDec)` will return an error `decimal quotient error: exponent out of range` and cause a chain halt when `doTallyAndUpdate` is called from the EndBlocker. ### Steps to Reproduce Create a new chain with ignite: Create the following two json files using the addressed created by ignite server: members.json policy.json Create the group and transfer some funds to the policy address for testing: Create a new proposal file: proposal.json Submit and vote for the proposal Chain halts: ### Workarounds I think a patch/update will need to be applied to fix the issue. ### Supporting Material/References Criticality: High (Considerable Impact; Likely Likelihood per [ACMv1.2]( Affected users: Validators, Full nodes, Users on chains that utilize the groups module ## Impact A malicious user that 

### 838635 — Spring Actuator endpoints publicly available and broken authentication
LY Corporation · $12500 · critical · https://hackerone.com/reports/838635

Due to insufficient access control, it was possible to access the Spring Boot Actuator endpoints /heapdump and /env. @kazan71p identified two highly sensitive applications leaking information through these endpoints. The LINE Security team shutdown the secondary endpoints just as it was discovered by the reporter, as part of our incident response process. After further investigation, we also found that both applications had the same issue with their authentication functionality, due to using the same library. The issue was that old tokens were not expiring and being properly invalidated, allowing for replay attacks that should not have been possible. The applications were highly sensitive in nature, but due to not being able to retrieve specific data, we decided to award a bounty slightly below the maximum reward for this type of issue. We want to thank @kazan71p for his cooperation and contribution to our program!

### 3113398 — Internal Access to Hackerone confluence Docs
HackerOne · $12500 · high · https://hackerone.com/reports/3113398

This vulnerability allowed external access to HackerOne's internal Confluence documentation through a support system misconfiguration. The impact included: - Access to internal documentation that wasn't intended for public viewing - The ability to view and modify limited content within the Confluence instance This configuration issue demonstrated how support system workflows could be leveraged to gain unauthorized access to internal resources.

### 185775 — Crash: Initialize Decimal with itself triggers an assertion
shopify-scripts · $10000 · high · https://hackerone.com/reports/185775

When `Decimal` is initialized with itself, a new (empty) `mpd_t` will be created. To fill it with a value, `to_s` of the current instance is called, which accesses the empty `mpd_t`. This triggers an assertion, which leads to a crash. # Patch I've created and attached a simple patch which just returns self when a Decimal is initialized with itself. Pretty simple, but should do the job (careful: I've created the patch after a 20h flight, could be... uhm, suboptimal). # PoC PoC does work on ` but as it's not up2date that shouldn't really mean anything. # Trace

### 228648 — WannaCrypt “Killswitch”
HackerOne · no bounty (valid finding) · severity n/a · https://hackerone.com/reports/228648

WannaCrypt (a.k.a. WannaCry) is the name of a malware used in the May 2017 global ransomware attack targeting Microsoft Windows operating systems via known vulnerabilities leaked by The Shadow Brokers. In MalwareTech’s research, it was found that the malware sends an HTTP request to a seemingly random domain name in the early stages of its execution. If the HTTP call fails, the malware encrypts the user’s files, requests ransom, and will spread to other vulnerable machines. If the HTTP call is successful, the malware exits, halting encrypting files and spreading itself. Malware Tech also discovered that the domain name used in the malware’s HTTP request was available for sale and was able to register it. The malware relied on the domain name being unregistered so the HTTP call would always fail and it would continue to spread. By registering the domain name, it was possible to make the malware’s HTTP call return successfully. This resulted in the malware exiting early on new infections and effectively stopped this variant of the malware from spreading further. Original disclosure:

### 684092 — Steal ALL collateral during liquidation by exploiting lack of validation in `flip.kick`
BlockDev Sp. Z o.o · no bounty (valid finding) · critical · https://hackerone.com/reports/684092

## Summary: The `flip` contract allows for the MCD system to auction collateral in exchange for DAI. A lack of validation in the method `flip.kick` allows an attacker to create an auction with a fake bid value. Since the `end` contract trusts that value, it can be exploited to issue any amount of free DAI during liquidation. That DAI can then be immediately used to obtain all collateral stored in the `end` contract. ## Detailed Description: The `flipper` contract (`flip.sol`) is intended to offer a way for the MCD contracts to obtain DAI by auctioning gems. An auction is initiated by calling the `flip.kick` method, which is normally done by the `cat` contract when it grabs collateral from a CDP. The implementation of that method, however, completely lacks access control and has very little validation -- in particular, it's possible to execute the method even during the liquidation phase. On top of that, all values stored in the auction are accepted as parameters of the method, including the bid amount. By directly calling the method, a malicious user can create a "fake" auction, with an arbitrary initial bid value, without spending the corresponding DAI. Though that technique could be used to cause other damage, I will focus this report on the maximum-impact effect by exploiting it during the liquidation phase, in an attack vector that leads to transferring all collateral to th

## Field playbook (unedited)

### quick

- Classify the root cause before choosing a playbook.
- Search the corpus for the same technology or feature.
- Read the closest class skill and adapt its checklist.

### tools

- the corpus
- Burp
- nuclei

### chain

- Combine primitives into a higher-impact chain.

## Corpus search commands

```sh
python3 ~/.local/share/hackerone-reports/h1.py stats --class other
python3 ~/.local/share/hackerone-reports/h1.py search "<feature or param>" --class other --limit 10
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```
