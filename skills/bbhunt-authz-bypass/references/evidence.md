# Evidence appendix — Authorization and Access-Control Bypass

Mined from all **1386 valid disclosed reports** for this class (337 paid, 24% — payment is not validity).

## Technique frequency (all valid writeups)

| Item | Count |
|---|---:|
| admin / privileged-role context | 514 |
| public source-code / repo review | 230 |
| Content-Type / body-format switch | 165 |
| encoding / double-encode / null byte | 152 |
| subdomain / DNS / cert-transparency recon | 152 |
| header injection (Host / X-Forwarded / etc.) | 147 |
| file upload / filename / extension | 140 |
| two-account / cross-account replay | 137 |
| HTTP method / verb tampering | 125 |
| internal service / port / container | 110 |
| employee / developer public info | 99 |
| cache / CDN / unkeyed header | 98 |
| intercept & replay request in Burp | 97 |
| webhook / OAuth / SAML / integration abuse | 79 |
| unauthenticated / removed-cookie test | 75 |
| XML / SOAP / SAML / XXE | 67 |
| parameter pollution / duplicate keys | 66 |
| cloud metadata / IAM abuse | 58 |
| JWT / token / base64 decode | 50 |
| WAF / sanitizer / filter bypass | 46 |
| API docs / Swagger / introspection | 44 |
| DOM / HTML source inspection | 41 |
| race / concurrency / timing | 41 |
| second-order / stored / blind delivery | 40 |
| OAST / DNS / HTTP callback proof | 38 |
| swap object ID / parameter value | 33 |
|  HosT/absolute-URL reset poisoning | 32 |
| fuzzing / wordlist brute force | 31 |
| public bucket / storage exposure | 29 |
| error message / stack trace probing | 28 |
| replay / modify a captured request | 25 |
| git history / exposed .git | 24 |
| JS bundle / source-map inspection | 24 |
| redirect chain / Location header | 23 |
| third-party data / paste / breach reuse | 22 |
| mass assignment / extra request fields | 16 |
| verbose debug / framework fingerprint | 15 |
| browser DevTools / network tab | 14 |
| parser confusion / normalization | 14 |
| response diff / status / length comparison | 13 |
| deserialization / gadget chain | 10 |
| template injection (SSTI) | 9 |
| archive / Wayback endpoint discovery | 7 |
| search-engine dorking | 7 |

## Tools mentioned

| Item | Count |
|---|---:|
| source-code-review | 204 |
| browser | 141 |
| burp | 98 |
| curl | 75 |
| devtools | 69 |
| python | 33 |
| git | 32 |
| burp-repeater | 26 |
| burp-collaborator | 19 |
| collaborator/oast | 19 |
| burp-intruder | 18 |
| javascript-debugging | 18 |
| decompiler | 10 |
| shodan | 6 |
| ffuf | 6 |
| dnsdump | 5 |
| jq | 4 |
| nmap | 3 |
| sqlmap | 3 |
| beautifier | 2 |

## Bypass primitives

| Item | Count |
|---|---:|
| bypass | 357 |
| content-type | 314 |
| bypassed | 51 |
| bypassing | 47 |
| whitelist | 40 |
| blind | 25 |
| open redirect | 19 |
| bypasses | 18 |
| %0d%0a | 18 |
| time-based | 9 |
| content type | 8 |
| host header | 6 |
| http method | 6 |
| blacklist | 5 |
| race condition | 5 |
| crlf | 4 |
| allowlist | 4 |
| same site | 3 |
| second order | 3 |
| unicode | 3 |
| normalize_forum_visibility | 3 |
| null byte | 2 |
| bypass1007 | 2 |
| lowercase | 2 |
| uppercase | 2 |
| bypassable | 2 |
| same-site | 2 |
| backslash | 2 |

## Impact language

| Item | Count |
|---|---:|
| admin | 1537 |
| token | 1020 |
| password | 791 |
| credential | 390 |
| secret | 260 |
| payment | 161 |
| unauthorized | 156 |
| localhost | 142 |
| privilege escalation | 99 |
| sensitive information | 54 |
| api key | 38 |
| account takeover | 32 |
| full access | 30 |
| sensitive data | 30 |
| exfiltration | 30 |
| arbitrary file | 29 |
| pii | 28 |
| funds | 23 |
| rce | 21 |
| arbitrary code | 21 |

## Parameters observed

| Item | Count |
|---|---:|
| charset | 34 |
| name | 32 |
| action | 21 |
| token | 19 |
| value | 15 |
| type | 10 |
| _ga | 9 |
| xsrft | 8 |
| path | 8 |
| message | 8 |
| authenticity_token | 8 |
| vuid | 7 |
| email | 7 |
| src | 7 |
| _gid | 7 |
| nonce | 7 |
| xxxxxxxxxxxxxxxxxxxx | 7 |
| __utma | 6 |
| __utmb | 6 |
| __utmc | 6 |
| __utmz | 6 |
| utmcsr | 6 |
| utmccn | 6 |
| utmcmd | 6 |
| vimeo | 6 |
| expires | 6 |
| mode | 6 |
| max-age | 6 |
| url | 6 |
| month | 6 |

## Recurring approach patterns

- **2×** common access control vulnerabilities include bypassing access control checks by modifying the url internal application state or the html page or simply using a custom api attack tool
  - e.g. Common access control vulnerabilities include: * Bypassing access control checks by modifying the URL, internal application state, or the HTML page, or simply using a custom API attack tool.
- **2×** i created a folder named eicar on my system
  - e.g. I created a folder named 'eicar' on my system.
- **2×** steps to reproduce i created a dll file which when loaded spawns while giving information as to which application loaded the dll path from where the file was loaded and user privilege
  - e.g. ## Steps To Reproduce I created a DLL file which when loaded spawns while giving information as to which application loaded the DLL, path from where the file was loaded, and user privilege.
- **2×** so i was able to takeover the page and host the poc kubernetes version na component version na steps to reproduce
  - e.g. So I was able to takeover the page and host the PoC ## Kubernetes Version: NA ## Component Version: NA ## Steps To Reproduce: 1.
- **2×** i haven t found any smart contract that has implemented this code
  - e.g. I haven't found any smart contract that has implemented this code.
- **2×** i have found smart contract that could be used for atomic swap between eth xmr but it hasn t got this vulnerability
  - e.g. I have found smart contract that could be used for atomic swap between eth-xmr, but it hasn't got this vulnerability.
- **2×** we have found non production endpoints which exhibit this behavior
  - e.g. We have found 18 non-production endpoints which exhibit this behavior.
- **1×** i just created the admin profile go check it out or see attached image
  - e.g. I just created the admin profile, go check it out: Or see attached image!
- **1×** we just need a moment p i actually discovered this bug when gmail rejected my smtp credentials to prevent suspicious login p
  - e.g. (we just need a moment :P) I actually discovered this bug when gmail rejected my smtp credentials to prevent suspicious login :P.
- **1×** hackeradmin can obtain the victim account ids by sending an invitation to the victim email id account id displayed in the response
  - e.g. -> Hackeradmin can obtain the victim account ids by sending an invitation to the victim email id (account id displayed in the response).
- **1×** hello this time i found a idor insecure direct object reference vulnerability
  - e.g. Hello, This time I found a IDOR(Insecure Direct Object Reference) vulnerability.
- **1×** so a member of any team can pass this token to other people and they will be added to the team i used this token times and it s still live
  - e.g. So, a member of any team can pass this token to other people and they will be added to the team.I used this token 3 times and it's still live.
- **1×** however bob can edit his previous comments by replaying the request captured in step
  - e.g. However, Bob can edit his previous comments by replaying the request captured in step 3.
- **1×** however bob can post comments on the private video by replaying the request captured in step
  - e.g. However, Bob can post comments on the private video by replaying the request captured in step 5.
- **1×** but he can comment on that video by replaying the request captured in step
  - e.g. But he can comment on that video by replaying the request captured in step 2.
- **1×** hello i found a way to access group dm s which i don t have access to conditions to be met should have been in that dm group atleast once
  - e.g. **Hello**, I found a way to access group DM's which i don't have access to, Conditions to be met: - Should have been in that DM group atleast once.
- **1×** however he can modify the login services by sending the below request use proper authenticity token and cookies before sending the request
  - e.g. However, he can modify the Login Services by sending the below request (use proper authenticity_token and cookies before sending the request).
- **1×** to resolve this we changed the display of the account page so only the account owner has access to the invitation link
  - e.g. To resolve this, we changed the display of the Account page so only the account owner has access to the invitation link.
- **1×** i have found a readme md files also i think this is leaking more information
  - e.g. I have found a readme.md files also i think this is leaking more information.
- **1×** the shopify point of sale application is compatible with a new emv card reader from miura the researcher discovered that the firmware for this device contains a wifi password configured in wpa supplicant presumably used during factory tests
  - e.g. The Shopify Point of Sale application is compatible with a new EMV card reader from [Miura]( The researcher discovered that the firmware for this device contains a wifi password configured in wpa_supplicant (presumably used during factory tests).
- **1×** we ve removed the author name from the public api
  - e.g. We've removed the author name from the public API.
- **1×** we fixed the issue by correctly checking for each permissions separately on the relevant endpoints
  - e.g. We fixed the issue by correctly checking for each permissions separately on the relevant endpoints.
- **1×** hi i found out that a user who belongs to a group with read only permission can still request and approuve public disclosure when the report is closed by privileged admin although that these permissions are only allowed if the user group has report scope
  - e.g. Hi, I found out that a user who belongs to a group with Read-Only permission can still request and approuve public disclosure when the report is closed by privileged admin although that these permissions are only allowed if the user group has **Report** scope.
- **1×** i tried using my accounts and got success in the same
  - e.g. I tried using my 2 accounts and got success in the same.

## Case studies (full excerpts)

### 2293343 — Account Takeover via Password Reset without user interactions
GitLab · $35000 · critical · https://hackerone.com/reports/2293343

@asterion04 submitted a report to GitLab. Summary I found a way to change the password of a GitLab account via the password reset form and successfully retrieve the final reset link without user interactions, using just its email address. Steps to reproduce Go to "Forgot Your Password?" link Enter the victim's email and intercept the submit request via Burp Suite . Then right-click on the HTTP Editor inside Burp Suite and select Extensions -> Content-Type Converter -> Convert to JSON (make sure to have the Content-Type Converter plugin installed from the BApp Store) Now replace this converted JSON line `` "user[email]":"victim@gmail.com"``, to Forward the requests and you should get an email containing the reset link that was send to both emails (``victim@gmail.com`` and ``attacker@gmail.com``) . Click on the reset link, change the password and done, you can now login as the victim using the new password. Impact By just knowing the victim email address used on GitLab, you can takeover his account by changing his password without user interaction since the attacker get the same email as the victim.

### 1685822 — RepositoryPipeline allows importing of local git repos
GitLab · $22300 · medium · https://hackerone.com/reports/1685822

### Summary When importing a project via the BulkImports, the response field `httpUrlToRepo` from the client is used to fetch the repo: `Gitlab::UrlBlocker.validate` is called, but since no schemas are passed in it allows any (such as file) so long as the rest of the url is valid. This means that if a url such as `file://aw.rs/var/opt/gitlab/git-data/repositories/@hashed/b1/74/b174103b399555239923697fbe124faa61de4d441bd5c5678275eb0a5a27a562.git` is supplied, this will end up being used by git fetch, eg: This allows an attacker to import any local repository that the current machine has access to if the path is known. The storage path for projects in gitlab is just based on a configurable folder combined with a bucketed sha2 hash of the id, eg for project 38006449 the `Digest::SHA2.hexdigest("38006449")` is `b174103b399555239923697fbe124faa61de4d441bd5c5678275eb0a5a27a562` so the path will be at `@hashed/b1/74/b174103b399555239923697fbe124faa61de4d441bd5c5678275eb0a5a27a562.git`. This can then be used to import any gitlab repository via the project id by calculating the path, such as the gitlab ctf project! `{gitlab-bounty-flag-7a3f26698d2ef146843d7209e5efc8ec}` ### Steps to reproduce 1. Create a private project with User A and edit the readme file, make note of the project id 1. Download {F1892171} and edit line 99 with the new path to the repository above (replace `b1/74/b1741

### 391217 — Getting all the CD keys of any game
Valve · $20000 · critical · https://hackerone.com/reports/391217

Using the `/partnercdkeys/assignkeys/` endpoint on partner.steamgames.com with specific parameters, an authenticated user could download previously-generated CD keys for a game which they would not normally have access. Audit logs were not bypassed using this method, and an investigation of those audit logs did not show any prior or ongoing exploitation of this bug.

### 1379975 — bd-j exploit chain
PlayStation · $20000 · high · https://hackerone.com/reports/1379975

Hey PlayStation! Below are 5 vulnerabilities chained together that allows an attacker to gain JIT capabilities and execute arbitrary payloads. The provided payload triggers a buffer overflow that causes a kernel panic. Please consider each of the vulnerabilities individually. AFAIK, this is the first exploit chain that is being submitted to you :) ## Vulnerabilities ### [MEDIUM] [PS4] [PS5] Vulnerability 1 The class `com.sony.gemstack.org.dvb.user.UserPreferenceManagerImpl` deserializes the `userprefs` file under privileged context using `readObject()` which is insecure: An attacker can replace the `userprefs` file with a malicious serialized object to **instantiate classes under privileged context**. On older firmwares such as 5.05, where the commit is not present, exploitation of this vulnerability is easy: An attacker can instantiate a `ClassLoader` subclass to call `defineClass` with all permissions and finally bypass the security manager. ### [MEDIUM] [PS4] Vulnerability 2 The class `com.oracle.security.Service` contains a method `newInstance` which calls `Class.forName` on an arbitrary class name. **This allows arbitrary classes, even restricted ones (for example in `sun.`), to be instantiated**. This works for all classes with public constructors that have single arguments. The check in `newInstance` can be bypassed by calling `com.oracle.ProviderAdapter.setProviderAcces

### 689314 — Project Template functionality can be used to copy private project data, such as repository, confidential issues, snippets, and merge requests
GitLab · $12000 · critical · https://hackerone.com/reports/689314

I've found a three minor vulnerabilities which, when combined, allow an attacker to copy private repositories, confidential issues, private snippets, and then some. I'll go through the code path to explain the vulnerabilities and how they are combined. See the **Proof of Concept** section if you want to reproduce it immediately. Let's start at the `ProjectsController` of EE, which is prepended to `app/controllers/projects_controller.rb` in an EE instance. **ee/app/controllers/ee/projects_controller.rb** This method defines what parameters can be passed by the user. The two notable parameters here are `use_custom_template` and `group_with_project_templates_id`. This method appends the result value of `project_params_attributes` method in `app/controllers/projects_controller.rb` on line 351, which specifies all the CE attributes a user can provide when creating a project. The CE controller allows the `template_name` parameter to be passed, too. This means that these three parameters can be passed to the `Projects::CreateService` in the `create` method: **app/controllers/projects_controller.rb** In EE, the `EE:Projects::CreateService` is prepended to the `Projects::CreateService`. The prepended EE code contains logic to validate the `use_custom_template` and `group_with_project_templates_id` parameters. **ee/app/services/ee/projects/create_service.rb** The code above is where the 

### 796808 — [Part II] Email Confirmation Bypass in myshop.myshopify.com that Leads to Full Privilege Escalation
Shopify · no bounty (valid finding) · critical · https://hackerone.com/reports/796808

## Summary In #791775, I submitted a bug at Sunday 5pm Canada time, it was triaged two hours later, and I got the **temp** fix message at around 3am the next day in Canada time. Truly awesome, the next day I retested after the first fix, and found that I - Cannot receive the email confirmation in the email used to sign up - Cannot integrate across stores/partner even they share the same email address after confirming them And the report was later resolved after I verified the fix. For some reason, I decided to test again to see what's something new that I can find. Then I found user can change their email prior to receiving the verification message on their original email. i.e. the same technique, I don't know what went wrong in my first retest, but Shopify security and engineering team again showed their professionalism, quickly resolving the second comments I left in ~3.5 hrs. And when I thought this is the end of story, I later received a comment asking me to open a new report about the second retest, and here I am writing this report. Thanks, Ron ## Impact .

### 792927 — Email address of any user can be queried on Report Invitation GraphQL type when username is known
HackerOne · no bounty (valid finding) · high · https://hackerone.com/reports/792927

**Summary:** Email id of all hackerone users disclosure **Description:** There is an flaw , with that i can get all hackerone users email id ### Steps To Reproduce 1. Invoke the below graphql call POST /graphql HTTP/1.1 you will get below response 2. to reproduce from your account, create one test program, and create one report for that program, get that report id gid://hackerone/Report/626371 (here 626371 my test program's report id) convert it into base 64, replace that id with the "report_id" in the above graphql query 3. Done ## Impact PII disclosed

## Field playbook (unedited)

### quick

- Build a role matrix (anon, user, member, admin, support) and replay every request across roles.
- Try admin endpoints and hidden routes found in JS bundles, mobile apps, and API docs.
- Test org/tenant boundaries with two accounts on different plans.
- Check function-level authz: the UI hides it, but does the API enforce it?
- Replay requests after removing cookies, tokens, and role headers.

### payloads

- Role fields -> `role=admin`, `is_admin=true`, `plan=enterprise`, `permissions=["*"]`
- Headers -> `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-For: 127.0.0.1`, `X-User-Id`
- Path tricks -> `/admin/../user`, `/admin%2f..%2f`, `/.;/admin`, trailing slash
- Method swap -> GET->POST->PUT->DELETE, `X-HTTP-Method-Override`

### bypass

- Middleware path-normalization mismatch: `/admin/..;/`, `%2e%2e`, double slashes.
- Header spoofing for IP allowlists and internal-only endpoints.
- GraphQL/REST resolver differences: one enforces authz, the other does not.
- Stale permissions after role change or org removal.

### surface

- role
- admin
- permission
- org
- team
- account
- tenant
- owner
- visibility
- public
- internal

### tools

- Autorize
- Burp
- ffuf
- nuclei
- jwt_tool

### chain

- Authz bypass -> admin panel -> data export.
- Privilege escalation -> cross-tenant access.
- Unauth endpoint -> internal API -> RCE.

## Corpus search commands

```sh
python3 ~/.local/share/hackerone-reports/h1.py stats --class authz-bypass
python3 ~/.local/share/hackerone-reports/h1.py search "<feature or param>" --class authz-bypass --limit 10
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```
