# Evidence appendix — IDOR / Broken Object-Level Authorization

Mined from all **382 valid disclosed reports** for this class (88 paid, 23% — payment is not validity).

## Technique frequency (all valid writeups)

| Item | Count |
|---|---:|
| two-account / cross-account replay | 102 |
| admin / privileged-role context | 74 |
| encoding / double-encode / null byte | 56 |
| header injection (Host / X-Forwarded / etc.) | 52 |
| Content-Type / body-format switch | 49 |
| intercept & replay request in Burp | 45 |
| swap object ID / parameter value | 40 |
| HTTP method / verb tampering | 36 |
| file upload / filename / extension | 35 |
| public source-code / repo review | 32 |
| employee / developer public info | 23 |
| parameter pollution / duplicate keys | 16 |
| unauthenticated / removed-cookie test | 16 |
| cache / CDN / unkeyed header | 15 |
| fuzzing / wordlist brute force | 15 |
| XML / SOAP / SAML / XXE | 15 |
| error message / stack trace probing | 14 |
| internal service / port / container | 13 |
| subdomain / DNS / cert-transparency recon | 11 |
| JWT / token / base64 decode | 11 |
|  HosT/absolute-URL reset poisoning | 6 |
| second-order / stored / blind delivery | 6 |
| race / concurrency / timing | 6 |
| third-party data / paste / breach reuse | 6 |
| public bucket / storage exposure | 5 |
| cloud metadata / IAM abuse | 5 |
| DOM / HTML source inspection | 5 |
| replay / modify a captured request | 5 |
| OAST / DNS / HTTP callback proof | 4 |
| WAF / sanitizer / filter bypass | 4 |
| mass assignment / extra request fields | 4 |
| git history / exposed .git | 3 |
| browser DevTools / network tab | 3 |
| template injection (SSTI) | 3 |
| webhook / OAuth / SAML / integration abuse | 2 |
| response diff / status / length comparison | 2 |
| JS bundle / source-map inspection | 2 |
| deserialization / gadget chain | 2 |
| search-engine dorking | 1 |
| redirect chain / Location header | 1 |
| API docs / Swagger / introspection | 1 |
| parser confusion / normalization | 1 |
| archive / Wayback endpoint discovery | 1 |

## Tools mentioned

| Item | Count |
|---|---:|
| browser | 52 |
| burp | 41 |
| source-code-review | 24 |
| burp-repeater | 17 |
| devtools | 13 |
| burp-intruder | 8 |
| curl | 7 |
| python | 4 |
| git | 3 |
| burp-collaborator | 2 |
| collaborator/oast | 2 |
| zap | 1 |
| shodan | 1 |
| postman | 1 |
| waybackurls | 1 |

## Bypass primitives

| Item | Count |
|---|---:|
| content-type | 70 |
| bypass | 25 |
| whitelist | 9 |
| bypassed | 8 |
| same-site | 5 |
| bypasses | 2 |
| bypassing | 2 |
| blind | 2 |
| null byte | 1 |
| race condition | 1 |
| normalized | 1 |

## Impact language

| Item | Count |
|---|---:|
| token | 148 |
| admin | 95 |
| password | 94 |
| unauthorized | 54 |
| payment | 42 |
| localhost | 29 |
| credential | 23 |
| secret | 18 |
| pii | 15 |
| sensitive information | 14 |
| account takeover | 13 |
| sensitive data | 10 |
| privilege escalation | 8 |
| financial | 6 |
| api key | 4 |
| full access | 3 |
| mass enum | 3 |
| funds | 1 |
| ato | 1 |
| personally identifiable | 1 |

## Parameters observed

| Item | Count |
|---|---:|
| onerror | 10 |
| src | 10 |
| max-age | 7 |
| charset | 5 |
| user_id | 5 |
| password | 5 |
| txtamount | 4 |
| amount | 4 |
| txtcustomamount | 4 |
| username | 4 |
| imageid | 4 |
| profileid | 4 |
| target_id | 4 |
| target_type | 4 |
| selectedaddressid | 3 |
| _ga | 3 |
| _gid | 3 |
| awsalb | 3 |
| awsalbcors | 3 |
| googtrans | 3 |
| uid2 | 3 |
| team_id | 3 |
| detailed | 3 |
| hacker_username | 2 |
| http-session | 2 |
| asp.net_sessionid | 2 |
| cams_sid_mycamscluster_system | 2 |
| _format | 2 |
| filename | 2 |
| comment_id | 2 |

## Recurring approach patterns

- **2×** psychomantis was able to demonstrate this vulnerability by crafting a specially formatted url
  - e.g. @psychomantis was able to demonstrate this vulnerability by crafting a specially formatted URL.
- **2×** i have tested retrieving following ids
  - e.g. I have tested retrieving following ids: █████.
- **2×** i l victim is able see the association to the attacker s child epic and may trust navigate to the attacker s group when clicking on it
  - e.g. * `I:L`: Victim is able see the association to the attacker's child epic and may trust/navigate to the attacker's group when clicking on it.
- **1×** i haven t tried this but i think this can be done
  - e.g. I haven't tried this but I think this can be done.
- **1×** see screenshot where i was able to remove certain folks without inviting them
  - e.g. See screenshot 2 where I was able to remove certain folks without inviting them.
- **1×** i apologize for the emails that were sent out to two different hackerone researchers accidentally
  - e.g. I apologize for the 2 emails that were sent out to two different HackerOne researchers accidentally.
- **1×** when i change identified user id to other user s id then request of add friend is send to other user without any token and secession validation
  - e.g. when i change identified user ID to other user's ID then request of add friend is send to other user without any token and secession validation ..
- **1×** description while creating a product i noticed there is a call to which returns json details about the product
  - e.g. ##Description While creating a product, I noticed there is a call to which returns json details about the product.
- **1×** while exploring subgroup functionality i noticed that an unprivileged user can disclose private group names by incrementing the parent id parameter
  - e.g. While exploring Subgroup functionality, I noticed that an unprivileged user can disclose private group names by incrementing the `parent_id` parameter.
- **1×** afterwards i created an unprivileged user no group or project assignments and visited the below url disclosing the name of privategroup
  - e.g. Afterwards, I created an unprivileged user (no group or project assignments) and visited the below URL, disclosing the name of `PrivateGroup`.
- **1×** type a random last name i used smith and type a random number in the other field
  - e.g. Type a random last name (I used Smith) and type a random number in the other field 5.
- **1×** note for my tests i created previously some two appointment numbers 30ac5814 and 9d1d10c7 and i have added them to the wordlist thus i don t gotten any user legit information
  - e.g. █████████ **Note:** For my tests I created previously some two Appointment Numbers (**30AC5814** and **9D1D10C7**) and I have added them to the wordlist, thus I don't gotten any user legit information.
- **1×** also by clicking again the transfer store to client link you will see in the dropdown the staff members
  - e.g. __Also, by clicking again the Transfer store to client link, you will see in the dropdown the staff members.
- **1×** good evening vulnerability i m able to create accounts with the email verification that originates from the first account i created
  - e.g. Good evening, #Vulnerability I'm able to create accounts with the email verification that originates from the first account I created.
- **1×** this is my confirm email link that created the account poc originally the post body was going to my main email connected to my github account then i changed the post body attribute to post request post body here s the screenshot of the request saying it was created
  - e.g. This is my confirm email link that created the account #POC Originally the post body was going to my main email connected to my Github account █████████ then I changed the post body attribute to POST REQUEST POST body: Here's the screenshot of the request saying it was created █████.
- **1×** i found an insecure direct object reference vulnerability on the endpoint
  - e.g. I found an Insecure Direct Object Reference vulnerability on the ` endpoint.
- **1×** i think i have found a security issue
  - e.g. I think I have found a security issue .
- **1×** however after the trial period is over for a free account upon logging in to the actors account he gets a message like this and it s not possible to access anything at all as this comes every time
  - e.g. However after the trial period is over for a free account , Upon logging in to the actors account he gets a message like this and it's not possible to access anything at all as this comes every time .
- **1×** i used jong jong accounts to submit test report to parrot sec program
  - e.g. I used @jong_jong accounts to submit test report to Parrot Sec program.
- **1×** the researcher found an idor that when exploited would result in an error message that was too verbose
  - e.g. The researcher found an IDOR that when exploited would result in an error message that was too verbose.
- **1×** description through google dorking i discovered that there are two results in google for subdomains of api semrush com see f234928
  - e.g. **Description:** Through google dorking, I discovered that there are two results in google for subdomains of api.semrush.com (see F234928).
- **1×** by clicking either of the links i realised that it is possible to change the domain parameter and get the information for that domain
  - e.g. By clicking either of the links, I realised that it is possible to change the domain parameter and get the information for that domain.
- **1×** i tried to further look at this by adding in other fields as per the api guide and could submit any query i wished such as see f234936 i noticed that this doesn t work against api semrush com only uk api semrush com or us api semrush com
  - e.g. I tried to further look at this by adding in other fields as per the API guide, and could submit any query I wished, such as: (see F234936) I noticed that this doesn't work against api.semrush.com, only uk.api.semrush.com or us.api.semrush.com.
- **1×** however i have found a way to edit the visibility of any co admin co member of the team where i belong using idor
  - e.g. However i have found a way to edit the visibility of any co-admin / co-member of the team where i belong using IDOR.

## Case studies (full excerpts)

### 743953 — Steal private objects of other projects via project import
GitLab · $20000 · critical · https://hackerone.com/reports/743953

### Summary An attacker could transfer issues, merge requests of another project to the imported project by importing a crafted GitLab export. ### Steps to reproduce 1. Import the attached tarball as GitLab export. 2. Check the issues page of the imported project. You will see an private issue created by instead of the current user. ### Description The exploit is in project.json, I added one line to assign `issue_ids` and kept `issues` an empty array. The issues_ids contains the database id of the issues the attacker wants to steal. There's no good way for the attacker to know the id of a specific issue, but as the id is incremental, the attacker could simply steal as many issues as possible in a brute forcing manner. The root cause of this issue lies in `project_tree_restorer.rb` Many attributes (foreign key) like `issue_ids` and `merge_request_ids` are not excluded during import. According to my observation, affected objects including (but not limited to): Looks like almost all non-excluded attributes behaves like `issues` are affected. ### Examples {F640860} ### Output of checks This bug happens on GitLab.com and self-hosted GitLab installations. ## Impact With this ability to modify relations between objects, an attacker could end up with accessing random resources of other users by traversing the incremental ID space.

### 767770 — Private objects exposed through project import
GitLab · $20000 · critical · https://hackerone.com/reports/767770

### Summary This is a bypass of , the current fix is blocking all "_ids" attributes. However an attacker could still set attributes like `issue_ids` by indrectly settings the field within the `attributes` field it self: ### Steps to reproduce 1. Import the attached tarball. 2. Check issues tab The other parts of the report are mostly same as those I mentioned in , I decide to write a new report considering the impact to gitlab.com. ## Impact With this ability to modify relations between objects, an attacker could end up with accessing random resources of other users by traversing the incremental ID space.

### 1819832 — Delete anyone's content spotlight remotely.
Snapchat · $15000 · high · https://hackerone.com/reports/1819832

Hello Snapchat, Snapchat has viral video feature callled spotlight which alone was the biggest trend and increase snapchat users and profit in millions. I found a way to delete anyone's spotlight remotely. Please see the below poc:- 1. First go to and log in there. 2. You will see your posts . 3. Now turn burp suite and intercept. 4.Select any of your posts and click delete option. 5. Now capture the delete request. In delete request there is parameter of id {"operationName":"DeleteStorySnaps","variables":{"ids":["███████"],"storyType":"SPOTLIGHT_STORY"},"query":"mutation DeleteStorySnaps($ids: [String!]!, $storyType: StoryType!) {\n deleteStorySnaps(ids: $ids, storyType: $storyType)\n}\n"} 6. You just have to change this id parameter. You can easily get the id parameter. Now forward the request after replacing id with someone's else video id. And the video of other user will get delete. HOW TO GET ID PARAMETER 1. Whenever you share spotlight you can see the parameter in the url as: I have attached a video POC please check it out ## Impact Delete anyone's Content Spotlight. Imagine deleting video biggest influencers and content creators.

### 3862641 — IDOR allows user to access report details via reference.json endpoint
HackerOne · $15000 · critical · https://hackerone.com/reports/3862641

**Summary:** An information disclosure vulnerability on the `/reports/{id}/reference.json` endpoint allowed VDP accounts created via `hackerone.com/vdp-sign-up` to access certain private report details. While the endpoint returned HTTP 422 "You do not have the appropriate access," the error response contained additional report details in the `context.subject` field. **Description:** By sending a POST request to the `/reports/{report_id}/reference.json` endpoint with an empty JSON body `{}`, VDP users could retrieve information about private reports belonging to other programs despite receiving an access-denied error. Although the endpoint correctly rejected unauthorized access with an HTTP 422 status code, it inadvertently included private report data in the error response body. **Steps To Reproduce:** 1. Create a VDP account at `hackerone.com/vdp-sign-up` 2. Log in with the VDP account 3. Obtain an approved test report ID from (these reports contain flags to include in your POC), 4. Send a POST request to ` with the following structure: 4. Observe that despite receiving HTTP 422 with "You do not have the appropriate access," the response contains report details in the `context.subject` field **Note:** This vulnerability has been fixed. We have found no evidence of misuse in our investigation to date, and no action is required from users..

### 415081 — IDOR to add secondary users in www.paypal.com/businessmanage/users/api/v1/users
PayPal · $10500 · high · https://hackerone.com/reports/415081

PayPal Business Accounts allow account owners to create multiple secondary users with specific privileges assigned to their employees. This submission identified a method that made it possible for a Business Account owner to assign secondary users from other accounts. The new secondary user would be granted access to the login allowing for unauthorized access to the functions of that single user login. PayPal remediated the vulnerability and found no evidence of abuse associated with it.

### 762510 — How the Bug stole hacking
HackerOne · no bounty (valid finding) · none · https://hackerone.com/reports/762510

In light of the season - here's a story I wrote for you: ## Impact Happy Holidays and thanks for all you do. <3

### 2122671 — IDOR - Delete all Licenses and certifications from users account using CreateOrUpdateHackerCertification GraphQL query
HackerOne · no bounty (valid finding) · high · https://hackerone.com/reports/2122671

**Summary:** Hey team, While editing our **Licenses and certifications** if we change the ID number we can delete other users **Licenses and certifications**. it simply can be done by editing the ID number in our graphql query. If change the ID from 1 to X possible range then we can delete all the **Licenses and certifications** present between these. ### Steps To Reproduce 1. Log in to your own account in two browsers A and B with User A and User B 2. Create your own **Licenses and certifications* in both the account 3. Now edit your own **Licenses and certifications* and Intercept this using a Burp Proxy 4. Now In the body change the **ID** number and you will be able to delete all the **Licenses and certifications** present in HackerOne 5. For now change the ID to the **Licenses and certifications** ID of the Other account and it will be deleted. PoC Video: ████ ## Impact Able to delete all the **Licenses and certifications** present in HackerOne

## Field playbook (unedited)

### quick

- Collect every identifier from responses, exports, emails, JS bundles, and mobile APIs.
- Replay the same request with a second account and with no auth; compare status, length, and body.
- Test list/search/export/batch endpoints, not only detail pages.
- Try nested resources: /org/1/user/2, /invoice/9/line/1, and composite IDs.
- Check file downloads and signed-URL generation for object substitution.

### payloads

- Numeric -> id=1 -> id=2, id=0, id=-1, id=999999
- UUID/hash -> swap a known UUID from another account; try UUIDv1 timestamps.
- Encoded -> base64 decode/encode, hex, JWT sub, gid://app/Model/123
- Batch -> `{"ids":[1,2,3]}` or repeated `id=1&id=2`
- Nested -> `/users/1/orders/2` with user 1 but order 2

### bypass

- Swap GET/POST/PUT/PATCH/DELETE; try method override headers and `_method`.
- Move the ID from body to query, path, or header; try JSON arrays and duplicate keys.
- Test hidden fields and mass assignment on owner/org/role/account fields.
- GraphQL: query other users' nodes, aliases, and nested connections directly.

### surface

- id
- user_id
- account_id
- org_id
- team_id
- order_id
- invoice_id
- file_id
- message_id
- project_id
- tenant
- uuid

### tools

- Autorize
- Burp Repeater
- ffuf
- mitmproxy
- Postman

### chain

- IDOR read -> PII exposure.
- IDOR write -> account takeover.
- IDOR + mass assignment -> privilege escalation.

## Corpus search commands

```sh
python3 ~/.local/share/hackerone-reports/h1.py stats --class idor
python3 ~/.local/share/hackerone-reports/h1.py search "<feature or param>" --class idor --limit 10
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```
