---
name: hackerone-idor
description: >-
  Hunt IDOR and broken object-level authorization. Use when APIs expose IDs, files, invoices, messages, or tenant-scoped resources. Backed by 450 disclosed HackerOne reports.
---

# IDOR / Object-Level Authorization — HackerOne field guide

Built from **450** publicly disclosed HackerOne reports (2015–2026). Corpus: `~/.local/share/hackerone-reports/`.

## Signal

- Reports: **450** · paid: **107**
- Median bounty **$500** · p90 **$5,000** · max **$20,000** · total **$199,099**
- Median upvotes **31**

## Where it pays

| Program | Reports | Bounty | Upvotes |
|---|---|---|---|
| GitLab | 12 | $44,550 | 858 |
| Mail.ru | 37 | $24,260 | 971 |
| New Relic | 18 | $19,250 | 379 |
| HackerOne | 20 | $18,000 | 3370 |
| Snapchat | 1 | $15,000 | 801 |
| Reddit | 7 | $10,500 | 813 |
| PayPal | 1 | $10,500 | 797 |
| GitHub | 6 | $10,000 | 657 |

## Quick wins

Start here. These are the highest-yield tests for this class.

- Collect every identifier from responses, exports, emails, JS bundles, and mobile APIs.
- Replay the same request with a second account and with no auth; compare status, length, and body.
- Test list/search/export/batch endpoints, not only detail pages.
- Try nested resources: /org/1/user/2, /invoice/9/line/1, and composite IDs.
- Check file downloads and signed-URL generation for object substitution.

## Payloads & probes

- Numeric -> id=1 -> id=2, id=0, id=-1, id=999999
- UUID/hash -> swap a known UUID from another account; try UUIDv1 timestamps.
- Encoded -> base64 decode/encode, hex, JWT sub, gid://app/Model/123
- Batch -> `{"ids":[1,2,3]}` or repeated `id=1&id=2`
- Nested -> `/users/1/orders/2` with user 1 but order 2

## Bypass tricks

- Swap GET/POST/PUT/PATCH/DELETE; try method override headers and `_method`.
- Move the ID from body to query, path, or header; try JSON arrays and duplicate keys.
- Test hidden fields and mass assignment on owner/org/role/account fields.
- GraphQL: query other users' nodes, aliases, and nested connections directly.

## Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`id` `user_id` `account_id` `org_id` `team_id` `order_id` `invoice_id` `file_id` `message_id` `project_id` `tenant` `uuid`

## Tools

`Autorize` · `Burp Repeater` · `ffuf` · `mitmproxy` · `Postman`

## Escalation chains

- IDOR read -> PII exposure.
- IDOR write -> account takeover.
- IDOR + mass assignment -> privilege escalation.

## Deeper checklist

- Collect every object identifier from responses, exports, emails, and JS bundles.
- Swap IDs across two accounts and across tenants; test sequential, UUID, and hashed IDs.
- Try ID formats: numeric +-1, UUID v1, base64, slug, composite keys, nested IDs.
- Check list, search, export, and batch endpoints, not just detail endpoints.
- Test file/download endpoints and signed URL generation for object substitution.
- Look for authorization based only on the parent object (nested resource IDOR).
- Confirm cross-account data access with a second controlled account.

## Techniques from real reports

One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.

- **Delete anyone's content spotlight remotely.** — `#1819832` · Snapchat · $15,000 · ▲801
  > {"operationName":"DeleteStorySnaps","variables":{"ids":["███████"],"storyType":"SPOTLIGHT STORY"},"query":"mutation DeleteStorySnaps($ids: [String!]!, $storyType: StoryType!) {\n deleteStorySnaps(ids: $ids, storyType: $storyType)\n}\n"}
- **IDOR allows user to access report details via reference.json endpoint** — `#3862641` · HackerOne · $15,000 · ▲372
  > By sending a POST request to the `/reports/{report id}/reference.json` endpoint with an empty JSON body `{}`, VDP users could retrieve information about private reports belonging to other programs despite receiving an access-denied error.
- **Insecure Direct Object Reference (IDOR) - Delete Campaigns** — `#1969141` · HackerOne · $0 · ▲346
  > At the campaign id parameter in the request change it to another program's ongoing campaign id parameter.
- **Attachment disclosure via summary report** — `#2442008` · HackerOne · $0 · ▲340
  > or in gdrive, if yt can't be seen yet : https://███████
- **Arbitrary Read of Another Users private repository without Authorization** — `#3124517` · GitHub · $10,000 · ▲276
  > [CVE-2025-8447](https://www.cve.org/cverecord?id=CVE-2025-8447)
- **Deleting all DMs on RedditGifts.com** — `#1213237` · Reddit · $5,000 · ▲267
  > Change cookies/csrf token and `4423007` to your own message ID
- **Insecure Direct Object Reference (IDOR) Allows Viewing Private Report Details via /bugs.json Endpoint** — `#2487889` · HackerOne · $0 · ▲266
  > idor lead to view private reports `title`,`url`,`id`,`state`,`substate`,`severity rating`,`readable substate`,`created at`,`submitted at`,`reporter name`
- **Singapore - Account Takeover via IDOR** — `#876300` · Starbucks · $0 · ▲260
  > ko2sec discovered that an alternate site shared database and cookie credentials with card.starbucks.com.sg.
- **Steal private objects of other projects via project import** — `#743953` · GitLab · $20,000 · ▲254
  > Many attributes (foreign key) like `issue ids` and `merge request ids` are not excluded during import.
- **IDOR: Account Deletion via Session Misbinding – Attacker Can Delete Victim Account** — `#3154983` · Mozilla · $0 · ▲244
  > A critical vulnerability in the Firefox Accounts API allows an authenticated attacker to permanently delete any user's account by sending a `POST /v1/account/destroy` request using attacker session, but including the victim’s `email` and `authPW` (password…
- **Insecure redirect rule results in bypassing ban redirect on certain pages** — `#703058` · Roblox · $0 · ▲233
  > This allows us to access any pages ending in `.aspx/.ashx` without a ban-redirect, just by appending `/membership/` after the extension.
- **An IDOR that can lead to enumeration of a user and disclosure of email and phone number within cashier** — `#1966006` · Unikrn · $0 · ▲232
  > It was during the https://cashier.unikrn.com/cashier/transaction-history session handshake where we found out you could actually get access to another customer's data.
- **IDOR delete any Tickets on ads.tiktok.com** — `#1475520` · TikTok · $0 · ▲216
  > An IDOR (Insecure Direct Object Reference) vulnerability was found on TikTok ads, through the "draft order id" parameter which could have allowed an attacker to delete the support tickets of other users.
- **I.D.O.R To Order,Book,Buy,reserve On YELP FOR FREE (UNAUTHORIZED USE OF OTHER USER'S CREDIT CARD)** — `#391092` · Yelp · $0 · ▲214
  > @hk755a found an Insecure Direct Object Reference (IDOR) Vulnerability that allowed an attacker to pay with someone else's registered credit card, while ordering food with Grubhub through the `/checkout/transaction platform` endpoint.
- **IDOR vulnerability in unreleased HackerOne Copilot feature** — `#2218334` · HackerOne · $0 · ▲210
  > After creating a new conversation, look for `"operationName":"NewConversation",` graphql request in your `Proxy History` and store somewhere the value of `data.newConversation.llm conversation.id` from the response.
- **IDOR allows an attacker to modify the links of any user** — `#1661113` · Reddit · $0 · ▲208
  > - In the next request you have to put in the request body, in the "id" parameter the previously saved id, you can also change the name and the link:
- **IDOR when editing users leads to Account Takeover without User Interaction at CrowdSignal** — `#915114` · Automattic · $0 · ▲202
  > If you click `Edit` button on any user of your team at https://app.crowdsignal.com/users/list-users.php, you will send a GET request to `https://app.crowdsignal.com/users/invite-user.php?id=(userid)&popup=1`
- **IDOR on GraphQL queries BillingDocumentDownload and BillDetails** — `#2207248` · Shopify · $5,000 · ▲187
  > An IDOR on the `BillingInvoice` id on both `BillingDocumentDownload` and `BillDetails` graphql operations are leaking other merchants' ██████:
- **IDOR Vulnerability at AddTagToAssets operation name** — `#2633771` · HackerOne · $0 · ▲178
  > You will obtain a request whose the operationName: `AddTagToAssets` and contains `tagId` parameter which has a base64 cipher text within
- **IDOR leads to Edit Anyone's Blogs / Websites** — `#974222` · Automattic · $0 · ▲177
  > Go to `https://www.intensedebate.com/edit-user-profile`, again and click `Save Settings` button open burp suite and change `hidBlogID` parameter with victim's `hidBlogID`.
- **Unauthorized Access to TikTok Account [Private Videos] via API Endpoint** — `#2868084` · TikTok · $0 · ▲167
  > A vulnerability on a TikTok endpoint was found that could have resulted in unauthorized viewing of videos from private accounts.
- **Getting access of mod logs from any public or restricted subreddit with IDOR vulnerability** — `#1658418` · Reddit · $5,000 · ▲163
  > + If it's true then there are more logs and we can get them by just adding new variable after and assigning value of endCursor , which we can see in the reponse body of our request {F1851533}
- **Unreleased CTF Levels are Revealed on /group/user/ID1?user=USERID endpoint** — `#536853` · HackerOne · $0 · ▲161
  > However, an IDOR at the https://ctf.hacker101.com/group/user/ID1?user=USERID endpoint reveals them (see attached screenshot)
- **Email change or personal data change on the account.** — `#1250037` · Stripe · $3,000 · ▲149
  > @dk82hg found the email change flow on indiehackers.com was vulnerable to an insecure direct object reference (IDOR) which allowed an attacker to change the email associated with a user account to one they owned and ultimately take over a victim’s account in…
- **Disclose Hidden Comments on Media Section of hub.vroid.com** — `#2541962` · pixiv · $500 · ▲149
  > From UserAttacker, intercept any POST request made to https://hub.vroid.com/ and send it to the repeater
- **Importing GitLab project archives can replace uploads of other users** — `#534794` · GitLab · $0 · ▲148
  > Note that the request was for the `/root/new project/uploads/ed5ab56bc85699117ba230eb799fd3bf/indi.jpg` file, however the file from the `test/modified project` was served.
- **IDOR vulnerability (Price manipulation)** — `#1403176` · Acronis · $0 · ▲146
  > 2.buy any product in this case i am going to buy this https://www.acronis.cz/produkt/acronis-cyber-protect-home-office/ for test
- **Applicant security exam Attachments/Documents accessible through an IDOR/BAC on the custom Apex controller on https://█████.mil** — `#2950536` · U.S. Dept Of Defense · $0 · ▲142
  > These are highly predictable: example methodology/script here: https://blog.hypn.za.net/2022/11/12/Hacking-Salesforce-backed-WebApps/.
- **Missing ownership check on remote wipe endpoint** — `#819807` · Nextcloud · $500 · ▲141
  > Forward with burpsuite and in the url that looks like settings/personal/authtokens/wipe/{data-id}, change the data-id to the id of the device of the victim
- **IDOR and statistics leakage in Orders** — `#544329` · X / xAI · $289 · ▲141
  > Twitter on its service "MoPub" statistics dedicated to the results of "Order", after the test shows that the endpoint "https://app.mopub.com/web-client/api/orders/stats/query" is infected with a "IDOR " bug

## Payload fragments observed

Recurring payloads from this class's writeups. Adapt, don't paste blindly.

| Seen | Fragment |
|---:|---|
| 4× | `MembershipRequest::getMembership()` |
| 4× | `link()` |
| 3× | `victim@email.com` |
| 3× | `MembershipService::getMembership()` |
| 2× | `Move to > My Content` |
| 2× | `application%5Bid%5D` |
| 2× | `curl --request POST \ / --url 'https://gitlab.domain.com/api/v4/projects/<ATTACKID>/merge_requests/1/status_check_responses?sha=<SHA>&extern` |
| 2× | `/BugReport/Admin/Attachment/{id}` |
| 2× | `attacker@email.com` |
| 2× | `{attacker-email}` |
| 2× | `curl -X GET "http://localhost:8080/ocs/v2.php/apps/circles/link/r2gmJl8n5xKWecQaVYe1dP3h6nqIUDk/ovYvboLMBNGvRXSkqhgllIKo6T7fvZl" \ / -H "OCS` |
| 2× | `getMembership()` |
| 2× | `LocalController::link()` |
| 1× | `POST /reports/[TEST_REPORT_ID]/reference.json HTTP/2 / Host: hackerone.com / Cookie: [your session cookie] / Content-Type: application/json` |
| 1× | `/reports/{id}/reference.json` |
| 1× | `/reports/{report_id}/reference.json` |
| 1× | `https://app.crowdsignal.com/users/invite-user.php?id=(userid)&popup=1` |
| 1× | `<PUT_VICTIM_EMAIL_HERE>` |
| 1× | `exmaple: GET /api/v1/users/@hasn0xxxx` |
| 1× | `GET /attachments/938540538 HTTP/1.1 / X-Signal-Agent: OWA / Accept-Encoding: gzip, deflate / X-Client-Version: BCM Android/5.1 Model/generic` |

## Parameters observed

`id` · `type` · `action` · `message` · `userId` · `Password` · `aura.context` · `aura.pageURI` · `aura.token` · `file` · `domain` · `PID` · `RNo` · `time_range` · `accounts` · `passChange` · `__RequestVerificationToken` · `ConfirmPassword` · `export_columns` · `start`

## Case studies

### Delete anyone's content spotlight remotely.
`#1819832` · Snapchat · $15,000 · high · 2023-03-06 · ▲801
> Hello Snapchat, Snapchat has viral video feature callled spotlight which alone was the biggest trend and increase snapchat users and profit in millions. I found a way to delete anyone's spotlight remotely. Please see the below poc:- 1. First go to https://my.snapchat.com/myposts and log in there. 2. You will see your posts . 3. Now turn burp suite and intercept. 4.Select any of your posts and click delete option. 5. Now capture the delete request.

### IDOR to add secondary users in www.paypal.com/businessmanage/users/api/v1/users
`#415081` · PayPal · $10,500 · high · 2019-07-30 · ▲797
> PayPal Business Accounts allow account owners to create multiple secondary users with specific privileges assigned to their employees. This submission identified a method that made it possible for a Business Account owner to assign secondary users from other accounts. The new secondary user would be granted access to the login allowing for unauthorized access to the functions of that single user login.

### How the Bug stole hacking
`#762510` · HackerOne · $0 · none · 2019-12-20 · ▲471
> In light of the season - here's a story I wrote for you: Impact Happy Holidays and thanks for all you do. <3

### IDOR - Delete all Licenses and certifications from users account using CreateOrUpdateHackerCertification GraphQL query
`#2122671` · HackerOne · $0 · high · 2023-08-29 · ▲395
> Summary: Hey team, While editing our Licenses and certifications if we change the ID number we can delete other users Licenses and certifications . it simply can be done by editing the ID number in our graphql query. If change the ID from 1 to X possible range then we can delete all the Licenses and certifications present between these. Steps To Reproduce 1. Log in to your own account in two browsers A and B with User A and User B 2.

### IDOR allows user to access report details via reference.json endpoint
`#3862641` · HackerOne · $15,000 · critical · 2026-10-01 · ▲372
> Summary: An information disclosure vulnerability on the /reports/{id}/reference.json endpoint allowed VDP accounts created via hackerone.com/vdp-sign-up to access certain private report details. While the endpoint returned HTTP 422 "You do not have the appropriate access," the error response contained additional report details in the context.subject field.

## Wordlists

Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.

| File | Entries |
|---|---:|
| `~/.local/share/hackerone-reports/wordlists/paths_idor.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/params_idor.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |
| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |

```sh
W=~/.local/share/hackerone-reports/wordlists
ffuf -u https://target/FUZZ -w $W/paths_idor.txt \
     -mc all -fc 404 -fs 0 -rate 40
ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_idor.txt \
     -mr 'canary|error|invalid|not found' -rate 40
```

## Nuclei

Nuclei only finds exposed objects; the real work is cross-account replay with two identities.

```sh
nuclei -u https://target -tags idor,exposure \
       -severity low,medium,high,critical -rl 40 -o nuclei_idor.txt
nuclei -u https://target -t ~/nuclei-templates/http/exposures \
       -rl 40 -o nuclei_idor_exposures.txt
# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'
```

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

## Query the corpus

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class idor --limit 20
python3 ~/.local/share/hackerone-reports/h1.py stats --class idor
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```

Search by technology, endpoint, parameter, or program. Examples:

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class idor
python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class idor --min-bounty 1000
```

## Related

- `hackerone-authz-bypass` (1,386 reports)
- `hackerone-info-disclosure` (1,827 reports)
- `hackerone-graphql` (79 reports)

## Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.
