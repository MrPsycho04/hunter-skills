---
name: hackerone-race-condition
description: >-
  Hunt race conditions and TOCTOU. Use when testing coupons, withdrawals, invites, limits, and multi-step state changes. Backed by 97 disclosed HackerOne reports.
---

# Race Conditions / TOCTOU — HackerOne field guide

Built from **97** publicly disclosed HackerOne reports (2015–2026). Corpus: `~/.local/share/hackerone-reports/`.

## Signal

- Reports: **97** · paid: **18**
- Median bounty **$510** · p90 **$5,000** · max **$15,250** · total **$37,946**
- Median upvotes **26**

## Where it pays

| Program | Reports | Bounty | Upvotes |
|---|---|---|---|
| Shopify | 4 | $15,750 | 394 |
| Internet Bug Bounty | 7 | $8,960 | 113 |
| Cosmos | 1 | $5,000 | 61 |
| Tools for Humanity | 1 | $3,000 | 95 |
| InnoGames | 1 | $2,000 | 137 |
| Mail.ru | 4 | $1,000 | 116 |
| Pornhub | 1 | $520 | 13 |
| HackerOne | 11 | $500 | 1136 |

## Quick wins

Start here. These are the highest-yield tests for this class.

- Identify check-then-act flows: balance, quota, coupon, invite, vote, refund.
- Fire parallel requests with last-byte sync or HTTP/2 single-packet attack.
- Test idempotency keys and database constraints.
- Look for partial-state windows in multi-step workflows.

## Payloads & probes

- Single-packet attack: 20-30 requests in one HTTP/2 packet
- Last-byte sync: hold final byte, release together
- Repeat the same coupon/withdrawal across parallel connections

## Bypass tricks

- Bypass rate limits by racing before the counter commits.
- Use different sessions/accounts to hit shared resources.
- Combine with limit/refund logic for financial impact.

## Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`coupon` `withdraw` `transfer` `invite` `vote` `refund` `balance` `quota` `limit`

## Tools

`Burp Turbo Intruder` · `race-the-web` · `custom scripts`

## Escalation chains

- Race -> double spend.
- Race -> multiple invites/rewards.
- Race -> limit bypass.

## Deeper checklist

- Identify check-then-act flows: balance, quota, coupon, invite, vote, refund.
- Fire parallel requests with last-byte sync or HTTP/2 single-packet attack.
- Test idempotency keys and database constraints for bypass.
- Look for partial-state windows in multi-step workflows.
- Measure the resulting over-spend/over-claim precisely.
- Keep request volume controlled and reproducible.

## Techniques from real reports

One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.

- **Race Condition allows to redeem multiple times gift cards which leads to free "money"** — `#759247` · Reverb.com · $0 · ▲308
  > - Now set the external HTTP header `x-request: %s` - This is needed by the turbo intruder
- **Ability to bypass partner email confirmation to take over any store given an employee email** — `#300305` · Shopify · $15,250 · ▲273
  > Visit `https://partners.shopify.com/[ID]/managed stores`, add the store, and you now have access.
- **Race condition in performing retest allows duplicated payments** — `#429026` · HackerOne · $0 · ▲240
  > Right click the request in Burp Suite and select `Copy as curl command`.
- **Client-Side Race Condition using Marketo, allows sending user to data-protocol in Safari when form without onSuccess is submitted on www.hackerone.com** — `#381356` · HackerOne · $0 · ▲154
  > However, if the `onSuccess` doesn't exist or returns `true`, the parameter called `followUpUrl` will instead be sent to `location.href`.
- **Race Condition leads to undeletable group member** — `#604534` · HackerOne · $0 · ▲153
  > - Join using the invitation link on the second account and intercept the request:
- **Bypassing HackerOne 2FA due to race condition** — `#2598548` · HackerOne · $0 · ▲139
  > When a user canceled one reset request, the remaining requests would stay active, potentially leading to unauthorized 2FA removal after 24 hours.
- **Race Conditions in Popular reports feature.** — `#146845` · HackerOne · $0 · ▲125
  > POST https://hackerone.com/reports/127158/votes HTTP/1.1
- **Race Condition when following a user** — `#927384` · Staging.every.org · $0 · ▲113
  > Right click to follow request, click `Send to turbo intruder` and drop the request
- **Race Condition : Exploiting the loyalty claim https://xxx.vendhq.com/loyalty/claim/email/xxxxx url and gain x amount of loyalty bonus/cash** — `#331940` · Vend VDP · $0 · ▲96
  > https://support.vendhq.com/hc/en-us/articles/201382810-Setting-Up-and-Using-Loyalty-in-Vend redeem
- **Race Condition Enables Bypassing Verification Check** — `#2110030` · Tools for Humanity · $3,000 · ▲95
  > This ensures that only one successful request per nullifier use can occur, even if parallel requests are attempted simultaneously.
- **Race Condition in Flag Submission** — `#454949` · HackerOne · $0 · ▲94
  > To the PoC I used "Race The Web", available at: https://github.com/insp3ctre/race-the-web
- **Race condition on add 1 free domain** — `#2616045` · Automattic · $0 · ▲93
  > When a website/provider provide free account they will give the user some feature that limited from access, but if we using race condition vulnerability an user can create/bypass limitation from the provider
- **Race Condition of Transfer data Credits to Organization Leads to Add Extra free Data Credits to the Organization** — `#974892` · Helium · $250 · ▲74
  > then click transfer and make sure you see the HTTP Request of "https://console.helium.com/api/data credits/transfer dc" in popup example below
- **Race condition in joining CTF group** — `#1540969` · HackerOne · $500 · ▲72
  > A race condition in `https://ctf.hacker101.com/group/join` allows a user to join the same CTF group multiple times.
- **Email Verification Bypass via Race Condition** — `#3020733` · Malwarebytes · $0 · ▲70
  > An email verification bypass vulnerability was discovered in the my.malwarebytes.com.
- **Exceed the maximum number of subscribers using Race Condition** — `#3221185` · SingleStore · $0 · ▲70
  > By sending multiple concurrent POST requests to the CreateAlertReceivers endpoint with different email addresses, an unlimited number of subscribers could be added despite the UI displaying a restriction message.
- **Session works after logout from Shopify account** — `#340191` · Shopify · $0 · ▲69
  > @Cryptographer reported if a logout request for a given session was received during the time a product creation request was in progress from the same session, it was possible the logout request could fail.
- **Race Condition in Folder Creation Allows Bypassing Folder Limit** — `#3104355` · Dust · $0 · ▲65
  > This vulnerability allows users to bypass the folder creation limit by sending multiple requests at the same time.
- **Exceeding the limit of Workspaces via Race Condition** — `#3226838` · SingleStore · $0 · ▲62
  > Reporter 4x4 discovered a race condition vulnerability in backend.singlestore.com that allowed free-tier users to bypass the 5-workspace limit by sending multiple simultaneous CreateWorkspace requests, enabling unlimited workspace creation and potential…
- **Race condition in faucet when using starport** — `#1438052` · Cosmos · $5,000 · ▲61
  > https://github.com/tendermint/starport/blob/develop/starport/pkg/cosmosfaucet/transfer.go L59
- **Race Condition on "Get free Badoo Premium" which allows to get more days of free premium for Free.** — `#1037430` · Bumble · $0 · ▲57
  > Before clicking `Get free Badoo Premium` turn intercept On in your burp suite and then click `Get free Badoo Premium` intercept this `POST /webapi.phtml?SERVER PROMO ACCEPTED ` select any parameter value right click send it to turbo inturer.
- **Promotion code can be used more than redemption limit.** — `#1717650` · Stripe · $0 · ▲55
  > In both payment links, Fill the form and apply coupon but don't hit Pay/ Subscribe.
- **Race condition in claiming program credentials** — `#488985` · HackerOne · $0 · ▲54
  > and I then sent this request to burp suite intruder and got 22 responses , 21 of them had the same response as this:
- **Race Conditions in OAuth 2 API implementations** — `#55140` · Internet Bug Bounty · $0 · ▲52
  > According to [OAuth 2.0 RFC](https://tools.ietf.org/html/rfc6749), `code` obtained via callback may be used only once to generate `access token` (and corresponding `refresh token`).
- **Race condition leads to add more than 5 email at Data breaches monitor system at https://stage.firefoxmonitor.nonprod.cloudops.mozgcp.net** — `#1913309` · Mozilla · $0 · ▲50
  > Visit https://stage.firefoxmonitor.nonprod.cloudops.mozgcp.net/user/settings - add email and see you can add only 5 email
- **Race condition while removing the love react in community files.** — `#996141` · Figma · $150 · ▲45
  > While logically one person is only allowed to remove the one like they had, a hundred requests at the same time could allow one person to do a hundred unlikes.
- **Race Condition on Create API Function** — `#2682392` · Enjin · $0 · ▲45
  > @mo salah12 was able to demonstrate a race condition that allowed user's to submit multiple requests within rapid succession to allow creating additional keys beyond the defined limit on the Enjin Platform Cloud service.
- **Timeout-based race conditions make Uint8Array/Buffer.alloc non-zerofilled** — `#3405778` · Node.js · $0 · ▲43
  > Under specific timing conditions, buffers allocated with `Buffer.alloc` and other `TypedArray` instances like `Uint8Array` may contain leftover data from previous operations, allowing in-process secrets like tokens or passwords to leak or causing data…
- **Race Condition in Redeeming Coupons** — `#157996` · Instacart · $0 · ▲43
  > Intercept the request using a proxy, and make the request multiple times, asynchronously.
- **curl --skip-existing has a TOCTOU race that lets a post-check symlink redirect the later download write** — `#3747959` · curl · $0 · ▲42
  > In the strongest real-world case, this means a local attacker can wait for a privileged or automated curl job that uses `--skip-existing` in `/tmp`, a shared workspace, or another attacker-writable directory, then create the symlink after curl has already…

## Payload fragments observed

Recurring payloads from this class's writeups. Adapt, don't paste blindly.

| Seen | Fragment |
|---:|---|
| 9× | `Curl_dnscache_add_negative()` |
| 5× | `Curl_dnscache_add()` |
| 5× | `std::fs::remove_dir_all()` |
| 5× | `Curl_fopen()` |
| 4× | `Curl_hash_add()` |
| 4× | `Curl_hsts_save()` |
| 3× | `data:` |
| 3× | `stat()` |
| 3× | `dnscache_lock()` |
| 3× | `dnscache_add_addr()` |
| 3× | `Curl_hsts_parse()` |
| 3× | `curlx_gmtime()` |
| 3× | `Curl_close()` |
| 2× | `x-request: %s` |
| 2× | `Buffer.from()` |
| 2× | `share->cookies` |
| 2× | `remove_dir_all()` |
| 2× | `hsts_out()` |
| 2× | `--hsts <file>` |
| 1× | `https://sandbox.reverb.com/<lang>/redeem` |

## Parameters observed

`client_id` · `redirect_uri` · `code` · `invite` · `client_secret` · `token` · `commit` · `response_type` · `term` · `raw_json` · `id` · `authenticity_token` · `search` · `new` · `dl` · `access_token` · `refresh_token` · `defid` · `direction` · `key`

## Case studies

### Race Condition allows to redeem multiple times gift cards which leads to free "money"
`#759247` · Reverb.com · $0 · high · 2020-01-25 · ▲308
> Hello team! I've found a Race Condition vulnerability which allows to redeem gift cards multiple times. This how a s/he can easily buy stuff just bying one gift card and redeem it over and over again. Steps to reproduce Preparations - Burp Suite Pro - Turbo Intruder Note: This also can be reproduced other way but this is maybe the easiest The attack - Login - Buy a gift card - Now redeem it at https://sandbox.reverb.com/ /redeem - Intercept the request…

### Ability to bypass partner email confirmation to take over any store given an employee email
`#300305` · Shopify · $15,250 · critical · 2018-02-07 · ▲273
> It's possible to take over any store account through partners given an employee email address. This is possible because I found a way to confirm arbitrary emails. I don't know the Shopify ecosystem well enough to know the other ramifications of such a bug.

### Race condition in performing retest allows duplicated payments
`#429026` · HackerOne · $0 · medium · 2018-12-27 · ▲240
> There exists a race condition in performing retests. By executing multiple requests to confirm a retest at the same time, a malicious user is paid multiple times for the retest. This allows for stealing money from HackerOne, which could go unnoticed by both HackerOne and the attacker (me).

### Client-Side Race Condition using Marketo, allows sending user to data-protocol in Safari when form without onSuccess is submitted on www.hackerone.com
`#381356` · HackerOne · $0 · low · 2019-04-05 · ▲154
> In this case however, I noticed that as soon as you submit a form, one of the listener being on www.hackerone.com will pass the content forward to a handler for the specific form that was loaded. As soon as it finds the form that was initiated and submitted, it will either run the error or success-function based on the content of the postMessage. If the message is a success, it will run any form.onSuccess being defined when the form was loaded.

### Race Condition leads to undeletable group member
`#604534` · HackerOne · $0 · low · 2020-03-20 · ▲153
> Hi, Summary: There exists a Race Condition in which the user can add themselves twice to a group which will make them unremovable from group. They themselves cannot remove themselves from the group as well as the group leader cannot remove that user from the group.

## Wordlists

Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.

| File | Entries |
|---|---:|
| `~/.local/share/hackerone-reports/wordlists/paths_race-condition.txt` | 61 |
| `~/.local/share/hackerone-reports/wordlists/params_race-condition.txt` | 36 |
| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |
| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |

```sh
W=~/.local/share/hackerone-reports/wordlists
ffuf -u https://target/FUZZ -w $W/paths_race-condition.txt \
     -mc all -fc 404 -fs 0 -rate 40
ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_race-condition.txt \
     -mr 'canary|error|invalid|not found' -rate 40
```

## Nuclei

No reliable scanner. Use Turbo Intruder single-packet or last-byte sync on check-then-act flows.

```sh
nuclei -u https://target -tags race-condition \
       -severity low,medium,high,critical -rl 40 -o nuclei_race-condition.txt
# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'
```

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

## Query the corpus

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class race-condition --limit 20
python3 ~/.local/share/hackerone-reports/h1.py stats --class race-condition
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```

Search by technology, endpoint, parameter, or program. Examples:

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class race-condition
python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class race-condition --min-bounty 1000
```

## Related

- `hackerone-logic-and-design` (931 reports)
- `hackerone-authz-bypass` (1,386 reports)

## Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.
