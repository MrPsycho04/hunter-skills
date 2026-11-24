---
name: hackerone-logic-and-design
description: >-
  Hunt business logic abuse and secure-design violations. Use when testing payments, coupons, refunds, quotas, workflows, approvals, or state machines. Backed by 931 disclosed HackerOne reports.
---

# Business Logic & Design Flaws — HackerOne field guide

Built from **931** publicly disclosed HackerOne reports (2014–2026). Corpus: `~/.local/share/hackerone-reports/`.

## Signal

- Reports: **931** · paid: **134**
- Median bounty **$500** · p90 **$2,400** · max **$12,000** · total **$134,498**
- Median upvotes **10**

## Where it pays

| Program | Reports | Bounty | Upvotes |
|---|---|---|---|
| HackerOne | 101 | $17,000 | 4218 |
| GitLab | 9 | $15,320 | 508 |
| Internet Bug Bounty | 12 | $12,960 | 136 |
| Coinbase | 11 | $11,100 | 851 |
| Valve | 3 | $10,000 | 615 |
| Mail.ru | 18 | $7,507 | 628 |
| Augur | 2 | $7,000 | 54 |
| Reddit | 5 | $5,500 | 357 |

## Quick wins

Start here. These are the highest-yield tests for this class.

- Model the intended state machine, then skip/reorder/replay steps.
- Test negative values, zero, decimals, rounding, and currency confusion in money flows.
- Replay one-time actions: coupons, invites, refunds, withdrawals, votes, trials.
- Check seat/limit counting and plan changes for proration and cancellation abuse.
- Look for trust in client-supplied price, role, plan, timestamp, or status.

## Payloads & probes

- Quantity -> `-1`, `0`, `0.001`, `1e9`, `NaN`, very long decimals
- Price -> change `price=100` to `price=1`, remove the field, send array
- State -> `status=approved`, `paid=true`, `step=3` out of order
- Race -> parallel redeem of the same coupon/withdrawal

## Bypass tricks

- Skip payment by calling the fulfillment endpoint directly.
- Abuse currency/rounding with fractional quantities.
- Reuse idempotency keys or omit them.
- Exploit trial reset via email aliases, domains, or deleted accounts.

## Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`quantity` `price` `amount` `coupon` `discount` `plan` `trial` `refund` `withdraw` `balance` `limit` `seat`

## Tools

`Burp` · `Turbo Intruder` · `custom scripts` · `mitmproxy`

## Escalation chains

- Logic flaw -> free goods/credit.
- Limit bypass -> resource abuse.
- Refund abuse -> financial loss.

## Deeper checklist

- Model the intended workflow and state machine; look for steps that can be skipped, replayed, or reordered.
- Test quantity/price/tax manipulation, negative values, rounding, and currency confusion.
- Replay one-time actions: coupons, invites, refunds, withdrawals, votes, trials.
- Race critical actions and check idempotency (see race-condition skill).
- Test boundary values and overflow in balances, limits, and counters.
- Abuse trial/plan changes: downgrade/upgrade, proration, seat counting, cancellation.
- Look for trust in client-supplied state (price, role, plan, feature flags, timestamps).
- Show concrete financial or access impact, not just unexpected behavior.

## Techniques from real reports

One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.

- **Modify in-flight data to payment provider Smart2Pay** — `#1295844` · Valve · $7,500 · ▲443
  > For example, we can change original `Amount=2000` to `Amount2=000` and after contacting it still will be `Amount2000`
- **H1514 Ability to MiTM Shopify PoS Session to Takeover Communications** — `#423467` · Shopify · $0 · ▲372
  > The code actually specifically listens on all local interfaces (`0.0.0.0`) and the wifi network address is specifically used in the QR code connection string, as shown here in…
- **Hackerone is not properly deleting user id** — `#1133118` · HackerOne · $0 · ▲356
  > Optional: Supporting Material/References (Screenshots)
- **Getting New Invitations without Leaving Programs** — `#999789` · HackerOne · $0 · ▲322
  > Yesterday, I sent about 25-30 request with different private programs and I asked `how much pending invitations do I have?` to `support@hackerone.com` and they said `It looks like you currently have 19 pending invitations at this time.`.
- **Race Condition allows to redeem multiple times gift cards which leads to free "money"** — `#759247` · Reverb.com · $0 · ▲308
  > - Now set the external HTTP header `x-request: %s` - This is needed by the turbo intruder
- **An attacker can run pipeline jobs as arbitrary user** — `#894569` · GitLab · $12,000 · ▲307
  > - Go to `Project settings` = `Repository` = `Mirroring repositories`
- **Ethereum account balance manipulation** — `#300748` · Coinbase · $0 · ▲276
  > https://www.vicompany.nl/magazine/from-christmas-present-in-the-blockchain-to-massive-bug-bounty
- **An attacker can buy marketplace articles for lower prices as it allows for negative quantity values leading to business loss** — `#771694` · Semrush · $0 · ▲267
  > When someone goes to https://www.semrush.com/marketplace/offers/ and orders for articles, an attacker can pay for less than intended due to negative quantities being allowed.
- **Fee discounts can be redeemed many times, resulting in unlimited fee-free transactions** — `#1849626` · Stripe · $5,000 · ▲266
  > So, I used Burp Turbo Intruder to race the request that accepts the fee discount, `/ajax/accept fee discount offer` (forgot to take screenshot as I did not think it would work!).
- **Change phone number OTP flaw leads to any phone number takeover** — `#2588329` · inDrive · $2,000 · ▲241
  > When an user requests a phone number change inside the app, it will send a 4 digit code but if you place 0000, it will accept any number and update it into the app!!
- **[www.zomato.com] Availing Zomato Gold membership for free by tampering plan id(s)** — `#511044` · Eternal · $0 · ▲229
  > POST █████████useragent=model iPad os 9.3.5 v 13.1.9 t iPad&app version=13.1.9&push permission=0&session id=7&app run id=1&lang=en&presentlon=77.70730672359205&uuid=YOUR UUID
- **Config override using non-validated query parameter allows at least reflected XSS by injecting configuration into state** — `#1082847` · Superhuman (formerly Grammarly) · $0 · ▲223
  > The issue is that the code on `app.grammarly.com` allows a `?config=`-parameter to be used:
- **ETH contract handling errors** — `#328526` · Coinbase · $0 · ▲208
  > In addition, the code did not appropriately handle `delegatecall` within a contract.
- **Able to approve admin approval and change effective status without adding payment details .** — `#1543159` · Reddit · $5,000 · ▲191
  > Go to https://ads.reddit.com/dashboard, you will see a table list that shows your ads and campaign , there the status is stated as PENDING .
- **Account creation with invalid email addresses / email is accepting % and %0d%0a line termination chars** — `#815085` · HackerOne · $3,750 · ▲176
  > Email address parameter is accepting % and %0d%0a character along with genuine email address.
- **OLO Total price manipulation using negative quantities** — `#364843` · Upserve · $0 · ▲167
  > Manipulating an order request JSON object, containing an additional item with a negative quantity directly manipulates the total amount of the order.
- **2-factor authentication can be disabled when logged in without confirming account password** — `#783258` · Localize · $0 · ▲159
  > Go to repeater and make a POST request to `https://localizestaging.com/api/user/two-factor/set` also Paste the header here.
- **Takeover of Twitter-owned domain at mobileapplinking.com** — `#321699` · X / xAI · $0 · ▲159
  > The site is currently registered under my github pages account, as can be seen at mobileapplinking.com/takeover
- **Client-Side Race Condition using Marketo, allows sending user to data-protocol in Safari when form without onSuccess is submitted on www.hackerone.com** — `#381356` · HackerOne · $0 · ▲154
  > However, if the `onSuccess` doesn't exist or returns `true`, the parameter called `followUpUrl` will instead be sent to `location.href`.
- **Steal collateral during `end` process, by earning DSR interest after `flow`.** — `#672664` · BlockDev Sp. Z o.o · $0 · ▲152
  > the `pot` contract, and not allowing the `pot.drip` method to be called when
- **Access Token Smuggling from my.playstation.com via Referer Header** — `#835437` · PlayStation · $1,000 · ▲147
  > `https://docs.playstation.com/consumers/auth/psn oauth2/callback?code=${code}&state=${state}&cid=${cid}`
- **Bypassing CORS Misconfiguration Leads to Sensitive Exposure** — `#768151` · U.S. Dept Of Defense · $0 · ▲145
  > 2) If you add the ``Origin-parameter`` to the ``Request-header``, the responsive header will reject
- **Bypassing HackerOne 2FA due to race condition** — `#2598548` · HackerOne · $0 · ▲139
  > When a user canceled one reset request, the remaining requests would stay active, potentially leading to unauthorized 2FA removal after 24 hours.
- **Business Logic Error – Bypass of OTP Verification During Signup on hover.com** — `#3255473` · Tucows (VDP) · $0 · ▲135
  > By omitting the code parameter entirely from the signup request, the backend completes the registration and returns a valid session.
- **Add upto 10K rupees to a wallet by paying an arbitrary amount** — `#1408782` · Eternal · $2,000 · ▲132
  > The amount requested to generate the `order id - XXXX` was `1000` but while paying one could have passed an arbitrary amount instead of `1000` against the `order id`, which was not cross-checked.
- **Able to manipulate order amount by removing cancellation amount and cause financial impact** — `#614523` · Eternal · $0 · ▲130
  > - Select payment method and intercept the request, change the cancellation amount parameter to 0, it will reduce the order amount and cancel all the previous cancellation charges on that account.
- **Exploitable live argument in onClick Function leads to Data Leakage of Inactive/Suspended Products** — `#2295958` · TikTok · $1,000 · ▲129
  > where's `onClick` is a function assigned to an event and then within the `onClick` function, the `Fa()` function is called with three arguments: `self-promotion, live, and live dashboard.` This function call is used for some live shopping ads.
- **Email Verification bypass on signup** — `#1040047` · Automattic · $0 · ▲127
  > See the burp suite proxy tab and find the GET request to this endpoint [https://public-api.wordpress.com/rest/v1.1/sites/siteId here/invites?http envelope=1&status=all&number=100] [there will be a number instead of siteId here]
- **Non-premium user can disable Ads in japanese version of dic.pixiv.net** — `#3183520` · pixiv · $3,000 · ▲123
  > Intercept any request to `dic.pixiv.net` that includes your cookies
- **Any user could upload attachments to pentest scoping form they don't have access to** — `#2450215` · HackerOne · $0 · ▲121
  > ====================================================================================================================

## Payload fragments observed

Recurring payloads from this class's writeups. Adapt, don't paste blindly.

| Seen | Fragment |
|---:|---|
| 7× | `Curl_httpsrr_applicable()` |
| 6× | `security@` |
| 6× | `(all)` |
| 5× | `wallet2::sign_tx(unsigned_tx_set &...)` |
| 5× | `gtsatsis@staff.ratelimited.me` |
| 5× | `hostmatch()` |
| 4× | `conn->ssl_config` |
| 4× | `$.extend` |
| 3× | `data:` |
| 3× | `__proto__` |
| 3× | `get_peer_type()` |
| 3× | `ossl_verifyhost()` |
| 3× | `conn_config->CRLfile` |
| 3× | `cr_init_backend()` |
| 2× | `x-request: %s` |
| 2× | `javascript:` |
| 2× | `%00` |
| 2× | `master @ 3ad4a5ee8` |
| 2× | `tester@test.com` |
| 2× | `h1test@example.com` |

## Parameters observed

`url` · `email` · `returnRoute` · `client_id` · `callback_url` · `signature` · `name` · `config` · `requestID` · `callback` · `source` · `load` · `amount` · `lang` · `baseUrl` · `targetOrigin` · `type` · `key` · `all_results` · `html`

## Case studies

### Modify in-flight data to payment provider Smart2Pay
`#1295844` · Valve · $7,500 · critical · 2021-08-10 · ▲443
> I have found vulnerability which allows attacker to generate steam wallet balance. Firstly you will have to change yours steam account email to something like (I will explain why in next steps, amount100 is the important part): brixamount100abc@█████ Then go to https://store.steampowered.com/steamaccount/addfunds and click add add funds. Proceed to payment and select any payment which uses Smart2Pay payment method (przelewy24 in my country).

### H1514 Ability to MiTM Shopify PoS Session to Takeover Communications
`#423467` · Shopify · $0 · medium · 2019-11-04 · ▲372
> Hi @iv-rodriguez, After a decent amount more digging and research, I must disagree with you on the "expecting to work offline" portion. The code actually specifically listens on all local interfaces (0.0.0.0) and the wifi network address is specifically used in the QR code connection string, as shown here in com.shopify.pos.customerview.server.CustomerViewWebSocketServer::getConnectionString() in the com.shopify.pos app: This can also be seen from netstat…

### Hackerone is not properly deleting user id
`#1133118` · HackerOne · $0 · medium · 2021-06-11 · ▲356
> Summary: Long ago, i had an account on hackerone that is now deleted. I used the alias email provided by h1 to sigbup on a site for bug testing. To my surprise, i receive an email to my account routed from an alias email that should not exist. Description: Steps To Reproduce 1. SignUp on H1 2. Use h1 alias email to signup on some website 3.

### Double Payout via PayPal
`#307239` · Coinbase · $10,000 · critical · 2018-04-04 · ▲324
> An issue with the handling of the PayPal transaction states resulted in a user being able to both withdraw money from PayPal, but not have the funds deducted from their account.

### Getting New Invitations without Leaving Programs
`#999789` · HackerOne · $0 · low · 2020-10-15 · ▲322
> When you leave the private program, you get a chance to get a new invitation. But using this vulnerability, I can get new invitations without leaving private programs. Steps: 1. Go to any private bug bounty program. 2. Click Leave Program button 3. Click Confirm button 4. Then you will see a questionnaire form. You can see this text: When you fill out this questionnaire, we will fast track you for the next invite batch. {F1022548} 5.

## Wordlists

Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.

| File | Entries |
|---|---:|
| `~/.local/share/hackerone-reports/wordlists/paths_logic-and-design.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/params_logic-and-design.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |
| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |

```sh
W=~/.local/share/hackerone-reports/wordlists
ffuf -u https://target/FUZZ -w $W/paths_logic-and-design.txt \
     -mc all -fc 404 -fs 0 -rate 40
ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_logic-and-design.txt \
     -mr 'canary|error|invalid|not found' -rate 40
```

## Nuclei

No scanner finds business-logic flaws. Use Nuclei for recon, then model the workflow manually.

```sh
nuclei -u https://target -tags vuln,exposure \
       -severity low,medium,high,critical -rl 40 -o nuclei_logic-and-design.txt
nuclei -u https://target -t ~/nuclei-templates/http/exposures \
       -rl 40 -o nuclei_logic-and-design_exposures.txt
# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'
```

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

## Query the corpus

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class logic-and-design --limit 20
python3 ~/.local/share/hackerone-reports/h1.py stats --class logic-and-design
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```

Search by technology, endpoint, parameter, or program. Examples:

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class logic-and-design
python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class logic-and-design --min-bounty 1000
```

## Related

- `hackerone-race-condition` (97 reports)
- `hackerone-authz-bypass` (1,386 reports)
- `hackerone-dos` (66 reports)

## Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.
