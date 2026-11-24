---
name: hackerone-account-takeover
description: >-
  Hunt account takeover chains. Use when combining auth, reset, OAuth, XSS, IDOR, or logic bugs into full account compromise. Backed by 262 disclosed HackerOne reports.
---

# Account Takeover — HackerOne field guide

Built from **262** publicly disclosed HackerOne reports (2014–2026). Corpus: `~/.local/share/hackerone-reports/`.

## Signal

- Reports: **262** · paid: **39**
- Median bounty **$1,500** · p90 **$10,500** · max **$35,000** · total **$144,138**
- Median upvotes **36**

## Where it pays

| Program | Reports | Bounty | Upvotes |
|---|---|---|---|
| GitLab | 2 | $37,450 | 1088 |
| HackerOne | 6 | $22,500 | 2145 |
| Uber | 6 | $21,000 | 787 |
| Mail.ru | 27 | $14,550 | 1730 |
| TikTok | 4 | $12,000 | 724 |
| Superhuman (formerly Grammarly) | 3 | $10,500 | 628 |
| Chaturbate | 2 | $8,000 | 67 |
| LY Corporation | 2 | $5,000 | 708 |

## Quick wins

Start here. These are the highest-yield tests for this class.

- Enumerate ATO primitives: reset, email change, OAuth linking, OTP, session fixation.
- Test email-change flows for missing verification, race, and token leakage.
- Look for reset-token leakage via Referer, host-header poisoning, and shared caches.
- Test account merging/linking and pre-registration takeover.

## Payloads & probes

- Host header -> `Host: evil.com` in reset request
- Email -> `victim@example.com` with unicode/plus/dot variants
- OAuth -> link attacker provider to victim email
- OTP -> brute force, reuse, response leakage

## Bypass tricks

- Chain XSS/CSRF/IDOR into the ATO path.
- Abuse email normalization and case sensitivity.
- Race the email-change confirmation.

## Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`reset` `email` `verify` `oauth` `link` `otp` `mfa` `session`

## Tools

`Burp` · `Turbo Intruder` · `interactsh`

## Escalation chains

- Reset poisoning -> ATO.
- XSS -> cookie theft -> ATO.
- OAuth link -> ATO.

## Deeper checklist

- Enumerate ATO primitives: password reset, email change, OAuth linking, OTP, session fixation.
- Test email-change flows for missing verification, race conditions, and token leakage.
- Look for reset-token leakage via Referer, host-header poisoning, and shared caches.
- Test account merging/linking and pre-registration takeover.
- Chain lower-severity bugs (XSS, CSRF, IDOR) into ATO.
- Demonstrate login to a victim account you control, with a clear step-by-step PoC.

## Techniques from real reports

One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.

- **Takeover an account that doesn't have a Shopify ID and more** — `#867513` · Shopify · $0 · ▲3006
  > Save your own staff page and copy the CURL request by using browser inspection
- **Account Takeover via Password Reset without user interactions** — `#2293343` · GitLab · $35,000 · ▲989
  > Forward the requests and you should get an email containing the reset link that was send to both emails (``victim@gmail.com`` and ``attacker@gmail.com``) .
- **Mass account takeovers using HTTP Request Smuggling on https://slackb.com/ to steal session cookies** — `#737140` · Slack · $0 · ▲870
  > The CLTE issue found on slackb.com is when the frontend server interprets the request sized using `Content-Length` and the backend server interprets the request using the `Transfer-Encoding: chunked` method.
- **Bypassing Digits origin validation which leads to account takeover** — `#129873` · X / xAI · $0 · ▲619
  > In short, the event origin is checked against Digits' origin in this line:`-1 !== this.config.get("sdk host").search(t.origin)`, which is the same as `-1 !== "https://www.digits.com".search(t.origin)`.
- **Request smuggling on admin-official.line.me could lead to account takeover** — `#740037` · LY Corporation · $0 · ▲565
  > The reporter identified a request smuggling issue on admin-official.line.me [(TE.CL-type).](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn) The reporter clearly illustrated the impact without putting our users at risk or…
- **Flickr Account Takeover using AWS Cognito API** — `#1342088` · Flickr · $0 · ▲440
  > The `access token` can be directly used against Amazon's AWS API, for instance using the [AWS Command Line Interface](https://docs.aws.amazon.com/cli/) tool:
- **Full account takeover** — `#314808` · Reverb.com · $0 · ▲412
  > Reverb ios application is not validating facebook `access token` on the server side in login api, which allows an attacker to hack all account using his own app access token.
- **[CSRF] TikTok Careers Portal Account Takeover** — `#1010522` · TikTok · $0 · ▲366
  > If you have any feedback, feel free to ping me at [Twitter](https://twitter.com/ lauritz ).
- **[cs.money] Open Redirect Leads to Account Takeover** — `#905607` · CS Money · $0 · ▲357
  > Open this url `https://auth.dota.trade/login?redirectUrl=https://cs.money///loving-turing-29a494.netlify.app%2523&callbackUrl=https://cs.money///loving-turing-29a494.netlify.app%2523` , the login url was gotten from `cs.money` index page button `sign in…
- **yelp.com XSS ATO (via login keylogger, link Google account)** — `#2010530` · Yelp · $0 · ▲324
  > This should be parsed as 1 cookie `a` with the value "`1 b=2`", but Yelp will parse it as 2 cookies `a` and `b`.
- **Change any Uber user's password through /rt/users/passwordless-signup - Account Takeover (critical)** — `#143717` · Uber · $0 · ▲312
  > Through the endpoint at /rt/users/passwordless-signup it is possible to change the password of any Uber user, given knowledge of their phone number (or by just enumerating phone numbers until one is found that is registered with Uber - not too hard given the…
- **Account takeover through the combination of cookie manipulation and XSS** — `#534450` · Superhuman (formerly Grammarly) · $0 · ▲292
  > Our payload will make a post request to gnar.grammarly.com/cookies to replace the gnar containerid with the second stage of our payload and the redirect the user to the vulnerable page.
- **[CRITICAL] 0-Click Account Takeover via Password Reset [AUTH-3243] /orchestrator/v1/password_reset/start** — `#2831902` · Remitly · $0 · ▲291
  > 4-----Intercept the HTTP request using a proxy tool like Burp Suite or OWASP ZAP when submitting the password reset request.
- **Insufficient OAuth callback validation which leads to Periscope account takeover** — `#110293` · X / xAI · $0 · ▲277
  > callback url = a/../../login?redirect after login=https://cards.twitter.com/card id
- **Ability to DOS any organization's SSO and open up the door to account takeovers** — `#976603` · Superhuman (formerly Grammarly) · $10,500 · ▲260
  > So if you have `myentity` as the legitimate entity, and an attacker sets their entity to `myentity[SPACE]` (with a space at the end); users attempting to authenticate into the legitimate `myentity` will technically authenticate against it, but then the…
- **Singapore - Account Takeover via IDOR** — `#876300` · Starbucks · $0 · ▲260
  > ko2sec discovered that an alternate site shared database and cookie credentials with card.starbucks.com.sg.
- **Mass Account Takeover at https://app.taxjar.com/ - No user Interaction** — `#1581240` · Stripe · $0 · ▲253
  > The vulnerability was caused by a leaked token in the delete invitation request feature and resolved by using the invitation ID instead of the token to look up the user’s invite when deleting an invitation.
- **Account takeover of existing HackerOne accounts through SCIM provisioning** — `#3178999` · HackerOne · $0 · ▲232
  > If the attacker with verified domain as `verified.com` adds a victim as `victim@ato.com` to Okta, with the username as `victim@ato.com` and email field as `victim@verifed.com`, the victim's email will be changed, AND no notification will be sent to the victim…
- **1 Click Account Takeover via Auth Token Theft on marketing.hostinger.com** — `#3081691` · hostinger · $0 · ▲219
  > This vulnerability poses a significant risk to Hostinger users, as it allows attackers to bypass authentication and gain unauthorized access to accounts with just one click.
- **Account Takeover in Periscope TV** — `#317476` · X / xAI · $0 · ▲213
  > When you login periscope.tv using twitter, and change the host header from `www.periscope.tv` to `attacker.com/www.periscope.tv`, the oauth redirect destination will be `attacker.com/www.periscope.tv`, thus allowing attacker to send the oauth authorize link…
- **IDOR when editing users leads to Account Takeover without User Interaction at CrowdSignal** — `#915114` · Automattic · $0 · ▲202
  > If you click `Edit` button on any user of your team at https://app.crowdsignal.com/users/list-users.php, you will send a GET request to `https://app.crowdsignal.com/users/invite-user.php?id=(userid)&popup=1`
- **Helpdesk Takeover at dmc.datastax.com** — `#759454` · DataStax · $0 · ▲195
  > On this page, https://dmc.datastax.com/hc/en-us I haven't made the page public, I'm attaching a screenshot of the webpage:
- **1 click Account takeover via deeplink in [com.kayak.android]** — `#1667998` · KAYAK · $0 · ▲173
  > https://fluidattacks.com/blog/account-takeover-kayak/
- **Account Takeover via Authentication Bypass in TikTok Account Recovery** — `#2443228` · TikTok · $12,000 · ▲172
  > I identified a critical vulnerability in one of TikTok's endpoints that permitted unauthorized changes to user accounts due to improper parameter handling.
- **SSRF in Autodesk Rendering leading to account takeover** — `#3024673` · Autodesk · $0 · ▲161
  > A server side request forgery (SSRF) vulnerability was found in Autodesk Rendering, which could have allowed an attacker to send a malicious link to a victim and gain control of their account while logged in.
- **Cache Deception Allows Account Takeover** — `#1698316` · Expedia Group Bug Bounty · $0 · ▲160
  > I'm able to extract user's session (HASESSIONV3) as it is disclosed in a cacheable page, allowing me to access the `ha.crumb` token located in `/traveler/profile/edit`
- **Hackerone supports accounts organitation takeover** — `#2798380` · HackerOne · $2,500 · ▲155
  > - In this case, HackerOne attempts to request SAML authentication, but you bypass it, allowing you to log in to other services like PullRequest.com under the affected company’s identity.
- **Account takeover - improper validation of jwt signature (with regards  to experiation date claim)** — `#1760403` · Linktree · $0 · ▲147
  > I was able to bypass validation by changing the expiration date to a date in the past.
- **Open Redirect on central.uber.com allows for account takeover** — `#206591` · Uber · $0 · ▲144
  > When logging into `central.uber.com`, the `state` parameter for login.uber.com contained a redirect location instead of a CSRF token.
- **Spring Actuator endpoints publicly available, leading to account takeover** — `#862589` · LY Corporation · $5,000 · ▲143
  > This endpoint was not discovered by the internal security team due to being put on a custom path, avoiding detection through our usual means.

## Payload fragments observed

Recurring payloads from this class's writeups. Adapt, don't paste blindly.

| Seen | Fragment |
|---:|---|
| 5× | `victim@ato.com` |
| 3× | `attacker@example.com` |
| 3× | `@import` |
| 2× | `GET https://<URL> HTTP/1.1` |
| 2× | `demo-member@hackerone.com` |
| 2× | `https://cdn.kastatic.org/khanacademy/khanacademy.<hash>.js.map` |
| 2× | `badca7@wearehackerone.com` |
| 2× | `application%5Bid%5D` |
| 2× | `check_alter_user()` |
| 2× | `$regex` |
| 2× | `loadDataWithBaseURL()` |
| 2× | `^FLAG^736c635d8842751b8aafa556154eb9f3$FLAG$` |
| 2× | `<input>` |
| 1× | `user[email]":"victim@gmail.com` |
| 1× | `victim@gmail.com` |
| 1× | `attacker@gmail.com` |
| 1× | `GET / HTTP/1.1 / Transfer-Encoding : chunked / Host: slackb.com / User-Agent: Smuggler/v1.0 / Content-Length: 83 / 0 / GET <URL> HTTP/1.1 /` |
| 1× | `https://<URL>` |
| 1× | `Burp->Burp Collaborator Client` |
| 1× | `host: slackb.com , Port: 443 (SSL)` |

## Parameters observed

`username` · `month` · `year` · `template` · `template[]` · `url` · `email` · `redirectUrl` · `token` · `userId` · `p_datasource_data` · `switch` · `ticket_id` · `canary` · `password` · `continue` · `PositionTitleIds` · `Title` · `FirstName` · `MiddleName`

## Case studies

### Takeover an account that doesn't have a Shopify ID and more
`#867513` · Shopify · $0 · critical · 2020-09-02 · ▲3006
> The https://pos-channel.shopifycloud.com/graphql-proxy/admin can be exploited to update a staff member email without any email confirmation. Using the partner dashboard, we've the ability to create a store that doesn't have a Shopify ID account on https://accounts.shopify.com.

### Account takeover via leaked session cookie
`#745324` · HackerOne · $20,000 · high · 2019-12-03 · ▲1642
> Summary: You are disclose for me you session Description: you are gevi me your session on last report I am can use your session(sorry) ███ ████████ █████████ Impact HackerOneStaff Access, i can read all reports @security and more program

### Account Takeover via Password Reset without user interactions
`#2293343` · GitLab · $35,000 · critical · 2025-02-26 · ▲989
> I found a way to change the password of a GitLab account via the password reset form and successfully retrieve the final reset link without user interactions, using just its email address. Steps to reproduce Go to "Forgot Your Password?" link Enter the victim's email and intercept the submit request via Burp Suite .

### Mass account takeovers using HTTP Request Smuggling on https://slackb.com/ to steal session cookies
`#737140` · Slack · $0 · critical · 2020-03-12 · ▲870
> Hi Slack Security Team! My name is Evan and I'm a first time bug hunter to your platform :) Because you guys were running a month long bounty promotion I decided to take a little of my time and gently perform recon on your platform. Specifically the area of interest I focus in is HTTP Request Smuggling. I developed tooling to actively target some advanced HTTP Smuggling exploits and ran it on your in-scope assets.

### Bypassing Digits origin validation which leads to account takeover
`#129873` · X / xAI · $0 · n/a · 2020-06-24 · ▲619
> Hi, I would like to report an important issue that affects websites that has integrated "Signin with Digits" , leading to potential account takeover. Detail In Digits architecture, the data communication channel between Digits and customer's site relies on postMessage() .

## Wordlists

Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.

| File | Entries |
|---|---:|
| `~/.local/share/hackerone-reports/wordlists/paths_account-takeover.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/params_account-takeover.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |
| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |

```sh
W=~/.local/share/hackerone-reports/wordlists
ffuf -u https://target/FUZZ -w $W/paths_account-takeover.txt \
     -mc all -fc 404 -fs 0 -rate 40
ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_account-takeover.txt \
     -mr 'canary|error|invalid|not found' -rate 40
```

## Nuclei

Use Nuclei for exposed tokens and takeover fingerprints, then chain reset/OAuth/email-change primitives manually.

```sh
nuclei -u https://target -tags takeover,auth-bypass,jwt \
       -severity low,medium,high,critical -rl 40 -o nuclei_account-takeover.txt
nuclei -u https://target -t ~/nuclei-templates/http/takeovers \
       -rl 40 -o nuclei_account-takeover_takeovers.txt
nuclei -u https://target -t ~/nuclei-templates/http/exposures/tokens/generic/jwt-token.yaml \
       -rl 40 -o nuclei_account-takeover_jwt-token.txt
# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'
```

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

## Query the corpus

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class account-takeover --limit 20
python3 ~/.local/share/hackerone-reports/h1.py stats --class account-takeover
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```

Search by technology, endpoint, parameter, or program. Examples:

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class account-takeover
python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class account-takeover --min-bounty 1000
```

## Related

- `hackerone-auth-bypass` (989 reports)
- `hackerone-oauth-oidc` (177 reports)
- `hackerone-xss` (2,569 reports)

## Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.
