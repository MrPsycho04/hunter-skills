---
name: hackerone-csrf
description: >-
  Hunt CSRF and state-changing request forgery. Use when testing account settings, email/password changes, OAuth flows, and JSON endpoints. Backed by 541 disclosed HackerOne reports.
---

# Cross-Site Request Forgery (CSRF) — HackerOne field guide

Built from **541** publicly disclosed HackerOne reports (2014–2026). Corpus: `~/.local/share/hackerone-reports/`.

## Signal

- Reports: **541** · paid: **93**
- Median bounty **$300** · p90 **$2,450** · max **$10,000** · total **$69,328**
- Median upvotes **9**

## Where it pays

| Program | Reports | Bounty | Upvotes |
|---|---|---|---|
| GitHub | 2 | $10,000 | 152 |
| HackerOne | 20 | $8,850 | 735 |
| GitLab | 6 | $6,570 | 287 |
| X / xAI | 16 | $5,320 | 598 |
| TikTok | 12 | $4,847 | 847 |
| Internet Bug Bounty | 2 | $4,660 | 58 |
| Uber | 9 | $4,000 | 256 |
| PayPal | 1 | $3,500 | 81 |

## Quick wins

Start here. These are the highest-yield tests for this class.

- Find state-changing requests and check for anti-CSRF tokens and SameSite cookies.
- Remove the token, blank it, reuse another session's token, and try a fixed token.
- Try GET, form POST, text/plain JSON, multipart, and method override.
- Check email/password change, OAuth consent, and login CSRF.
- Look for subdomain XSS or cookie scope that enables CSRF.

## Payloads & probes

- Form -> `<form action=https://target/email method=POST><input name=email value=attacker@x>`
- JSON -> `<form enctype=text/plain><input name='{"email":"attacker@x","x":"' value='"}'>`
- GET -> `<img src=https://target/settings?email=attacker@x>`
- Method override -> `_method=POST` in a GET/form request

## Bypass tricks

- Token not bound to session; token from another account accepted.
- SameSite=Lax bypass via top-level GET or 2-minute window.
- CORS misconfig allowing credentialed cross-origin requests.
- Bypass token check by changing content-type or removing the parameter.

## Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`email` `password` `change` `delete` `transfer` `invite` `settings` `oauth` `consent`

## Tools

`Burp CSRF PoC generator` · `browser devtools` · `mitmproxy`

## Escalation chains

- CSRF -> email change -> ATO.
- CSRF -> OAuth link -> ATO.
- CSRF + XSS -> worm.

## Deeper checklist

- Identify state-changing requests and check for anti-CSRF tokens and SameSite cookies.
- Test token validation: missing token, empty token, token from another session, fixed token.
- Try method/content-type tricks: GET, POST forms, text/plain JSON, multipart, method override.
- Check CORS misconfigurations that allow credentialed cross-origin reads/writes.
- Test login CSRF, logout CSRF, OAuth state CSRF, and email-change CSRF.
- Look at subdomain/XSS-assisted CSRF where cookies are scoped to the parent domain.
- Build a minimal PoC page and confirm the state change on a victim account.

## Techniques from real reports

One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.

- **[CSRF] TikTok Careers Portal Account Takeover** — `#1010522` · TikTok · $0 · ▲366
  > If you have any feedback, feel free to ping me at [Twitter](https://twitter.com/ lauritz ).
- **CSRF on connecting Paypal as Payment Provider** — `#807924` · Shopify · $0 · ▲304
  > `https://h60ngalog.myshopify.com/admin/payments/complete paypal incontext oauth/41?merchantId=MTU4MzAzMDUwNDowMTBmMDZkYjg1NzM0YjQ4NWVkMDk1YzQ1YWYxY2ZlNw%3D%3D&merchantIdInPayPal=5NS8DHQCFGT84&permissionsGranted=true&accountStatus=BUSINESS…
- **Periscope android app deeplink leads to CSRF in follow action** — `#583987` · X / xAI · $1,540 · ▲224
  > + It means we can use ` pscp://user/<user-id or pscpd://user/<user-id `
- **Take over of accounts created using Google or Facebook** — `#442901` · Khan Academy · $0 · ▲184
  > Since the account is created using a social media account, no existing password check is needed and the CSRF check on the endpoint is broken.
- **Improper CSRF token validation allows attackers to access victim's accounts linked to Hackerone** — `#1727221` · HackerOne · $0 · ▲168
  > Then it redirects us to the callback endpoint which sends a postmessage to the embedded iframe to validate the integration on the client side.
- **CSRF protection bypass in GitHub Enterprise management console** — `#1497169` · GitHub · $10,000 · ▲152
  > [CVE-2022-23732](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23732)
- **Slack integration setup lacks CSRF protection** — `#170552` · HackerOne · $2,500 · ▲149
  > Cross-site Request Forgery in the `Integrations` (https://hackerone.com/[YOUR TEAM]/integrations) feature for teams.
- **CSRF token validation system is disabled on Stripe Dashboard** — `#1483327` · Stripe · $0 · ▲113
  > @d sharad discovered that due to a code change deployed on 2/14/2022, Cross Site Request Forgery (CSRF) protection was disabled in the Stripe Dashboard.
- **Referer Leakage Vulnerability in  socialclub.rockstargames.com/crew/ leads to FB'S OAuth token theft.** — `#787160` · Rockstar Games · $0 · ▲112
  > The Open Redirect is the subject of a separate report; in this report, we addressed the problem by strengthening the Referer header policy with `<meta name="referrer" content="origin" / `.
- **Cross-Site Request Forgery** — `#2041007` · ownCloud · $0 · ▲111
  > I think the cause of this vulnerability is the second condition of https://github.com/owncloud/core/blob/master/lib/private/AppFramework/Middleware/Security/SecurityMiddleware.php L145, because the the value of `$this- request- getHeader("Authorization")` is…
- **Cross-Site Request Forgery (CSRF) vulnerability on API endpoint allows account takeovers** — `#419891` · Khan Academy · $0 · ▲111
  > The `/signup/email` API endpoint at [khanacademy.org](https://khanacademy.org) is vulnerable to Cross-Site Request Forgery (CSRF) attacks, allowing takeovers of accounts associated with unconfirmed email addresses.
- **CSRF Vulnerability on https://signin.rockstargames.com/tpa/facebook/link/** — `#474833` · Rockstar Games · $0 · ▲104
  > In this report, the researcher identified a Cross-Site Request Forgery vulnerability that could have allowed attackers to link a Facebook account to another user's Social Club account, and thus gain the ability to log in as the victim.
- **Account takeover due to insufficient URL validation on RelayState parameter** — `#1923672` · GitLab · $2,450 · ▲99
  > https://bitbucket.org/site/oauth2/authorize?client id=b9jLmh8WCLZPBAwWba&redirect uri=https%3A%2F%2Fgitlab.com%2Fusers%2Fauth%2Fbitbucket%2Fcallback&response type=token&state=DoesNotMatter
- **One Click Account takeover using Ouath CSRF bypass by adding Null byte %00 in state parameter on  www.streamlabs.com** — `#1046630` · Logitech · $0 · ▲99
  > Allow twitch access and once you see a get request in burp with host streamlabs.com and parameters code, scope and state then generate CSRF PoC
- **CSRF Account Takeover** — `#1253462` · TikTok · $0 · ▲95
  > A Cross-Site Request Forgery (CSRF) vulnerability was found on a TikTok endpoint which could have resulted in a full account takeover.
- **CSRF to HTML Injection in Comments** — `#428019` · WordPress · $0 · ▲95
  > More [details are available on the RIPS blog](https://blog.ripstech.com/2019/wordpress-csrf-to-rce/).
- **CSRF in Account Deletion feature (https://www.flickr.com/account/delete)** — `#615448` · Flickr · $0 · ▲92
  > While testing the account deletion feature, I noticed that there were no CSRF token :/ Later found out it was because of the new login flow.
- **Account takeover at https://try.discourse.org due to no CSRF protection in connecting Yahoo account** — `#423022` · Discourse · $0 · ▲89
  > There is an option in https://try.discourse.org/u/testh1ay/preferences/account to connect our Yahoo account.
- **CSRF on /api/graphql allows executing mutations through GET requests** — `#1122408` · GitLab · $3,370 · ▲88
  > Mutations are `edit` or `create` queries used in Graphql.
- **CSRF token validation system is disabled on Stripe Dashboard** — `#1493437` · Stripe · $2,500 · ▲87
  > @rodolfomarianocy discovered that due to a code change deployed on 2/14/2022, Cross Site Request Forgery (CSRF) protection was disabled in the Stripe Dashboard.
- **CSRF leads to Account takeover** — `#2699029` · U.S. Dept Of Defense · $0 · ▲87
  > Vulnerable domain and endpoint : https://██████████/account/profile/edit
- **Login CSRF vulnerability on hackerone.com** — `#834366` · HackerOne · $500 · ▲84
  > We found a CSRF token bypass on the Hacker One login page.
- **Delete any user's added Email,Telephone,Fax,Address,Skype via csrf in (https://academy.acronis.com/)** — `#709537` · Acronis · $0 · ▲82
  > - navigate to `https://academy.acronis.com/ /account/edit/account id/<your id `
- **XSSI on refer.xoom.com allows stealing email addresses and posting to Twitter on behalf of victim** — `#450796` · PayPal · $3,500 · ▲81
  > This included the email addresses being used and, in extreme cases, tokens allowing Xoom access to post on a user’s Twitter.
- **CSRF in ticket function** — `#1890310` · TikTok · $0 · ▲80
  > I found this issue by removing the CsrfToken from the header and converting the content type from `JSON` to `x-www-form-urlencoded`.
- **Account takeover by changing email** — `#538800` · Khan Academy · $0 · ▲80
  > Attacker then lures a new KA user to visit a URL linking to a page that sends a `POST` request to `/signup/email` with the POST body : `casing=camel&email=ATTACKER EMAIL`.
- **CSRF protection bypass on TikTok Webcast Endpoints** — `#1543234` · TikTok · $2,500 · ▲79
  > API on TikTok Webcast endpoints prevent CSRF by validating the Origin header which indicates the source of the request.
- **CSRF protection on OIDC login is broken** — `#1878381` · Nextcloud · $500 · ▲77
  > So I assume the bug is also the same https://github.com/nextcloud/user oidc/blob/main/lib/Controller/Id4meController.php L175-L181
- **Japan - CSRF in webapp.starbucks.co.jp with user interaction could leak an access token if the user was not using Chrome** — `#1113559` · Starbucks · $0 · ▲77
  > elber discovered a CSRF in webapp.starbucks.co.jp leaked an access token if an authenticated user opened a crafted HTML file in a browser other than Chrome which has Same Site Attribute for the cookie set by default.
- **CSRF on Periscope Web OAuth authorization endpoint** — `#215381` · X / xAI · $0 · ▲74
  > At minimum, I found endpoints that allow creating a broadcast (https://public-api.periscope.tv/v1/broadcast/create), tweeting it (https://public-api.periscope.tv/v1/broadcast/publish) and deleting a broadcast…

## Payload fragments observed

Recurring payloads from this class's writeups. Adapt, don't paste blindly.

| Seen | Fragment |
|---:|---|
| 3× | `new.cs.money{.withgoogle.com` |
| 2× | `www.pscp.tv/<user-id>/follow` |
| 2× | `new.cs.money{.attacker.com` |
| 2× | `http://localhost$something.io` |
| 2× | `<html> / <!-- CSRF PoC - generated by Burp Suite Professional --> / <body> / <script>history.pushState('', '', '/')</script> / <form action=` |
| 1× | `MTU4MzAzMDUwNDowMTBmMDZkYjg1NzM0YjQ4NWVkMDk1YzQ1YWYxY2ZlNw%3D%3D` |
| 1× | `pscp://user/<user-id> or pscpd://user/<user-id>` |
| 1× | `{F1976253} / 3. Following the redirection takes us to the authorization page of the service provider / {F1976255} / If we choose to Authoriz` |
| 1× | `This endpoint validates the code received from Github, the backend relies on the ***state*** parameter to determine to which user should the` |
| 1× | `Location: https://slack.com/oauth/authorize / ?client_id=2174110321.11522100978 / &redirect_uri=https%3A%2F%2Fhackerone.com%2Fauth%2Fslack%2` |
| 1× | `<meta name="referrer" content="origin" />` |
| 1× | `$this->request->getHeader("Authorization")` |
| 1× | `GET /2.0/repositories/%7B766210f9-9bec-4010-9f4d-917b06661c0c%7D HTTP/2 / Host: api.bitbucket.org / User-Agent: curl/7.79.1 / Accept: */* /` |
| 1× | `gitlab@gitlab.com` |
| 1× | `https://academy.acronis.com/#/account/edit/account_id/<your_id>` |
| 1× | `<img>` |
| 1× | `__utmz=123456.123456789.11.2.utmcsr=[HOST]\\|utmccn=(referral)\\|utmcmd=referral\\|utmcct=[PATH]` |
| 1× | `__utmz=123456.123456789.11.2.utmcsr=blackfan.ru\\|utmccn=(referral)\\|utmcmd=referral\\|utmcct=/path/` |
| 1× | `https://eu1.badoo.com/google/verify.phtml?rt=<State_param_value>&code=<Code_returned_from_google>` |
| 1× | `GET /u/x.css HTTP/1.1 / Host: try.discourse.org / <meta name="csrf-token" content="aYBW0N/1nfI1PHBa24YNx+...+BJJX+Fg==" />` |

## Parameters observed

`email` · `code` · `state` · `id` · `page` · `redirect_uri` · `authenticity_token` · `client_id` · `scope` · `nonce` · `sort_type` · `sort_direction` · `limit` · `password` · `act` · `subject` · `report_id` · `view` · `text_query` · `response_type`

## Case studies

### [CSRF] TikTok Careers Portal Account Takeover
`#1010522` · TikTok · $0 · high · 2020-12-15 · ▲366
> A missing CSRF protection and open redirect vulnerability was reported in the TikTok Careers portal single sign on flow which is used by applicants to apply for TikTok positions. This flaw was quickly remediated and does not impact TikTok.com or mobile application. We thank @lauritz for reporting this vulnerability to our team and for confirming the resolution. I wrote a short blog post that covers this report.

### CSRF on connecting Paypal as Payment Provider
`#807924` · Shopify · $0 · medium · 2020-04-10 · ▲304
> Hi, I think there is a weak csrf protection on adding paypal as the payment provider, but the protection is not good. When user try to add paypal as payment provider, they will make this GET request https://h60ngalog.myshopify.com/admin/payments/complete paypal incontext oauth/41?merchantId=MTU4MzAzMDUwNDowMTBmMDZkYjg1NzM0YjQ4NWVkMDk1YzQ1YWYxY2ZlNw%3D%3D&merchantIdInPayPal=5NS8DHQCFGT84&permissionsGranted=true&accountStatus=BUSINESS…

### Account Takeover using Linked Accounts due to lack of CSRF protection
`#463330` · Rockstar Games · $0 · high · 2019-02-20 · ▲238
> In this report, the researcher found a weakness in our third-party account linking process. They were able to create a malicious link that, if clicked by the victim, would under certain conditions give the attacker access to the victim's Social Club account. This issue has now been fixed.

### Periscope android app deeplink leads to CSRF in follow action
`#583987` · X / xAI · $1,540 · low · 2020-02-21 · ▲224
> This issue is mainly in the Periscope Android app against CSRF follow action using deeplink.

### Take over of accounts created using Google or Facebook
`#442901` · Khan Academy · $0 · critical · 2019-05-17 · ▲184
> When a user creates an account using Google or Facebook and does not set an additional password, it is possible to set their passwords via CSRF. Since the account is created using a social media account, no existing password check is needed and the CSRF check on the endpoint is broken. To reproduce, create an account with Google or Facebook and make account load the attached HTML file.

## Wordlists

Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.

| File | Entries |
|---|---:|
| `~/.local/share/hackerone-reports/wordlists/paths_csrf.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/params_csrf.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |
| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |

```sh
W=~/.local/share/hackerone-reports/wordlists
ffuf -u https://target/FUZZ -w $W/paths_csrf.txt \
     -mc all -fc 404 -fs 0 -rate 40
ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_csrf.txt \
     -mr 'canary|error|invalid|not found' -rate 40
```

## Nuclei

Confirm with a real cross-origin PoC; scanner hits need a browser check.

```sh
nuclei -u https://target -tags csrf \
       -severity low,medium,high,critical -rl 40 -o nuclei_csrf.txt
nuclei -u https://target -t ~/nuclei-templates/http/vulnerabilities/generic \
       -rl 40 -o nuclei_csrf_generic.txt
# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'
```

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

## Query the corpus

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class csrf --limit 20
python3 ~/.local/share/hackerone-reports/h1.py stats --class csrf
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```

Search by technology, endpoint, parameter, or program. Examples:

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class csrf
python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class csrf --min-bounty 1000
```

## Related

- `hackerone-xss` (2,569 reports)
- `hackerone-oauth-oidc` (177 reports)
- `hackerone-clickjacking` (166 reports)

## Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.
