---
name: hackerone-authz-bypass
description: >-
  Hunt IDOR, privilege escalation, tenant isolation breaks, and missing function-level authorization. Use when testing roles, admin actions, org boundaries, or object IDs. Backed by 1,386 disclosed HackerOne reports.
---

# Broken Access Control / Authorization Bypass — HackerOne field guide

Built from **1,386** publicly disclosed HackerOne reports (2014–2026). Corpus: `~/.local/share/hackerone-reports/`.

## Signal

- Reports: **1,386** · paid: **337**
- Median bounty **$500** · p90 **$2,500** · max **$35,000** · total **$484,104**
- Median upvotes **20**

## Where it pays

| Program | Reports | Bounty | Upvotes |
|---|---|---|---|
| GitLab | 52 | $100,590 | 4494 |
| Mail.ru | 43 | $40,350 | 1580 |
| PlayStation | 6 | $30,700 | 830 |
| Shopify | 92 | $29,400 | 5300 |
| Valve | 10 | $22,500 | 1064 |
| Teleport | 1 | $21,000 | 255 |
| HackerOne | 63 | $20,100 | 5079 |
| Internet Bug Bounty | 22 | $17,005 | 705 |

## Quick wins

Start here. These are the highest-yield tests for this class.

- Build a role matrix (anon, user, member, admin, support) and replay every request across roles.
- Try admin endpoints and hidden routes found in JS bundles, mobile apps, and API docs.
- Test org/tenant boundaries with two accounts on different plans.
- Check function-level authz: the UI hides it, but does the API enforce it?
- Replay requests after removing cookies, tokens, and role headers.

## Payloads & probes

- Role fields -> `role=admin`, `is_admin=true`, `plan=enterprise`, `permissions=["*"]`
- Headers -> `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-For: 127.0.0.1`, `X-User-Id`
- Path tricks -> `/admin/../user`, `/admin%2f..%2f`, `/.;/admin`, trailing slash
- Method swap -> GET->POST->PUT->DELETE, `X-HTTP-Method-Override`

## Bypass tricks

- Middleware path-normalization mismatch: `/admin/..;/`, `%2e%2e`, double slashes.
- Header spoofing for IP allowlists and internal-only endpoints.
- GraphQL/REST resolver differences: one enforces authz, the other does not.
- Stale permissions after role change or org removal.

## Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`role` `admin` `permission` `org` `team` `account` `tenant` `owner` `visibility` `public` `internal`

## Tools

`Autorize` · `Burp` · `ffuf` · `nuclei` · `jwt_tool`

## Escalation chains

- Authz bypass -> admin panel -> data export.
- Privilege escalation -> cross-tenant access.
- Unauth endpoint -> internal API -> RCE.

## Deeper checklist

- Build a role matrix (anon, user, org member, admin, support) and replay every request across roles.
- Swap object identifiers (numeric, UUID, slug, base64) and test cross-tenant access.
- Try HTTP method swaps (GET/POST/PUT/PATCH/DELETE) and hidden admin routes from JS bundles.
- Test parameter pollution and mass assignment on role/org/owner fields.
- Check GraphQL/REST resolvers individually; list endpoints often leak more than detail endpoints.
- Look for client-side-only checks: disabled buttons, hidden menus, local role flags.
- Test invitation, transfer, export, and billing flows for cross-org actions.
- Verify impact with a second account you control; capture both identities and responses.

## Techniques from real reports

One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.

- **Account Takeover via Password Reset without user interactions** — `#2293343` · GitLab · $35,000 · ▲989
  > Forward the requests and you should get an email containing the reset link that was send to both emails (``victim@gmail.com`` and ``attacker@gmail.com``) .
- **[Part II] Email Confirmation Bypass in myshop.myshopify.com that Leads to Full Privilege Escalation** — `#796808` · Shopify · $0 · ▲894
  > - Cannot integrate across stores/partner even they share the same email address after confirming them
- **Exfiltrate and mutate repository and project data through injected templated service** — `#446585` · GitLab · $11,000 · ▲762
  > Replace `CiService` in the `services` array with `MockCiService`
- **Email address of any user can be queried on Report Invitation GraphQL type when username is known** — `#792927` · HackerOne · $0 · ▲671
  > gid://hackerone/Report/626371 (here 626371 my test program's report id) convert it into base 64, replace that id with the "report id" in the above graphql query
- **Getting all the CD keys of any game** — `#391217` · Valve · $20,000 · ▲638
  > Using the `/partnercdkeys/assignkeys/` endpoint on partner.steamgames.com with specific parameters, an authenticated user could download previously-generated CD keys for a game which they would not normally have access.
- **Ability to reset password for account** — `#322985` · Upserve · $0 · ▲637
  > POST https://hq.breadcrumb.com/api/v1/password reset HTTP/1.1
- **Email Confirmation Bypass in your-store.myshopify.com which leads to privilege escalation** — `#910300` · Shopify · $0 · ▲559
  > Go to your new store and don't verify email, then go to admin/settings/account/youraccountnumber
- **Shopify Stocky App OAuth Misconfiguration** — `#740989` · Shopify · $0 · ▲527
  > This resulted in a full authentication bypass.
- **One-click account hijack for anyone using Apple sign-in with Reddit, due to response-type switch + leaking href to XSS on www.redditmedia.com** — `#1567186` · Reddit · $0 · ▲509
  > Also, the `response type` is modified from `code` to `code+id token` and the `response mode` to `fragment`.
- **Able to Become Admin for Any LINE Official Account** — `#698579` · LY Corporation · $0 · ▲493
  > This was due to an issue where the group ID could be extracted and/or easily guessed, combined with lack of authentication, leading to being able to craft a request that resulted in being given administration rights to that LINE Official Account.
- **Project Template functionality can be used to copy private project data, such as repository, confidential issues, snippets, and merge requests** — `#689314` · GitLab · $12,000 · ▲457
  > in this request, change `use custom template` to `true`, the `template name` to the name the victim gave to the project (`test project`), and `group with project templates id` to the group ID of the public group the victim created (`1`).
- **Reset password link sent over unsecured http protocol** — `#1888915` · Mattermost · $750 · ▲440
  > Navigate to https://h1-\ your-own-instance\ .cloud.mattermost.com/reset password and enter signup email
- **Full account takeover** — `#314808` · Reverb.com · $0 · ▲412
  > Reverb ios application is not validating facebook `access token` on the server side in login api, which allows an attacker to hack all account using his own app access token.
- **Read-only application can publish/delete fleets** — `#1032468` · X / xAI · $0 · ▲398
  > In `/fleets/v1/create` of `https://api.twitter.com`, there is no check to whether if the application has permission to write to the account.
- **Attacker is able to access commit title and team member comments which are supposed to be private** — `#502593` · GitLab · $0 · ▲351
  > - Go to profile of `victim@gmail.com` from `attacker@gmail.com` and subscribe to all events, like this:
- **Private list members disclosure via GraphQL** — `#885539` · X / xAI · $0 · ▲346
  > Send requests to `https://api.█████████.com/graphql/iUmNRKLdkKVH4WyBNw9x2A/ListMembers?variables=%7B%22listId%22%3A%22[Valid Snowflake…
- **Subdomain takeover of datacafe-cert.starbucks.com** — `#665398` · Starbucks · $0 · ▲311
  > view-source:http://datacafe-cert.starbucks.com/
- **Shopify admin authentication bypass using partners.shopify.com** — `#270981` · Shopify · $0 · ▲311
  > The intention was that, when a partner already had a valid user account on the store, their collaborator account request could be accepted automatically, with the user account converted into a collaborator account.
- **Full access to internal Gitlab instances at redash.gitlab.com, dashboards.gitlab.com, prometheus.gitlab.com** — `#498964` · GitLab · $0 · ▲306
  > Once this was done, I replayed the request in Google and again tried to verify `support@gitlab.com` this time the ticket had the verification code public.
- **bd-j exploit chain** — `#1379975` · PlayStation · $20,000 · ▲298
  > The class `com.sony.gemstack.org.dvb.user.UserPreferenceManagerImpl` deserializes the `userprefs` file under privileged context using `readObject()` which is insecure:
- **Exposed proxy allows to access internal reddit domains** — `#2967634` · Reddit · $7,500 · ▲296
  > https://github.com/search?q=org%3Areddit%20snoo.dev&type=code
- **[CRITICAL] 0-Click Account Takeover via Password Reset [AUTH-3243] /orchestrator/v1/password_reset/start** — `#2831902` · Remitly · $0 · ▲291
  > 4-----Intercept the HTTP request using a proxy tool like Burp Suite or OWASP ZAP when submitting the password reset request.
- **Team member with Program permission only can escalate to Admin permission** — `#605720` · HackerOne · $0 · ▲268
  > I noticed that `hackerone.com/teams.json` is accessible to users with "read-only" permission, but `https://hackerone.com/TEAM/groups.json` is accessible to users with at least 1 valid permission.
- **Organization Takeover** — `#809816` · Helium · $500 · ▲263
  > To exploit the vulnerability [A] needs to remain inside the organization of which he is Administrator (a POST call to `/api/organizations/6c6c8c8a-49fe-4bef-a00c-fd99bee39b0d/switch` will invalidate the Bearer token and provide a new one that has the correct…
- **View Titles of Private Reports with pending email invitation** — `#2312029` · HackerOne · $0 · ▲257
  > Send GraphQL request, replacing PRIVATE REPORT ID integer:
- **Privilege escalation from any user (including external) to gitlab admin when admin impersonates you** — `#493324` · GitLab · $0 · ▲256
  > When the gitlab admin impersonates some user, he gets new ` gitlab session` cookie and then clicking at `Stop impersonating` he gets his own admin's cookie back.
- **Stealing Users OAuth authorization code via redirect_uri** — `#1861974` · pixiv · $2,000 · ▲253
  > Path traversal vulnerability in this `redirect uri` parameter allows the attacker to direct the user to the product page created by the attacker.
- **Unrestricted File Upload Leads to RCE on mobile.starbucks.com.sg** — `#1027822` · Starbucks · $0 · ▲247
  > ko2sec discovered an .ashx endpoint on mobile.starbucks.com.sg intended for image files permitted unrestricted file type uploads which could lead to a potential RCE.
- **Shopify Partners Invitation Process Allows Privilege Escalation Without Email Verification** — `#2885269` · Shopify · $0 · ▲245
  > A Proof of Concept (PoC) video is attached to demonstrate the exploit and the steps taken to successfully escalate privileges using the method described above.
- **Account takeover of existing HackerOne accounts through SCIM provisioning** — `#3178999` · HackerOne · $0 · ▲232
  > If the attacker with verified domain as `verified.com` adds a victim as `victim@ato.com` to Okta, with the username as `victim@ato.com` and email field as `victim@verifed.com`, the victim's email will be changed, AND no notification will be sent to the victim…

## Payload fragments observed

Recurring payloads from this class's writeups. Adapt, don't paste blindly.

| Seen | Fragment |
|---:|---|
| 5× | `victim@ato.com` |
| 4× | `%TEMP%` |
| 3× | `@hackerone.com` |
| 3× | `../../app0/bdjstack/lib/ext/00000.jar` |
| 3× | `../../` |
| 3× | `The HEY Team <support@hey.com>` |
| 3× | `support@hey.com` |
| 3× | `POST /index.php/apps/groupfolders/folders/{id}/groups` |
| 3× | `postmaster@email.mg.gitlab.com` |
| 3× | `%temp%\Acronis\DriverSetup\inst.log` |
| 3× | `get_editable_roles()` |
| 3× | `wp_ensure_editable_role()` |
| 3× | `setuid()` |
| 2× | `victim@gmail.com` |
| 2× | `attacker@gmail.com` |
| 2× | `demo-member@hackerone.com` |
| 2× | `%0d%0a` |
| 2× | `j@hackerone.com` |
| 2× | `0xacb@hackerone.com` |
| 2× | `https://cdn.kastatic.org/khanacademy/khanacademy.<hash>.js.map` |

## Parameters observed

`subject` · `report_id` · `scope` · `state` · `client_id` · `response_type` · `redirect_uri` · `group_id` · `search` · `repository_ref` · `aura.context` · `aura.pageURI` · `aura.token` · `authenticity_token` · `page` · `code` · `id` · `type` · `snippets` · `phone`

## Case studies

### Account Takeover via Password Reset without user interactions
`#2293343` · GitLab · $35,000 · critical · 2025-02-26 · ▲989
> I found a way to change the password of a GitLab account via the password reset form and successfully retrieve the final reset link without user interactions, using just its email address. Steps to reproduce Go to "Forgot Your Password?" link Enter the victim's email and intercept the submit request via Burp Suite .

### [Part II] Email Confirmation Bypass in myshop.myshopify.com that Leads to Full Privilege Escalation
`#796808` · Shopify · $0 · critical · 2020-04-01 · ▲894
> In 791775, I submitted a bug at Sunday 5pm Canada time, it was triaged two hours later, and I got the temp fix message at around 3am the next day in Canada time. Truly awesome, the next day I retested after the first fix, and found that I - Cannot receive the email confirmation in the email used to sign up - Cannot integrate across stores/partner even they share the same email address after confirming them And the report was later resolved after I…

### Exfiltrate and mutate repository and project data through injected templated service
`#446585` · GitLab · $11,000 · critical · 2019-03-05 · ▲762
> When looking into this feature, it was also observed that an attacker can create custom attributes for a project. I noticed that custom project attributes can only be created by an instance Administrator. However, by specifying custom attributes in the custom attributes array, a user can create custom project attributes for the project that is being created.

### Email address of any user can be queried on Report Invitation GraphQL type when username is known
`#792927` · HackerOne · $0 · high · 2020-02-20 · ▲671
> Summary: Email id of all hackerone users disclosure Description: There is an flaw , with that i can get all hackerone users email id Steps To Reproduce 1. Invoke the below graphql call POST /graphql HTTP/1.1 you will get below response 2. to reproduce from your account, create one test program, and create one report for that program, get that report id gid://hackerone/Report/626371 (here 626371 my test program's report id) convert it into base 64, replace…

### Getting all the CD keys of any game
`#391217` · Valve · $20,000 · critical · 2018-10-31 · ▲638
> Using the /partnercdkeys/assignkeys/ endpoint on partner.steamgames.com with specific parameters, an authenticated user could download previously-generated CD keys for a game which they would not normally have access. Audit logs were not bypassed using this method, and an investigation of those audit logs did not show any prior or ongoing exploitation of this bug. https://www.youtube.com/watch?v=t0MWDqiKVPk

## Wordlists

Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.

| File | Entries |
|---|---:|
| `~/.local/share/hackerone-reports/wordlists/paths_authz-bypass.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/params_authz-bypass.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |
| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |

```sh
W=~/.local/share/hackerone-reports/wordlists
ffuf -u https://target/FUZZ -w $W/paths_authz-bypass.txt \
     -mc all -fc 404 -fs 0 -rate 40
ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_authz-bypass.txt \
     -mr 'canary|error|invalid|not found' -rate 40
```

## Nuclei

Nuclei cannot infer your object model. Use tags for exposed admin panels, then build a manual role/object matrix.

```sh
nuclei -u https://target -tags idor,authorization,exposure \
       -severity low,medium,high,critical -rl 40 -o nuclei_authz-bypass.txt
nuclei -u https://target -t ~/nuclei-templates/http/exposures \
       -rl 40 -o nuclei_authz-bypass_exposures.txt
# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'
```

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

## Query the corpus

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class authz-bypass --limit 20
python3 ~/.local/share/hackerone-reports/h1.py stats --class authz-bypass
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```

Search by technology, endpoint, parameter, or program. Examples:

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class authz-bypass
python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class authz-bypass --min-bounty 1000
```

## Related

- `hackerone-idor` (450 reports)
- `hackerone-auth-bypass` (989 reports)
- `hackerone-logic-and-design` (931 reports)

## Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.
