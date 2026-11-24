---
name: hackerone-info-disclosure
description: >-
  Hunt sensitive data exposure. Use when reviewing APIs, debug pages, error messages, backups, source maps, directory listings, cloud storage, or verbose responses. Backed by 1,827 disclosed HackerOne reports.
---

# Information Disclosure — HackerOne field guide

Built from **1,827** publicly disclosed HackerOne reports (2014–2026). Corpus: `~/.local/share/hackerone-reports/`.

## Signal

- Reports: **1,827** · paid: **339**
- Median bounty **$500** · p90 **$2,500** · max **$40,000** · total **$418,640**
- Median upvotes **11**

## Where it pays

| Program | Reports | Bounty | Upvotes |
|---|---|---|---|
| HackerOne | 156 | $98,650 | 11273 |
| Uber | 47 | $47,600 | 2067 |
| Snapchat | 6 | $41,000 | 1282 |
| Mail.ru | 136 | $34,350 | 1894 |
| Internet Bug Bounty | 35 | $28,998 | 751 |
| Shopify | 45 | $27,902 | 1327 |
| GitLab | 32 | $26,300 | 1725 |
| X / xAI | 30 | $15,710 | 1172 |

## Quick wins

Start here. These are the highest-yield tests for this class.

- Fuzz for debug endpoints: /debug, /actuator, /health, /metrics, /graphql, .env, .git, source maps.
- Check error handling for stack traces, SQL errors, internal hosts, and versions.
- Look for extra fields, deleted records, internal notes, PII, tokens in API responses.
- Enumerate cloud storage, backups, DB dumps, log archives, CI artifacts.

## Payloads & probes

- `/.git/config` `/.env` `/.DS_Store` `/server-status` `/actuator/env`
- `/api/v1/users?limit=1000` `/api/v1/users/0`
- `?fields=all` `?expand=*` `?include=deleted`
- S3 -> `https://bucket.s3.amazonaws.com/?list-type=2`

## Bypass tricks

- Bypass auth on static/debug paths with path normalization.
- Use GraphQL introspection and field suggestions.
- Check cache headers for private data.

## Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`debug` `actuator` `health` `metrics` `env` `backup` `export` `logs` `graphql`

## Tools

`ffuf` · `gobuster` · `nuclei` · `trufflehog` · `waybackurls`

## Escalation chains

- Info leak -> creds -> ATO.
- Debug endpoint -> RCE.
- PII leak -> compliance impact.

## Deeper checklist

- Fuzz for debug endpoints: /debug, /actuator, /health, /metrics, /graphql introspection, .env, .git, source maps.
- Check error handling: stack traces, SQL errors, internal hostnames, framework versions, request IDs.
- Look for object leaks in API responses: extra fields, deleted records, internal notes, PII, tokens.
- Enumerate cloud storage and backups: S3/GCS/Azure buckets, DB dumps, log archives, CI artifacts.
- Test cache and CDN behavior for private content leakage across users or regions.
- Check JS bundles for hardcoded keys, internal URLs, feature flags, staging hosts.
- Compare responses across roles and unauthenticated requests for over-exposure.
- Verify the data is genuinely sensitive and not intended public data before reporting.

## Techniques from real reports

One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.

- **Confidential data of users and limited metadata of programs and reports accessible via GraphQL** — `#489146` · HackerOne · $0 · ▲1033
  > The GraphQL endpoint doesn't have access controls implemented properly.
- **Sensitive user information disclosure at bonjour.uber.com/marketplace/_rpc via the 'userUuid' parameter** — `#542340` · Uber · $0 · ▲643
  > Public API endpoint leaked mobile API token of a user by passing driver uuid/rider uuid in the request.
- **The /reports/:id.json endpoint discloses potentially sensitive user attributes when reporter summary is present** — `#3000510` · HackerOne · $0 · ▲625
  > The.json endpoint of any disclosed report is leaking reporter's email, OTP backup codes, reporter's phone number, "graphql secret token", tshirt size all the reporter account's internal details etc.
- **Customer private program can disclose email any users through invited via username** — `#807448` · HackerOne · $7,500 · ▲589
  > `{"data":{"team":{" id":"47388","handle":"hackerone h1p bbp3","soft launch invitations":{"total count":5,"nodes":[{"token":"████████"},{"token":"███"},{"token":"████"},{"token":"██████"},{"token":"████████"}]}}}}`
- **Access to multiple production Grafana dashboards** — `#663628` · Snapchat · $10,000 · ▲464
  > Furthermore one of the custom modules was vulnerable to SQL Injection.
- **Open prod Jenkins instance** — `#231460` · Snapchat · $15,000 · ▲436
  > Once logged in, they gained access to sensitive API tokens.
- **An attacker can can view any hacker email via  /SaveCollaboratorsMutation operation name** — `#2032716` · HackerOne · $12,500 · ▲429
  > 4- Go the pen on the right for adding more collaborator and click on the pen and capture traffic , you will see the user email in first request,
- **gitlab-workhorse bypass in Gitlab::Middleware::Multipart allowing files in `allowed_paths` to be read** — `#850447` · GitLab · $10,000 · ▲410
  > Determine a valid PID by looping over `/proc/PID` until a `cwd` is found and readable by `git` (eg the `unicorn` worker will have `/proc/19606/cwd - /var/opt/gitlab/gitlab-rails/working`) and traverse to a valid upload path:
- **Employee's GitHub Token Found In Travis CI Build Logs** — `#496937` · Superhuman (formerly Grammarly) · $5,000 · ▲408
  > This report was a part of our research on Travis CI's attack surface: https://edoverflow.com/2019/ci-knew-there-would-be-bugs-here/
- **JSON serialization of any Project model results in all Runner tokens being exposed through Quick Actions** — `#509924` · GitLab · $12,000 · ▲366
  > Write `/move <full path of any other project ` and click "Comment", a request to `/:namespace/:project/notes` is submitted
- **Partial disclosure of report activity through new "Export as .zip" feature** — `#182358` · HackerOne · $10,000 · ▲355
  > Go to this partially disclosed report https://hackerone.com/reports/██████████
- **Information Disclosure in /skills call** — `#188719` · HackerOne · $10,000 · ▲287
  > IN respone of above request all reports submitted for review are getting disclosed.
- **Brave Browser Tor Window leaks user's real IP to the external DNS server** — `#1077022` · Brave Software · $0 · ▲280
  > When a user navigates to a URL in Tor Window, the DNS requests are sent directly without using the Tor proxy, which leaks the user's real IP address and the requested domain name to the user's ISP and the DNS server.
- **Exfiltrating a victim's exact location (to within 5m)** — `#1234406` · Bumble · $0 · ▲278
  > This is not a new vulnerability; Tinder was found to be vulnerable to a version of it in 2014 (https://blog.includesecurity.com/2014/02/how-i-was-able-to-track-the-location-of-any-tinder-user/).
- **Internal attachments can be exported via "Export as .zip" feature** — `#186230` · HackerOne · $12,500 · ▲269
  > Now extract the .zip file (`HackerOne Report-security 182358.zip`)
- **OAuth `redirect_uri` bypass using IDN homograph attack resulting in user's access token leakage** — `#861940` · Semrush · $0 · ▲265
  > IDN homography attack exploits the fact that many different characters look alike such as `semrush.com` is different from `sеmrush.com` because in the latter we used the Cyrillic letter `е` which looks exactly like the latin `e`.
- **AWS keys and user cookie leakage via uninitialized memory leak in outdated librsvg version in Basecamp** — `#2107680` · Basecamp · $8,868 · ▲248
  > Replace the `.avif` extension with `.png`, and the filename (the part right before the extension) with the string `$RANDOM$RANDOM$RANDOM$RANDOM`.
- **[www.zomato.com] CORS Misconfiguration, could lead to disclosure of sensitive information** — `#426165` · Eternal · $550 · ▲246
  > run the following code in console and you would find it pops up user information var req = new XMLHttpRequest(); req.onload = reqListener; req.open('get','https://www.zomato.com/abudhabi',true); req.withCredentials = true; req.send('{}'); function…
- **Google API key leaked to Public** — `#1065041` · FetLife · $0 · ▲228
  > https://maps.googleapis.com/maps/api/geocode/json?latlng=40,30&key=AI████████DM
- **Public GitHub repositories for multiple HackerOne managed triage team profiles contain private HackerOne reports information** — `#2937622` · HackerOne · $0 · ▲226
  > Here's a random report's commit: █████/setup-chain-node/commit/█████████ (and another fresh commit called "Retest," meaning the issue is potentially fixed) , which is a GitHub actions injection into █████'s repository.
- **Google Docs link in JS files allows editing & reading survey information** — `#2180521` · HackerOne · $0 · ▲217
  > `https://hackerone.com/assets/static/js/5930.078b8e86.chunk.js`
- **Manipulate hacker profile and private program hacktivity to expose your name as researchers who is actively submitting reports with resolve status** — `#654198` · HackerOne · $500 · ▲213
  > For PoC purposes, I have tested it in [███████](https://hackerone.com/███████) private program because they have `security@` email forwarding: `hackerone@█████████.com`.
- **Stealing Facebook OAuth Code Through Screenshot viewer** — `#488269` · Rockstar Games · $0 · ▲200
  > We have resolved the image injection vulnerability, thereby preventing the potential exfiltration of sensitive authentication tokens.
- **An invite-only's program submission state is accessible to users no longer part of the program** — `#800109` · HackerOne · $500 · ▲194
  > Cookie: cfduid=████████; cfuid=█████; ga=█████████; mkto trk=███████; biz uid=███████; biz nA=14; biz pendingA=%5B%5D; biz flagsA=████████; Host-session=█████████████; gid=GA1.2.1121101145.1582021374
- **Unauthorized access to metadata of undisclosed reports that were retested** — `#871749` · HackerOne · $0 · ▲189
  > `report retests` object in `User` node discloses some information about undisclosed report
- **How The Hackers Saved Christmas** — `#1069335` · h1-ctf · $0 · ▲179
  > Note: `/api/experiments` is a false positive because `/api/anythingandeverything` will respond with `401` as well.
- **Information Disclosure through Sentry Instance ███████** — `#697512` · Eternal · $750 · ▲178
  > Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng, / ;q=0.8,application/signed-exchange;v=b3
- **Disclosure of `payment_transactions` for programs via GraphQL query** — `#707433` · HackerOne · $0 · ▲178
  > {"query":"query Team mini profile($handle 0:String!,$size 1:ProfilePictureSizes!) {team(handle:$handle 0) {id,...F0}} fragment F0 on Team {id,name,about, profile picturePkPpF:profile picture(size:$size 1),offers swag,offers bounties,base bounty,payment…
- **404-response contains debug-information with all headers** — `#792998` · HackerOne · $0 · ▲173
  > When requesting a page that does not exist under `www.hackerone.com` the page returns a hidden HTML-element ` debugData` that reflects all headers in the GET-request, including http-only cookies.
- **Total Paid Bounty Paid can be disclose** — `#674757` · HackerOne · $500 · ▲168
  > 2- The program is not 90 days or younger, but an automated script is continually tracking "Bounties sent in the last 90 days" value (note that this would give an exact number since the tracking has started or a very approximate number) (inspired from report…

## Payload fragments observed

Recurring payloads from this class's writeups. Adapt, don't paste blindly.

| Seen | Fragment |
|---:|---|
| 6× | `acf_get_posts()` |
| 6× | `is_trusted_daemon()` |
| 5× | `try_to_connect_and_handshake_with_new_peer()` |
| 4× | `rescan_spent()` |
| 3× | `connections_maker()` |
| 3× | `curl_easy_reset()` |
| 3× | `\x00` |
| 3× | `data->state.referer` |
| 3× | `wallet2::rescan_spent()` |
| 2× | `jdh34k' and 1=0 union all select 1,2,3;--` |
| 2× | `doSearch()` |
| 2× | `{id}` |
| 2× | `<feature.flag>` |
| 2× | `<REDACTED>` |
| 2× | `{F_number_file}` |
| 2× | `fetch()` |
| 2× | `https://fetlife.com/events/{event-id}` |
| 2× | `curl -XPOST -H 'Content-Type: application/json' -d ‘{"solution": "Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution", "parameter` |
| 2× | `/wp-json/wp/v2/sensei-messages/<numericID>` |
| 2× | `get_outgoing_connections_count()` |

## Parameters observed

`text_query` · `page` · `url` · `token` · `subject` · `sort_type` · `client_id` · `sentry_key` · `action` · `query` · `defid` · `id` · `username` · `email` · `sort` · `file.path` · `SRBHeaderID` · `isBoard` · `OT` · `redirect_uri`

## Case studies

### Confidential data of users and limited metadata of programs and reports accessible via GraphQL
`#489146` · HackerOne · $0 · critical · 2019-02-03 · ▲1033
> Summary: The GraphQL endpoint doesn't have access controls implemented properly. Description: Any attacker can get personally identifiable information of users of Hackerone such as email address, backup hash codes, facebook user id, account recovery phone number verified at, totp enabled, etc. These are just some examples of fields which are getting leaked directly from GraphQL.

### Sensitive user information disclosure at bonjour.uber.com/marketplace/_rpc via the 'userUuid' parameter
`#542340` · Uber · $0 · high · 2019-09-09 · ▲643
> It was possible for an attacker to insert another user’s UUID into the userUuid POST parameter when making a request to https://bonjour.uber.com/marketplace/ rpc?rpc=getConsentScreenDetails, allowing them to retrieve personal data from the victim user’s account, as well as the user's mobile auth token, which could allow them to make requests to mobile APIs as the victim.

### The /reports/:id.json endpoint discloses potentially sensitive user attributes when reporter summary is present
`#3000510` · HackerOne · $0 · critical · 2025-04-01 · ▲625
> Hi The.json endpoint of any disclosed report is leaking reporter's email, OTP backup codes, reporter's phone number, "graphql secret token", tshirt size all the reporter account's internal details etc. I was checking Hackerone's disclosed report ██████████ and suddenly during check found .json point is leaking too much data of reporter . I immediately reported it to you.

### Customer private program can disclose email any users through invited via username
`#807448` · HackerOne · $7,500 · high · 2020-05-15 · ▲589
> Summary: Hey team,This bug could have been used by my calculations a long time ago Steps To Reproduce: 1)Go to https://hackerone.com/hackerone h1p bbp3/launch 2)Take invite via username 3)Input username , send invite 3.1)When an invite is created, we get a token 4)Now Go use GraphQL query https://hackerone.com/graphql? {"query": "query {team(handle:\\"hackerone h1p bbp3\\"){ id,handle,soft launch invitations{total count,nodes{...

### Access to multiple production Grafana dashboards
`#663628` · Snapchat · $10,000 · high · 2020-11-04 · ▲464
> @damian89 found a production Grafana instance which displayed confidential metrics inside various dashboards. While fuzzing patterns of certain snapchat related projects, I was able to find an instance of Grafana which was accessible by a guest user. That instance contained hundreds of production dashboards, valuable data about company. Furthermore one of the custom modules was vulnerable to SQL Injection.

## Wordlists

Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.

| File | Entries |
|---|---:|
| `~/.local/share/hackerone-reports/wordlists/paths_info-disclosure.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/params_info-disclosure.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |
| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |

```sh
W=~/.local/share/hackerone-reports/wordlists
ffuf -u https://target/FUZZ -w $W/paths_info-disclosure.txt \
     -mc all -fc 404 -fs 0 -rate 40
ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_info-disclosure.txt \
     -mr 'canary|error|invalid|not found' -rate 40
```

## Nuclei

Run exposures/misconfiguration templates against every host; triage for real secrets and PII.

```sh
nuclei -u https://target -tags exposure,disclosure,debug,config,files,keys,tokens \
       -severity info,low,medium,high,critical -rl 40 -o nuclei_info-disclosure.txt
nuclei -u https://target -t ~/nuclei-templates/http/exposures \
       -rl 40 -o nuclei_info-disclosure_exposures.txt
nuclei -u https://target -t ~/nuclei-templates/http/misconfiguration \
       -rl 40 -o nuclei_info-disclosure_misconfiguration.txt
# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'
```

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

## Query the corpus

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class info-disclosure --limit 20
python3 ~/.local/share/hackerone-reports/h1.py stats --class info-disclosure
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```

Search by technology, endpoint, parameter, or program. Examples:

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class info-disclosure
python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class info-disclosure --min-bounty 1000
```

## Related

- `hackerone-authz-bypass` (1,386 reports)
- `hackerone-crypto-and-secrets` (562 reports)
- `hackerone-idor` (450 reports)

## Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.
