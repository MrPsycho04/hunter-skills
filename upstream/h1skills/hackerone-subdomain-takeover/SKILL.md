---
name: hackerone-subdomain-takeover
description: >-
  Hunt subdomain takeover. Use when enumerating DNS records pointing at abandoned SaaS, cloud, or CDN resources. Backed by 196 disclosed HackerOne reports.
---

# Subdomain Takeover — HackerOne field guide

Built from **196** publicly disclosed HackerOne reports (2014–2026). Corpus: `~/.local/share/hackerone-reports/`.

## Signal

- Reports: **196** · paid: **31**
- Median bounty **$350** · p90 **$1,000** · max **$3,000** · total **$15,040**
- Median upvotes **25**

## Where it pays

| Program | Reports | Bounty | Upvotes |
|---|---|---|---|
| Snapchat | 5 | $3,250 | 199 |
| Shipt | 3 | $1,050 | 224 |
| Mozilla | 18 | $1,000 | 651 |
| Shopify | 10 | $1,000 | 264 |
| HackerOne | 7 | $1,000 | 598 |
| Lyst | 1 | $1,000 | 163 |
| Grab | 1 | $1,000 | 142 |
| Internet Bug Bounty | 1 | $1,000 | 0 |

## Quick wins

Start here. These are the highest-yield tests for this class.

- Enumerate subdomains and resolve CNAME/A records to third-party services.
- Check for unclaimed resources: S3, GitHub Pages, Heroku, Azure, Fastly, Shopify, status pages.
- Confirm the dangling fingerprint before claiming.
- Assess impact: cookie scope, CSP allowlists, OAuth redirect URIs, email.

## Payloads & probes

- CNAME -> `foo.s3.amazonaws.com` (NoSuchBucket)
- CNAME -> `foo.github.io` (404 repo)
- CNAME -> `foo.herokuapp.com` (No such app)
- CNAME -> `foo.statuspage.io` / `foo.zendesk.com`

## Bypass tricks

- Look for forgotten staging/dev subdomains and wildcard DNS.
- Check NS delegation to abandoned providers.

## Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`DNS` `CNAME` `A` `NS` `MX` `TXT`

## Tools

`subfinder` · `amass` · `dnsx` · `nuclei -t takeovers` · `can-i-take-over-xyz`

## Escalation chains

- Subdomain takeover -> cookie theft.
- Subdomain takeover -> OAuth redirect.

## Deeper checklist

- Enumerate subdomains and resolve CNAME/A records to third-party services.
- Check for unclaimed resources: S3, GitHub Pages, Heroku, Azure, Fastly, Shopify, status pages.
- Confirm the dangling fingerprint (NXDOMAIN/claim page) before claiming.
- Assess impact: cookie scope, CSP allowlists, OAuth redirect URIs, email.
- Claim only within scope and with permission; never squat third-party brands.

## Techniques from real reports

One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.

- **Subdomain Takeover to Authentication bypass** — `#335330` · Roblox · $0 · ▲783
  > As `.ROBLOSECURITY` cookies is scoped to ` .roblox.com` means same cookies shared with all other subdomain, i'm not much familiar with hubspot with hosting following code on will steal all the users cookie who visit this subdomain.
- **Subdomain takeover of datacafe-cert.starbucks.com** — `#665398` · Starbucks · $0 · ▲311
  > view-source:http://datacafe-cert.starbucks.com/
- **Authentication bypass on auth.uber.com via subdomain takeover of saostatic.uber.com** — `#219205` · Uber · $0 · ▲183
  > Although there were some countermeasures to prevent theft, the current setup still allows leakage of these high-value session cookies to the overtaken subdomain https://saostatic.uber.com in all modern browsers, leading to a full Authentication Bypass (highly…
- **Subdomain takeover of storybook.lystit.com** — `#779442` · Lyst · $1,000 · ▲163
  > https://www.hackerone.com/blog/Guide-Subdomain-Takeovers
- **Subdomain Takeover Via Insecure CloudFront Distribution cdn.grab.com** — `#352869` · Grab · $1,000 · ▲142
  > An attacker can take a forgotten subdomain, trick the user to visit it, and extract cookies
- **Subdomain takeover at info.hacker.one** — `#202767` · HackerOne · $0 · ▲134
  > Go to - http://info.hacker.one/blank-page-123133617adasdasdsa/
- **Subdomain takeover of d02-1-ag.productioncontroller.starbucks.com** — `#661751` · Starbucks · $0 · ▲122
  > I then crafted a website and uploaded it to the cloud service using this as a guide: https://docs.microsoft.com/en-us/azure/cloud-services/cloud-services-how-to-create-deploy-portal.
- **Subdomain takeover of mydailydev.starbucks.com** — `#570651` · Starbucks · $0 · ▲122
  > A subdomain of `starbucks.com` had a CNAME record pointing to an Azure Traffic Manager profile that @0xpatrik was able to claim.
- **Subdomain takeover on http://fastly.sc-cdn.net/** — `#154425` · Snapchat · $3,000 · ▲114
  > I've confirmed this is a snapchat property via Censys (https://censys.io/certificates/65ba2e172a1eb85eb1071c9fd7a4e8371ef12625409890507c89a54978305558) though the risk here seems minimal at best as this domain does not appear to be used anywhere on any…
- **Subdomain takeover on svcgatewayus.starbucks.com** — `#325336` · Starbucks · $0 · ▲109
  > https://blog.sweepatic.com/subdomain-takeover-principles/
- **Subdomain takeover on usclsapipma.cv.ford.com** — `#484420` · Ford · $0 · ▲105
  > https://labs.detectify.com/tag/hostile-subdomain-takeover/
- **Subdomain takeover on happymondays.starbucks.com due to non-used AWS S3 DNS record** — `#186766` · Starbucks · $0 · ▲105
  > In addition, there's no way at all for a visitor of this page to validate that the content on this domain is not served by Starbucks, making it extremely easy to utilize this for targeting the organization by fake login forms / spear phishing using your own…
- **Subdomain takeover of fr1.vpn.zomans.com** — `#1182864` · Eternal · $350 · ▲99
  > I could also use this in case your domain whitelists your own domain for OAuth, or if there are cookies scoped to the entire domain.
- **Subdomain takeover of resources.hackerone.com** — `#863551` · HackerOne · $500 · ▲95
  > I just went to https://resources.hackerone.com/ and it shows an error "Non-hub domain, The URL you've accessed does not provide a hub.
- **Subdomain takeover on wfmnarptpc.starbucks.com** — `#388622` · Starbucks · $0 · ▲91
  > https://0xpatrik.com/subdomain-takeover-basics/
- **Subdomain Takeover** — `#180393` · Paragon Initiative Enterprises · $0 · ▲83
  > http://blog.detectify.com/post/100600514143/hostile-subdomain-takeover-using-heroku-github-desk
- **Subdomain takeover in Gitlab pages** — `#2523654` · GitLab · $0 · ▲79
  > I did some tests with gitlab.com domains, `docs-dev.gitlab.com` worked correctly.
- **Subdomain takeover at signup.uber.com** — `#197489` · Uber · $0 · ▲79
  > The domain `signup.uber.com` was pointing to an unclaimed Netlify domain, allowing an attacker to take over the subdomain.
- **Subdomain takeover #2  at info.hacker.one** — `#209004` · HackerOne · $0 · ▲78
  > utf8=%E2%9C%93& method=put&authenticity token=1FSc6oHzQZPfCrlSKHCSXqwyCRn5q7YxTbkva6wQ2oI%3D&page%5Bdescription%5D=test&page%5Bdomain%5D= anydomain.com &page%5Bpath%5D=full-takeover
- **Subdomain Takeover due to ████████ NS records at us-east4.37signals.com** — `#1342422` · Basecamp · $0 · ▲77
  > http://nagli.us-east4.37signals.com/takeover.html
- **Subdomain takeover due to unclaimed Amazon S3 bucket on a2.bime.io** — `#121461` · Bime · $0 · ▲77
  > If you need me to release `a2.bime.io` as an S3 bucket, let me know and I'll delete the bucket.
- **Subdomain Takeover on demo.greenhouse.io pointing to unbouncepages** — `#407355` · Greenhouse.io · $0 · ▲76
  > https://labs.detectify.com/2014/10/21/hostile-subdomain-takeover-using-herokugithubdesk-more/
- **Subdomain takeover on a subdomain under firefox.com** — `#2899858` · Mozilla · $500 · ▲75
  > We could however, use the domain to block access of individual user by setting some large cookies, see for example www.firefox.com after setting 100kb of cookies via http://████/large-cookies.html
- **Subdomain takeover of main domain of https://www.cyberlynx.lu/** — `#1256389` · Acronis · $100 · ▲70
  > I found one of your subdomains which is `www.cyberlynx.lu` (One of your Acquisition) is pointing towards
- **Subdomain takeover on rider.uber.com due to non-existent distribution on Cloudfront** — `#175070` · Uber · $0 · ▲69
  > https://labs.detectify.com/2016/10/05/the-story-of-ev-ssl-aws-and-trailing-dot-domains/
- **Subdomain Takeover Via unclaimed Heroku Instance tim-exclusive.shopify.com** — `#424669` · Shopify · $500 · ▲68
  > https://www.dropbox.com/s/0p6dqz3rwbx2wxn/Screenshot%202018-10-16%2011.30.52.png?dl=0
- **[ addons-preview-cdn.mozilla.net ] A subdomain takeover is available via unregistered domain in Fastly** — `#2706358` · Mozilla · $500 · ▲66
  > Screenshot of [http://addons-preview-cdn.mozilla.net/haveanicetakeover-poc.html](http://addons-preview-cdn.mozilla.net/haveanicetakeover-poc.html?x) displaying custom content
- **Subdomain takeover ████████.mil** — `#2499178` · U.S. Dept Of Defense · $0 · ▲64
  > The subdomain `█████.mil` is pointing to `peosol-lg.███████.`, the domain `██████` is currently available for registration as can be seen at https://www.godaddy.com/nl-nl/domainsearch/find?domainToCheck=█████
- **Bug Report #23JAN136 (subdomain takeover via shopify )** — `#1851895` · Mars · $0 · ▲63
  > This type of vulnerability occurred when DNS records continued to point to external services (in this case, Shopify) that were no longer actively managed by the organization, allowing attackers to claim the unused service and gain control over the subdomain.
- **Subdomain Takeover Via via Dangling NS records on Amazon Route 53 http://api.e2e-kops-aws-canary.test-cncf-aws.canary.k8s.io** — `#746000` · Kubernetes · $250 · ▲62
  > https://web.archive.org/web/20191125154616/http://api.e2e-kops-aws-canary.test-cncf-aws.canary.k8s.io/

## Payload fragments observed

Recurring payloads from this class's writeups. Adapt, don't paste blindly.

| Seen | Fragment |
|---:|---|
| 4× | `{REDACTED}.data.gov` |
| 3× | `smb_send_open()` |
| 3× | `req->path` |
| 3× | `smbc->share` |
| 2× | `smb_parse_url_path()` |
| 2× | `Curl_conn_free()` |
| 2× | `smb_conn_dtor()` |
| 1× | `*@devrel.roblox.com` |
| 1× | `% dig +short fr1.vpn.zomans.com / 52.47.57.107 / % curl fr1.vpn.zomans.com / <!-- hackerone.com/ian -->` |
| 1× | `% dig +short v.zego.com / 52.214.138.192 / % curl v.zego.com / <!-- hackerone.com/ian -->` |
| 1× | `Force HTTPS (requires valid certificates)` |
| 1× | `ASAN_OPTIONS=detect_leaks=0 LD_LIBRARY_PATH=./lib/.libs \ / ./src/.libs/curl -u guest:guest \ / "smb://127.0.0.1:5445/share1/file1" -o /dev/` |
| 1× | `strlen(req->path)` |
| 1× | `smbc->share = strdup(path)` |
| 1× | `req->path = slash` |
| 1× | `url_find_or_create_conn()` |
| 1× | `free(smbc->share)` |
| 1× | `smb_request_state()` |
| 1× | `% curl https://s3.amazonaws.com/affirm-prod-www-cms████████/index.html / <!-- taken over by hackerone.com/ian bugcrowd.com/iangcarroll ian@l` |
| 1× | `alert(document.domain)` |

## Parameters observed

`_method` · `authenticity_token` · `domainToCheck` · `conversationId` · `pageSize` · `domain` · `state` · `dl` · `button` · `id`

## Case studies

### Subdomain Takeover to Authentication bypass
`#335330` · Roblox · $0 · critical · 2020-04-23 · ▲783
> ----------- Due to unclaimed or expired Hubspot instance an attacker is able to claim and serve content from devrel.roblox.com and perform different kind of attacks which i shared in impact section.

### Subdomain takeover of datacafe-cert.starbucks.com
`#665398` · Starbucks · $0 · high · 2019-08-28 · ▲311
> Summary: The subdomain datacafe-cert.starbucks.com had an CNAME record pointing to an unclaimed Azure webservice. This is a high severity security issue because an attacker can register the subdomain on Azure and therefore can own the subdomain datacafe-cert.starbucks.com. Description: The dangling CNAME record of datacafe-cert.starbucks.com is pointing to s00397nasv101-datacafe-cert.azurewebsites.net which was not claimed by you.

### Authentication bypass on auth.uber.com via subdomain takeover of saostatic.uber.com
`#219205` · Uber · $0 · critical · 2017-07-13 · ▲183
> This is not a standard vulnerability, but a chain of two more exotic vulnerabilities leading to a full authentication bypass of your SSO login system at auth.uber.com (via saostatic.uber.com). The root cause of this authentication bypass is two-fold: 1. Subdomain saostatic.uber.com was pointing to Amazon Cloudfront CDN, but the hostname was not registered there anymore. This allowed me to fully takeover this domain.

### Subdomain takeover of storybook.lystit.com
`#779442` · Lyst · $1,000 · high · 2020-01-22 · ▲163
> The subdomain storybook.lystit.com had an CNAME record pointing to an unclaimed S3 bucket. This is a high severity security issue because an attacker can register the bucket on AWS and therefore can serve her own content on the subdomain. This allows for various attacks.

### Hacker.One Subdomain Takeover
`#159156` · HackerOne · $0 · low · 2016-09-20 · ▲154
> This report is about domain takeover of hacker.one via instapage 0day issue which i just found .

## Wordlists

Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.

| File | Entries |
|---|---:|
| `~/.local/share/hackerone-reports/wordlists/paths_subdomain-takeover.txt` | 81 |
| `~/.local/share/hackerone-reports/wordlists/params_subdomain-takeover.txt` | 10 |
| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |
| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |

```sh
W=~/.local/share/hackerone-reports/wordlists
ffuf -u https://target/FUZZ -w $W/paths_subdomain-takeover.txt \
     -mc all -fc 404 -fs 0 -rate 40
ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_subdomain-takeover.txt \
     -mr 'canary|error|invalid|not found' -rate 40
```

## Nuclei

Enumerate subdomains first (subfinder/amass), then run the takeover templates against the resolved host list.

```sh
nuclei -u https://target -tags takeover \
       -severity low,medium,high,critical -rl 40 -o nuclei_subdomain-takeover.txt
nuclei -u https://target -t ~/nuclei-templates/http/takeovers \
       -rl 40 -o nuclei_subdomain-takeover_takeovers.txt
# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'
```

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

## Query the corpus

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class subdomain-takeover --limit 20
python3 ~/.local/share/hackerone-reports/h1.py stats --class subdomain-takeover
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```

Search by technology, endpoint, parameter, or program. Examples:

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class subdomain-takeover
python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class subdomain-takeover --min-bounty 1000
```

## Related

- `hackerone-info-disclosure` (1,827 reports)
- `hackerone-xss` (2,569 reports)

## Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.
