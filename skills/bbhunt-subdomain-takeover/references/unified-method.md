# Unified upstream methodology

Collected from every contributing repository skill. Deduplicated by content hash; full originals are preserved in `references/upstream-*.md`.

## Discovery and hunting method

### Quick wins

Start here. These are the highest-yield tests for this class.

- Enumerate subdomains and resolve CNAME/A records to third-party services.
- Check for unclaimed resources: S3, GitHub Pages, Heroku, Azure, Fastly, Shopify, status pages.
- Confirm the dangling fingerprint before claiming.
- Assess impact: cookie scope, CSP allowlists, OAuth redirect URIs, email.

### Deeper checklist

- Enumerate subdomains and resolve CNAME/A records to third-party services.
- Check for unclaimed resources: S3, GitHub Pages, Heroku, Azure, Fastly, Shopify, status pages.
- Confirm the dangling fingerprint (NXDOMAIN/claim page) before claiming.
- Assess impact: cookie scope, CSP allowlists, OAuth redirect URIs, email.
- Claim only within scope and with permission; never squat third-party brands.

### Step-by-Step Hunting Methodology

1. **Enumerate all subdomains** for the target using passive + active sources:
   - `subfinder -d target.com -all`
   - `amass enum -passive -d target.com`
   - `assetfinder --subs-only target.com`
   - Certificate transparency: `crt.sh/?q=%.target.com`

2. **Resolve all subdomains** and flag those with:
   - NXDOMAIN responses
   - CNAME pointing to a third-party provider
   ```bash
   cat subdomains.txt | dnsx -a -cname -o resolved.txt
   ```

3. **Cross-reference CNAMEs** against known vulnerable provider fingerprints using `nuclei` or `subjack`:
   ```bash
   subjack -w subdomains.txt -t 100 -timeout 30 -ssl -c fingerprints.json
   nuclei -l subdomains.txt -t takeovers/
   ```

4. **Manual verification** for each flagged subdomain:
   - `dig CNAME subdomain.target.com` — confirm CNAME exists
   - `dig A <cname-target>` — confirm NXDOMAIN or no resolution
   - `curl -sk https://subdomain.target.com` — check for provider error string

5. **Confirm claimability** — attempt to register the resource:
   - GitHub Pages: check if `<username>.github.io/<repo>` or org page is unclaimed
   - GitLab Pages: check project namespace
   - S3: attempt `aws s3api create-bucket --bucket <bucketname>`
   - UserVoice/Zendesk/WordPress: visit registration URL
   - Fastly: check if origin hostname is unregistered

6. **Claim the resource** (only enough to prove control — do NOT serve malicious content):
   - Create a minimal index page with your HackerOne username and a timestamp
   - Take screenshot showing your content served on `subdomain.target.com`

7. **Document the chain**: CNAME record → provider target → unclaimed resource → your content

8. **Assess impact escalation**:
   - Does the subdomain appear in OAuth redirect allowlists?
   - Does it share cookies with parent domain (`domain=.target.com`)?
   - Is it referenced in the app's CSP?
   - Can it receive authenticated API calls?

9. **Write report** before releasing the claim (some programs want to verify first)

---

### A. Discovery checklist — concrete places, params, headers, infra signals to look

- Build the candidate set from multiple independent sources: CT logs (crt.sh, censys), passive DNS (SecurityTrails, RiskIQ, DNSDB, VirusTotal), Chaos, and live CNAME/A/AAAA/ALIAS/ANAME/MX/NS enumeration. Old CNAMEs in historical DNS are a high-yield source — the resource was deleted but the record survived.
- Confirm wildcards vs explicit records before triaging. A `*.example.com` wildcard CNAME to a third party lets an attacker generate *arbitrary* subdomains pointing at their page, amplifying impact; it also creates false positives when a scanner assumes an explicit record exists.
- Provider fingerprints to match in HTTP body, TLS cert, or DNS error (from can-i-take-over-xyz and nuclei `takeover` templates): GitHub Pages ("There isn't a GitHub Pages site here"), S3 ("NoSuchBucket" / "The specified bucket does not exist"), Fastly ("Fastly error: unknown domain"), Azure ("Web App - Unavailable" / `cloudapp.azure.com`, `azurewebsites.net`, `blob.core.azure.com`), Vercel (`cname.vercel-dns.com`, "404 Not Found - Request ID"), Heroku, Netlify, Zendesk, Shopify, Atlassian, ReadMe, Intercom, Statuspage, SurveyGizmo, Tave, and `NXDOMAIN` providers.
- Check 2026-specific surfaces: Microsoft Azure DevOps `cloudapp.azure.com` regional-pool re-issue (paired with wildcard `reply_to` can yield 1-click OAuth ATO), Zendesk help-desk takeover -> email interception -> password-reset chain, Vercel `cname.vercel-dns.com` deleted-project takeover, S3 dangling-bucket cookie-scope abuse.
- Look beyond CNAME: dangling **NS** delegation ("Sitting Ducks") where the parent still delegates to a provider that no longer hosts the zone. This is higher impact (whole-zone control) and is often missed by CNAME-only scanners.
- Check MX/email-chain targets: DKIM CNAMEs, SPF `include:` of dead domains, MX pointing at a lapsed provider. An attacker controlling the email path can intercept password-reset mail for the parent brand.
- Map downstream amplifiers immediately: does the taken-over host appear in OAuth `redirect_uri` allowlists, CSP `script-src`, CORS ACAO regexes, cookie `Domain=` scope, or SAML/OIDC discovery? These turn a "hosting" finding into ATO/XSS/data theft.
- Note OOB signal for blind cases: DNS resolution alone may succeed while HTTP returns a generic error. Verify claimability at the provider, not just the HTTP response.

## Signals and surfaces

### Signal

- Reports: **196** · paid: **31**
- Median bounty **$350** · p90 **$1,000** · max **$3,000** · total **$15,040**
- Median upvotes **25**

### Where it pays

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

### Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`DNS` `CNAME` `A` `NS` `MX` `TXT`

### Crown Jewel Targets

Subdomain takeover is high-value because it allows an attacker to serve content from a **trusted, company-owned domain** — bypassing browser same-origin trust, phishing filters, and user skepticism simultaneously.

**Highest payout contexts:**
- Subdomains of major SaaS brands (Shopify, Snapchat, Mozilla, Yelp) where the trusted domain has user session context
- CDN-backed subdomains (Fastly, CloudFront) where CNAME points to unclaimed origins
- Third-party service integrations: UserVoice, WordPress.com, GitHub Pages, GitLab Pages, Heroku, Zendesk
- Preview/staging/dev subdomains (`new.`, `preview.`, `course.`, `delivery.`, `addons-preview.`) — abandoned after feature launches
- Subdomains used for OAuth redirect URIs or SSO endpoints — these pay highest

**Asset types that matter most:**
- CNAME records pointing to deprovisioned third-party services
- NS delegations to abandoned zones
- A records pointing to unallocated cloud IPs (less common)
- GitLab/GitHub Pages with unclaimed project namespaces

---

### Attack Surface Signals

**DNS signals:**
- `CNAME` pointing to `*.github.io`, `*.gitlab.io`, `*.fastly.net`, `*.herokudns.com`, `*.wordpress.com`, `*.uservoice.com`, `*.zendesk.com`, `*.s3.amazonaws.com`, `*.azurewebsites.net`, `*.netlify.app`
- NXDOMAIN or `SERVFAIL` on the CNAME target while the parent record still exists
- NS records delegating to registrars where the zone is no longer registered

**HTTP response signals:**
- `"There isn't a GitHub Pages site here"`
- `"NoSuchBucket"` (S3)
- `"The specified bucket does not exist"`
- `"No such app"` (Heroku)
- `"Sorry, this shop is currently unavailable"` (Shopify)
- `"This UserVoice subdomain is available"`
- `"Do you want to register"` (any domain parking page)
- HTTP 404 with provider-specific error templates
- Fastly: `"Fastly error: unknown domain"`
- `"404 Web Site not found"` (Azure App Service)

**Tech stack signals:**
- Response headers: `X-Served-By: cache-*` (Fastly), `X-GitHub-Request-Id`, `Server: Netlify`
- `CNAME` chain resolving to provider infrastructure but returning provider 404
- SSL cert issued to provider wildcard (`*.fastly.net`) rather than company domain

---

## Techniques, payloads and bypasses

### Payloads & probes

- CNAME -> `foo.s3.amazonaws.com` (NoSuchBucket)
- CNAME -> `foo.github.io` (404 repo)
- CNAME -> `foo.herokuapp.com` (No such app)
- CNAME -> `foo.statuspage.io` / `foo.zendesk.com`

### Bypass tricks

- Look for forgotten staging/dev subdomains and wildcard DNS.
- Check NS delegation to abandoned providers.

### Techniques from real reports

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

### Payload fragments observed

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

### Subdomain Takeover to Authentication bypass

`#335330` · Roblox · $0 · critical · 2020-04-23 · ▲783
> ----------- Due to unclaimed or expired Hubspot instance an attacker is able to claim and serve content from devrel.roblox.com and perform different kind of attacks which i shared in impact section.

### Authentication bypass on auth.uber.com via subdomain takeover of saostatic.uber.com

`#219205` · Uber · $0 · critical · 2017-07-13 · ▲183
> This is not a standard vulnerability, but a chain of two more exotic vulnerabilities leading to a full authentication bypass of your SSO login system at auth.uber.com (via saostatic.uber.com). The root cause of this authentication bypass is two-fold: 1. Subdomain saostatic.uber.com was pointing to Amazon Cloudfront CDN, but the hostname was not registered there anymore. This allowed me to fully takeover this domain.

### Common Root Causes

1. **Service offboarding without DNS cleanup** — Developer removes a Heroku app, UserVoice account, or WordPress site but never deletes the CNAME record. DNS lives forever; service does not.

2. **Staging/preview infrastructure abandoned post-launch** — `course.`, `new.`, `preview.`, `beta.` subdomains provisioned for a product launch, pointed at a third-party, then forgotten when the campaign ends.

3. **Subdomain provisioned by a third-party team** — Marketing sets up a UserVoice or Zendesk subdomain via IT, product sunset kills it, but DNS is owned by engineering who doesn't know.

4. **CDN misconfiguration without origin validation** — Fastly and similar CDNs historically allowed any domain to "claim" a backend hostname by creating a service pointing to it. Unregistered origin hostnames become claimable.

5. **GitHub/GitLab Pages namespace not reserved** — Organization renames, user accounts deleted, or repos made private/deleted while the Pages CNAME still points to the old namespace.

6. **Wildcard DNS entries** — `*.target.com` pointing to a cloud provider means *any* unclaimed subdomain potentially resolves to claimable infrastructure.

7. **Acquired/divested company DNS not cleaned** — Post-acquisition, former brand subdomains (like `oberlo.com` under Shopify) retain CNAMEs to services that are no longer paid for.

---

### Operator-level pattern

The five chains above are exhaustive in practice — virtually every senior-tier subdomain-takeover payout maps to one of them. Before reporting any takeover, run through the checklist:

1. **OAuth `redirect_uri` allowlist** — does the taken-over host appear? → Chain 1, Critical.
2. **Parent-domain cookies** — does the main app set `Domain=.target.com`? → Chain 2, High.
3. **CSP `script-src`** — does the taken-over host appear in the allowlist? → Chain 3, Critical.
4. **CORS allowlist** — does any regex match the taken-over host? → Chain 4, High.
5. **Email DNS (DKIM selector / SPF include)** — does the taken-over host appear? → Chain 5, High.

If none apply, file at Low/Informational. **Do not file at Critical without demonstrating one of these chains** — triagers downgrade fast otherwise.

Cross-references:
- `oauth-oidc` — Chain 1 (`redirect_uri` bypass class)
- `auth-bypass` Duende BFF Attack Class 2 — Chain 2 (cookie scoping)
- `xss` Chain 4 — Chain 3 (CSP bypass via trusted-origin JS)
- `api-misconfig` CORS section — Chain 4
- `offensive-osint` email-security section — Chain 5

---

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- Detection and triage loop:
  ```
  dig sub.target.com CNAME +short
  curl -i https://sub.target.com        # match provider fingerprint
  nuclei -u https://sub.target.com -tags takeover
  ```
  Then consult can-i-take-over-xyz for the exact claim steps and whether provider ownership validation exists.
- Confirm claimability in a controlled way: attempt to add the custom domain to a provider account you own. If the provider challenges ownership (TXT file, `asuid` record for Azure, GitHub Pages CNAME verification), the dangling record is **not** exploitable — do not report it as a takeover.
- Wildcard CNAME amplification: if `*.target.com` CNAMEs to `<user>.github.io`, register the third-party name and any arbitrary prefix becomes attacker-controlled content under the victim domain.
- Sitting Ducks / lame delegation — read the parent-side referral and probe each delegated NS directly:
  ```
  zone=delegated.example.com; parent=example.com
  pns=$(dig +short "$parent" NS | head -1)
  dig @"${pns%.}" "$zone" NS +norecurse +noall +answer +authority
  for ns in $(dig @"${pns%.}" "$zone" NS +norecurse +noall +authority | awk '$4=="NS"{print $5}'); do
    dig @"${ns%.}" "$zone" SOA +norecurse +noall +comments +answer +authority
  done
  ```
  Look for `aa` + `SOA`; absence indicates broken delegation. Creating the zone can disrupt production — only attempt with explicit permission, and prove with a random TXT record.
- Chain recipes (prove the amplifier, not just the hosting):
  - OAuth `redirect_uri` allowlist -> authorization-code theft -> 1-click ATO.
  - Sibling subdomain + `Domain=.example.com` cookie -> session fixation on the parent app (host-only cookies are NOT sent to the sibling — verify scope).
  - CSP `script-src` includes the host -> persistent stored XSS on the main app.
  - CORS ACAO matches the host -> credentialed cross-origin API read.
  - Email DNS (MX/DKIM/SPF) -> spoofed mail trusted by the parent brand.
- Add legitimacy with a valid TLS cert (Let's Encrypt) for the claimed host — increases phishing credibility but is not itself the finding.

### Payload & Detection Patterns

**Bulk CNAME extraction and NXDOMAIN detection:**
```bash
# Extract CNAMEs and check if target resolves
while read sub; do
  cname=$(dig +short CNAME "$sub" | head -1)
  if [ -n "$cname" ]; then
    result=$(dig +short A "$cname")
    if [ -z "$result" ]; then
      echo "[POTENTIAL] $sub -> $cname (NXDOMAIN)"
    fi
  fi
done < subdomains.txt
```

**Nuclei takeover scan:**
```bash
nuclei -l subdomains.txt -t ~/nuclei-templates/http/takeovers/ -severity medium,high,critical
```

**subjack with SSL:**
```bash
subjack -w subdomains.txt -t 100 -timeout 30 -ssl -c $GOPATH/src/github.com/haccer/subjack/fingerprints.json -v
```

**Provider fingerprint grep patterns:**
```bash
curl -sk "https://$subdomain" | grep -iE \
  "there isn't a github pages|no such bucket|no such app|this uservoice|fastly error: unknown domain|do you want to register|sorry, this shop|project not found|404 not found|unclaimed"
```

**Check if subdomain is in scope for cookies (shared parent domain):**
```bash
curl -Isk "https://target.com" | grep -i "set-cookie" | grep "domain=.target.com"
```

**Fastly-specific detection:**
```bash
curl -sI "https://subdomain.target.com" -H "Host: subdomain.target.com" | grep -i "fastly\|x-served-by\|x-cache"
curl -sk "https://subdomain.target.com" | grep -i "fastly error"
```

**S3 unclaimed bucket check:**
```bash
aws s3api head-bucket --bucket <extracted-bucket-name> 2>&1 | grep -i "NoSuchBucket\|403\|404"
```

**GitLab Pages specific:**
```bash
dig CNAME sub.target.com
# If pointing to *.gitlab.io — visit the gitlab.io URL directly
# 404 from gitlab.io project = claimable
```

---

### Bypass Techniques

**Defense: Manual fingerprint review before publishing**
- Bypass: Use alternative error strings — providers change their 404 pages. Maintain an up-to-date fingerprint list. Some providers show *different* errors on HTTP vs HTTPS. Test both.

**Defense: Scope restrictions (only main domain in scope)**
- Bypass: Check program's asset list carefully — `*.target.com` wildcards often include subdomains implicitly. Escalate impact to get it in scope.

**Defense: "Can't reproduce" responses due to timing**
- Bypass: Screenshot immediately after claiming. Record a video walkthrough. The window can be short for popular subdomains.

**Defense: HTTPS certificate mismatch blocking proof**
- Bypass: Some providers (GitHub Pages, Netlify) auto-provision TLS for claimed domains. Others don't — show HTTP takeover and note TLS would be resolved by provider on claim.

**Defense: Provider-side validation (Fastly verifying domain ownership)**
- Bypass: Some Fastly configurations don't validate origin hostnames. Check if the CNAME target is a generic Fastly backend hostname vs. a customer-verified one. Try claiming anyway and observe behavior.

**Defense: Rate limiting on subdomain enumeration**
- Bypass: Use passive-only sources (SecurityTrails, Shodan, crt.sh, VirusTotal) to avoid triggering WAF/IDS. DNS resolution doesn't touch the web server.

**Defense: Program claims "low severity / no impact"**
- Bypass: Demonstrate same-origin cookie theft, OAuth redirect abuse, or CSP bypass to escalate. Find if the subdomain is listed in any `postMessage` `targetOrigin` checks in JS.

---

### Operator-level pattern

The five chains above are exhaustive in practice — virtually every senior-tier subdomain-takeover payout maps to one of them. Before reporting any takeover, run through the checklist:

1. **OAuth `redirect_uri` allowlist** — does the taken-over host appear? → Chain 1, Critical.
2. **Parent-domain cookies** — does the main app set `Domain=.target.com`? → Chain 2, High.
3. **CSP `script-src`** — does the taken-over host appear in the allowlist? → Chain 3, Critical.
4. **CORS allowlist** — does any regex match the taken-over host? → Chain 4, High.
5. **Email DNS (DKIM selector / SPF include)** — does the taken-over host appear? → Chain 5, High.

If none apply, file at Low/Informational. **Do not file at Critical without demonstrating one of these chains** — triagers downgrade fast otherwise.

Cross-references:
- `hunt-oauth` — Chain 1 (`redirect_uri` bypass class)
- `hunt-auth-bypass` Duende BFF Attack Class 2 — Chain 2 (cookie scoping)
- `hunt-xss` Chain 4 — Chain 3 (CSP bypass via trusted-origin JS)
- `hunt-api-misconfig` CORS section — Chain 4
- `offensive-osint` email-security section — Chain 5

---

## Validation and proof

### Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.

### Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.

---

<!-- ============ PART 2: BUG HUNTER METHODOLOGY (execution + validation) ============ -->

### Gate 0 Validation

1. **What can the attacker DO right now?**
   Can you register the unclaimed resource (GitHub repo, S3 bucket, Heroku app, UserVoice account) and serve arbitrary content — including phishing pages, credential harvesters, or malicious scripts — under the target's trusted domain name?

2. **What does the victim LOSE?**
   Users lose trust and safety: they see a company-branded URL serving attacker content. The company loses brand integrity, potentially leaks session cookies if the subdomain is in `domain=.target.com` scope, and may have OAuth/SSO flows hijacked. Depending on CSP configuration, XSS against the main application may be possible.

3. **Can it be reproduced in 10 minutes from scratch?**
   - `dig CNAME subdomain.target.com` → confirms CNAME to provider
   - `curl -sk https://subdomain.target.com` → confirms provider error string
   - Visit provider registration page → confirms namespace is available
   - Screenshots of all three steps = reproducible in under 10 minutes

If you cannot show the provider resource is *currently unclaimed and claimable*, it is not a valid report.

---

### C. Validation / proof bar — how to confirm and avoid false positives

- A fingerprint string alone is not a finding. The proof bar is: content you control is served from the victim subdomain, demonstrated with an arbitrary file (e.g. a plain-text marker) on an authorized/owned test basis.
- Before claiming, verify the provider actually permits re-registration. Ownership verification (Azure `asuid`, GitHub TXT/CNAME checks) and non-reclaimable names produce false positives. The ice/IONIX data shows huge numbers of *flagged* dangling records but far fewer *validated* ones.
- Rule out wildcard/HTTP-default false positives: confirm the DNS record is explicit, that the response is the provider's "unclaimed" page (not a parked/default page), and that a second independent check agrees.
- Gate the impact claim: if you say ATO via `redirect_uri`, show a real authorization code delivered to the claimed host. If you say CORS read, show credentialed data returned. If you say cookie scope, show the cookie actually attached to a request to the sibling.
- Host-only cookies are not sent to subdomains; `HttpOnly` does not stop a browser from attaching a `Domain`-scoped cookie. State the exact cookie attributes in the report.
- For NS/Sitting Ducks, destructive risk is real — lower TTL, use an isolated test zone where possible, and restore the provider state. Never create a zone for production infrastructure without written authorization.
- Map the finding to impact honestly: a claimable help-desk subdomain that can intercept reset mail is Critical; a claimable static host with no trust relationships is Medium at best.

- Canary the takeover proof with a uniquely named marker file and record the timestamp; programs require evidence content is *currently* served, not just that the record looks dangling.
- Track provider status over time: services move between "vulnerable", "edge case", and "mitigated" as they add domain-ownership checks (can-i-take-over-xyz tracks this via CI verification). Re-validate old leads before reporting.
- Check historical CNAMEs from passive DNS even when the current record is healthy — a deleted resource may still be claimable under a different subdomain the org forgot.

## Escalation and related chains

### Escalation chains

- Subdomain takeover -> cookie theft.
- Subdomain takeover -> OAuth redirect.

### Chains & Compositions (Senior Hunting)

Subdomain takeover by itself is Low-Medium / Informational on most mature programs — defacement of a non-business-critical subdomain is unsexy. The chain payout is 10-100x the standalone. **Every takeover should be evaluated against the five chains below before submission.** If none apply, you have a Low; if one applies, you have a High; if two compose, you have a Critical.

### Chain 1 — Takeover + OAuth `redirect_uri` Whitelist → Auth-Code Theft → 1-Click ATO

- **A.** Enumerate the OAuth `redirect_uri` allowlist via `/oauth/authorize` flow. Look for any wildcard `*.target.com` or any takeover-candidate hostname in the static list (e.g., `feedsprod.feeds.visualstudio.com`, `legacy.target.com`).
- **B.** Find a takeover-able subdomain in that allowlist. Claim it via the provider's onboarding (Vercel project, Azure cloudapp regional pool, S3 bucket, Heroku app, Zendesk, Shopify storefront — see the Disclosed Report Citations above).
- **C.** Host an OAuth callback receiver on the claimed subdomain. Send victim to `/oauth/authorize?redirect_uri=https://legacy.target.com/cb&response_type=code&client_id=<legit>`. Victim's browser already has session → auth happens transparently → auth code lands on attacker host. Exchange via token endpoint → ATO.
- **Impact:** Persistent 1-click ATO across every user of the target. OAuth flow is implicit-to-the-user (no consent screen if previously consented), so requires only a single click on attacker's link.
- **Real shape:** Microsoft Azure DevOps `cloudapp.azure.com` + wildcard `*.visualstudio.com` reply_to chain (Binary Security, Nov 2022 — Disclosed Report Citation #12). Multiple H1 disclosures on SaaS programs with permissive OAuth allowlists.

### Chain 2 — Takeover at Sibling Subdomain + Cookie-Domain Wildcard → Session Fixation on Parent App

- **A.** Inspect cookies set by the main app (`app.target.com`). If `Set-Cookie` has `Domain=.target.com` (parent-scoped) instead of host-only, cookies bleed to every sibling subdomain — including taken-over ones.
- **B.** Take over any sibling (`legacy.target.com`, `feedback.target.com`, `assets.target.com`). The taken-over host can now `Set-Cookie` for the parent domain.
- **C.** Plant `Set-Cookie: SESSIONID=<attacker_session>; Domain=.target.com` via a script on the taken-over host. Victim visits `app.target.com` with attacker's session cookie attached. Server treats them as the attacker's account → session-fixation ATO.
- **Impact:** ATO without OAuth or password reset — pure cookie-domain bleed. Especially effective when the parent app uses a non-`__Host-` prefixed session cookie.
- **Real shape:** Discussed extensively in `auth-bypass` Duende BFF Attack Class 2 (cookie-domain wildcarding turns subdomain takeover into session fixation). Pattern class: S3-bucket-takeover combined with parent-scoped (`Domain=.target.com`) cookies.

### Chain 3 — Takeover + CSP `script-src` Includes the Taken-Over Host → Persistent Stored XSS on Main App

- **A.** Inspect CSP header on the main app's HTML response. Look for `script-src 'self' assets.target.com cdn.target.com legacy.target.com ...`.
- **B.** Take over one of the CSP-allowlisted subdomains (especially common: stale CNAMEs to deleted CDNs, deleted Vercel/Netlify projects, archived analytics services).
- **C.** Host attacker-controlled JavaScript at the takeover host. Every page load on the main app fetches `<script src="//taken-over-host/x.js">` because the host is on the CSP allowlist. JS executes with main-app origin — full session access, can call any same-origin API.
- **Impact:** Stored XSS-equivalent on every page of the main app, persistent until the CSP is updated. Bypasses every input sanitiser because the JS source is "trusted" per CSP.
- **Real shape:** Sifchain `proxies.sifchain.finance` Vercel takeover — Disclosed Report Citation #14 (web3 phishing); pattern documented in multiple H1 disclosures 2020-2024.

### Chain 4 — Takeover + CORS `Access-Control-Allow-Origin` Regex Match → Credentialed Cross-Origin API Read

- **A.** Inspect the API's CORS configuration. Look for any regex / wildcard / suffix-match in `Access-Control-Allow-Origin` that includes `*.target.com` or `target.com.*` (the second is a common bug).
- **B.** Take over any subdomain that the CORS regex would accept (or register a new `target.com.attacker.com` host if suffix-match is broken).
- **C.** Attacker page hosted on the taken-over subdomain issues `fetch('https://api.target.com/account', {credentials:'include'})`. CORS preflight passes. Server returns credentialed response. Attacker's JS reads it.
- **Impact:** Mass cross-tenant API read with credentials — sessions, PATs, account data, billing records — all reachable from a single attacker page.
- **Real shape:** Multiple disclosed cases; cross-refs `api-misconfig` CORS subsection. Pairs with `misc` step 1 (CORS regex enumeration).

### Chain 5 — Takeover at Email DNS (DKIM / SPF / MX) → Email Spoofing → Phishing Trusted by Parent Brand

- **A.** Enumerate the target's email DNS — DKIM selectors (`selector1._domainkey.target.com`), SPF includes (`include:_spf.takeover-candidate.com`), MX records (`mx.target.com → defunct-provider.example`).
- **B.** Take over any DKIM-selector or SPF-include host. Now the attacker can publish DKIM/SPF records that authorise their own server to send mail "from" `@target.com`.
- **C.** Send phishing email `From: support@target.com` to victim. Recipient mail server passes SPF + DKIM checks (because the takeover server is now authorised). Email lands in inbox with `target.com` brand, no security warning.
- **Impact:** Highly-effective phishing campaign exploiting the parent brand. Victims trust the email because every authentication check passes. Credential harvesting, BEC fraud, supply-chain access.
- **Real shape:** Multiple historical disclosures on DKIM selector takeover / SPF include chain hijacking. Cross-refs DMARC / SPF / DKIM section in `offensive-osint`.

### Related Skills & Chains

- **`cloud-misconfig`** — Most stale CNAMEs point at deleted cloud assets (S3, CloudFront, Heroku). Chain primitive: Cloud misconfig (S3 deleted) + `subdomain-takeover` → unclaimed CNAME points to bucket → claim bucket name → full subdomain control.
- **`oauth-oidc`** — A takeover on an OAuth `redirect_uri` host = persistent ATO across the entire SSO surface. Chain primitive: Subdomain takeover at `auth.target.com` + OAuth redirect_uri allowlist → auth code theft → ATO every user that re-authenticates.
- **`api-misconfig`** — CORS regexes routinely allowlist a takeoverable subdomain. Chain primitive: Subdomain takeover + CORS `*.target.com` with credentials → credentialed cross-origin API read → mass IDOR.
- **`xss`** — A claimed subdomain is same-origin to session-cookie-domain siblings. Chain primitive: Subdomain takeover at `feedback.target.com` + cookie scope `.target.com` → JS hosted on takeover host reads main-app cookies → session hijack.
- **`security-arsenal`** — Load the 27+ Subdomain Takeover Fingerprint Table (NoSuchBucket, "no such app", GitHub Pages 404 strings, Heroku, Shopify, Fastly) and the `subzy`/`subjack` automation patterns.
- **`triage-validation`** — Apply the Unique-Marker gate: takeover claim is informational on its own; submit only after publishing a unique HTML marker on the claimed host AND demonstrating a downstream impact (cookie read, OAuth chain, CSP bypass).

### Chain 2 — Takeover at Sibling Subdomain + Cookie-Domain Wildcard → Session Fixation on Parent App

- **A.** Inspect cookies set by the main app (`app.target.com`). If `Set-Cookie` has `Domain=.target.com` (parent-scoped) instead of host-only, cookies bleed to every sibling subdomain — including taken-over ones.
- **B.** Take over any sibling (`legacy.target.com`, `feedback.target.com`, `assets.target.com`). The taken-over host can now `Set-Cookie` for the parent domain.
- **C.** Plant `Set-Cookie: SESSIONID=<attacker_session>; Domain=.target.com` via a script on the taken-over host. Victim visits `app.target.com` with attacker's session cookie attached. Server treats them as the attacker's account → session-fixation ATO.
- **Impact:** ATO without OAuth or password reset — pure cookie-domain bleed. Especially effective when the parent app uses a non-`__Host-` prefixed session cookie.
- **Real shape:** Discussed extensively in `hunt-auth-bypass` Duende BFF Attack Class 2 (cookie-domain wildcarding turns subdomain takeover into session fixation). Pattern class: S3-bucket-takeover combined with parent-scoped (`Domain=.target.com`) cookies.

### Chain 4 — Takeover + CORS `Access-Control-Allow-Origin` Regex Match → Credentialed Cross-Origin API Read

- **A.** Inspect the API's CORS configuration. Look for any regex / wildcard / suffix-match in `Access-Control-Allow-Origin` that includes `*.target.com` or `target.com.*` (the second is a common bug).
- **B.** Take over any subdomain that the CORS regex would accept (or register a new `target.com.attacker.com` host if suffix-match is broken).
- **C.** Attacker page hosted on the taken-over subdomain issues `fetch('https://api.target.com/account', {credentials:'include'})`. CORS preflight passes. Server returns credentialed response. Attacker's JS reads it.
- **Impact:** Mass cross-tenant API read with credentials — sessions, PATs, account data, billing records — all reachable from a single attacker page.
- **Real shape:** Multiple disclosed cases; cross-refs `hunt-api-misconfig` CORS subsection. Pairs with `hunt-misc` step 1 (CORS regex enumeration).

### Related Skills & Chains

- **`hunt-cloud-misconfig`** — Most stale CNAMEs point at deleted cloud assets (S3, CloudFront, Heroku). Chain primitive: Cloud misconfig (S3 deleted) + `hunt-subdomain` → unclaimed CNAME points to bucket → claim bucket name → full subdomain control.
- **`hunt-oauth`** — A takeover on an OAuth `redirect_uri` host = persistent ATO across the entire SSO surface. Chain primitive: Subdomain takeover at `auth.target.com` + OAuth redirect_uri allowlist → auth code theft → ATO every user that re-authenticates.
- **`hunt-api-misconfig`** — CORS regexes routinely allowlist a takeoverable subdomain. Chain primitive: Subdomain takeover + CORS `*.target.com` with credentials → credentialed cross-origin API read → mass IDOR.
- **`hunt-xss`** — A claimed subdomain is same-origin to session-cookie-domain siblings. Chain primitive: Subdomain takeover at `feedback.target.com` + cookie scope `.target.com` → JS hosted on takeover host reads main-app cookies → session hijack.
- **`security-arsenal`** — Load the 27+ Subdomain Takeover Fingerprint Table (NoSuchBucket, "no such app", GitHub Pages 404 strings, Heroku, Shopify, Fastly) and the `subzy`/`subjack` automation patterns.
- **`triage-validation`** — Apply the Unique-Marker gate: takeover claim is informational on its own; submit only after publishing a unique HTML marker on the claimed host AND demonstrating a downstream impact (cookie read, OAuth chain, CSP bypass).

## Tools and wordlists

### Tools

`subfinder` · `amass` · `dnsx` · `nuclei -t takeovers` · `can-i-take-over-xyz`

### Wordlists

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

### Nuclei

Enumerate subdomains first (subfinder/amass), then run the takeover templates against the resolved host list.

```sh
nuclei -u https://target -tags takeover \
       -severity low,medium,high,critical -rl 40 -o nuclei_subdomain-takeover.txt
nuclei -u https://target -t ~/nuclei-templates/http/takeovers \
       -rl 40 -o nuclei_subdomain-takeover_takeovers.txt
# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'
```

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

## Real-world examples

### Real Impact Examples

**Scenario A — Trusted Brand Phishing via Abandoned SaaS (Snapchat/UserVoice)**
An attacker finds `feedback.snapchat.com` CNAME pointing to a UserVoice subdomain. The UserVoice account was cancelled but the DNS record remained. The attacker registers the matching UserVoice subdomain for free, gaining control of `feedback.snapchat.com`. Any user navigating to that URL — perhaps from old bookmarks or Google results — sees attacker-controlled content on a Snapchat-branded domain. Since the domain is trusted by browsers, phishing campaigns sent from this subdomain bypass email security filters that check domain reputation.

**Scenario B — CDN Origin Takeover Enabling Same-Origin Attacks (Mozilla/Fastly)**
`addons-preview-cdn.mozilla.net` had a CNAME pointing to a Fastly origin hostname that was no longer registered to Mozilla's Fastly account. An attacker could create a Fastly service claiming that origin hostname, causing all requests to `addons-preview-cdn.mozilla.net` to be routed to attacker-controlled Fastly infrastructure. Since the subdomain shares the `mozilla.net` domain, it could be leveraged to serve malicious CDN assets that appear to come from Mozilla's infrastructure, potentially bypassing CSP rules that allowlist `*.mozilla.net`.

**Scenario C — Staging Subdomain Abandoned Post-Product Migration (Rails/GitHub Pages)**
`new.rubyonrails.org` was pointed at a GitHub Pages deployment for a website redesign project. After the new site launched and the old GitHub repo was deleted or made private, the DNS CNAME remained. An attacker could fork or create a matching GitHub Pages repository and claim the namespace, serving content under `new.rubyonrails.org`. Because this is the official Ruby on Rails domain, any content served there — including fake download links or malicious gems — carries the full trust of the Rails brand.

---

## Sources and related reading

### Query the corpus

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

### Related

- `hackerone-info-disclosure` (1,827 reports)
- `hackerone-xss` (2,569 reports)

### Related

- `info-disclosure` (1,827 reports)
- `xss` (2,569 reports)

### D. Sources — numbered list of URLs you actually fetched

1. https://hacktricks.wiki/en/pentesting-web/domain-subdomain-takeover.html
2. https://github.com/edoverflow/can-i-take-over-xyz
3. https://www.hackerone.com/blog/guide-subdomain-takeovers-20
4. https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover
5. https://aws.amazon.com/blogs/security/threat-tactic-spotlight-subdomain-takeover
6. https://www.ionix.io/writing-center/how-to-detect-dangling-dns-and-prevent-subdomain-takeovers-in-2026
7. https://firecompass.com/blog-subdomain-takeover-dangling-dns-records

## Additional notes

### Parameters observed

`_method` · `authenticity_token` · `domainToCheck` · `conversationId` · `pageSize` · `domain` · `state` · `dl` · `button` · `id`

### Subdomain takeover of datacafe-cert.starbucks.com

`#665398` · Starbucks · $0 · high · 2019-08-28 · ▲311
> Summary: The subdomain datacafe-cert.starbucks.com had an CNAME record pointing to an unclaimed Azure webservice. This is a high severity security issue because an attacker can register the subdomain on Azure and therefore can own the subdomain datacafe-cert.starbucks.com. Description: The dangling CNAME record of datacafe-cert.starbucks.com is pointing to s00397nasv101-datacafe-cert.azurewebsites.net which was not claimed by you.

### Subdomain takeover of storybook.lystit.com

`#779442` · Lyst · $1,000 · high · 2020-01-22 · ▲163
> The subdomain storybook.lystit.com had an CNAME record pointing to an unclaimed S3 bucket. This is a high severity security issue because an attacker can register the bucket on AWS and therefore can serve her own content on the subdomain. This allows for various attacks.

### Hacker.One Subdomain Takeover

`#159156` · HackerOne · $0 · low · 2016-09-20 · ▲154
> This report is about domain takeover of hacker.one via instapage 0day issue which i just found .

### Disclosed Report Citations (2022-2023)

The following coordinated-disclosure / writeup cases extend this skill with **modern provider fingerprints** (Vercel/Azure cloudapp/Zendesk era) and explicit ATO-chain examples. Citations #12 and #13 are external writeups (not disclosed HackerOne reports) — treat their payout figures as unverified; only #14 has a public H1 report ID.

12. **Microsoft Azure DevOps — Two `cloudapp.azure.com` subdomains + wildcard `*.visualstudio.com` OAuth reply_to → 1-click ATO** ([Binary Security writeup](https://www.binarysecurity.no/posts/2022/11/azure-devops-takeover))
    - Subclass: Azure `cloudapp.azure.com` regional-pool dangling CNAME — chained to ATO
    - ATO chain: **YES** — `app.vssps.visualstudio.com/_signin?reply_to=https://feedsprodwcus0dr.feeds.visualstudio.com/` whitelisted any `*.visualstudio.com`. Attacker claimed the dangling Azure VM hostnames, then crafted sign-in URLs that returned JWT + FedAuth tokens to attacker-controlled endpoints
    - Claim flow: identify dangling `cloudapp.azure.com` CNAME, deploy a free-tier VM in the same Azure region requesting the exact released hostname, Azure re-issues the name first-come-first-serve
    - Year: reported Feb 2021, disclosed Nov 2022 — MSRC explicitly out-of-scope (relied on subdomain takeover), $0

13. **Anonymous H1 — `admin-support.xyz.com` → unclaimed Zendesk → email interception → ATO** ([Writeup by 0xprial](https://0xprial.com/the-art-of-zendesk-hijacking/))
    - Subclass: Zendesk help-desk takeover via `xyzdocs.zendesk.com` host-mapping
    - ATO chain: **YES** — researcher configured email forwarding on the hijacked Zendesk instance, intercepted `support@xyz.com` tickets containing payment info + password-reset emails, then triggered password resets on customer accounts that delivered reset links into the attacker's Zendesk inbox
    - Claim flow: `dig CNAME` returns `xyzdocs.zendesk.com` (unregistered) → register free Zendesk trial → add `xyzdocs` as subdomain → enable host-mapping for `admin-support.xyz.com`
    - Year: 2023 — payout per the 0xprial writeup (blog source; no public HackerOne report ID, treat as unverified)

14. **Vercel deleted-project takeover** — a dangling `cname.vercel-dns.com` CNAME pointing to a removed Vercel project can be re-claimed by deploying a new project under that name.
    - Subclass: Vercel dangling CNAME (`cname.vercel-dns.com`) after project deletion
    - Impact: crypto-DEX phishing — `proxies.` subdomain trusted for RPC proxy routing; attacker could serve malicious wallet-drain JS under a "trusted" subdomain
    - Claim flow: subdomain returns Vercel 404 `DEPLOYMENT_NOT_FOUND` → create free Vercel project → Settings → Domains → add `proxies.sifchain.finance` — Vercel verifies the existing CNAME and auto-issues TLS without out-of-band ownership proof
    - Year: 2022 — Sifchain treated as Critical (web3 phishing vector)

**Fastly CDN dangling-service technique (general, not a single disclosed report):**
- Fingerprint: subdomain returns `Fastly error: unknown domain. Please check that this domain has been added to a service`
- Claim flow: sign up for Fastly free trial → create new CDN service → attach the dangling hostname as the service domain
- Root cause: Fastly historically does not verify CNAME ownership on service-creation; any CNAME pointing into Fastly's anycast can be attached to a fresh service
- Potential ATO chain: chains to CSP-bypass + JS-injection if the parent domain trusts the `assets.`/CDN host for `script-src`

---

## Companion methodology (merged, deduplicated)

Full text of every non-SKILL.md methodology file from the contributing skills — payload banks, technique references, reconnaissance and attack-class guides.

### Companion: hunting / references/payloads.md

# Subdomain Takeover — Combined Field Guide — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

## Payloads & probes



- CNAME -> `foo.s3.amazonaws.com` (NoSuchBucket)

- CNAME -> `foo.github.io` (404 repo)

- CNAME -> `foo.herokuapp.com` (No such app)

- CNAME -> `foo.statuspage.io` / `foo.zendesk.com`



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



## Payload & Detection Patterns



**Bulk CNAME extraction and NXDOMAIN detection:**

```bash

# Extract CNAMEs and check if target resolves

while read sub; do

  cname=$(dig +short CNAME "$sub" | head -1)

  if [ -n "$cname" ]; then

    result=$(dig +short A "$cname")

    if [ -z "$result" ]; then

      echo "[POTENTIAL] $sub -> $cname (NXDOMAIN)"

    fi

  fi

done < subdomains.txt

```



**Nuclei takeover scan:**

```bash

nuclei -l subdomains.txt -t ~/nuclei-templates/http/takeovers/ -severity medium,high,critical

```



**subjack with SSL:**

```bash

subjack -w subdomains.txt -t 100 -timeout 30 -ssl -c $GOPATH/src/github.com/haccer/subjack/fingerprints.json -v

```



**Provider fingerprint grep patterns:**

```bash

curl -sk "https://$subdomain" | grep -iE \

  "there isn't a github pages|no such bucket|no such app|this uservoice|fastly error: unknown domain|do you want to register|sorry, this shop|project not found|404 not found|unclaimed"

```



**Check if subdomain is in scope for cookies (shared parent domain):**

```bash

curl -Isk "https://target.com" | grep -i "set-cookie" | grep "domain=.target.com"

```



**Fastly-specific detection:**

```bash

curl -sI "https://subdomain.target.com" -H "Host: subdomain.target.com" | grep -i "fastly\|x-served-by\|x-cache"

curl -sk "https://subdomain.target.com" | grep -i "fastly error"

```



**S3 unclaimed bucket check:**

```bash

aws s3api head-bucket --bucket <extracted-bucket-name> 2>&1 | grep -i "NoSuchBucket\|403\|404"

```



**GitLab Pages specific:**

```bash

dig CNAME sub.target.com

# If pointing to *.gitlab.io — visit the gitlab.io URL directly

# 404 from gitlab.io project = claimable

```



---

### Companion: hunting / references/techniques.md

# Subdomain Takeover — Combined Field Guide — Technique reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete technique.

---

## Quick wins



Start here. These are the highest-yield tests for this class.



- Enumerate subdomains and resolve CNAME/A records to third-party services.

- Check for unclaimed resources: S3, GitHub Pages, Heroku, Azure, Fastly, Shopify, status pages.

- Confirm the dangling fingerprint before claiming.

- Assess impact: cookie scope, CSP allowlists, OAuth redirect URIs, email.



## Bypass tricks



- Look for forgotten staging/dev subdomains and wildcard DNS.

- Check NS delegation to abandoned providers.



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



## Bypass Techniques



**Defense: Manual fingerprint review before publishing**

- Bypass: Use alternative error strings — providers change their 404 pages. Maintain an up-to-date fingerprint list. Some providers show *different* errors on HTTP vs HTTPS. Test both.



**Defense: Scope restrictions (only main domain in scope)**

- Bypass: Check program's asset list carefully — `*.target.com` wildcards often include subdomains implicitly. Escalate impact to get it in scope.



**Defense: "Can't reproduce" responses due to timing**

- Bypass: Screenshot immediately after claiming. Record a video walkthrough. The window can be short for popular subdomains.



**Defense: HTTPS certificate mismatch blocking proof**

- Bypass: Some providers (GitHub Pages, Netlify) auto-provision TLS for claimed domains. Others don't — show HTTP takeover and note TLS would be resolved by provider on claim.



**Defense: Provider-side validation (Fastly verifying domain ownership)**

- Bypass: Some Fastly configurations don't validate origin hostnames. Check if the CNAME target is a generic Fastly backend hostname vs. a customer-verified one. Try claiming anyway and observe behavior.



**Defense: Rate limiting on subdomain enumeration**

- Bypass: Use passive-only sources (SecurityTrails, Shodan, crt.sh, VirusTotal) to avoid triggering WAF/IDS. DNS resolution doesn't touch the web server.



**Defense: Program claims "low severity / no impact"**

- Bypass: Demonstrate same-origin cookie theft, OAuth redirect abuse, or CSP bypass to escalate. Find if the subdomain is listed in any `postMessage` `targetOrigin` checks in JS.



---
