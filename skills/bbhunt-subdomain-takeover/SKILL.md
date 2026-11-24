---
name: bbhunt-subdomain-takeover
description: "Use for dangling DNS records pointing to unclaimed or misconfigured third-party services and for verifiable control of an in-scope hostname. Unified from 3 upstream skills (cbh, h1skills, hunting). Plus evidence from all 15,259 disclosed HackerOne reports. For authorized security testing only."
agent_created: true
---

# Subdomain Takeover — unified methodology

> **Unified skill.** Built from 3 upstream skills across cbh, h1skills, hunting and the local HackerOne corpus. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Corpus evidence (72 valid reports, 12 paid / 17%)

Payment is not validity — zero-bounty disclosures are mined as evidence too.

### Techniques ranked across ALL valid writeups

| Technique | Reports |
|---|---:|
| subdomain / DNS / cert-transparency recon | 56 |
| cache / CDN / unkeyed header | 7 |
| public source-code / repo review | 6 |
| webhook / OAuth / SAML / integration abuse | 4 |
| admin / privileged-role context | 3 |
| two-account / cross-account replay | 3 |
| API docs / Swagger / introspection | 3 |
| file upload / filename / extension | 3 |
| OAST / DNS / HTTP callback proof | 2 |
| header injection (Host / X-Forwarded / etc.) | 2 |

### Parameters observed

`summary`, `concept`, `mitigation`, `example`, `cdn.grab.com`

### Case studies (real reports, paid and unpaid)

- [154425](https://hackerone.com/reports/154425) Snapchat — Subdomain takeover on http://fastly.sc-cdn.net/ ($3000, severity n/a)
- [352869](https://hackerone.com/reports/352869) Grab — Subdomain Takeover Via Insecure CloudFront Distribution cdn.grab.com ($1000, medium)
- [1474784](https://hackerone.com/reports/1474784) Zenly — Subdomain Takeover of brand.zen.ly ($750, medium)

Full payload bank, bypass frequencies, approach patterns and case-study excerpts: `references/evidence.md`.

## Corpus-backed method (this class)

1. Collect DNS records for all in-scope hosts, including historical CNAMEs from archives and JS.
2. Fingerprint the service behind each dangling record and check whether the resource name is claimable.
3. Verify ownership rules: many programs require proof of control but forbid actually claiming third-party resources.
4. Demonstrate verifiable control safely — a DNS TXT record you can set, a hosted file you can place, or a controlled response — within program rules.
5. Confirm the hostname is genuinely in scope and not third-party hosted.

### Signals

- CNAME to a service that returns a not-found/unclaimed page
- Staging/legacy hostnames in old docs or JS bundles
- Cloud/hosting records that no longer resolve to an owned resource

### Kill criteria

- Host is out of scope or third-party hosted.
- Record points to an active resource owned by the target.
- Claiming the resource would violate program rules — stop at the evidenced fingerprint.

### Escalation chains

- Takeover -> trusted-origin content -> cookie/OAuth/token phishing.

### Veteran tip

The operator's notes flag dangling-CNAME exclusions — always check the program's known-issues list first.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

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


### A. Discovery checklist — concrete places, params, headers, infra signals to look

- Build the candidate set from multiple independent sources: CT logs (crt.sh, censys), passive DNS (SecurityTrails, RiskIQ, DNSDB, VirusTotal), Chaos, and live CNAME/A/AAAA/ALIAS/ANAME/MX/NS enumeration. Old CNAMEs in historical DNS are a high-yield source — the resource was deleted but the record survived.
- Confirm wildcards vs explicit records before triaging. A `*.example.com` wildcard CNAME to a third party lets an attacker generate *arbitrary* subdomains pointing at their page, amplifying impact; it also creates false positives when a scanner assumes an explicit record exists.
- Provider fingerprints to match in HTTP body, TLS cert, or DNS error (from can-i-take-over-xyz and nuclei `takeover` templates): GitHub Pages ("There isn't a GitHub Pages site here"), S3 ("NoSuchBucket" / "The specified bucket does not exist"), Fastly ("Fastly error: unknown domain"), Azure ("Web App - Unavailable" / `cloudapp.azure.com`, `azurewebsites.net`, `blob.core.azure.com`), Vercel (`cname.vercel-dns.com`, "404 Not Found - Request ID"), Heroku, Netlify, Zendesk, Shopify, Atlassian, ReadMe, Intercom, Statuspage, SurveyGizmo, Tave, and `NXDOMAIN` providers.
- Check 2026-specific surfaces: Microsoft Azure DevOps `cloudapp.azure.com` regional-pool re-issue (paired with wildcard `reply_to` can yield 1-click OAuth ATO), Zendesk help-desk takeover -> email interception -> password-reset chain, Vercel `cname.vercel-dns.com` deleted-project takeover, S3 dangling-bucket cookie-scope abuse.
- Look beyond CNAME: d

### Signals and surfaces

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

### Techniques, payloads and bypasses

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
- **Subdomain takeover of d02-1-ag.productioncontroller.starbucks.com** — `#661751` · Starbucks · $0 · ▲

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

_...and 6 more sections in `references/unified-method.md`._

### Validation and proof

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
- Map the finding to impact honestly: a claimable help-desk subdomain that can intercept reset mail is Critical; a claimable static host with no trust 

### Escalation and related chains

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

_...and 5 more sections in `references/unified-method.md`._

### Tools and wordlists

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

## Source skills merged into this topic

- `h1skills` — `hackerone-subdomain-takeover`
- `hunting` — `subdomain-takeover`
- `cbh` — `hunt-subdomain`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `references/upstream-assets/` — 2 companion files (payload/technique references, scripts, validators and schemas) from the contributing skills
- `references/unified-method.md` — includes 2 merged companion methodology documents
- `references/corpus-wordlists/` — 2 mined paths/params/payload lists from the HackerOne corpus
- `../../upstream/` — complete unmodified archives of all five source repositories
- `references/evidence.md` — corpus technique frequencies, parameters, case studies and payload bank
- `bbhunt-methodology` — orchestrator, state machine and class router
