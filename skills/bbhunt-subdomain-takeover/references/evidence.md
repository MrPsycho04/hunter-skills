# Evidence appendix — Subdomain Takeover

Mined from all **72 valid disclosed reports** for this class (12 paid, 17% — payment is not validity).

## Technique frequency (all valid writeups)

| Item | Count |
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
| DOM / HTML source inspection | 1 |
| cloud metadata / IAM abuse | 1 |
| public bucket / storage exposure | 1 |
| intercept & replay request in Burp | 1 |
| employee / developer public info | 1 |
| Content-Type / body-format switch | 1 |

## Tools mentioned

| Item | Count |
|---|---:|
| source-code-review | 4 |
| curl | 2 |
| browser | 2 |
| shodan | 1 |
| burp | 1 |

## Bypass primitives

| Item | Count |
|---|---:|
| host header | 8 |
| bypass | 7 |
| trailing dot | 4 |
| content-type | 3 |

## Impact language

| Item | Count |
|---|---:|
| credential | 7 |
| sensitive information | 3 |
| password | 3 |
| admin | 2 |
| unauthorized | 1 |

## Parameters observed

| Item | Count |
|---|---:|
| summary | 1 |
| concept | 1 |
| mitigation | 1 |
| example | 1 |
| cdn.grab.com | 1 |

## Recurring approach patterns

- **1×** the researcher found a dns entry pointing to an unused ip address
  - e.g. The researcher found a DNS entry pointing to an unused IP address.
- **1×** hi i noticed that the following domain api legalrobot com was returning the following information f102881 from modulus io
  - e.g. Hi, I noticed that the following domain: api.legalrobot.com was returning the following information: {F102881} from Modulus.io.
- **1×** in this case what i did was to create a new account on modulus and saw the following setup when i created my own application f102879 i tried adding the specific domain but it said it was already added somewhere
  - e.g. In this case, what I did was to create a new account on Modulus, and saw the following setup when I created my own application: {F102879} I tried adding the specific domain, but it said it was already added somewhere.
- **1×** the problem was that i then tried with the wildcard legalrobot com and that actually worked f102878 which also made the page resolve my app f102877 you should not point subdomains to services you do not use yet
  - e.g. The problem was that I then tried with the wildcard: `*.legalrobot.com`, and that actually worked: {F102878} Which also made the page resolve my app: {F102877} You should not point subdomains to services you do not use (yet).
- **1×** hey team i ve found a snapchat cdn domain here which had a test instance of fastly setup but did not remove the dns record when the service was cancelled
  - e.g. Hey team, I've found a snapchat cdn domain here which had a test instance of fastly setup but did not remove the dns record when the service was cancelled.
- **1×** the researcher found a subdomain takeover on ws bimedb com
  - e.g. The researcher found a subdomain takeover on `ws.bimedb.com`.
- **1×** we removed the record because it was not needed any longer
  - e.g. We removed the record because it was not needed any longer.
- **1×** but due to some problem the main domain help cloudup com see screenshot below png is showing ssl error maybe due to expired certificate i m not sure as i m just a started still have to learn many things
  - e.g. But Due to some Problem The Main Domain ***help.cloudup.com (See Screenshot Below 0.png) is Showing SSL Error Maybe due to expired Certificate I'm Not sure as I'm just a Started still have to learn many things!
- **1×** i recently discovered that gitbook hosted sites are also vulnerable to subdomain takeovers due to a trailing dot vulnerability in the gitbook custom domain feature seen below
  - e.g. I recently discovered that GitBook-hosted sites are also vulnerable to subdomain takeovers due to a trailing dot vulnerability in the GitBook "Custom Domain" feature (seen below).
- **1×** first we will look at the results for with the trailing dot and now the results for mitigation i noticed that this service is hosted by gitbook however your bug bounty brief does not state that third party hosted services being out of scope
  - e.g. First, we will look at the results for (with the trailing dot) And now the results for Mitigation ===== I noticed that this service is hosted by GitBook, however, your bug bounty brief does not state that third-party hosted services being out of scope.
- **1×** see also which was an independent discovery of the same issue on a different subdomain using a combination of tools and techniques described in i was able to take control of different subdomains linked to redacted data gov
  - e.g. [See also #263542, which was an independent discovery of the same issue on a different subdomain.] Using a combination of tools and techniques described in I was able to take control of 7 different subdomains linked to {REDACTED}.data.gov.
- **1×** hy wordpress sec i found as it is posible to takeover this domain when you navigate it you will get this error msg warning
  - e.g. Hy Wordpress sec i found as it is posible to takeover this domain when you navigate it you will get this error msg: Warning!
- **1×** when browsing to the subdomain an aws cloudflare error is displayed
  - e.g. When browsing to the subdomain an AWS cloudflare error is displayed.
- **1×** i recently found an abandoned and or overlooked nodejs org subdomain that was indirectly pointing to fastly
  - e.g. I recently found an abandoned and/or overlooked nodejs.org subdomain that was indirectly pointing to Fastly.
- **1×** fastly doesn t require any proof of dns ownership to register new distributions that use a given domain so i was able to effectively take it over
  - e.g. Fastly doesn't require any proof of DNS ownership to register new distributions that use a given domain, so I was able to effectively take it over.
- **1×** good day i truly hope it treats you awesomely on your side of the screen i have found that your website cdn grab com is pointed via a cname to a cloudfront instance cdn grab com cloudfront net this was not registered on amazon aws cloudfront
  - e.g. Good day, I truly hope it treats you awesomely on your side of the screen :) I have found that your website cdn.grab.com is pointed via a cname to a cloudfront instance cdn.grab.com => *.cloudfront.net This was not registered on Amazon Aws Cloudfront.
- **1×** summary i discovered that it was possible to takeover test cncf aws canary k8s io by assigning a zone to that name with one of the following nameservers in route53 once the zone was claimed i was able to create dns records under this host
  - e.g. ## Summary: I discovered that it was possible to takeover ` test-cncf-aws.canary.k8s.io` by assigning a zone to that name with one of the following nameservers in Route53: Once the zone was claimed, I was able to create DNS records under this host.
- **1×** using enumeration i was able to discover this domain and determined it note the hostname was not claimed by me also because i need to pay certain amount to host a website
  - e.g. Using enumeration, I was able to discover this domain and determined it NOTE: The hostname was not claimed by me also because i need to pay certain amount to host a website.
- **1×** while we removed the dns records the ttcdn co domain is out of scope for our program making this report ineligible for a bounty
  - e.g. While we removed the DNS records, the `ttcdn.co` domain is out of scope for our program, making this report ineligible for a bounty.
- **1×** hence it is possible to do sub domain takeover impact an attacker can claim this subdomain by requesting a process of registering this abandoned subdomain to his name
  - e.g. Hence it is possible to do Sub-domain Takeover ## Impact An attacker can claim this subdomain by requesting a process of registering this abandoned subdomain to his name.
- **1×** the reporter was able to re register the decommissioned subdomain with his own heroku account
  - e.g. The reporter was able to re-register the decommissioned subdomain with his own Heroku account.
- **1×** i have found a subdomain of to be vulnerable to takeovers via a cname to unclaimed domain
  - e.g. I have found a subdomain of `███████` to be vulnerable to takeovers via a CNAME to unclaimed domain.
- **1×** these are the following domains i discovered and the outdated endpoints on azure to which they point and the proof of concept file is at the following location i have not hosted any other file nor attempted any other vector of attack
  - e.g. These are the following domains I discovered and the outdated endpoints on Azure to which they point: █████ --> ████ ...and the proof-of-concept file is at the following location: I have not hosted any other file nor attempted any other vector of attack.
- **1×** summary i just went to brand zen ly and it shows an error not found also i ve checked the cname is pointing to brandpad io which means it can be added to any account
  - e.g. ### Summary: + I just went to `brand.zen.ly` and it shows an error "Not Found", also I've checked the CNAME is pointing to `brandpad.io`, which means it can be added to any account.

## Case studies (full excerpts)

### 154425 — Subdomain takeover on http://fastly.sc-cdn.net/
Snapchat · $3000 · severity n/a · https://hackerone.com/reports/154425

Hey team, I've found a snapchat cdn domain here which had a test instance of fastly setup but did not remove the dns record when the service was cancelled. This allowed me to create a Fastly instance to take it over. I've confirmed this is a snapchat property via Censys ( though the risk here seems minimal at best as this domain does not appear to be used anywhere on any snapchat properties. Repro steps: * Visit Recommended fix: Removal of this record is recommended.

### 352869 — Subdomain Takeover Via Insecure CloudFront Distribution cdn.grab.com
Grab · $1000 · medium · https://hackerone.com/reports/352869

Good day, I truly hope it treats you awesomely on your side of the screen :) I have found that your website cdn.grab.com is pointed via a cname to a cloudfront instance cdn.grab.com => *.cloudfront.net This was not registered on Amazon Aws Cloudfront. I was able to take over the domain: See my POC (Pug of Concept) Options How to fix: 1) Remove the Cname record on cdn.grab.com to not point to cloudfront.net 2) Ask me to remove my registered cdn.grab.com on cloudfront, and you can re register yours :) May you be well on your side of the screen :) -Eric ## Impact Impact: Cyber attackers can launch a phishing campaign leveraging your established (soon to be impacted) brand reputation. The victim has no way of telling, whether the content is served by the domain owner or the cyber attacker. Attackers can also chain higher severity attacks to this. Many applications expose session cookies to a wildcard domain (*.example.com), so any subdomain can access them. An attacker can take a forgotten subdomain, trick the user to visit it, and extract cookies (even those with secure flag). This can be seen as an advanced version of XSS.

### 1474784 — Subdomain Takeover of brand.zen.ly
Zenly · $750 · medium · https://hackerone.com/reports/1474784

Hello Gents, ### Background: > + Subdomain takeover vulnerabilities occur when a subdomain (subdomain.example.com) is pointing to a service (e.g. GitHub pages, Heroku, etc.) that has been removed or deleted. This allows an attacker to set up a page on the service that was being used and point their page to that subdomain. For example, if subdomain.example.com was pointing to a GitHub page and the user decided to delete their GitHub page, an attacker can now create a GitHub page, add a CNAME file containing subdomain.example.com, and claim subdomain.example.com. ### Summary: + I just went to `brand.zen.ly` and it shows an error "Not Found", also I've checked the CNAME is pointing to `brandpad.io`, which means it can be added to any account. + This is pretty serious security issue in some context, so please act as fast as possible. + I was able to takeover `brand.zen.ly` by registering at **Brandpad**. ### Vulnerable URL: + ### Proof of Concept: + Please visit: + {F1610891} ### Recommended Fix: + Check your DNS-configuration for subdomains pointing to services not in use. + Set up your external service so it fully listens to your wildcard DNS. ## Impact + Subdomain takeover is abused for several purposes: 1. Malware distribution. 2. Phishing / Spear phishing. 3. XSS and steal cookies. 4. Bypass domain security. 5. Legitimate mail sending and receiving on behalf of Datadog subdoma

### 863551 — Subdomain takeover of resources.hackerone.com
HackerOne · $500 · low · https://hackerone.com/reports/863551

Hello, I just went to and it shows an error "Non-hub domain, The URL you've accessed does not provide a hub. Please check the URL and try again." also i've checked the CNAME is poiting to read.uberflip.com which means if it is not added it can be added to any account, as [Uberflip documentation]( suggests that after your subdomain is pointing to their CNAME which is read.uberflip.com, your subdomain should be added to your account so it shows the URL you chose for your hub. As i couldn't signup on their website to test due to signup problems, i just wanted your confirmation whether this subdomain is added in uberflip account or not. If not then claim it otherwise any one can add or claim this to their Uberflip account ## Impact Subdomain takeover.

### 2899858 — Subdomain takeover on a subdomain under firefox.com
Mozilla · $500 · medium · https://hackerone.com/reports/2899858

## Summary: Subdomain takeover via ██████████ of █████ ## Steps To Reproduce: The subdomain ████ is a CNAME to www.mozilla.org (which is hosted at ███████), however it was not currently registered at ███████. By claiming it I was able to take it over. As PoC please visit: ██████ It seems that the CAA records does not allow ████████ to generate an SSL certificate for me. ## Supporting Material/References: Following the documentation of this program I decided to report it: > Domain takeovers supported by a proof of concept for *.mozilla.org, *.mozilla.com, *.mozilla.net, *.firefox.com, *.mozgcp.net and *.mozaws.net in addition to the list of sites in scope. If the domain is pointing to a claimed instance by another company, then the report will not be eligible for bounty. ## Impact ## Summary: Given this is a very generic and thrust worthy domain name it is suitable for a malware campaign. Besides that it could maybe read some non-secure cookie but that is not that likely. We could however, use the domain to block access of individual user by setting some large cookies, see for example www.firefox.com after setting 100kb of cookies via {F3852214} This action can also be performed via eg a tracking pixel.

### 335330 — Subdomain Takeover to Authentication bypass
Roblox · no bounty (valid finding) · critical · https://hackerone.com/reports/335330

## Vulnerability Type: ----------- Subdomain Takeover ## Description: ----------- Due to unclaimed or expired Hubspot instance an attacker is able to claim and serve content from `devrel.roblox.com` and perform different kind of attacks which i shared in impact section. ## Affected Area: ----------- ## Steps to Reproduce: ----------- + Visit: {F283580} ## Mitigation: ----------- + Remove the CNAME entry for the `devrel.roblox.com` ## Impact Let's talk about about in details, as attacker could possible takeover other users account. 1. As `.ROBLOSECURITY` cookies is scoped to `*.roblox.com` means same cookies shared with all other subdomain, i'm not much familiar with hubspot with hosting following code on will steal all the users cookie who visit this subdomain. {F283554} ###steal_cookie.php 2. Also `devrel.roblox.com` can be used to read all the chats between other users as `devrel.roblox.com` is also white listed to make CORS request at `chat.roblox.com` {F283553} Which can be done like this: ` Apart form all above issue, attacker can do following things as well. + Creating fake login page for credentials harvesting. + Sharing malicious files using roblox. + Creating mail account using GSuite to send and recived emails on behalf of `*@devrel.roblox.com`

### 159156 — Hacker.One Subdomain Takeover
HackerOne · no bounty (valid finding) · low · https://hackerone.com/reports/159156

Hello HackerOne Sec Team, ####Description : > This report is about domain takeover of __hacker.one__ via __instapage 0day__ issue which i just found . ####Step To Verify : + Visit : + You will see some html updated by me. ####Impact : + as its one of offical website of hackerone , so attacker can serve anything like login page or etc as he have complete access to main domain ! ####Possible Fix : + For now just remove the cname of instapage , till i try to contact them and get complete fix . Please let me know if any more info needed ! ------------- **Regards** *Geekboy !*

## Field playbook (unedited)

### quick

- Enumerate subdomains and resolve CNAME/A records to third-party services.
- Check for unclaimed resources: S3, GitHub Pages, Heroku, Azure, Fastly, Shopify, status pages.
- Confirm the dangling fingerprint before claiming.
- Assess impact: cookie scope, CSP allowlists, OAuth redirect URIs, email.

### payloads

- CNAME -> `foo.s3.amazonaws.com` (NoSuchBucket)
- CNAME -> `foo.github.io` (404 repo)
- CNAME -> `foo.herokuapp.com` (No such app)
- CNAME -> `foo.statuspage.io` / `foo.zendesk.com`

### bypass

- Look for forgotten staging/dev subdomains and wildcard DNS.
- Check NS delegation to abandoned providers.

### surface

- DNS
- CNAME
- A
- NS
- MX
- TXT

### tools

- subfinder
- amass
- dnsx
- nuclei -t takeovers
- can-i-take-over-xyz

### chain

- Subdomain takeover -> cookie theft.
- Subdomain takeover -> OAuth redirect.

## Corpus search commands

```sh
python3 ~/.local/share/hackerone-reports/h1.py stats --class subdomain-takeover
python3 ~/.local/share/hackerone-reports/h1.py search "<feature or param>" --class subdomain-takeover --limit 10
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```
