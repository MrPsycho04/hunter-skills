# CSRF — Combined Field Guide — Technique reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete technique.

---

## Quick wins



Start here. These are the highest-yield tests for this class.



- Find state-changing requests and check for anti-CSRF tokens and SameSite cookies.

- Remove the token, blank it, reuse another session's token, and try a fixed token.

- Try GET, form POST, text/plain JSON, multipart, and method override.

- Check email/password change, OAuth consent, and login CSRF.

- Look for subdomain XSS or cookie scope that enables CSRF.



## Bypass tricks



- Token not bound to session; token from another account accepted.

- SameSite=Lax bypass via top-level GET or 2-minute window.

- CORS misconfig allowing credentialed cross-origin requests.

- Bypass token check by changing content-type or removing the parameter.



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



## Bypass Techniques



### Defense: SameSite=Lax cookies

**Bypass:** Top-level navigation GET requests still work. If the sensitive action can be triggered via GET (or if a redirect chain converts POST→GET), Lax doesn't protect it. Also: subdomains can still set cookies for parent domain.



### Defense: CSRF token present

**Bypasses:**

- Token is static per session — steal via XSS, Referer leakage, or cached page

- Token not validated server-side — just remove it and try

- Token validated by length/format only — submit a fake but correctly-formatted value

- Token tied to session but session is predictable



### Defense: `Content-Type: application/json` enforcement

**Bypass:** Use `text/plain` enctype with crafted form input names that produce valid JSON. Server receives JSON body, skips CORS preflight.



### Defense: Referer/Origin header check

**Bypasses:**

- Null Origin: use sandboxed iframe (`<iframe sandbox="allow-scripts allow-forms">`)

- Subdomain bypass: if `*.target.com` is trusted and you have XSS on any subdomain

- Referer stripping: HTTPS→HTTP transitions strip Referer header

- Weak matching: `target.com.evil.com` passes naive string matching



### Defense: Double-submit cookie pattern

**Bypass:** If attacker can set cookies (subdomain takeover, cookie injection via HTTP), they can set both the cookie and the form field to matching attacker-controlled values.



### Defense: Custom request header (e.g., `X-Requested-With`)

**Bypass:** Simple requests (form POST, `text/plain`) don't trigger preflight and can't set custom headers — but some servers only check for header *presence*, not value, and some frameworks accept requests without it.



---



### Mobile-app CSRF via custom-scheme deeplink

CSRF is not browser-only. For targets with a mobile app, enumerate exported deeplink / custom-scheme handlers (`scheme://action` from the Android manifest / iOS `Info.plist`) and test whether opening one performs a state-changing action (follow, link, purchase) using the app's ambient session with no CSRF token — deliverable to a victim by a plain link or a QR code. Disclosed: reports/583987, reports/805073.
