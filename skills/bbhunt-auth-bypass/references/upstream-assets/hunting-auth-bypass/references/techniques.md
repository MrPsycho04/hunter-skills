# Auth Bypass — Combined Field Guide — Technique reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete technique.

---

## Quick wins



Start here. These are the highest-yield tests for this class.



- Test password reset: token entropy, reuse, expiry, host-header poisoning, email enumeration.

- Attack JWT: alg=none, key confusion, weak secret, kid/jku injection, missing signature.

- Probe OAuth/SSO redirect_uri, state, nonce, and account-linking flows.

- Try type juggling and NoSQL/SQLi in login and OTP endpoints.

- Check registration verification: email/phone reuse, unicode normalization, duplicate identities.



## Bypass tricks



- Reset token leaked via Referer, shared cache, logs, or email link scanner.

- Response manipulation: change `success:false` to true, remove error checks.

- Case/unicode normalization of emails and usernames.

- Session fixation and missing token rotation after login.



## Deeper checklist



- Test password reset: token entropy, reuse, expiry, host-header poisoning, email enumeration, response leakage.

- Attack JWT: alg=none, key confusion, weak HMAC secret, kid/jku injection, missing signature checks.

- Probe OAuth/SSO flows for redirect_uri bypass, state CSRF, code reuse, and account linking flaws.

- Try SQLi/NoSQLi and type juggling in login and OTP endpoints.

- Test OTP: brute force limits, reuse, response leakage, race conditions, backup codes.

- Check registration for email/phone verification bypass and duplicate-identity handling.

- Test remember-me and session tokens for predictability, fixation, and missing revocation.

- Confirm you can access another account or a privileged area end-to-end.



## Techniques from real reports



One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.



- **Token leak in security challenge flow allows retrieving victim's PayPal email and plain text password** — `#739737` · PayPal · $15,300 · ▲1409

  > https://medium.com/@alex.birsan/the-bug-that-exposed-your-paypal-password-539fc2896da9?sk=aeba33c3c331c3f06d230296a21a41e7

- **Improper Authentication - any user can login as other user with otp/logout & otp/login** — `#921780` · Snapchat · $0 · ▲972

  > - Attacker performs `/scauth/otp/login` request with username equal victim's username, and the token obtained on previous step.

- **Bypassing Digits origin validation which leads to account takeover** — `#129873` · X / xAI · $0 · ▲619

  > In short, the event origin is checked against Digits' origin in this line:`-1 !== this.config.get("sdk host").search(t.origin)`, which is the same as `-1 !== "https://www.digits.com".search(t.origin)`.

- **Flickr Account Takeover using AWS Cognito API** — `#1342088` · Flickr · $0 · ▲440

  > The `access token` can be directly used against Amazon's AWS API, for instance using the [AWS Command Line Interface](https://docs.aws.amazon.com/cli/) tool:

- **Chained Bugs to Leak Victim's Uber's FB Oauth Token** — `#202781` · Uber · $0 · ▲427

  > Next, @ngalog found that the `https://login.uber.com/logout` endpoint would redirect based on the Referer header, making it possible to chain together another redirect.

- **URL link spoofing** — `#481472` · Slack · $250 · ▲362

  > Words such as `http://example.com` and `example.com` included in the message are displayed by URL link.

- **[cs.money] Open Redirect Leads to Account Takeover** — `#905607` · CS Money · $0 · ▲357

  > Open this url `https://auth.dota.trade/login?redirectUrl=https://cs.money///loving-turing-29a494.netlify.app%2523&callbackUrl=https://cs.money///loving-turing-29a494.netlify.app%2523` , the login url was gotten from `cs.money` index page button `sign in…

- **Change any Uber user's password through /rt/users/passwordless-signup - Account Takeover (critical)** — `#143717` · Uber · $0 · ▲312

  > Through the endpoint at /rt/users/passwordless-signup it is possible to change the password of any Uber user, given knowledge of their phone number (or by just enumerating phone numbers until one is found that is registered with Uber - not too hard given the…

- **Bypass Password Authentication for updating email and phone number - Security Vulnerability** — `#770504` · X / xAI · $0 · ▲288

  > {"flow token":"[PASTE FLOW TOKEN HERE]:1","status":"success","subtasks":[{"subtask id":"EnterPhoneForAssociation","enter phone":{"primary text":{"text":"Add a phone number","entities":[]},"secondary text":{"text":"Enter the phone number youâd like to…

- **Insufficient OAuth callback validation which leads to Periscope account takeover** — `#110293` · X / xAI · $0 · ▲277

  > callback url = a/../../login?redirect after login=https://cards.twitter.com/card id

- **Insufficient validation on Digits bridge** — `#168116` · X / xAI · $0 · ▲263

  > The problem is that there is a way for a website to disable sending Referer for out bound requests by using the tag `<meta name="referrer" content="never" `.

- **Ability to DOS any organization's SSO and open up the door to account takeovers** — `#976603` · Superhuman (formerly Grammarly) · $10,500 · ▲260

  > So if you have `myentity` as the legitimate entity, and an attacker sets their entity to `myentity[SPACE]` (with a space at the end); users attempting to authenticate into the legitimate `myentity` will technically authenticate against it, but then the…

- **Ability to bypass email verification for OAuth grants results in accounts takeovers on 3rd parties** — `#922456` · GitLab · $3,000 · ▲257

  > It's possible to play the `/oauth/authorize` request directly to bypass the `Verify the email address in your account profile before you sign in.` prompt.

- **Mass Account Takeover at https://app.taxjar.com/ - No user Interaction** — `#1581240` · Stripe · $0 · ▲253

  > The vulnerability was caused by a leaked token in the delete invitation request feature and resolved by using the invitation ID instead of the token to look up the user’s invite when deleting an invitation.

- **Improper Validation at Partners Login** — `#990048` · Eternal · $2,000 · ▲251

  > Our backend generated the OTP for `phone number` param but appended the `country isd` parameter to the `phone number` param before sending the SMS without any major checks.

- **Stealing SSO Login Tokens (snappublisher.snapchat.com)** — `#265943` · Snapchat · $7,500 · ▲244

  > `https://snappublisher.snapchat.com/api/v1/media/████/file/somthine.svg?%23pranav` this redirects with `307` status code to `storage.googleapis.com/creativesuite-prod-media/ ` with `SSO login token ticket` in ` hashfragment` carried forward by browser.

- **Incorrect authorization to the intelbot service leading to ticket information** — `#1328546` · TikTok · $15,000 · ▲219

  > An authentication bypass and site wide stored XSS (cross-site scripting) vulnerability was found on TikTok Ads as JWT (JSON Web Token) was not verified properly.

- **HackerOne Jira integration plugin Leaked JWT to unauthorized jira users** — `#1103582` · HackerOne · $3,000 · ▲213

  > When you click on "click here", you will be directed to a link this "`https://hackerone.com/apps/atlassian/claim-app?jwt=<TOKEN `" containing JWT parameter to complete the integration process.

- **Mass Accounts Takeover Without any user Interaction  at https://app.taxjar.com/** — `#1685970` · Stripe · $0 · ▲212

  > The vulnerability was caused by manipulating the user's number in the POST request to `/accounts/<ACCOUNT NUMBER ` with adding the user's email parameter carrying the attacker's email in the payload data in the request, which causing changing the email in the…

- **2FA Bypass leads to  impersonation of legimate users** — `#2885636` · Drugs.com · $0 · ▲207

  > Go to https://www.drugs.com/account/register/ and create an account using an email you own.

- **H1514 [*.(my)shopify.com] - Viewing Password Protected Content** — `#421859` · Shopify · $3,000 · ▲192

  > Because of the `/preview bar`, the password protection is rendered useless.

- **Authentication bypass on auth.uber.com via subdomain takeover of saostatic.uber.com** — `#219205` · Uber · $0 · ▲183

  > Although there were some countermeasures to prevent theft, the current setup still allows leakage of these high-value session cookies to the overtaken subdomain https://saostatic.uber.com in all modern browsers, leading to a full Authentication Bypass (highly…

- **Account Takeover via Authentication Bypass in TikTok Account Recovery** — `#2443228` · TikTok · $12,000 · ▲172

  > I identified a critical vulnerability in one of TikTok's endpoints that permitted unauthorized changes to user accounts due to improper parameter handling.

- **Web Authentication Endpoint Credentials Brute-Force Vulnerability** — `#127844` · HackerOne · $0 · ▲161

  > The following successful brute-force attack of 10.001 passwords (https://github.com/danielmiessler/SecLists/blob/master/Passwords/10k most common.txt appended with the real password) against test account ██████:Geniaal2!!

- **Absence of Token expiry leads to Unauthorized login Access** — `#766578` · Affirm · $0 · ▲155

  > When the user enters the number, and a password login URL/login is generated on the endpoint https://hackerone.affirm-odin.com/api/v3/login/phone/, the URL could be set invalid after a few OTP limits.

- **H1514 Session Fixation on multiple shopify-built apps on *.shopifycloud.com and *.shopifyapps.com** — `#423136` · Shopify · $0 · ▲144

  > Attacker uses XSS on .shopifycloud.com and writes the cookie scoped to all subdomain to victim `document.cookie=' flow session=EVIL;domain=.shopifycloud.com;path=/';`

- **Open Redirect on central.uber.com allows for account takeover** — `#206591` · Uber · $0 · ▲144

  > When logging into `central.uber.com`, the `state` parameter for login.uber.com contained a redirect location instead of a CSRF token.

- **Attacker can obtain write access to any federated share/public link** — `#1170024` · Nextcloud · $4,000 · ▲142

  > For the sake of this example the `remote id = 2` and the `token = nOxdNJkb1xbI1VX`

- **Reading Emails in Uber Subdomains** — `#156536` · Uber · $0 · ▲141

  > Link to blog: http://blog.pentestnepal.tech/post/149985438982/reading-ubers-internal-emails-uber-bug-bounty

- **Mint Oauth2 access token for targeted user** — `#1148364` · GitLab · $5,580 · ▲140

  > `doorkeeper application%5Btrusted%5D=0&doorkeeper application%5Btrusted%5D=1& ` This will allow us to create an application that is trusted by default.



## Case studies



### Token leak in security challenge flow allows retrieving victim's PayPal email and plain text password

`#739737` · PayPal · $15,300 · high · 2020-01-08 · ▲1409

> A bug was identified whereby sensitive, unique tokens were being leaked in a JS file used by the recaptcha implementation. In certain cases, a user must solve a CAPTCHA challenge after authenticating. When the security challenge is completed, the authentication request is replayed to log in. The exposed tokens were used in the POST request to solve the CAPTCHA.



### Improper Authentication - any user can login as other user with otp/logout & otp/login

`#921780` · Snapchat · $0 · critical · 2021-09-03 · ▲972

> '/scauth/otp/droid/logout' request contains user id parameter. Usually it is equal to current user user id, but if an attacker passes user id of victim account he can login as victim. I will demonstrate the problem on two accounts. Victim: ███ Attacker: ██████████ - Attacker perform a usuall login to attacker's personal account.



### Bypassing Digits origin validation which leads to account takeover

`#129873` · X / xAI · $0 · n/a · 2020-06-24 · ▲619

> Hi, I would like to report an important issue that affects websites that has integrated "Signin with Digits" , leading to potential account takeover. Detail In Digits architecture, the data communication channel between Digits and customer's site relies on postMessage() .



### Flickr Account Takeover using AWS Cognito API

`#1342088` · Flickr · $0 · critical · 2021-12-18 · ▲440

> Flickr uses Amazon Cognito to implement its login functionality. Furthermore, Flickr does not allow users to change their registered e-mail address via the user interface. This restriction can be bypassed via direct communication with the Amazon Cognito User Pool API. Consider we have the following accounts: 1. flickr-benign@lauritz-holtmann.de (our victim) 2.



### Chained Bugs to Leak Victim's Uber's FB Oauth Token

`#202781` · Uber · $0 · high · 2019-01-25 · ▲427

> The Facebook OAuth application was misconfigured to allow any URL that followed the https://auth.uber.com/login? format to be provided as a redirect uri. By taking advantage of this, @ngalog was able to discover that the next url parameter could be added to the redirect uri allowing it to be chained further.



## Query the corpus



```sh

python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class auth-bypass --limit 20

python3 ~/.local/share/hackerone-reports/h1.py stats --class auth-bypass

python3 ~/.local/share/hackerone-reports/h1.py show <id> --full

```



Search by technology, endpoint, parameter, or program. Examples:



```sh

python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class auth-bypass

python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class auth-bypass --min-bounty 1000

```



## Bypass Techniques



| Defense | Bypass |

|---|---|

| SSO enforced on login page | Probe alternate entry points: XMLRPC, REST API, mobile API, legacy endpoints |

| SAML signature validation | XML comment injection, namespace wrapping, signature wrapping (XSW), remove signature entirely |

| IP allowlisting on admin portal | Use partner portal token if it shares auth backend |

| Rate limiting on login | XMLRPC allows credential stuffing via `system.multicall` — batches hundreds of auth attempts in one request |

| CSRF token on login form | SAML flow is POST-based cross-origin by design; no CSRF token needed on `/saml/callback` |

| JWT signature validation | `alg: none`, key confusion (RS256 → HS256 with public key as secret), brute-force weak secrets |

| Separate session stores per portal | Check if cookie domain is `.target.com` (wildcard) — cookie bleeds between subdomains |

| MFA on primary login | If SAML SP doesn't enforce MFA at the assertion level and accepts pre-auth assertions, MFA can be skipped |



**XMLRPC multicall for mass auth bypass:**

```xml

<methodCall>

  <methodName>system.multicall</methodName>

  <params><param><value><array><data>

    <value><struct>

      <member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>

      <member><name>params</name><value><array><data>

        <value><string>admin</string></value>

        <value><string>password1</string></value>

      </data></array></value></member>

    </struct></value>

    <!-- repeat for each credential pair -->

  </data></array></value></param></params>

</methodCall>

```



---
