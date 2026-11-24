---
name: hackerone-mobile
description: >-
  Hunt mobile app flaws. Use when testing Android/iOS apps, deep links, exported components, and local storage. Backed by 198 disclosed HackerOne reports.
---

# Mobile Application Security — HackerOne field guide

Built from **198** publicly disclosed HackerOne reports (2014–2026). Corpus: `~/.local/share/hackerone-reports/`.

## Signal

- Reports: **198** · paid: **67**
- Median bounty **$750** · p90 **$2,940** · max **$10,000** · total **$80,330**
- Median upvotes **18**

## Where it pays

| Program | Reports | Bounty | Upvotes |
|---|---|---|---|
| Mail.ru | 19 | $14,950 | 627 |
| GitHub Security Lab | 6 | $12,200 | 102 |
| X / xAI | 16 | $12,180 | 677 |
| Pornhub | 4 | $8,000 | 85 |
| Slack | 3 | $5,000 | 402 |
| VK.com | 7 | $4,400 | 261 |
| Shopify | 7 | $3,400 | 367 |
| Nextcloud | 26 | $3,275 | 515 |

## Quick wins

Start here. These are the highest-yield tests for this class.

- Decompile and inspect exported components and URL schemes.
- Test deep links for auth bypass, open redirect, and token leakage.
- Check local storage, logs, backups, and clipboard for secrets.
- Intercept traffic and test certificate pinning bypass.
- Look for insecure WebViews and JS bridges.

## Payloads & probes

- Deep link -> `app://open?url=https://evil.com` `app://webview?url=javascript:...`
- WebView -> `addJavascriptInterface` abuse
- Backup -> extract shared_prefs / Keychain

## Bypass tricks

- Bypass pinning with Frida/Objection.
- Use dynamic instrumentation for root/jailbreak checks.

## Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`deeplink` `intent` `webview` `keystore` `shared_prefs` `keychain`

## Tools

`apktool` · `jadx` · `Frida` · `objection` · `MobSF`

## Escalation chains

- Deeplink -> token theft.
- WebView bridge -> RCE.

## Deeper checklist

- Decompile and inspect exported activities/services/receivers and URL schemes.
- Test deep links for auth bypass, open redirect, and token leakage.
- Check local storage, logs, backups, and clipboard for secrets.
- Intercept traffic and test certificate pinning bypass.
- Look for insecure WebViews and JS bridges.
- Verify server-side impact, not just client behavior.

## Techniques from real reports

One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.

- **[Grab Android/iOS] Insecure deeplink leads to sensitive information disclosure** — `#401793` · Grab · $0 · ▲552
  > I've found a set of possible deeplinks, one of them ( ) could lead that an arbtrary URL was opened in a built-in browser in activity using that code (should be used in an external browser/messenger)
- **Periscope android app deeplink leads to CSRF in follow action** — `#583987` · X / xAI · $1,540 · ▲224
  > + It means we can use ` pscp://user/<user-id or pscpd://user/<user-id `
- **[PayPal Android] Remote theft of user session using push_notification_webview deeplink** — `#424443` · PayPal · $0 · ▲188
  > A deeplink feature built into the PayPal Android application failed to validate the requested endpoint.
- **1 click Account takeover via deeplink in [com.kayak.android]** — `#1667998` · KAYAK · $0 · ▲173
  > https://fluidattacks.com/blog/account-takeover-kayak/
- **[Venmo Android] Remote theft of user session** — `#401940` · PayPal · $0 · ▲151
  > Khilly highlighted a logic flaw in the Venmo app’s use of `android.net.Uri` parser, which we further explored together.
- **[Information Disclosure] Amazon S3 Bucket of Shopify Ping (iOS) have public access of other users image** — `#1021906` · Shopify · $2,900 · ▲135
  > Back to Shopify Store as Customer and inspect the website code, you will find the URL of image ██████████ https://ping-api-production.s3.us-west-2.amazonaws.com/oks██████
- **Changing email address on Twitter for Android unsets "Protect your Tweets"** — `#472013` · X / xAI · $2,940 · ▲119
  > (Add details for how we can reproduce the issue)
- **Possible to steal any protected files on Android** — `#377107` · ownCloud · $750 · ▲115
  > You can bypass the verification using specifying an alternative path: `/data/user/0/com.owncloud.android/`
- **Disclosure of all uploads to Cloudinary via hardcoded api secret in Android app** — `#351555` · Reverb.com · $0 · ▲96
  > Also this url https://api.cloudinary.com/v1 1/reverb/usage discloses statistics regarding stored files
- **Twitter lite(Android): Vulnerable to local file steal, Javascript injection, Open redirect** — `#499348` · X / xAI · $0 · ▲95
  > To reproduce javascript injection: adb shell am start -n com.twitter.android.lite/com.twitter.android.lite.TwitterLiteActivity -d "javascript://example.com%0A alert(1);"
- **Unsafe deserialization leads to token leakage in PayPal & PayPal for Business [Android]** — `#453791` · PayPal · $0 · ▲93
  > https://blog.oversecured.com/Exploiting-memory-corruption-vulnerabilities-on-Android/
- **Bypass of biometrics security functionality is possible in Android application (com.shopify.mobile)** — `#637194` · Shopify · $500 · ▲90
  > `adb shell am start -n com.shopify.mobile/com.shopify.mobile.lib.app.DeepLinkActivity -d 'https://www.shopify.com/admin/products'`
- **MetaMask Browser URL and Transaction Origin Spoofing - Metamask wallet Android & Metamask wallet iOS** — `#1751333` · MetaMask · $0 · ▲87
  > @renekroka and @hackerontwowheels from the talented team at [UGWST](https://ugwst.com/) discovered a bug that prevented the MetaMask Mobile browser from correctly updating the domain of the browser tab after a redirect.
- **Grammarly Keyboard for Android <4.1  leaks user input through logs (except for sensitive input fields)** — `#462416` · Superhuman (formerly Grammarly) · $0 · ▲84
  > @homelander identified that Grammarly for Android (on Android <4.1) was leaking user-entered text to device logs.
- **Domain highlighting on External link warning is not working on Chrome & Microsoft Edge browsers on Mobile** — `#2553026` · HackerOne · $0 · ▲82
  > - https://google.com@1234567890/download/safest file: Browsers automatically convert decimal to IP address.
- **Grammarly Keyboard for Android "Authorization Code with PKCE" flow implementation vulnerability that allows account takeover** — `#824931` · Superhuman (formerly Grammarly) · $0 · ▲76
  > @tomtenisse identified a vulnerability in Grammarly Keyboard for Android that allowed malicious application installed on the device to guess the PKCE code verifier value and consequently obtain access to OAuth access token (`grauth` cookie).
- **[Zomato Android/iOS] Theft of user session** — `#328486` · Eternal · $0 · ▲68
  > When any WebView (in a client app, or a browser) meets a URL it will automatically launch Zomato app.
- **Authorization bypass using login by phone option+horizontal escalation possible on Grab Android App** — `#205000` · Grab · $0 · ▲68
  > So, I found the endpoint using android app `https://p.grabtaxi.com/api/passenger/v2/profiles/activationsms` which allow me to bypass OTP code due to lack of rate limiting.
- **Persistant Arbitrary code execution in mattermost android** — `#1115864` · Mattermost · $0 · ▲67
  > On the next launch of the app the malicious code will be executed.In this poc the app will crash on next launch because i was too lazy and to create a modified version of `libyoga.so`
- **URL Scheme Validation Bypass in Shopify Mobile App Allows Javascript Execution** — `#1737358` · Shopify · $0 · ▲65
  > It was found that the com.shopify.mobile app doesn't validate the scheme of the url given as an extra parameter to the com.shopify.mobile.navigation.NavigationActivity which may allow the loading of arbitrary html content (including js code) in the…
- **MetaMask Browser (on Android) does not enforce Content-Security-Policy header** — `#1941767` · MetaMask · $0 · ▲64
  > Notice how our javascript `<script alert('Javascript is executed.')</script ` is blocked by the browser (Chrome in this example):
- **Insufficient session expiration in the **com.shopify.ping** android app** — `#1172205` · Shopify · $0 · ▲63
  > More specifically, after the user provides the required credentials, an access token will be fetched from the server at accounts.shopify.com/oauth/token.
- **Default Nextcloud Server and Android Client leak sharee searches to Nextcloud** — `#1167916` · Nextcloud · $750 · ▲58
  > https://github.com/nextcloud/server/blob/master/apps/files sharing/lib/Controller/ShareesAPIController.php L144
- **Firebase Database Takeover in Zego Sense Android app** — `#1065134` · Zego · $0 · ▲58
  > reponse = requests.put("https://api-project-615509201590.firebaseio.com/.json", json=data)
- **bypass two-factor authentication in Android apps and web** — `#1747978` · TikTok · $0 · ▲55
  > It was found that this vulnerability required access to the user's email/password or phone number/code associated with the account and multiple bruteforcing attempts to bypass would be needed.
- **Insecure Storage and Overly Permissive  API Keys in Android App** — `#753868` · Zenly · $750 · ▲52
  > You can also create server-side filters to help prevent this thing from happening.
- **[Zomato for Business Android] Vulnerability in exported activity WebView** — `#537670` · Eternal · $0 · ▲52
  > Since the following activity `com.application.zomatomerchant.home.HomeSalt` has `exported="true"` it can be exploited by another application.
- **[Android] Directory traversal leading to disclosure of auth tokens** — `#1378889` · Slack · $3,500 · ▲50
  > In order to take advantage of this vulnerability, attackers needed to be in a workspace with the user and to induce a user to click on a file uploaded to Slack exceeding 1MB (files smaller than 1MB are not downloaded to the device and therefore do not present…
- **[Android] XSS via start ContentActivity** — `#189793` · Quora · $0 · ▲50
  > Using intent extra parameter `html` we can pass javascript, which will be executed in the context of www.quora.com.
- **iOS Brave Playlist "Open in Private Tab" bypasses FaceID requirement for Private Tabs** — `#3693295` · Brave Software · $0 · ▲49
  > Adding/Opening a song in your Brave playlist and holding for the option of "Open in new Private Tab" bypasses FaceID/Passcode Requirement for Private Tabs.

## Payload fragments observed

Recurring payloads from this class's writeups. Adapt, don't paste blindly.

| Seen | Fragment |
|---:|---|
| 2× | `www.pscp.tv/<user-id>/follow` |
| 2× | `<meta>` |
| 2× | `../../../lib-1/libjnigraphics.so` |
| 1× | `) could lead that an arbtrary URL was opened in a built-in browser in activity` |
| 1× | `pscp://user/<user-id> or pscpd://user/<user-id>` |
| 1× | `and be the connected to the Grab account on Android app) - or you can use my test number` |
| 1× | `<script>alert('Javascript is executed.')</script>` |
| 1× | `alert()` |
| 1× | `DELETE /api/v1/logout HTTP/1.1 / authorization: Bearer atkn_********************************** / Host: accounts.shopify.com / Connection: cl` |
| 1× | `GET /oauth/userinfo HTTP/1.1 / Accept-Encoding: gzip, deflate / authorization: Bearer *************** / ....` |
| 1× | `adb shell / am start -n com.quora.android/com.quora.android.ActionBarContentActivity -e url 'http://test/test' -e html 'XSS<script>alert(123` |
| 1× | `am start -n com.quora.android/com.quora.android.ModalContentActivity -e url 'http://test/test' -e html '<script>alert(QuoraAndroid.getClipbo` |
| 1× | `Intent i = new Intent(); / i.setComponent(new ComponentName("com.quora.android","com.quora.android.ActionBarContentActivity")); / i.putExtra` |
| 1× | `HTTP/1.1 400 Bad Request / Content-Encoding: gzip / Content-Type: application/json; charset=utf-8 / Date: Tue, 31 Jan 2017 17:45:43 GMT / X-` |
| 1× | `ImageList.fetchImageInfo(..)` |
| 1× | `<script> / location="https://www.google.com/search?q=</title><h1><marquee><s>Injection<!--" / </script>` |
| 1× | `<body> / <a href="intent://app/feedback#Intent;scheme=mymos;package=█████████;S.URL=javascript:(function() { alert('XSS by Cleanchain') })()` |
| 1× | `../../../../../../../data/data/jp.naver.line.android/files/something` |
| 1× | `getLastPathSegment()` |
| 1× | `file:///data/data/com.attacker/x/x/x/x/..%2F..%2F..%2F..%2Fsdcard%2Fprefs.xml` |

## Parameters observed

`view` · `url` · `diff` · `navigation_bar_title` · `id` · `raw_json` · `include_zero_rate` · `settings_version` · `ro` · `auth_token` · `session` · `screenType` · `report_id` · `text_query` · `sort_type` · `sort_direction` · `limit` · `page` · `path` · `name`

## Case studies

### [Grab Android/iOS] Insecure deeplink leads to sensitive information disclosure
`#401793` · Grab · $0 · high · 2019-03-15 · ▲552
> A deeplink feature was found missing validation that led to sensitive information disclosure. Once triggered, the deeplink would direct users to load any attacker-controlled URL within a webview. The impact was further escalated as the webview contain sensitive information. A temporary patch was distributed shortly after the submission was verified and a permanent patch was released and completely rolled out soon after.

### Multiple bugs leads to RCE on TikTok for Android
`#1065500` · TikTok · $0 · critical · 2021-03-17 · ▲371
> A series of WebView vulnerabilities were found including XSS which could have potentially led an attacker to achieve remote code execution. We thank @dphoeniixx for reporting this to our team and verifying the resolution!

### AWS bucket leading to iOS test build code and configuration exposure
`#404822` · Slack · $1,500 · critical · 2019-02-23 · ▲321
> @kiyell discovered an open AWS bucket which hosted the source code of the iOS test application, as well as some configuration information and test data relating to that test build. No customer data was exposed or at risk, and we resolved and investigated this issue. Thank you @kiyell for a neat finding!

### Periscope android app deeplink leads to CSRF in follow action
`#583987` · X / xAI · $1,540 · low · 2020-02-21 · ▲224
> This issue is mainly in the Periscope Android app against CSRF follow action using deeplink.

### [PayPal Android] Remote theft of user session using push_notification_webview deeplink
`#424443` · PayPal · $0 · medium · 2019-02-07 · ▲188
> A deeplink feature built into the PayPal Android application failed to validate the requested endpoint. A specifically crafted request from a website or separate app on the device could call the deeplink and direct traffic to any destination. While the impact was limited by compensating controls, headers containing sensitive data could be collected by a malicious actor.

## Wordlists

Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.

| File | Entries |
|---|---:|
| `~/.local/share/hackerone-reports/wordlists/paths_mobile.txt` | 77 |
| `~/.local/share/hackerone-reports/wordlists/params_mobile.txt` | 35 |
| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |
| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |

```sh
W=~/.local/share/hackerone-reports/wordlists
ffuf -u https://target/FUZZ -w $W/paths_mobile.txt \
     -mc all -fc 404 -fs 0 -rate 40
ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_mobile.txt \
     -mr 'canary|error|invalid|not found' -rate 40
```

## Nuclei

Nuclei only sees the backend. Decompile the app and test deep links, WebViews, and local storage manually.

```sh
nuclei -u https://target -tags android,ios \
       -severity low,medium,high,critical -rl 40 -o nuclei_mobile.txt
nuclei -u https://target -t ~/nuclei-templates/http/misconfiguration \
       -rl 40 -o nuclei_mobile_misconfiguration.txt
# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'
```

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

## Query the corpus

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class mobile --limit 20
python3 ~/.local/share/hackerone-reports/h1.py stats --class mobile
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```

Search by technology, endpoint, parameter, or program. Examples:

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class mobile
python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class mobile --min-bounty 1000
```

## Related

- `hackerone-auth-bypass` (989 reports)
- `hackerone-crypto-and-secrets` (562 reports)
- `hackerone-xss` (2,569 reports)

## Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.
