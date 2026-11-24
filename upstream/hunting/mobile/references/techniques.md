# Mobile Application Security — HackerOne field guide — Technique reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete technique.

---

## Quick wins



Start here. These are the highest-yield tests for this class.



- Decompile and inspect exported components and URL schemes.

- Test deep links for auth bypass, open redirect, and token leakage.

- Check local storage, logs, backups, and clipboard for secrets.

- Intercept traffic and test certificate pinning bypass.

- Look for insecure WebViews and JS bridges.



## Bypass tricks



- Bypass pinning with Frida/Objection.

- Use dynamic instrumentation for root/jailbreak checks.



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
