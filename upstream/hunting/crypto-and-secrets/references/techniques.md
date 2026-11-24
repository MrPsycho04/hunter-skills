# Crypto And Secrets — Combined Field Guide — Technique reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete technique.

---

## Quick wins



Start here. These are the highest-yield tests for this class.



- Search JS bundles, mobile apps, and public repos for keys/tokens.

- Check password storage, reset tokens, and encryption modes.

- Test TLS/certificate validation in mobile/thick clients.

- Look for secrets in logs, errors, URLs, and analytics.



## Bypass tricks



- Check base64/hex-obfuscated keys in bundles.

- Look at source maps and CI artifacts for env files.

- Test key scope before reporting.



## Deeper checklist



- Search JS bundles, mobile apps, and public repos for API keys, tokens, and private keys.

- Check password storage and reset tokens for weak hashing, short entropy, or reuse.

- Test TLS/certificate validation in mobile and thick clients (proxy interception).

- Look for secrets in logs, error messages, URLs, and analytics events.

- Check encryption modes, IV reuse, hardcoded keys, and missing integrity protection.

- Validate that a leaked key is live and scoped to sensitive access before reporting.



## Techniques from real reports



One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.



- **JumpCloud API Key leaked via Open Github Repository.** — `#716292` · Starbucks · $0 · ▲739

  > File: [https://github.com/████/Project/blob/0d56bb910923da2fbee95971778923f734a25f68/getSystemUsers.go](https://github.com/████/Project/blob/0d56bb910923da2fbee95971778923f734a25f68/getSystemUsers.go)

- **Github Token Leaked publicly for https://github.sc-corp.net** — `#396467` · Snapchat · $0 · ▲582

  > https://github.com/█████/leetcode/blob/0eec6434940a01e490d5eecea9baf4778836c54e/TopicMatch.py

- **Reflected XSS and sensitive data exposure, including payment details, on lioncityrentals.com.sg** — `#340431` · Uber · $4,000 · ▲376

  > And be sure to check out my blog https://healdb.tech/blog/ or my twitter https://twitter.com/heald ben

- **Reset any password** — `#703972` · pixiv · $0 · ▲313

  > 1.input the email [reset password url](https://www.pixiv.net/reminder.php).

- **Infromation Disclosure To Use of Hard-coded Cryptographic Key** — `#2353237` · Reddit · $0 · ▲238

  > [ I discovered this link while I was conducting a survey and collecting information, and I discovered it when I visited this link https://www.reddit.com/?rdt=49420 after logging into my account, as I will explain in pictures using the Trufflehog tool.

- **Key Reinstallation Attacks: Breaking WPA2 by forcing nonce reuse** — `#286740` · Internet Bug Bounty · $0 · ▲191

  > [The Wi-Fi Alliance](https://www.wi-fi.org/news-events/newsroom/wi-fi-alliance-security-update) is using these to [test if new products are affected](https://www.wi-fi.org/security-update-october-2017) or not.

- **Slack DTLS uses a private key that is in the public domain, which may lead to SRTP stream hijack** — `#531032` · Slack · $2,000 · ▲170

  > Notice that the `SetRemoteDescription` fingerprint in the `about:webrtc-internals` page is `C5:5F:DA:7D:84:47:B1:BF:6B:55:16:62:48:31:3E:D3:F1:7B:25:89:92:4A:4B:4D:4D:D9:D5:AF:EA:D8:15:44`

- **Public and secret api key leaked  in JavaScript source** — `#983331` · Stripo Inc · $0 · ▲148

  > Directory sensitive is ``main.c1965c58f39a0f4aadc3.js`` parse this json files using jsonparseronline

- **[3DS][SSL] Improper certificate validation allows an attacker to perform MitM attacks** — `#894922` · Nintendo · $0 · ▲129

  > - spoofing the `NetUpdateSOAP` and `ECommerceSOAP` endpoints used by the NIM module to:

- **MySQL username and password leaked in developer.valvesoftware.com via source code dislosure** — `#291057` · Valve · $0 · ▲123

  > But they forgot about `/scripts/`itself where it's also allowing a directory listing to see it contents.

- **connect.8x8.com/api/v1: JWT Algorithm Confusion Vulnerability** — `#3800870` · 8x8 · $1,337 · ▲111

  > @kyotozzx reported a JWT algorithm confusion vulnerability in the `v1` API of `connect.8x8.com`.

- **Unauthorized Account Access via Leaked Credentials in URL Format (Account Takeover )** — `#3080597` · Khan Academy · $0 · ▲107

  > this time the email and password of the victim is archived in clear text ( https://en.khanacademy.org/login,██████,,█████████,,,█████████,██████████,Personal )

- **Insecure Zendesk SSO implementation by generating JWT client-side** — `#638635` · Trint Ltd · $0 · ▲102

  > Looking at some of the UI views, I stumbled upon `static/js/modules/auth/pages/ZendeskLoadingPage.js`.

- **Important information leaked on Github** — `#649322` · Equifax-vdp · $0 · ▲98

  > In the following link (https://github.com/ajiththorali/Testing/blob/49025b364451fb2076f85ad009a0dc50a941c5ce/target/classes/API Equifax/propertiesHandle.properties) you could find this info

- **internal dev tokens disclosure** — `#1940443` · Snapchat · $250 · ▲96

  > such as https://github.com/Snapchat/KeyDB/commit/157b32109854f947843366f66215ccf90809e766

- **Leaked reused password for a few Khan Academy users** — `#3099978` · Khan Academy · $0 · ▲92

  > Increased risk of account takeover (ATO) if users reuse passwords across platforms.

- **Github Token Leaked publicly for https://github.com/mopub** — `#612231` · X / xAI · $0 · ▲92

  > ====================================================

- **███ leaking PII of tour visitors (names, email addresses, phone numbers) via misconfigured record permissions** — `#2294930` · U.S. Dept Of Defense · $0 · ▲90

  > Content-Type: application/x-www-form-urlencoded;charset=UTF-8

- **Cleartext Transmission of Sensitive Information Leads to administrator access** — `#813159` · Helium · $0 · ▲89

  > Vulnerable URL: https%3A%2F%2Fconsole.helium.com%2Fusers

- **fetlife.com/signup_step_profile expose access_token of mapbox.com** — `#2129769` · FetLife · $0 · ▲87

  > Upon having this access token, I could freely use your token on my site, even though fetlife have `Referer: https://fetlife.com/`, I could navigate around that easily using direct http call from my server and inject Referer header as `https://fetlife.com/`.

- **elections.k8s.io uses weak session secret key, may place elections at risk** — `#1387366` · Kubernetes · $250 · ▲86

  > @nagli and I discovered that `elections.k8s.io` uses a weak Flask SECRET KEY, literally the string `N/A`, to sign authentication cookies.

- **Microsoft `x-apikey` Exposed in Mozilla CI Public Logs** — `#3243860` · Mozilla · $200 · ▲84

  > The key appears in HTTP POST requests sent to Microsoft's telemetry endpoint during automated Firefox testing and is captured via mitmproxy logs.

- **Invite tokens have Insufficient entropy in GHES Management Console** — `#2197801` · GitHub · $0 · ▲81

  > An insufficient entropy vulnerability was identified in GitHub Enterprise Server (GHES) that allowed an attacker to brute force a user invitation to the GHES Management Console.

- **Cookie steal through content Uri** — `#876192` · Brave Software · $0 · ▲79

  > Because of the usage of `root-path` with path `.`, it is possible to use this provider to point to all files in the Android system.

- **Sensitive Info Leak - An Attacker Can Retrieve All the Users Mobile Numbers at https://website-api.production.curve.app/api/waitlist/us** — `#902733` · Curve · $0 · ▲79

  > When am going through all the JS files in curve.com I found a link called "/usa" is used to create Curve USA Waitlists by entering your name, email address, mobile number and address details.

- **SMTP interaction theft via MITM** — `#953219` · PortSwigger Web Security · $0 · ▲78

  > See http://www.postfix.org/CVE-2011-0411.html for adetailled description.

- **Page has a link to google drive which has logos and a few customer phone recordings** — `#864712` · Eternal · $200 · ▲76

  > As you can see in the above image,there are about 35 recordings wherein sensitive information is being disclosed.I guess everything is uploaded yesterday (May 1st).

- **Grammarly Keyboard for Android "Authorization Code with PKCE" flow implementation vulnerability that allows account takeover** — `#824931` · Superhuman (formerly Grammarly) · $0 · ▲76

  > @tomtenisse identified a vulnerability in Grammarly Keyboard for Android that allowed malicious application installed on the device to guess the PKCE code verifier value and consequently obtain access to OAuth access token (`grauth` cookie).

- **SameSite restrictions are lifted, and SameSite:Strict cookie are being sent.** — `#3253725` · Brave Software · $0 · ▲73

  > The reason SameSite=Strict cookies are being sent in this case is because the Sec-Fetch-Site: cross-site header, which should normally be present, is missing.

- **明確な認証不備および潜在的な中間者攻撃の可能性（Clear Authentication Deficiencies & Potential for Man-in-the-Middle Attacks）** — `#2642615` · Sony · $0 · ▲71

  > For example, if you want to set the Bluetooth name to "Example Laptop", write `PRETTY HOSTNAME=Example Laptop` in `machine-info`.



## Case studies



### JumpCloud API Key leaked via Open Github Repository.

`#716292` · Starbucks · $0 · critical · 2019-12-30 · ▲739

> Summary: Open Github Repo Leaking Starbucks JumbCloud API Key Description: Team, While going through Github search I discovered a public repository which contains Jumbcloud API Key of Starbucks. Repo: https://github.com/██████████/Project. File: https://github.com/████/Project/blob/0d56bb910923da2fbee95971778923f734a25f68/getSystemUsers.go POC List systems There are multiple AWS instances present SSO Applications AWS login SAM config is presents.



### Github Token Leaked publicly for https://github.sc-corp.net

`#396467` · Snapchat · $0 · critical · 2018-10-08 · ▲582

> GitHub is a truly awesome service but it is unwise to put any sensitive data in code that is hosted on GitHub and similar services as i was able to find github token indexed 7 hours Ago by user ██████ - Software Engineer - Snap Inc



### Reflected XSS and sensitive data exposure, including payment details, on lioncityrentals.com.sg

`#340431` · Uber · $4,000 · high · 2020-04-30 · ▲376

> lioncityrentals.com.sg employed a Wordpress installation that possessed a vulnerable plugin, Formidable Forms, which was vulnerable to reflected XSS, and exposed sensitive form data. Thanks again for the report, @healdb! This was the first bug I ever found that exposed a large amount of PII, thanks for disclosing @uber! This bug reinforces to me that hackers should always examine microsites as well as core domains, sometimes bugs on microsites can lead to…



### Reset any password

`#703972` · pixiv · $0 · high · 2021-03-31 · ▲313

> When I try to reset the password, the verification code of the mailbox is 6 digits, and there is no limit on the number of submissions, so I can reset the password of any user.



### Infromation Disclosure To Use of Hard-coded Cryptographic Key

`#2353237` · Reddit · $0 · medium · 2024-02-06 · ▲238

> [ Leaking very sensitive information through a JS file that is clearly for developers within the website and should not be available to the public. The leaked information consists of a lot of API keys, Paypal keys, information and keys about the server and the application, and a lot or a lot of sensitive information, and I will explain the information through screenshots. ] I will explain and clarify each of these keys that were leaked.



## Query the corpus



```sh

python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class crypto-and-secrets --limit 20

python3 ~/.local/share/hackerone-reports/h1.py stats --class crypto-and-secrets

python3 ~/.local/share/hackerone-reports/h1.py show <id> --full

```



Search by technology, endpoint, parameter, or program. Examples:



```sh

python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class crypto-and-secrets

python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class crypto-and-secrets --min-bounty 1000

```
