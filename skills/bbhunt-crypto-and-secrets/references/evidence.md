# Evidence appendix — Cryptographic Failures and Exposed Secrets

Mined from all **562 valid disclosed reports** for this class (83 paid, 15% — payment is not validity).

## Technique frequency (all valid writeups)

| Item | Count |
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

## Tools mentioned

| Item | Count |
|---|---:|
| source-code-review | 144 |
| curl | 109 |
| python | 29 |
| git | 27 |
| browser | 25 |
| nmap | 14 |
| burp | 12 |
| devtools | 11 |
| javascript-debugging | 9 |
| burp-intruder | 4 |
| burp-collaborator | 2 |
| collaborator/oast | 2 |

## Bypass primitives

| Item | Count |
|---|---:|
| bypass | 83 |
| content-type | 45 |
| %00 | 33 |
| bypassed | 25 |
| trailing dot | 24 |
| crlf | 17 |
| lowercase | 16 |
| bypassing | 14 |
| bypasses | 7 |
| whitelist | 4 |
| blind | 3 |
| unicode | 2 |
| normalize | 2 |
| url encoded | 1 |
| uppercase | 1 |
| mixed case | 1 |
| trailing slash | 1 |
| type confusion | 1 |
| normalized | 1 |
| case-sensitive | 1 |
| allowlist | 1 |
| normalizes | 1 |

## Impact language

| Item | Count |
|---|---:|
| password | 682 |
| token | 275 |
| secret | 253 |
| credential | 116 |
| localhost | 106 |
| admin | 96 |
| payment | 73 |
| api key | 63 |
| sensitive information | 51 |
| unauthorized | 47 |
| sensitive data | 21 |
| financial | 18 |
| account takeover | 14 |
| pii | 14 |
| exfiltration | 6 |
| rce | 4 |
| exfiltrate | 4 |
| internal service | 4 |
| privilege escalation | 3 |
| unauthorised | 3 |

## Parameters observed

| Item | Count |
|---|---:|
| max-age | 12 |
| charset | 11 |
| domain | 10 |
| name | 10 |
| path | 7 |
| expires | 7 |
| samesite | 7 |
| duse_apple_sectrust | 6 |
| version | 5 |
| random | 5 |
| result | 5 |
| signature | 5 |
| name0 | 5 |
| headers | 4 |
| mode | 4 |
| key | 4 |
| password | 4 |
| content | 4 |
| token | 4 |
| curlopt_ssl_verifypeer | 4 |
| verifypeer | 4 |
| subdomain | 4 |
| require_ocsp | 4 |
| serialnumber | 3 |
| encoding | 3 |
| subject | 3 |
| txt | 3 |
| phpsessid | 3 |
| post-check | 3 |
| pre-check | 3 |

## Recurring approach patterns

- **3×** ai disclosure i used an ai assistant claude for code review test setup and drafting
  - e.g. AI disclosure: I used an AI assistant (Claude) for code review, test setup and drafting.
- **2×** i was unable to use the found password as the api appears to be currently non functional but since the repo is active i would expect the server to be worked upon and the api to be functional in the future
  - e.g. I was unable to use the found password as the API appears to be currently non-functional, but since the repo is active I would expect the server to be worked upon, and the API to be functional in the future.
- **2×** for this reason i ve decided to make you aware of the issue
  - e.g. For this reason I've decided to make you aware of the issue.
- **2×** summary when i searched github for sensitive information i found some privet key in github repository
  - e.g. ## Summary: When I searched Github for sensitive information I found some privet key in GitHub repository.
- **1×** i have identified approximately android applications and some ipad that fail to validate ssl certificates either failing to validate valid certificate authorities correct hostnames or both
  - e.g. I have identified approximately 75 Android applications (and some iPad) that fail to validate SSL certificates, either failing to validate valid certificate authorities, correct hostnames or both.
- **1×** based on the available source code i see that proguard is not being used
  - e.g. Based on the [available source code]( I see that ProGuard is not being used.
- **1×** by mx receiving tld with esmtps id e3si1568039obp for recipient domain tld version tlsv1 cipher ecdhe rsa rc4 sha bits tue apr pdt the perhaps slightly obvious fix seems to be to support esmtps by allowing starttls to be negotiated by the sending system s
  - e.g. [167.89.13.71]) by mx.receiving.tld with ESMTPS id e3si1568039obp.178.2014.04.08.05.59.10 for <recipient@domain.tld> (version=TLSv1 cipher=ECDHE-RSA-RC4-SHA bits=128/128); Tue, 08 Apr 2014 05:59:11 -0700 (PDT) The perhaps slightly obvious fix seems to be to support ESMTPS by allowing STARTTLS to be 
- **1×** as a possible fix you can replace captcha check with a honeypot trap or a simple task or skill testing question
  - e.g. As a possible Fix, you can Replace Captcha check with- 1) A Honeypot Trap or 2) A simple Task or 3) Skill testing Question.
- **1×** i have used ncat which generates a certificate on the fly to demonstrate the issue ncat ssl p v n l ncat version ncat generating a temporary bit rsa key
  - e.g. I have used ncat which generates a certificate on the fly to demonstrate the issue: ncat --ssl -p 443 -v -n -l Ncat: Version 6.46 ( ) Ncat: Generating a temporary 1024-bit RSA key.
- **1×** i found that bruteforce protection is not enabled on the login page of
  - e.g. I found that bruteforce protection is not enabled on the login page of .
- **1×** i tried a lot but didn t get any type of capcha or ratelimiting
  - e.g. I tried a lot but didn't get any type of capcha or ratelimiting.
- **1×** i found a bug in twitter com description and poc create a twitter account having email address abcd x com
  - e.g. I found a bug in twitter.com Description and POC: 1) Create a twitter account having email address "abcd@x.com".
- **1×** twitterflight com from twitter inc i just checked it with whois website service encrypts traffic using an old deprecated protocol with known weakness wich is obsolete and insecure you should disable it
  - e.g. Twitterflight.com (From Twitter Inc..I just checked it with whois) Website service encrypts traffic using an old deprecated protocol with known weakness wich is obsolete and insecure, you should disable it.
- **1×** i have checked by reloading multiple times and all tokens are valid
  - e.g. I have checked by reloading multiple times and all tokens are valid.
- **1×** you can get a lot fancier with this such as creating a separate file per victim or by parsing the file within php and only writing the relevant information to disk
  - e.g. You can get a lot fancier with this, such as creating a separate file per victim, or by parsing the file within php and only writing the relevant information to disk.
- **1×** where i found it data data co vine android databases webview db poc please see the screenshot of sqlite database
  - e.g. - **Where I found it?** `/data/data/co.vine.android/databases/webview.db` - **POC:**Please see the screenshot of SQLite database.
- **1×** i created a program named puffer bird and i leave the sandbox to prepare to launch the program
  - e.g. I created a program named *Puffer Bird* and I leave the sandbox to prepare to launch the program.
- **1×** initial validation can begin by sending an email from the pufferbird com to support hackerone com
  - e.g. Initial validation can begin by sending an email from the Pufferbird.com to support@hackerone.com.
- **1×** so i went to a hosting website i created a new account to create a domain pufferbird com
  - e.g. So, I went to a [Hosting Website]( I created a New Account to create a domain *pufferbird.com* .
- **1×** screenshot after creating the domain i created an email no reply pufferbird com screenshot then i sent an email to hackerone com screenshot and it has been sent successfully
  - e.g. Screenshot: After creating the domain, I created an email *no-reply@pufferbird.com* Screenshot: Then, I sent an email to ██████@hackerone.com Screenshot: And It has been sent successfully.
- **1×** i sent another email directly to hackerone com using my own and real email
  - e.g. ----------- I sent another email directly to ██████@hackerone.com using my own and real email.
- **1×** screenshot short recap i made a program leave the sandbox to request review hackerone com emailed me for validation of the program i validate the program using the fake pufferbird com email address i emailed hackerone com that i already sent the email which contains information about the program
  - e.g. Screenshot: Short Recap: I made a program Leave the sandbox to request review ██████@hackerone.com emailed me for validation of the program I validate the program using the fake pufferbird.com email address I emailed ██████@hackerone.com that I already sent the email which contains information about
- **1×** this only works if the user has the remember me for a week option ticked when logging in
  - e.g. This only works if the user has the "Remember me for a week" option ticked when logging in.
- **1×** i furthermore noticed that the various values that i yielded upon subsequent logins did not look random at all but they instead looked quite similar to each other
  - e.g. I furthermore noticed that the various values that I yielded upon subsequent logins did not look random at all, but they instead looked quite similar to each other.

## Case studies (full excerpts)

### 340431 — Reflected XSS and sensitive data exposure, including payment details, on lioncityrentals.com.sg
Uber · $4000 · high · https://hackerone.com/reports/340431

lioncityrentals.com.sg employed a Wordpress installation that possessed a vulnerable plugin, Formidable Forms, which was vulnerable to reflected XSS, and exposed sensitive form data. Thanks again for the report, @healdb! This was the first bug I ever found that exposed a large amount of PII, thanks for disclosing @uber! This bug reinforces to me that hackers should always examine microsites as well as core domains, sometimes bugs on microsites can lead to significant data exposure. In this case, lioncityrentals.com.sg was collecting data on thousands of Uber Singapore users, which was then exposed by the outdated Wordpress plugin. You can read more about the formidable forms vulnerability here - And be sure to check out my blog or my twitter for Bug Bounty tips and guides!

### 1888803 — Use of Cryptographically Weak Pseudo-Random Number Generator in WebCrypto keygen
Internet Bug Bounty · $4000 · high · https://hackerone.com/reports/1888803

CVE-2022-35255 Detail Description A weak randomness in WebCrypto keygen vulnerability exists in Node.js 18 due to a change with EntropySource() in SecretKeyGenTraits::DoKeyGen() in src/crypto/crypto_keygen.cc. There are two problems with this: 1) It does not check the return value, it assumes EntropySource() always succeeds, but it can (and sometimes will) fail. 2) The random data returned byEntropySource() may not be cryptographically strong and therefore not suitable as keying material. NVD Link: HackerOne original report:

### 113288 — OpenSSL Key Recovery Attack on DH small subgroups (CVE-2016-0701)
Internet Bug Bounty · $2500 · severity n/a · https://hackerone.com/reports/113288

Full write up: DH small subgroups (CVE-2016-0701) ================================== Severity: High Historically OpenSSL usually only ever generated DH parameters based on "safe" primes. More recently (in version 1.0.2) support was provided for generating X9.42 style parameter files such as those required for RFC 5114 support. The primes used in such files may not be "safe". Where an application is using DH configured with parameters based on primes that are not "safe" then an attacker could use this fact to find a peer's private DH exponent. This attack requires that the attacker complete multiple handshakes in which the peer uses the same private DH exponent. For example this could be used to discover a TLS server's private DH exponent if it's reusing the private DH exponent or it's using a static DH ciphersuite. OpenSSL provides the option SSL_OP_SINGLE_DH_USE for ephemeral DH (DHE) in TLS. It is not on by default. If the option is not set then the server reuses the same private DH exponent for the life of the server process and would be vulnerable to this attack. It is believed that many popular applications do set this option and would therefore not be at risk. OpenSSL before 1.0.2f will reuse the key if: - - SSL_CTX_set_tmp_dh()/SSL_set_tmp_dh() is used and SSL_OP_SINGLE_DH_USE is not set. - - SSL_CTX_set_tmp_dh_callback()/SSL_set_tmp_dh_callback() is used, and both the p

### 1888758 — Inadequate Encryption Strength in nodejs-current reads openssl.cnf from /home/iojs/build/... upon startup on MacOS
Internet Bug Bounty · $2400 · medium · https://hackerone.com/reports/1888758

CVE-2022-32222 Detail Current Description A cryptographic vulnerability exists on Node.js on linux in versions of 18.x prior to 18.40.0 which allowed a default path for openssl.cnf that might be accessible under some circumstances to a non-admin user instead of /etc/ssl as was the case in versions prior to the upgrade to OpenSSL 3. NVD Details: HackerOne original report:

### 168538 — Twitter iOS fails to validate server certificate and sends oauth token
X / xAI · $2100 · high · https://hackerone.com/reports/168538

Twitter on iOS newest two versions (6.62 and 6.62.1) are affected, other versions not tested. Tested independently on two different iPhone 6 with iOS version 9.3.3 and 9.3.5 without Jailbreak. The iPhone were without any mobileconfig profiles installed - *no* we did not install any CA certificate in the CA store of the device. Really stock iPhones. The Twitter app does not check the SSL/TLS certificate of . A transparent proxy setup (eg. burp suite in transparent mode) is sufficient to exploit. Steps to reproduce: 1. Start Burp or other Proxy software in transparent mode. Setting "Generate CA-signed per-host certificates", which means the CA cert of Burp is used, which is *not* trusted on the iPhones. 2. Start rogue Wifi access point (eg. on the same machine as burp) 3. Redirect all incoming HTTPS traffic on the rogue Wifi access point to the transparent proxy. We simply used on Linux: iptable -t nat -A PREROUTING -i wlan0 -p tcp --dport 443 -j DNAT --to $BURP_IP:8080 iptable -t nat -A PREROUTING -i wlan0 -p tcp --dport 443 -j REDIRECT --to-port 8080 4. Connect with the iOS device to the Wifi access point 5. Open Twitter app on iOS 6. In burp only the calls to api.twitter.com are visible and include sensitive authentication information etc. This is the information we saw for two different accounts in burp which includes the oauth token etc.: GET /1.1/help/settings.json?include_

### 716292 — JumpCloud API Key leaked via Open Github Repository.
Starbucks · no bounty (valid finding) · critical · https://hackerone.com/reports/716292

**Summary:** Open Github Repo Leaking Starbucks JumbCloud API Key **Description:** Team, While going through Github search I discovered a public repository which contains Jumbcloud API Key of Starbucks. Repo: [ File: [ **POC** * List systems There are multiple AWS instances present * * SSO Applications AWS login SAM config is presents. This would leads to AWS account takeover ## Impact This issue impact is critical as through this API anyone could * Execute commands on systems [ * Add/Remove users which has access to internal systems * AWS Account Takeover

### 396467 — Github Token Leaked publicly for https://github.sc-corp.net
Snapchat · no bounty (valid finding) · critical · https://hackerone.com/reports/396467

###Description : GitHub is a truly awesome service but it is unwise to put any sensitive data in code that is hosted on GitHub and similar services as i was able to find github token indexed ***7 hours Ago*** by user ***██████ - Software Engineer - Snap Inc*** ### Issue & POC : You can find the leak in this link : ## Impact I didn't try anything with the token, and dont know what access it has, and i know that in order to login to you need to have an email @snap but still i though it would be a good idea to share this finding with you in case it can be used in a way that i dont know. Best Regards

## Field playbook (unedited)

### quick

- Search JS bundles, mobile apps, and public repos for keys/tokens.
- Check password storage, reset tokens, and encryption modes.
- Test TLS/certificate validation in mobile/thick clients.
- Look for secrets in logs, errors, URLs, and analytics.

### payloads

- Regex -> `AKIA[0-9A-Z]{16}`, `AIza[0-9A-Za-z_-]{35}`, `ghp_[0-9A-Za-z]{36}`
- JWT secret -> `hashcat -m 16500`
- Weak reset token -> timestamp/random seed

### bypass

- Check base64/hex-obfuscated keys in bundles.
- Look at source maps and CI artifacts for env files.
- Test key scope before reporting.

### surface

- js
- env
- config
- logs
- mobile
- repo
- backup

### tools

- trufflehog
- gitleaks
- hashcat
- jwt_tool
- nuclei

### chain

- Leaked key -> cloud access.
- Weak crypto -> token forgery.

## Corpus search commands

```sh
python3 ~/.local/share/hackerone-reports/h1.py stats --class crypto-and-secrets
python3 ~/.local/share/hackerone-reports/h1.py search "<feature or param>" --class crypto-and-secrets --limit 10
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```
