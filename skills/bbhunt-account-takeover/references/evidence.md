# Evidence appendix — Account Takeover Chains

Mined from all **64 valid disclosed reports** for this class (10 paid, 16% — payment is not validity).

## Technique frequency (all valid writeups)

| Item | Count |
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

## Tools mentioned

| Item | Count |
|---|---:|
| browser | 5 |
| source-code-review | 3 |
| curl | 3 |
| devtools | 2 |
| burp | 2 |
| python | 1 |
| javascript-debugging | 1 |
| burp-collaborator | 1 |
| ffuf | 1 |
| collaborator/oast | 1 |
| subfinder | 1 |
| git | 1 |
| decompiler | 1 |
| waybackurls | 1 |

## Bypass primitives

| Item | Count |
|---|---:|
| content-type | 13 |
| bypass | 12 |
| bypassing | 2 |
| whitelist | 2 |
| parameter pollution | 2 |
| blind | 2 |
| %00 | 1 |
| blacklist | 1 |
| header injection | 1 |

## Impact language

| Item | Count |
|---|---:|
| password | 68 |
| token | 48 |
| admin | 32 |
| credential | 18 |
| account takeover | 12 |
| unauthorized | 6 |
| privilege escalation | 3 |
| exfiltrate | 3 |
| rce | 3 |
| sensitive data | 2 |
| payment | 2 |
| exfiltration | 2 |
| secret | 1 |
| api key | 1 |
| remote code execution | 1 |
| sensitive information | 1 |
| full access | 1 |

## Parameters observed

| Item | Count |
|---|---:|
| password | 2 |
| month | 2 |
| year | 2 |
| username | 1 |
| challenge | 1 |
| challenge_answer | 1 |
| url | 1 |
| page. | 1 |
| risk. | 1 |
| approved | 1 |
| address | 1 |
| takeover | 1 |
| scope | 1 |

## Recurring approach patterns

- **1×** so i was able to claim the domain for my own host and thus can place content on this url
  - e.g. So I was able to claim the domain for my own host, and thus, can place content on this URL.
- **1×** description i have noticed that there is no security check at changing password
  - e.g. #Description I have noticed that there is no security check at changing password.
- **1×** hi summary i have found a design issue on the e mail change functionality offered by the accounts profile handler
  - e.g. Hi, **Summary** I have found a design issue on the e-mail change functionality offered by the "/accounts/profile" handler.
- **1×** i changed my email1 to email2 through profile
  - e.g. I changed my email1 to email2 through profile 2.
- **1×** it was failed and when i used email2 its working
  - e.g. It was failed and when I used email2 its working.
- **1×** the researcher was able to pass verification to another account by finding confirmation data in response from the server
  - e.g. The researcher was able to pass verification to another account by finding confirmation data in response from the server.
- **1×** i was able to claim dmc support zendesk com
  - e.g. I was able to claim dmc-support.zendesk.com.
- **1×** also attached is the apk of the malicious app i used as poc and for the video
  - e.g. Also attached is the `.apk` of the "malicious" app i used as PoC and for the video.
- **1×** after quickly restricting access to this endpoint we investigated and found no activity except that of the reporter
  - e.g. After quickly restricting access to this endpoint, we investigated and found no activity except that of the reporter.
- **1×** f859739 flag flag 736c635d8842751b8aafa556154eb9f3 flag in this report i ll try to focus more on my way of thinking rather than on the technical implementation so others will be able to learn what i ve learned and use it to hit harder and make our world a safer place
  - e.g. 💙 {F859739} Flag: `^FLAG^736c635d8842751b8aafa556154eb9f3$FLAG$` In this report, I'll try to **focus more on my way of thinking**, rather than on the technical implementation so others will be able to learn what I've learned and use it to hit harder and make our world a safer place.
- **1×** ctf walkthrough recon i ve started the challenge by performing two basic recon steps subdomain enumeration with subfinder subfinder d bountypay h1ctf com
  - e.g. ## CTF Walkthrough ## Recon I've started the challenge by performing two basic recon steps: - Subdomain enumeration with [subfinder]( (`subfinder -d bountypay.h1ctf.com`).
- **1×** finding credentials in the log file i was able to find base64 encoded strings to make it easier to work with i used the following bash liner which prints only the base64 decoded payload the next step was to actually try and log in with the exposed username and password username brian oliver password v7h0inzx but it required me to do a factor authentication
  - e.g. ## Finding Credentials In the log file I was able to find base64 encoded strings: To make it easier to work with, I used the following Bash 1-liner which prints only the base64 **decoded** payload: The next step was to actually try and log in with the exposed username and password `{"username":"bria
- **1×** f859768 finding the next door ssrf via load transactions functionality now that i was logged in as brian i saw the bountypay dashboard with no transactions
  - e.g. {F859768} ## Finding the next door (SSRF via "Load Transactions" functionality) Now that I was logged in as Brian I saw the BountyPay Dashboard with no transactions.
- **1×** during the recon phase i also found out two more things that now come handy
  - e.g. During the recon phase I also found out two more things that now come handy: 1.
- **1×** in there is a link to google with an explanation on what is rest api but the link isn t referring directly to google but to an internal redirect endpoint which have some kind of urls whitelist by combining those two clues i decided to enumerate files directories in the software subdomain and was able to achieve it by chaining the ssrf vulnerability with the semi open redirect
  - e.g. In there is a link to Google with an explanation on what is REST API, but the link isn't referring directly to Google, but to an internal `/redirect` endpoint (which have some kind of URLs whitelist) By combining those two clues, I decided to enumerate files/directories in the software subdomain and
- **1×** i created a simple bash script that gets a url and generates the base64 encoded cookie value
  - e.g. I created a simple Bash script that gets a url and generates the base64 encoded cookie value.
- **1×** i created the payloads list and used ffuf for the enumeration one of the responses contained the following data which tells us that directory listing is enabled in uploads and that there is an apk file there
  - e.g. I created the payloads list and used ffuf for the enumeration: One of the responses contained the following data which tells us that directory listing is enabled in `/uploads/` and that there is an APK file there.
- **1×** i was then able to download the file from android application reverse engineering challenge i started by installing the application on a local android studio emulator
  - e.g. I was then able to download the file from ## Android Application Reverse-Engineering Challenge I started by installing the application on a local [Android Studio]( emulator.
- **1×** then once i clicked the money bag button at the bottom of the app i saw the following notification f860987 deep links
  - e.g. Then once I clicked the money bag button at the bottom of the app I saw the following notification: {F860987} Deep links?
- **1×** let s open up the code in order to start reverse engineering the application i used multiple tools and techniques which will now be explained
  - e.g. **Let's open up the code.** In order to start reverse-engineering the application, I used multiple tools and techniques which will now be explained.
- **1×** i used apktool to unpack the apk file
  - e.g. I used [Apktool]( to unpack the APK file.
- **1×** once the apk is unpacked we can investigate things like the manifest file and look for hard coded strings
  - e.g. Once the APK is unpacked we can investigate things like the manifest file and look for hard-coded strings.
- **1×** after i searched for hard coded strings like urls tokens and api keys without success i moved on to investigating the deep links
  - e.g. After I searched for hard-coded strings like URLs, tokens, and API keys without success, I moved on to investigating the deep-links.
- **1×** i used dex2jar and jd gui to decompile the code and view it as java files
  - e.g. I used [dex2jar]( and [jd-gui]( to decompile the code and view it as java files.

## Case studies (full excerpts)

### 862589 — Spring Actuator endpoints publicly available, leading to account takeover
LY Corporation · $5000 · critical · https://hackerone.com/reports/862589

Due to insufficient access controls, it was possible to access the Spring Boot Actuator endpoints /heapdump and /env. The /heapdump endpoint leaks data from the Java Virtual Machine, leading to disclosure of admin credentials, user tokens and a combination of other data. This endpoint was not discovered by the internal security team due to being put on a custom path, avoiding detection through our usual means. The reporter accessing this endpoint also triggered a warning for our CSIRT team, allowing us to take quick and coordinated action. After quickly restricting access to this endpoint, we investigated and found no activity except that of the reporter. The maximum impact of this issue was potential takeover of random LINE Official Accounts through leaked tokens/cookies. We appreciate the professionalism and clear communication from @kazan71p and want to thank him for helping keep LINE secure.

### 2798380 — Hackerone supports accounts organitation takeover
HackerOne · $2500 · medium · https://hackerone.com/reports/2798380

## Description: - I have discovered a vulnerability in HackerOne's email change process where the system automatically verifies the email address if the verification link is opened in any browser. This behavior differs from report #2128237, as it affects specific situations where email scanning bots automatically open links without human interaction. - The issue arises because some email services, such as security bots that scan emails and analyze links, automatically open verification links. In certain cases, these bots do not validate whether the email originates from a "no-reply" address or another that should prevent verification. By exploiting this behavior, an attacker can verify email addresses without the legitimate owner’s interaction, allowing them to register email addresses as if they belong to a specific company. ## Reproduction Steps: 1. Register an account on HackerOne with any valid email address. 2. Change the email of the account to one belonging to a company that uses email scanning bots (e.g., certain security solutions). example ██████ 3. If the email system of the target automatically scans the link without properly checking the email nature, the email address will be verified without any human action. 4. This allows the attacker to use a fake corporate email address without the legitimate owner’s consent. - In this case, HackerOne attempts to request SAML

### 1266828 — Staff who only have apps and channels permission can do a takeover account at the wholesale store (Bypass get invitation link)
Shopify · $1600 · medium · https://hackerone.com/reports/1266828

When we invite customers at the wholesale store there is a feature to "Send invite" and "Get invite link" the get invite link feature displays the customner invitation link and can only be used once, but when the customer has accepted the invitation and actived their account already have access to wholesale store then these 2 features will not be able to be used again, this works as it should and the invitation link itself can be used to change the customer's account password, maybe this is why the "Get invite link" feature cannot be used again when the customer has activated his account because to avoid takeover accounts, but here I found a vulnerability to bypass getting an activated account customer invite link so that staff who only have Wholesale permission can get an invitation link even though the customer has activated his account which causes the takeover account Step to reproduce : I tested with Shopify plus partner sandbox store 1. Login to the store using the account staff who only has permission to wholesale 2. At wholesale customers, customers whose accounts are already active will have the status of Enable {F1380035} 3. Here you will not be able to use the Send invite and Get invite link features, and if you use these features you will get an error Error when using the send invite feature : {F1380038} Error when using the Get invite link feature : {F1380040} Here

### 1626205 — Wordpress Takeover using setup configuration at http://████.edu [HtUS]
U.S. Dept Of Defense · $1000 · critical · https://hackerone.com/reports/1626205

Description: The WordPress 'setup-config.php' installation page allows users to install WordPress in local or remote MySQL databases. This typically requires a user to have valid MySQL credentials to complete. However, a malicious user can host their own MySQL database server and can successfully complete the WordPress installation without having valid credentials on the target system. Reproduce step by step: I found this vulnerable url: Then i configured db I used this site After configure I got wordpress admin access proof: Admin credentials that I set after installing the config username: ████████ password: ███ Login Panel: Video POC has been attached as well. ## Impact Impact Remote Code Execution/Total system compromise. Attacker can upload webshell into the server. I did not upload any shell for security violation. Malware distribution Phishing / Spear phishing XSS Authentication bypass

### 1679734 — Account Takeover Vulnerability in Shopify Collabs Platform Due to Missing Email Verification
Shopify · $800 · low · https://hackerone.com/reports/1679734

## Summary: Shopify collabs (collabs.shopify.com) is a new platform for content creators / influencers to discover and advertise the millions of brands of Shopify. The content creators can apply for different brands on this platform and get paid (affiliate marketing). In the past, the features of this new platform were provided by Dovetale ( but Dovetale was now * migrated to Shopify (via an extra app for the **brands** * replaced by the new platform collabs.shopify.com for the **creators** I found a way to take over the account of **arbitrary creators** by using the new platform collabs.shopify.com. If a creator applies to be an ambassador of a brand with his email address, an attacker is also able to create a new Shopify ID and sign up at collabs.shopify.com with the **victim's email address**. Due to the fact that there is no email verification needed for using collabs.shopify.com, the attacker is thus able to take over the victim's account. ## Shops Used to Test: ██████ ## Steps To Reproduce: ### Setup 1. (Brand) Install the new Shopify collabs app ( to your store and create an application page for the creators 2. (Victim/Creator) Use the public link to apply for being an ambassador for the brand. You can find the link in the Dashboard of the app: {F1875876} 3. (Victim/Creator) Follow the application process. Choose an email address (kun_19+takeover@wearehackerone.com in my

### 867513 — Takeover an account that doesn't have a Shopify ID and more
Shopify · no bounty (valid finding) · critical · https://hackerone.com/reports/867513

## Details The can be exploited to update a staff member email without any email confirmation. Using the partner dashboard, we've the ability to create a store that doesn't have a Shopify ID account on By using these two together, all we have to do is create an arbitrary store to an email that we own and confirm it with received email, then use the the POS Staff endpoint to update our email without having to validate it. You'll then be prompted to create a Shopify ID for your stores (the new created one alongs with the victim stores) and you won't need to validate that you own the email since it is already verified. ## Steps to reproduce 1. Have a victim with a shop that doesn't have a Shopify ID 1. Open and create a development store 1. Within the store creation form, you'll need to update your shop email to one that doesn't exist within Shopify and that you own (so it can be validated). As the field is read-only, that can either be done by intercepting the request with an application like Burp or do the above **within your browser console** to update the form object. 1.. Validate that you own the email address (Link sent to your email) 1. Add the **POS** to your shop **Sales Channels** 1. Open up the **POS > Staff** 1. Save your own staff page and copy the CURL request by using browser inspection 1. Replace the CURL payload email field with the victim email and send the reque

### 759454 — Helpdesk Takeover at dmc.datastax.com
DataStax · no bounty (valid finding) · high · https://hackerone.com/reports/759454

## Summary: DNS record [dmc.datastax.com](dmc.datastax.com) is pointing to stale [dmc-support.zendesk.com](dmc-support.zendesk.com) domain on Zendesk which is available for takeover. DNS Stale Records: {F661014} ## Proof of Concept: There was no helpdesk configured at this address, which means that the address was available and anyone could claim it. I was able to claim dmc-support.zendesk.com. On this page, I haven't made the page public, I'm attaching a screenshot of the webpage: {F661004} ## Supporting Material/References: Login page: {F661021} ## Impact Subdomain takeover

## Field playbook (unedited)

### quick

- Enumerate ATO primitives: reset, email change, OAuth linking, OTP, session fixation.
- Test email-change flows for missing verification, race, and token leakage.
- Look for reset-token leakage via Referer, host-header poisoning, and shared caches.
- Test account merging/linking and pre-registration takeover.

### payloads

- Host header -> `Host: evil.com` in reset request
- Email -> `victim@example.com` with unicode/plus/dot variants
- OAuth -> link attacker provider to victim email
- OTP -> brute force, reuse, response leakage

### bypass

- Chain XSS/CSRF/IDOR into the ATO path.
- Abuse email normalization and case sensitivity.
- Race the email-change confirmation.

### surface

- reset
- email
- verify
- oauth
- link
- otp
- mfa
- session

### tools

- Burp
- Turbo Intruder
- interactsh

### chain

- Reset poisoning -> ATO.
- XSS -> cookie theft -> ATO.
- OAuth link -> ATO.

## Corpus search commands

```sh
python3 ~/.local/share/hackerone-reports/h1.py stats --class account-takeover
python3 ~/.local/share/hackerone-reports/h1.py search "<feature or param>" --class account-takeover --limit 10
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```
