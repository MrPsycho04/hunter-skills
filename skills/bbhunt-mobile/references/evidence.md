# Evidence appendix — Mobile App and Client-Side Flaws

Mined from all **49 valid disclosed reports** for this class (14 paid, 29% — payment is not validity).

## Technique frequency (all valid writeups)

| Item | Count |
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

## Tools mentioned

| Item | Count |
|---|---:|
| browser | 5 |
| devtools | 2 |
| source-code-review | 2 |
| javascript-debugging | 1 |
| zap | 1 |

## Bypass primitives

| Item | Count |
|---|---:|
| bypass | 5 |
| bypassed | 4 |
| content-type | 1 |
| trailing dot | 1 |
| bypassing | 1 |
| normalization | 1 |
| normalized | 1 |
| unicode | 1 |

## Impact language

| Item | Count |
|---|---:|
| password | 13 |
| admin | 13 |
| token | 12 |
| unauthorized | 3 |
| credential | 2 |
| privilege escalation | 1 |
| remote code execution | 1 |
| arbitrary code | 1 |
| secret | 1 |

## Parameters observed

| Item | Count |
|---|---:|
| str4 | 2 |
| str5 | 2 |
| localbundle | 1 |
| str1 | 1 |
| str2 | 1 |
| str3 | 1 |
| localhttpmethod | 1 |
| exported | 1 |
| report_id | 1 |
| view | 1 |
| text_query | 1 |
| sort_type | 1 |
| sort_direction | 1 |
| limit | 1 |
| page | 1 |

## Recurring approach patterns

- **1×** i have already tried to logout from my twitter apps including from built in twitter apps for ios and then i already reboot the idevice too
  - e.g. I have already tried to logout from my Twitter apps (including from built-in twitter apps for iOS), and then, I already reboot the iDevice too.
- **1×** so when testing i entered the random mobile number and twitter says that verification code sent to the mobile number and asking for the verification code i cant provide the code coz i entered the random number
  - e.g. so when testing i entered the random mobile number and twitter says that verification code sent to the mobile number , and asking for the verification code >> i cant provide the code coz i entered the random number .
- **1×** hello i have recently found several critical vulnerabilities in odnoklassniki android application which is one of your projects thus i am reporting it here
  - e.g. Hello, I have recently found several critical vulnerabilities in Odnoklassniki Android application, which is one of your projects, thus I am reporting it here.
- **1×** you have been tricked u putextra conversation id u putextra mediatopic id u putextra dsc id user photo getactivity sendbroadcast u another vulnerability that i have found is unauthorized intent receipt in this certain case it is unauthorized notification message receipt
  - e.g. You have been tricked."); //u.putExtra("conversation_id", ""); //u.putExtra("mediatopic_id", "413434225584"); u.putExtra("dsc_id", "612470493988:USER_PHOTO"); getActivity().sendBroadcast(u); Another vulnerability that I have found is Unauthorized intent receipt, in this certain case it is unauthoriz
- **1×** when logging in to an account on the website a user s account gets locked out after tries to prevent an attacker from brute forcing access to the account
  - e.g. When logging in to an account on the website, a user's account gets locked out after ~15 tries to prevent an attacker from brute forcing access to the account.
- **1×** these same restrictions do not apply to the mobile sign in endpoint a post request to which allows an attacker to brute force login of any user s account i have attempted logging into my account times with no restrictions
  - e.g. These same restrictions do not apply to the mobile sign-in endpoint (a POST request to ` which allows an attacker to brute force login of any user's account (I have attempted logging into my account ~50 times, with no restrictions).
- **1×** as an example i found a list of the most common passwords and added my own password somewhere in the list
  - e.g. As an example, I found a list of the most common 100 passwords and added my own password somewhere in the list.
- **1×** products affected in ios affected is the latest version in android affected in brave latest version steps to reproduce i created a html code which would spoof address bar of brave browser bravespoof html in the attachments
  - e.g. ## Products affected: * In IOS - Affected is the Latest Version 1.2.16 (16.09.30.10) * In Android - Affected in Brave Latest version 1.9.56 ## Steps To Reproduce I created a HTML Code which would spoof address bar of Brave Browser ( bravespoof.html) in the Attachments.
- **1×** as we can understand the code contains a form which i have created just to demonstrate a look a like impact where it asks for username and password of any user
  - e.g. As we can understand, the code contains a form which i have created just to demonstrate a look-a-like impact where it asks for username and password of any user.
- **1×** additionally to complete the exploit i used setinterval function to execute the function f continuously after every milliseconds
  - e.g. Additionally, to complete the exploit i used `setInterval` function to execute the function f continuously after every 10 milliseconds.
- **1×** i tested the same on many browsers and brave turned out to be affected
  - e.g. I tested the same on many browsers and Brave turned out to be affected.
- **1×** hey summary i ve found an address bar spoofing vulnerability in the latest version of brave for ios
  - e.g. Hey ## Summary: I've found an address bar spoofing vulnerability in the latest version of Brave for iOS.
- **1×** today i discovered that search engines can access the private users messages otp pins group invites information etc it happens because the host allows search indexing and can leak the auth token to the search engines which also can lead to privilege escalation
  - e.g. Today i discovered, that Search Engines can access the private users messages (OTP pins, Group invites information etc.) It happens because the ` host allows search indexing, and can leak the auth_token to the Search Engines which also can lead to privilege escalation.
- **1×** when vieving notifications section on the app i noticed the unsecure get request to the i was surprised when tried to repeat it in the browser it gave me access to my messages
  - e.g. When vieving "Notifications" section on the app, i noticed the unsecure GET request to the ` I was surprised, when tried to repeat it in the browser - it gave me access to my messages.
- **1×** hello i want to report the vulnerability found since the following activity com application zomatomerchant home homesalt has exported true it can be exploited by another application
  - e.g. Hello, i want to report the vulnerability found, Since the following activity `com.application.zomatomerchant.home.HomeSalt` has `exported="true"` it can be exploited by another application.
- **1×** malicious apps can thus crash the nextcloud client by sending following data in intent nc login
  - e.g. malicious apps can thus crash the nextcloud client by sending following data in intent : `nc://login`.
- **1×** recently i ve noticed a strange issue with chrome and edge browsers on mobile
  - e.g. Recently, I've noticed a strange issue with Chrome and Edge browsers on mobile.
- **1×** reference bugs fixed in past by hackerone multiple issues with markdown and url parsing fake url additional vectors for homograph attack homograph fix bypass
  - e.g. ## Reference bugs fixed in past by HackerOne #113070 - Multiple issues with Markdown and URL parsing #59469 - Fake URL + Additional vectors for homograph attack #271324 - Homograph fix Bypass

## Case studies (full excerpts)

### 1189162 — End to end encryption public key is not properly verified on Desktop and Android
Nextcloud · $1500 · medium · https://hackerone.com/reports/1189162

Since last time when I reported something on multiple platforms you seems to prefer handling it in 1 spot. I now just do one. Let me know if You want me to fill separate for android as well. This issue does not seem to happen on iOS as there a test string is encrypted and decrypted, in short binding the keypair. So the attack vector results in weird behavior but that seems to be due to random bugs in the end to end encryption implementations (because I also ran into those when just messing around with the end to end encryption). In any case there should be a big error if this happens. 1. userA has an account on serverA 2. End2End encryption is enabled on serverA 3. userA setups device1 and enabled end to end encryption. Stores the nonce. Uploads some data. All is good. 4. Now an attacker obtains access to the server, for sake of argument assume there is an evil Admin. 5. They replace the public key of userA with their own 6. userA now setups device2 7, userA enters the nonce 8. userA uploads more data 9. the evil admin now has access to the uploaded data ## Impact In short it breaks the whole premise of your end to end encryption. An evil admin is able to make the device encrypt to their key. It is even in the RFC: "Client checks if private key belongs to previously downloaded public certificate." Recommendations: 1. the clients should verify that the private key matches with t

### 519059 — Protected Tweets setting overridden by Android app
X / xAI · $560 · low · https://hackerone.com/reports/519059

**Summary:** Protected Tweets setting overridden by Android app **Description:** The Android app overrides the "Protect your Tweets" setting set from outside the app in some cases when changing other settings. ## Steps To Reproduce: 1. Log in to an account with unprotected tweets on the Android app. 1. Log in to the same account on mobile.twitter.com and turn on protected tweets. 1. Confirm that the account's tweets are protected. 1. In the Android app, go to the Direct Messages tab, click the gear icon and change a setting such as "Receive message requests" or "Show read receipts." 1. The account's tweets are now unprotected. If this does not work, you may have to first explicitly unset the protected tweets setting in the Android app before setting it elsewhere. ## Impact: This can cause a user's tweets to unknowingly become public. It is possible this could be exploited by an attacker asking the user to change their settings but that is less likely to succeed than with the previous bug where only changing the email address was required. ## Impact See above.

### 1189168 — Android app does not clear end to end encryption keys
Nextcloud · $100 · low · https://hackerone.com/reports/1189168

1. userA on serverA sets up end to end encryption on their android device 2. userA has some end to end encrypted data 3. userA removes their account on serverA from their android device (for whatever reason) 4. attacker (evil admin) obtains the device of userA 5. attacker (evil admin) logs in on the account of userA (reset the pw and just log in) 6. attacker (evil admin) can see and access all encrypted files ## Impact While I believe the impact is minimal since you need to obtain the device of the victim. Once you remove your account all information regarding that account should be removed. * the keys * the mnemonic And certainly when you re-add an account you should be asked to enter your mnemonic!

### 57764 — ByPassing the email Validation Email on Sign up process in mobile apps
Coinbase · $100 · severity n/a · https://hackerone.com/reports/57764

Hi, According to the design When the new user sign up using mobile apps(android,ios).It will ask for the confirmation of the email.It will send a confirmation mail to mail id and a screen will also appear in the mobile app. The user needs to open the email in the device then the screen will Off and user will successfully login. Bypass: Here simply we can bypass this validation and can successfully login to the application without verifying the validation email which comes to the user.Using this the attacker can create so many spoofed accounts. 1.Sign for new user using email id and password 2.Next screen will appear saying please click on the validation which sent to proceed further 3.Here in the second screen click the back button now you will go to Login screen 4.Now login with the creds which you have given in the registration process 5.Now you will successfully login to the application 6.Here it is not asking for email verification email. Pls follow above procedure to reproduce the issue. Pls respond to remaining bugs which I had reported Thanks, kaleem

### 1454002 — Theft of protected files on Android
ownCloud · $50 · low · https://hackerone.com/reports/1454002

There is an issue that allows to retrieve any files from protected directory of application - . The issue is caused by exported activity with intent filter that accepts URI of files for upload. Any 3rd-party application could start this activity and upload on server any files such as database file from protected directory in context of owncloud application. Tested on latest stable version of app - 2.19. Version of android - 11. Java PoC: **Mitigation:** There is valid protection for preventing reading files from directory in similar intent-filter . Copy this protection for . ## Impact Potential attacker could steal files from protected directory of application for example files of databases, cache and history of files.

### 2553026 — Domain highlighting on External link warning is not working on Chrome & Microsoft Edge browsers on Mobile
HackerOne · no bounty (valid finding) · low · https://hackerone.com/reports/2553026

There have been multiple issues with External Link Warning in the past. Sometimes it's Homograph, sometimes more than 2 slashes in link, sometimes domain highlighting and/or weird markdown. And these all have been fixed. Recently, I've noticed a strange issue with Chrome and Edge browsers on mobile. The highlighting of domains doesn't work at all on External Link Warning interstitial page. None of the links are highlighted. Similar issues were fixed in the past by HackerOne (you can see the bug references below). It seems like these problems have appeared again in the code. ### Steps To Reproduce 1. Log into your account on your mobile from either Latest version of Microsoft Edge browser or Google Chrome. 1. Click on links mentioned below in **Impact** section. 1. Observe that none External link warning interstitial page highlights domain. ## Test cases: Google Chrome, Microsoft Edge & Firefox👇 - Below are the images from Chrome browser along with Chrome's details: {F3363744} {F3363747} {F3363766} - Below are the images from Microsoft Edge browser along with Edge's details: {F3362316} {F3362317} {F3363753} - Below are the images from Firefox Browser along with Firefox's details: {F3362321} {F3362323} {F3363752} ## Impact - Browsers automatically convert decimal to IP address. Upon clicking the link from mobile on Edge or Chrome browser, nothing is highlighted in External link w

### 328486 — [Zomato Android/iOS] Theft of user session
Eternal · no bounty (valid finding) · severity n/a · https://hackerone.com/reports/328486

Hi, I'd like to report a bug which allows to theft user data even without installing third-party apps. Activity is exported, and can be accessed by browser. When any WebView (in a client app, or a browser) meets a URL it will automatically launch Zomato app. File File PoC video is very simple: {F277437} Code on local server: All tokens were sent to Google page: {F277440} Third-party apps can also attack your app, PoC from ADB: Hopefully in this case the latest app, but not 2 year old build :) ## Impact 1) Leakage of user tokens to arbitrary sites 2) XSS/Ability of open arbitrary sites in your internal WebView

## Field playbook (unedited)

### quick

- Decompile and inspect exported components and URL schemes.
- Test deep links for auth bypass, open redirect, and token leakage.
- Check local storage, logs, backups, and clipboard for secrets.
- Intercept traffic and test certificate pinning bypass.
- Look for insecure WebViews and JS bridges.

### payloads

- Deep link -> `app://open?url=https://evil.com` `app://webview?url=javascript:...`
- WebView -> `addJavascriptInterface` abuse
- Backup -> extract shared_prefs / Keychain

### bypass

- Bypass pinning with Frida/Objection.
- Use dynamic instrumentation for root/jailbreak checks.

### surface

- deeplink
- intent
- webview
- keystore
- shared_prefs
- keychain

### tools

- apktool
- jadx
- Frida
- objection
- MobSF

### chain

- Deeplink -> token theft.
- WebView bridge -> RCE.

## Corpus search commands

```sh
python3 ~/.local/share/hackerone-reports/h1.py stats --class mobile
python3 ~/.local/share/hackerone-reports/h1.py search "<feature or param>" --class mobile --limit 10
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```
