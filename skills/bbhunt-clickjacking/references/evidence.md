# Evidence appendix — Clickjacking / UI Redress

Mined from all **153 valid disclosed reports** for this class (11 paid, 7% — payment is not validity).

## Technique frequency (all valid writeups)

| Item | Count |
|---|---:|
| HTTP method / verb tampering | 14 |
| DOM / HTML source inspection | 13 |
| XML / SOAP / SAML / XXE | 12 |
| public source-code / repo review | 9 |
| webhook / OAuth / SAML / integration abuse | 6 |
| two-account / cross-account replay | 6 |
| admin / privileged-role context | 5 |
| file upload / filename / extension | 5 |
| encoding / double-encode / null byte | 4 |
| subdomain / DNS / cert-transparency recon | 3 |
| cache / CDN / unkeyed header | 2 |
| JWT / token / base64 decode | 2 |
| WAF / sanitizer / filter bypass | 2 |
|  HosT/absolute-URL reset poisoning | 2 |
| error message / stack trace probing | 2 |
| OAST / DNS / HTTP callback proof | 2 |
| redirect chain / Location header | 2 |
| internal service / port / container | 2 |
| Content-Type / body-format switch | 1 |
| API docs / Swagger / introspection | 1 |
| header injection (Host / X-Forwarded / etc.) | 1 |
| cloud metadata / IAM abuse | 1 |
| parser confusion / normalization | 1 |
| search-engine dorking | 1 |
| template injection (SSTI) | 1 |
| unauthenticated / removed-cookie test | 1 |
| third-party data / paste / breach reuse | 1 |
| git history / exposed .git | 1 |

## Tools mentioned

| Item | Count |
|---|---:|
| browser | 10 |
| source-code-review | 9 |
| devtools | 7 |
| javascript-debugging | 2 |
| curl | 1 |
| git | 1 |

## Bypass primitives

| Item | Count |
|---|---:|
| unicode | 4 |
| bypasses | 3 |
| content-type | 2 |
| bypass | 2 |
| bypassed | 1 |
| blacklist | 1 |

## Impact language

| Item | Count |
|---|---:|
| password | 59 |
| token | 17 |
| admin | 15 |
| credential | 12 |
| account takeover | 7 |
| payment | 4 |
| sensitive information | 3 |
| unauthorized | 3 |
| sensitive data | 1 |

## Parameters observed

| Item | Count |
|---|---:|
| src | 49 |
| width | 33 |
| height | 32 |
| style | 14 |
| lang | 10 |
| charset | 10 |
| window.onbeforeunload | 5 |
| sandbox | 5 |
| frameborder | 5 |
| scrolling | 4 |
| href | 3 |
| rel | 2 |
| target | 2 |
| window.top.location | 2 |
| opacity | 1 |
| internal | 1 |
| exp | 1 |
| act | 1 |
| cols | 1 |
| email.value | 1 |
| summary | 1 |
| reproduce | 1 |
| impact | 1 |
| solution | 1 |
| references | 1 |
| language | 1 |
| type | 1 |
| canvas | 1 |
| prevent_bust | 1 |
| http-equiv | 1 |

## Recurring approach patterns

- **10×** clickjacking user interface redress attack ui redress attack ui redressing is a malicious technique of tricking a web user into clicking on something different from what the user perceives they are clicking on thus potentially revealing confidential information or taking control of their computer while clicking on seemingly innocuous web pages
  - e.g. Clickjacking (User Interface redress attack, UI redress attack, UI redressing) is a malicious technique of tricking a Web user into clicking on something different from what the user perceives they are clicking on, thus potentially revealing confidential information or taking control of their comput
- **1×** hi i found your site is vulnerable to clickjacking
  - e.g. hi, i found your site is vulnerable to clickjacking.
- **1×** i have set up a user agent switcher and tried to support my claim with regards to the mobile website
  - e.g. I have set up a user agent switcher and tried to support my claim with regards to the mobile website.
- **1×** after clicking the victim will automatically post a tweet with content pwn3d
  - e.g. After clicking the victim will automatically post a tweet with content "Pwn3d!".
- **1×** this isn t quite as bad as the previous vulnerability i found since it requires an additional step favoriting a tweet to exploit
  - e.g. This isn't quite as bad as the previous vulnerability I found, since it requires an additional step (favoriting a tweet) to exploit.
- **1×** i found that there is a form for submitting user information for applying for beta program
  - e.g. I found that There is a Form for Submitting User Information for applying for Beta Program.
- **1×** information like name email company following is html code i used to test it
  - e.g. #Information Like: Name: Email: Company Following is HTML code i used to test it!
- **1×** i have found clickjacking vulnerability in your website you should set the frames to fix the issue
  - e.g. i have found clickjacking vulnerability in your website you should set the frames to fix the issue
- **1×** i tested this on the latest version of the android app
  - e.g. I tested this on the latest version of the Android App.
- **1×** hello problem i found that is vulnerable to click jacking because of missing x frame options on this page which allows an attacker to send the victim the poc sent with the report to the user to remove his profile picture poc solution adding x frame options header with value deny or and asking for user password when deleting photos thanks mohamed
  - e.g. Hello, # Problem I found that is vulnerable to click-jacking because of missing X-Frame-Options on this page which allows an attacker to send the victim the POC ( sent with the report ) to the user to remove his profile picture # POC # Solution Adding X-FRAME-OPTIONS header with value DENY or ( and 
- **1×** i discovered this because i noticed that internal links are treated differently than external links
  - e.g. I discovered this, because I noticed that internal links are treated differently than external links.
- **1×** i found clickjacking vulnerability while updating business page one of the endpoints which is vulnerable to clickjacking is
  - e.g. I found clickjacking vulnerability while updating business page.One of the endpoints which is vulnerable to clickjacking is .
- **1×** in this report you people said the clickjacking issue is fixed but i have found another issue of clickjacking
  - e.g. In this report you people said the clickjacking issue is fixed but i have found another issue of clickjacking.
- **1×** share the file i also added a password but it shouldn t matter
  - e.g. Share the file (I also added a password, but it shouldn't matter) 4.
- **1×** i found some others endpoints as well which can be clickjacked easily
  - e.g. I found some others endpoints as well which can be Clickjacked easily.
- **1×** recently i have tested you all sub domain and got a domain which is vulnerable named as clickjacking
  - e.g. Recently I have tested you all sub-domain and got a domain which is vulnerable named as clickjacking.
- **1×** i found clickjacking url on this clickjacking must be characturs and must be number this entered endpoint of url
  - e.g. i found clickjacking URL on this clickjacking must be 3 characturs and must be 5 number this entered endpoint of URL ..
- **1×** when i use the iframe tag object tag and embed tag it show me the message that these tags are not allowed for security reasons may be cause of clickjacking attack or something but when i used frameset n frame tag it does not showed any message and allows them
  - e.g. When i use the iframe tag , object tag and embed tag it show me the message that these tags are not allowed for security reasons(may be cause of clickjacking attack or something) but when i used frameset n frame tag it does not showed any message and allows them.
- **1×** supporting material references impact revealing confidential information credentials and or taking control of their computer account while clicking on seemingly innocuous web pages
  - e.g. **Supporting Material/References:** ## Impact Revealing confidential information(credentials) AND/OR taking control of their computer/account while clicking on seemingly innocuous web pages.
- **1×** at yelp com i have found the following functions to be vulnerable report a profile with custom message in it using url follow a user using url send a compliment with custom message in it using url poc please watch the minute poc video to see how these url are embedded into hidden iframes and how the victim is exploited
  - e.g. At yelp.com I have found the following functions to be vulnerable: ##1.) Report A profile (With custom Message in it) **Using URL:** ##2.) Follow a user **Using URL:** ##3.) Send A Compliment (With Custom message in it)** **Using URL:** ##POC: *PLEASE WATCH THE 1 minute POC VIDEO TO SEE HOW THESE UR
- **1×** bonus feature exploit to lock the victim there s an option to logout from everywhere in the edit profile page by clicking on that the attacker can make sure that the victim is not logged into any other accounts after he changed the password
  - e.g. ###Bonus feature/exploit to lock the victim- There's an option to logout from everywhere in the edit-profile page, by clicking on that the attacker can make sure that the victim is not logged into any other accounts after he changed the password.
- **1×** here is an example full link we received from a malicious account that we were investigating named only for you eric jn ellason message id what gets displaying and hotlinked in the direct message is this only for you eric jn ellason accounts youtube com accounts setsi
  - e.g. Here is an example "FULL" link we received from a malicious account that we were investigating named @█████████ ONLY FOR YOU Eric JN Ellason {{ … }} message id: 92439 What gets displaying and hotlinked in the Direct Message is this: ONLY FOR YOU Eric JN Ellason { accounts.youtube.com/accounts/SetSI.
- **1×** here is an older example that we found steps to reproduce add details for how we can reproduce the issue
  - e.g. Here is an older example that we found: ] ## Steps To Reproduce: (Add details for how we can reproduce the issue) 1.
- **1×** we provide a list of domains we believe have been used in this campaign
  - e.g. We provide a list of 7 domains we believe have been used in this campaign.] 4.

## Case studies (full excerpts)

### 662287 — Cross-site Scripting (XSS) - Stored in RDoc wiki pages
GitLab · $3500 · high · https://hackerone.com/reports/662287

### Summary When creating an RDoc wiki page it's possible to use a large number of html tags and attributes that are normally sanitized, when creating a linkable image of the format `{<img src>}[link]` For example it is possible to specify a `class` attribute when creating an image link: will generate the following: This will place a link taking over the entire page and intercept any clicks, `atwho-view select2-drop-mask pika-select` are just some real classes that make the links position absolute with a high z-index. The `target` attribute could also be set to `_blank` and as there is no `rel="noopener"` [reverse tabnabbing]( is also possible. Another attack that is more likely to work would be to create a form in a modal, which could be used to ask for a username and password: Which produces the following dialog when viewing the page: {F541421} ### Steps to reproduce 1. Create a wiki on gitlab 1. Add a new RDoc page with the above snippet 1. Save and wait for someone to click it ### Impact An attacker could trick a user into thinking they had clicked on a gitlab element when they are actually redirected to the attackers site, or be presented with a dialog that will post to an attackers site. ### Examples Example linking to a fake sign in form: Example creating a modal form: ### What is the current *bug* behavior? When using an image link in RDoc the anchor tag attributes are 

### 591432 — Twitter Periscope Clickjacking Vulnerability
X / xAI · $1120 · medium · https://hackerone.com/reports/591432

Bonjour, ## Summary X-Frame-Options ALLOW-FROM not supported by several Browser, this caused Clickjacking on Twitter Periscope subdomain ( & ## Steps To Reproduce: 1. Create a new HTML file 2. Put <iframe src=" frameborder="0"></iframe> 3. Save the file 4. Open document in browser ## Impact Attacker may tricked user, sending them malicious link then user open it clicked some image and their account unconsciously has been deactivated ## Solution The vulnerability can be fixed by adding "frame-ancestors 'self';" to the CSP (Content-Security-Policy) header. ## NOTE - POC & Attacking Scenarios ( PASS:Per!scop3^) ## References Cheers!

### 198622 — Clickjacking Periscope.tv on Chrome
X / xAI · $560 · medium · https://hackerone.com/reports/198622

Hi, The X-FRAME-OPTIONS header returned from is: But Chrome doesn't support this value for the header: Because of that, no value for X-FRAME-OPTIONS is set and all of the periscope.tv pages are vulnerable to Clickjacking. You can see for example my attached poc (Make sure you test it on chrome) that I am framing my own user on periscope. I can use regular Clickjacking tricks to make the user follow other users and do practically any action on the site.

### 97510 — Following a User After Favoriting Actually Follows Another User (related to #95243)
X / xAI · $280 · severity n/a · https://hackerone.com/reports/97510

Hi, There appears to be a bug similar to #95243 which affects following a user after favoriting one of their tweets via an Intent dialog. The following is a proof of concept: The screen_name param submits with the favorite form and ends up getting injected into the follow param on the resulting page. This isn't quite as bad as the previous vulnerability I found, since it requires an additional step (favoriting a tweet) to exploit. However, the impact is exactly the same as the last vulnerability, in that the user has no idea that they're actually following a completely different user. Please let me know if you have any other questions.

### 2119892 — clickjacing can lead to account takeover
pixiv · $200 · low · https://hackerone.com/reports/2119892

hello team . while testing the site we found an endpoint call {F2626044} using it we can trick the user to fake login with the use of clickjackingpoc : as poc shown : {F2626057} ## Impact Users are tricked into performing all sorts of unintended actions are such as typing in the password, clicking on ‘Delete my account’ button, liking a post, deleting a post, commenting on a blog. In other words all the actions that a normal user can do on a legitimate website can be done using clickjacking.

### 85624 — Highly wormable clickjacking in player card
X / xAI · no bounty (valid finding) · severity n/a · https://hackerone.com/reports/85624

Hi, I would like to report an issue where player card is vulnerable to clickjacking in certain browsers. This may result in something similar to XSS worm and many other critical damages. ##Details Twitter Player Card allows a website to embed a custom player(html) into an iframe in a tweet. There are currently 2-3 security features in place to defend clickjacking on Twitter: 1. covering the whole twitter.com domain 2. ditto 3. JS-based frame-buster in some pages (but not all) For (1), SAMEORIGIN only checks if the embedded frame is on the same origin of the top window. For example, attacker can do something like twitter.com -> attacker.com -> twitter.com to evade it. More details can been seen from here: For (2), this is the only way to correctly prevent framing from other websites (it performs the check against the ancestor list). However this is a CSP2 directive so not all browsers support it. For example, Safari and IE do not support it. For (3), using the sandbox attribute of iframe can disable JS of a frame, hence anti-frame-buster Since Player Card is shown on a Tweet (on twitter.com), attacker can embed an iframe which embeds a Twitter page so that attacker can overlay it with "bait" content to lure victims to click on it. The impact is huge because of the following facts: * The card displays directly on the user's timeline, making the attack less suspicious to normal cl

### 921709 — Clickjacking on donation page
WordPress · no bounty (valid finding) · low · https://hackerone.com/reports/921709

## Description: Vulnerable URL: Clickjacking on the vulnerable URL allows an attacker to redirect a victim to do a donation at an attacker's page. ## Steps To Reproduce: 1) To test whether the page is vulnerable to clickjacking or not use this code <!DOCTYPE HTML> <html lang="en-US"> <head> <meta charset="UTF-8"> <meta http-equiv="refresh" content="5"> <title>i Frame</title> </head> <body> <center><h1>THIS PAGE IS VULNERABLE TO CLICKJACKING</h1> <iframe src=" frameborder="0 px" height="1200px" width="1920px"></iframe> </center> </body> </html> 2) To test whether an attacker is able to trick the victim to donate money to the attacker's payment gateway i) Open the attached page "donation.html " ii) Click on the button give once iii) The page will be redirected to the attacker's PayPal money request page. *Sorry for the bad UI and please remove my payment-request id after the vulnerability check from donation.html page. ## Recommendations To control where your site can be embedded, use the frame-ancestors directive: Content-Security-Policy: frame-ancestors 'none' (The page cannot be displayed in a frame, regardless of the site attempting to do so.) Content-Security-Policy: frame-ancestors 'self' (The page can only be displayed in a frame on the same origin as the page itself.) Content-Security-Policy: frame-ancestors *uri* (The page can only be displayed in a frame on the specifie

## Field playbook (unedited)

### quick

- Check X-Frame-Options and CSP frame-ancestors on sensitive pages.
- Test settings, delete, payment, OAuth consent, and admin actions.
- Look for bypassable frame-busting.
- Build a minimal overlay and confirm the action executes.

### payloads

- `<iframe src=https://target/settings style="opacity:0.1">` + overlay button
- `frame-ancestors 'self'` missing -> any origin
- Double framing to bypass `X-Frame-Options: SAMEORIGIN`

### bypass

- Bypass JS frame-busting with sandbox or double framing.
- Use drag-and-drop / cursorjacking where needed.

### surface

- settings
- delete
- payment
- oauth
- admin
- transfer

### tools

- Burp
- clickjacking PoC generator
- browser

### chain

- Clickjacking -> CSRF-like action.
- Clickjacking -> OAuth consent.

## Corpus search commands

```sh
python3 ~/.local/share/hackerone-reports/h1.py stats --class clickjacking
python3 ~/.local/share/hackerone-reports/h1.py search "<feature or param>" --class clickjacking --limit 10
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```
