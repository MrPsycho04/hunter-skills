---
name: bbhunt-clickjacking
description: "Use when a sensitive action page can be framed without X-Frame-Options or frame-ancestors and can be overlaid by attacker UI. Unified from 3 upstream skills (cbh, h1skills, hunting). Plus evidence from all 15,259 disclosed HackerOne reports. For authorized security testing only."
agent_created: true
---

# Clickjacking / UI Redress — unified methodology

> **Methodology skill.** Merged from 3 upstream skills across cbh, h1skills, hunting and grounded in 15,259 disclosed HackerOne reports. Payloads, wordlists and supporting data are in `references/`.

## Corpus signal — 153 valid reports (11 paid / 7%)

Every disclosed report is valid; payment is an impact signal, not a validity test. Full technique frequencies, case studies and approach patterns: `references/evidence.md`.

### Techniques ranked across ALL valid reports

| Technique | Reports |
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

## Corpus-backed method (this class)

1. Identify sensitive state-changing pages and verify framing is actually allowed in a current browser.
2. Check for frame busting and whether it can be neutralized (sandbox attribute, onbeforeunload tricks) — modern CSP is the real control.
3. Build a proof-of-concept overlay that performs a meaningful action with the victim logged in.
4. Evaluate impact by action sensitivity; a like/follow is not the same as a transfer or permission grant.

### Signals

- Sensitive action reachable in an iframe
- No frame-ancestors CSP / X-Frame-Options
- Drag-and-drop or multi-click flows

### Kill criteria

- Frame-ancestors CSP or XFO actually blocks framing.
- Sensitive action requires a second confirmation the overlay cannot perform.
- No security-relevant action available in the frame.

### Escalation chains

- Clickjacking -> permission grant or payment action -> real harm.

### Veteran tip

Corpus counts are moderate but payment is rare — only report when the framed action has real consequences.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method
### Quick wins

Start here. These are the highest-yield tests for this class.

- Check X-Frame-Options and CSP frame-ancestors on sensitive pages.
- Test settings, delete, payment, OAuth consent, and admin actions.
- Look for bypassable frame-busting.
- Build a minimal overlay and confirm the action executes.

### Deeper checklist

- Check `X-Frame-Options` and CSP `frame-ancestors` on sensitive pages.
- Test frames of settings, delete, payment, OAuth consent, and admin actions.
- Look for frame-busting that is bypassable or only client-side.
- Build a minimal overlay PoC and confirm the action executes when framed.
- Assess impact: which state change can a victim be tricked into?

### Web-Research Methodology Additions (2026)

Research basis: the OWASP Clickjacking Defense Cheat Sheet and PortSwigger Web Security Academy "Clickjacking (UI redressing)." Both agree on the core discipline this skill already enforces: **header absence is a trigger to investigate, never the finding.** OWASP now also documents DoubleClickjacking as a distinct, framing-independent variant.

### A. Discovery checklist — concrete places, params, headers, flows to look

- **Per-page headers, not site-wide assumptions:** `X-Frame-Options` (`DENY`/`SAMEORIGIN`/obsolete `ALLOW-FROM`) and CSP `frame-ancestors`. Note OWASP: `frame-ancestors` takes priority over XFO when enforced; older browsers followed XFO instead. Multiple XFO headers / multiple values are not honored — check for conflicting duplicates.
- **Meta tags are useless:** `<meta http-equiv="X-Frame-Options" ...>` does NOT work, and neither does a meta `frame-ancestors`. Only real HTTP response headers count — a common false "protection."
- **Proxy/CDN stripping:** an intermediary can remove the header; verify the header in the *browser's* response, not just at origin.
- **Cookie posture:** `SameSite=Strict|Lax` withholds cookies from cross-site iframe requests. But SameSite does **not** block same-site framing — a sibling subdomain is same-site yet cross-origin. Use CSP `frame-ancestors` to check that gap.
- **Frame-buster scripts:** look for `if(top!==self)`, `top.location=self.location`, `parent.location` assignment, `onbeforeunload`. PortSwigger and OWASP both catalog these as bypassable.
- **Prefilled form inputs:** applications that populate form fields from GET parameters make "clickjacking with prefilled input" possible — check URLs with `?email=`, `?amount=`, etc.
- **Multistep flows** (add-to-cart then checkout; change-email then confirm) and **clickjacking as a DOM-XSS carrier** — the iframe src contains the XSS URL.
- **DoubleClickjacking surface:** top-level consent screens, payment confirmations, "disable 2FA"/account-security dialogs — these win because framing defenses are irrelevant to a separate-window double-click.
- **High-value actions:** OAuth authorize/consent, money transfer, email/password change, 2FA disable, admin delete/promote.

- **Header matrix per role/page:** authenticated vs anonymous, HTTP vs HTTPS, main app vs admin vs OAuth consent — headers are often set inconsistently.
- **CSP detail:** `frame-ancestors 'self'` vs a domain list; a wildcard subdomain entry may let a taken-over sibling frame the page. The CSP wildcard matches subdomains only, not the bare host.
- **XFO detail:** flag `ALLOW-FROM` (obsolete, fails open), duplicate XFO headers, and a proxy that strips the header.
- **SameSite nuance:** Lax/Strict withhold cookies cross-site, but a same-site sibling subdomain can still frame — check both conditions independently.
- **Frame-buster catalog:** `if(top!==self)`, `top.location`, `parent.location`, `onbeforeunload`, `document.designMode` — each has a known bypass.
- **Interaction depth:** single-click vs multistep (cart→checkout, change-email→confirm) and whether a text field must be prefilled from the URL.
- **Clickbandit baseline:** generate one overlay with Burp Clickbandit to confirm the page is frameable and clickable before hand-tuning geometry.
- **Sensitive action list:** consent, transfer, email/password change, 2FA disable, admin delete — rank by impact; read-only pages are informational.### Signals and surfaces
### Signal

- Reports: **166** · paid: **12**
- Median bounty **$500** · p90 **$3,000** · max **$3,500** · total **$10,640**
- Median upvotes **5**

### Where it pays

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

### Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`settings` `delete` `payment` `oauth` `admin` `transfer`### Techniques and bypasses
### Payloads & probes

- `<iframe src=https://target/settings style="opacity:0.1">` + overlay button
- `frame-ancestors 'self'` missing -> any origin
- Double framing to bypass `X-Frame-Options: SAMEORIGIN`

### Bypass tricks

- Bypass JS frame-busting with sandbox or double framing.
- Use drag-and-drop / cursorjacking where needed.

### Techniques from real reports

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

### Payload fragments observed

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

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- **Basic overlay geometry:** `position:relative` iframe with `opacity:0.00001`, `z-index:2`, precise width/height over a `position:absolute` decoy. Chrome applies threshold-based transparency detection (since v76), so tune opacity below the threshold; Firefox does not. For rapid PoCs use Burp **Clickbandit** — perform the clicks in your browser and it generates the overlay HTML.
- **Neutralise frame busters with `sandbox`:** `<iframe src="https://victim/..." sandbox="allow-forms"></iframe>` (or `allow-scripts`). Omitting `allow-top-navigation` stops the frame-buster from checking/breaking out of the top window while keeping the target functional.
- **Double framing:** nest the victim inside two iframes; `parent.location` becomes a descendant-navigation security violation, disabling the buster.
- **`onbeforeunload` prompt:** the attacker page registers a handler returning "Do you want to exit…?" so the user cancels the buster's redirect. The no-content-flushing variant repeatedly navigates to a 204 endpoint to cancel the redirect without any prompt.
- **Restricted zones:** a `<iframe sandbox>` (Chrome) or `document.designMode='on'` (Firefox) disables JS in the subframe, so JS frame busters never run.
- **`window.confirm()` is weak:** browsers suppress simple dialogs in sandboxed frames without `allow-modals` (returns `false`). Server-side transaction authorization is the real fix.
- **Prefilled-input variant:** put attacker values in the target URL's GET params and overlay only the submit button.
- **DOM-XSS carrier:** combine a known DOM-XSS URL in the iframe `src` so the tricked click executes script — clickjacking becomes the delivery mechanism.
- **DoubleClickjacking PoC:** use a top-level window (not an iframe) and a double-click sequence that swaps the clicked element to the sensitive control between the two clicks — framing headers cannot stop it.### Validation and proof
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

### C. Validation / proof bar — how to confirm and avoid false positives

- **Mandatory browser proof:** (1) the target page actually renders inside the attacker-controlled iframe, (2) a sensitive state-changing action succeeds from a framed click while the victim is authenticated — i.e. cookies survive the cross-site context, (3) screenshot/recording of the overlay. Header absence alone is documentation-quality, not a vulnerability.
- **SameSite check:** confirm the session cookie is actually attached to the cross-site framed request in DevTools. `SameSite=Lax/Strict` can defeat an otherwise valid overlay.
- **Frame-buster check:** confirm the page did not blank/redirect itself; if it did, try the `sandbox`, double-frame, or designMode bypasses above before concluding.
- **Opacity threshold:** Chrome v76+ may warn/block at certain transparency values — validate the PoC in the victim's likely browser, using ~0.0001 for submission.
- **DoubleClickjacking is a separate test:** it needs its own window-based PoC; an iframe PoC does not cover it, and vice versa. OWASP recommends server-side transaction authorization for high-risk actions.
- **Avoid false positives:** public read-only pages, JSON/API endpoints, and images are not targets. CSRF tokens do not mitigate clickjacking (requests are on-domain with the real session), so their presence is not a defense.

- **Two-decoy control:** run the identical overlay over a non-sensitive page; if no state changes, the effect is target-specific rather than a generic rendering artifact.
- **Cookie-context proof:** show in DevTools that the framed request carries the authenticated session cookie; if not, the clickjack fails regardless of framing.
- **Browser matrix:** test Chrome and Firefox — transparency thresholds and sandbox behavior differ.
- **Frame-buster bypass proof:** if the page escapes the frame, document which sandbox/frame technique neutralized it; otherwise no finding.
- **CSRF-token note:** a CSRF token is not a mitigation here — don't treat its presence as protection.
- **DoubleClickjacking separation:** a header-protected page can still be vulnerable to the two-window variant; test it separately with a top-level-window PoC.
- **Screenshot discipline:** capture the decoy page, the transparent iframe in DevTools, and the resulting state change (e.g. email changed) in the victim account.
- **Ownership proof:** perform the click against a second controlled account so the report shows real cross-user impact.
- **No-header-but-no-action:** if the frameable page exposes no state-changing action, downgrade to informational and say so.
- **Interaction check:** confirm the overlay works with mouse, keyboard, and (if relevant) touch — OWASP warns against mouse-only assumptions.### Escalation and related chains
### Escalation chains

- Clickjacking -> CSRF-like action.
- Clickjacking -> OAuth consent.### Tools
### Tools

`Burp` · `clickjacking PoC generator` · `browser`

### Wordlists

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

### Nuclei

Scanner hits are only a signal; build a framed PoC on a sensitive action and confirm it executes.

```sh
nuclei -u https://target -tags clickjacking,headers \
       -severity low,medium,high,critical -rl 40 -o nuclei_clickjacking.txt
nuclei -u https://target -t ~/nuclei-templates/http/misconfiguration \
       -rl 40 -o nuclei_clickjacking_misconfiguration.txt
# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'
```

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.### Sources and related reading
### Query the corpus

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

### Related

- `hackerone-csrf` (541 reports)
- `hackerone-xss` (2,569 reports)

### Related

- `csrf` (541 reports)
- `xss` (2,569 reports)

### D. Sources — numbered list of URLs you actually fetched

1. https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html
2. https://portswigger.net/web-security/clickjacking### Additional notes
### Parameters observed

`oauth_token` · `id` · `subcat` · `previous_url` · `hl` · `sl` · `tl` · `Bi06UejC9N` · `continue` · `client_id` · `response_type` · `redirect_uri` · `cardname` · `autoplay_disabled` · `earned` · `lang` · `card_height` · `message` · `userid` · `depth`

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

### What is Clickjacking

Clickjacking (UI Redressing) lets an attacker load a target page inside a transparent iframe on a malicious site. The victim sees the attacker's decoy UI but clicks the hidden target UI beneath it. No JavaScript on the target is required.

**Highest-value targets:**
- Login / authentication pages — force login with attacker credentials
- Money transfer / checkout / "confirm payment" buttons
- Account settings (email change, password change, 2FA disable)
- OAuth / social-login "Authorize app" confirmation dialogs
- Admin actions (delete, promote user, change role)

### Protection Headers

Two mechanisms prevent framing:

```
X-Frame-Options: DENY              # strongest — blocks all framing
X-Frame-Options: SAMEORIGIN        # allows same-origin frames only
Content-Security-Policy: frame-ancestors 'none'     # CSP equivalent of DENY
Content-Security-Policy: frame-ancestors 'self'     # CSP equivalent of SAMEORIGIN
```

If NEITHER is present, the page is frameable from any origin.

### How to Test

Header-absence is the **trigger for investigation, not the finding**. Two steps:

**Step 1 — Header check (screening).** Fetch the target page and inspect the response headers:

```
curl -sI https://target.example/account/transfer | grep -iE 'x-frame-options|content-security-policy'
```
If BOTH `X-Frame-Options` and CSP `frame-ancestors` are absent, the page is a *candidate*. If either is present and restrictive (`DENY`/`SAMEORIGIN`/`frame-ancestors 'none'|'self'`), stop — it's protected.

**Step 2 — Prove it actually frames and clicks (required for a real finding).** Build a minimal PoC and load it in a real browser:

```html
<!doctype html>
<h1>Win a prize — click below</h1>
<iframe src="https://target.example/account/transfer"
        style="opacity:0.1;position:absolute;top:0;left:0;width:1000px;height:800px"></iframe>
```
Confirm ALL of the following, or it is not exploitable:
- The page **actually renders inside the iframe** (no framebusting JS that blanks/redirects it — e.g. `if(top!==self)` breakout, or a `Sec-Fetch-Dest`/JS frame check).
- The **sensitive action still works while framed** — critically, the action must succeed *cross-site*. If it relies on a session cookie set `SameSite=Lax` or `SameSite=Strict` (the modern default), the cookie is **not** sent on the cross-site framed request, and the clickjack fails. Verify the victim's authenticated state carries into the frame.
- The target is a **state-changing action** (transfer, settings/email/password change, 2FA disable, OAuth authorize, admin action), not a read-only page.

**Strategy:** target the most sensitive action pages first — severity scales directly with what the victim is tricked into doing.

### False Positives

- Public, read-only pages (home/marketing) lacking frame protection are low/informational — no sensitive action to redress.
- APIs and non-HTML endpoints (JSON, images) are not clickjacking targets.
- **Header-absence alone is NOT a finding.** SameSite cookies, framebusting JS, or the lack of any sensitive framed action can each fully defeat it — which is why Step 2 is mandatory.

### Proof Requirements

A valid clickjacking report shows: (1) the target page rendered inside an attacker-controlled iframe in a real browser, (2) a sensitive state-changing action reachable by a framed click while the victim is authenticated (cookies survive the cross-site context), and (3) a screenshot/recording of the overlay. Reporting missing headers with no working frame PoC is a documentation-quality issue, not a vulnerability.### Companion methodology (deduplicated)
### hunting / references/techniques.md

# Clickjacking — Combined Field Guide — Technique reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete technique.

---

## Quick wins



Start here. These are the highest-yield tests for this class.



- Check X-Frame-Options and CSP frame-ancestors on sensitive pages.

- Test settings, delete, payment, OAuth consent, and admin actions.

- Look for bypassable frame-busting.

- Build a minimal overlay and confirm the action executes.



## Bypass tricks



- Bypass JS frame-busting with sandbox or double framing.

- Use drag-and-drop / cursorjacking where needed.



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

```## Probes

- Framed page in a test HTML with transparent overlay; verify action executes with victim session.

## Supporting data

- `references/evidence.md` — corpus technique frequencies, case studies, approach patterns
- `references/payloads.md` — curated payload bank + upstream payload references
- `references/wordlists/` — 2 mined paths/params/payload lists
- `bbhunt-methodology` — orchestrator, state machine and class router
