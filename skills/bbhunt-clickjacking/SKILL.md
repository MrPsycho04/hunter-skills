---
name: bbhunt-clickjacking
description: "Use when a sensitive action page can be framed without X-Frame-Options or frame-ancestors and can be overlaid by attacker UI. Unified from 3 upstream skills (cbh, h1skills, hunting). Plus evidence from all 15,259 disclosed HackerOne reports. For authorized security testing only."
agent_created: true
---

# Clickjacking / UI Redress — unified methodology

> **Unified skill.** Built from 3 upstream skills across cbh, h1skills, hunting and the local HackerOne corpus. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

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
- **DoubleClickjacking surface:** top-level consent screens, payment confirmatio

### Signals and surfaces

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

`settings` `delete` `payment` `oauth` `admin` `transfer`

### Techniques, payloads and bypasses

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
- **Viral Dire

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
| 1× | `https://█████/████&url=http%3a%2f%2fgalnagli.com%2f%3

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- **Basic overlay geometry:** `position:relative` iframe with `opacity:0.00001`, `z-index:2`, precise width/height over a `position:absolute` decoy. Chrome applies threshold-based transparency detection (since v76), so tune opacity below the threshold; Firefox does not. For rapid PoCs use Burp **Clickbandit** — perform the clicks in your browser and it generates the overlay HTML.
- **Neutralise frame busters with `sandbox`:** `<iframe src="https://victim/..." sandbox="allow-forms"></iframe>` (or `allow-scripts`). Omitting `allow-top-navigation` stops the frame-buster from checking/breaking out of the top window while keeping the target functional.
- **Double framing:** nest the victim inside two iframes; `parent.location` becomes a descendant-navigation security violation, disabling the buster.
- **`onbeforeunload` prompt:** the attacker page registers a handler returning "Do you want to exit…?" so the user cancels the buster's redirect. The no-content-flushing variant repeatedly navigates to a 204 endpoint to cancel the redirect without any prompt.
- **Restricted zones:** a `<iframe sandbox>` (Chrome) or `document.designMode='on'` (Firefox) disables JS in the subframe, so JS frame busters never run.
- **`window.confirm()` is weak:** browsers suppress simple dialogs in sandboxed frames without `allow-modals` (returns `false`). Server-side transaction authorization is the real fix.
- **Prefilled-input variant:** put attacker values in the target URL's GET params and overlay only the submit button.


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

### C. Validation / proof bar — how to confirm and avoid false positives

- **Mandatory browser proof:** (1) the target page actually renders inside the attacker-controlled iframe, (2) a sensitive state-changing action succeeds from a framed click while the victim is authenticated — i.e. cookies survive the cross-site context, (3) screenshot/recording of the overlay. Header absence alone is documentation-quality, not a vulnerability.
- **SameSite check:** confirm the session cookie is actually attached to the cross-site framed request in DevTools. `SameSite=Lax/Strict` can defeat an otherwise valid overlay.
- **Frame-buster check:** confirm the page did not blank/redirect itself; if it did, try the `sandbox`, double-frame, or designMode bypasses above before concluding.
- **Opacity threshold:** Chrome v76+ may warn/block at certain transparency values — validate the PoC in the victim's likely browser, using ~0.0001 for submission.
- **DoubleClickjacking is a separate test:** it needs its own window-based PoC; an iframe PoC does not cover it, and vice versa. OWASP recommends server-side transaction authorization for high-risk actions.
- **Avoid false positives:** public read-only pages, JSON/API endpoints, and images are not targets. CSRF tokens do not mitigate clickjacking (requests are on-domain with the real session), so their presence is not a defense.

- **Two-decoy control:** run the identical overlay over a non-sensitive page; if no state changes, the effect is target-specific rather than a generic rendering artifact.
- **Cookie-context proof:** show in DevTools that 

### Escalation and related chains

### Escalation chains

- Clickjacking -> CSRF-like action.
- Clickjacking -> OAuth consent.

### Tools and wordlists

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

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

## Source skills merged into this topic

- `h1skills` — `hackerone-clickjacking`
- `hunting` — `clickjacking`
- `cbh` — `hunt-clickjacking`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `references/upstream-assets/` — 2 companion files (payload/technique references, scripts, validators and schemas) from the contributing skills
- `../../upstream/` — complete unmodified archives of all five source repositories
- `references/evidence.md` — corpus technique frequencies, parameters, case studies and payload bank
- `bbhunt-methodology` — orchestrator, state machine and class router
