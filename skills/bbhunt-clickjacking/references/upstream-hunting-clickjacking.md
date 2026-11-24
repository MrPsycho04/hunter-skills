# Upstream source: clickjacking (hunting)

Original path: `/tmp/h1res_MrPsycho04_Hunting-Agent/clickjacking/SKILL.md`

---

---
name: clickjacking
description: >-
  Hunt Clickjacking — missing X-Frame-Options / CSP frame-ancestors lets an attacker embed the target page
  in an invisible iframe and trick victims into clicking buttons they cannot see (UI redressing). Targets:
  login flows, money transfers, account settings, OAuth confirmation pages. Confirm by fetching the page,
  then PROVE it frames in a real browser and a sensitive state-changing action survives the cross-site
  context (SameSite cookies / framebusting JS can defeat it) — header-absence alone is not a finding.
  Combined with the HackerOne field guide (real disclosed-report data: where it pays, quick wins, payload
  banks). Hunt clickjacking and UI redress. Use when testing sensitive actions and checking frame-
  ancestors/X-Frame-Options. Backed by 166 disclosed HackerOne reports.
---

# Clickjacking — Combined Field Guide

**Merged skill.** This fuses two complementary sources into one reference:

- **Part 1 — HackerOne field guide:** statistics from disclosed reports, "where it pays," quick wins, and curated payload banks.
- **Part 2 — Bug hunter methodology:** autonomous testing priority, canary discipline, crown-jewel targeting, OOB/validation gates, and reporting guidance.

**How to use:** Open with Part 2 for execution discipline (set your canary, know your success/failure gate). Use Part 1 to prioritize targets and pull payloads. Before reporting, run the validation gates in both parts.

---

<!-- ============ PART 1: HACKERONE FIELD GUIDE (data + payloads) ============ -->

# Clickjacking / UI Redressing — HackerOne field guide

Built from **166** publicly disclosed HackerOne reports (2014–2026). Corpus: `~/.local/share/hackerone-reports/`.

**Reference files (load on demand):**

- `references/payloads.md` — payload banks, probes, wordlists, Nuclei templates, observed parameters
- `references/techniques.md` — quick wins, bypasses, real-report techniques, deeper checklists

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

## Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`settings` `delete` `payment` `oauth` `admin` `transfer`

## Tools

`Burp` · `clickjacking PoC generator` · `browser`

## Escalation chains

- Clickjacking -> CSRF-like action.
- Clickjacking -> OAuth consent.

## Related

- `csrf` (541 reports)
- `xss` (2,569 reports)

## Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.

---

<!-- ============ PART 2: BUG HUNTER METHODOLOGY (execution + validation) ============ -->

## What is Clickjacking

Clickjacking (UI Redressing) lets an attacker load a target page inside a transparent iframe on a malicious site. The victim sees the attacker's decoy UI but clicks the hidden target UI beneath it. No JavaScript on the target is required.

**Highest-value targets:**
- Login / authentication pages — force login with attacker credentials
- Money transfer / checkout / "confirm payment" buttons
- Account settings (email change, password change, 2FA disable)
- OAuth / social-login "Authorize app" confirmation dialogs
- Admin actions (delete, promote user, change role)

## Protection Headers

Two mechanisms prevent framing:

```
X-Frame-Options: DENY              # strongest — blocks all framing
X-Frame-Options: SAMEORIGIN        # allows same-origin frames only
Content-Security-Policy: frame-ancestors 'none'     # CSP equivalent of DENY
Content-Security-Policy: frame-ancestors 'self'     # CSP equivalent of SAMEORIGIN
```

If NEITHER is present, the page is frameable from any origin.

## How to Test

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

## False Positives

- Public, read-only pages (home/marketing) lacking frame protection are low/informational — no sensitive action to redress.
- APIs and non-HTML endpoints (JSON, images) are not clickjacking targets.
- **Header-absence alone is NOT a finding.** SameSite cookies, framebusting JS, or the lack of any sensitive framed action can each fully defeat it — which is why Step 2 is mandatory.

## Proof Requirements

A valid clickjacking report shows: (1) the target page rendered inside an attacker-controlled iframe in a real browser, (2) a sensitive state-changing action reachable by a framed click while the victim is authenticated (cookies survive the cross-site context), and (3) a screenshot/recording of the overlay. Reporting missing headers with no working frame PoC is a documentation-quality issue, not a vulnerability.

## Web-Research Methodology Additions (2026)

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
- **Sensitive action list:** consent, transfer, email/password change, 2FA disable, admin delete — rank by impact; read-only pages are informational.

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- **Basic overlay geometry:** `position:relative` iframe with `opacity:0.00001`, `z-index:2`, precise width/height over a `position:absolute` decoy. Chrome applies threshold-based transparency detection (since v76), so tune opacity below the threshold; Firefox does not. For rapid PoCs use Burp **Clickbandit** — perform the clicks in your browser and it generates the overlay HTML.
- **Neutralise frame busters with `sandbox`:** `<iframe src="https://victim/..." sandbox="allow-forms"></iframe>` (or `allow-scripts`). Omitting `allow-top-navigation` stops the frame-buster from checking/breaking out of the top window while keeping the target functional.
- **Double framing:** nest the victim inside two iframes; `parent.location` becomes a descendant-navigation security violation, disabling the buster.
- **`onbeforeunload` prompt:** the attacker page registers a handler returning "Do you want to exit…?" so the user cancels the buster's redirect. The no-content-flushing variant repeatedly navigates to a 204 endpoint to cancel the redirect without any prompt.
- **Restricted zones:** a `<iframe sandbox>` (Chrome) or `document.designMode='on'` (Firefox) disables JS in the subframe, so JS frame busters never run.
- **`window.confirm()` is weak:** browsers suppress simple dialogs in sandboxed frames without `allow-modals` (returns `false`). Server-side transaction authorization is the real fix.
- **Prefilled-input variant:** put attacker values in the target URL's GET params and overlay only the submit button.
- **DOM-XSS carrier:** combine a known DOM-XSS URL in the iframe `src` so the tricked click executes script — clickjacking becomes the delivery mechanism.
- **DoubleClickjacking PoC:** use a top-level window (not an iframe) and a double-click sequence that swaps the clicked element to the sensitive control between the two clicks — framing headers cannot stop it.

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
- **Interaction check:** confirm the overlay works with mouse, keyboard, and (if relevant) touch — OWASP warns against mouse-only assumptions.

### D. Sources — numbered list of URLs you actually fetched

1. https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html
2. https://portswigger.net/web-security/clickjacking
