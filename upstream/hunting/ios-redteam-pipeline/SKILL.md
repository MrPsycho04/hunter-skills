---
name: ios-redteam-pipeline
description: End-to-end iOS red-team pipeline — IPA acquisition (App Store extraction, TestFlight, enterprise/ad-hoc sideload), class-dump/Hopper/Ghidra static analysis, Info.plist + entitlements + Keychain secret extraction, App Transport Security (ATS) misconfig + certificate-pinning bypass (frida-ios-dump, objection, SSL Kill Switch 2), URL-scheme / Universal Link hijack, exported-service enumeration, Frida runtime instrumentation. Companion to apk-redteam-pipeline for the iOS side of a mobile app catalogue. Use when target has an iOS app (App Store listing, TestFlight link, enterprise MDM distribution), when an IPA URL is found hosted on a web server, or when post-recon mentions "iOS app" / "mobile app" in scope alongside an Apple developer account.
---

**Reference files (load on demand):**

- `references/techniques.md` — quick wins, bypasses, real-report techniques, deeper checklists

## When to use this skill

Trigger when:
- Recon surfaces 1+ apps under the target's Apple Developer / App Store publisher page
- A TestFlight public link or enterprise/ad-hoc `.ipa`/`manifest.plist` (OTA install) is found
- Customer-facing app, dealer/partner portal, or employee mobile companion app ships on iOS
- Bug bounty program lists iOS in scope
- `apk-redteam-pipeline` already found Android endpoints/secrets — the iOS build often ships a *different* backend version worth diffing (see `shadow-api`)

DO NOT use for:
- Android-only targets — that's `apk-redteam-pipeline`
- React Native / Flutter apps already fully covered by JS-bundle analysis on the web side
- Server-side only assessments with no mobile client in scope

---

## Stage 0 — Inventory all org-owned iOS apps

```bash
# App Store search API (no auth, no scraping needed)
curl -s "https://itunes.apple.com/search?term=<brand>&country=us&entity=software&limit=50" | python3 -m json.tool

# Pull the full metadata for a known bundle ID (once you have one)
curl -s "https://itunes.apple.com/lookup?bundleId=com.<brand>.app&country=us"
```

Extract: `trackId`, `bundleId`, `sellerName` (developer account — pivot to find sibling apps), `version`,
`releaseNotes` (changelogs often reference deprecated/removed API behavior — feeds `shadow-api`).

Cross-reference sibling-app bundle IDs surfaced from Android APK inventories (same
multi-brand conglomerate usually reuses `com.<corp>.<sub-brand>` naming on both platforms).

---

## Stage 1 — IPA acquisition

### Primary: from a real device you control (no jailbreak needed for a purchased/free app)
```bash
# Install the app on a real device via Apple Configurator 2 or Xcode, then pull the .ipa
# Apple Configurator 2 (macOS): Devices > select device > right-click installed app > "Save to..."
# Or via libimobiledevice:
brew install libimobiledevice ideviceinstaller
ideviceinstaller -l              # list installed apps + bundle IDs
```

### Secondary: TestFlight (if the program distributes betas publicly)
Open the public TestFlight link, install via the TestFlight app, then extract as above.
TestFlight builds are frequently LESS hardened than App Store releases (debug logging left on,
staging API hosts hardcoded) — always prefer a TestFlight build over the Store build if both exist.

### Tertiary: enterprise / ad-hoc distribution (OTA install)
```bash
# itms-services:// links embed a manifest.plist with a direct .ipa URL
curl -s "https://<target>/manifest.plist" | plutil -convert xml1 -o - -
# Look for <key>software-package</key> — that URL is a directly downloadable, unencrypted IPA
curl -sk -L "<software-package-url>" -o target.ipa
```
Enterprise/ad-hoc IPAs are **not FairPlay-encrypted** — no jailbreak or decryption tooling needed,
unlike an App Store binary pulled from a device.

### Decrypting an App-Store-sourced binary (only if extracted from a jailbroken device)
App Store binaries are FairPlay-encrypted at rest; a binary copied off a jailbroken device
needs runtime decryption (`frida-ios-dump`, `bagbak`, or `flexdecrypt`) before static tools can
read it meaningfully:
```bash
pip install --break-system-packages frida-tools
# with frida-server running on the jailbroken device and the app in foreground:
python3 dump.py <bundle_id>          # frida-ios-dump — outputs a decrypted .ipa
```

---

## Stage 2 — Unpack and static analysis

```bash
# An IPA is just a zip
unzip -o target.ipa -d extracted_target/
cd extracted_target/Payload/*.app

# Info.plist — bundle ID, URL schemes, ATS config, entitlements hint
plutil -convert xml1 -o - Info.plist

# Entitlements — codesign reads the .app bundle (or the Mach-O binary), NOT Info.plist
codesign -d --entitlements :- Payload/<AppName>.app 2>/dev/null || \
  security cms -D -i embedded.mobileprovision | plutil -convert xml1 -o - -

# class-dump for Objective-C symbol/class recovery (compiled binary, not the .app bundle)
brew install class-dump
class-dump -H <AppBinaryName> -o headers/

# Swift binaries: class-dump won't show much — use Hopper, Ghidra, or `nm`/`strings` instead
nm -a <AppBinaryName> | grep -i swift | head -50
strings -a <AppBinaryName> > strings_target.txt
```

For a fast triage pass without a disassembler, the strings dump alone usually surfaces most of
what Stage 3 is looking for.

---

## Stage 3 — Secret grep (same catalog as apk-redteam-pipeline, iOS-specific sources added)

```bash
# URL grep — owned-domain references
grep -oE 'https?://[a-zA-Z0-9.-]+\.(target1|target2|target3)\.(com|io|net)[a-zA-Z0-9./_?=&%-]*' strings_target.txt | sort -u

# Cloud credentials (same 60-pattern catalog as Android — reuse verbatim)
grep -oE 'AKIA[A-Z0-9]{16}'                             # AWS Access Key
grep -oE 'AIza[A-Za-z0-9_-]{35}'                        # Google API key
grep -oE 'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*' strings_target.txt   # JWT

# iOS-specific: GoogleService-Info.plist (Firebase config bundled per-platform)
find extracted_target -iname "GoogleService-Info.plist" -exec plutil -convert xml1 -o - {} \;
# Look for API_KEY, PROJECT_ID, STORAGE_BUCKET, GCM_SENDER_ID, GOOGLE_APP_ID — same Firebase
# public-read tests as apk-redteam-pipeline Stage 6.

# iOS-specific: hardcoded config plists shipped in the bundle
find extracted_target -iname "*.plist" ! -iname "Info.plist" -exec sh -c 'echo "=== {} ==="; plutil -convert xml1 -o - "{}"' \;

# App Transport Security exceptions (Info.plist) — tells you if arbitrary/insecure loads are allowed
plutil -extract NSAppTransportSecurity xml1 -o - Info.plist 2>/dev/null
```

### Keychain items left in a backup (if you have a device backup, encrypted or not)
```bash
pip install --break-system-packages iphone_backup_decrypt   # for encrypted local backups
# keychain-dumper (run ON a jailbroken device) for live keychain contents:
./keychain-dumper -e   # -e also decodes entitlements per item, showing which app owns which secret
```

---

## Stage 5 — URL scheme / Universal Link enumeration

```bash
# Custom URL schemes (CFBundleURLTypes) — anything can invoke these via Safari/another app
plutil -extract CFBundleURLTypes xml1 -o - Info.plist

# Universal Links / Associated Domains (applinks:) — requires a matching apple-app-site-association
plutil -extract com.apple.developer.associated-domains xml1 -o - Info.plist 2>/dev/null
curl -s "https://<domain>/.well-known/apple-app-site-association" | python3 -m json.tool
```

For each custom scheme found (e.g. `myapp://`):
- Trigger it from Safari/Notes and observe what the app does with parameters:
  `myapp://reset-password?token=x&redirect=https://evil.com` — does the app trust an
  attacker-supplied `redirect`/`url`/`callback` param and load it in a WebView (open-redirect →
  WebView-XSS chain) or use it to bypass an auth screen?
- If the scheme is also registered by another app on the device (scheme squatting), a malicious
  app can intercept traffic intended for the legitimate app — check `CFBundleURLName` uniqueness.
- Universal Links degrade to the custom scheme when the AASA validation fails or is absent —
  test both paths for the same parameter-injection surface.

---

## Stage 6 — Runtime instrumentation (Frida / objection)

Requires a jailbroken device (checkra1n/palera1n for older iOS, or a Corellium virtual device) —
unlike Android, there is no practical rooted-emulator equivalent for iOS.

```bash
# Setup
pip install --break-system-packages frida-tools objection
# Install frida-server on the jailbroken device via Cydia/Sileo (frida repo), matching the
# host frida-tools version exactly — version skew is the #1 cause of "failed to attach" errors.

# Full interactive exploration
objection --gadget <bundle_id> explore
# Inside objection:
ios hooking watch class <ClassName>
ios hooking watch class_method <Class>.<method> --dump-args --dump-return
ios keychain dump
ios plist dump
ios cookies get
```

### Network traffic capture (once pinning is bypassed)
```bash
mitmproxy --listen-port 8080
# Set the device Wi-Fi proxy to host:8080, install the mitmproxy CA via http://mitm.it on-device
# (Settings > General > VPN & Device Management > trust the cert, then enable full trust under
# Certificate Trust Settings — iOS requires this second step, unlike Android)
```

---

## Decision tree — what to do with what you find

| Finding | Next move |
|---|---|
| `NSAllowsArbitraryLoads = true` | Confirm a token/credential actually transits HTTP — needs a network position to exploit, but is a real finding on its own (config-level, no MITM needed to report) |
| Hardcoded JWT / API key in strings dump | Same as Android — test against the API host, chain into `api-misconfig` |
| GoogleService-Info.plist present | Test public Firestore/RTDB/Storage read (identical to apk-redteam-pipeline Stage 6) |
| Custom URL scheme accepts a `redirect`/`url` param | Test open-redirect → WebView-load chain; check for scheme squatting by other installed apps |
| Universal Link AASA missing/misconfigured | Confirm scheme fallback still carries the same injectable params |
| Entitlements show `keychain-access-groups` shared with other apps | Cross-app Keychain read — a compromised sibling app reads this app's secrets |
| Older API version referenced vs. what the current web app calls | Hand off to `shadow-api` for version-diffing |

---

## Anti-patterns

- **Don't assume App Store = FairPlay-encrypted requires jailbreak** — TestFlight and enterprise/ad-hoc
  builds are frequently NOT encrypted and need no decryption step at all. Always check distribution
  channel before reaching for `frida-ios-dump`.
- **Don't skip Swift binaries because class-dump shows nothing** — `strings` and `nm` still work; a
  proper Swift-aware disassembler (Hopper, Ghidra with Swift demangling) recovers the rest.
- **Don't stop at "pinning is present" as a finding** — pinning is a mitigation, not a vulnerability;
  the finding is what you can do once it's bypassed (or the ATS misconfig that makes it moot).
- **Don't ignore WKWebView-loaded content** — `NSAllowsArbitraryLoadsInWebContent` is a distinct,
  frequently-overlooked exception from the top-level ATS setting.
- **Don't run Frida instrumentation against a personal/production Apple ID device** — use a
  dedicated jailbroken test device or Corellium instance.

---

## Tooling install (one-time)

```bash
brew install libimobiledevice ideviceinstaller class-dump
pip install --break-system-packages frida-tools objection iphone_backup_decrypt
# Jailbroken test device (checkra1n/palera1n) or a Corellium virtual iOS device for runtime work
# frida-server installed on-device via the Frida Cydia/Sileo repo
```

---

## Related Skills & Chains

- **`apk-redteam-pipeline`** — the Android counterpart; run both when a target ships on both
  platforms. Sibling bundle IDs and shared backend endpoints frequently surface cross-platform.
- **`shadow-api`** — mobile builds (iOS and Android alike) often hardcode an older API
  version than the current web app. Chain: IPA reveals `/v1/*` endpoints → `shadow-api`
  diffs `/v1/` against the current `/v3/` for auth/validation regressions.
- **`cloud-iam-deep`** — IPA secret extraction frequently yields live AWS/GCP/Azure credentials
  or Firebase configs. Chain: strings-grep produces an AWS key → `cloud-iam-deep` privilege
  analysis.
- **`api-misconfig`** — hardcoded JWTs/API keys extracted here feed directly into JWT
  algorithm-confusion and mass-assignment testing there.
- **`evidence-hygiene`** — extracted Keychain items and secrets need redaction before report
  inclusion.
- **`offensive-osint`** — App Store developer-page enumeration is part of the broader org recon
  graph; pair with certificate-transparency lookups for the same brand.

## Web-Research Methodology Additions (2026)

### A. Discovery checklist — concrete artifacts, endpoints, patterns, tools to look for

- **IPA acquisition paths (2024–2026):** `ipatool auth/download -b <bundle>` (free App Store copy with your own Apple ID), Apple Configurator 2 temporary download, OTA `itms-services://` manifest via `itms-services -u ... -o - > out.ipa`, or client-supplied Xcode-exported IPA. App Store binaries are FairPlay-encrypted (`LC_ENCRYPTION_INFO_64`, `cryptid 1`) — a raw unzip of that IPA yields unusable `strings`/class-dump until decrypted.
- **Decrypted binary acquisition:** jailbroken device + `frida-ios-dump` (`./dump.py -l`, `./dump.py com.target.app`), `flexdecrypt`/`flexdump`, `bagbak`, or `ipa-decryptor`. Non-jailbroken route: Sideloadly re-packages the app with the **Frida Gadget** and installs it with `get-task-allow`, giving full objection/Frida testing without a jailbreak (OWASP MASTG demo workflow).
- **IPA static inventory:** `unzip`, then `Payload/<App>.app/`: `Info.plist`, `_CodeSignature/`, `embedded.mobileprovision`, `Assets.car`, SQLite/plist/JSON caches. Commands: `plutil -p Info.plist`, `security cms -D -i embedded.mobileprovision`, `codesign -d --entitlements -`, `otool -hv | grep PIE`, `otool -I -v | grep stack_chk`, `otool -L`, `class-dump -H <bin> -o headers/`, `nm -gU`, `strings | egrep -i 'https?://|api|auth|token|key|secret'`.
- **Info.plist / entitlements markers:** `CFBundleURLTypes` (custom URL schemes), `LSApplicationQueriesSchemes` (max 50), `NSAppTransportSecurity`/`NSExceptionDomains`/`NSAllowsArbitraryLoads` (ATS exceptions), `com.apple.developer.associated-domains`, `keychain-access-groups`, `app groups`, `get-task-allow` (debug entitlement — should be absent in release), wildcard `applinks:*.example.com`.
- **Universal Links vs custom schemes (MASTG-KNOW-0080):** Universal Links are `https://` and cannot be claimed by other apps; require a valid `apple-app-site-association` at the domain. Custom `tg://`-style schemes are claimable by any installed app and are the weaker surface — test whether a legacy scheme remains registered alongside Universal Links.
- **Keychain & storage (MASTG-KNOW-0057):** Keychain items with `SecAccessControl` (Touch ID/passcode gating), accessibility class `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`; compare `UserDefaults`, plists, CoreData, Realm, SQLite, and `UIPasteboard` (expiry/`.localOnly`). Keychain survives uninstall — plan migration in fixes.
- **Pinning sources:** `TrustKit`, custom `URLSessionDelegate`/`WKNavigationDelegate` `URLSession:didReceiveChallenge:`, `SecTrustEvaluate` hooks; third-party analytics/ads SDKs typically do **not** honor the app's pinning and must be enumerated per MASVS-NETWORK.
- **Frameworks:** MobSF (automated static), class-dump/class-dump-swift, Hopper/Ghidra/IDA/Binary Ninja for Swift name mangling, Frida + objection for dynamic, `xcrun simctl openurl` for deep-link testing, `mitmproxy`/Burp with a trusted CA, `ipropxy` + SSH for jailbroken device access.

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- **Pinning bypass validation:** run the app behind mitmproxy with the custom CA installed; every HTTPS request the app makes should fail if pinned — any that succeeds is unpinned (and a finding). Inspect `URLSession` configuration at runtime for custom protocol classes or redirect handlers that bypass pinning. Generic bypass: `objection -g <pkg> explore` → `ios sslpinning disable` hooking TrustKit / `SecTrustEvaluate`; custom pinning needs a targeted Frida script.
- **Deep-link URL fuzzing (HackTricks):** enumerate schemes from `Info.plist`, then drive via `xcrun simctl openurl <sim> 'targetapp://...'` or a Safari page `<a href="target://oauth/callback?code=...">`. Test path traversal in the path, SQLi in query params, oversize inputs, terminator chars, and `target://webview?url=javascript:...`. Frida URL-scheme fuzzing via SpringBoard: `frida -U SpringBoard -l ios-url-scheme-fuzzing.js` then `fuzz("iGoat", "iGoat://?contactNumber={0}&message={0}")`.
- **Scheme hijack / OAuth token theft:** any app can register the same custom scheme, so an OAuth `code` delivered via `target://` can be intercepted by a malicious app; prefer Universal Links. Confirm Universal Link association by serving a malformed `apple-app-site-association` and verifying rejection.
- **Frida on non-jailbroken devices:** sideload with Frida Gadget via Sideloadly, then use objection fully. For file protection/Secure Enclave behaviour, a physical device is required; simulator builds lack the FairPlay-encrypted segment.
- **Swift vs Objective-C:** Objective-C retains class/method metadata — `class-dump` reconstructs headers quickly. Swift uses name mangling; use `class-dump-swift`, `swift-demangle`, `nm`, or Ghidra/Hopper and Frida `ObjC.classes` enumeration for runtime inspection.
- **Secret greps that matter:** `strings` + jadx-equivalent static review for `password|secret|api_key|token|BEGIN RSA`, AWS keys, Firebase configs; then validate each live and in scope. Pin the public key (SPKI hash), not the leaf cert, so renewal does not break the app.
- **MinimumOSVersion tweak:** if a jailbroken device's iOS is newer than the app supports, edit `Info.plist` `MinimumOSVersion` in the encrypted IPA downloaded via Configurator (same Apple ID as the device) to install and dump it.

### C. Validation / proof bar — how to confirm and avoid false positives

- **Pinning is defense-in-depth** (MASVS-RESILIENCE): absence of pinning alone is not a critical finding — prove what the intercepted API exposes. Pinning fails closed with a bad test cert (missing `serverAuth` EKU) — ensure the test CA is valid or matching/non-matching pins are both cancelled and you get a false negative.
- **Do not trust encrypted-range analysis:** in partial/decrypted mode, disassembly, Swift metadata, and `strings` from protected `__TEXT` ranges produce noise that looks like evidence. Run them only against verified-decrypted binaries/ranges.
- **Entitlements:** `get-task-allow = true` in a release build is a real finding; wildcard `applinks:*.example.com` widens what a compromised subdomain can do; app groups/associated domains should exist only when needed. Ad-hoc signing simulator builds may be refused by SpringBoard if these are wrong.
- **Keychain items survive uninstall** — validation of a "fix" must account for migration of weaker legacy items, not just new writes.
- **Deep-link findings require a demonstrated unauthorized action or data leak** — a declared custom scheme alone is not a vulnerability; show the malformed URI reaching a WebView, query, or privileged flow.
- **Simulator vs device gap:** file protection, Secure Enclave, Universal Clipboard, and real Keychain extraction are unverified on a simulator; say so explicitly rather than claiming coverage.
- A clean advisory/OSV lookup is not proof of a vulnerable dependency — pair with the shipped version from `Package.resolved`/`swift package show-dependencies`.

- **Objective-C vs Swift triage:** Objective-C leaks header-like declarations via `class-dump`; Swift needs `class-dump-swift`/`swift-demangle`/Ghidra plus Frida `ObjC.classes` enumeration — budget more reverse-engineering time and don't treat a failed class-dump as "no classes".
- **Binary hardening checks:** PIE (`otool -hv | grep PIE`), stack canaries (`otool -I -v | grep stack_chk`), ARC, and encryption are hardening signals; their absence is not automatically a vulnerability (MASVS-RESILIENCE framing).
- **ATS exceptions as recon:** `NSAllowsArbitraryLoads`/`NSExceptionDomains` tell you exactly which hosts the app talks to over HTTP or with reduced TLS — prioritize those for traffic interception.
- **Validation of dynamic analysis tooling:** confirm Frida/objection actually attached (`frida-ps -U`, objection prompt shows the process) before concluding a control held — a failed hook is a false negative, not a passing test.
- **Jailbreak detection scope:** MASVS-RESILIENCE expects detection of jailbreak, debugger, and dynamic-instrumentation frameworks, but the standard deliberately does not prescribe techniques; every technique has known bypasses, so report the *consequence* (sensitive data accessible under instrumentation), not the missing check in isolation.
- **Pasteboard and screenshot exposure:** `UIPasteboard.general` persists across apps unless `.localOnly` and an expiry are set; background snapshots leak sensitive screens (MASWE-0036/0038) — verify with `simctl` screenshots before reporting.
- **Deep-link fix verification:** require both input validation and source-application validation in custom URL scheme handlers (MASTG-BEST-0054/0055); Universal Link handlers need their own parameter validation (BEST-0072).
- **Dependency checking on iOS:** `swift package show-dependencies` exposes the transitive tree where forgotten packages hide; combine with OSV/advisory lookup and the shipped version, not just a clean scan result.
- **Scope discipline:** use only apps you own or are engaged to test; device instrumentation is performed on a device/emulator you control with test accounts and test data.

- **Non-production resources in the bundle:** development/staging configuration, test credentials, and internal hostnames shipped in the release IPA are common high-yield findings (MASWE-0064) — grep the decrypted bundle and bundled plists for `dev`/`staging`/`internal`.
- **Holistic ordering:** acquire → decrypt → automated MobSF triage → manual static review → targeted Frida/objection hooks → traffic capture → chain to API testing; each step's output should feed the next rather than being reported in isolation.

### D. Sources — numbered list of URLs you actually fetched

1. https://hacktricks.wiki/en/mobile-pentesting/ios-pentesting/basic-ios-testing-operations.html (FairPlay decryption, `otool`/`LC_ENCRYPTION_INFO`, frida-ios-dump, flexdecrypt, encrypted-range caveat)
2. https://desecurity.github.io/hacktricks/mobile-pentesting/ios-pentesting/ios-custom-uri-handlers-deeplinks-custom-schemes.html (URL scheme enumeration, handler methods, Frida scheme fuzzing, hijacking)
3. https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0080/ (Universal Links uniqueness and domain association)
4. https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0019 (cross-platform deep-link verification principles)
5. https://sentinelden.com/blog/owasp-masvs-ios-real-ipa (MASVS applied to an IPA: entitlements, pinning, third-party SDK trust, `xcrun simctl openurl`)
6. https://hosted-files.sched.co/owasp2025globalappseceu/f8/OWASP%20AppSec%20EU%202025%20-%20Hack-Proof%20Your%20Code_%20%20Exploring%20Mobile%20App%20Weaknesses%20with%20OWASP%20MAS.pdf (MASVS/MASTG v2, non-jailbroken sideload with Frida Gadget)
7. https://codezup.com/ios-app-security-auditing-guide (release entitlements, Keychain accessibility, pinning caveats, simulator limitations)
8. https://bugbounty.info/Attack-Surface/Mobile/iOS/ (ipatool/frida-ios-dump acquisition, Info.plist ATS checks, URL-scheme hijack PoC)
9. https://platformsecurity.com/blog/decrypt-ios-apps-pentest-guide (decrypted-binary-first workflow, MobSF/Ghidra/Frida ordering)
10. https://notsunde.com/blogs/ios-pentest-setup-pt1 (non-jailbroken setup, `LC_ENCRYPTION_INFO_64` inspection, MinimumOSVersion tweak)

