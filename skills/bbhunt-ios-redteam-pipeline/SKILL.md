---
name: bbhunt-ios-redteam-pipeline
description: "Acquire, decrypt, static-analyze and runtime-instrument an in-scope IPA end to end. Unified from 2 upstream skills (cbh, hunting). For authorized security testing only."
agent_created: true
---

# iOS IPA red-team pipeline — unified methodology

> **Unified skill.** Built from 2 upstream skills across cbh, hunting. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### A. Discovery checklist — concrete artifacts, endpoints, patterns, tools to look for

- **IPA acquisition paths (2024–2026):** `ipatool auth/download -b <bundle>` (free App Store copy with your own Apple ID), Apple Configurator 2 temporary download, OTA `itms-services://` manifest via `itms-services -u ... -o - > out.ipa`, or client-supplied Xcode-exported IPA. App Store binaries are FairPlay-encrypted (`LC_ENCRYPTION_INFO_64`, `cryptid 1`) — a raw unzip of that IPA yields unusable `strings`/class-dump until decrypted.
- **Decrypted binary acquisition:** jailbroken device + `frida-ios-dump` (`./dump.py -l`, `./dump.py com.target.app`), `flexdecrypt`/`flexdump`, `bagbak`, or `ipa-decryptor`. Non-jailbroken route: Sideloadly re-packages the app with the **Frida Gadget** and installs it with `get-task-allow`, giving full objection/Frida testing without a jailbreak (OWASP MASTG demo workflow).
- **IPA static inventory:** `unzip`, then `Payload/<App>.app/`: `Info.plist`, `_CodeSignature/`, `embedded.mobileprovision`, `Assets.car`, SQLite/plist/JSON caches. Commands: `plutil -p Info.plist`, `security cms -D -i embedded.mobileprovision`, `codesign -d --entitlements -`, `otool -hv | grep PIE`, `otool -I -v | grep stack_chk`, `otool -L`, `class-dump -H <bin> -o headers/`, `nm -gU`, `strings | egrep -i 'https?://|api|auth|token|key|secret'`.
- **Info.plist / entitlements markers:** `CFBundleURLTypes` (custom URL schemes), `LSApplicationQueriesSchemes` (max 50), `NSAppTransportSecurity`/`NSExceptionDomains`/`NSAllowsArbitraryLoads` (ATS exceptions), `com.apple.developer.associated-

### Techniques, payloads and bypasses

### Network traffic capture (once pinning is bypassed)

```bash
mitmproxy --listen-port 8080
# Set the device Wi-Fi proxy to host:8080, install the mitmproxy CA via http://mitm.it on-device
# (Settings > General > VPN & Device Management > trust the cert, then enable full trust under
# Certificate Trust Settings — iOS requires this second step, unlike Android)
```

---

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- **Pinning bypass validation:** run the app behind mitmproxy with the custom CA installed; every HTTPS request the app makes should fail if pinned — any that succeeds is unpinned (and a finding). Inspect `URLSession` configuration at runtime for custom protocol classes or redirect handlers that bypass pinning. Generic bypass: `objection -g <pkg> explore` → `ios sslpinning disable` hooking TrustKit / `SecTrustEvaluate`; custom pinning needs a targeted Frida script.
- **Deep-link URL fuzzing (HackTricks):** enumerate schemes from `Info.plist`, then drive via `xcrun simctl openurl <sim> 'targetapp://...'` or a Safari page `<a href="target://oauth/callback?code=...">`. Test path traversal in the path, SQLi in query params, oversize inputs, terminator chars, and `target://webview?url=javascript:...`. Frida URL-scheme fuzzing via SpringBoard: `frida -U SpringBoard -l ios-url-scheme-fuzzing.js` then `fuzz("iGoat", "iGoat://?contactNumber={0}&message={0}")`.
- **Scheme hijack / OAuth token theft:** any app can register the same custom scheme, so an OAuth `code` delivered via `target://` can be intercepted by a malicious app; prefer Universal Links. Confirm Universal Link association by serving a malformed `apple-app-site-association` and verifying rejection.
- **Frida on non-jailbroken devices:** sideload with Frida Gadget via Sideloadly, then use objection fully. For file protection/Secure Enclave behaviour, a physical device is required; simulator builds lack the FairPlay-encrypted segment.
- **Swift v

### Certificate-pinning bypass (when pinning IS present and correctly configured)

```bash
pip install --break-system-packages frida-tools objection
objection --gadget <bundle_id> explore
# inside objection:
ios sslpinning disable
```
If you want a Frida script instead, don't hand-roll one — use a maintained universal bypass
(e.g. the widely-used `frida-ios-pinning`/`ios-ssl-bypass` community scripts). Modern iOS TLS goes
through **BoringSSL**, so a reliable universal hook targets `SSL_CTX_set_custom_verify` /
`SSL_get_psk_identity` at the native layer and forces the verify callback to return "OK" — this
catches `URLSession`, `AFNetworking`, `Alamofire`, and `TrustKit` at once, which per-delegate
Objective-C hooks (like the deprecated `NSURLConnection` delegate) miss:
```bash
# Pull a maintained universal BoringSSL-layer bypass and run it:
frida -U -f <bundle_id> -l ios-ssl-bypass.js --no-pause
```
In practice, prefer **SSL Kill Switch 2** (jailbroken device, installs as a tweak) or
**objection's `ios sslpinning disable`** over any hand-rolled script — both cover the common
pinning implementations (`NSURLSession`, `AFNetworking`, `TrustKit`) without per-app tuning.

---

### Validation and proof

### C. Validation / proof bar — how to confirm and avoid false positives

- **Pinning is defense-in-depth** (MASVS-RESILIENCE): absence of pinning alone is not a critical finding — prove what the intercepted API exposes. Pinning fails closed with a bad test cert (missing `serverAuth` EKU) — ensure the test CA is valid or matching/non-matching pins are both cancelled and you get a false negative.
- **Do not trust encrypted-range analysis:** in partial/decrypted mode, disassembly, Swift metadata, and `strings` from protected `__TEXT` ranges produce noise that looks like evidence. Run them only against verified-decrypted binaries/ranges.
- **Entitlements:** `get-task-allow = true` in a release build is a real finding; wildcard `applinks:*.example.com` widens what a compromised subdomain can do; app groups/associated domains should exist only when needed. Ad-hoc signing simulator builds may be refused by SpringBoard if these are wrong.
- **Keychain items survive uninstall** — validation of a "fix" must account for migration of weaker legacy items, not just new writes.
- **Deep-link findings require a demonstrated unauthorized action or data leak** — a declared custom scheme alone is not a vulnerability; show the malformed URI reaching a WebView, query, or privileged flow.
- **Simulator vs device gap:** file protection, Secure Enclave, Universal Clipboard, and real Keychain extraction are unverified on a simulator; say so explicitly rather than claiming coverage.
- A clean advisory/OSV lookup is not proof of a vulnerable dependency — pair with the shipped version from `Package.r

### Escalation and related chains

### Keychain items left in a backup (if you have a device backup, encrypted or not)

```bash
pip install --break-system-packages iphone_backup_decrypt   # for encrypted local backups
# keychain-dumper (run ON a jailbroken device) for live keychain contents:
./keychain-dumper -e   # -e also decodes entitlements per item, showing which app owns which secret
```

---

### Related Skills & Chains

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

### Related Skills & Chains

- **`apk-redteam-pipeline`** — the Android counterpart; run both when a target ships on both
  platforms. Sibling bundle IDs and shared backend endpoints frequently surface cross-platform.
- **`hunt-shadow-api`** — mobile builds (iOS and Android alike) often hardcode an older API
  version than the current web app. Chain: IPA reveals `/v1/*` endpoints → `hunt-shadow-api`
  diffs `/v1/` against the current `/v3/` for auth/validation regressions.
- **`cloud-iam-deep`** — IPA secret extraction frequently yields live AWS/GCP/Azure credentials
  or Firebase configs. Chain: strings-grep produces an AWS key → `cloud-iam-deep` privilege
  analysis.
- **`hunt-api-misconfig`** — hardcoded JWTs/API keys extracted here feed directly into JWT
  algorithm-confusion and mass-assignment testing there.
- **`evidence-hygiene`** — extracted Keychain items and secrets need redaction before report
  inclusion.
- **`offensive-osint`** — App Store developer-page enumeration is part of the broader org recon
  graph; pair with certificate-transparency lookups for the same brand.

### Tools and wordlists

### Tooling install (one-time)

```bash
brew install libimobiledevice ideviceinstaller class-dump
pip install --break-system-packages frida-tools objection iphone_backup_decrypt
# Jailbroken test device (checkra1n/palera1n) or a Corellium virtual iOS device for runtime work
# frida-server installed on-device via the Frida Cydia/Sileo repo
```

---

## Source skills merged into this topic

- `hunting` — `ios-redteam-pipeline`
- `cbh` — `ios-redteam-pipeline`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `references/upstream-assets/` — 1 companion files (payload/technique references, scripts, validators and schemas) from the contributing skills
- `../../upstream/` — complete unmodified archives of all five source repositories
- `bbhunt-methodology` — orchestrator, state machine and class router
