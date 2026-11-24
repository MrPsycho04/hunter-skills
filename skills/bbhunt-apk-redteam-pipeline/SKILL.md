---
name: bbhunt-apk-redteam-pipeline
description: "Acquire, decompile, grep, instrument and test an in-scope APK end to end. Unified from 2 upstream skills (cbh, hunting). For authorized security testing only."
agent_created: true
---

# Android APK red-team pipeline — unified methodology

> **Unified skill.** Built from 2 upstream skills across cbh, hunting. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### A. Discovery checklist — concrete artifacts, endpoints, patterns, tools to look for

- **Map findings to OWASP MASVS v2 groups (MASVS-STORAGE, -CRYPTO, -AUTH, -NETWORK, -PLATFORM, -CODE, -RESILIENCE, -PRIVACY)** and cite MASTG test IDs. MASWE-0004 (sensitive data hardcoded in package), MASWE-0018 (no authz on app components), MASWE-0028 (insecure identity pinning), MASWE-0029 (insecure deep links) are the highest-yield weakness categories.
- **Manifest entry points (apktool `d app.apk` → AndroidManifest.xml):** `android:exported="true"` on activity/service/receiver/provider without `android:permission`; `android:debuggable="true"`; `android:allowBackup="true"`; `usesCleartextTraffic`; `android:networkSecurityConfig="@xml/network_security_config"`; `android:sharedUserId`; task `android:launchMode`. A custom permission with `normal`/`dangerous` protection is *not* sufficient — prefer `signature`.
- **Deep links (MASTG-KNOW-0019 / MASWE-0029):** browsable `<intent-filter>` = `VIEW` + `DEFAULT` + `BROWSABLE` + `<data scheme/host/path>`. Custom `myapp://` schemes are unverifiable and claimable by any app; App Links need `autoVerify="true"` and a valid `https://<host>/.well-known/assetlinks.json` (every subdomain needs its own file; redirects break verification). Enumerate with MASTG-TECH-0172; monitor handlers with Frida (TECH-0173).
- **Network security config & pinning sources:** `res/xml/network_security_config.xml` `<domain-config><pin-set>` with digest hashes; pinned certs in `res/raw/` and `assets/`; OkHttp `CertificatePinner.check`; BoringSSL/Cronet native pinning; Tr

### Techniques, payloads and bypasses

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

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- **Bypassing pinning (MASTG-TECH-0012):** start with `objection -g <pkg> explore` → `android sslpinning disable` (patches `X509TrustManager`/`TrustManagerImpl`), or `frida -U -f <pkg> -l frida-multiple-unpinning.js --no-pause` (covers OkHttp, Conscrypt, Cronet more broadly). Targeted hooks: `Java.use('okhttp3.CertificatePinner').check.overload('java.lang.String','java.util.List').implementation = function(){}`.
- **Native pinning:** `frida-gum Interceptor.attach` on `SSL_CTX_set_custom_verify`; handle anti-Frida checks that scan `/proc/self/maps` for `frida-agent` by renaming the library or using Frida Gadget injection. `frida-trace -U -f <pkg> -j 'javax.net.ssl.*!*'` auto-generates stubs for discovery.
- **No-root alternative:** `apk-mitm` repackages with trust changes; or lower `targetSdkVersion` to 23 in the manifest so user CAs are trusted, rebuild with `apktool b`, sign — but expect signature-verification crashes, which themselves confirm integrity controls.
- **Exported-component abuse via drozer/adb:** `run app.activity.info -a com.target` lists exported activities; launch sensitive screens directly to bypass auth. Content providers: `adb shell content query --uri content://com.target.provider/users` can leak SQLite rows. Missing `grantUriPermissions` on FileProviders enables file reads.
- **Intent injection:** proxy components that forward attacker-controlled Intents to `startActivity()`/`sendBroadcast()` act like web open redirects — drive non-exported components or content providers. We

### Validation and proof

### C. Validation / proof bar — how to confirm and avoid false positives

- **Pinning is a speed bump, not a control** — MASVS files pinning under resilience; the finding is what the now-visible API exposes. Do not report "missing pinning" alone as Critical; test every app as if pinning were already defeated.
- **Resilience absence ≠ vulnerability** (MASTG anti-reversing overview): lack of root detection, obfuscation, or anti-debug does not create a vuln — only report where the threat model requires it.
- **Severity from impact and likelihood for the actual threat model:** an exported provider leaking notes in a note app is Critical; a missing root check in the same app is usually not a finding.
- **Validate extracted credentials as live** and in scope (`triage-validation` 7-Question Gate: "does this credential still authenticate today?") — a rotated key in commit history or a publishable Firebase web config is not a live secret.
- **Prove component abuse end-to-end:** demonstrate the exported activity/provider actually returns another user's or privileged data, not just that it is exported. For deep links, show the malformed URI drives an unauthorized action or leaks a token.
- **Use only apps you own or are engaged to test** on devices/emulators you control with test accounts — decompiling third-party apps may violate licence, and probing their backend without permission is unauthorized access.
- **Partial-mode caveat (HackTricks iOS/Android):** do not trust disassembly or `strings` attributed to encrypted/protected ranges; verify decrypted state first.

- **App Links ver

### Escalation and related chains

### Related Skills & Chains

- **`cloud-iam-deep`** — APK secret extraction frequently yields live AWS/GCP/Azure credentials. Chain primitive: jadx string-grep produces AWS Access Key ID + Secret → `cloud-iam-deep` `aws sts get-caller-identity` → role/policy enumeration → IAM privilege-escalation path (one of 24 documented AWS escalation patterns) → cloud-plane takeover. Same flow applies to GCP service-account JSON and Azure shared-access-signature tokens extracted from APK resources.
- **`api-misconfig`** — APK endpoint inventory hands you the API surface for free; mass-assignment, JWT, and CORS bugs are typical. Chain primitive: APK reveals `/v1/users/me` and `/v1/admin/users` → `api-misconfig` mass-assignment probes (`{is_admin:true}`) against `/v1/users/me` → admin role escalation → access to `/v1/admin/users`.
- **`rce`** — Hardcoded JWT signing secrets (HS256) extracted from APK enable arbitrary token forging. Chain primitive: APK strings yield HS256 secret → forge admin token → access admin API → if API has eval/template/sink → `rce` to server. Also: exported components with intent-injection sinks can reach `Runtime.exec` if app is local-installed.
- **`offensive-osint`** — APK is one node in the broader org recon graph; pair with breach corpora and cert transparency. Chain primitive: APK reveals internal API hostname `api2.example.com` → `offensive-osint` certificate-transparency lookup → discover sibling subdomains → expanded attack surface.
- **`redteam-report-template`** — APK findings need clear "what the binary leaks" framing because client engineers often dis

### Related Skills & Chains

- **`cloud-iam-deep`** — APK secret extraction frequently yields live AWS/GCP/Azure credentials. Chain primitive: jadx string-grep produces AWS Access Key ID + Secret → `cloud-iam-deep` `aws sts get-caller-identity` → role/policy enumeration → IAM privilege-escalation path (one of 24 documented AWS escalation patterns) → cloud-plane takeover. Same flow applies to GCP service-account JSON and Azure shared-access-signature tokens extracted from APK resources.
- **`hunt-api-misconfig`** — APK endpoint inventory hands you the API surface for free; mass-assignment, JWT, and CORS bugs are typical. Chain primitive: APK reveals `/v1/users/me` and `/v1/admin/users` → `hunt-api-misconfig` mass-assignment probes (`{is_admin:true}`) against `/v1/users/me` → admin role escalation → access to `/v1/admin/users`.
- **`hunt-rce`** — Hardcoded JWT signing secrets (HS256) extracted from APK enable arbitrary token forging. Chain primitive: APK strings yield HS256 secret → forge admin token → access admin API → if API has eval/template/sink → `hunt-rce` to server. Also: exported components with intent-injection sinks can reach `Runtime.exec` if app is local-installed.
- **`offensive-osint`** — APK is one node in the broader org recon graph; pair with breach corpora and cert transparency. Chain primitive: APK reveals internal API hostname `api2.example.com` → `offensive-osint` certificate-transparency lookup → discover sibling subdomains → expanded attack surface.
- **`redteam-report-template`** — APK findings need clear "what the binary leaks" framing because client

### Tools and wordlists

### Tooling install (one-time)

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

## Source skills merged into this topic

- `hunting` — `apk-redteam-pipeline`
- `cbh` — `apk-redteam-pipeline`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `bbhunt-methodology` — orchestrator, state machine and class router
