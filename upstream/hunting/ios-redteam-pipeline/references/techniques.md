# ios-redteam-pipeline — Technique reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete technique.

---

## Stage 4 — App Transport Security (ATS) misconfig + certificate-pinning bypass



### Check for blanket ATS disablement (the single most common iOS network misconfig)

```bash

plutil -extract NSAppTransportSecurity xml1 -o - Info.plist

```

Red flags in the output:

- `NSAllowsArbitraryLoads = true` at the top level — HTTP (cleartext) allowed anywhere, app-wide.

- Per-domain `NSExceptionAllowsInsecureHTTPLoads = true` for a domain that carries auth tokens.

- `NSAllowsArbitraryLoadsInWebContent = true` — WKWebView traffic exempted, common blind spot.



A blanket ATS exception + a network position (rogue AP, ARP spoof, malicious VPN profile) =

plaintext credential/token interception without touching pinning at all.



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
