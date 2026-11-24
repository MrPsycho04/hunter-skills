---
name: bbhunt-grpc
description: "Unified methodology for grpc.. Unified from 2 upstream skills (cbh, hunting). For authorized security testing only."
agent_created: true
---

# Grpc — unified methodology

> **Unified skill.** Built from 2 upstream skills across cbh, hunting. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### A. Discovery checklist — concrete places, params, headers, flows to look

- **Fingerprint by content-type and trailers** (OWASP WSTG WSTG-APIT-10): requests with `application/grpc`, `application/grpc-web`, `application/grpc-web-text`; responses with `grpc-status` / `grpc-message` trailers; POST paths of the form `/<package>.<Service>/<Method>` (e.g. `/shop.v1.OrderService/GetOrder`). Generated gRPC-Web client code in JS bundles leaks service paths and often message field names/numbers.
- Probe **all entry points**, because controls are frequently applied to only one: native gRPC (port 50051 / h2), gRPC-Web through Envoy/APISIX/grpcwebproxy, and REST/JSON transcoding via `google.api.http` annotations (grpc-gateway, cloud API gateways). Ask specifically: can the native port be reached directly, bypassing the gateway's auth/rate limits?
- **Reflection first**: `grpcurl <host>:443 list`, `... describe <pkg>.<Service>`, `... describe .<pkg>.<RequestMessage>` (leading dot = fully qualified type). Success means full API inventory. Note any `admin`, `debug`, `internal`, `migration` methods the browser client never calls.
- **Built-in services** to check explicitly (WSTG): `grpc.reflection.v1.ServerReflection` and legacy `grpc.reflection.v1alpha.ServerReflection`, `grpc.health.v1.Health` (can reveal internal service names), and `grpc.channelz.v1.Channelz` (debug: internal channels, connections, peer addresses). Reflection in production is an enabler, not by itself a vuln — but Channelz exposure is often reportable.
- **Reflection disabled? Work blind**: `.proto`/descriptor sets 

### Signals and surfaces

### Crown Jewel Targets

gRPC reflection enabled = full service catalog enumeration without source code. The highest-value gRPC bugs come from the architectural assumption that a service is "internal" — auth is enforced at the edge proxy, and the backend trusts any caller that reaches it. Once you reach the backend directly (exposed port, SSRF, proxy bypass), that trust collapses.

**Highest-value findings:**
- **Reflection enabled in production** — `grpc.reflection.v1alpha.ServerReflection` / `grpc.reflection.v1.ServerReflection` lists every method, message, and internal service. Enumeration enabler, not a vuln on its own (see Validation).
- **Missing auth on internal service** — a service designed for east-west microservice traffic exposed externally with no mTLS and no per-method authorization → call privileged methods directly.
- **Edge-auth-only / metadata-stripping** — proxy authenticates the user but the backend re-trusts proxy-injected headers (`x-user-id`, `x-tenant-id`, `x-forwarded-*`); if you reach the backend or can inject those headers via the proxy, you impersonate any tenant.
- **Plaintext gRPC** — gRPC h2c (cleartext HTTP/2) on a non-standard port → credential/metadata interception.
- **HTTP/2 Rapid Reset DoS (CVE-2023-44487)** — interleaved HEADERS + immediate RST_STREAM frames bypass `MAX_CONCURRENT_STREAMS` accounting → resource exhaustion. **DoS is in scope on almost no program — get explicit written authorization before sending a single burst.**

---

### Techniques, payloads and bypasses

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- **Authz matrix**: for every discovered method × every call type × every entry point, call (a) with no metadata, (b) expired token, (c) low-privileged user's token. A `grpcurl -plaintext target:50051 pkg.AdminService/DeleteUser` that succeeds with no metadata is direct BFLA.
- **Interceptors vs. call types**: if unary calls are denied but a server-streaming equivalent accepts the same token, report the streaming method as the unauthenticated surface; OWASP recommends a stream interceptor plus per-message checks.
- **Metadata spoofing**: `grpcurl -H 'x-user-id: 1' -H 'x-is-admin: true' ... pkg.v1.Svc.Method` — if the backend trusts gateway-populated identity headers, this is complete impersonation. Also try `-H 'cookie: session=<victim>'` and `-H 'authorization-bin: <base64>'`.
- **Token validation differential** (same JWT attacks as REST, carried in metadata): `alg:none`, expired `exp`, swapped `kid`, and another user's signed token. grpc itself does nothing with the token — validation is app-side.
- **mTLS is not authz**: `grpcurl -insecure` succeeding without a client cert means mTLS isn't enforced; conversely, a channel-authenticated workload can still be a confused deputy if per-method authorisation is missing. Distinguish `UNAUTHENTICATED` (credential rejected) from `PERMISSION_DENIED` (credential accepted, role insufficient).
- **Mass assignment in protobuf**: set fields the client "shouldn't" send — `role`, `owner_id`, `price`, `verified`. For update methods using `google.protobuf.FieldMas

### Phase 4 — Authentication / Trust-Boundary Bypass

```bash
# (a) Forged bearer / alg=none JWT in the authorization metadata
grpcurl -plaintext $TARGET:50051 \
  -H "authorization: Bearer eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4iLCJzdWIiOiIxIn0." \
  -d '{}' admin.AdminService/GetConfig

# (b) Backend-trusts-proxy headers: many gRPC backends authenticate at Envoy and
#     then trust identity injected as metadata. If the edge does not STRIP these,
#     spoofing them = full impersonation. Test every plausible name:
for H in "x-user-id: 1" "x-authenticated-user: admin" "x-tenant-id: 0" \
         "x-internal-request: true" "x-forwarded-for: 127.0.0.1" \
         "x-envoy-internal: true" "grpc-internal-encoding-request: true"; do
  echo "== $H =="
  grpcurl -plaintext $TARGET:50051 -H "$H" -d '{}' internal.InternalService/GetSecrets 2>&1 | head -3
done

# (c) Binary metadata smuggling — keys ending in -bin are base64-decoded by the
#     server; some auth middlewares only inspect text metadata, missing -bin keys.
grpcurl -plaintext $TARGET:50051 -H "auth-token-bin: $(printf admin|base64)" \
  -d '{}' admin.AdminService/GetConfig
```

The metadata-stripping bug (b) is the gRPC-specific crown jewel: confirm it by sending the spoofed header **directly to the backend port** AND, separately, **through the public proxy** — if the proxy forwards your `x-user-id` unchanged to the backend, it is exploitable for real users, not just on the bypassed port.

---

### Validation and proof

### Validation — false-positive discipline

gRPC's failure modes look like successes to a naive `grep`. Apply these gates before any submission.

1. **Status-code discrimination, not byte-counting.** A non-empty response can still be an error frame. Confirm the `grpc-status` trailer is `0` (OK). `Unauthenticated (16)` / `PermissionDenied (7)` mean auth WORKS — close the candidate. `Unimplemented (12)` means you have the wrong method. Re-run with `grpcurl -v` and read the trailers explicitly.

2. **Reflection / health endpoints are often intentionally public.** `grpc.reflection.*` and `grpc.health.v1.Health` being reachable is, by itself, **info disclosure (Low/Medium at most)** — many vendors ship reflection on by design. Do NOT report it as "missing auth" unless it leaks a non-public service catalog. The finding is the *sensitive* service you can then call without auth, proven in Phase 3.

3. **Distinguish "no auth" from "auth not required for THIS method."** Some methods (health, public catalog reads) are legitimately anonymous. Prove the bug by showing an authenticated-vs-unauthenticated **state delta**: the same RPC returns another user's/tenant's private data without credentials, or a mutating admin RPC executes (re-read the changed state to confirm side-effect).

4. **Proxy-vs-backend reachability.** A bug reachable only by hitting an internal `:50051` you found via SSRF/port-scan is real but its severity depends on reachability. State explicitly how an external attacker reaches it (exposed port, SSRF egress, proxy passthrough). For metadata-spoofing, prove the PUBLIC

### C. Validation / proof bar — how to confirm and avoid false positives

- Reflection enabled is an **enabler**, not a vulnerability. Report a callable sensitive method, metadata trust bypass, or leaked internal service — not "reflection is on" by itself (WSTG and OWASP agree).
- For each authz claim, show the exact method path, call type, entry point, and metadata used, plus a successful response containing another user's or admin-only data. An `UNAUTHENTICATED` error from a method you had no right to call is not a finding.
- Confirm gateway-vs-native differences on the **same method with the same credentials**; a format-only difference is expected. Verify the route/upstream before calling it a bypass (WSTG / Envoy issue caveat).
- For metadata spoofing, prove the header reached the backend and changed authorization — not merely that it was accepted by the proxy. Compare with a control request where the header is absent.
- For `DiscardUnknown` findings, demonstrate that a security-relevant field actually disappeared and the request still succeeded with a `200`; a missing *cosmetic* field is not a vulnerability.
- For CORS on gRPC-Web, show a credentialed cross-origin call from a browser (preflight + actual request) producing sensitive data — header reflection alone is informational per the CORS skill's bar.
- Treat DoS/resource tests as authorized-only: use a single bounded oversized message or short stream, capture latency/error behavior, and stop. Never run sustained stream floods on a live program.
- For stream-authz claims, keep the stream open past the point where th

### Validation — false-positive discipline

gRPC's failure modes look like successes to a naive `grep`. Apply these gates before any submission.

1. **Status-code discrimination, not byte-counting.** A non-empty response can still be an error frame. Confirm the `grpc-status` trailer is `0` (OK). `Unauthenticated (16)` / `PermissionDenied (7)` mean auth WORKS — close the candidate. `Unimplemented (12)` means you have the wrong method. Re-run with `grpcurl -v` and read the trailers explicitly.

2. **Reflection / health endpoints are often intentionally public.** `grpc.reflection.*` and `grpc.health.v1.Health` being reachable is, by itself, **info disclosure (Low/Medium at most)** — many vendors ship reflection on by design. Do NOT report it as "missing auth" unless it leaks a non-public service catalog. The finding is the *sensitive* service you can then call without auth, proven in Phase 3.

3. **Distinguish "no auth" from "auth not required for THIS method."** Some methods (health, public catalog reads) are legitimately anonymous. Prove the bug by showing an authenticated-vs-unauthenticated **state delta**: the same RPC returns another user's/tenant's private data without credentials, or a mutating admin RPC executes (re-read the changed state to confirm side-effect).

4. **Proxy-vs-backend reachability.** A bug reachable only by hitting an internal `:50051` you found via SSRF/port-scan is real but its severity depends on reachability. State explicitly how an external attacker reaches it (exposed port, SSRF egress, proxy passthrough). For metadata-spoofing, prove the PUBLIC

### Escalation and related chains

### Chain Table

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

### Chain Table

| gRPC finding | Chain to | Impact |
|--------------|----------|--------|
| Reflection enabled | Enumerate all internal service methods + messages | Full API catalog disclosure (enabler) |
| Admin method, no auth | Call privileged RPCs (`DeleteUser`, `GetConfig`) | Data manipulation / system access — Critical |
| Proxy forwards `x-user-id`/`x-tenant-id` unstripped | Spoof identity metadata → cross-tenant impersonation | Tenant isolation bypass — Critical |
| IDOR via enumerable id field | Iterate `user_id` over `GetUser` | Mass PII exfil — High |
| grpc-gateway / gRPC-Web route re-exposes internal RPC | Hit transcoded REST/JSON path unauth | Externally-reachable authz bypass — High/Critical |
| Plaintext h2c on internal port | MITM / sniff metadata (bearer tokens) | Credential capture — High |
| `.proto` leak (repo/swagger) | `-protoset` to drive reflection-off target | Unlocks Phases 3–4 — Low alone, High as enabler |

Related skills: **hunt-idor** (id enumeration logic), **hunt-api-misconfig** (JWT alg=none / mass-assignment in request messages), **hunt-auth-bypass** (edge-vs-backend trust boundary), **hunt-tls-network** (h2c/plaintext + ALPN), **cloud-iam-deep** (if a called RPC returns cloud creds).

---

### Tools and wordlists

### Tools

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

## Source skills merged into this topic

- `hunting` — `grpc`
- `cbh` — `hunt-grpc`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `references/upstream-assets/` — 1 companion files (payload/technique references, scripts, validators and schemas) from the contributing skills
- `../../upstream/` — complete unmodified archives of all five source repositories
- `bbhunt-methodology` — orchestrator, state machine and class router
