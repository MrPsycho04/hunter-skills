---
name: bbhunt-k8s
description: "Unified methodology for k8s.. Unified from 2 upstream skills (cbh, hunting). For authorized security testing only."
agent_created: true
---

# K8S — unified methodology

> **Unified skill.** Built from 2 upstream skills across cbh, hunting. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### A. Discovery checklist — concrete fingerprints, endpoints, headers, CVEs to look for

- **CVE-2025-1974 "IngressNightmare" (CVSS 9.8) — the headline 2025 cluster-takeover path.** Unauthenticated RCE in the **ingress-nginx admission controller** (typically `:8443`, cluster-internal but sometimes exposed on the public internet). An attacker sends a crafted `AdmissionReview` directly to the webhook; the controller builds an NGINX config from the Ingress object, validates it by invoking `nginx`, and the injected directive executes code in the controller pod — whose service account is powerful enough to read Secrets cluster-wide. Wiz found **~43% of cloud environments** vulnerable and **6,500+ publicly exposed admission controllers**. Fixed in **v1.11.5 / v1.12.1**; related CVE-2025-1097 / 1098 / 24513 / 24514.
- **Exact exploit-shape fingerprints:** `POST /` with `Content-Type: application/json` and an `AdmissionReview` whose `request.object.metadata.annotations` contains `nginx.ingress.kubernetes.io/auth-url` (or `auth-tls-match-cn` per Nuclei) with a `#;}}}` + newline + directive injection such as `load_module`, `ssl_engine`, or a `server { location ... }` block. Vulnerable responses contain `AdmissionReview`, `directive is not allowed here`, and `load_module`. Recon: `kubectl get pods --all-namespaces --selector app.kubernetes.io/name=ingress-nginx`, then check the controller image tag (vulnerable: 1.11.x < 1.11.5, 1.12.0, and all older lines). Shodan: `ssl:"ingress-nginx" port:8443`.
- **Ingress NGINX is now EOL — permanent exposure.** Kubernetes' Steering/Security Resp

### Signals and surfaces

### Crown Jewel Targets

K8s API anonymous cluster-admin = full cluster control. docker.sock + RCE = host root. A single privileged-pod create or a kubelet `/run` shell pivots one finding to total compromise.

**Highest-value findings:**
- **K8s API anonymous cluster-admin** — `system:anonymous`/`system:unauthenticated` bound to a powerful role (classic misconfig: `system:anonymous` in a `ClusterRoleBinding` to `cluster-admin`) → full `kubectl`. Mere anonymous `200` is NOT this (see false-positive section).
- **Kubelet `10250` exec/run** — `/run` returns command output directly; `/exec` is a SPDY/WebSocket stream (see Phase 3). Either → RCE in any pod → steal that pod's SA token.
- **API-server-mediated kubelet RCE** — `/api/v1/nodes/<node>/proxy/run/...` reaches the kubelet *through* the API server using your (low-priv) token; if RBAC grants `nodes/proxy`, you get pod RCE without touching 10250 directly. Primary 2024-2026 vector.
- **etcd `2379` unauth** — every Secret (SA tokens, TLS keys, app creds) stored, often plaintext (unless `EncryptionConfiguration` is set) → full credential dump.
- **docker.sock exposure** — SSRF/LFI/RCE reaching `/var/run/docker.sock` → create `--privileged` container, bind-mount host `/` → host root.
- **Container escape via runc** — Leaky Vessels (CVE-2024-21626): `WORKDIR`/`process.cwd` pointing at a leaked `/proc/self/fd/<n>` host FD → break out of an attacker-controlled image/exec to host root.
- **SA token abuse** — auto-mounted token at `/var/run/secrets/kubernetes.io/serviceaccount/token`; check its real grants with SelfSubjectRulesRevie

### Techniques, payloads and bypasses

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- **IngressNightmare non-destructive probe (use `kube-review` to generate the AdmissionReview from an Ingress manifest):** send the JSON to `https://<controller>:8443/` with `dryRun: true`, an annotation payload of `nginx.ingress.kubernetes.io/auth-url: "http://example.com#;load_module test;\n"` or `auth-tls-match-cn: "x#;load_module /tmp/x.so;"`, and match on the `directive is not allowed here` / `load_module` response. Do not load a real shared object during authorized testing — the config-injection error proves the primitive; only escalate to code execution in a lab / owned cluster.
- **Cluster-side verification path:** if the admission controller is internal-only, the same flaw is reachable by any principal that can create an Ingress — the API server sends the AdmissionReview for you. Test with a low-priv token and a deliberately malformed annotation; then check whether the controller's SA can list Secrets (`SelfSubjectRulesReview` from that context if you achieve controlled code execution).
- **Version-based templates are leads, not proof.** ProjectDiscovery's two Nuclei templates distinguish an externally exposed vulnerable admission controller from an internal cluster with a vulnerable image tag. Run both: the external template proves reachability, the internal one proves version, and the report should state which you observed.
- **Kubelet `/run` before `/exec`:** `POST https://<node>:10250/run/<ns>/<pod>/<ctr> -d "cmd=id"` returns output directly; `/exec` is a SPDY/WebSocket stream (plain 

### Validation and proof

### OOB / Confirmation Gate (Read First)

K8s findings are RCE/credential-disclosure class. House rule: **prove state change or data read, never infer from a status code.**

- A `200` on `/api/v1/namespaces` does **not** mean cluster-admin. The API server returns `200` with an RBAC-filtered (often empty `items: []`) list to *any* principal that can reach `list namespaces` — anonymous read on a few resources is common and low-impact. Confirm real privilege with **SelfSubjectRulesReview / SelfSubjectAccessReview**, then by actually reading a Secret value.
- **10255 (read-only) vs 10250 (exec)** are constantly conflated. 10255 (HTTP, no auth) is info-disclosure only — it has `/pods`, `/stats`, `/metrics`, NO exec/run. 10250 (HTTPS) is where `/run` and `/exec` live. Do not report "kubelet RCE" off a 10255 hit.
- **Blind/outbound vectors need OOB.** If you exploit SSRF→IMDS→K8s, or a pod's egress, confirm the outbound hop with a Burp Collaborator / interactsh subdomain (e.g. `curl http://<token>.<collab>` from inside the pod via `/run`). A delayed response or an echoed URL is NOT proof.
- **Impact proof = the artifact.** For exec: the literal `id`/`hostname` output. For etcd/Secret: the decoded token bytes (redact in report). For docker.sock escape: the host file content (`/etc/hostname` of the node, distinct from the container's).
- Use a **dedicated test namespace / test pod** when you have create rights; never exec into production workloads to "prove" RCE — list the pod and exec a read-only `id` in a pod you spun up if policy allows, or limit to a single non-destructive `id` 

### Validation Checklist

- [ ] **API anon:** SelfSubjectRulesReview shows privileged verbs AND a real Secret value was read (redacted).
- [ ] **Kubelet:** literal `id`/`hostname` output returned from 10250 `/run`, or a completed `/exec` stream — not a bare 302.
- [ ] **nodes/proxy RCE:** command output returned through `/api/v1/nodes/<node>/proxy/run/...` with your token.
- [ ] **etcd:** decoded Secret bytes shown (proves unencrypted + readable), not just a key listing.
- [ ] **docker.sock / escape:** the NODE's host file content retrieved (distinct from container), or runc-escape PoC output.
- [ ] **SA token:** `aud`/`exp` decoded and shown valid; impact bounded to its real RBAC.
- [ ] **OOB:** any outbound/SSRF hop confirmed via Collaborator/interactsh subdomain.

**Severity:**
- API anon→secret read, kubelet/nodes-proxy RCE, etcd dump, docker.sock/runc escape, CVE-2018-1002105: **Critical**
- Dashboard token-less data access, exposed Tiller: **High**
- Read-only kubelet 10255, anon `/version`/`/pods` info disclosure: **Medium**

---

### C. Validation / proof bar — how to confirm and avoid false positives

- **IngressNightmare proof tiers:** (1) external — the admission controller returns the NGINX config-validation error containing your injected directive; (2) internal — the image tag is in a vulnerable range *and* you have a reachable admission path; (3) full — command output or Secret contents from the controller pod. Report which tier you reached; do not call (1)+(2) "cluster compromise" without (3) or an equivalent demonstration.
- **EOL is itself a finding, not a CVE PoC.** "Ingress NGINX deployed after March 2026 with no upstream fixes" is a High-severity hygiene/risk finding; pair it with a version-specific CVE demonstration (1974 / 3288) for Critical. Do not claim a CVE from the EOL date alone.
- **Port confusion killers (retain from baseline):** 10255 has no `/run` or `/exec`; a 200 on `/version` or an RBAC-filtered empty `items: []` is not cluster-admin; a bare 200 on the Dashboard HTML shell is just the login page; etcd peer port 2380 or a TLS handshake error is not unauth client access. Require `SelfSubjectRulesReview` + an actual Secret value, or literal command output.
- **Do not exec into production workloads to "prove" RCE.** Use a dedicated test namespace/pod you created, or a single non-destructive `id`; document the scope explicitly. For IngressNightmare, prefer the config-validation error over loading a real shared object.
- **Post-exploitation containment:** if the controller SA is cluster-wide, a confirmed RCE implies exposure of all Secrets — treat as Critical and recommend immed

### Validation Checklist

- [ ] **API anon:** SelfSubjectRulesReview shows privileged verbs AND a real Secret value was read (redacted).
- [ ] **Kubelet:** literal `id`/`hostname` output returned from 10250 `/run`, or a completed `/exec` stream — not a bare 302.
- [ ] **nodes/proxy RCE:** command output returned through `/api/v1/nodes/<node>/proxy/run/...` with your token.
- [ ] **etcd:** decoded Secret bytes shown (proves unencrypted + readable), not just a key listing.
- [ ] **docker.sock / escape:** the NODE's host file content retrieved (distinct from container), or runc-escape PoC output.
- [ ] **SA token:** `aud`/`exp` decoded and shown valid; impact bounded to its real RBAC.
- [ ] **OOB:** any outbound/SSRF hop confirmed via Collaborator/interactsh subdomain.

**Severity:**
- API anon→secret read, kubelet/nodes-proxy RCE, etcd dump, docker.sock/runc escape, CVE-2018-1002105: **Critical**
- Dashboard token-less data access, exposed Tiller: **High**
- Read-only kubelet 10255, anon `/version`/`/pods` info disclosure: **Medium**

### Escalation and related chains

### Chain Table

| K8s finding | Chain to | Impact |
|-------------|----------|--------|
| API anon **with confirmed secret read** | extract SA/TLS/app creds | Full cluster compromise |
| `nodes/proxy` token | API-server-mediated `/run` → pod RCE → SA token | Node-wide RCE → escalation |
| Kubelet 10250 `/run` | exec in any pod → steal SA token → API | Cluster privilege escalation |
| etcd 2379 unauth | dump all Secrets (if unencrypted) → replay token | Full credential dump |
| docker.sock | privileged container + host bind-mount | Host root |
| CVE-2024-21626 (runc) | malicious image/exec → host FD escape | Container → host root |
| EphemeralContainers / pods create | privileged/hostPID debug container | Pod → node escape |
| Projected SA token (aud matches) | API access scoped to its real RBAC | Depends on RBAC — verify first |
| Tiller 44134 exposed | helm install as Tiller SA | Cluster-admin if Tiller is privileged |

---

## Source skills merged into this topic

- `hunting` — `k8s`
- `cbh` — `hunt-k8s`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `../../upstream/` — complete unmodified archives of all five source repositories
- `bbhunt-methodology` — orchestrator, state machine and class router
