---
name: bbhunt-cicd
description: "Hunt workflow injection, self-hosted runner poisoning, OIDC trust abuse and secret exfiltration. Unified from 2 upstream skills (cbh, hunting). For authorized security testing only."
agent_created: true
---

# CI/CD pipeline attack hunting — unified methodology

> **Unified skill.** Built from 2 upstream skills across cbh, hunting. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### A. Discovery checklist — concrete fingerprints, endpoints, headers, CVEs, misconfigs to look for

- **GitHub Actions cache poisoning is now a first-class attack class (2024-2026), not a curiosity.** Adnan Khan's original research, Cacheract PoC, CodeQL queries `actions/cache-poisoning/poisonable-step` and `actions/cache-poisoning/direct-cache` (severity 7.5), and CVE-2024-50338-adjacent toolkit issues. The structural fact: branches are the cache security boundary; a feature branch can read parent/default-branch caches; a low-trust trigger (`pull_request_target`, `issue_comment`, `workflow_run`) that can *write* the default-branch cache can detonate code in a later privileged/release job. GitHub hardened this in Nov 2024 by blocking cache writes after job conclusion — the current technique performs the whole poisoning **in-build**.
- **Fingerprint:** `grep -rn "actions/cache\|cache:" .github/workflows/`; compare cache keys used by PR jobs vs release/publish jobs; look for `setup-node with cache: npm` in a job that also checks out PR head; `--only-verified` secret scans.
- **Shai-Hulud worm family (2025-2026) — install-time execution and CI persistence:**
  - Sept 2025 original: npm preinstall/postinstall scripts, TruffleHog credential sweep, exfil to public GitHub repos named `Shai-Hulud`, new workflows exfiltrating repo secrets to `webhook.site`, private→public repo migration with `-migration` suffix, self-propagation on any found npm token. Assessed downstream of the s1ngularity/Nx compromise.
  - Nov 2025 **Shai-Hulud 2.0**: 796 packages / >20M weekly downloads; paylo

### Signals and surfaces

### Crown Jewel Targets

Jenkins `/script` console reachable = immediate RCE. A GitHub Actions `pull_request_target` (or `workflow_run`) workflow that checks out the **PR head ref** and references untrusted `${{ github.event.* }}` in a shell `run:` = "Pwnrequest" → secret exfil from a fork PR with zero approval.

**Highest-value findings:**
- **Jenkins Script Console** — Groovy execution → full RCE → dump the credential store
- **Jenkins CLI file read (CVE-2024-23897)** — pre-auth `@/etc/passwd` arg expansion → read `secret.key`/`credentials.xml` → forge admin → RCE
- **GitHub Actions `pull_request_target` injection (Pwnrequest)** — fork PR controls `${{ }}` inside a privileged shell step → exfil `GITHUB_TOKEN` (often `contents:write`) and org secrets
- **Self-hosted runner poisoning** — non-ephemeral runner on a public repo executes a fork PR's build → attacker code runs on the runner host → persistence + secret theft
- **OIDC trust-policy abuse** — over-broad `sub` claim wildcard in an AWS IAM role trust policy → any workflow in the org assumes a privileged cloud role
- **Terraform state leakage** — `*.tfstate` in public S3/GCS/Blob → plaintext infra creds, DB passwords, private keys
- **Runner token / artifact / log leakage** — register attacker runner, or harvest secrets printed before `::add-mask::`

---

### Techniques, payloads and bypasses

### B. Techniques & bypasses — specific actionable techniques/payload shapes

```bash
# Cache poisoning primitive (extend the existing Actions section)
# 1. In a low-trust job that can run PR code and write cache:
ACTIONS_CACHE_URL=...   # from job environment
ACTIONS_RUNTIME_TOKEN=...
# 2. Predict the key the privileged job restores:
#    node-modules-${{ hashFiles('package-lock.json') }}  — compute the hash yourself
# 3. Poisoned tarball contains extra files; tar extracts and overwrites by default:
#    node_modules/.bin/*, Makefile, package.json, _actions/.../index.js (post-step actions)
# 4. Later release job restores cache -> attacker files execute with registry publish rights.
# Cacheract automates steps 1-3 (entry replacement via actions:write, key prediction
#    for setup-node, inactive-cache static analysis of all workflows).

# Static triage before opening any PR
pip install zizmor && zizmor .github/workflows/
grep -rn "pull_request_target\|workflow_run\|issue_comment\|self-hosted" .github/workflows/
grep -rn "cache:" .github/workflows/                 # compare PR-job vs release-job keys
gh api "repos/ORG/REPO/actions/cache/caches" --jq '.caches[] | [.key,.scope] | @tsv'
# Self-hosted runner poisoning tell (Sysdig/Shai-Hulud):
#   runner process from ~/.dev-env, name SHA1HULUD, workflows with unsanitized ${{ }} in run:

# Worm IoCs to grep in installed deps / CI logs (Shai-Hulud family)
grep -rnE "setup_bun\.js|bun_environment\.js|math_init\.js|Math_Symbol\.js|setup\.mjs" node_modules/ .github/
grep -rn "bypass_2fa" ~/.npmrc .npmrc 2>/dev/null    # CHAINDROP pro

### Validation and proof

### Validation Discipline (per finding, before you report)

- **Jenkins console:** the `scriptText` POST returns your `id` output (`uid=…(jenkins)`). A returned login/SSO/Crowd page = **not** anon access. Screenshot the request+response.
- **CVE-2024-23897:** response contains real `/etc/passwd` content; confirm version is in range. Patched instances return an error with no leaked line.
- **Actions injection:** confirm the data flow into a sink first (FP section). Blind step → **Collaborator callback with the runner's source IP** is mandatory. Token exfil via `printenv`/`/proc/self/environ` decoded at your endpoint — never `cat $GITHUB_TOKEN`.
- **OIDC abuse:** `aws sts get-caller-identity` from your controlled workflow returns the privileged role ARN — not just a permissive-looking trust policy.
- **Terraform state:** `jq` extraction yields ≥1 *live* secret, then a read-only auth proves it. ID/ARN-only state = no finding.
- **Runner token / image / logs:** demonstrate the secret authenticates (trufflehog `--only-verified`, or a real API call) — possession of a string is not impact.

### C. Validation / proof bar — how to confirm and avoid false positives

- **Keep every existing gate in the "It-Didn't-Happen-Without-Proof" section** and add:
- **Cache poisoning:** a cache key collision is not a finding until you show (a) a low-trust trigger can *write* that key after GitHub's Nov-2024 timing change (in-build poisoning), and (b) a privileged job restores it and executes attacker-controlled content. OOB callback from the privileged job is mandatory; "the PR passed CI" proves nothing. CodeQL's high-precision queries encode the same rule — prefer them over eyeballing.
- **Compromised action (CVE-2025-30066 class):** check whether the repo pins actions to full commit SHAs vs mutable tags; pinning to SHA after the fact is the fix. A workflow merely *using* `tj-actions/changed-files` is not proof of exposure — check the run timeframe (Mar 14-15 2025) and whether logs/artifacts are public, then rotate.
- **Worm claims:** a malicious package name in a vulnerability feed is not proof of execution. Require `preinstall`/`postinstall` in `package.json`, payload file hashes, and a callback or filesystem artifact. Elastic/JFrog publish SHA-256s and EQL detections — reuse them. Presence of `bun` processing `Math_Symbol.js`/`math_init.js` is a high-fidelity endpoint signal.
- **Pwn request FP discipline:** `pull_request_target` without untrusted data reaching an execution sink remains non-exploitable (existing FP list). Confirm `actions/checkout` ref + a reachable sink first, then use `printenv`/`/proc/self/environ` + Collaborator — never `cat $GITHUB_TOKEN`.
- **OIDC 

### Escalation and related chains

### Chain Table

| CI/CD finding | Chain to | Impact |
|---|---|---|
| Jenkins anon script console | Dump credential store → cloud/DB creds → lateral | Critical |
| Jenkins CLI file read (CVE-2024-23897) | Read `secret.key`+`credentials.xml` → forge admin → RCE | Critical |
| Actions `${{ }}` injection (Pwnrequest) | `printenv GITHUB_TOKEN`/secrets → push to protected branch | Critical |
| Self-hosted runner poisoning | Code-exec on runner host → IMDS creds → persistence | Critical |
| OIDC `sub` wildcard | `AssumeRole` privileged cloud role from any org workflow | Critical |
| Terraform state w/ live creds | Infra/DB/API credential use | Critical |
| GitLab runner registration | Register runner → capture pipeline secrets | High/Critical |
| Image/log/artifact secret | Direct credential use | High |

---

## Source skills merged into this topic

- `hunting` — `cicd`
- `cbh` — `hunt-cicd`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `bbhunt-methodology` — orchestrator, state machine and class router
