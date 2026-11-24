---
name: bbhunt-supply-chain-attack-recon
description: "Hunt namespace squatting, dependency confusion, workflow injection and registry exposure. Unified from 2 upstream skills (cbh, hunting). For authorized security testing only."
agent_created: true
---

# Software supply-chain recon — unified methodology

> **Unified skill.** Built from 2 upstream skills across cbh, hunting. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### A. Discovery checklist — concrete fingerprints, endpoints, headers, CVEs, misconfigs to look for

- **2025-2026 threat-data baseline (use to prioritize recon effort, not as a finding by itself):** Safeguard's H1 2025 report tracked 847 confirmed supply-chain attacks (+34% YoY): npm 312, PyPI 198, Maven 89; **62% used typosquatting or dependency confusion**, **23% involved compromised maintainer accounts** (up from 14%). Detection time dropped to 4.2 days. npm malware detection caught 78% of typosquats within 24h; PyPI attacks grew 67% YoY with AI/ML mimic packages (`torch`, `transformers`, `langchain` variants) exfiltrating model weights and training data. Hugging Face is now a first-class squatting registry (1.1M models, hierarchical names).
- **"Slopsquatting" — new 2025 vector:** packages hallucinated by LLMs in generated code/tutorials. Recon should check whether target repos' AI-generated configs/docs reference non-existent package names, then check whether those names have been registered.
- **Full typosquat generation taxonomy to enumerate candidates (Andrew Nesbitt / Purdue TypoSmart):** omission (`reqests`), repetition (`rrequests`), transposition (`reqeusts`), adjacent-key replacement (`requezts`), addition at start/end (`arequests`), vowel swaps, **bitsquatting** (single-bit flips: `coogle`), **combosquatting** (`lodash-js`, `lodash-utils`), hierarchical/scope confusion (`@angular/…` lookalikes), and Unicode homoglyph substitutions. Typosquat attacks have accumulated >1.2 billion weekly downloads across campaigns; OpenSSF's malicious-packages repo and Datadog

### Signals and surfaces

### The supply-chain attack surface map

```
Target Org
├── Public GitHub Org → workflow files → secrets exfil opportunities
├── Internal package names in JS/Android bundles → dependency confusion
├── Docker images on public registries → secrets in layers, RCE on pull
├── SBOM / artifact metadata → exact dep versions for known-vuln chaining
├── npmrc / pip.conf in repos → internal registry URL disclosure
├── External package dependencies → typosquat name candidates
└── Build/release pipelines → injection if pull_request_target etc.
```

---

### Techniques, payloads and bypasses

### B. Techniques & bypasses — specific actionable techniques/payload shapes

```bash
# Candidate mapping: for each real dependency, generate and CHECK REGISTRATION (recon only — do not publish)
# Example with requests -> reqests, rrequests, reqeusts, requezts, arequests, requestsa, raquests, coogle...
for name in reqests rrequests reqeusts requezts arequests requestsa; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://pypi.org/pypi/$name/json")
  echo "$name $code"
done
for name in lodash-js lodash-utils lodash-core; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://registry.npmjs.org/$name")
  echo "$name $code"
done
# A registered lookalike with a recent publish date, no repo/homepage, and a postinstall script
# is the high-signal pattern. Fetch metadata and inspect scripts:
curl -s "https://registry.npmjs.org/<candidate>/latest" | jq '{name,version,scripts,maintainer:.maintainers[].name}'

# Internal package-name discovery (recon inputs to the existing Step 3/4)
grep -rhoE '"@?[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+"\s*:\s*"[0-9]' package.json package-lock.json yarn.lock pnpm-lock.yaml 2>/dev/null
grep -rniE 'registry|npmrc|pypi|index-url|artifactory|nexus|internal.*pkg' .npmrc pyproject.toml requirements*.txt setup.cfg .github/workflows/ 2>/dev/null

# Install-time payload fingerprints (Trail of Bits / Wiz / Elastic / JFrog)
grep -rnE 'preinstall|postinstall|setup_bun\.js|bun_environment\.js|setup\.mjs|math_init\.js' package.json */package.json
grep -rn 'curl.*webhook.site\|base64 -d.*\|TruffleHog\|trufflehog' package.json *.sh .github/workflows/ 2>/dev/nul

### Validation and proof

### C. Validation / proof bar — how to confirm and avoid false positives

- **A lookalike name alone is not a finding.** Confirm it (a) mirrors a real dependency the target actually uses, (b) is registered by an unrelated party, (c) contains an install-time script or suspicious network target. Nesbitt's dataset maps malicious packages to intended targets precisely because `reqeusts` is obvious but `beautifulsoup-numpy` or `payments-core` are ambiguous — record the mapping rationale.
- **Automated detections are noisy:** TyposSmart exists precisely because of high false-positive rates;bitsquatting/homoglyph variants need visual comparison. Triangulate registry metadata (publish date, maintainer, download count, repository link) before grading.
- **"Clean OSV/advisory lookup" is not proof** (OWASP AppSec EU 2025 checklist): OSV only knows reported issues. Pair registry checks with the target's actual lockfile and install behavior.
- **Maintainer compromise claims** require vendor-confirmed advisories (npm/GitHub blog, Microsoft/Unit42/Wiz) plus evidence the target consumed the malicious version during the exposure window. Do not infer compromise from a package name in a threat-feed alone.
- **Dependency-confusion confirmation** must show the package manager would resolve the public package over the private one (scope config, registry URL precedence, version comparison). When testing, use a benign canary package in an authorized lab — never a real payload.
- **Worm exposure:** presence of an affected package version = inventory item; execution requires `preinstall` evidence or

### Escalation and related chains

### 2. 3CX VoIP softphone supply chain (CVE-2023-29059, March 2023)

- **Flow:** DPRK-attributed Lazarus subgroup (UNC4736 / Labyrinth Chollima) trojanized the 3CX DesktopApp (Electron-based softphone) on both Windows and macOS. Initial entry was via a PREVIOUS supply-chain attack — an employee installed a backdoored copy of Trading Technologies' X_TRADER, the FIRST disclosed cascading supply-chain compromise (one supply-chain victim becomes another's vector).
- **Root cause:** Dev workstation compromise → access to 3CX source/build pipeline → malicious `ffmpeg.dll` and `d3dcompiler_47.dll` shipped in signed installer.
- **Impact:** ~600,000 organisations use 3CX; tens of thousands of trojanized clients downloaded. Lazarus selectively activated second-stage payloads against cryptocurrency and trading firms.
- **References:**
  - CrowdStrike: https://www.crowdstrike.com/en-us/blog/crowdstrike-detects-and-prevents-active-intrusion-campaign-targeting-3cxdesktopapp-customers/
  - SentinelOne: https://www.sentinelone.com/blog/smoothoperator-ongoing-campaign-trojanizes-3cx-software-in-software-supply-chain-attack/
  - Mandiant cascading attack analysis: https://cloud.google.com/blog/topics/threat-intelligence/3cx-software-supply-chain-compromise
  - 3CX post-mortem: https://www.3cx.com/blog/news/desktopapp-security-alert-update/
- **Recon takeaway:** Cascading supply chain is real — your target's vendors' vendors matter. When recon enumerates "what software does this org install on engineer laptops," each one is itself a supply-chain target. Electron apps (signed JS bundles) are 

### Related Skills & Chains

- **`rce`** — Dependency confusion lands as RCE on whatever runner installs the package; CI runners are the highest-value target. Chain primitive: internal package name leaked in public JS bundle / SBOM / Docker image → publish malicious package to public npm/PyPI under same name with higher version → next `npm install` / `pip install` on CI runner executes attacker code in `preinstall` hook → `rce` post-foothold (env-var extraction yields AWS keys, GitHub PATs, Slack tokens) → CI-plane takeover.
- **`cloud-iam-deep`** — CI runners have IAM credentials; supply-chain RCE there is a credential-exfil bonanza. Chain primitive: malicious package executes on GitHub Actions runner → reads `$AWS_ACCESS_KEY_ID` / `$GITHUB_TOKEN` from env → `cloud-iam-deep` enumeration → IAM-privilege-escalation chain → production cloud-plane access.
- **`offensive-osint`** — Recon discipline overlaps heavily; SBOMs, JS bundles, GitHub org enumeration, Docker registry tags all live in both. Chain primitive: `offensive-osint` GitHub-org recon yields internal package names referenced in CI workflows → `supply-chain-attack-recon` cross-references these against public npm/PyPI for typosquat/confusion candidates.
- **`cloud-misconfig`** — Container registries (Docker Hub, GHCR, ECR public) frequently expose private images by accident. Chain primitive: SBOM mining reveals `internal-tools-v2:latest` referenced → check Docker Hub for accidentally-public mirror → `cloud-misconfig` registry enum → pull image → extract secrets baked into layers.
- **`triage-validation`** + **`redtea

### Related Skills & Chains

- **`hunt-rce`** — Dependency confusion lands as RCE on whatever runner installs the package; CI runners are the highest-value target. Chain primitive: internal package name leaked in public JS bundle / SBOM / Docker image → publish malicious package to public npm/PyPI under same name with higher version → next `npm install` / `pip install` on CI runner executes attacker code in `preinstall` hook → `hunt-rce` post-foothold (env-var extraction yields AWS keys, GitHub PATs, Slack tokens) → CI-plane takeover.
- **`cloud-iam-deep`** — CI runners have IAM credentials; supply-chain RCE there is a credential-exfil bonanza. Chain primitive: malicious package executes on GitHub Actions runner → reads `$AWS_ACCESS_KEY_ID` / `$GITHUB_TOKEN` from env → `cloud-iam-deep` enumeration → IAM-privilege-escalation chain → production cloud-plane access.
- **`offensive-osint`** — Recon discipline overlaps heavily; SBOMs, JS bundles, GitHub org enumeration, Docker registry tags all live in both. Chain primitive: `offensive-osint` GitHub-org recon yields internal package names referenced in CI workflows → `supply-chain-attack-recon` cross-references these against public npm/PyPI for typosquat/confusion candidates.
- **`hunt-cloud-misconfig`** — Container registries (Docker Hub, GHCR, ECR public) frequently expose private images by accident. Chain primitive: SBOM mining reveals `internal-tools-v2:latest` referenced → check Docker Hub for accidentally-public mirror → `hunt-cloud-misconfig` registry enum → pull image → extract secrets baked into layers.
- **`triage-valid

### Tools and wordlists

### Tooling

| Tool | Purpose |
|---|---|
| **`trufflehog`** | Filesystem/git/docker secret scan |
| **`gitleaks`** | Git history secret scan |
| **`dependency-confusion`** (Confused) | npm scope/PyPI checks |
| **`packj`** | Package risk score (PyPI/npm/RubyGems) |
| **`Lift / Snyk vuln-db`** | Known CVE lookup by package version |
| **`actionlint`** | GitHub Actions static analyzer |
| **`zizmor`** | GitHub Actions injection & security antipattern detection |
| **`OSSGadget`** | Microsoft's package metadata toolkit |
| **`semgrep`** + supply-chain rules | Workflow injection detection |
| **`osv-scanner`** | Match versions to known vulns |

---

## Source skills merged into this topic

- `hunting` — `supply-chain-attack-recon`
- `cbh` — `supply-chain-attack-recon`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `bbhunt-methodology` — orchestrator, state machine and class router
