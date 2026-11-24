---
name: js-analyse
description: Analyze collected JavaScript from a web target during authorized bug bounty or security testing to extract routes, parameters, API endpoints, feature flags, secrets, libraries, framework details, and a feature map. Use this skill whenever the user has JS files or bundles and wants to find hidden endpoints, admin routes, old API versions, outdated or vulnerable libraries, hardcoded secrets or API keys, or understand what the app does from its frontend code. Trigger on phrases like "analyse the JS", "find endpoints in this bundle", "look for secrets", "what libraries does it use", or "map the features", even if the user does not say "analyse". Expects input from js-collect.
---

# JS Analyse

Goal: turn collected JavaScript into a prioritized list of testing leads: endpoints, parameters, hidden features, weak dependencies, and exposed secrets.

> Authorized testing only. Report secrets, don't use them. Never use a found credential or key against any system beyond what the program's rules explicitly allow.

## Input

A `js-collect-output/<target>/` folder (or any set of JS files). Prefer `processed/` and recovered sourcemap sources. Also use `flows_endpoints.txt` and `summary.md` from `js-collect` as a starting point, and join `gadgets.md` from `js-sinks` to the routes and features you find.

## Workflow

### 1. Params and route analysis

Extract every client-side route and parameter name:
- Router definitions (React Router, Vue Router, Angular routes, Next.js pages, Express-style path strings)
- Query parameters and form field names the code reads or sends
- **Admin and privileged routes:** paths containing `admin`, `internal`, `debug`, `staff`, `manage`, `superuser`, role checks such as `isAdmin`, `role ===`, `hasPermission`
- **Feature flags:** flag names, default values, how they are loaded (config endpoint, inline object, third-party flag service), and whether flags are enforced client-side only
- **Interesting comments:** TODO/FIXME/HACK, developer names, internal hostnames, ticket IDs, commented-out code, disabled endpoints

For each route, note whether it needs authentication and which role the code expects.

### 2. API analysis

- Extract every `fetch`, `axios`, `XMLHttpRequest`, GraphQL operation, and WebSocket message.
- Record: method, URL or path template, parameters, headers, auth mechanism, request/response shape.
- **Old versions:** look for `/v1/`, `/v2/`, `/legacy/`, `/beta/` and compare with the version the app currently uses. Older versions often lack newer authorization checks.
- **Group all calls by functionality** (auth, profile, payments, uploads, admin, search, messaging, etc.), so related endpoints can be tested together for authorization and logic issues.
- Note base URLs, third-party APIs, and any internal or staging hosts.

### 3. Library analysis

- Identify every library and version (from banners, `package.json` fragments in sourcemaps, version constants, known file signatures).
- **Outdated:** compare against the latest release.
- **Security:** check each version against known-vulnerability sources (OSV, GitHub advisories, retire.js database, npm audit). Record the CVE/advisory ID and whether the vulnerable code path is actually reachable in this app.
- An old version is a lead, not a finding. Confirm exploitability before reporting.

### 4. Framework and tech analysis

Identify and record:
- Framework and version (React, Angular, Vue, Next.js, Nuxt, Svelte, jQuery, etc.)
- Bundler and build tooling (webpack, Vite, Rollup), and whether dev builds or sourcemaps are exposed in production
- State management, auth libraries (OAuth/OIDC clients, JWT handling), analytics, error-tracking, and payment SDKs
- Framework-specific risks: SSR data leaks (`__NEXT_DATA__`, `window.__INITIAL_STATE__`), exposed server actions, client-trusted authorization

### 5. Feature map

Combine the above into one map of what the app can do:

| Feature | Routes | API endpoints | Roles | Flags | Notes / test ideas |
|---------|--------|---------------|-------|-------|--------------------|

Highlight features that exist in code but aren't reachable from the UI. These are often the most valuable targets.

### 6. Secrets

Scan for exposed credentials and sensitive values using two methods, then compare:
- **Known-pattern regex:** cloud provider keys, API tokens (Stripe, Slack, GitHub, Google, Twilio, etc.), JWTs, private key blocks, database URLs, OAuth client secrets
- **High-entropy strings:** compute Shannon entropy on string literals and flag long, random-looking values the regexes missed

Triage each hit:
- Is it a secret or a public identifier? (Public client IDs, publishable keys, and analytics IDs are usually not findings.)
- What would it grant, according to the provider's documentation?
- Is it in current code or only in an old/historical version?

Verify validity only through methods the program allows (for example, a provider's documented non-destructive key-check endpoint), and stop there. Redact secrets in notes and reports.

## Output

Produce `analysis.md` with these sections:

1. **Summary**: target, files analyzed, tech stack, top 5 leads
2. **Routes and parameters**
3. **API inventory** (grouped by functionality, old versions flagged)
4. **Libraries** (name, version, latest, known issues)
5. **Feature map**
6. **Secrets** (redacted, with triage notes)
7. **Next steps**: ordered list of what to test manually, most promising first

For each lead, include the source file and line so you can find it again.
