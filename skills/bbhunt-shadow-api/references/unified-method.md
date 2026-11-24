# Unified upstream methodology

Collected from every contributing repository skill. Deduplicated by content hash; full originals are preserved in `references/upstream-*.md`.

## Discovery and hunting method

### A. Discovery checklist — concrete artifacts, endpoints, patterns, tools to look for

- **Classify before testing (OWASP API9:2023):** shadow = active but undocumented; zombie = deprecated but still reachable; orphan = no accountable owner; rogue = created outside approved architecture. Categories overlap — a route can be both shadow and orphan. CWE-1059 is the reference weakness.
- **Path-based versioning sweep:** `for v in v1 v2 v3 v4 beta alpha internal legacy old 2022-01-01 2023-01-01 2024-01-01; do curl -s -o /dev/null -w "%{http_code} /api/$v/" ...; done`. Also date-style versions (`/api/2023-01-01/`) and `/beta`, `/internal`, `/legacy` prefixes.
- **Header/subdomain versioning:** `X-API-Version: 1`, `Accept: application/vnd.company.v1+json`; subdomains `api-v1`, `api-v2`, `apiv1`, `apiv2`, `legacy-api`, `old-api`, `internal-api`, `staging-api`. Anything but 404/connection-refused (200, 401, 403) means the version is live.
- **Every reachable spec, not just the linked one:** `openapi.json`, `swagger.json`, `v1/swagger.json`, `v2/swagger.json`, `v3/api-docs`, `api-docs.json`, `swagger/v1/swagger.json`, `.well-known/openapi.json`. Diff `info.version` fields — one version implies others exist.
- **Wayback Machine (key shadow-API source):** CDX queries for `*swagger*` and `*openapi*` with `collapse=urlkey`; an old spec often remains indexed after the live link is removed.
- **Five signal sources (Safeguard/OWASP):** gateway & load-balancer logs (methods/paths receiving real traffic), route tables in source (Express routers, Flask blueprints, Spring `@RequestMapping`), stale/exposed docs, client apps (web bundles + mobile binaries), DNS/cloud inventory (forgotten `api-v1.`, `staging-api.` hosts). No single source is complete.
- **30-day log diff:** list distinct method+path pairs, normalize IDs to placeholders, and flag anything not matching a documented operation; a spec-vs-traffic gap of ~40% is common in industry research.
- **Mobile-vs-web drift:** APK/IPA hardcoded endpoints that look older than the current web app are prime zombie candidates; feed `apk-redteam-pipeline`/`ios-redteam-pipeline` output here.
- **Shadow parameters:** even documented endpoints can have undocumented parameters — Salt Security research found 102 params on an endpoint whose spec listed 3. Use Param Miner/ffuf/`=1` preservation trick.
- **Risk scoring for triage:** internet-facing vs internal, sensitive data (PII/PCI/PHI), traffic volume from logs, and whether an owner exists.

## Techniques, payloads and bypasses

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- **Spec-to-spec diff:** `jq -r '.paths | keys[]' v1-swagger.json | sort > /tmp/v1_paths.txt`; same for v2; `comm -23 /tmp/v1_paths.txt /tmp/v2_paths.txt` = in v1 only. Confirm each against the v1 base URL; a non-404 route documented only in the old spec is a zombie candidate.
- **Behavioral diff, not shape diff:** send payloads that behave differently under old vs new logic — weaker auth, missing rate limit, lax validation, extra response fields (PII/internal IDs). Cosmetic field renames are Informational only.
- **The OWASP canonical scenario:** rate limiting implemented in a separate component in front of `api.socialnetwork...` but *not* on `beta.api.socialnetwork...` — brute-force a 6-digit reset token against the beta host. Also: old versions connected to the same production database expose admin functions or unpatched CVEs.
- **Alias check before claiming regression:** confirm the old endpoint is not simply a proxy/alias to the current implementation; send a discriminator payload that would actually behave differently under the two code paths.
- **Deprecation-message false positive:** a `200` serving only "this API version is deprecated, use v2" is not a finding — confirm the underlying operation still executes.
- **Client-app extraction:** browse with highest-privilege account, capture XHR/fetch calls, compare with the spec; for SPAs extract path-shaped strings from the bundle, including admin/internal/feature-flagged routes the UI never calls.
- **Use Nuclei/ffuf/feroxbuster** with API wordlists (`api-endpoints-res.txt`) to enumerate remaining paths, then test each for auth bypass, BOLA, injection. Passive DAST reconstruction of specs from live traffic catches shadow routes no client links to anymore.
- **Parameter-definition discrepancies:** types declared loosely (`String` instead of `UUID`/`DateTime`) let malicious values through schema-based WAF validation — test with typed-but-invalid inputs.
- **Retirement verification:** last_seen traffic alone does not prove retirement; check route/DNS removal, runtime resource shutdown, credential revocation, spec/catalog update, and consumer migration.

## Validation and proof

### C. Validation / proof bar — how to confirm and avoid false positives

- **The finding is the security-relevant regression**, not the version string. Severity scale: auth/rate-limit/validation regression High; extra PII/internal fields Medium–High; behaviorally identical Informational.
- Prove the endpoint is genuinely unmanaged: no inventory entry, no owner, no gateway/WAF coverage — a documented-but-untested internal route is not automatically shadow.
- Confirm reachability from the attacker's network position and demonstrate one concrete impact (read cross-tenant data, bypass rate limit, reach admin function). Stop at PoC; do not dump production datasets.
- Check that a different status code alone is not evidence — compare bodies and successful operations with controlled accounts (admin baseline vs low-privilege vs anonymous).
- Avoid claiming "zombie" just because traffic is low or a spec says deprecated; require confirmed deprecation intent plus ongoing reachability/callability.
- Keep the internal inventory itself sensitive — it maps hosts, environments, owners, and data classification; separate public docs from the internal register.

- **Runtime-signal alerts worth mining (NHI Mgmt 2026):** traffic to routes/hosts not in the inventory, calls to deprecated versions after sunset, enumeration of `/v1`/`/beta`/`/internal`, new DNS records or certificates for API hostnames, and docs endpoints answering from outside.
- **Spec accuracy metric:** share of APIs whose live routes match their specification — a low value is the attacker's advantage; a high value is the goal of contract testing.
- **CI/CD reflection of this play:** require endpoint registration before deployment, generate OpenAPI automatically in the build, and block on schema drift — these are the controls that remove the shadow surface you are exploiting.
- **Third-party data-flow blind spot:** OWASP API9's second blind spot is undocumented sensitive data flows to partners — a spec diff will not find these; look at OAuth consent scopes, webhook destinations, and outbound integrations discovered in code/config.
- **Header-based versioning trap:** changing `Accept`/`X-API-Version` sometimes selects a *different backend implementation* rather than just a response shape — repeat the full auth and validation test matrix under each version header.
- **Date-versioned APIs:** `/api/2023-01-01/` style versioning often leaves older date versions alive; enumerate adjacent dates around any version you find.
- **Gateway log normalization:** collapse IDs to placeholders before diffing so one route with many object IDs is not counted as thousands of distinct endpoints.
- **Do not equate "no spec" with "shadow":** a host may be documented in an internal register you cannot see; report reachability plus missing public documentation and the observed security-control gap, not an assertion about the org's inventory.
- **Combine code + traffic + DNS + client:** each source catches a different gap (code = debug/admin handlers, traffic = undocumented live paths, DNS = forgotten beta hosts, client = internal calls); the strongest finding is corroborated by two or more.

- **Host-based vs path-based discovery are complementary:** a forgotten `api-v1.example.com` host can serve the same routes as `/api/v1` on the main host; enumerate both and diff against the single documented spec.
- **Retirement verification is part of the test:** confirm a deprecated route's credentials, DNS records, deployments, and consumer migration were all removed — an incomplete retirement leaves a zombie you can still reach.

## Escalation and related chains

### Related Skills & Chains

- **`api-misconfig`** — owns exploitation once a spec or endpoint is in hand (mass
  assignment, JWT attacks, OData, Swagger-chain attacks). This skill hands it a sharper target:
  "here's a zombie endpoint with weaker validation than the current one."
- **`subdomain-takeover`** — owns host/subdomain-level discovery (`api-v1.target.com` as its own
  host, potential takeover). This skill owns what happens once you're inside a given host's
  version surface.
- **`info-disclosure`** — JS-bundle grep for internal/undocumented calls; reused here
  specifically for version-diffing rather than secret extraction.
- **`apk-redteam-pipeline`** / **`ios-redteam-pipeline`** — mobile builds routinely hardcode an
  older API version; every mobile-sourced endpoint is a version-diff candidate.
- **`brute-force`** — a rate-limit regression found here is only a complete finding once
  chained to actual brute-forceable impact (login, OTP, enumeration).

### Related Skills & Chains

- **`hunt-api-misconfig`** — owns exploitation once a spec or endpoint is in hand (mass
  assignment, JWT attacks, OData, Swagger-chain attacks). This skill hands it a sharper target:
  "here's a zombie endpoint with weaker validation than the current one."
- **`hunt-subdomain`** — owns host/subdomain-level discovery (`api-v1.target.com` as its own
  host, potential takeover). This skill owns what happens once you're inside a given host's
  version surface.
- **`hunt-source-leak`** — JS-bundle grep for internal/undocumented calls; reused here
  specifically for version-diffing rather than secret extraction.
- **`apk-redteam-pipeline`** / **`ios-redteam-pipeline`** — mobile builds routinely hardcode an
  older API version; every mobile-sourced endpoint is a version-diff candidate.
- **`hunt-brute-force`** — a rate-limit regression found here is only a complete finding once
  chained to actual brute-forceable impact (login, OTP, enumeration).

## Sources and related reading

### D. Sources — numbered list of URLs you actually fetched

1. https://api-security.owasp.org/editions/2023/en/0xa9-improper-inventory-management (official API9 definition, beta-host reset-token scenario, prevention items)
2. https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management (mirror of the canonical API9 entry)
3. https://raw.githubusercontent.com/elementalsouls/Claude-BugHunter/main/skills/hunt-shadow-api/SKILL.md (version/path/header sweep commands, spec diff, false-positive gate)
4. https://safeguard.sh/resources/blog/find-undocumented-api-endpoints-five-places-to-look (five discovery sources, log normalization, version patterns)
5. https://salt.security/blog/api9-2019-improper-assets-management (shadow endpoints/parameters and definition discrepancies, ~40% spec gap)
6. https://www.ammune.ai/blog/owasp-api9-2023-improper-inventory-management (shadow/zombie/orphan/rogue taxonomy, runtime detection, confidence)
7. https://www.wiz.io/academy/api-security/shadow-api (continuous discovery, code-to-cloud visibility, contract testing in CI/CD)
8. https://www.cloudflare.com/learning/security/api/what-is-shadow-api/ (shadow vs zombie definitions, API discovery)
9. https://www.invicti.com/blog/web-security/how-to-detect-shadow-and-zombie-apis-automatically (spec reconstruction from live traffic, diff against docs)

## Additional notes

### OWASP API9 — Improper Inventory Management (Shadow / Zombie APIs)

As an API evolves, old versions and internal/staging routes routinely stay reachable without
receiving the same security fixes as the current version — because nobody tracks that they
still exist. The bug is rarely in one endpoint; it's in the **delta** between what an old
version enforces and what the current version enforces on the same operation.

### When to use

Trigger when:
- Versioned paths are visible (`/v1/`, `/v2/`, `/api/2023-01-01/`) or `Accept`/`X-API-Version`
  headers are in play.
- A changelog, release notes, or deprecation notice references removed/old API behavior.
- A mobile APK/IPA (via `apk-redteam-pipeline` / `ios-redteam-pipeline`) hardcodes endpoints
  that look like an older backend version than the current web app calls.
- Multiple OpenAPI/Swagger specs are discoverable, or `info.version` in one spec implies others
  exist.

DO NOT use for single-version APIs with no version history — there's nothing to diff; go
straight to `api-misconfig` for direct exploitation of the one surface that exists.

---

### Stage 1 — Enumerate the Full Version Surface

```bash
# Path-based versioning
for v in v1 v2 v3 v4 beta alpha internal legacy old 2022-01-01 2023-01-01 2024-01-01; do
  curl -s -o /dev/null -w "%{http_code} /api/$v/\n" "https://$TARGET/api/$v/"
done

# Header-based versioning
curl -s -H "X-API-Version: 1" https://$TARGET/api/users
curl -s -H "Accept: application/vnd.company.v1+json" https://$TARGET/api/users

# Subdomain-based versioning
for sub in api api-v1 api-v2 apiv1 apiv2 legacy-api old-api internal-api staging-api; do
  curl -s -o /dev/null -w "%{http_code} $sub\n" "https://$sub.$TARGET/"
done
```

A `200`/`401`/`403` on an old version path (anything but `404`/connection-refused) means the
version is still live and worth carrying into Stage 3, even if it demands auth.

---

### Stage 2 — Pull Every Reachable Spec, Not Just the Linked One

```bash
for path in openapi.json swagger.json v1/swagger.json v2/swagger.json v3/api-docs \
            api-docs.json swagger/v1/swagger.json .well-known/openapi.json; do
  curl -s -o /dev/null -w "%{http_code} /$path\n" "https://$TARGET/$path"
done

# Wayback Machine — a DEPRECATED version's spec often stays indexed after the live link is removed
curl -s "http://web.archive.org/cdx/search/cdx?url=$TARGET/*swagger*&output=json&collapse=urlkey"
curl -s "http://web.archive.org/cdx/search/cdx?url=$TARGET/*openapi*&output=json&collapse=urlkey"
```

When more than one spec resolves (a current one and an archived/old one), diff the endpoint
inventories directly:
```bash
jq -r '.paths | keys[]' v1-swagger.json | sort > /tmp/v1_paths.txt
jq -r '.paths | keys[]' v2-swagger.json | sort > /tmp/v2_paths.txt
comm -23 /tmp/v1_paths.txt /tmp/v2_paths.txt   # in v1 only — candidates for "still live but forgotten"
```
For every path in that diff, confirm it's still reachable against the v1 base URL. A route
documented only in the old spec that still returns something other than `404` is a zombie-
endpoint candidate — carry it into Stage 3.

---

### Stage 3 — Behavioral Diff Between Old and Current Version

For each operation that exists in **both** versions, compare security-relevant behavior, not
response shape. Response shape differences are Informational; behavioral security regressions
are the finding.

- **Auth strength.** Does the old version accept no token, an expired token, or a lower-
  privilege token that the current version rejects?
  ```bash
  curl -s -H "Authorization: Bearer $EXPIRED_TOKEN" https://$TARGET/api/v1/users/me -w '\n%{http_code}\n'
  curl -s -H "Authorization: Bearer $EXPIRED_TOKEN" https://$TARGET/api/v2/users/me -w '\n%{http_code}\n'
  ```
- **Rate limiting.** Burst the same number of requests against both versions' equivalent
  endpoint; a missing `429` on the old version means rate-limiting was added later and never
  backported.
- **Input validation.** Send the identical injection/oversized/malformed payload to both; the
  old version accepting what the new one rejects means hardening happened forward-only —
  chain into whichever injection class the payload targets (`sqli`, `idor`, etc.).
- **Field exposure.** Does the old version's response body include fields — internal IDs, other
  users' data, internal notes, PII — that the current version has since redacted?

---

### Stage 4 — Deprecated / Internal Routes Never Referenced by the Current UI

- Grep JS bundles for API calls no visible UI flow triggers (`/internal/`, `/admin/`, `/debug/`,
  `/_internal/`, `/test/`, `/staging/`) — reuse `info-disclosure`'s JS-bundle grep patterns for
  this specifically.
- Check `robots.txt` / `sitemap.xml` for disallowed API paths — a self-inflicted disclosure.
- Mobile-app endpoint inventories (via `apk-redteam-pipeline` / `ios-redteam-pipeline`) very
  often reference an older backend version than the current web app calls. Treat every
  APK/IPA-sourced endpoint as a version-diff candidate against the live web API.

---

### False-Positive Gate

- A version difference alone (different response shape, cosmetic field renaming) is
  Informational. The finding is a **security-relevant regression** — auth, rate-limit, or
  validation that got weaker going backward in version history.
- Confirm the old endpoint is not simply an alias/proxy to the current implementation before
  claiming a behavioral difference — send a payload that would actually behave differently
  under old vs. new logic, not just compare a version string in the response body.
- A `200` on a path that just serves a static "this API version is deprecated, use v2" message
  is not a finding — confirm the underlying operation still executes.

---

### Severity Table

| Finding | Severity |
|---|---|
| Old version bypasses auth entirely where current version requires it | Critical |
| Old version missing rate-limit present on current version | Medium–High (chain via `brute-force`) |
| Old version leaks extra fields (PII, internal IDs) vs. current | Medium–High |
| Old version accepts payloads the current version now validates/sanitizes | High (chain to the underlying injection class) |
| Version is reachable but behaviorally identical to current | Informational |

---

### When to use

Trigger when:
- Versioned paths are visible (`/v1/`, `/v2/`, `/api/2023-01-01/`) or `Accept`/`X-API-Version`
  headers are in play.
- A changelog, release notes, or deprecation notice references removed/old API behavior.
- A mobile APK/IPA (via `apk-redteam-pipeline` / `ios-redteam-pipeline`) hardcodes endpoints
  that look like an older backend version than the current web app calls.
- Multiple OpenAPI/Swagger specs are discoverable, or `info.version` in one spec implies others
  exist.

DO NOT use for single-version APIs with no version history — there's nothing to diff; go
straight to `hunt-api-misconfig` for direct exploitation of the one surface that exists.

---

### Stage 3 — Behavioral Diff Between Old and Current Version

For each operation that exists in **both** versions, compare security-relevant behavior, not
response shape. Response shape differences are Informational; behavioral security regressions
are the finding.

- **Auth strength.** Does the old version accept no token, an expired token, or a lower-
  privilege token that the current version rejects?
  ```bash
  curl -s -H "Authorization: Bearer $EXPIRED_TOKEN" https://$TARGET/api/v1/users/me -w '\n%{http_code}\n'
  curl -s -H "Authorization: Bearer $EXPIRED_TOKEN" https://$TARGET/api/v2/users/me -w '\n%{http_code}\n'
  ```
- **Rate limiting.** Burst the same number of requests against both versions' equivalent
  endpoint; a missing `429` on the old version means rate-limiting was added later and never
  backported.
- **Input validation.** Send the identical injection/oversized/malformed payload to both; the
  old version accepting what the new one rejects means hardening happened forward-only —
  chain into whichever injection class the payload targets (`hunt-sqli`, `hunt-idor`, etc.).
- **Field exposure.** Does the old version's response body include fields — internal IDs, other
  users' data, internal notes, PII — that the current version has since redacted?

---

### Stage 4 — Deprecated / Internal Routes Never Referenced by the Current UI

- Grep JS bundles for API calls no visible UI flow triggers (`/internal/`, `/admin/`, `/debug/`,
  `/_internal/`, `/test/`, `/staging/`) — reuse `hunt-source-leak`'s JS-bundle grep patterns for
  this specifically.
- Check `robots.txt` / `sitemap.xml` for disallowed API paths — a self-inflicted disclosure.
- Mobile-app endpoint inventories (via `apk-redteam-pipeline` / `ios-redteam-pipeline`) very
  often reference an older backend version than the current web app calls. Treat every
  APK/IPA-sourced endpoint as a version-diff candidate against the live web API.

---

### Severity Table

| Finding | Severity |
|---|---|
| Old version bypasses auth entirely where current version requires it | Critical |
| Old version missing rate-limit present on current version | Medium–High (chain via `hunt-brute-force`) |
| Old version leaks extra fields (PII, internal IDs) vs. current | Medium–High |
| Old version accepts payloads the current version now validates/sanitizes | High (chain to the underlying injection class) |
| Version is reachable but behaviorally identical to current | Informational |

---
