# Upstream source: exceptional-conditions (hunting)

Original path: `/tmp/h1res_MrPsycho04_Hunting-Agent/exceptional-conditions/SKILL.md`

---

---
name: exceptional-conditions
description: "Hunt mishandling of exceptional conditions — feed an endpoint malformed/unexpected input (wrong type, broken JSON, oversized field, null byte) and make it fail OPEN or leak internals: a verbose stack-trace / framework error page that discloses ORM internals, server file paths, library versions, or a language traceback. Use on any input-accepting endpoint (JSON APIs, forms, query params). Medium-High when the leak exposes internal structure that arms a deeper attack."
---

# HUNT-EXCEPTIONAL-CONDITIONS — Verbose Errors / Fail-Open (A10:2025)

## What actually pays

Well-built apps catch errors and return a clean, generic message. A broken app,
when handed input it didn't expect, throws an unhandled exception and renders a
**developer error page** straight to the client — leaking the stack trace, the
ORM/query internals, server-side file paths, and framework/library versions.
That disclosure is the finding (and it arms SQLi/RCE/path attacks next).

## Recon

Any endpoint that parses input is a candidate; the richest are:

```
JSON APIs that expect typed fields:  POST /api/* with {numbers, ids, enums}
Endpoints with numeric/id path or query params:  /item/{id}, ?page=, ?quantity=
Search / filter / sort params
File or content-type sensitive uploads
```

## Attack — send what the code didn't anticipate

Take a known-good request and break ONE assumption at a time:

- **Wrong type:** a field the app expects to be a number/string is sent as an
  array or object — `{"rating":"x","comment":[1,2,3]}`, `{"quantity":{}}`.
- **Malformed body:** truncated/!invalid JSON, an unterminated string, a stray
  brace, a wrong/missing Content-Type.
- **Boundary/oversized:** a very long string, a huge/negative/overflow number.
- **Null byte / control chars** embedded in a value.

```
POST /api/Feedbacks   {"rating":"notanumber","comment":[1,2,3]}
GET  /item/' OR /item/%00   (also exercises the error path)
```

Watch the RESPONSE BODY, not just the status: a 500 (or even a 200/400) whose
body contains a stack trace or framework error page is the signal.

## What counts as a leak (the success signal)

A finding is confirmed when the response body contains a cross-framework error-disclosure signature:

- **Node/Express + Sequelize:** `SequelizeDatabaseError`, `node_modules/sequelize`,
  a JS stack with internal paths.
- **PHP:** `<b>Warning</b> ... /var/www/.../file.php on line N`.
- **Python:** `Traceback (most recent call last)`, `werkzeug.exceptions`.
- **Java:** `at com.app.Foo(Foo.java:42)` stack frames.
- **.NET:** `Server Error in '/' Application`, a `[System.XxxException: ...]` YSOD.

A clean JSON error (`{"error":"Invalid input"}`) with no internals is NOT a
finding — that's correct handling. Disclosure of internal structure is.

## Validation discipline

- Capture the exact leaked artifact (path, ORM class, version, stack frame) —
  that's the evidence. "It returned 500" alone is not disclosure.
- Note what the leak enables next (e.g. a disclosed SQL error → sqli; a
  disclosed absolute path → path-traversal).

---

## Web-Research Methodology Additions (2026)

> Fresh-source pass: OWASP Top 10 **A10:2025 Mishandling of Exceptional Conditions** (official page), MITRE CWE mappings, and the PortSwigger error-disclosure lab. This extends the existing "send what the code didn't anticipate" section with the full 2025 category and its fail-open/state-corruption angles.

### A. Discovery checklist — concrete surfaces, inputs, configs to look for

1. **A10:2025 is a *new* OWASP category** (24 CWEs, 769,581 occurrences, 3,416 CVEs, max incidence 20.67%, avg weighted exploit 7.11). Its three failings: the app does not *prevent* an unusual situation, does not *detect* it, or *responds poorly / not at all*. OWASP's own summary: "any time an application is unsure of its next instruction, an exceptional condition has been mishandled." Your existing wrong-type/malformed-body probes are one slice of this — expand to detection and response.
2. **Work through the full mapped CWE list, not just CWE-209.** High-value ones for hunters:
   - CWE-209 / CWE-550 — error message containing sensitive information (incl. server-generated)
   - CWE-215 — sensitive info inserted into debugging code
   - CWE-234 / CWE-235 — missing / extra parameters
   - CWE-248 — uncaught exception; CWE-252 — unchecked return value
   - CWE-274 / CWE-280 — improper handling of insufficient privileges/permissions
   - CWE-369 — divide by zero; CWE-390 / CWE-391 / CWE-394 — detected-but-unacted / unchecked / unexpected status
   - CWE-396 / CWE-397 — catch/throw generic exception; CWE-460 — improper cleanup on thrown exception
   - CWE-476 — NULL pointer dereference; CWE-478 / CWE-484 — missing default case / omitted `break` in switch
   - CWE-636 — not failing securely ("failing open"); CWE-703 / CWE-754 / CWE-755 / CWE-756 — improper check/handling, missing custom error page
3. **Add these probes to the type-fuzzing list:** omit a required parameter entirely; add an unexpected extra parameter; send `null`, `[]`, `{}`; send `0` or a negative number to any field used as a divisor (CWE-369); send an unexpected status/return value from an upstream service; force a generic-catch path (CWE-396); trigger cleanup-failure (CWE-460).
4. **Hunt debug-mode indicators.** `?debug=true`, `?test=1`, `X-Debug: 1`, `/debug`, `/actuator`, `trace.axd`, `elmah.axd`, `APP_DEBUG=true`, framework default error pages. PortSwigger's "Information disclosure in error messages" lab: an unexpected data type → full stack trace → Apache Struts 2 2.3.31 disclosed. That version string then arms targeted CVE selection.
5. **Look beyond the response body to *state*.** OWASP scenario #3: a multi-step transaction (debit → credit → log) interrupted mid-flight that does not roll back (fails open) → drained account or double-send. OWASP scenario #1: exceptions during file upload that don't release resources → resource exhaustion/DoS. These are fail-open findings, not disclosure findings, and can be High/Critical.
6. **Check the environment-dependent error paths.** Memory pressure, network timeouts, permission denial, and missing optional services often have completely different (and unhandled) error handling than the happy path. Force upstream failures via invalid credentials/hosts where in scope.
7. **Look at error-handling *consistency*, not just individual endpoints.** OWASP explicitly recommends centralized handling and a global exception handler because "one application should not [have] multiple functions for handling exceptional conditions." In practice that means fuzz the same malformed input across many endpoints: the one that returns a different, verbose shape is where the global handler was bypassed.
8. **Check rate/resource limits on the error path itself.** OWASP's prevention guidance calls for rate limiting, quotas, and throttling so exceptional conditions are not trivially reachable at scale. An error page that is both verbose *and* unthrottled is a cheap reconnaissance primitive — and repeated identical errors can be collapsed into statistics rather than echoed verbatim.

### B. Techniques & bypasses — specific actionable techniques/payload shapes

1. **Take a known-good request and break ONE assumption at a time** (existing), but now also break: parameter presence (`{"rating":5}` → `{}`), parameter count (add `{"extra":"x"}`), divisor values (`?per=0`), and content-type (`text/plain` body with JSON content, form body where JSON expected).
2. **Remove `Accept: application/json`** (or set it to `*/*`) to make a framework fall back to an HTML error page — often more verbose than the JSON error. Toggle `X-Requested-With: XMLHttpRequest` and inspect the diff.
3. **Type-confusion into ORM internals.** Send an object where a scalar is expected (`{"quantity":{}}`, `{"rating":"x","comment":[1,2,3]}`); a `SequelizeDatabaseError` or `SQLException` response often discloses table names, column names, and the query fragment — directly reusable for SQLi.
4. **CWE-636 fail-open probe.** On any authorization or payment step, trigger an exception *after* the auth decision but *before* the state change: does the error path default to allow, or does it roll back and deny? Example shape: send a valid token plus a malformed body that throws during deserialization — check whether the action still executes.
5. **State-corruption / rollback test.** For a multi-step operation, interrupt it mid-flight (drop the connection, force a 500 on step 2, or race two requests) and query final state. A partial commit = fail-open state corruption (OWASP scenario #3), not a mere verbose error.
6. **Error-page fingerprinting chain.** Capture framework/version from the stack trace, then map to known CVEs. A disclosed absolute path also enables `path-traversal`; a disclosed ORM enables `sqli`; a disclosed deserialization stack enables `deserialization`. Always attempt the chain before writing up disclosure alone.
7. **Resource-exhaustion check.** Repeat an erroring request that allocates resources (upload, image processing); watch for leaked locks/handles and eventual DoS (OWASP scenario #1). Pair this with the OWASP prevention advice to add quotas and throttling — the absence of both is what turns a handled error into an availability bug.

### Cross-skill routing for exceptional-condition findings

- **Stack trace / ORM / path / version disclosed** → `info-disclosure`, then chain to `sqli` / `path-traversal` / `deserialization` where the leaked artifact enables it.
- **Error path defaults to allow, or a transaction partially commits** → `authz-bypass` / `fintech-graphql` / `race-condition` (fail-open state corruption is usually the higher-severity finding).
- **Oversized/unterminated input crashes a native parser** → `memory-corruption`; **oversized input exhausts a managed runtime** → `dos`.
- **A missing parameter changes a security decision** (e.g. omitting a role or scope field) → `api-misconfig` mass-assignment / `authz-bypass`.

### C. Validation / proof bar — how to confirm and avoid false positives (confabulation is NOT a finding for AI classes)

1. **A clean JSON error `{"error":"Invalid input"}` with no internals is NOT a finding** (existing) — that is correct handling. So is a generic error page with no framework/version/path detail.
2. **Capture the exact leaked artifact** — path, ORM class, version, stack frame (existing). "It returned 500" is not disclosure.
3. **Score disclosure by what it enables.** Verbose error alone is Low–Medium info disclosure (CWE-209/550). If you chain it to SQLi, traversal, or RCE, score the chained finding — but prove the chain, don't assert it.
4. **Fail-open needs a demonstrated unauthorized outcome** — a resource accessed, a payment completed, or a privilege gained — not just "the code probably defaults to allow." Reproduce twice.
5. **State-corruption needs before/after state** and a clean-state reproduction; document whether it requires a specific timing window.
6. **Don't report theoretical exceptional conditions.** CWE-390 (detected but no action) is only a finding when you can show the inaction causes a security-relevant outcome. Scanner-flagged "unhandled exception" with no attacker-controlled trigger and no consequence is noise.
7. **Confabulation note (AI classes).** If an AI-assisted tool claims an error-handling bug, verify the exact response body yourself — do not report a hallucinated stack trace or a framework version the server never returned.

### D. Sources — numbered list of URLs you actually fetched

1. https://top10.owasp.org/2025/A10_2025-Mishandling_of_Exceptional_Conditions/ (official A10:2025 page — 24 CWEs, score table, three failings, prevention, scenarios #1–#3; webfetched)
2. https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-in-error-messages (unexpected data type → stack trace → Apache Struts 2 2.3.31 disclosure)
3. https://cwe.mitre.org/data/definitions/209.html (CWE-209: Generation of Error Message Containing Sensitive Information)
4. https://nhimg.org/owasp-top-10-a10-guide (A10:2025 as reconnaissance, CWE-209/CWE-550, error messages as recon)
5. https://www.raventek.com/exception-handling-for-federal-application-security/ (fail-open/default-allow, raw stack trace, debug mode, key technical weaknesses)
6. https://www.invicti.com/web-application-vulnerabilities/stack-trace-disclosure-java (disable debug mode in production, custom error pages)
