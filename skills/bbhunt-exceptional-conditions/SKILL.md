---
name: bbhunt-exceptional-conditions
description: "Feed malformed, unexpected input to make an endpoint fail open or leak internals. Unified from 2 upstream skills (cbh, hunting). For authorized security testing only."
agent_created: true
---

# Exceptional-condition mishandling — unified methodology

> **Unified skill.** Built from 2 upstream skills across cbh, hunting. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### Web-Research Methodology Additions (2026)

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
3. **Add these probes to the type-fuzzing list:** omit a required parameter entirely; add an unexpected ex

### Signals and surfaces

### What counts as a leak (the success signal)

A finding is confirmed when the response body contains a cross-framework error-disclosure signature:

- **Node/Express + Sequelize:** `SequelizeDatabaseError`, `node_modules/sequelize`,
  a JS stack with internal paths.
- **PHP:** `<b>Warning</b> ... /var/www/.../file.php on line N`.
- **Python:** `Traceback (most recent call last)`, `werkzeug.exceptions`.
- **Java:** `at com.app.Foo(Foo.java:42)` stack frames.
- **.NET:** `Server Error in '/' Application`, a `[System.XxxException: ...]` YSOD.

A clean JSON error (`{"error":"Invalid input"}`) with no internals is NOT a
finding — that's correct handling. Disclosure of internal structure is.

### Techniques, payloads and bypasses

### B. Techniques & bypasses — specific actionable techniques/payload shapes

1. **Take a known-good request and break ONE assumption at a time** (existing), but now also break: parameter presence (`{"rating":5}` → `{}`), parameter count (add `{"extra":"x"}`), divisor values (`?per=0`), and content-type (`text/plain` body with JSON content, form body where JSON expected).
2. **Remove `Accept: application/json`** (or set it to `*/*`) to make a framework fall back to an HTML error page — often more verbose than the JSON error. Toggle `X-Requested-With: XMLHttpRequest` and inspect the diff.
3. **Type-confusion into ORM internals.** Send an object where a scalar is expected (`{"quantity":{}}`, `{"rating":"x","comment":[1,2,3]}`); a `SequelizeDatabaseError` or `SQLException` response often discloses table names, column names, and the query fragment — directly reusable for SQLi.
4. **CWE-636 fail-open probe.** On any authorization or payment step, trigger an exception *after* the auth decision but *before* the state change: does the error path default to allow, or does it roll back and deny? Example shape: send a valid token plus a malformed body that throws during deserialization — check whether the action still executes.
5. **State-corruption / rollback test.** For a multi-step operation, interrupt it mid-flight (drop the connection, force a 500 on step 2, or race two requests) and query final state. A partial commit = fail-open state corruption (OWASP scenario #3), not a mere verbose error.
6. **Error-page fingerprinting chain.** Capture framework/version from the stack trace,

### Validation and proof

### Validation discipline

- Capture the exact leaked artifact (path, ORM class, version, stack frame) —
  that's the evidence. "It returned 500" alone is not disclosure.
- Note what the leak enables next (e.g. a disclosed SQL error → sqli; a
  disclosed absolute path → path-traversal).

---

### C. Validation / proof bar — how to confirm and avoid false positives (confabulation is NOT a finding for AI classes)

1. **A clean JSON error `{"error":"Invalid input"}` with no internals is NOT a finding** (existing) — that is correct handling. So is a generic error page with no framework/version/path detail.
2. **Capture the exact leaked artifact** — path, ORM class, version, stack frame (existing). "It returned 500" is not disclosure.
3. **Score disclosure by what it enables.** Verbose error alone is Low–Medium info disclosure (CWE-209/550). If you chain it to SQLi, traversal, or RCE, score the chained finding — but prove the chain, don't assert it.
4. **Fail-open needs a demonstrated unauthorized outcome** — a resource accessed, a payment completed, or a privilege gained — not just "the code probably defaults to allow." Reproduce twice.
5. **State-corruption needs before/after state** and a clean-state reproduction; document whether it requires a specific timing window.
6. **Don't report theoretical exceptional conditions.** CWE-390 (detected but no action) is only a finding when you can show the inaction causes a security-relevant outcome. Scanner-flagged "unhandled exception" with no attacker-controlled trigger and no consequence is noise.
7. **Confabulation note (AI classes).** If an AI-assisted tool claims an error-handling bug, verify the exact response body yourself — do not report a hallucinated stack trace or a framework version the server never returned.

### Validation discipline

- Capture the exact leaked artifact (path, ORM class, version, stack frame) —
  that's the evidence. "It returned 500" alone is not disclosure.
- Note what the leak enables next (e.g. a disclosed SQL error → hunt-sqli; a
  disclosed absolute path → hunt-lfi).

## Source skills merged into this topic

- `hunting` — `exceptional-conditions`
- `cbh` — `hunt-exceptional-conditions`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `../../upstream/` — complete unmodified archives of all five source repositories
- `bbhunt-methodology` — orchestrator, state machine and class router
