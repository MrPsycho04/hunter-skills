# Report patterns and sanitized examples

## Title formulas

- "Cross-tenant read of <object> via <feature> in <endpoint>"
- "Authentication bypass in <flow> allows <consequence> without <prerequisite>"
- "Server-side request forgery in <feature> reaches <internal target> and returns <data>"
- "Business logic flaw in <flow> allows <financial/state consequence>"

Avoid: "XSS on target", "IDOR vulnerability", "Open redirect found", payload strings in the title.

## Impact statement formula

`<who> can <what> for <which victims> by <how>, resulting in <concrete harm>.`

Example: "Any authenticated user can read another organization's exported invoices by changing the `org_id` parameter on `/api/export`, exposing financial records of all customers on the platform."

## Sanitized example structure

```
Summary
  The export endpoint trusts a client-supplied org_id when building its query.
  Authorization checks the session but not the object owner.

Steps
  1. Create users A and B in different organizations.
  2. As A, GET /api/export?org_id=<B-id> with A's session cookie.
  3. Observe B's invoice records in the response.

Impact
  Any user can enumerate org IDs and export another tenant's financial data.
  <count> records across <N> tenants are reachable.

Remediation
  Derive the organization from the authenticated session and verify object ownership.
```

## Before/after hygiene

- Before: raw cookie values, other users' names/emails, live tokens, third-party analytics in HAR.
- After: cookie names with values masked, black-barred PII, only the proving request sequence, your own test accounts.
