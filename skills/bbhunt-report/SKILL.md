---
name: bbhunt-report
description: "Write reproducible, redacted bug-bounty submissions and capture evidence hygiene: impact-first title and summary, exact steps, sanitized request/response, severity reasoning, CVSS, and platform-specific notes. Use after validation passes, when drafting or tightening a report, or when preparing evidence screenshots/HARs."
agent_created: true
---

# Reporting and evidence hygiene

This is **phase 6** of `bbhunt-methodology`. Only findings that passed `bbhunt-validate` reach this skill.

## Report bar

- Title states the **impact**, not the payload: "Cross-tenant read of another organization's invoices via unscoped export" — not "IDOR on /api/export?id=".
- Summary answers: what is wrong, who is affected, what an attacker gets.
- Steps are numbered, minimal, and reproducible by a triager with two test accounts.
- Raw request and response are included, with secrets and other users' data redacted.
- Impact is stated in business terms with a count where possible: records, users, money, authority.
- Severity is requested with reasoning tied to demonstrated impact, not a template score.

## Structure

```
Title: <impact statement>

Summary
  <3–5 sentences: defect, surface, who can trigger, what they get>

Steps to reproduce
  1. <setup, including which two accounts>
  2. <exact request or UI action>
  3. <observation that proves the defect>

Sanitized request / response
  <HTTP block or screenshot; redact session cookies, tokens, PII>

Impact
  <real harm, quantified; who is affected; what the attacker controls>

Root cause (optional, if known)
  <one paragraph — helps the team fix it>

Remediation (optional)
  <specific control, not generic advice>

 Severity: <CVSS 3.1 vector + one-line justification>
```

## Evidence hygiene

- **Cookies/tokens**: redact session values, CSRF tokens, API keys, and authorization headers before capture, not after. Keep the cookie *name* so triagers can see which session was used.
- **Other users' data**: black-bar names, emails, addresses, IDs, and payment details. Use your own test accounts wherever possible.
- **HAR files**: strip unrelated domains and third-party analytics; keep only the request sequence that proves the finding.
- **Screenshots**: capture in order — setup, triggering request, observed result — before the state changes. Annotate the exact field that matters.
- **Timing**: if the bug depends on race/timing, include the parallel request set and the state delta, not just one lucky response.
- Never include live credentials, even redacted-in-appearance. Rotate anything you accidentally exposed.

## Severity quick guide

| Impact | Typical range |
|---|---|
| Unauthenticated RCE, full-tenant compromise, mass PII, financial theft | Critical / High |
| Cross-user data read/write with authenticated attacker, ATO chain | High / Medium |
| Blind SSRF with limited reachability, logic abuse with bounded gain | Medium / Low |
| Self-only, theoretical, or best-practice | Do not submit |

CVSS 3.1 is a communication aid, not a verdict. Explain the environmental context in words.

## Platform notes

- **HackerOne / Bugcrowd / Intigriti / Immunefi**: check the program's own impact taxonomy and VRT category before choosing severity; search for the closest category and fall back deliberately.
- If no exact VRT category exists, pick the nearest and explain the mismatch in the impact paragraph.
- One report per chain. Do not split a proved chain into several low-impact reports, and do not merge unrelated bugs.

## Final pre-submit checklist

- [ ] Asset is in scope; not a known issue; not already disclosed in the corpus.
- [ ] Validation gate passed; no unresolved fact remains.
- [ ] PoC works from the exact steps with no hidden setup.
- [ ] All third-party data redacted; test accounts are your own.
- [ ] Title and impact describe real harm, not a payload.
- [ ] Chain (if any) was demonstrated end to end.

## References

- `references/report-examples.md` — sanitized before/after report examples and corpus-derived title/impact patterns.

## Unified upstream methodology

All 4 contributing upstream skills from cbh, hunting are merged and deduplicated in `references/unified-method.md`; full originals are preserved as `references/upstream-*.md`.
