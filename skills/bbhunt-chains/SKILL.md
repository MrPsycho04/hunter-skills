---
name: bbhunt-chains
description: "Cluster hunting and escalation methodology: treat a confirmed low-severity primitive as a signal, sweep sibling endpoints and adjacent classes, and build chains to account takeover, RCE, or real data access. Use after any confirmed finding, when a lead is valid but low impact, or before reporting a chain."
agent_created: true
---

# A → B cluster hunting and escalation

Single bugs pay; chains pay several times more. This skill runs at **phase 5** of `bbhunt-methodology`. It never reports a chain that has not been proved end to end.

## The protocol

1. **Confirm A** with a real request. An unconfirmed primitive is not a signal.
2. **Map siblings** — same controller, API group, route family, feature module, or identity provider. Sibling code shares shortcuts.
3. **Test siblings** for the same class. A single root cause usually appears in more than one place.
4. **Change class** on the same surface. Ask what a different primitive here would unlock.
5. **Build the chain** — demonstrate A → B → C with a continuous request sequence. "Could be chained if…" is not a chain.
6. **Quantify** — affected users, records, money, authority. Then report one chain, not three separate low findings.

## Known high-yield chains

| Confirmed A | Hunt for B | Escalate to C |
|---|---|---|
| IDOR (read) | PUT/PATCH/DELETE on same object | Modify another user's data; privilege or money change |
| SSRF | Cloud metadata endpoint | IAM credentials → cloud account or internal admin |
| Stored XSS | Session cookie flags, admin views | Admin session use → privileged action |
| Open redirect | `redirect_uri` accepts your domain | Auth code/token interception → ATO |
| Public bucket | JS bundles in bucket | Client secret or token → OAuth compromise |
| Missing rate limit | OTP / reset token endpoint | Brute force → account takeover |
| GraphQL introspection | Field-level authorization | Mass PII extraction |
| Debug endpoint | Environment variables | Cloud credential → infrastructure access |
| CORS reflects origin | Credentialed request accepted | Cross-origin data theft |
| Host header reflection | Password-reset link generation | Reset poisoning → ATO |
| Cache poisoning unkeyed header | Static-extension or login page | Cross-user page takeover |
| Race on balance/limit | Repeat with parallel requests | Financial or quota bypass |
| Source-map secret | Scope of that token | Use the credential, then report the chain |
| LLM prompt injection | Agent tool access / markdown exfiltration | Data leakage or cross-tenant action |

## Adjacent-class sweep checklist

For every confirmed bug, test these before writing:

- [ ] Same parameter on GET, POST, PUT, PATCH, DELETE and with method overrides.
- [ ] Same parameter in query, JSON body, form body, multipart, and header.
- [ ] Same object ID with a second account, a different tenant, and an unauthenticated request.
- [ ] Same feature on staging, legacy, and versioned API paths (if in scope).
- [ ] Same input in admin-visible contexts (logs, exports, notifications, PDFs).
- [ ] Same trust boundary through a redirect, webhook, or async job (second-order).
- [ ] Any check-then-act flow in the same module under parallel requests.

## Stop rules

- A chain that requires the victim to take unusual actions is not reportable as a chain.
- Do not keep stacking hypotheticals: two proved primitives plus one proved consequence is the ceiling for a clean report.
- Do not access more data than the proof requires, even when a chain could expose more.
- If the chain fails at step B, report A alone only if A independently meets the validation gate.

## Corpus grounding

Mined from all 15,259 valid disclosures: cross-account replay, second-order/stored delivery, encoding bypasses, admin-context testing, internal-service discovery and OAST callbacks recur as the techniques that turn an odd response into a real finding. Search precedents with:

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "chain <primitive>" --limit 10
```

## References

- `references/chain-library.md` — extended chain catalogue by root cause and by technology, with corpus search terms.

## Unified upstream methodology

All 0 contributing upstream skills from  are merged and deduplicated in `references/unified-method.md`; full originals are preserved as `references/upstream-*.md`.
