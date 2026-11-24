# Extended chain library

## By root cause

| Root primitive | Adjacent classes to test | Typical consequence |
|---|---|---|
| Unscoped object reference | Authz, mass assignment, export | Cross-tenant data and writes |
| Reflected input | Stored delivery, admin view, CSP | Session/privileged action |
| Server-side URL fetch | Redirect allowlist, metadata, gopher | Cloud credentials, internal services |
| Weak identity binding | OAuth, reset, email change | Account takeover |
| Missing friction | OTP brute force, rate limit, race | Limit/financial bypass |
| Parser mismatch | Cache, smuggling, CORS | Cross-user responses |
| Exposed artifact | Source map, bucket, debug endpoint | Secret -> API access |

## By technology

- **GraphQL**: introspection -> hidden mutation -> field-level authz -> mass PII.
- **OAuth/OIDC**: redirect_uri -> code capture; state -> login CSRF -> account linking.
- **Node/JS**: prototype pollution -> property override -> auth bypass; source map -> secret.
- **PHP/Java**: deserialization -> gadget -> RCE; file include -> log poisoning -> RCE.
- **Cloud**: SSRF -> IMDS -> IAM -> storage; debug endpoint -> env -> credential.
- **AI features**: indirect injection -> markdown exfiltration; agent tool -> internal API; conversation IDOR -> cross-tenant data.

## Corpus search terms

```sh
H1=~/.local/share/hackerone-reports/h1.py
python3 $H1 search "<primitive> chain" --limit 10
python3 $H1 search "<primitive> to account takeover" --limit 10
python3 $H1 search "<technology> <primitive>" --limit 10
```

All disclosed reports are valid; rank by relevance and upvotes, not payment.
