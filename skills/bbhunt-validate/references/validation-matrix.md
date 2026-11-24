# Extended validation matrix

## False-positive catalogue

| Observation | Usually is | Only a finding when |
|---|---|---|
| Version banner | Informational stack detail | Tied to a specific exploitable CVE in scope |
| Source map available | Build artifact | Contains a live secret or directly enables an attack |
| Stack trace | Verbose error | Exposes data/credentials usable by an attacker |
| Open redirect | Behaviour | Chained to token theft or trusted-origin phishing |
| DNS callback from SSRF primitive | Blind reachability | Internal data/status or a chained effect is demonstrated |
| CORS reflects Origin | Misconfiguration | Credentialed cross-origin read actually succeeds with victim data |
| Self-XSS / self-IDOR | Client-only | A second user is affected |
| Rate-limit response | Control | Bypassable across IP/session/param and leads to a real attack |
| Admin UI visible | Front-end exposure | The underlying function executes for a low-privilege user |
| Secret string | Possible leak | Demonstrably grants access to something valuable |

## Valid-but-unpaid findings: what they still teach

Across the corpus, most classes have only 14–24% paid reports. Unpaid valid writeups are still excellent evidence of technique: parameter-shape tricks, parser confusion, workflow abuse, and second-order delivery often appear there first. Use them to learn the *approach*; use paid reports to calibrate *impact language*.

## Severity decision guide

1. Who can trigger it? (anonymous / any user / specific role / victim-assisted)
2. What is affected? (money / identity / PII / internal system / configuration)
3. How many? (one object / all tenants / everyone)
4. How repeatable? (once / reliable / at scale)
5. Does any other control stop it? (if yes → hardening, not a vulnerability)

Write the answer in business terms. CVSS is the shorthand, not the reasoning.

## Unresolved-fact format

`needs_validation` records must contain exactly one missing fact, e.g. "whether the reset token is bound to the requesting account's email". No severity, no speculation, no promotion to finding.
