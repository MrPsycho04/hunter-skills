# HackerOne Hunting Skills

Deep, field-tested hunting playbooks generated from **15,000+ publicly disclosed HackerOne reports** — 12,500+ full writeups, $4.9M+ in disclosed bounties.

Each skill is a ready-to-use [OpenCode](https://opencode.ai) skill. It contains quick wins, curated payloads, WAF/filter bypasses, real parameters, escalation chains, 30 techniques mined from actual reports, case studies, ffuf wordlists, and mapped Nuclei templates.

> For authorized security testing only. The underlying reports are public disclosures; do not test outside program scope.

## Install

```sh
git clone https://github.com/MrPsycho04/hackerone-skills.git
cd hackerone-skills
./install.sh          # symlink into ~/.config/opencode/skill
./install.sh --copy   # or copy the files
```

OpenCode loads them automatically. Ask for a class by name, e.g. `hackerone-xss`, or start with `hackerone-hunting`.

## Skills

| Skill | Focus | Reports |
|---|---|---:|
| [`hackerone-account-takeover`](hackerone-account-takeover/SKILL.md) | Hunt account takeover chains | 262 |
| [`hackerone-auth-bypass`](hackerone-auth-bypass/SKILL.md) | Hunt login, session, and identity verification flaws | 989 |
| [`hackerone-authz-bypass`](hackerone-authz-bypass/SKILL.md) | Hunt IDOR, privilege escalation, tenant isolation breaks, and missing function-level authorization | 1,386 |
| [`hackerone-clickjacking`](hackerone-clickjacking/SKILL.md) | Hunt clickjacking and UI redress | 166 |
| [`hackerone-crlf-injection`](hackerone-crlf-injection/SKILL.md) | Hunt CRLF injection and response splitting | 168 |
| [`hackerone-crypto-and-secrets`](hackerone-crypto-and-secrets/SKILL.md) | Hunt weak crypto, exposed secrets, and credential handling flaws | 562 |
| [`hackerone-csrf`](hackerone-csrf/SKILL.md) | Hunt CSRF and state-changing request forgery | 541 |
| [`hackerone-deserialization`](hackerone-deserialization/SKILL.md) | Hunt insecure deserialization | 93 |
| [`hackerone-dos`](hackerone-dos/SKILL.md) | Hunt algorithmic complexity, unbounded resource use, and app-layer DoS | 66 |
| [`hackerone-file-upload`](hackerone-file-upload/SKILL.md) | Hunt file upload flaws | 100 |
| [`hackerone-graphql`](hackerone-graphql/SKILL.md) | Hunt GraphQL authorization, introspection, and injection flaws | 79 |
| [`hackerone-hunting`](hackerone-hunting/SKILL.md) | Hunt bugs using 15,000+ publicly disclosed HackerOne reports | — |
| [`hackerone-idor`](hackerone-idor/SKILL.md) | Hunt IDOR and broken object-level authorization | 450 |
| [`hackerone-info-disclosure`](hackerone-info-disclosure/SKILL.md) | Hunt sensitive data exposure | 1,827 |
| [`hackerone-js-analyze`](hackerone-js-analyze/SKILL.md) | Analyze collected JS for secrets, endpoints, DOM sinks, and client-side auth flaws | 1,330 |
| [`hackerone-js-collect`](hackerone-js-collect/SKILL.md) | Collect JS files from a live target: bundles, chunks, and source maps | 1,330 |
| [`hackerone-llm-ai`](hackerone-llm-ai/SKILL.md) | Hunt prompt injection, agent tool abuse, and AI data leakage | 7 |
| [`hackerone-logic-and-design`](hackerone-logic-and-design/SKILL.md) | Hunt business logic abuse and secure-design violations | 931 |
| [`hackerone-memory-corruption`](hackerone-memory-corruption/SKILL.md) | Hunt memory safety bugs in native software | 892 |
| [`hackerone-mfa-and-passwords`](hackerone-mfa-and-passwords/SKILL.md) | Hunt MFA bypass, OTP flaws, and password policy issues | 285 |
| [`hackerone-mobile`](hackerone-mobile/SKILL.md) | Hunt mobile app flaws | 198 |
| [`hackerone-oauth-oidc`](hackerone-oauth-oidc/SKILL.md) | Hunt OAuth and OIDC flaws | 177 |
| [`hackerone-open-redirect`](hackerone-open-redirect/SKILL.md) | Hunt open redirects and redirect-chain abuse | 385 |
| [`hackerone-other`](hackerone-other/SKILL.md) | Hunt miscellaneous vulnerability classes | 1,226 |
| [`hackerone-path-traversal`](hackerone-path-traversal/SKILL.md) | Hunt path traversal, local file inclusion, and arbitrary file read | 300 |
| [`hackerone-prototype-pollution`](hackerone-prototype-pollution/SKILL.md) | Hunt prototype pollution and object injection | 59 |
| [`hackerone-race-condition`](hackerone-race-condition/SKILL.md) | Hunt race conditions and TOCTOU | 97 |
| [`hackerone-rce`](hackerone-rce/SKILL.md) | Hunt RCE, OS command injection, code injection, and unsafe eval | 1,399 |
| [`hackerone-request-smuggling`](hackerone-request-smuggling/SKILL.md) | Hunt request smuggling and cache desync | 101 |
| [`hackerone-session`](hackerone-session/SKILL.md) | Hunt session flaws | 150 |
| [`hackerone-sqli`](hackerone-sqli/SKILL.md) | Hunt SQL and NoSQL injection | 331 |
| [`hackerone-ssrf`](hackerone-ssrf/SKILL.md) | Hunt SSRF and server-side request primitives | 337 |
| [`hackerone-ssti`](hackerone-ssti/SKILL.md) | Hunt SSTI | 28 |
| [`hackerone-subdomain-takeover`](hackerone-subdomain-takeover/SKILL.md) | Hunt subdomain takeover | 196 |
| [`hackerone-web-cache`](hackerone-web-cache/SKILL.md) | Hunt cache poisoning and deception | 68 |
| [`hackerone-xss`](hackerone-xss/SKILL.md) | Hunt reflected, stored, and DOM XSS | 2,569 |
| [`hackerone-xxe`](hackerone-xxe/SKILL.md) | Hunt XXE and XML parser flaws | 64 |

## What is inside each skill

- **Signal** — report volume, median/p90/max bounty, top-paying programs
- **Quick wins** — the highest-yield tests, ordered
- **Payloads & probes** — context-specific starting payloads
- **Payload bank** — 50–90 hand-curated payloads with WAF/filter variants (XSS, SQLi, SSRF, path traversal, RCE, SSTI, XXE, redirect, CRLF)
- **Bypass tricks** — encoding, parser, allowlist, and sanitizer bypasses
- **Where to look** — parameters and endpoints that carry the bug
- **Escalation chains** — how a low-severity primitive becomes ATO/RCE/data access
- **Techniques from real reports** — 30 mined lessons with report IDs, programs, and bounties
- **Payload fragments observed** — frequency-ranked from the corpus
- **Case studies** — 5 full examples per class
- **Wordlists** — ffuf-ready paths and parameters, mined from the writeups
- **Nuclei** — verified tags and template paths for the class

## Corpus

Skills were generated from a local corpus of public HackerOne disclosures:

```text
15,259 indexed reports
12,537 full writeups
 3,243 paid reports
$4,945,915 disclosed bounties
2013-11-07 → 2026-11-18
```

Search it with the companion CLI if you have the corpus locally:

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class auth-bypass
```

## License

Skill text is provided for educational and authorized testing use. Report excerpts remain subject to their original disclosure terms.
