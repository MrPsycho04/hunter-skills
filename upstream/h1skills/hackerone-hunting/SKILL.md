---
name: hackerone-hunting
description: >-
  Hunt bugs using 15,000+ publicly disclosed HackerOne reports. Use at the start of any web, API, mobile, or AI security assessment; when choosing what to test; when you need real-world payloads, bypasses, or report precedents for a vulnerability class.
---

# HackerOne hunting corpus

A local, searchable copy of **15,259** disclosed HackerOne reports (3,243 paid, $4,945,915 in disclosed bounties; 12,537 full writeups downloaded). Each class skill distills the reports that matter and links back to the raw writeups.

## Corpus

```text
~/.local/share/hackerone-reports/
├── index.csv          # metadata for every report
├── raw/<id>.json      # full disclosed writeups
├── reports.sqlite     # searchable DB (FTS5)
├── h1.py              # search CLI
├── wordlists/         # mined paths, params, curated payloads
├── payloads.py        # hand-curated payload banks
└── build.py           # rebuilds the DB, wordlists, and skills
```

## Search it

```sh
H1=~/.local/share/hackerone-reports/h1.py
python3 $H1 search "webhook ssrf" --limit 15
python3 $H1 search "reset token" --class auth-bypass --min-bounty 500
python3 $H1 search "shopify" --program shopify
python3 $H1 show 1234567            # metadata + full writeup
python3 $H1 stats --class xss
python3 $H1 classes                 # counts per class
```

Search tip: quote phrases, use program names, technologies (`rails`, `graphql`, `aws`), or parameters (`redirect_uri`, `next`, `file`).

## Wordlists & payloads

Mined paths and parameters plus curated payload banks live in `~/.local/share/hackerone-reports/wordlists/`.

```sh
W=~/.local/share/hackerone-reports/wordlists
ls $W | head                      # paths/params/payloads per class
ffuf -u https://target/FUZZ -w $W/paths.txt -mc all -fc 404 -fs 0 -rate 40
ffuf -u 'https://target/api?FUZZ=canary' -w $W/params.txt \
     -mr 'canary|error|invalid' -rate 40
```

Every class skill embeds its own payload bank (XSS/SQLi/SSRF: 80+ each, with WAF-bypass subsets) and links to the matching wordlist files.

## Nuclei quickstart

```sh
# Broad known-CVE and exposure sweep first
nuclei -u https://target -tags cve -severity high,critical -rl 40 -o cve.txt
nuclei -u https://target -tags exposure,config,debug,files,keys,tokens \
       -severity info,low,medium,high,critical -rl 40 -o exposure.txt
# Then class-specific fuzzing (see each skill's Nuclei section)
nuclei -u https://target -tags xss -rl 40 -o xss.txt
nuclei -u https://target -t ~/nuclei-templates/dast/vulnerabilities/xss -dast
```

Template tags and paths are verified against the official `projectdiscovery/nuclei-templates` repository.

## Workflow

1. **Scope** — read the program brief, in-scope assets, and out-of-scope list. Never test outside it.
2. **Map** — enumerate endpoints, roles, object IDs, and third-party integrations.
3. **Pick classes** — for each surface, open the matching `hackerone-<class>` skill.
4. **Read precedents** — search the corpus for the same technology or feature and read 3–5 writeups.
5. **Test the checklist** — adapt the class checklist; don't blindly replay payloads.
6. **Chain** — combine low-severity primitives into ATO/RCE/data access.
7. **Prove impact** — second account, callback, or exact data boundary; then write a tight report.

## How each class skill is built

Every `hackerone-<class>` skill contains: **Quick wins**, **Payloads & probes**, **a curated payload bank** (XSS/SQLi/SSRF/Path-traversal/RCE have 50+ each), **Bypass tricks**, **Where to look** (params/endpoints), **Tools**, **Escalation chains**, a deeper checklist, **30 techniques mined from real reports**, a table of **payloads & parameters observed**, 5 full case studies, **mined wordlists**, and **class-mapped Nuclei commands**.

## Cross-class high-yield checks

- **Host header** — inject `Host`, `X-Forwarded-Host`, `X-Original-URL` into reset, cache, and routing paths.
- **Method swap** — replay every request as GET/POST/PUT/PATCH/DELETE and with `_method` overrides.
- **Path normalization** — `/admin/..;/`, `%2e%2e`, double slashes, trailing dots/spaces.
- **JSON ↔ form ↔ multipart** — change content-type and move parameters between body, query, and path.
- **Two accounts** — always test cross-account read *and* write, not just read.
- **Race** — parallelize any check-then-act flow (coupon, withdraw, invite, limit).
- **Cache** — look for unkeyed headers, static-extension deception, and cross-user caching.
- **Errors** — force stack traces, SQL errors, and debug output; they leak paths, versions, and queries.
- **Chaining** — a low-severity read/redirect/XSS often becomes ATO when combined with one more primitive.

## Classes

| Skill | Reports | Median bounty |
|---|---:|---:|
| `hackerone-xss` | 2,569 | $500 |
| `hackerone-info-disclosure` | 1,827 | $500 |
| `hackerone-rce` | 1,399 | $800 |
| `hackerone-authz-bypass` | 1,386 | $500 |
| `hackerone-auth-bypass` | 989 | $500 |
| `hackerone-logic-and-design` | 931 | $500 |
| `hackerone-memory-corruption` | 892 | $750 |
| `hackerone-crypto-and-secrets` | 562 | $500 |
| `hackerone-csrf` | 541 | $300 |
| `hackerone-idor` | 450 | $500 |
| `hackerone-open-redirect` | 385 | $300 |
| `hackerone-ssrf` | 337 | $700 |
| `hackerone-sqli` | 331 | $1,350 |
| `hackerone-path-traversal` | 300 | $1,000 |
| `hackerone-mfa-and-passwords` | 285 | $500 |
| `hackerone-account-takeover` | 262 | $1,500 |
| `hackerone-mobile` | 198 | $750 |
| `hackerone-subdomain-takeover` | 196 | $350 |
| `hackerone-oauth-oidc` | 177 | $900 |
| `hackerone-crlf-injection` | 168 | $400 |
| `hackerone-clickjacking` | 166 | $500 |
| `hackerone-session` | 150 | $100 |
| `hackerone-request-smuggling` | 101 | $1,800 |
| `hackerone-file-upload` | 100 | $400 |
| `hackerone-race-condition` | 97 | $510 |
| `hackerone-deserialization` | 93 | $600 |
| `hackerone-graphql` | 79 | $2,250 |
| `hackerone-web-cache` | 68 | $650 |
| `hackerone-dos` | 66 | $447 |
| `hackerone-xxe` | 64 | $1,000 |
| `hackerone-prototype-pollution` | 59 | $3,000 |
| `hackerone-ssti` | 28 | $2,150 |
| `hackerone-llm-ai` | 7 | — |

Topic skills (GraphQL, OAuth, ATO, mobile, AI, cache, etc.) intentionally overlap with root-cause skills: a GraphQL IDOR belongs in both. Counts are per skill, not a partition.

## Prioritisation

Bias toward bugs that are easy to prove and hard to dispute: cross-tenant data access, auth bypass, ATO, RCE, SSRF to cloud metadata, and payment/limit logic. Read the program's disclosed reports first — they reveal what the team rewards and what has been missed.

## Report bar

- Title states the impact, not the payload.
- Summary, exact steps, raw request/response, and a short impact statement.
- Redact other users' data; use your own test accounts.
- Never test outside scope, never run destructive DoS, never access data you don't need.

## Ethics

This corpus contains public disclosures only. Use it for authorized testing and learning. Follow each program's policy and the law.
