# Hunter playbook — field discipline and corpus evidence

Companion to `bbhunt-methodology/SKILL.md`. Load when planning a session, when a branch is stalling, or when choosing the next coverage unit.

## What top hunters do differently

- They build a **mental model of the application's internals** — why a feature exists, what shortcut the developer likely took — instead of only cataloguing endpoints.
- They hunt **`A → B` clusters**: finding one defect triggers a systematic sweep of sibling endpoints and other classes in the same module. Chains pay several times more than isolated primitives.
- They **kill weak findings fast**. An unproven lead consumes the same budget as a real one; the triage gate is applied before writing, never after.
- They **work authenticated surfaces early**. In the operator's own recon notes, unauthenticated passes on hardened apps repeatedly ended with the same conclusion: the real bugs need two test accounts.
- They **log negatives as carefully as positives**, including the exact request set and response signatures that were ruled out. This is what makes repeat runs additive.
- They use tools for **breadth**, then switch to manual reasoning for **depth**. Automated scans find the same bugs everyone else finds.
- They read **disclosed reports for the specific program/stack** before testing. The corpus is a map of what this community already missed.

## Pre-hunt framework (10 minutes, non-negotiable)

1. Read scope, out-of-scope, known issues, rate limits. Write them into `scope.md`. Do not rely on memory.
2. Ask: *if authorization failed here, what could an attacker actually take?* Rank surfaces by that answer, not by how easy they are to fuzz.
3. Identify the roles and at least two identities (attacker/victim, low-priv/admin) before testing object-level bugs. Without them, IDOR testing is guesswork.
4. Record a **404/403 control** per host before probing paths. Modern SPAs return 200 + app shell for nonexistent paths; a status code alone proves nothing.
5. Choose one class from the router. Write `PHASE` and `CLASS` into `state.md`.
6. Read 3–5 corpus precedents for that class + technology. Note the technique and the impact, not the payload.

## Baseline control — do this before enumeration

```sh
for H in $HOSTS; do
  for P in /zzz-nope-12345 /qqq-other-98765; do
    printf "%-34s " "$H$P"
    curl -sk -m 12 -o /tmp/b -w "%{http_code} %{size_download} " "https://$H$P"
    shasum /tmp/b | cut -c1-12
  done
done
```

Record **status, byte length, body hash** per host. A 200 matching the control hash is a soft 404. A 404 whose body differs from the control may be a real handler. Re-derive per host and per path depth. CDN "Access Denied" bodies mean the request never reached the app — classify as edge behaviour and move on.

## 403 bypass pass (bounded, rate-limit aware)

From field notes: a thorough header/path pass that still returns 403 is a **logged negative**, not a puzzle to obsess over. Test once, record the matrix, move on.

Headers: `X-Forwarded-For: 127.0.0.1|10.0.0.1|::1`, `X-Real-IP`, `Forwarded`, `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-Host`, `X-Original-Host`, `X-Forwarded-Proto`, `Referer`, `Host` overrides, absolute-form request target, `Host` trailing dot.
Paths: `/./`, `/%2e%2e/`, `/..;/`, `//`, `/health`, `/api`, `/%00`.
Methods: `OPTIONS`, `POST`, `PUT`, `TRACE`, `X-HTTP-Method-Override`, `X-Original-Method`.
Any `Host` value other than the exact hostname producing a default-backend 404 confirms server_name-scoped allowlisting with no spoofable trust — stop.

## Time budget and switching rules

| Situation | Rule |
|---|---|
| Host baseline | 5 min max |
| One class on one surface | 20–40 min, then re-evaluate |
| 3 identical failures | Change approach; log signature |
| Stalled on target | 60 min → switch context or surface |
| Recon rabbit hole | 15 min → log and move |
| Stalled at pipeline step | Change approach after N identical failures; never just repeat |

## Negative-result log template

```
[YYYY-MM-DD HH:MM] host/path — class — tested: <exact variations>
Control: <status/bytes/hash>. Observed: <status/bytes/hash>.
Conclusion: <ruled out / needs-auth / out-of-scope / blocked>.
Next: <one concrete action or "none — switch to X">.
```

## Candidate record template

```
id: <short slug>
class: <bbhunt-<class>>
surface: <host + endpoint + param>
primitive: <what the app does wrong>
proof: <exact request/response, sanitized>
impact: <real harm to a real user, quantified>
verdict: confirmed | needs_validation | rejected
unresolved_fact: <only for needs_validation — the ONE missing fact>
chain: <what this enables when combined with X>
```

## Corpus search recipes

```sh
H1=~/.local/share/hackerone-reports/h1.py
# Which techniques recur for a feature?
python3 $H1 search "reset token" --limit 15
python3 $H1 search "webhook" --class ssrf --limit 15
python3 $H1 search "graphql introspection" --limit 10
# Rank by community signal, not by payment.
python3 $H1 search "race condition" --min-upvotes 50 --limit 10
python3 $H1 show <id> --full
python3 $H1 stats --class <class>
```

Reminder: all 15,259 disclosed reports are valid findings. Payment (about 14–24% per class) measures program policy and impact, not whether the bug was real.

## Corpus evidence by class

Valid disclosed reports, share paid, and the most frequent techniques across **all** valid writeups. Paid share is an impact/program signal, never a validity filter.

| Class | Valid | Paid % | Top techniques |
|---|---:|---:|---|
| `bbhunt-xss` | 2569 | 21% | DOM / HTML source inspection (743), second-order / stored / blind delivery (413), encoding / double-encode / null byte (332), WAF / sanitizer / filter bypass (332) |
| `bbhunt-info-disclosure` | 1827 | 19% | public source-code / repo review (243), admin / privileged-role context (215), encoding / double-encode / null byte (162), internal service / port / container (159) |
| `bbhunt-rce` | 1399 | 24% | public source-code / repo review (393), internal service / port / container (221), file upload / filename / extension (220), HTTP method / verb tampering (200) |
| `bbhunt-authz-bypass` | 1386 | 24% | admin / privileged-role context (514), public source-code / repo review (230), Content-Type / body-format switch (165), encoding / double-encode / null byte (152) |
| `bbhunt-other` | 1226 | 20% | public source-code / repo review (189), encoding / double-encode / null byte (146), admin / privileged-role context (144), internal service / port / container (139) |
| `bbhunt-auth-bypass` | 989 | 20% | admin / privileged-role context (162), encoding / double-encode / null byte (107), Content-Type / body-format switch (98), header injection (Host / X-Forwarded / etc.) (86) |
| `bbhunt-logic-and-design` | 931 | 14% | encoding / double-encode / null byte (132), public source-code / repo review (96), Content-Type / body-format switch (95), header injection (Host / X-Forwarded / etc.) (91) |
| `bbhunt-memory-corruption` | 892 | 33% | public source-code / repo review (232), WAF / sanitizer / filter bypass (209), race / concurrency / timing (201), HTTP method / verb tampering (150) |
| `bbhunt-crypto-and-secrets` | 562 | 15% | public source-code / repo review (154), internal service / port / container (87), JWT / token / base64 decode (55), subdomain / DNS / cert-transparency recon (54) |
| `bbhunt-csrf` | 541 | 17% | encoding / double-encode / null byte (83), Content-Type / body-format switch (78), header injection (Host / X-Forwarded / etc.) (73), intercept & replay request in Burp (56) |
| `bbhunt-idor` | 382 | 23% | two-account / cross-account replay (102), admin / privileged-role context (74), encoding / double-encode / null byte (56), header injection (Host / X-Forwarded / etc.) (52) |
| `bbhunt-open-redirect` | 360 | 21% | redirect chain / Location header (161), encoding / double-encode / null byte (44), webhook / OAuth / SAML / integration abuse (36), header injection (Host / X-Forwarded / etc.) (35) |
| `bbhunt-ssrf` | 337 | 31% | internal service / port / container (131), public source-code / repo review (66), header injection (Host / X-Forwarded / etc.) (60), encoding / double-encode / null byte (60) |
| `bbhunt-sqli` | 331 | 25% | second-order / stored / blind delivery (68), encoding / double-encode / null byte (61), header injection (Host / X-Forwarded / etc.) (52), admin / privileged-role context (51) |
| `bbhunt-path-traversal` | 300 | 17% | public source-code / repo review (113), internal service / port / container (85), file upload / filename / extension (68), admin / privileged-role context (65) |
| `bbhunt-mfa-and-passwords` | 159 | 18% | fuzzing / wordlist brute force (51), intercept & replay request in Burp (31), admin / privileged-role context (21), encoding / double-encode / null byte (19) |
| `bbhunt-clickjacking` | 153 | 7% | HTTP method / verb tampering (14), DOM / HTML source inspection (13), XML / SOAP / SAML / XXE (12), public source-code / repo review (9) |
| `bbhunt-crlf-injection` | 115 | 17% | internal service / port / container (31), encoding / double-encode / null byte (30), header injection (Host / X-Forwarded / etc.) (26), WAF / sanitizer / filter bypass (23) |
| `bbhunt-session` | 112 | 16% | unauthenticated / removed-cookie test (14), admin / privileged-role context (14),  HosT/absolute-URL reset poisoning (13), cache / CDN / unkeyed header (11) |
| `bbhunt-request-smuggling` | 97 | 31% | parser confusion / normalization (61), encoding / double-encode / null byte (46), cache / CDN / unkeyed header (39), JS bundle / source-map inspection (39) |
| `bbhunt-subdomain-takeover` | 72 | 17% | subdomain / DNS / cert-transparency recon (56), cache / CDN / unkeyed header (7), public source-code / repo review (6), webhook / OAuth / SAML / integration abuse (4) |
| `bbhunt-deserialization` | 69 | 29% | deserialization / gadget chain (34), public source-code / repo review (25), internal service / port / container (14), file upload / filename / extension (11) |
| `bbhunt-dos` | 66 | 27% | internal service / port / container (14), public source-code / repo review (14), HTTP method / verb tampering (10), file upload / filename / extension (10) |
| `bbhunt-race-condition` | 65 | 22% | race / concurrency / timing (43), intercept & replay request in Burp (17), encoding / double-encode / null byte (14), public source-code / repo review (14) |
| `bbhunt-account-takeover` | 64 | 16% | subdomain / DNS / cert-transparency recon (9), admin / privileged-role context (9),  HosT/absolute-URL reset poisoning (7), employee / developer public info (7) |
| `bbhunt-file-upload` | 55 | 22% | file upload / filename / extension (43), second-order / stored / blind delivery (10), JWT / token / base64 decode (6), HTTP method / verb tampering (6) |
| `bbhunt-mobile` | 49 | 29% | admin / privileged-role context (8), file upload / filename / extension (7), XML / SOAP / SAML / XXE (5), two-account / cross-account replay (4) |
| `bbhunt-xxe` | 42 | 21% | XML / SOAP / SAML / XXE (22), encoding / double-encode / null byte (12), Content-Type / body-format switch (8), file upload / filename / extension (8) |
| `bbhunt-oauth-oidc` | 40 | 20% | webhook / OAuth / SAML / integration abuse (15), admin / privileged-role context (11), internal service / port / container (9), public source-code / repo review (7) |
| `bbhunt-web-cache` | 30 | 30% | cache / CDN / unkeyed header (21), header injection (Host / X-Forwarded / etc.) (13), encoding / double-encode / null byte (11), JS bundle / source-map inspection (6) |
| `bbhunt-prototype-pollution` | 14 | 0% | public source-code / repo review (9), HTTP method / verb tampering (2), deserialization / gadget chain (1), third-party data / paste / breach reuse (1) |
| `bbhunt-graphql` | 13 | 15% | API docs / Swagger / introspection (4), public source-code / repo review (3), admin / privileged-role context (3), race / concurrency / timing (3) |
| `bbhunt-ssti` | 7 | 14% | admin / privileged-role context (1), internal service / port / container (1), template injection (SSTI) (1) |
| `bbhunt-llm-ai` | 5 | 0% | parser confusion / normalization (3), public source-code / repo review (3), encoding / double-encode / null byte (2), two-account / cross-account replay (1) |
