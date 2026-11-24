---
name: bbhunt-recon
description: "Scope intake, asset discovery, soft-404/403 baselining, JavaScript and API surface mapping for authorized bug-bounty hunts. Use at the start of a hunt or when a class skill needs new endpoints, parameters, roles, or technology signals. Produces scope.md, surface.md and coverage-ledger units. Never widens scope."
agent_created: true
---

# Scope and reconnaissance

This skill executes **phases 0–1** of `bbhunt-methodology`. Its output is a surface map good enough to choose a class; it is not an end in itself. Stop recon as soon as there are enough units to hunt.

## 1. Scope intake (write it down first)

Create `scope.md` with: in-scope assets and wildcards, explicit exclusions, third-party hosted assets, CIDRs, known issues and already-reported classes, rate limits, test-account availability, and rules of engagement. Treat third-party hosting on an in-scope hostname as out of scope until confirmed. A known issue listed by the program is a **do-not-report**, not a lead.

## 2. Establish response controls before enumerating

For every live host, capture two bogus-path responses and record **status, byte length, body hash**. This is the control against which every later "found path" is judged. Repeat per path depth if the framework renders different fallbacks. Classify CDN edge denials separately — the request never reached the app.

## 3. Asset discovery (breadth, then prune)

- Passive first: certificate transparency (`crt.sh`), DNS, archived URLs (`waybackurls`, `gau`), search engines, ASNs, acquisitions, GitHub. Passive sources do not contact the target.
- Active second: `subfinder`/`amass`, `httpx` for liveness, `masscan`/`nmap` only where CIDRs are explicitly in scope.
- Correlate: identify which hosts are first-party vs third-party hosted vs dead infrastructure. The operator's notes show how a 738-host list collapsed to 6 meaningful live hosts — **pruning matters more than collection**.
- Record status distribution and host families; repeated staging/k8s families often share the same defect.

## 4. Technology fingerprinting

Follow redirects (`-L`) — IdP and CDN signals often sit behind a 30x. Pull headers **and** body markers: `__NEXT_DATA__`, `/_next/`, `VIEWSTATE`, `rO0`, `laravel_session`, `Ignition`, `Telescope`, `/actuator`, `application/grpc`, `socket.io`, `swagger`, `.js.map`. Attribute each signal to the specific host; a framework on host B says nothing about host A.

## 5. JavaScript and API surface

- Collect bundles, chunks, and source maps from live crawl and archives. Read bundler manifests by hand (webpack runtime, Next `_buildManifest.js`, Vite/Rollup manifest).
- Use JS analysis to recover: real API base URLs, hidden endpoints, feature flags, GraphQL operations, secrets, DOM sinks, `postMessage` handlers, and internal hostnames.
- Enumerate API version history (`v1`, `v2`, `beta`, `legacy`, header- and subdomain-based versions). Shadow APIs are a rich source of missing auth.
- Verify each recovered endpoint against the live app; log 401/403/404 as negative results rather than assuming exposure.

## 6. Map identity and object model

Record roles (anonymous, user, admin, service), the IDs that reference objects, and how tenancy is expressed (header, subdomain, path, claim). Two test accounts are a prerequisite for the IDOR/authz classes. Without them, mark those ledger units `blocked` rather than testing blindly.

## 7. Build the coverage ledger

One unit per `host × feature × plausible class`. Each unit: `checks[]`, `verdict`, evidence path, last touched. Seed `not-covered` units for the router. A second run should target `not-covered` and `needs-validation` first.

## 8. Corpus precedents

Before leaving recon, search the disclosures for the program and stack:

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "<program> <feature>" --limit 10
python3 ~/.local/share/hackerone-reports/h1.py search "<framework> <param>" --limit 10
```

All disclosed reports are valid; do not filter to paid. Note recurring techniques for the chosen class in `notes.md`.

## Stop conditions

- Enough units exist to pick a class → stop recon and update `state.md`.
- 15 minutes in a single recon rabbit hole → log negative and move.
- Any out-of-scope lead → stop that branch, do not pursue or record it as a finding.

## References

- `references/recon-commands.md` — command recipes, parsing tips, and the operator's field notes on host pruning and 403 passes.

## Unified upstream methodology

All 0 contributing upstream skills from  are merged and deduplicated in `references/unified-method.md`; full originals are preserved as `references/upstream-*.md`.
