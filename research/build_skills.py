#!/usr/bin/env python3
"""Generate the bbhunt-* class skills from authored slices + mined corpus evidence."""
import importlib.util
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SKILLS = os.path.join(ROOT, "skills")
CORPUS = os.path.expanduser("~/.local/share/hackerone-reports")

spec = importlib.util.spec_from_file_location("cm", os.path.join(HERE, "class_methodology.py"))
cm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cm)
CLASSES = cm.CLASSES

with open(os.path.join(HERE, "class_digest.json")) as f:
    DIGEST = json.load(f)

sys.path.insert(0, CORPUS)
from tricks import TRICKS
from payloads import PAYLOAD_BANK


def bullets(items, indent=""):
    return "\n".join(f"{indent}- {i}" for i in items) if items else f"{indent}- none"


def table(rows, head=("Item", "Count")):
    out = [f"| {head[0]} | {head[1]} |", "|---|---:|"]
    for name, count in rows:
        nm = str(name).replace("|", "\\|")
        out.append(f"| {nm} | {count} |")
    return "\n".join(out)


def build_class(cls, meta):
    d = DIGEST[cls]
    n = d["valid_reports"]
    paid = d["paid_reports"]
    pct = round(100.0 * paid / max(1, n))
    tricks = TRICKS.get(cls, {})
    bank = PAYLOAD_BANK.get(cls, [])

    desc = meta["trigger"].rstrip(".")
    full_desc = (
        f"{desc}. Class slice of the authorized bug-bounty methodology; "
        f"grounded in {n} disclosed HackerOne reports. "
        "Use when the target surface matches this vulnerability class."
    ).replace("\n", " ")
    front = (
        "---\n"
        f"name: bbhunt-{cls}\n"
        f"description: {json.dumps(full_desc)}\n"
        "agent_created: true\n"
        "---\n\n"
    )

    body = [
        f"# {meta['name']} — class slice\n",
        "> **Part, not the whole.** This is one class inside `bbhunt-methodology`. "
        "Keep `state.md` current, finish this class before loading another, and "
        "return to the orchestrator when this slice is exhausted.\n",
        "## Evidence base\n",
        f"- **{n}** disclosed (valid) reports in the local corpus; **{paid} ({pct}%)** paid a bounty.",
        "- Payment measures program policy and impact, **not validity**. Zero-bounty writeups are mined as evidence too.",
        f"- Median paid bounty: ${d['median_bounty']:.0f} (impact signal only).",
        "- Techniques below are counted across **all** valid writeups for this class.\n",
        "## When this slice applies\n",
        bullets(meta["signals"]) + "\n",
        "## Method — " + meta["name"] + " only\n",
        bullets(meta["steps"], "") .replace("- ", "1. ", 0) if False else "\n".join(
            f"{i+1}. {s}" for i, s in enumerate(meta["steps"])
        ),
        "",
        "## Corpus-ranked techniques (all valid writeups)\n",
        table(d["techniques"][:12]),
        "",
        "## Where to look\n",
        "Parameters observed in writeups: " + ", ".join(f"`{p}`" for p, _ in d["parameters"][:18]),
        "",
    ]
    if tricks.get("surface"):
        body += ["Surfaces from the field playbook:", bullets(tricks["surface"]) + "\n"]

    body += ["## Probes and payloads\n", bullets(meta["probes"]), ""]
    if tricks.get("payloads"):
        body += ["Starting payloads:", bullets(tricks["payloads"]), ""]
    if bank:
        body.append("Curated payload bank (first group; full bank in `references/evidence.md`):")
        group, payloads = bank[0]
        body.append(f"**{group}**")
        body.append("```text")
        body.extend(payloads[:18])
        body.append("```\n")

    body += ["## Bypasses observed\n"]
    if d["bypasses"]:
        body.append("Corpus frequency: " + ", ".join(f"`{k}` ({v})" for k, v in d["bypasses"][:12]))
        body.append("")
    if tricks.get("bypass"):
        body += ["Field bypass notes:", bullets(tricks["bypass"]), ""]

    body += ["## Kill criteria — stop and move on\n", bullets(meta["kill"]), ""]
    body += ["## Escalation chains\n", bullets(meta["chains"]), ""]

    tools = [t for t, _ in d["tools"][:8]]
    if tricks.get("tools"):
        tools = list(dict.fromkeys(tools + tricks["tools"]))
    body += ["## Tools\n", bullets(tools), ""]

    body += ["## Real cases (valid reports — paid and unpaid)\n"]
    for c in d["case_studies"][:3]:
        money = f"${float(c['bounty']):.0f}" if c["bounty"] else "no bounty (still valid)"
        body.append(
            f"- **[{c['id']}](https://{c['url']})** {c['program']} — {c['title']} "
            f"({money}, {c['severity'] or 'severity n/a'})"
        )
    body.append("")

    tip = meta["tip"]
    body += [f"## Veteran tip\n\n{tip}\n"]
    body += [
        "## Next action\n",
        "Record the candidate with a verdict, run `bbhunt-validate`, then `bbhunt-chains`. "
        "If nothing confirmed within the time box, mark the ledger unit `covered-negative` and return to the orchestrator.\n",
        "## References\n",
        "- `references/evidence.md` — full technique table, all mined parameters/bypasses, "
        "approach patterns, complete payload bank, and all case studies.\n",
        "- `bbhunt-methodology` — state machine, router and anti-drift rules.\n",
    ]

    skill_dir = os.path.join(SKILLS, f"bbhunt-{cls}")
    os.makedirs(os.path.join(skill_dir, "references"), exist_ok=True)
    with open(os.path.join(skill_dir, "SKILL.md"), "w") as f:
        f.write(front + "\n".join(body))

    refs = [
        f"# Evidence appendix — {meta['name']}\n",
        f"Mined from all **{n} valid disclosed reports** for this class ({paid} paid, {pct}% — "
        "payment is not validity).\n",
        "## Technique frequency (all valid writeups)\n",
        table(d["techniques"]),
        "",
        "## Tools mentioned\n",
        table(d["tools"]),
        "",
        "## Bypass primitives\n",
        table(d["bypasses"]),
        "",
        "## Impact language\n",
        table(d["impacts"]),
        "",
        "## Parameters observed\n",
        table(d["parameters"]),
        "",
        "## Recurring approach patterns\n",
    ]
    for a in d["approach_patterns"]:
        refs.append(f"- **{a['count']}×** {a['phrase']}")
        if a.get("example"):
            refs.append(f"  - e.g. {a['example'][:300]}")
    refs += ["", "## Case studies (full excerpts)\n"]
    for c in d["case_studies"]:
        money = f"${float(c['bounty']):.0f}" if c["bounty"] else "no bounty (valid finding)"
        refs += [
            f"### {c['id']} — {c['title']}",
            f"{c['program']} · {money} · {c['severity'] or 'severity n/a'} · https://{c['url']}",
            "",
            c["excerpt"][:1400],
            "",
        ]
    if bank:
        refs += ["## Full curated payload bank\n"]
        for group, payloads in bank:
            refs += [f"### {group}", "", "```text"]
            refs.extend(payloads)
            refs += ["```", ""]
    if tricks:
        refs += ["## Field playbook (unedited)\n"]
        for key in ("quick", "payloads", "bypass", "surface", "tools", "chain"):
            if tricks.get(key):
                refs.append(f"### {key}\n")
                refs += [f"- {x}" for x in tricks[key]]
                refs.append("")
    refs += [
        "## Corpus search commands\n",
        "```sh",
        f"python3 ~/.local/share/hackerone-reports/h1.py stats --class {cls}",
        f"python3 ~/.local/share/hackerone-reports/h1.py search \"<feature or param>\" --class {cls} --limit 10",
        "python3 ~/.local/share/hackerone-reports/h1.py show <id> --full",
        "```",
        "",
    ]
    with open(os.path.join(skill_dir, "references", "evidence.md"), "w") as f:
        f.write("\n".join(refs))
    return n


def build_phase_references():
    # Corpus evidence appendix to the orchestrator playbook.
    playbook = os.path.join(SKILLS, "bbhunt-methodology", "references", "hunter-playbook.md")
    with open(playbook) as f:
        text = f.read()
    if "## Corpus evidence by class" in text:
        text = text.split("## Corpus evidence by class")[0]
    lines = [
        "## Corpus evidence by class\n",
        "Valid disclosed reports, share paid, and the most frequent techniques across **all** valid writeups. "
        "Paid share is an impact/program signal, never a validity filter.\n",
        "| Class | Valid | Paid % | Top techniques |",
        "|---|---:|---:|---|",
    ]
    for cls, d in sorted(DIGEST.items(), key=lambda kv: -kv[1]["valid_reports"]):
        pct = round(100.0 * d["paid_reports"] / max(1, d["valid_reports"]))
        tops = ", ".join(f"{k} ({v})" for k, v in d["techniques"][:4])
        lines.append(f"| `bbhunt-{cls}` | {d['valid_reports']} | {pct}% | {tops} |")
    lines.append("")
    with open(playbook, "w") as f:
        f.write(text + "\n".join(lines))

    static = {
        ("bbhunt-recon", "recon-commands.md"): """# Recon command recipes

All commands assume written authorization and the program's rate limit. Run passive sources first.

```sh
# Passive: archives and certificate transparency
subfinder -d target.com -o recon/subdomains.txt
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sort -u
waybackurls target.com | sort -u > recon/wayback.txt
gau target.com | sort -u >> recon/wayback.txt

# Liveness + soft-404 control
httpx -l recon/subdomains.txt -status-code -content-length -title -o recon/live.txt
for H in $(cat recon/live-hosts.txt); do
  for P in /zzz-nope-12345 /qqq-other-98765; do
    curl -sk -m 12 -o /tmp/b -w "$H $P %{http_code} %{size_download} " "https://$H$P"
    shasum /tmp/b | cut -c1-12
  done
done

# JS collection and analysis
katana -u https://target -jc -o recon/js_urls.txt
grep -aoE 'https?://[^"\\' ]+' bundle.js | sort -u
# sourcemap: check for sourceMappingURL, then extract sourcesContent

# Fingerprint (headers AND body, follow redirects)
curl -sSL -m 12 -D - -o /tmp/body https://target | tr -d '\\r'
grep -aoE '__NEXT_DATA__|/_next/|VIEWSTATE|rO0[AB]|laravel_session|Ignition|Telescope|/actuator|swagger|\\.js\\.map' /tmp/body | sort -u
```

## Field notes (from authorized sessions)

- A 738-host passive list collapsed to 6 meaningful live hosts. **Prune before probing.**
- Third-party hosted pages on in-scope hostnames are out of scope until confirmed.
- Staging/k8s host families often share a single misconfiguration — record the family, not just the host.
- A full 403 header/path/method pass that stays 403 is a logged negative. Record the matrix and move on.
- GraphQL introspection may be disabled while the schema is still reconstructable from validation errors (`__typename` often works).
- Two test accounts unlock entire classes; without them mark IDOR/authz units blocked.
""",
        ("bbhunt-validate", "validation-matrix.md"): """# Extended validation matrix

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
""",
        ("bbhunt-chains", "chain-library.md"): """# Extended chain library

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
""",
        ("bbhunt-report", "report-examples.md"): """# Report patterns and sanitized examples

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
""",
    }
    for (skill, name), content in static.items():
        path = os.path.join(SKILLS, skill, "references", name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(content)


def main():
    assert set(CLASSES) == set(DIGEST), (
        f"class mismatch: missing={set(DIGEST)-set(CLASSES)} extra={set(CLASSES)-set(DIGEST)}"
    )
    total = 0
    for cls, meta in CLASSES.items():
        total += build_class(cls, meta)
    build_phase_references()
    print(f"generated {len(CLASSES)} class skills + 5 phase skills")
    print(f"corpus reports represented: {total}")
    print(f"output: {SKILLS}")


if __name__ == "__main__":
    main()
