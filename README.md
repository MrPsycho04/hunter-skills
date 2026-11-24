# bbhunt — unified bug-bounty skill suite

A **96-skill** WorkBuddy suite for authorized bug-bounty and security testing. Every topic is a **unified skill**: all matching skills from all five reference repos are merged into one deduplicated methodology, with every original preserved alongside it. Corpus-backed topics also carry evidence mined from all 15,259 disclosed HackerOne reports.

## Start here

Invoke **`bbhunt-methodology`** first — the conductor that keeps written state, picks one topic at a time, and routes to the rest. The other skills are slices of that methodology; none is the whole thing.

```
bbhunt-methodology
├── bbhunt-recon          scope, assets, soft-404/403 control, JS/API surface
├── bbhunt-<topic>        one unified topic at a time
├── bbhunt-validate       seven-question gate and proof standards
├── bbhunt-chains         A -> B cluster hunting and escalation
└── bbhunt-report         reproducible, redacted submission
```

## What "unified" means

Each skill directory contains:

| File | Contents |
|---|---|
| `SKILL.md` | The deduplicated union of all upstream methodologies for that topic, plus the corpus-backed method (for the 34 vulnerability classes) |
| `references/unified-method.md` | Complete extracted sections from every contributing repo skill, deduplicated by content hash |
| `references/upstream-*.md` | Full, unmodified original SKILL.md from each contributing repo, with source path and attribution |
| `references/evidence.md` | Corpus technique frequencies, parameters, bypasses, case studies and payload bank (class topics only) |

Nothing from the source repos was discarded — the merge is additive and traceable.

## Sources merged

- **cloudflare/security-audit-skill** — coverage ledger, isolated verification, structured verdicts
- **MrPsycho04/hackerone-skills** — 37 corpus-generated class playbooks and payload banks
- **MrPsycho04/Hunting-Agent** — 93 skills: six-phase pipeline, seven-question gate, A -> B chains, platform specialisms
- **MrPsycho04/Research-Skills** — 10 scoped-research and validation skills
- **elementalsouls/Claude-BugHunter** — 84 skills: extended taxonomy, red-team tradecraft, reporting
- **Local corpus** — `~/.local/share/hackerone-reports/reports.sqlite`, all 15,259 disclosed reports, `tricks.py`, `payloads.py`
- **Local field notes** — `adjust-recon-notes.md`, `thredup-recon-notes.md`, `Bug_Bounty_Notes/`, `mt-*` / `h1-*` hunt notes

**225 upstream SKILL.md files** were collected and mapped into 96 canonical topics (local generated copies were verified byte-identical to repo originals and excluded).

## Validity definition

Every disclosed report is a valid, triaged finding — **paid or not**. Only 14–24% of valid reports in most classes paid a bounty. Filtering to paid reports discards most of the evidence. The corpus miner processes all 15,259 reports; bounty and severity are impact/weighting signals, never a validity filter.

## Full topic list

The orchestrator's SKILL.md contains the complete 96-skill catalog grouped by: orchestration/phases, corpus-backed vulnerability classes, web/API/protocol specialisms, framework/platform specialisms, and recon/red-team/reporting/other.

## Install / rebuild

```sh
# Skills are installed to WorkBuddy user scope:
cp -R <suite>/skills/bbhunt-* ~/.workbuddy-ai/skills/

# Rebuild after new reports or upstream changes:
python3 ~/.local/share/hackerone-reports/build.py
python3 hunter-skills/research/mine_corpus.py
python3 hunter-skills/research/build_skills.py
python3 hunter-skills/research/unify_skills.py
```

## Ethics

For authorized testing and learning only. Respect scope, rate limits and program rules. Redact other users' data. The corpus is public disclosure; report excerpts remain subject to their original disclosure terms.
