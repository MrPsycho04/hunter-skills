# Payloads — Local bug-bounty toolkit router

Payload lists and probe banks. Methodology and usage are in the parent SKILL.md.

## Payload references from upstream skills (deduplicated)

### hunting / references/payloads.md

# Bug Bounty Master Workflow — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

## Wordlists

- [SecLists](https://github.com/danielmiessler/SecLists) -- Comprehensive wordlists

- [HowToHunt](https://github.com/KathanP19/HowToHunt) -- Step-by-step vuln hunting

- [DefaultCreds](https://github.com/ihebski/DefaultCreds-cheat-sheet) -- Default credentials



## Payload Databases

- [XSSHunter](https://xsshunter.trufflesecurity.com/) -- Blind XSS detection

- [interactsh](https://app.interactsh.com) -- OOB callback server



---



# INSTALLATION (Claude Code Skill)



To use this as a Claude Code skill, copy this file to your skills directory:



```bash

# Option A: Clone the repo and link the skill

git clone https://github.com/shuvonsec/claude-bug-bounty.git ~/.claude/skills/bug-bounty

ln -s ~/.claude/skills/bug-bounty/SKILL.md ~/.claude/skills/bug-bounty/SKILL.md



# Option B: Direct copy

mkdir -p ~/.claude/skills/bug-bounty

curl -s https://raw.githubusercontent.com/shuvonsec/claude-bug-bounty/main/SKILL.md \

  -o ~/.claude/skills/bug-bounty/SKILL.md

```



Then in Claude Code, this skill loads automatically when you ask about bug bounty, recon, or vulnerability hunting.



---
