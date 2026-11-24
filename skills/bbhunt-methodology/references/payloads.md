# Payloads — Bug-bounty methodology orchestrator

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

### hunting / references/payloads.md

# HackerOne hunting corpus — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

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
