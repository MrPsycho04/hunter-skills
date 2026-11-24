# Bug Hunting & Security Research Skills

A curated collection of reusable skills, methodologies, and checklists for
bug bounty hunting and security research, maintained by
[MrPsycho04](https://www.linkedin.com/in/abdelrahmaneid1) of **Bugmith Research**.

> ⚠️ **For authorized testing only.** Use these skills only against targets
> you own or have explicit written permission to test (e.g., in-scope
> bug bounty programs). Always read and follow the program's scope and rules.

## What is a skill?

A skill is a self-contained, repeatable playbook for one task or vulnerability
class: when to use it, how to execute it, what to look for, and how to
report it. Each lives in its own folder with a `SKILL.md`.

## Repository layout

```
skills/
├── recon/
│   ├── subdomain-enumeration/SKILL.md
│   └── js-analysis/SKILL.md
├── web/
│   ├── oauth-2-flows/SKILL.md
│   ├── idor-bola/SKILL.md
│   ├── ssrf/SKILL.md
│   └── xss/SKILL.md
├── api/
├── mobile/
├── reporting/
│   └── writing-good-reports/SKILL.md
└── templates/
    └── SKILL_TEMPLATE.md
```

## Skill index

| Skill | Category | Covers | Status |
|-------|----------|--------|--------|
| oauth-2-flows | Web | redirect_uri, state, PKCE, token leakage | Draft |
| idor-bola | Web/API | Object-level authorization testing | Stable |
| writing-good-reports | Reporting | Clear, reproducible reports | Stable |

## Usage

- **Manual:** open a skill's `SKILL.md` and follow the checklist.
- **With an AI assistant:** point your tool at the skill folder so it can
  follow the steps as context.

## Anatomy of a skill

Each `SKILL.md` includes:

- **Purpose**: what vulnerability class or task it covers
- **When to use**: signals that this skill applies
- **Prerequisites**: tools, access, setup
- **Methodology**: step-by-step testing approach
- **Common pitfalls and false positives**
- **Impact and severity guidance**
- **Reporting tips**: how to write it up
- **References**: OWASP, RFCs, writeups

## Community

This project is part of **Bugmith Research**, a community of bug hunters and
security researchers sharing techniques, findings, and feedback.

- Website / Discord / Telegram: <add link here>
- Found a gap or have a technique to share? Open an issue or PR.

## Contributing

1. Copy `templates/SKILL_TEMPLATE.md`
2. Keep skills focused: one vuln class or task per skill
3. Include only techniques that are safe for in-scope testing
4. No real target data, credentials, or undisclosed vulnerabilities
5. Open a PR

## Roadmap

- [ ] SSRF skill
- [ ] XSS skill
- [ ] Mobile testing skills
- [ ] Report templates per platform

## Disclaimer & License

Provided for educational and authorized security testing. The authors and
Bugmith Research are not responsible for misuse. Licensed under MIT.
