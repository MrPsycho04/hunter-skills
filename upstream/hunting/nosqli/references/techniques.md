# HUNT-NOSQLI — NoSQL Injection — Technique reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete technique.

---

## Bypass Table



| Defense | Bypass |

|---------|--------|

| JSON.parse rejects objects | Use array: `password[$ne]=x` (URL params) |

| Sanitizes `$` | Unicode: `$gt` |

| Blocks operator keys | Nested objects deeper in structure |



---
