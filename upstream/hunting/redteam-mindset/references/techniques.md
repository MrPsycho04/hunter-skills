# redteam-mindset — Technique reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete technique.

---

## Mindset correction #7 — Multi-technique cross-validation



For every "vulnerable" finding, prove via 2+ techniques:



| Vuln class | Primary | Cross-check |

|---|---|---|

| Time-based blind SQLi | SLEEP() differential | Different SLEEP variants (3 distinct payloads min) |

| Boolean blind SQLi | Body-size differential | Different boolean comparisons |

| Error-based SQLi | Error message reflection | UPDATEXML + EXTRACTVALUE both |

| RCE | Command output reflection | OOB callback (interactsh DNS) |

| LFI | File content reflection | Different file paths, different encodings |

| SSRF | Internal-only response | OOB callback (interactsh DNS) |

| Valid credential (M365) | ROPC + AADSTS53003 | SAML SSO browser flow + ConvergedConditionalAccess page |

| Auth bypass | Logged-in landing page | Session cookie persistence on subsequent request |



A single signal can be coincidence (network jitter, server hiccup, cache). Two distinct signals from the same root cause is definitive.



---
