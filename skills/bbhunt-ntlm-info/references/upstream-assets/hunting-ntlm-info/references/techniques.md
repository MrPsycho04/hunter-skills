# ntlm-info — Technique reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete technique.

---

## Bypass Techniques



This skill describes a disclosure leak, not an authentication bypass. The "bypass" question is: *how do defenders block this AV-pair leak while still allowing legitimate NTLM auth?*



| Defense | Effectiveness |

|---|---|

| **Disable NTLM on the public IIS binding entirely** (Forms-only) | Best — eliminates the surface |

| **IIS Extended Protection = Required** | Restricts NTLM challenge to authenticated callers; AV-pair leak mitigated |

| **Reverse-proxy strip `WWW-Authenticate` from anonymous responses** | Sometimes works but breaks legitimate clients |

| **Rate-limit the Type-1 → Type-2 endpoint** | Doesn't prevent disclosure, only slows enumeration |

| **Rename the Windows host from `WIN-XXXXXXXXXXX`** | Removes the "lazy provisioning" tell; doesn't stop the leak |

| **Move the SP/Exchange farm to a child AD with no cross-trust to corporate** | Mitigates the *forest disclosure*; doesn't stop the leak |



For the attacker: there's no "bypass" needed — the leak is the finding.



---
