# m365-entra-attack — Technique reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete technique.

---

## Conditional Access bypass options (most blocked, document anyway)



| Vector | Status (2026) | Notes |

|---|---|---|

| Different ROPC client_id (Microsoft Graph PowerShell vs Azure CLI vs Office) | Sometimes works | CA can be per-app; try `1b730954-1685-4b74-9bfd-dac224a7b894` (Graph PS), `04b07795-8ddb-461a-bbee-02f9e1bf7b46` (Azure CLI), `d3590ed6-52b3-4102-aeff-aad2292ab01c` (Office) |

| Different resource (graph.microsoft.com / outlook.office.com / management.azure.com) | Sometimes works | CA scope can be per-resource |

| EWS / IMAP / POP3 / SMTP Basic Auth | Mostly disabled | MS deprecated Basic Auth Oct 2022; per-account exceptions exist |

| FOCI (Family of Client IDs) | Token-refresh path | Use a refresh token from one FOCI client to mint tokens for another |

| Device-code phishing | Works | Requires user-side interaction (OOS for many engagements) |

| Compliant-device emulation | Hard | Requires Intune device registration — high effort, often impossible without insider |

| AiTM session-cookie steal | Works (with phishing) | Modern primary technique — out of scope for non-phishing engagements |

| FOCI + Family Refresh Token Theft | Post-auth | Requires already having a token |

| SAML SSO via different SP | Sometimes | Each enterprise app has its own CA policy; an app with weaker CA = pivot |

| Geo-bypass via VPN | Sometimes | If "trusted location" CA policy includes corp HQ IPs, use a VPN exit there |



**Key insight from this engagement:** in a tenant with universal CA policy (compliant device + MFA), all the above paths return AADSTS53003 with the same flow. The cred is valid, but unusable from external. **Phishing-completed cookie steal is the only realistic adversary path.** Document this clearly so the client understands the threat model.



---
