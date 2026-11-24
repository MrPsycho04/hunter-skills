# Payloads — Enterprise VPN appliance attack matrix

Payload lists and probe banks. Methodology and usage are in the parent SKILL.md.

## Payload references from upstream skills (deduplicated)

### hunting / references/payloads.md

# enterprise-vpn-attack — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

## Nuclei templates for fast triage



Nuclei has high-quality templates for most of the above CVEs. Single command sweeps:



```bash

nuclei -u https://target/ \

  -tags vpn,cisco-asa,fortinet,citrix,palo-alto,pulse-secure,sonicwall,f5 \

  -severity high,critical -rl 5

```



Add `-as` (auto-scan) for broader vuln coverage but slower.



---
