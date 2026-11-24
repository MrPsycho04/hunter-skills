---
name: bbhunt-mid-engagement-ir-detection
description: "Unified methodology for mid engagement ir detection.. Unified from 2 upstream skills (cbh, hunting). For authorized security testing only."
agent_created: true
---

# Mid Engagement Ir Detection — unified methodology

> **Unified skill.** Built from 2 upstream skills across cbh, hunting. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Unified upstream methodology (deduplicated)

### Signals and surfaces

### The "single signal recanted" rule

If a confirmed-vulnerable finding stops reproducing:

1. **DO NOT delete the original PoC.** Original timestamps + payloads + response captures are forever.
2. **Capture the new state in detail.** What's the recheck response? What's different?
3. **Try at least 3 alternative vectors** before declaring "indeterminate".
4. **If none restore the signal**, document as "vulnerability confirmed at T0, mitigation observed at T0+<delta>, mitigation depth: [WAF | code]".
5. **Both states go in the report.** The original finding + the IR observation.

This is the discipline that distinguishes professional red team from "hobbyist scanning". Your client wants the timeline of vulnerability + mitigation, not just the static state.

---

### Techniques, payloads and bypasses

### Observation 1 — Mid-engagement WAF rule deployment

**Symptoms:**
- Original payloads return identical response → no signal at all on recheck
- Body size identical to baseline (login page reflection)
- Timing reverts to baseline regardless of payload
- New cookie or header in responses (e.g., `cf-bm`, `__cf_bm`, `awselb`)
- Specific keyword in URL/body now triggers different response code (403, 406, 429)

**Confirmation:** retry with WAF-evasion variants:
- URL-encode the payload differently (`%27` vs `%5cu0027`)
- Change request method (POST → PUT, GET → POST)
- Different content-type (form-urlencoded → multipart)
- Slower pace (5s → 60s between requests)
- Mixed-case keywords (`SLEEP` → `SlEeP`)

If WAF-evasion variants restore the signal, the mitigation is at the WAF layer (bypassable).

If even WAF-evasion variants stay blocked, the mitigation is likely in code.

**Finding template:**
```
Subject: Mid-engagement mitigation deployed for <vulnerability X>
Observation: At engagement timestamp T0, vulnerability <X> on <endpoint> was
confirmed via <PoC>. At T0+<minutes>, recheck via the original payload no longer
reproduces the timing/error/size differential. <WAF-evasion variant> [does/does
not] restore the signal.

Description: This pattern is consistent with the client SOC observing engagement
traffic and deploying a mitigation in real time. Mitigation depth assessment:
[at-WAF, bypassable] vs [in-code, durable].

Impact (positive): Client SOC has both detection-grade visibility into application
traffic AND the authority to deploy mitigations within ~<minutes> of dete

### State diff — the key technique

Maintain three pieces of state:

### Escalation and related chains

### Related Skills & Chains

- **`redteam-mindset`** — This skill is a specific application of the broader red-team discipline. Engagement flow: `redteam-mindset` loaded at engagement start → baseline-capture habit built in → when response patterns shift mid-test, `mid-engagement-ir-detection` activates to capture the SOC-patch state as a NEW finding (defensive-action observed = client capability metric, not "the bug got fixed so we lose the finding").
- **`evidence-hygiene`** — Mid-engagement IR detection produces TWO states (pre-patch and post-patch); both need disciplined evidence capture or the second finding can't be defended. Engagement flow: baseline screenshots + timestamped request/response dumps at session start → response shift detected → second capture set with explicit timestamp delta → both packaged together.
- **`m365-entra-attack`** — The single richest source of mid-engagement IR signal in modern engagements. Engagement flow: M365 spray triggers AADSTS50053 lockout → baseline lockout policy captured → if lockout window changes mid-test (e.g., from 60min to 24hr) → `mid-engagement-ir-detection` captures the policy change as a finding ("CA policy hardened mid-engagement; defensive response measured").
- **`enterprise-vpn-attack`** + **`vmware-vcenter-attack`** — Critical-infrastructure CVE exploitation is the highest-noise activity; expect SOC to patch within hours. Engagement flow: confirmed VPN/vCenter CVE → baseline capture BEFORE exploitation attempt → if appliance updates mid-test, capture as defensive-action finding → report both the original CVE AND th

### Tools and wordlists

### Tooling — automated state-change detection

```bash
# Bash watcher — runs every 5 min during engagement, alerts on shifts

cd "$ENGAGEMENT_DIR"

# Re-measure baseline timing on key targets
for target in "$@"; do
  ms=$(curl -sk -o /dev/null -w "%{time_total}" "$target" --max-time 30)
  ms_int=$(echo "$ms * 1000" | bc | cut -d. -f1)
  echo "$(date -u +%FT%TZ) $target $ms_int" >> baseline_history.log
done

# Diff against pre-session baseline
python3 - << 'PY'
import json, time
baseline = json.load(open("engagement_log/baseline.json"))
for line in open("baseline_history.log"):
    parts = line.strip().split()
    ts, target, ms = parts[0], parts[1], int(parts[2])
    if target in baseline["targets"]:
        pre = baseline["targets"][target]["baseline_response_time_ms"]
        if abs(ms - pre) > pre * 0.5:  # >50% shift
            print(f"ALERT {ts} {target} time {pre} -> {ms}")
PY
```

For lockout-count tracking on M365:
```bash
# Run every 30 min during M365 spray
LOCK_COUNT=$(grep -c '"AADSTS50053"' engagement_log/o365_results.jsonl)
echo "$(date -u +%FT%TZ) lockout_count $LOCK_COUNT" >> lockout_history.log
# Diff first vs last to surface delta
```

---

## Source skills merged into this topic

- `hunting` — `mid-engagement-ir-detection`
- `cbh` — `mid-engagement-ir-detection`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `references/upstream-assets/` — 1 companion files (payload/technique references, scripts, validators and schemas) from the contributing skills
- `references/unified-method.md` — includes 1 merged companion methodology documents
- `../../upstream/` — complete unmodified archives of all five source repositories
- `bbhunt-methodology` — orchestrator, state machine and class router
