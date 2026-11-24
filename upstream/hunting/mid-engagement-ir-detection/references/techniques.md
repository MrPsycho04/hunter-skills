# mid-engagement-ir-detection — Technique reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete technique.

---

## State diff — the key technique



Maintain three pieces of state:



### 1. `engagement_log/baseline.json` — captured at session start



```json

{

  "ts": "2026-05-08T13:00:00",

  "source_ip": "<operator-src-ip>",

  "targets": {

    "https://target.example.com/login": {

      "baseline_response_time_ms": 584,

      "baseline_response_size_bytes": 11966,

      "headers_seen": ["Server: Apache", "X-Powered-By: PHP/8.0.26"],

      "set_cookie_names": ["PHPSESSID"]

    }

  },

  "m365": {

    "lockout_count": 247,

    "valid_creds_count": 0

  }

}

```



### 2. `engagement_log/journal.jsonl` — append-only test log



Every test logs:

```jsonl

{"ts":"...","ip":"...","tool":"...","target":"...","payload":"...","resp_code":...,"resp_size":...,"resp_ms":...,"verdict":"...","notes":"..."}

```



### 3. `engagement_log/state_changes.jsonl` — observed deltas



When a state change is detected, append:

```jsonl

{"ts_observed":"2026-05-08T14:30:00","change_type":"baseline_time_shift","target":"https://<employee-app-host>/<app>/login.php","baseline_pre_ms":24412,"baseline_post_ms":90403,"interpretation":"likely WAF rule deployed","actions_taken":["tested WAF-evasion variants — no signal restoration","documented as IR-mitigation finding"]}

```



This third file is your finding evidence. Every entry is a candidate finding.



---
