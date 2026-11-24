#!/usr/bin/env python3
"""Scaffold a bug-bounty hunt folder with the anti-drift state files.

Usage: python3 new_hunt.py <target-name> [output-dir]
Default output dir: ./hunts (relative to the current working directory).
"""
import json
import os
import sys
from datetime import datetime, timezone


def main():
    if len(sys.argv) < 2:
        print("usage: new_hunt.py <target-name> [output-dir]", file=sys.stderr)
        sys.exit(2)
    target = sys.argv[1]
    root = sys.argv[2] if len(sys.argv) > 2 else os.path.join(os.getcwd(), "hunts")
    path = os.path.join(root, target)
    os.makedirs(os.path.join(path, "findings"), exist_ok=True)
    os.makedirs(os.path.join(path, "evidence"), exist_ok=True)
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")

    files = {
        "scope.md": (
            f"# Scope — {target}\n\n"
            "- [ ] Authorization / program brief recorded\n"
            "- [ ] In-scope assets:\n"
            "- [ ] Out-of-scope assets:\n"
            "- [ ] Known issues (do NOT report):\n"
            "- [ ] Rate limit (combined across tools/threads/agents):\n"
            "- [ ] Test accounts available: yes / no\n"
            "- [ ] Rules of engagement notes:\n"
        ),
        "state.md": (
            "PHASE: SCOPE | CLASS: none | NEXT: read program brief and fill scope.md | BLOCKED: none\n\n"
            f"created: {now}\n\n"
            "## Decision log\n"
            "- \n\n"
            "## Active candidate\n"
            "none\n"
        ),
        "surface.md": (
            f"# Surface map — {target}\n\n"
            "## Live hosts / status / control signature\n\n"
            "| Host | Status | Bytes | Body hash (soft-404 control) | Tech |\n"
            "|---|---|---|---|---|\n"
            "\n## Endpoints & parameters\n\n"
            "\n## Roles / object IDs / tenants\n\n"
            "\n## Integrations (OAuth, webhooks, uploads, AI)\n\n"
        ),
        "notes.md": (
            f"# Notes — {target}\n\n"
            "## Negative results (keep these; they prevent re-work)\n\n"
            "- \n\n"
            "## Ideas / leads\n\n"
            "- \n"
        ),
        "ledger.json": json.dumps(
            {"target": target, "created": now, "units": []}, indent=2
        ) + "\n",
    }
    for name, body in files.items():
        dest = os.path.join(path, name)
        if os.path.exists(dest):
            print(f"skip existing: {dest}")
            continue
        with open(dest, "w") as f:
            f.write(body)
        print(f"created: {dest}")
    print(f"\nHunt scaffold ready at {path}")


if __name__ == "__main__":
    main()
