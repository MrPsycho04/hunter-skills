#!/usr/bin/env bash
# Install the HackerOne skills into OpenCode's global skill directory.
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST="${OPENCODE_SKILL_DIR:-$HOME/.config/opencode/skill}"
MODE="${1:-link}"

mkdir -p "$DEST"

n=0
for d in "$SRC"/hackerone-*; do
  [ -d "$d" ] || continue
  name="$(basename "$d")"
  if [ "$MODE" = "--copy" ]; then
    rm -rf "$DEST/$name"
    cp -R "$d" "$DEST/$name"
  else
    ln -sfn "$d" "$DEST/$name"
  fi
  n=$((n + 1))
done

echo "Installed $n skills into $DEST"
if [ "$MODE" = "--copy" ]; then
  echo "Copied files. Re-run after pulling updates."
else
  echo "Symlinked. git pull updates them in place."
fi
