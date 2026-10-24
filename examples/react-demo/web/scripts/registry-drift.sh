#!/bin/sh
# Fails when a component the demo installed differs from its registry source,
# so an edit to clients/react/registry that was never re-installed (or a
# hand edit in the demo) is caught. Fix: task ui:add ITEMS="@ubgo/<item>".
set -eu

WEB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REG="$(cd "$WEB_DIR/../../../clients/react/registry" && pwd)"
status=0
for src in "$REG"/ui/*.tsx "$REG"/auth/*.tsx; do
  kind="$(basename "$(dirname "$src")")"
  name="$(basename "$src")"
  [ "$kind" = "auth" ] && dest="$WEB_DIR/src/components/auth/$name" || dest="$WEB_DIR/src/components/ui/$name"
  [ -f "$dest" ] || continue # not installed in the demo
  # shadcn add usually drops a leading "use client" in a non-RSC app
  # (components.json rsc: false) but not always, so either form matches.
  if ! cmp -s "$src" "$dest" && ! sed -e '1{/^"use client"$/d;}' "$src" | sed -e '1{/^$/d;}' | cmp -s - "$dest"; then
    echo "DRIFT: $dest differs from registry/$kind/$name"
    status=1
  fi
done
[ "$status" -eq 0 ] && echo "demo components match the registry"
exit "$status"
