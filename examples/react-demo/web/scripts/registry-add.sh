#!/bin/sh
# Installs registry items into the demo exactly as an app would
# (shadcn add @ubgo/<item>), serving the built registry
# (clients/react/registry/r) on 127.0.0.1:5181 for the duration, because
# shadcn reads a registry over HTTP only. components.json maps @ubgo there.
# Usage: registry-add.sh @ubgo/sign-in-form [@ubgo/...]
set -eu

PORT=5181
WEB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REG_DIR="$(cd "$WEB_DIR/../../../clients/react/registry/r" && pwd)"
[ "$#" -gt 0 ] || { echo "usage: $0 @ubgo/<item> [...]" >&2; exit 2; }

python3 -m http.server "$PORT" --bind 127.0.0.1 -d "$REG_DIR" >/dev/null 2>&1 &
SRV=$!
trap 'kill "$SRV" 2>/dev/null || true' EXIT INT TERM
i=0
until curl -s -o /dev/null "http://127.0.0.1:$PORT/registry.json"; do
  i=$((i + 1)); [ "$i" -gt 20 ] && { echo "FAIL: registry server did not start" >&2; exit 1; }
  sleep 0.25
done
cd "$WEB_DIR" && pnpm exec shadcn add -y --overwrite "$@"
