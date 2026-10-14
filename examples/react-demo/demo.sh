#!/bin/sh
# task demo: the demo API (8097) and the Vite app (5180) together, with zero
# setup. The SQLite file (react-demo.db here) is created, migrated and seeded
# on start. Ctrl-C stops both.
set -eu

DIR="$(cd "$(dirname "$0")" && pwd)"
API_PORT=8097
WEB_PORT=5180
URL="http://localhost:$WEB_PORT"
API_PID=""
WEB_PID=""

for p in "$API_PORT" "$WEB_PORT"; do
  if lsof -nP -iTCP:"$p" -sTCP:LISTEN >/dev/null 2>&1; then
    echo "Port $p is in use (is the demo already running?). Stop that process first." >&2
    exit 1
  fi
done
[ -d "$DIR/web/node_modules" ] || { echo "Run task ui:install once first." >&2; exit 1; }

cleanup() {
  [ -n "$WEB_PID" ] && kill "$WEB_PID" 2>/dev/null || true
  [ -n "$API_PID" ] && kill "$API_PID" 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 130' INT TERM

mkdir -p "$DIR/.bin"
(cd "$DIR/.." && GOFLAGS=-mod=mod go build -o "$DIR/.bin/react-demo" ./react-demo)
(cd "$DIR" && DEMO_DB="$DIR/react-demo.db" PORT="$API_PORT" APP_URL="$URL" exec ./.bin/react-demo) &
API_PID=$!
(cd "$DIR/web" && DEMO_WEB_PORT="$WEB_PORT" DEMO_API_PORT="$API_PORT" exec pnpm exec vite --logLevel warn) &
WEB_PID=$!

i=0
until curl -s -o /dev/null "http://localhost:$API_PORT/dev/mail" && curl -s -o /dev/null "$URL/"; do
  i=$((i + 1)); [ "$i" -gt 120 ] && { echo "The demo did not start in 60s." >&2; exit 1; }
  sleep 0.5
done
cat <<MSG

  ubgo/auth React demo is running:  $URL
  Sign in as ada@example.com / correct horse battery staple
  Mail goes to the demo Inbox:      $URL/inbox
  Ctrl-C stops both servers.

MSG
wait
