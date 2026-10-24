#!/bin/sh
# Runs a command against a throwaway demo: the Go API (built from
# examples/react-demo, its SQLite file in a temporary directory) and the Vite
# dev server, on ports of their own so a dev session on 5180/8097 keeps
# running. The server seeds the demo user itself; runs "$@" with DEMO_URL set, then stops both
# servers and removes the directory, also on failure.
set -eu

WEB_PORT="${SHOTS_WEB_PORT:-5182}"
API_PORT="${SHOTS_API_PORT:-8098}"
WEB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
EXAMPLES_DIR="$(cd "$WEB_DIR/../.." && pwd)"
WORK="$(mktemp -d)"
API_PID=""
WEB_PID=""

cleanup() {
  [ -n "$WEB_PID" ] && kill "$WEB_PID" 2>/dev/null || true
  [ -n "$API_PID" ] && kill "$API_PID" 2>/dev/null || true
  wait 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

# wait_for URL: polls until the URL answers, for up to 30 seconds.
wait_for() {
  i=0
  until curl -s -o /dev/null "$1"; do
    i=$((i + 1))
    [ "$i" -gt 60 ] && { echo "FAIL: $1 did not answer in 30s" >&2; exit 1; }
    sleep 0.5
  done
}

(cd "$EXAMPLES_DIR" && GOFLAGS=-mod=mod go build -o "$WORK/react-demo" ./react-demo)
# A short fresh window, so a script reaches "confirm it's you" in seconds
# rather than the library's ten minutes; DEMO_FRESH_WINDOW in the caller's
# environment wins.
FRESH_WINDOW="${DEMO_FRESH_WINDOW:-8s}"
(cd "$WORK" && PORT="$API_PORT" APP_URL="http://localhost:$WEB_PORT" DEMO_FRESH_WINDOW="$FRESH_WINDOW" exec ./react-demo >"$WORK/api.log" 2>&1) &
API_PID=$!
(cd "$WEB_DIR" && DEMO_WEB_PORT="$WEB_PORT" DEMO_API_PORT="$API_PORT" exec pnpm exec vite --logLevel warn >"$WORK/web.log" 2>&1) &
WEB_PID=$!

wait_for "http://localhost:$API_PORT/auth/oauth/providers"
wait_for "http://localhost:$WEB_PORT/"
export DEMO_URL="http://localhost:$WEB_PORT" DEMO_FRESH_WINDOW="$FRESH_WINDOW"
"$@"
