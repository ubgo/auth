#!/bin/sh
# Runs a command against a throwaway API and a production Next server for
# this example, on ports of its own (8121 and 5201) so the React demo's dev
# session (8097/5180) and its own test runs (8098/5182) keep running. The API
# is the React demo's Go server (examples/react-demo): it has every plugin the
# app uses, seeds ada@example.com, and keeps mail in memory. Its SQLite file
# lives in a temporary directory. Builds the app first (next.config.ts fixes
# the /auth rewrite at build time), runs "$@" with NEXT_URL set, then stops
# both servers and removes the directory, also on failure.
set -eu

WEB_PORT="${NEXT_WEB_PORT:-5201}"
API_PORT="${NEXT_API_PORT:-8121}"
WEB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
EXAMPLES_DIR="$(cd "$WEB_DIR/.." && pwd)"
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
(cd "$WEB_DIR" && NEXT_API_PORT="$API_PORT" pnpm exec next build >"$WORK/build.log" 2>&1) || { cat "$WORK/build.log" >&2; exit 1; }
(cd "$WORK" && PORT="$API_PORT" APP_URL="http://localhost:$WEB_PORT" exec ./react-demo >"$WORK/api.log" 2>&1) &
API_PID=$!
(cd "$WEB_DIR" && NEXT_API_PORT="$API_PORT" exec pnpm exec next start --port "$WEB_PORT" >"$WORK/web.log" 2>&1) &
WEB_PID=$!

wait_for "http://localhost:$API_PORT/auth/oauth/providers"
wait_for "http://localhost:$WEB_PORT/"
export NEXT_URL="http://localhost:$WEB_PORT"
"$@"
