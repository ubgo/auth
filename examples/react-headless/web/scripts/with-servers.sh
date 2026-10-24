#!/bin/sh
# Runs a command against a throwaway API and Vite dev server for this
# example, on ports of its own (8113 and 5190) so the React demo's dev session
# (8097/5180) and its own test runs (8098/5182) keep running. The API is the
# React demo's Go server (examples/react-demo): it has every plugin the page
# uses, seeds ada@example.com, and serves a pretend OAuth provider. Its
# SQLite file lives in a temporary directory. Runs "$@" with HEADLESS_URL
# set, then stops both servers and removes the directory, also on failure.
set -eu

WEB_PORT="${HEADLESS_WEB_PORT:-5190}"
API_PORT="${HEADLESS_API_PORT:-8113}"
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
(cd "$WORK" && PORT="$API_PORT" APP_URL="http://localhost:$WEB_PORT" exec ./react-demo >"$WORK/api.log" 2>&1) &
API_PID=$!
(cd "$WEB_DIR" && HEADLESS_WEB_PORT="$WEB_PORT" HEADLESS_API_PORT="$API_PORT" exec pnpm exec vite --logLevel warn >"$WORK/web.log" 2>&1) &
WEB_PID=$!

wait_for "http://localhost:$API_PORT/auth/oauth/providers"
wait_for "http://localhost:$WEB_PORT/"
export HEADLESS_URL="http://localhost:$WEB_PORT"
"$@"
