#!/bin/sh
# What task docs:shots runs: the screenshots the docs embed, retaken from
# scratch. Each app gets its own throwaway API and web server through its
# with-servers.sh, on ports 8140-8143 and 5220-5223 so neither the owner's
# demo (8097/5180) nor the e2e runs (8098/5182, 8113/5190, 8120/5200,
# 8121/5201) are disturbed. docs-shots.mjs writes raw PNGs into a temporary
# directory; pngquant (when on PATH) then optipng compress them into
# docs/assets/screenshots, which replaces the old set.
set -eu

WEB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
EXAMPLES_DIR="$(cd "$WEB_DIR/../.." && pwd)"
DEST="$(cd "$EXAMPLES_DIR/.." && pwd)/docs/assets/screenshots"
SHOTS="$WEB_DIR/scripts/docs-shots.mjs"
RAW="$(mktemp -d)"
trap 'rm -rf "$RAW"' EXIT INT TERM
export SHOTS_OUT="$RAW/"

# The demo run needs the session to stay fresh through two-factor setup, so
# the fresh window is the library's ten minutes rather than the e2e's 8s.
(cd "$WEB_DIR" && SHOTS_API_PORT=8140 SHOTS_WEB_PORT=5220 DEMO_FRESH_WINDOW=10m ./scripts/with-servers.sh node "$SHOTS" demo)
(cd "$EXAMPLES_DIR/react-headless/web" && HEADLESS_API_PORT=8141 HEADLESS_WEB_PORT=5221 ./scripts/with-servers.sh node "$SHOTS" headless)
(cd "$EXAMPLES_DIR/react-router-app" && RR_API_PORT=8142 RR_WEB_PORT=5222 ./scripts/with-servers.sh node "$SHOTS" router)
(cd "$EXAMPLES_DIR/nextjs-app" && NEXT_API_PORT=8143 NEXT_WEB_PORT=5223 ./scripts/with-servers.sh node "$SHOTS" nextjs)

if command -v pngquant >/dev/null 2>&1; then
  pngquant --force --skip-if-larger --quality 70-90 --strip --ext .png "$RAW"/*.png || true
fi
if command -v optipng >/dev/null 2>&1; then
  optipng -quiet -o2 -strip all "$RAW"/*.png
fi
mkdir -p "$DEST"
rm -f "$DEST"/*.png
cp "$RAW"/*.png "$DEST"/
du -ch "$DEST"/*.png | tail -1 | sed "s|total|total in $DEST|"
