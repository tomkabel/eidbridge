#!/usr/bin/env bash
# Build the stack, run e2e.py, print timings, tear down. Needs docker, curl, python3.
#   EXTRA_CA_FILE=$HOME/.ccr/ca-bundle.crt ./run-e2e.sh   (behind a TLS-intercepting proxy)
set -euo pipefail
cd "$(dirname "$0")"

PLUGIN_VERSION=3.11.5
PLUGIN_SHA256=81a2940e4b7bf85f08310d23bb1671b703bb023f44ae17afeb780ecdc77452dd
ZIP=.cache/daggerhart-openid-connect-generic.$PLUGIN_VERSION.zip
export WP_CLIENT_SECRET="${WP_CLIENT_SECRET:-$(head -c 48 /dev/urandom | od -An -tx1 | tr -d ' \n')}"
export EXTRA_CA_FILE="${EXTRA_CA_FILE:-/dev/null}"
export COMPOSE_PROJECT_NAME=eidbridge-wordpress

mkdir -p .cache
if [ ! -f "$ZIP" ]; then
  curl -fsSL -o "$ZIP" "https://downloads.wordpress.org/plugin/daggerhart-openid-connect-generic.$PLUGIN_VERSION.zip"
fi
echo "$PLUGIN_SHA256  $ZIP" | sha256sum -c -

now() { date +%s.%N; }
t0=$(now)
cleanup() { docker compose down -v --remove-orphans >/dev/null 2>&1 || true; echo "compose down done"; }
trap cleanup EXIT

docker compose down -v --remove-orphans >/dev/null 2>&1 || true
docker compose build eidbridge
t1=$(now)
docker compose up -d db wordpress eidbridge
docker compose run --rm provision
t2=$(now)
status=0
python3 -I e2e.py || status=$?
t3=$(now)
if [ "$status" -ne 0 ]; then docker compose logs --tail 60 eidbridge wordpress || true; fi
printf 'timings: build %.1fs, up+provision %.1fs, e2e %.1fs, total %.1fs\n' \
  "$(echo "$t1 - $t0" | bc)" "$(echo "$t2 - $t1" | bc)" "$(echo "$t3 - $t2" | bc)" "$(echo "$t3 - $t0" | bc)"
exit "$status"
