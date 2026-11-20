#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# End-to-end demo: offline mock + bridge, sign a sample file as ASiC-E / XAdES-B through the
# signing API, validate it, check it without DSS, then tamper with it and show the rejection.
# Needs: Go (GOTOOLCHAIN=local), Java 17+, Maven (Maven Central on first build), Python 3 with
# lxml and cryptography. Uses ports 18590 (mock) and 18591 (bridge) on 127.0.0.1 only.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
WORK="$(mktemp -d /tmp/eidbridge-signing.XXXXXX)"
PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

export GOTOOLCHAIN=local
SECRET="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"   # >= 32 chars, never written to the repo
export EIDBRIDGE_CLIENT_SECRET="$SECRET"
SIGNER="PNOEE-40404040009"   # SK's published demo test code: synthetic identity

echo "== build"
(cd "$ROOT" && go build -o "$WORK/eidbridge" ./cmd/eidbridge && go build -o "$WORK/eidbridge-mock" ./cmd/eidbridge-mock)
(cd "$HERE" && mvn -q -B package)

cat > "$WORK/clients.json" <<JSON
[{"client_id":"signer","client_secret":"$SECRET","token_endpoint_auth_method":"client_secret_basic",
  "redirect_uris":["http://localhost:8081/callback"],"sub_mode":"pairwise","sector_id":"localhost","signing_allowed":true}]
JSON
chmod 600 "$WORK/clients.json"

echo "== start mock (18590) and bridge (18591)"
"$WORK/eidbridge-mock" --listen 127.0.0.1:18590 --ca-out "$WORK/ca.pem" >"$WORK/mock.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 50); do [ -s "$WORK/ca.pem" ] && break; sleep 0.2; done
mkdir -m 700 "$WORK/keys"
(cd "$WORK" && \
 EIDBRIDGE_SMARTID_ENV=mock EIDBRIDGE_SMARTID_BASE_URL=http://127.0.0.1:18590/smart-id-rp \
 EIDBRIDGE_SMARTID_AUTH_CA_DIR="$WORK" EIDBRIDGE_SIGNING_ENABLED=true \
 EIDBRIDGE_CLIENTS_FILE="$WORK/clients.json" EIDBRIDGE_KEY_DIR="$WORK/keys" \
 EIDBRIDGE_ISSUER=http://localhost:18591 EIDBRIDGE_LISTEN=127.0.0.1:18591 \
 exec "$WORK/eidbridge" serve --demo >"$WORK/bridge.log" 2>&1) &
PIDS+=($!)
for _ in $(seq 50); do grep -q "signing digest relay enabled" "$WORK/bridge.log" 2>/dev/null && break; sleep 0.2; done
grep -q "signing digest relay enabled" "$WORK/bridge.log" || { echo "bridge did not start"; cat "$WORK/bridge.log"; exit 1; }

JAR="$HERE/target/signing-asice.jar"
echo "== sign $HERE/sample.txt"
java -jar "$JAR" sign --bridge http://127.0.0.1:18591 --client-id signer --signer "$SIGNER" \
  --ca "$WORK/ca.pem" --in "$HERE/sample.txt" --out "$WORK/sample.asice"

echo "== validate (DSS; synthetic root as trust anchor; revocation checks off: the mock has no OCSP)"
java -jar "$JAR" validate --in "$WORK/sample.asice" --root "$WORK/ca.pem" --no-revocation true

echo "== validate with DSS default policy (revocation data required)"
java -jar "$JAR" validate --in "$WORK/sample.asice" --root "$WORK/ca.pem" || true

echo "== structural check without DSS"
python3 -I "$HERE/check_container.py" "$WORK/sample.asice"

echo "== negative: tamper one byte of sample.txt inside the container"
python3 -I "$HERE/tamper.py" "$WORK/sample.asice" "$WORK/tampered.asice" sample.txt
if java -jar "$JAR" validate --in "$WORK/tampered.asice" --root "$WORK/ca.pem" --no-revocation true; then
  echo "UNEXPECTED: tampered container validated"; exit 1
fi
if python3 -I "$HERE/check_container.py" "$WORK/tampered.asice"; then
  echo "UNEXPECTED: tampered container passed the structural check"; exit 1
fi
echo "== done: tampered container rejected by both checks"
