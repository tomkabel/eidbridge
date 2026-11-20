#!/bin/sh
# Clean build of the demo stack, then a scripted login; prints timings.
set -eu
cd "$(dirname "$0")/.."
start=$(date +%s)
docker compose up --build -d --wait 2>/dev/null || docker compose up --build -d
for i in $(seq 1 60); do
  curl -fsS http://localhost:8080/healthz >/dev/null 2>&1 && curl -fsS http://localhost:8081/ >/dev/null 2>&1 && break
  sleep 1
done
up=$(date +%s)
echo "stack up in $((up - start))s"
python3 scripts/e2e-demo.py http://localhost:8081
