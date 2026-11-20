#!/bin/sh
# Compare the live Smart-ID TLS SPKI pin against trust/<env>/ expectations.
# Usage: scripts/pin-check.sh demo|production   (BOGUS_PIN=true forces mismatch)
set -eu

env="${1:-}"
case "$env" in
demo | production) ;;
*)
	echo "usage: $0 demo|production" >&2
	exit 64
	;;
esac

dir="trust/$env"
hostfile="$dir/smartid-host.txt"
pinfile="$dir/smartid-tls-pins.txt"
if [ ! -f "$hostfile" ] || [ ! -f "$pinfile" ]; then
	echo "trust files missing for $env"
	exit 2
fi

host="$(head -n 1 "$hostfile" | tr -d ' \r\n')"
expected="$(grep -v '^#' "$pinfile" | grep -v '^[[:space:]]*$' | tr -d '\r' || true)"
if [ "${BOGUS_PIN:-false}" = "true" ]; then
	expected="sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
fi

observed="sha256/$(openssl s_client -connect "$host:443" -servername "$host" </dev/null 2>/dev/null |
	openssl x509 -pubkey -noout |
	openssl pkey -pubin -outform der |
	openssl dgst -sha256 -binary | base64)"

if printf '%s\n' "$expected" | grep -qxF "$observed"; then
	echo "pin OK $host"
	exit 0
fi
echo "pin MISMATCH host=$host observed=$observed expected=$(printf '%s' "$expected" | tr '\n' ',')"
exit 1
