#!/bin/sh
# NFR-004: run the fixture logins of every method with no network except
# loopback. Builds the integration test binary, then runs it inside a new
# network namespace (needs root or `sudo`; CI runs it with sudo).
set -eu
cd "$(dirname "$0")/.."
work=$(mktemp -d)  # 0700: the inner script and binary run as root
bin="$work/eidbridge-integration.test"
go test -c -o "$bin" ./cmd/eidbridge
# Warm the module and build caches for the eidbridge-mock build that
# TestBridgeAgainstStandaloneMockBinary runs offline.
go build -buildvcs=false -o "$work/eidbridge-mock" ./cmd/eidbridge-mock
cat > "$work/eidbridge-egress-inner.sh" <<EOF
set -eu
python3 - <<'PY'
import fcntl, socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
flags = struct.unpack("16sH14s", fcntl.ioctl(s, 0x8913, struct.pack("16sH14s", b"lo", 0, b"")))[1]
fcntl.ioctl(s, 0x8914, struct.pack("16sH14s", b"lo", flags | 1, b""))  # bring lo up
for host, port in [("1.1.1.1", 443), ("8.8.8.8", 53)]:
    c = socket.socket(); c.settimeout(2)
    try:
        c.connect((host, port))
        raise SystemExit("egress is not blocked: connected to %s" % host)
    except OSError as e:
        print("blocked:", host, port, "->", e)
PY
cd "$PWD/cmd/eidbridge"
# Every login test with fixture upstreams; live tests skip without EIDBRIDGE_LIVE.
rc=0
"$bin" -test.count=1 -test.v -test.run 'Login|Wallet|EUDI|WebEID|Signing|Mock|MobileID|Discovery|Headers' > "$work/eidbridge-egress.out" 2>&1 || rc=\$?
grep -E '^(--- |PASS|FAIL|ok)' "$work/eidbridge-egress.out"
[ \$rc = 0 ] || tail -n 60 "$work/eidbridge-egress.out"
exit \$rc
EOF
if [ "$(id -u)" = 0 ]; then
	unshare -n sh "$work/eidbridge-egress-inner.sh"
else
	sudo env "PATH=$PATH" "HOME=$HOME" "GOMODCACHE=$(go env GOMODCACHE)" "GOCACHE=$(go env GOCACHE)" "GOPATH=$(go env GOPATH)" "GOTOOLCHAIN=$(go env GOTOOLCHAIN)" unshare -n sh "$work/eidbridge-egress-inner.sh"
fi
