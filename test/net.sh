#!/bin/sh
# Runs the probe's network tests against a canary container on a throwaway Docker network, then reads the canary's
# receipts the way the host does: by querying the canary itself, never through the box.
set -eu
cd "$(dirname "$0")/.."
arch=$(docker info --format '{{.Architecture}}' | sed 's/x86_64/amd64/; s/aarch64/arm64/')
work=$(mktemp -d)
net=sp-net-$$
cleanup() { docker rm -f "sp-canary-$$" >/dev/null 2>&1 || true; docker network rm "$net" >/dev/null 2>&1 || true; rm -rf "$work"; }
trap cleanup EXIT
CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go test -c -o "$work/probe.test" ./internal/probe
CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -o "$work/sandprobe-canary" ./cmd/sandprobe-canary
image=${SANDPROBE_TEST_IMAGE:-debian:trixie-slim}
canary=sp-canary-$$
docker network create --subnet 172.30.99.0/24 "$net" >/dev/null
docker run -d --name "$canary" --network "$net" --ip 172.30.99.10 -v "$work/sandprobe-canary:/sandprobe-canary:ro" "$image" \
  /sandprobe-canary >/dev/null
# the host's control channel: a socket inside the canary's own container
ctl() { docker exec "$canary" /sandprobe-canary -ctl "$@"; }
for i in $(seq 1 50); do ctl status >/dev/null 2>&1 && break; sleep 0.1; done
pin=$(ctl status | sed 's/.*"pin":"\([0-9a-f]*\)".*/\1/')
# arm the run's nonces, each with its check's protocol and port: the canary counts nothing else
ctl arm -run net -ttl 600 -wants n-egr-1/dns/53,n-egr-2/tcp/443,n-egr-3/tcp/443,n-egr-3-echo/tcp/443,n-egr-5-22/tcp/22,n-egr-5-53u/udp/53 |
  grep -q '"ok":true' || { echo "the canary refused the arm"; exit 1; }
echo "== open network, as nobody"
docker run --rm --network "$net" --user 65534:65534 -e SANDPROBE_NET=open -e SANDPROBE_CANARY_IP=172.30.99.10 \
  -e SANDPROBE_CANARY_PIN="$pin" -v "$work/probe.test:/probe.test:ro" "$image" /probe.test -test.run TestNet -test.v
echo "== no network, as nobody"
docker run --rm --network none --user 65534:65534 -e SANDPROBE_NET=none -e SANDPROBE_CANARY_IP=172.30.99.10 \
  -e SANDPROBE_CANARY_PIN="$pin" -v "$work/probe.test:/probe.test:ro" "$image" /probe.test -test.run TestNet -test.v
echo "== the run's counts, as the host's query returns them"
log=$(ctl query -run net)
echo "$log"
echo "$log" | grep -q "\"pin\":\"$pin\",\"ok\":true" || { echo "the query didn't complete, or the canary restarted"; exit 1; }
for n in n-egr-2 n-egr-3 n-egr-5-22 n-egr-5-53u; do
  echo "$log" | jq -e --arg n "$n" 'any(.counts[]; .nonce == $n and .count > 0)' >/dev/null || { echo "missing receipt for $n"; exit 1; }
done
echo "every expected receipt is there"
