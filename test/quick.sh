#!/bin/sh
# QCK-2: exercise the packaged binary in our own throwaway local container only.
set -eu
cd "$(dirname "$0")/.."
arch=$(docker info --format '{{.Architecture}}' | sed 's/x86_64/amd64/; s/aarch64/arm64/')
artifacts=$(pwd)/bin/package
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
for uid in 65534 0; do
  docker run --rm --network none --read-only --user "$uid:$uid" \
    --cap-drop ALL --security-opt no-new-privileges \
    -e SANDPROBE_EXAMPLE_TOKEN=synthetic-marker-do-not-output \
    -v "$artifacts:/sp:ro" debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 \
    "/sp/sandprobe-probe-linux-$arch" -quick /etc/shadow /usr/local/bin > "$out/result.json"
  python3 - "$out/result.json" "$uid" <<'PY'
import json, sys
raw = open(sys.argv[1]).read()
d = json.loads(raw)
assert d['schema'] == 'sandprobe.quick/1'
assert d['identity']['effective_uid'] == int(sys.argv[2])
assert d['identity']['proc_status'] == 'observed'
assert d['identity']['no_new_privs'] == 1
assert d['identity']['cap_effective'] == '0000000000000000'
assert d['verification'] == 'partial_self_observed_unauthenticated'
assert 'SANDPROBE_EXAMPLE_TOKEN' in d['secret_shaped_environment_names']
assert 'synthetic-marker-do-not-output' not in raw
assert 'grade' not in d
assert len(d['paths']) == 2
assert len(raw.encode()) <= 256 * 1024
PY
done
