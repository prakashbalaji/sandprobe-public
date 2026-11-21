#!/bin/sh
# Builds every fixture image under test/fixtures, then runs each fixture through the whole host path beside a local
# canary (internal/host TestFixtures).
set -eu
cd "$(dirname "$0")/.."
for dir in test/fixtures/*/; do
  [ -f "$dir/Dockerfile" ] || continue # stub/ is a service the fixtures plant, built by the test itself
  name=$(basename "$dir")
  docker build -q -t "sandprobe-fixture-$name" "$dir" >/dev/null
done
SANDPROBE_FIXTURES=1 go test ./internal/host -run 'TestFixtures|TestDocker|TestSentinel' -count=1 -v -timeout 15m "$@"
