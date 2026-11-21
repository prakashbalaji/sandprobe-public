#!/bin/sh
# CAL-6: execute four local controls; never silently skip unavailable Docker.
set -eu
cd "$(dirname "$0")/.."
docker info >/dev/null
for calibration_image in clean holes; do
  docker build -q -t "sandprobe-fixture-$calibration_image" "test/fixtures/$calibration_image" >/dev/null
done
calibration_tmp=$(mktemp -d)
trap 'rm -rf "$calibration_tmp"' EXIT HUP INT TERM
calibration_status=0
SANDPROBE_FIXTURES=1 go test ./internal/host -run '^TestFixtures$/(clean|holes|net-canary-down|broken-arch)$' \
  -count=1 -json -timeout 10m >"$calibration_tmp/events.json" 2>"$calibration_tmp/stderr.log" || calibration_status=$?
if [ "$calibration_status" -ne 0 ]; then
  python3 test/calibration_summary.py "$calibration_tmp/events.json" --command-failed || :
  exit "$calibration_status"
fi
python3 test/calibration_summary.py "$calibration_tmp/events.json"
exit "$calibration_status"
