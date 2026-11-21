#!/bin/sh
# Run once before the demo: builds sandprobe into ~/.local/bin and the three demo images. Nothing here contacts a
# provider, and every key in the images is the fake value sandprobe-fake.
set -eu
cd "$(dirname "$0")/.."
make >/dev/null
install -m 0755 bin/sandprobe "$HOME/.local/bin/sandprobe"
cd demo/boxes
for box in vibe hardened regressed; do # regressed builds on hardened, so the order matters
  docker build -q -t "sandprobe-demo/$box" -f "$box.Dockerfile" . >/dev/null
done
echo "ready: $(command -v sandprobe), images sandprobe-demo/vibe, sandprobe-demo/hardened, sandprobe-demo/regressed"
