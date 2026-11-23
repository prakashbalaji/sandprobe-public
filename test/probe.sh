#!/bin/sh
# Builds the probe's tests for Linux and runs them in a throwaway container, as nobody and as root.
set -eu
cd "$(dirname "$0")/.."
arch=$(docker info --format '{{.Architecture}}' | sed 's/x86_64/amd64/; s/aarch64/arm64/')
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
# This directory holds only fixture executables. The nobody container must traverse it.
chmod 0755 "$out"
CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go test -c -o "$out/probe.test" ./internal/probe
CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -o "$out/sandprobe-probe" ./cmd/sandprobe-probe
for a in amd64 arm64; do # every architecture a provider runs, whatever this Mac's Docker emulates
  CGO_ENABLED=0 GOOS=linux GOARCH=$a go vet ./internal/probe ./cmd/sandprobe-probe
done
# Multi-architecture OCI index verified from Docker Hub on 17 November 2026.
image=${SANDPROBE_TEST_IMAGE:-debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2}
for user in 65534:65534 0:0; do
  echo "== as $user in $image"
  docker run --rm --network none --user "$user" -v "$out:/sp:ro" "$image" /sp/probe.test -test.v "$@"
done
# AMP-1 runs sudo from its pinned descriptor (execveat), never through a path: with a fake tree mounted over /proc,
# whose /proc/self/fd/3 plays a sudo granting everything, every listing must still come from the pinned stand-in.
echo "== as 0:0 in $image, a fake tree mounted over /proc"
docker run --rm --network none --user 0:0 --cap-add SYS_ADMIN --security-opt apparmor=unconfined -v "$out:/sp:ro" "$image" sh -c \
  'mkdir -p /fakeproc/self/fd && printf "#!/bin/sh\necho \"    (ALL) NOPASSWD: ALL\"\n" > /fakeproc/self/fd/3 &&
   chmod 0755 /fakeproc/self/fd/3 && mount --bind /fakeproc /proc && exec /sp/probe.test -test.v -test.run "^TestSudoList$"'
