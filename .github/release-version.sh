#!/usr/bin/env bash
# REL-2: what a release version publishes as. A version is x.y.z, or x.y.z-rc.N for a release candidate, each part
# digits. Prints "release" for x.y.z, a full release, and "prerelease" for x.y.z-rc.N, a GitHub pre-release never
# marked Latest. Anything else prints nothing on stdout and exits 1, so the release stops before anything is published.
set -euo pipefail
export LC_ALL=C # [0-9] means the ASCII digits only
v=${1-}
if [[ $v =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo release
elif [[ $v =~ ^[0-9]+\.[0-9]+\.[0-9]+-rc\.[0-9]+$ ]]; then
  echo prerelease
else
  echo "a release version is x.y.z or x.y.z-rc.N" >&2
  exit 1
fi
