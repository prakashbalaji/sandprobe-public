#!/usr/bin/env bash
# REL-2's version grammar, on every pull request: what each version publishes as, or that it's refused.
set -euo pipefail
here=$(dirname "$0")
fail=0
want() { # want release|prerelease|refused <version>
  local got
  got=$(bash "$here/release-version.sh" "$2" 2>/dev/null) || got=refused
  if [ "$got" != "$1" ]; then
    echo "FAIL: $(printf %q "$2") is $got, want $1"
    fail=1
  fi
}
want release 0.2.1
want release 0.3.0
want release 10.20.300
want prerelease 0.3.0-rc.1
want prerelease 1.0.0-rc.12
for v in "" v0.3.0 v0.3.0-rc.1 0.3 0.3.0. 0.3.0-rc 0.3.0-rc. 0.3.0-rc1 0.3.0-RC.1 0.3.0-rc.1a 0.3.0-rc.-1 \
  0.3.0-rc.1-rc.2 0.3.0-beta.1 0.3.0+build.1 a.b.c " 0.3.0" "0.3.0 " $'0.3.0\n0.3.1' $'0.3.0-rc.1\n'; do
  want refused "$v"
done
[ "$fail" = 0 ] && echo "release versions: every case as REL-2 says"
exit "$fail"
