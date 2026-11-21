#!/usr/bin/env bash
# canary_test.sh checks canary.sh's down against fake aws and cf CLIs, with no cloud account: a failed DNS listing
# stops it before anything else is touched, and a retry after the instance is gone still cleans up the rest.
set -euo pipefail
export PROFILE=test-profile # the deploy scripts need the operator's profile; these tests stub aws
here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/bin"
cat >"$tmp/bin/aws" <<'EOF'
#!/bin/sh
echo "aws $*" >>"$LOG"
case "$*" in
*describe-instances* | *describe-volumes* | *describe-addresses* | *describe-security-groups*)
  echo "An error occurred (InvalidResource.NotFound) when calling the operation" >&2; exit 254 ;;
*get-instance-profile* | *get-role*) echo "An error occurred (NoSuchEntity) when calling the operation" >&2; exit 254 ;;
*head-bucket*) echo "An error occurred (404) when calling the HeadBucket operation: Not Found" >&2; exit 254 ;;
*) echo "unexpected aws call: $*" >&2; exit 99 ;;
esac
EOF
cat >"$tmp/bin/cf" <<'EOF'
#!/bin/sh
echo "cf $*" >>"$LOG"
[ "$CF" = fail ] && { echo "authentication error" >&2; exit 1; }
[ "$CF" = junk ] && { echo '{"error": "rate limited"}'; exit 0; }
[ "$CF" = noid ] && { echo '[{}]'; exit 0; }
[ "$CF" = nullid ] && { echo '[{"id": null}]'; exit 0; }
echo '[]'
EOF
chmod +x "$tmp/bin/aws" "$tmp/bin/cf"
export PATH="$tmp/bin:$PATH" LOG="$tmp/log" STATE="$tmp/state"

state() {
  printf '%s\n' did=feedc0de zone=z1 domain=probe.example dns=rec1 instance=i-0123456789abcdef0 volume=vol-0123456789abcdef0 \
    eip=eipalloc-0123456789abcdef0 sg=sg-0123456789abcdef0 iprofile=sandprobe-canary-feedc0de role=sandprobe-canary-feedc0de \
    bucket=sandprobe-canary-feedc0de >"$STATE"
  : >"$LOG"
}
fails=0
check() { if eval "$2"; then echo "PASS $1"; else echo "FAIL $1"; fails=1; fi; }

for mode in fail junk noid nullid; do # a listing that fails, or isn't a list of records with IDs, never reads as "record gone"
  state
  out=$(CF=$mode "$here/canary.sh" down 2>&1) && rc=0 || rc=$?
  check "down stops on a $mode DNS listing" '[ $rc -ne 0 ] && grep -q "DNS" <<<"$out"'
  check "down touches no AWS resource after a $mode DNS listing" '! grep -q "^aws" "$LOG"'
  check "the state survives a $mode DNS listing" '[ -f "$STATE" ]'
done

state # a retry: the record and the instance are already gone, and EC2 no longer describes the instance
out=$(CF=ok "$here/canary.sh" down 2>&1) && rc=0 || rc=$?
check "down finishes when the instance is gone" '[ $rc -eq 0 ] && grep -q "deployment feedc0de gone" <<<"$out"'
for c in describe-addresses describe-security-groups get-instance-profile get-role head-bucket; do
  check "down still checks $c" 'grep -q "$c" "$LOG"'
done
check "down never asks for a gone instance's tags" '! grep -q "Tags" "$LOG"'
check "down retires the state" '[ ! -f "$STATE" ] && ls "$STATE".down-* >/dev/null'
# RUN-8: emulate an accepted create whose response/ID record is lost. Even if
# other exact IDs are known, no cleanup or IP release can claim success.
for kind in bucket instance dns_A; do
  state
  chmod 600 "$STATE"
  DURABLE_STATE=1 bash -c 'source "$1"; create_begin "$2"' -- "$here/canary.sh" "$kind"
  : >"$LOG"
  out=$(CF=ok "$here/canary.sh" down 2>&1) && rc=0 || rc=$?
  check "$kind response loss retains state" '[ $rc -ne 0 ] && [ -f "$STATE" ] && grep -q "unresolved create" <<<"$out"'
  check "$kind response loss never releases resources or DNS" '[ ! -s "$LOG" ]'
  # For EC2 this also covers instance ID saved before the implicit volume ID.
  # An ID saved without a durable resolution is also conservatively unresolved.
  DURABLE_STATE=1 bash -c 'source "$1"; put instance i-0123456789abcdef0' -- "$here/canary.sh"
  out=$(CF=ok "$here/canary.sh" down 2>&1) && rc=0 || rc=$?
  check "$kind ID-before-resolution crash remains unresolved" '[ $rc -ne 0 ] && [ -f "$STATE" ]'
  DURABLE_STATE=1 bash -c 'source "$1"; create_end "$2"' -- "$here/canary.sh" "$kind"
  out=$(CF=ok "$here/canary.sh" down 2>&1) && rc=0 || rc=$?
  check "$kind resolved original ID permits normal cleanup" '[ $rc -eq 0 ] && [ ! -f "$STATE" ]'
done
# RUN-10: only explicit per-run namespaces can bypass the default-name collision guard.
: >"$LOG"
out=$(SANDPROBE_CANARY_NAME=unscoped "$here/canary.sh" status 2>&1) && rc=0 || rc=$?
check "invalid receiver namespace makes no provider call" '[ $rc -ne 0 ] && [ ! -s "$LOG" ]'
state
out=$(CF=ok SANDPROBE_CANARY_NAME=sandprobe-canary-0123456789abcdef "$here/canary.sh" down 2>&1) && rc=0 || rc=$?
check "namespaced receiver cleanup remains exact-ID bound" '[ $rc -eq 0 ] && [ ! -f "$STATE" ]'
# HCN-1 to HCN-4: PUBLIC=1 deploys the hosted canary beside an operator canary, never in place of it.
ud() { PUBLIC=$1 ACME_STAGING=$2 DOMAIN=pub.example bash -c 'source "$1"; userdata https://example.invalid/p abc123' -- "$here/canary.sh"; }
legacy=$(ud 0 0) public=$(ud 1 0) staging=$(ud 1 1)
check "the operator canary's service is unchanged" 'grep -qx "ExecStart=/usr/local/bin/sandprobe-canary -domain pub.example -control /run/sandprobe-canary/ctl.sock" <<<"$legacy" &&
  grep -qx "systemctl enable --now sandprobe-canary" <<<"$legacy" && ! grep -q "public\|StateDirectory\|EnvironmentFile\|control.key" <<<"$legacy"'
check "the hosted canary serves signed control at control.<domain> for its own address" 'grep -q "^ExecStart=.* -public-control control.pub.example -public-addr \${PUBLIC_ADDR} -control-key /var/lib/sandprobe-canary/control.key .*-control-pin-file /var/lib/sandprobe-canary/control.pin$" <<<"$public"'
check "the hosted canary makes its control key once, in its own state directory" 'grep -qx "StateDirectory=sandprobe-canary" <<<"$public" && grep -qx "StateDirectoryMode=0700" <<<"$public" &&
  grep -qx "ExecStartPre=-/usr/local/bin/sandprobe-canary -make-control-key /var/lib/sandprobe-canary/control.key" <<<"$public"'
check "the hosted canary waits for publicstart to give it its address" 'grep -qx "EnvironmentFile=/etc/sandprobe-canary.env" <<<"$public" && ! grep -q "enable --now" <<<"$public"'
check "only ACME_STAGING=1 asks Let's Encrypt staging" '! grep -q acme-staging <<<"$public" && grep -q -- "-acme-staging$" <<<"$staging"'
defaults() { PUBLIC=$1 PROFILE=test-profile DOMAIN= STATE= SANDPROBE_CANARY_NAME= HOME=/home/t bash -c 'source "$1"; echo "$DOMAIN $STATE $NAME"' -- "$here/canary.sh"; }
check "the hosted canary has its own domain, state file and namespace" '[ "$(defaults 1)" = "pub.probe.ac0.dev /home/t/.config/sandprobe/hosted-canary-test-profile-us-west-2.state sandprobe-canary-00000000000000b1" ]'
check "the operator canary keeps its own" '[ "$(defaults 0)" = "probe.ac0.dev /home/t/.config/sandprobe/canary-test-profile-us-west-2.state sandprobe-canary" ]'
: >"$LOG"
out=$(PUBLIC=1 bash -c 'source "$1"; publicstart i-0123456789abcdef0 "203.0.113.9; rm -rf /"' -- "$here/canary.sh" 2>&1) && rc=0 || rc=$?
check "publicstart takes only an address, before any AWS call" '[ $rc -ne 0 ] && grep -q "not an address" <<<"$out" && [ ! -s "$LOG" ]'
# publiccheck under set -u, with and without staging (bash 3.2 calls an empty array unbound), through a stub go.
printf '#!/bin/sh\necho "go $*" >>"$LOG"\n' >"$tmp/bin/go"
chmod +x "$tmp/bin/go"
for staging in 0 1; do
  : >"$LOG"
  out=$(ACME_STAGING=$staging bash -c 'source "$1"; publiccheck pub.example 0123' -- "$here/canary.sh" 2>&1) && rc=0 || rc=$?
  check "publiccheck runs with ACME_STAGING=$staging" '[ $rc -eq 0 ] && grep -q "canary check .*-canary-url https://control.pub.example -canary-pin 0123" "$LOG"'
done
check "only staging skips WebPKI for the check" 'grep -q -- "-tls-insecure" "$LOG"'
exit $fails
