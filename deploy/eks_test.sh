#!/usr/bin/env bash
# eks_test.sh checks eks.sh against a fake AWS CLI, with no cloud account: a create that EKS accepts but that never
# shows up still leaves its name recorded, and down then finds the cluster by its tag and deletes it before the roles.
# CLN-2: up records nothing until AWS answers, and a record of no create is retired by down with no AWS call.
set -euo pipefail
export PROFILE=test-profile # the deploy scripts need the operator's profile; these tests stub aws
here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/bin" "$tmp/world"
cat >"$tmp/bin/aws" <<'FAKE'
#!/bin/bash
echo "aws $*" >>"$LOG"
w=$WORLD
arg() { local k=$1; shift; while [ $# -gt 0 ]; do [ "$1" = "$k" ] && { echo "$2"; return; }; shift; done; }
did() { sed -n 's/^did=//p' "$STATE" | tail -1; }
case "$*" in
*"sts get-caller-identity"*) [ -z "${STS_FAULT:-}" ] || { echo "Error when retrieving token from sso: Token has expired" >&2; exit 255; } ;;
*"ec2 describe-subnets"*)
  [ -z "${SUBNET_FAULT:-}" ] || { echo "An error occurred (UnauthorizedOperation)" >&2; exit 254; }
  printf 'subnet-a\tsubnet-b\tsubnet-c\n' ;;
*"ec2 describe-instances"*) ;;
*"iam create-role"*) n=$(arg --role-name "$@"); touch "$w/role-$n"; echo "arn:aws:iam::1:role/$n" ;;
*"iam attach-role-policy"* | *"iam detach-role-policy"*) ;;
*"iam get-role"*) n=$(arg --role-name "$@"); [ -f "$w/role-$n" ] || { echo "An error occurred (NoSuchEntity)" >&2; exit 254; } ;;
*"iam list-role-tags"*) did ;;
*"iam list-attached-role-policies"*) echo "arn:aws:iam::aws:policy/P" ;;
*"iam delete-role"*) rm "$w/role-$(arg --role-name "$@")" ;;
*"eks create-cluster"*) touch "$w/cluster" ;;
*"eks describe-cluster"*)
  if [ "$PHASE" != down ] || [ ! -f "$w/cluster" ]; then echo "An error occurred (ResourceNotFoundException)" >&2; exit 254; fi
  case "$*" in *sandprobe:deployment*) did ;; *) echo ACTIVE ;; esac ;;
*"eks delete-cluster"*)
  n=$(cat "$w/delete-count" 2>/dev/null || echo 0); n=$((n+1)); echo "$n" >"$w/delete-count"
  if [ "${DELETE_FAULT:-}" = persistent ] || { [ "${DELETE_FAULT:-}" = transient ] && [ "$n" -le 2 ]; }; then
    echo 'An error occurred (ResourceInUseException): cluster currently has an update in progress' >&2; exit 254
  fi
  if [ "${DELETE_FAULT:-}" = unrelated ]; then echo 'An error occurred (AccessDeniedException): synthetic error' >&2; exit 254; fi
  [ -f "$w/role-$(sed -n 's/^crole=//p' "$STATE")" ] || { echo "roles went first" >&2; exit 1; }; rm "$w/cluster" ;;
*"eks wait cluster-deleted"*) ;;
*) echo "unexpected aws call: $*" >&2; exit 99 ;;
esac
FAKE
chmod +x "$tmp/bin/aws"
export PATH="$tmp/bin:$PATH" LOG="$tmp/log" WORLD="$tmp/world" STATE="$tmp/state" NAP=0
fails=0
check() { if eval "$2"; then echo "PASS $1"; else echo "FAIL $1"; fails=1; fi; }

out=$(PHASE=up "$here/eks.sh" up 2>&1) && rc=0 || rc=$?
name=$(sed -n 's/^cluster=//p' "$STATE")
check "up fails when the cluster never shows" '[ $rc -ne 0 ] && grep -q "the name is recorded" <<<"$out"'
check "the cluster's name was recorded before the create" '[ -n "$name" ] && [ -f "$WORLD/cluster" ]'
# the accepted cluster isn't visible yet when down first runs: its absence proves nothing
out=$(PHASE=hidden "$here/eks.sh" down 2>&1) && rc=0 || rc=$?
check "down refuses while the accepted cluster is unseen" '[ $rc -ne 0 ] && grep -q "never seen" <<<"$out"'
check "and deletes nothing: state, roles and the cluster stay" '[ -f "$STATE" ] && [ "$(ls "$WORLD"/role-* | wc -l)" -eq 2 ] && ! grep -q "delete-role" "$LOG"'
out=$(PHASE=down "$here/eks.sh" down 2>&1) && rc=0 || rc=$?
check "down finds the unseen cluster and deletes it" '[ $rc -eq 0 ] && grep -q "eks delete-cluster --name $name" "$LOG" && [ ! -f "$WORLD/cluster" ]'
check "down deletes both roles after the cluster" '! ls "$WORLD"/role-* >/dev/null 2>&1'
check "down retires the state" '[ ! -f "$STATE" ]'
for fault in transient persistent unrelated; do
  printf 'did=12345678\ncluster=sandprobe-12345678\nseen=1\ncrole=cluster-role\nnrole=node-role\n' >"$STATE"
  touch "$WORLD/cluster" "$WORLD/role-cluster-role" "$WORLD/role-node-role"
  rm -f "$WORLD/delete-count"
  out=$(PHASE=down DELETE_FAULT="$fault" "$here/eks.sh" down 2>&1) && rc=0 || rc=$?
  case "$fault" in
    transient) check "update-in-progress is retried then cleaned" '[ $rc -eq 0 ] && [ "$(cat "$WORLD/delete-count")" -eq 3 ] && [ ! -f "$STATE" ]' ;;
    persistent) check "persistent update wait is bounded and retains resources" '[ $rc -ne 0 ] && [ "$(cat "$WORLD/delete-count")" -eq 60 ] && [ -f "$STATE" ] && [ -f "$WORLD/cluster" ] && [ -f "$WORLD/role-node-role" ]' ;;
    unrelated) check "unrelated errors are not retried or printed" '[ $rc -ne 0 ] && [ "$(cat "$WORLD/delete-count")" -eq 1 ] && [ -f "$STATE" ] && ! grep -q AccessDenied <<<"$out"' ;;
  esac
done

export STATE="$tmp/cln2/state"
: >"$LOG"
out=$(STS_FAULT=1 "$here/eks.sh" up 2>&1) && rc=0 || rc=$?
check "up with an expired session exits 3 and records nothing" '[ $rc -eq 3 ] && [ ! -e "$STATE" ] && grep -q "recorded and created nothing" <<<"$out"'
check "and makes no AWS call but the identity check, printing none of its output" '[ "$(wc -l <"$LOG")" -eq 1 ] && grep -q "sts get-caller-identity" "$LOG" && ! grep -q "Token has expired" <<<"$out"'
out=$(SUBNET_FAULT=1 "$here/eks.sh" up 2>&1) && rc=0 || rc=$?
check "a failed read after it leaves a record of no create, and isn't exit 3" '[ $rc -ne 0 ] && [ $rc -ne 3 ] && [ -f "$STATE" ] && ! grep -Eq "^(crole|nrole|cluster)=" "$STATE"'
: >"$LOG"
out=$("$here/eks.sh" status 2>&1) && rc=0 || rc=$?
check "status says nothing was created, with no AWS call" '[ $rc -ne 0 ] && grep -q "records no create" <<<"$out" && [ ! -s "$LOG" ]'
out=$("$here/eks.sh" up 2>&1) && rc=0 || rc=$?
check "up refuses the same way, with no AWS call, and not with exit 3" '[ $rc -ne 0 ] && [ $rc -ne 3 ] && grep -q "records no create" <<<"$out" && [ ! -s "$LOG" ]'
retire=$(sed -n 's/^  //p' <<<"$out")
check "the retire command names this state file" '[ "$retire" = "$(printf "STATE=%q PROFILE=test-profile REGION=us-west-2 %q down" "$STATE" "$here/eks.sh")" ]'
out=$(env -u PROFILE -u STATE bash -c "$retire" 2>&1) && rc=0 || rc=$?
check "run as printed, it retires the record with no AWS call" '[ $rc -eq 0 ] && grep -q "created nothing" <<<"$out" && [ ! -e "$STATE" ] && ls "$STATE".down-* >/dev/null && [ ! -s "$LOG" ]'
out=$(STS_FAULT=1 "$here/eks.sh" up 2>&1) && rc=0 || rc=$?
check "and up then gets past its refusal to the identity check" '[ $rc -eq 3 ] && grep -q "recorded and created nothing" <<<"$out"'
exit $fails
