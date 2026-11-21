#!/usr/bin/env bash
# eks.sh makes and deletes the EKS Auto Mode cluster the AWS Nitro adapter grades pods in (PRV table). Only Sandprobe
# uses it, so a pod's name can't be another's. Auto Mode brings the Nitro runtime classes and sandbox-capable nodes.
#   up      make the cluster and its two IAM roles, write Sandprobe's own kubeconfig, and check the runtime classes
#   status  check the recorded cluster is active, carries this deployment's tag, and offers isolated-sandbox
#   down    delete exactly what up recorded, and confirm each is gone
# Every resource carries a fresh deployment ID in its name and tag, and its exact ID goes in the state file. down
# deletes only those, after checking the tag, and counts one gone only on a definitive "not found": for the cluster,
# that's one up saw, or one down deleted and waited out; a cluster asked for but never seen stays unresolved.
set -euo pipefail
PROFILE=${PROFILE:?set PROFILE to the AWS CLI profile for the account the cluster runs in} REGION=${REGION:-us-west-2} VERSION=${VERSION:-1.37}
STATE=${STATE:-$HOME/.config/sandprobe/eks-$PROFILE-$REGION.state}
MARK=sandprobe:deployment
aws() { command aws --profile "$PROFILE" --region "$REGION" "$@"; }
fail() { echo "eks.sh: $*" >&2; exit 1; }
get() { [ -f "$STATE" ] && sed -n "s/^$1=//p" "$STATE" | tail -1; }
put() {
  if [ "${DURABLE_STATE:-0}" = 1 ]; then
    python3 "${BASH_SOURCE[0]%/*}/durable_state.py" append "$STATE" "$1=$2"
  else
    echo "$1=$2" >>"$STATE"
  fi
}

# exists runs an AWS read: true if the resource is there, false only on a definitive "not found".
exists() {
  local err
  err=$(aws "$@" 2>&1 >/dev/null) && return 0
  case $err in *NoSuchEntity* | *ResourceNotFoundException* | *"No cluster found"*) return 1 ;; *) fail "$err" ;; esac
}
role_owned() {
  [ "$(aws iam list-role-tags --role-name "$1" --query "Tags[?Key=='$MARK'].Value | [0]" --output text)" = "$(get did)" ] ||
    fail "role $1 doesn't carry this deployment's marker"
}
cluster_owned() {
  [ "$(aws eks describe-cluster --name "$1" --query "cluster.tags.\"$MARK\"" --output text)" = "$(get did)" ] ||
    fail "cluster $1 doesn't carry this deployment's marker"
}

role() { # name, service principal, policies...
  local name=$1 svc=$2
  shift 2
  aws iam create-role --role-name "$name" --tags "Key=Project,Value=sandprobe" "Key=$MARK,Value=$(get did)" \
    --assume-role-policy-document "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"$svc\"},\"Action\":[\"sts:AssumeRole\",\"sts:TagSession\"]}]}" \
    --query Role.Arn --output text
  for p in "$@"; do aws iam attach-role-policy --role-name "$name" --policy-arn "arn:aws:iam::aws:policy/$p"; done
}

status() {
  local name
  [ -f "$STATE" ] || fail "no deployment in $STATE"
  name=$(get cluster)
  cluster_owned "$name"
  [ "$(aws eks describe-cluster --name "$name" --query cluster.status --output text)" = ACTIVE ] || fail "cluster $name isn't active"
  kubectl --kubeconfig "$(get kubeconfig)" --context "$name" get runtimeclass isolated-sandbox -o name >/dev/null ||
    fail "no isolated-sandbox runtime class"
  printf 'deployment %s\ncluster %s\nkubeconfig %s\n' "$(get did)" "$name" "$(get kubeconfig)"
}

up() {
  local did subnets crole nrole name kc
  [ ! -f "$STATE" ] || fail "a deployment is recorded in $STATE: run status, or down first"
  did=$(openssl rand -hex 4)
  mkdir -p "$(dirname "$STATE")"
  if [ "${DURABLE_STATE:-0}" = 1 ]; then
    python3 "${BASH_SOURCE[0]%/*}/durable_state.py" init "$STATE" "did=$did" "profile=$PROFILE" "region=$REGION"
  else
    printf 'did=%s\nprofile=%s\nregion=%s\n' "$did" "$PROFILE" "$REGION" >"$STATE"
  fi
  subnets=$(aws ec2 describe-subnets --filters Name=default-for-az,Values=true \
    "Name=availability-zone,Values=${REGION}a,${REGION}b,${REGION}c" --query 'Subnets[].SubnetId' --output text | tr '\t' ',')
  [ "$(tr ',' '\n' <<<"$subnets" | grep -c .)" -ge 2 ] || fail "need default subnets in two zones, got $subnets"

  put crole "sandprobe-eks-$did"
  crole=$(role "sandprobe-eks-$did" eks.amazonaws.com AmazonEKSClusterPolicy AmazonEKSComputePolicy \
    AmazonEKSBlockStoragePolicy AmazonEKSLoadBalancingPolicy AmazonEKSNetworkingPolicy)
  put nrole "sandprobe-eksnode-$did"
  nrole=$(role "sandprobe-eksnode-$did" ec2.amazonaws.com AmazonEKSWorkerNodeMinimalPolicy AmazonEC2ContainerRegistryPullOnly)

  name=sandprobe-$did
  put cluster "$name" # before the create: a create that succeeds unseen is still found, by its tag, at down
  local err=""
  for _ in 1 2 3 4 5 6; do # new roles take a few seconds to reach EKS
    err=$(aws eks create-cluster --name "$name" --kubernetes-version "$VERSION" --role-arn "$crole" \
      --resources-vpc-config "subnetIds=$subnets,endpointPublicAccess=true,endpointPrivateAccess=true" \
      --compute-config "enabled=true,nodePools=general-purpose,nodeRoleArn=$nrole" \
      --kubernetes-network-config 'elasticLoadBalancing={enabled=true}' --storage-config 'blockStorage={enabled=true}' \
      --access-config authenticationMode=API,bootstrapClusterCreatorAdminPermissions=true \
      --tags "Project=sandprobe,$MARK=$did" 2>&1 >/dev/null) && break
    sleep "${NAP:-10}"
  done
  for _ in 1 2 3 4 5 6; do # a cluster just created can take a moment to describe
    exists eks describe-cluster --name "$name" && break
    sleep "${NAP:-10}"
  done
  exists eks describe-cluster --name "$name" || fail "create-cluster failed: $err (the name is recorded; down finds it if it appears)"
  put seen 1 # from here a not-found is definitive; before, it proves nothing
  aws eks wait cluster-active --name "$name"
  put endpoint "$(aws eks describe-cluster --name "$name" --query cluster.endpoint --output text)"
  kc=$(dirname "$STATE")/eks-$did.kubeconfig
  aws eks update-kubeconfig --name "$name" --kubeconfig "$kc" --alias "$name" >/dev/null # context named for the cluster
  chmod 600 "$kc"
  put kubeconfig "$kc"
  status
}

down() {
  local name r v deleted err
  [ -f "$STATE" ] || fail "no deployment in $STATE"
  name=$(get cluster)
  if [ -n "$name" ] && exists eks describe-cluster --name "$name"; then
    # CLN-1: a just-finished Auto Mode change can temporarily block deletion.
    deleted=0
    for _ in $(seq 60); do
      cluster_owned "$name"
      if err=$(aws eks delete-cluster --name "$name" 2>&1 >/dev/null); then
        deleted=1
        break
      fi
      case "$err" in
        *ResourceInUseException*"update in progress"*) sleep "${NAP:-10}" ;;
        *) fail "delete-cluster failed; deployment state retained" ;;
      esac
    done
    [ "$deleted" = 1 ] || fail "delete-cluster update wait exhausted; deployment state retained"
    aws eks wait cluster-deleted --name "$name"
  elif [ -n "$name" ] && [ "$(get seen)" != 1 ]; then # asked for, never seen: it may yet appear, so nothing is deleted
    fail "cluster $name was asked for but never seen, so its absence now proves nothing: nothing deleted, the state kept. Run down again once it shows. Retire $STATE by hand only once AWS confirms the create failed, such as by CloudTrail's CreateCluster event showing an error; a not-found at one moment never proves that"
  fi
  [ -z "$name" ] || ! exists eks describe-cluster --name "$name" || fail "cluster $name still there"
  # Auto Mode's nodes go with the cluster; any EC2 instance still tagged for it is a failure
  if [ -n "$name" ]; then
    for _ in $(seq 60); do
      v=$(aws ec2 describe-instances --filters "Name=tag:eks:eks-cluster-name,Values=$name" \
        "Name=instance-state-name,Values=pending,running,stopping,stopped,shutting-down" --query 'Reservations[].Instances[].InstanceId' --output text)
      [ -z "$v" ] && break
      sleep "${NAP:-10}"
    done
    [ -z "$v" ] || fail "instances of $name still there: $v"
  fi
  for r in $(get nrole) $(get crole); do
    if exists iam get-role --role-name "$r"; then
      role_owned "$r"
      for v in $(aws iam list-attached-role-policies --role-name "$r" --query 'AttachedPolicies[].PolicyArn' --output text); do
        aws iam detach-role-policy --role-name "$r" --policy-arn "$v"
      done
      aws iam delete-role --role-name "$r"
    fi
    ! exists iam get-role --role-name "$r" || fail "role $r still there"
  done
  r=$(get kubeconfig)
  [ -z "$r" ] || rm -f "$r"
  v=$(get did)
  mv "$STATE" "$STATE.down-$(date +%Y%m%d%H%M%S)"
  echo "down: deployment $v gone (cluster, its nodes, both IAM roles, the kubeconfig)"
}

case ${1:-} in
up | status | down) "$1" ;;
*) fail "usage: eks.sh up|status|down" ;;
esac
