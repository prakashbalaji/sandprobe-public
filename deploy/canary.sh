#!/usr/bin/env bash
# canary.sh runs the live canary (SBX-11) on one EC2 instance of its own. Nothing else runs there: sshd is off, so 22
# is the canary's, and the host reaches the control socket only through SSM, never over the network boxes use.
#   up      build the canary, launch a new deployment with a fixed IP and its DNS records, then verify it
#   status  verify the running canary: service, sshd off, binary digest, pin, and that the IP serves that pin
#   ctl     ask the canary over SSM, as the host does: ctl status | arm -run R -ttl S -wants n/proto/port,... |
#           query -run R | disarm -run R; prints its JSON answer
#   wildcard  add *.canary.<domain> to a running deployment, recorded like up's records (the Modal PoC, POC-2)
#   down    delete exactly what up created, DNS records first, and confirm each is gone
# Every resource up creates carries a fresh deployment ID in its name or tag, and its exact ID goes in the state file.
# down deletes only those IDs, after checking the tag, and counts a resource gone only on a definitive "not found".
# SSM Run Command is general command execution: whoever may call it on this instance controls the canary, so limit
# ssm:SendCommand and ssm:GetCommandInvocation to it (and audit them) in any account that isn't a throwaway.
# PUBLIC=1 deploys the hosted canary (HCN-1 to HCN-4): a t4g.small that also serves the signed public control path at
# control.<domain> on 443, with its control key made on the instance and its pin recorded here; it has its own
# namespace and state file, so it runs beside an operator canary without touching it. ACME_STAGING=1 takes the
# certificate from Let's Encrypt's staging service, for a dry run. Its domain defaults to pub.probe.ac0.dev, so its DNS
# records never meet an operator canary's under probe.ac0.dev; up refuses any domain that already has records.
set -euo pipefail
PUBLIC=${PUBLIC:-0} ACME_STAGING=${ACME_STAGING:-0}
PROFILE=${PROFILE:?set PROFILE to the AWS CLI profile for the account the canary runs in} REGION=${REGION:-us-west-2} ZONE=${ZONE:-ac0.dev}
if [ "$PUBLIC" = 1 ]; then # its own domain, state file (not canary-*.state, an operator canary's, used only when -canary names it) and namespace
  DOMAIN=${DOMAIN:-pub.probe.ac0.dev}
  STATE=${STATE:-$HOME/.config/sandprobe/hosted-canary-$PROFILE-$REGION.state}
  NAME=${SANDPROBE_CANARY_NAME:-sandprobe-canary-00000000000000b1}
else
  DOMAIN=${DOMAIN:-probe.ac0.dev}
  STATE=${STATE:-$HOME/.config/sandprobe/canary-$PROFILE-$REGION.state}
  NAME=${SANDPROBE_CANARY_NAME:-sandprobe-canary}
fi
MARK=sandprobe:deployment
# RUN-10: isolate concurrent owned receivers while retaining the default guard.
[[ "$NAME" =~ ^sandprobe-canary(-[a-f0-9]{16})?$ ]] || { echo 'canary.sh: invalid canary namespace' >&2; exit 1; }
aws() { command aws --profile "$PROFILE" --region "$REGION" "$@"; }
fail() { echo "canary.sh: $*" >&2; exit 1; }
get() { [ -f "$STATE" ] && sed -n "s/^$1=//p" "$STATE" | tail -1; }
put() {
  if [ "${DURABLE_STATE:-0}" = 1 ]; then
    python3 "${BASH_SOURCE[0]%/*}/durable_state.py" append "$STATE" "$1=$2"
  else
    echo "$1=$2" >>"$STATE"
  fi
}

# RUN-8: unresolved creates retain the deployment; never guess an unreturned ID.
create_begin() { [ "${DURABLE_STATE:-0}" != 1 ] || put create_pending "$1"; }
create_end() { [ "${DURABLE_STATE:-0}" != 1 ] || put create_resolved "$1"; }
creates_resolved() { python3 "${BASH_SOURCE[0]%/*}/durable_state.py" resolved "$STATE"; }

# exists runs an AWS read: true if the resource is there, false only on a definitive "not found".
exists() {
  local err
  err=$(aws "$@" 2>&1 >/dev/null) && return 0
  case $err in *NoSuchEntity* | *"(404)"* | *.NotFound*) return 1 ;; *) fail "$err" ;; esac
}

# tag prints the deployment marker on a resource.
tag() {
  local q="[?Key=='$MARK'].Value | [0]"
  case $1 in
  instance) aws ec2 describe-instances --instance-ids "$2" --query "Reservations[0].Instances[0].Tags$q" --output text ;;
  volume) aws ec2 describe-volumes --volume-ids "$2" --query "Volumes[0].Tags$q" --output text ;;
  sg) aws ec2 describe-security-groups --group-ids "$2" --query "SecurityGroups[0].Tags$q" --output text ;;
  eip) aws ec2 describe-addresses --allocation-ids "$2" --query "Addresses[0].Tags$q" --output text ;;
  role) aws iam list-role-tags --role-name "$2" --query "Tags$q" --output text ;;
  profile) aws iam list-instance-profile-tags --instance-profile-name "$2" --query "Tags$q" --output text ;;
  bucket) aws s3api get-bucket-tagging --bucket "$2" --query "TagSet$q" --output text ;;
  esac
}
owned() { [ "$(tag "$1" "$2")" = "$(get did)" ] || fail "$1 $2 doesn't carry this deployment's marker"; }

# dnsids lists the record IDs under our domain; a failed or malformed listing stops the script, never reads as empty.
dnsids() {
  local out
  out=$(cf dns records list -z "$1" --name-endswith "$(get domain)") || fail "listing DNS records under $(get domain) failed"
  jq -r 'if type == "array" and all(.[]; type == "object" and (.id | type) == "string" and (.id | length) > 0)
    then .[].id else error("not a list of records with IDs") end' <<<"$out" || fail "DNS listing under $(get domain) didn't parse"
}

# ssm runs a script on the instance as root and prints its stdout; any end but Success fails.
ssm() {
  local cmd st=Pending
  cmd=$(aws ssm send-command --instance-ids "$1" --document-name AWS-RunShellScript \
    --parameters "$(jq -n --arg c "$2" '{commands: [$c]}')" --query Command.CommandId --output text)
  for _ in $(seq 120); do
    st=$(aws ssm get-command-invocation --command-id "$cmd" --instance-id "$1" --query Status --output text 2>/dev/null) || st=Pending
    case $st in Pending | InProgress | Delayed) sleep 5 ;; *) break ;; esac
  done
  [ "$st" = Success ] || fail "ssm command $st: $(aws ssm get-command-invocation --command-id "$cmd" --instance-id "$1" \
    --query StandardErrorContent --output text 2>/dev/null)"
  aws ssm get-command-invocation --command-id "$cmd" --instance-id "$1" --query StandardOutputContent --output text
}

# online waits for the instance to reach SSM.
online() {
  local st
  for _ in $(seq 60); do
    st=$(aws ssm describe-instance-information --filters "Key=InstanceIds,Values=$1" \
      --query 'InstanceInformationList[0].PingStatus' --output text)
    [ "$st" = Online ] && return
    sleep 5
  done
  fail "instance $1 never reached SSM"
}

# inside checks the instance through SSM: user data finished, sshd off, the canary alone on 22, its digest and pin,
# and for the hosted canary its control-key pin.
inside() {
  local id
  id=$(get instance)
  online "$id"
  ssm "$id" 'set -euo pipefail
cloud-init status --wait >/dev/null || true
test -e /var/lib/sandprobe-canary.ready
! systemctl is-active --quiet sshd.service
! systemctl is-active --quiet sshd.socket
systemctl is-active --quiet sandprobe-canary
ss -Htlnp "sport = :22" | grep -q "\"sandprobe-canar"
! ss -Htlnp "sport = :22" | grep -v "\"sandprobe-canar"
sha256sum /usr/local/bin/sandprobe-canary | cut -d" " -f1
/usr/local/bin/sandprobe-canary -ctl status -control /run/sandprobe-canary/ctl.sock |
  sed -n "s/.*\"pin\":\"\([0-9a-f]*\)\",\"ok\":\([a-z]*\).*/\1 \2/p"
if [ -e /var/lib/sandprobe-canary/control.pin ]; then cat /var/lib/sandprobe-canary/control.pin; fi'
}

# publicstart gives the hosted canary the address it signs (HCN-1) once the Elastic IP holds it, then starts it.
publicstart() {
  [[ $2 =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || fail "not an address: $2"
  online "$1"
  ssm "$1" "set -euo pipefail
cloud-init status --wait >/dev/null || true
test -e /var/lib/sandprobe-canary.ready
printf 'PUBLIC_ADDR=%s\\n' '$2' >/etc/sandprobe-canary.env
systemctl start sandprobe-canary
systemctl is-active --quiet sandprobe-canary" >/dev/null
}

# publiccheck asks the hosted canary for its signed status from here, as any host would, a few times: the first
# request after a fresh start waits for the certificate (HCN-1).
publiccheck() {
  local d=$1 cpin=$2 flags=() i
  [ "$ACME_STAGING" = 1 ] && flags=(-tls-insecure)
  for i in 1 2 3 4 5 6; do
    if (cd "$(git rev-parse --show-toplevel)" && go run ./cmd/sandprobe canary check ${flags[@]+"${flags[@]}"} \
      -canary-url "https://control.$d" -canary-pin "$cpin"); then return; fi
    sleep 10
  done
  fail "control.$d never gave a status signed by $cpin"
}

# RUN-20: dynamically scoped to up; manual status never writes the journal.
readiness() { [ "${track_readiness:-0}" != 1 ] || put readiness_stage "$1"; }

# outside checks from here, against the fixed IP: the TLS key is the instance's pin, and each plain port answers health.
outside() {
  local ip=$1 pin=$2 got p transport_ok
  readiness tls
  if ! got=$(openssl s_client -connect "$ip:443" -servername "health.canary.$(get domain)" </dev/null 2>/dev/null |
    openssl x509 -pubkey -noout 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | shasum -a 256 | cut -d' ' -f1); then
    # A client/pipeline exit is not proof the peer was unreachable.
    if [ "$got" = "$pin" ]; then readiness tls_command_failed_matching_pin
    else readiness tls_command_failed; fi
    fail "receiver TLS verification command failed"
  fi
  if [ "$got" != "$pin" ]; then
    readiness tls_pin_mismatch
    fail "receiver TLS pin mismatch"
  fi
  for p in 22 80 8080; do
    readiness "tcp${p}"
    transport_ok=1
    got=$(printf 'health\n' | nc -w 4 "$ip" "$p" 2>/dev/null) || transport_ok=0
    if [ "$got" != sandprobe:health ]; then
      if [ "$transport_ok" = 0 ]; then readiness "tcp${p}_transport_failed"
      else readiness "tcp${p}_health_mismatch"; fi
      fail "receiver TCP health unproven on port $p"
    fi
  done
  readiness ready
}

status() {
  local id st out sum pin ok
  [ -f "$STATE" ] || fail "no deployment in $STATE"
  id=$(get instance)
  owned instance "$id"
  st=$(aws ec2 describe-instances --instance-ids "$id" --query 'Reservations[0].Instances[0].State.Name' --output text)
  [ "$st" = running ] || fail "instance $id is $st"
  readiness internal
  out=$(inside)
  sum=$(sed -n 1p <<<"$out")
  read -r pin ok < <(sed -n 2p <<<"$out")
  [ "$ok" = true ] || fail "the canary's log is broken"
  [ "$sum" = "$(get sha256)" ] || fail "the instance runs $sum, not the deployed $(get sha256)"
  if [ "$(get public)" = 1 ]; then # the control key is made once on the instance; its pin must never change
    local cpin
    cpin=$(sed -n 3p <<<"$out")
    [[ $cpin =~ ^[0-9a-f]{64}$ ]] || fail "the hosted canary has no control pin"
    if [ -z "$(get cpin)" ]; then put cpin "$cpin"; fi
    [ "$cpin" = "$(get cpin)" ] || fail "the control pin changed: $cpin, recorded $(get cpin)"
  fi
  [ "${1:-}" = noport ] && { echo "$pin"; return; }
  outside "$(get ip)" "$pin"
  [ "$(get public)" = 1 ] && publiccheck "$(get domain)" "$(get cpin)"
  printf 'deployment %s\ninstance %s\nip %s\nsha256 %s\npin %s\n' "$(get did)" "$id" "$(get ip)" "$sum" "$pin"
  [ "$(get public)" = 1 ] && printf 'control https://control.%s\ncontrol pin %s\n' "$(get domain)" "$(get cpin)"
  return 0
}

# userdata is the instance's first boot: the canary binary by digest, sshd off, and its service. The hosted canary's
# service also makes its control key on first start, keeps it in its own state directory, and waits for publicstart to
# give it the address it signs (HCN-1).
userdata() {
  local unit_public="" exec_public="" start_now=--now
  if [ "$PUBLIC" = 1 ]; then
    unit_public="StateDirectory=sandprobe-canary
StateDirectoryMode=0700
EnvironmentFile=/etc/sandprobe-canary.env
ExecStartPre=-/usr/local/bin/sandprobe-canary -make-control-key /var/lib/sandprobe-canary/control.key
"
    exec_public=" -public-control control.$DOMAIN -public-addr \${PUBLIC_ADDR} -control-key /var/lib/sandprobe-canary/control.key -acme-cache /var/lib/sandprobe-canary/acme -control-pin-file /var/lib/sandprobe-canary/control.pin"
    [ "$ACME_STAGING" = 1 ] && exec_public+=" -acme-staging"
    start_now=""
  fi
  cat <<EOF
#!/bin/bash
set -euo pipefail
systemctl disable --now sshd.service sshd.socket 2>/dev/null || true
systemctl mask sshd.service sshd.socket
curl -fsS -o /usr/local/bin/sandprobe-canary.new '$1'
echo '$2  /usr/local/bin/sandprobe-canary.new' | sha256sum -c -
install -m 0755 /usr/local/bin/sandprobe-canary.new /usr/local/bin/sandprobe-canary
rm /usr/local/bin/sandprobe-canary.new
if systemctl is-active --quiet systemd-resolved; then
  mkdir -p /etc/systemd/resolved.conf.d
  printf '[Resolve]\nDNSStubListener=no\n' >/etc/systemd/resolved.conf.d/sandprobe.conf
  ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
  systemctl restart systemd-resolved
fi
cat >/etc/systemd/system/sandprobe-canary.service <<'UNIT'
[Unit]
Description=Sandprobe canary (SBX-11)
After=network-online.target
Wants=network-online.target
[Service]
${unit_public}ExecStart=/usr/local/bin/sandprobe-canary -domain $DOMAIN -control /run/sandprobe-canary/ctl.sock$exec_public
DynamicUser=yes
RuntimeDirectory=sandprobe-canary
RuntimeDirectoryMode=0700
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
Restart=on-failure
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable $start_now sandprobe-canary
touch /var/lib/sandprobe-canary.ready
EOF
}

up() {
  local did b bin sum url vpc sg ami id vol alloc ip z rec t n c r itype=t4g.nano recs track_readiness=1
  [ "$PUBLIC" = 1 ] && itype=t4g.small # the hosted canary serves anyone
  [ ! -f "$STATE" ] || fail "a deployment is recorded in $STATE: run status, or down first"
  [ -z "$(aws ec2 describe-instances --filters "Name=tag:Name,Values=$NAME" \
    "Name=instance-state-name,Values=pending,running,stopping,stopped,shutting-down" \
    --query 'Reservations[].Instances[].InstanceId' --output text)" ] || fail "another canary instance is running"
  z=$(cf zones list | jq -er --arg z "$ZONE" '.[] | select(.name == $z) | .id')
  [ "$(cf dns records list -z "$z" --name-endswith "$DOMAIN" | jq length)" = 0 ] || fail "DNS records under $DOMAIN exist"

  did=$(openssl rand -hex 4)
  mkdir -p "$(dirname "$STATE")"
  if [ "${DURABLE_STATE:-0}" = 1 ]; then
    python3 "${BASH_SOURCE[0]%/*}/durable_state.py" init "$STATE" "did=$did" "profile=$PROFILE" "region=$REGION" "zone=$z" "domain=$DOMAIN"
  else
    printf 'did=%s\nprofile=%s\nregion=%s\nzone=%s\ndomain=%s\n' "$did" "$PROFILE" "$REGION" "$z" "$DOMAIN" >"$STATE"
  fi
  put public "$PUBLIC"
  # RUN-16: the durable barrier precedes every create-capable command.
  if [ -n "${SANDPROBE_CANARY_OUTCOME_FILE:-}" ]; then
    [ "${DURABLE_STATE:-0}" = 1 ] || fail "outcome requires durable state"
    python3 "${BASH_SOURCE[0]%/*}/canary_outcome.py" mutation \
      "$SANDPROBE_CANARY_OUTCOME_FILE" "${SANDPROBE_CANARY_OUTCOME_NONCE:?}" "$STATE" "${BASH_SOURCE[0]}"
  fi
  local tags="ResourceType=%s,Tags=[{Key=Name,Value=$NAME},{Key=Project,Value=sandprobe},{Key=$MARK,Value=$did}]"
  local itags="Key=Name,Value=$NAME Key=Project,Value=sandprobe Key=$MARK,Value=$did"

  bin=$(mktemp -d)/sandprobe-canary
  (cd "$(git rev-parse --show-toplevel)" && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o "$bin" ./cmd/sandprobe-canary)
  sum=$(shasum -a 256 "$bin" | cut -d' ' -f1)
  put sha256 "$sum"
  b=$NAME-$did
  create_begin bucket
  aws s3api create-bucket --bucket "$b" --create-bucket-configuration "LocationConstraint=$REGION" >/dev/null
  put bucket "$b"
  create_end bucket
  aws s3api put-bucket-tagging --bucket "$b" --tagging "TagSet=[{Key=Name,Value=$NAME},{Key=Project,Value=sandprobe},{Key=$MARK,Value=$did}]"
  aws s3 cp "$bin" "s3://$b/$sum" --only-show-errors
  url=$(aws s3 presign "s3://$b/$sum" --expires-in 3600)

  create_begin role
  aws iam create-role --role-name "$NAME-$did" --tags $itags --assume-role-policy-document \
    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}' >/dev/null
  put role "$NAME-$did"
  create_end role
  aws iam attach-role-policy --role-name "$NAME-$did" --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore # SSM only
  create_begin iprofile
  aws iam create-instance-profile --instance-profile-name "$NAME-$did" --tags $itags >/dev/null
  put iprofile "$NAME-$did"
  create_end iprofile
  aws iam add-role-to-instance-profile --instance-profile-name "$NAME-$did" --role-name "$NAME-$did"

  vpc=$(aws ec2 describe-vpcs --filters Name=isDefault,Values=true --query 'Vpcs[0].VpcId' --output text)
  create_begin sg
  sg=$(aws ec2 create-security-group --group-name "$NAME-$did" --vpc-id "$vpc" --description "Sandprobe canary (SBX-11)" \
    --tag-specifications "$(printf "$tags" security-group)" --query GroupId --output text)
  [[ $sg =~ ^sg-[a-f0-9]{8,17}$ ]] || fail "sg identity not confirmed"
  put sg "$sg"
  create_end sg
  for p in tcp:80 tcp:443 tcp:8080 udp:53; do # 22 opens only once the canary is proven to hold it
    aws ec2 authorize-security-group-ingress --group-id "$sg" --protocol "${p%:*}" --port "${p#*:}" --cidr 0.0.0.0/0 >/dev/null
  done

  ami=$(aws ssm get-parameter --name /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64 \
    --query Parameter.Value --output text)
  userdata "$url" "$sum" >"$bin.userdata"
  create_begin instance
  id=
  for _ in 1 2 3 4 5 6; do # a new instance profile takes a few seconds to reach EC2
    id=$(aws ec2 run-instances --client-token "sandprobe-canary-$did" --image-id "$ami" --instance-type "$itype" --security-group-ids "$sg" \
      --iam-instance-profile "Name=$NAME-$did" --user-data "file://$bin.userdata" \
      --metadata-options HttpTokens=required,HttpPutResponseHopLimit=1 \
      --tag-specifications "$(printf "$tags" instance)" "$(printf "$tags" volume)" \
      --query 'Instances[0].InstanceId' --output text 2>/dev/null) && break
    sleep 10
  done
  [ -n "$id" ] || fail "run-instances failed"
  [[ $id =~ ^i-[a-f0-9]{8,17}$ ]] || fail "instance identity not confirmed"
  put instance "$id"
  aws ec2 wait instance-running --instance-ids "$id"
  vol=$(aws ec2 describe-instances --instance-ids "$id" \
    --query 'Reservations[0].Instances[0].BlockDeviceMappings[0].Ebs.VolumeId' --output text)
  [[ $vol =~ ^vol-[a-f0-9]{8,17}$ ]] || fail "volume identity not confirmed"
  put volume "$vol"
  create_end instance

  create_begin eip
  alloc=$(aws ec2 allocate-address --domain vpc --tag-specifications "$(printf "$tags" elastic-ip)" --query AllocationId --output text)
  [[ $alloc =~ ^eipalloc-[a-f0-9]{8,17}$ ]] || fail "eip identity not confirmed"
  put eip "$alloc"
  create_end eip
  aws ec2 associate-address --allocation-id "$alloc" --instance-id "$id" >/dev/null
  ip=$(aws ec2 describe-addresses --allocation-ids "$alloc" --query 'Addresses[0].PublicIp' --output text)
  put ip "$ip"
  [ "$PUBLIC" = 1 ] && publicstart "$id" "$ip"

  status noport >/dev/null # sshd off and the canary alone on 22, checked on the instance before 22 opens
  aws ec2 authorize-security-group-ingress --group-id "$sg" --protocol tcp --port 22 --cidr 0.0.0.0/0 >/dev/null

  recs=("A canary.$DOMAIN $ip" "A *.canary.$DOMAIN $ip" "A ns.$DOMAIN $ip" "NS dns.$DOMAIN ns.$DOMAIN")
  [ "$PUBLIC" = 1 ] && recs+=("A control.$DOMAIN $ip")
  for rec in "${recs[@]}"; do # DNS only: a proxy breaks the pin, and the control answers are signed anyway
    read -r t n c <<<"$rec"
    create_begin "dns_$t"
    r=$(cf dns records create -z "$z" --body "$(jq -n --arg t "$t" --arg n "$n" --arg c "$c" \
      '{type: $t, name: $n, content: $c, proxied: false, ttl: 300, comment: "Sandprobe canary (SBX-11), DNS only"}')" | jq -er .id)
    [[ $r =~ ^[a-f0-9]{32}$ ]] || fail "DNS identity not confirmed"
    put dns "$r"
    create_end "dns_$t"
  done
  status
}

# wildcard makes <nonce>.canary.<domain> resolve to the canary: Modal resolves an allowlisted SNI itself (POC-2). It
# adds the one record, DNS only, and records its ID, so down deletes it with the others.
wildcard() {
  local z ip d n r
  [ -f "$STATE" ] || fail "no deployment in $STATE"
  z=$(get zone) ip=$(get ip) d=$(get domain)
  n="*.canary.$d"
  [ -n "$z" ] && [ -n "$ip" ] && [ -n "$d" ] || fail "the deployment in $STATE isn't whole"
  r=$(cf dns records list -z "$z" --name-endswith "$d") || fail "listing DNS records under $d failed"
  if jq -e --arg n "$n" 'if type == "array" then any(.[]; .name == $n) else error("not a list") end' <<<"$r" >/dev/null; then
    fail "$n already exists: down owns only what this script recorded, so remove it by hand first"
  fi
  create_begin wildcard
  r=$(cf dns records create -z "$z" --body "$(jq -n --arg n "$n" --arg c "$ip" \
    '{type: "A", name: $n, content: $c, proxied: false, ttl: 300, comment: "Sandprobe canary (SBX-11), DNS only"}')" | jq -er .id)
  [[ $r =~ ^[a-f0-9]{32}$ ]] || fail "DNS identity not confirmed"
  put dns "$r"
  create_end wildcard
  echo "wildcard: $n -> $ip (record $r)"
}

ctl() {
  local a
  [ -f "$STATE" ] || fail "no deployment in $STATE"
  for a in "$@"; do # names, numbers and nonce/proto/port lists only: they go into a shell on the instance
    [[ $a =~ ^-?[a-z0-9/,-]+$ ]] || fail "not a canary argument: $a"
  done
  owned instance "$(get instance)"
  ssm "$(get instance)" "/usr/local/bin/sandprobe-canary -control /run/sandprobe-canary/ctl.sock -ctl $*"
}

down() {
  local z r id v st ids
  [ -f "$STATE" ] || fail "no deployment in $STATE"
  creates_resolved || fail "unresolved create outcome: preserve deployment and state for owner review"
  z=$(get zone) # DNS first: a record left on a released IP would hand our names to its next holder
  for r in $(sed -n 's/^dns=//p' "$STATE"); do
    ids=$(dnsids "$z")
    ! grep -qx "$r" <<<"$ids" || cf dns records delete -z "$z" "$r" --force >/dev/null
    ids=$(dnsids "$z")
    ! grep -qx "$r" <<<"$ids" || fail "DNS record $r still there"
  done

  id=$(get instance) # an instance EC2 no longer describes is gone; one it still does must carry our marker
  if [ -n "$id" ] && exists ec2 describe-instances --instance-ids "$id"; then
    owned instance "$id"
    st=$(aws ec2 describe-instances --instance-ids "$id" --query 'Reservations[0].Instances[0].State.Name' --output text)
    [ "$st" = terminated ] || aws ec2 terminate-instances --instance-ids "$id" >/dev/null
    aws ec2 wait instance-terminated --instance-ids "$id"
  fi
  v=$(get volume)
  if [ -n "$v" ]; then # the root volume goes with the instance; delete it if it didn't
    for _ in $(seq 36); do
      exists ec2 describe-volumes --volume-ids "$v" || break
      st=$(aws ec2 describe-volumes --volume-ids "$v" --query 'Volumes[0].State' --output text)
      [ "$st" != deleted ] || break
      [ "$st" != available ] || { owned volume "$v"; aws ec2 delete-volume --volume-id "$v"; }
      sleep 5
    done
    ! exists ec2 describe-volumes --volume-ids "$v" ||
      [ "$(aws ec2 describe-volumes --volume-ids "$v" --query 'Volumes[0].State' --output text)" = deleted ] ||
      fail "volume $v still there"
  fi

  r=$(get eip)
  if [ -n "$r" ] && exists ec2 describe-addresses --allocation-ids "$r"; then
    owned eip "$r"
    aws ec2 release-address --allocation-id "$r"
  fi
  [ -z "$r" ] || ! exists ec2 describe-addresses --allocation-ids "$r" || fail "IP $r still there"

  r=$(get sg)
  if [ -n "$r" ] && exists ec2 describe-security-groups --group-ids "$r"; then
    owned sg "$r"
    for _ in $(seq 12); do aws ec2 delete-security-group --group-id "$r" >/dev/null 2>&1 && break; sleep 10; done
  fi
  [ -z "$r" ] || ! exists ec2 describe-security-groups --group-ids "$r" || fail "security group $r still there"

  r=$(get iprofile)
  if [ -n "$r" ] && exists iam get-instance-profile --instance-profile-name "$r"; then
    owned profile "$r"
    for v in $(aws iam get-instance-profile --instance-profile-name "$r" --query 'InstanceProfile.Roles[].RoleName' --output text); do
      aws iam remove-role-from-instance-profile --instance-profile-name "$r" --role-name "$v"
    done
    aws iam delete-instance-profile --instance-profile-name "$r"
  fi
  [ -z "$r" ] || ! exists iam get-instance-profile --instance-profile-name "$r" || fail "instance profile $r still there"

  r=$(get role)
  if [ -n "$r" ] && exists iam get-role --role-name "$r"; then
    owned role "$r"
    for v in $(aws iam list-attached-role-policies --role-name "$r" --query 'AttachedPolicies[].PolicyArn' --output text); do
      aws iam detach-role-policy --role-name "$r" --policy-arn "$v"
    done
    aws iam delete-role --role-name "$r"
  fi
  [ -z "$r" ] || ! exists iam get-role --role-name "$r" || fail "role $r still there"

  r=$(get bucket)
  if [ -n "$r" ] && exists s3api head-bucket --bucket "$r"; then
    owned bucket "$r"
    aws s3 rm "s3://$r" --recursive --only-show-errors
    aws s3api delete-bucket --bucket "$r"
  fi
  [ -z "$r" ] || ! exists s3api head-bucket --bucket "$r" || fail "bucket $r still there"

  r=$(get did)
  mv "$STATE" "$STATE.down-$(date +%Y%m%d%H%M%S)"
  echo "down: deployment $r gone (DNS records, instance, volume, IP, security group, instance profile, role, bucket)"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
case ${1:-} in
up | status | ctl | wildcard | down) "$@" ;;
*) fail "usage: canary.sh up|status|ctl|wildcard|down" ;;
esac

fi
