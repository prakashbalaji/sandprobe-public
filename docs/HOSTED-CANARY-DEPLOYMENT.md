# Updating the shared canary

HCN-7 provisions the public receiver with `PUBLIC=1 deploy/canary.sh up`. That is a
new-deployment command, not an updater. Merging code or publishing a GitHub release
does not replace the running service. This is an operator runbook; deployment
requires the owner's verified resource identities and coordinated maintenance.

## Identify the existing deployment

Obtain the original hosted-canary state file and explicit AWS account, profile and
region. Keep these private. Match its immutable instance ID, deployment tag,
Elastic IP, domain, recorded binary SHA-256 and persistent control-key pin against
read-only AWS inventory and independently verified signed public status. Confirm
the recorded bucket and service architecture too. DNS or a Name tag alone is
insufficient. Do not synthesize a deletion-capable state file from an IP lookup.
Never use `up` or `down` to update the existing shared service.

Review the current systemd unit and executable digest through the owner's SSM
path. Check only metadata of the private key: never read, copy or print its value.
Preserve the existing control-key file, ACME directory, service environment,
Elastic IP and DNS. The persistent control-key pin stays unchanged; the receipt
boot pin changes on every restart.

The existing deployment check is:

```sh
PUBLIC=1 PROFILE="$CANARY_PROFILE" REGION="$CANARY_REGION" \
  STATE="$CANARY_STATE" bash deploy/canary.sh status
```

`status` checks the recorded digest and tag. Record a new digest only after
successful verification, retaining the old entry for rollback. Do not change an
expected digest merely to silence a mismatch.

## Prepare before any restart

Build `cmd/sandprobe-canary` for the verified target architecture from a clean,
reviewed commit containing EVD-10 and HCN-8. Record source SHA, Go version and binary
SHA-256 in a private update journal. Use `CGO_ENABLED=0 GOOS=linux`, the explicit
`GOARCH`, `-trimpath` and `-buildvcs=false`. Retain an owner-only copy of the current
binary and exact unit/drop-ins on the instance. Verify its hash against the existing
deployment record. A rebuild of an older source tree is not the deployed rollback
binary.

Stage the new executable separately and verify its digest again on the instance.
Use an owner-approved artifact transfer path. Do not log presigned URLs or use
mutable unverified downloads. Serialize deployment operators with an exclusive
lock. No IAM, network, DNS, instance, key or certificate change is part of this
update.

## Finish existing runs

A deployment already containing HCN-8 supports the following private Unix control
commands, executed on the instance through its existing SSM management path:

```sh
/usr/local/bin/sandprobe-canary -control /run/sandprobe-canary/ctl.sock -ctl drain
/usr/local/bin/sandprobe-canary -control /run/sandprobe-canary/ctl.sock -ctl maintenance
```

Require `ok=true` and `maintenance.draining=true`. Existing runs continue; new
reservations are refused, while previously reserved public runs may still arm.
Wait for BOTH `active_runs=0` and `reservations=0`, then recheck immediately before
stopping. Zero counts with admission open are not clearance. Public reservations
and arms last at most 30 minutes; private runs may last up to one hour. Expiry
without collection does not create valid evidence: the affected client still needs
its run evaluated or explicitly abandoned. A timeout means postpone. Never disarm
another operator's run or infer idleness from quiet traffic.

**Bootstrap limitation:** an older running binary has neither drain nor active
counts. Installing this feature cannot retroactively make its first restart safe.
The service owner must establish an exclusive maintenance window, prevent new
producers through an existing admission mechanism and let outstanding runs finish.
Waiting on an open anonymous endpoint does not prove idleness. If the owner cannot
establish this window, postpone the in-place update and agree a separately reviewed
migration.

## Install, verify and resume

During the confirmed window, stop the service, atomically install the digest-checked
candidate and use a reviewed systemd override to start it with `-start-drained`.
Preserve every original argument and hardening setting. Verify the running digest,
systemd health, private drained/zero state, all existing port health checks and
signed public status under the original persistent control-key pin.

From the controller, check the new capability:

```sh
bin/sandprobe canary check -require-http-marker-v1
```

This proves capability, not guest delivery or reservable capacity. Resume through
the private socket only after those checks pass:

```sh
/usr/local/bin/sandprobe-canary -control /run/sandprobe-canary/ctl.sock -ctl resume
```

Run one bounded owned calibration during the established window: HTTP TCP/80 echo
with its independent receipt, legacy TCP/TLS/DNS controls, and confirmed release.
Private arms are also refused while drained, so a complete receipt calibration
needs this explicit resume. If calibration fails, drain again and wait for all
runs/reservations before rollback. Never stop immediately on the assumption only
the calibration client could have arrived after resume.

Record the new digest and source revision in the owner's deployment journal only
after verification. If `-start-drained` remains in the unit, every restart needs
private resume; document that behavior in monitoring. Then rerun both managed
provider evaluations against the new receipt boot pin. Do not reuse pre-restart
receipts. Keep the rollback binary until the verification period ends.

## Rollback

Before any resume, restore the verified old executable and exact previous
unit/drop-ins, reload systemd and restart. Recheck the original persistent control
pin, old digest and port health. An ambiguous SSM timeout requires read-only
inspection of that exact command/instance, never an automatic second install or
restart. After resume, rollback is another maintenance event: drain and wait first.
An older binary without HCN-8 again needs the coordinated bootstrap window on its
next update. Rollback cannot restore receipts already lost in a restart.
