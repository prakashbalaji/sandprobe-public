# Managed Daytona coding workload

Standard probe checks use RC's shared hosted canary at `control.pub.probe.ac0.dev`,
verified under the control-key pin shipped with the CLI. It keeps the guest IP and
run nonces in memory for at most 30 minutes and the controller IP in a rate counter
for at most one hour; it stores no access log. The collector reserves one slot and
releases it with an independent cleanup budget. An unavailable service stops grading.
The separate run-owned receiver still supplies independent delivery controls; it is
disposable and deleted by the recorded IDs after each run. No dedicated canary or
receiver is kept running between evaluations.

EVD-5 retains a pre-model `configuration-evidence.json` artifact using the same
wire format as Nitro. Snapshot metadata and private API visibility do not verify
runtime image content or process isolation; unavailable readbacks remain unknown.
See [configuration evidence](../../docs/CONFIGURATION-EVIDENCE.md).

RUN-10 runs the same CSV coding task and nine functional cases as Nitro, with up to
two requests to the existing regional Bedrock Ministral3B model. Model inference
runs on the trusted host; generated code executes only inside the original owned
Daytona sandbox. No operator, model or Daytona management credentials enter the guest.
The host model client uses the exact hash-locked Nitro boto3/botocore environment;
its version, request shape and experiment-account identity are checked before provisioning.
Compare with Nitro's explicit `--controller host --model-python <pinned interpreter>` mode,
which uses the same host-controller pattern and shared worker. Legacy Nitro guest-mode
runs contain an assigned model identity and must be labeled separately.

Trusted management first records its actual guest UID and utility availability.
When needed it uses the image's configured noninteractive administrator, separately
from the benchmark agent, and verifies UID0 before setup. It prepares root-owned read-only synthetic fixtures and
launches both workload and probe through the same UID/GID10001 wrapper, with all
capability sets dropped, no supplementary groups, no-new-privileges and a clean
environment. It does not attempt privilege acquisition from the workload. The
snapshot's seccomp and filesystem settings are observed as supplied. Networking
permits the resolved IPv4 addresses of the fixed regional model endpoint; the
workload checks its TLS certificate separately. The network configuration is
unchanged for collection.

SCR-4 makes RC's six-category exposure score the primary assessment.
`evaluation.json` declares `primary_assessment: rc_exposure_scorecard` and includes
`exposure_scorecard`; `exposure-scorecard.json` retains that score separately.
`workload-report.html` leads with RC exposure, followed by the conditional workload
configuration grade. `workload-report.json` is the configuration assessment.
Legacy generic reports and raw observations remain separate diagnostic records.

SCR-5 adds catalog-wide measurement coverage to source builds. Usable results,
conclusive results and every skipped, missing, scoped-out, unknown or unproven
check remain visible beside the score. Six green categories do not establish
that every check was conclusively assessed. Changing ranking does not remove
missing runtime-image/process proof or authorize additional endpoint checks.
Nitro's default guest-controller profile uses guest-side model inference and an
assigned model identity. Select its explicit host-controller mode, described above,
for the comparable credential-free host-controller workload; label legacy guest-mode
results separately.

EVD-1 also exports `evidence-coverage.json` and includes an evidence section in
the primary HTML. It uses the scorecard's six published category names (SCR-1) while
retaining workload-context results; it is not the scorecard's numeric score. Related unknowns
are grouped by missing measurement, with evidence source and next action. Missing
collector output is distinguished from missing configuration evidence, without
claiming a provider cannot support the feature. No required check is waived.
The existing image/process/receiver gaps below remain unknown until measured.

EVD-2 retains fixed TCP exchange-stage diagnostics when the owned-canary exchange
runs. A connected socket may still fail at TLS handshake, marker send or reply
receive. These labels contain no raw errors or response bodies and never replace
the kernel-refusal or host-receipt proof. Older records show exchange diagnostics
as unavailable; they are not reinterpreted as new observations. The host summary
tool exposes the same view to Nitro via `--workload-summary --include-coverage`.

Daytona's native snapshot metadata currently exposes UUIDs and tagged registry
references, not an OCI image-content verification result. WGR-8 preserves that
as `image-content-binding: unknown`. API `public=false` is not private-process
namespace verification, so the corresponding host guard remains unverified.
MEAS-1–4 adds the shared receiver calibration used by provider adapters. The host
freezes the receiver identity, endpoint, pin and three nonces before the first
model call. Only the middle nonce reaches the guest probe. Host-only controls
run before the workload and after confirmed original-sandbox deletion; final
receipts are collected after a grace interval. `receiver-binding.json` and
`receiver-calibration.json` preserve that evidence. This receiver's public or
private address scope is explicit: a public receiver does not measure private
network isolation. A calibrated missing receipt is not proof of refusal.

Image and private-process evidence gaps still prevent A/B, even if all nine functional
cases pass. A C with missing evidence is not a provider vulnerability or proof
that its isolation failed. Required positive exposures remain D/F under WGR-3.

RUN-23 adds internal owned-volume and recreate support for a separately labelled
persistent-workspace assessment. Managed live selection is not enabled yet; the
default ephemeral workload still skips PER-5. Volume creation and each sandbox
consumer have durable exclusive intents and returned-ID records. A lost create
response blocks reuse and storage deletion, rather than adopting a resource by name.
The reset adapter verifies the original context, deletes the original sandbox,
recreates with the same volume ID/path/subpath and uses the existing PER-5 engine.
It does not repair persisted paths during recreation. Partial replacements stay
tracked through teardown, and a delete request is not deletion confirmation.

[Daytona volumes](https://www.daytona.io/docs/en/volumes/) use FUSE over object storage;
[Nitro EBS volumes](https://docs.aws.amazon.com/eks/latest/userguide/sandboxing-storage.html)
are block-backed filesystems. These are comparable persistence intentions, not
identical filesystem implementations. UID permissions and workload filesystem
compatibility must pass preflight and the same nine functional cases before any
live persistent-profile result is presented. Do not relax the agent identity or
label a setup failure as a security pass.

## Run and recovery

Use a clean reviewed source checkout, Go1.25.14, Python3, the hash-locked Daytona
SDK environment, a separate Python3.10+ environment installed from
`deploy/eks-agent/requirements.lock`, AWS CLI, Bash, make, jq, OpenSSL and the existing owned-zone `cf`
helper. The DNS reference contains only an existing secret identifier and zone
ID; its token is fetched in memory and never included in guest environments or
records. AWS is restricted to the account named in `SANDPROBE_AWS_ACCOUNT`,
us-west-2 and the profile named in `SANDPROBE_AWS_PROFILE` (no default); the DNS token is read through
`SANDPROBE_AWS_BOOTSTRAP_PROFILE`. No new model agreement is enabled.

```sh
python3 deploy/daytona-agent/run.py \
  --key-file /path/to/owner-only-daytona.key \
  --sdk-python /path/to/pinned-sdk/bin/python \
  --model-python /path/to/pinned-nitro-bedrock-sdk/bin/python \
  --go /path/to/go1.25.14/bin/go \
  --cf-helper /path/to/owned-zone-cf-helper \
  --dns-reference /path/to/private-dns-reference.json
```

The script creates one private journal/output directory under
`~/.config/sandprobe/daytona-workload-<run-id>`, provisions a dedicated canary and
makes exactly one sandbox create attempt. It does not reuse an existing operator canary
or retry an ambiguous create. It freezes the native configuration/fixture
contract before the first model call, preserves failed workload records and
confirms original-ID sandbox cleanup before releasing receiver IP/DNS resources.
Unconfirmed sandbox cleanup retains the receiver and recovery journal.

For interrupted cleanup, pass the printed run ID with `--cleanup-run <run-id>`
and the same access/tool arguments. Recovery uses recorded original IDs only;
it makes no sandbox create or model request. Never delete by a guessed name.
The script exits5 on incomplete execution, assessment or cleanup, and6 on a
configuration exposure graded D/F. Exit0 requires passing workload/benchmark
requirements and confirmed cleanup. Inspect the primary assessment for grade
and unknowns; exit0 is not a deployment-security gate or a claim of RC6/6.
Exit5 can accompany a passed nine-case workload when configuration evidence is
incomplete. Check workload success, RC exposure, coverage and cleanup separately.

Run records remain private until credential-scanned and reviewed for internal
publication. Neither exported records nor host declarations are attestations.

For the same explicit EGR-6 workload-host measurement on both providers, add
`--upload-hosts bedrock-runtime.us-west-2.amazonaws.com` to the managed run command.
The common shipped policy is `internal/catalog/upload_hosts.json`; select at most
four exact names separated by commas. This sends only a certificate-verified TLS
handshake to one public address per name, with no HTTP request or upload. It is
off by default. Invalid selections stop before provisioning. A reachable intended
model endpoint remains an exposure indicator in RC scoring; it does not prove an
upload or a violation of the workload contract. DNS/transport failures remain unknown.

Host-controller workload commands and probes share the explicit clean environment
in `internal/host/workload_environment.json`; incidental image variables and
credentials are not inherited. Nitro verifies its original container command uses
that same prefix before each bound probe. This is a declared workload configuration,
not a filter applied only while measuring. Legacy guest-identity mode is unchanged.
