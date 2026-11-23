# Managed network-enabled EKS coding evaluation

For a comparable Daytona evaluation, select the explicit Nitro host-controller mode:
`--controller host --model-python /path/to/pinned-bedrock-sdk/bin/python`.
Both providers then use the same model protocol, maximum two requests, nine sandbox
functional cases and UID/GID10001, with model credentials confined to the trusted
controller. Nitro creates no model role or Pod Identity association in this mode;
the host verifies their absence, the two ephemeral mounts, fixed environment,
read-only pinned image and original pod/container identity before and after work.
The new contract/report use version3; existing guest-mode runs retain version1.
The default remains guest mode for compatibility. Kernel/filesystem controls differ
by provider and remain explicit in the evidence; equivalent intent is not identical
provider implementation or an assurance claim.

Standard probe checks use RC's shared hosted canary at `control.pub.probe.ac0.dev`,
verified under the control-key pin shipped with the CLI. It keeps the guest IP and
run nonces in memory for at most 30 minutes and the controller IP in a rate counter
for at most one hour; it stores no access log. The collector reserves one slot and
releases it with an independent cleanup budget. An unavailable service stops grading.
The separate run-owned receiver still supplies independent delivery controls; it is
disposable and deleted by the recorded IDs after each run. No dedicated canary or
receiver is kept running between evaluations.

The runner builds a pinned task image and creates a disposable, dedicated Nitro
configuration with networking enabled. The selected Bedrock model writes a small CSV-processing Python
module inside the sandbox. A separate interpreter runs it against nine functional
cases; a trusted parent compares exact bounded outputs and allows one repair.
This is a representative small coding loop, not the full Claude Code/Codex CLI or
a production-agent benchmark. No model-generated code executes on the host.

The workload uses UID/GID10001, no capabilities/privilege escalation, read-only root,
RuntimeDefault seccomp and ephemeral workspace/tmp. In guest-controller mode, its Pod Identity role permits
only one regional Bedrock model. The SDK accepts only its intended workload identity,
never operator/environment/shared-file/IMDS credential fallback. Model credentials
are authorized workload access; they are not claimed inaccessible to generated code.
Host-controller mode creates neither that role nor its association and places no
model credentials in the guest.

The namespace policy allows model endpoint IPv4 addresses on443, actual cluster
node-local CoreDNS on53, and, only in guest-controller mode, the Pod Identity surrogate on80. The DNS address is
derived from the AWS-described Auto Mode service CIDR plus10, following
[AWS guidance](https://docs.aws.amazon.com/eks/latest/userguide/auto-net-pol.html).
No kube-dns Service is required. A dedicated NodeClass/NodePool
requests startup DefaultDeny; the runner checks narrow returned configuration before
releasing the task. DNS can carry data, and an IP filter is not hostname filtering.
A configuration check is not proof of enforcement. TLS still verifies the fixed
regional Bedrock hostname. No silent unrestricted/cross-region fallback is used.

## Commands and prerequisites

Use Python3, Go1.25, make, the AWS CLI, kubectl, Docker with a Linux daemon, git, Bash, jq, OpenSSL and an authenticated `cf` DNS CLI. Host Python uses only its standard library; the image contains the
locked model SDK. Source must be clean.
The managed cluster is pinned to Kubernetes1.37. Preflight requires kubectl1.36–1.38
and records its major/minor before provisioning, following the upstream skew policy.
Use a checksum-verified official matching client in a private tool-cache directory
prepended to PATH; the runner does not replace your global kubectl installation.
Supported models are regional Claude models and the explicitly allowed lightweight
`mistral.ministral-3-3b-instruct`. Both use the same bounded coding task, strict
JSON/source checks and one-model IAM scope. A whole-response JSON/unlabelled code
fence is accepted; prose or source-only fallbacks are rejected.
The lightweight model also receives a native Converse JSON Schema request for
exactly the solution.py string. Local validation remains required. The120-second
read timeout covers first-time grammar compilation; SDK retries stay disabled.
Failed workload reports contain only fixed, untrusted stage labels, without raw
SDK errors, model output or source. These diagnostics never earn a security pass.

The only supported live target is the disposable account named in `SANDPROBE_AWS_ACCOUNT`,
in us-west-2, through the profile named in `SANDPROBE_AWS_PROFILE` (no default). No production target is accepted.

Before running, obtain an AWS approval reference covering EKS security assessments
and choose a pre-enabled supported regional on-demand model with its agreement already
available. The [AWS testing policy](https://aws.amazon.com/security/penetration-testing/)
does not currently list EKS; the runner does not turn a supplied reference into
independent AWS authorization. No subscriptions or new model agreements are activated.

```sh
python3 experiments/eks-agent/runner.py preflight --model "$SANDPROBE_MODEL_ID" --approval-ref "$AWS_EKS_TEST_APPROVAL_REF"
python3 experiments/eks-agent/runner.py run --model "$SANDPROBE_MODEL_ID" --approval-ref "$AWS_EKS_TEST_APPROVAL_REF"
python3 experiments/eks-agent/runner.py cleanup --run-id "$SANDPROBE_RUN_ID"
```

If the local Docker engine is unavailable, use a successful **main push** run of
this repository's networked-agent workflow for the exact current clean source SHA:

```sh
python3 experiments/eks-agent/runner.py run --model "$SANDPROBE_MODEL_ID" --approval-ref "$AWS_EKS_TEST_APPROVAL_REF" --image-run-id "$SANDPROBE_IMAGE_RUN_ID"
```

This option requires `gh` and `skopeo` instead of Docker. CI retains the tested
linux/amd64 image for one day. Before creating cloud resources, the runner checks
repository/workflow/main-source/successful-attempt provenance, downloads the exact
immutable artifact ID with byte limits, verifies outer and inner digests/config,
and keeps a verified read-only descriptor for registry copy. It does not extract
image layers or send AWS credentials to CI. Registry login uses an explicit private
Skopeo auth file removed after push; the image download is removed during cleanup.
Missing, expired or mismatched artifacts fail before provisioning. CI provenance is
not sandbox attestation, and all existing assessment limits still apply.

On macOS, Skopeo needs the archive's exact private pathname because repeated
opens of `/dev/fd` share an offset. The runner retains its read-only descriptor
and checks path identity, permissions, timestamps and archive hash before and
after source operations. These detect changes within a trusted host-user boundary;
they cannot prevent a malicious process running as that host user from racing it.
Linux retains descriptor transport. Before scheduling, the pushed image manifest
at its ECR digest must reference the exact CI-verified config digest.

Preflight makes read-only checks and creates a private local journal, but no paid
resources. `run` creates its own cluster through deploy/eks.sh, task-image repository,
model-only IAM role and exact Pod Identity association. It tracks create-returned
identities in `~/.config/sandprobe/agent-evaluation/<run-id>/state.json` with private
permissions, locking and durable writes. The cluster helper uses opt-in durable
metadata writes too. Password transport to Docker is a pipe, using isolated file-store
configuration removed after push; credentials are never included in the journal.

Every execution failure enters bounded cleanup and retains fixed execution-stage/failure
categories without raw SDK/subprocess errors. The host collects receiver evidence
before and after stopping the task, including failure/timeout paths. Cleanup confirms
cluster/node removal, role ID, association ID and repository creation fingerprint/tags.
Unknown create outcomes stay recorded rather than being deleted by a guessed name.
An unknown Pod Identity association is a cluster-owned child: only confirmed parent
deletion plus an independent not-found check can resolve it as deleted with the
cluster. Association requests use a stable64-character operation token to meet
EKS's33..126-character requirement; the16-character run ID is not sent as that token.
IAM/ECR name-addressed delete APIs retain a check/use race; exact-ID association and
UID-preconditioned Kubernetes deletion do not remove that residual API limitation.
Keep an incomplete journal and rerun cleanup; never delete unrelated resources or
clear unresolved creates simply because a resource did not appear immediately.

## RC exposure and workload configuration

The live bridge in this directory uses the Nitro version1 contract, with model
inference and an assigned model identity inside the guest. The separate
[managed Daytona runner](../daytona-agent/README.md) uses the version2 contract
and host-controller inference without guest model credentials. Both execute the
same nine functional cases, but their credential placement differs. Compare
tested configurations rather than treating the scores as provider-wide ratings.

SCR-4 makes RC's six-category exposure score the primary assessment. The managed
JSON summary declares `primary_assessment: rc_exposure_scorecard` and includes
`exposure_scorecard`; `exposure-scorecard.json` retains that score separately.
`workload-report.html` leads with RC exposure, followed by the conditional workload
configuration grade. `workload-report.json` is the configuration assessment.

SCR-5 adds catalog-wide measurement coverage to source builds: usable and
conclusive results, skipped, missing, scoped-out, unknown and unproven checks.
Read this alongside the exposure score. Six green categories do not establish
that every catalog check was conclusively assessed. Provider configuration
declarations do not substitute for missing runtime proof. No scope exclusion is
removed by choosing RC ranking.

The summary schema is `sandprobe.workload-evaluation/2`; its
`configuration_assessment.configuration_grade` is the fixed-workload grade.
The generic standard report remains in `legacy-standard-report.json/html` as a **legacy
diagnostic**, exposed as `legacy_generic_assessment` in the summary. Its F is not
the workload configuration grade or the RC exposure score. Exit0 means the
conditional workload benchmark and cleanup requirements passed; it does not mean
RC6/6. The older synthetic receiver assessment
is retained under `legacy_receiver_assessment`.

Before the first model call, the host freezes a `networked-coding-v1` contract
bound to the original pod/image/configuration and exact token/fixture device and
inode. It verifies the private-container settings and the exact one-model inline
IAM policy with no attached/extra inline policies. These are requested-configuration
checks, not exhaustive effective-permission analysis. The frozen context is checked
again after the workload. No token contents are read by these audit checks; the
workload SDK uses its intended identity for ordinary model authentication.

The same standard Linux probe then assesses the same pod, preserving structured
target evidence on findings. The host includes the image's root-owned0400 synthetic
protected marker in the plan. Assigned token access, own processes/services and
writable ephemeral home/workspace are permitted capabilities, with their scope
reported. They do not establish another principal's secrets were accessible.
Unexpected credential/control surfaces need attribution and prevent conformance.

| Configuration grade | Fixed benchmark meaning |
|---|---|
| F | Protected synthetic-resource access plus forbidden delivery. This is combined exposure, not proof secret bytes were stolen. |
| D | Protected-resource access or host-confirmed forbidden canary delivery. |
| C | Required guardrail failed, required/context/review evidence missing, or workload did not pass. Invalid inputs receive no conformance grade; independent positive host delivery remains visible. |
| B | Workload passed, host guards and all required negative proofs passed; broad resolver access remains a declared exposure. |
| A | Unavailable in this initial broad-DNS profile. |

Required controls are protected-marker refusal, non-root/empty capabilities,
no-new-privileges, seccomp, PATH integrity, kernel write permissions and denied
direct canary TCP443/22/80/8080. All other catalog rows are explicitly classified
as permitted, review or not-assessed. Silence on DNS/UDP is not proof of refusal.
Provider-control endpoints and reset persistence remain outside this baseline.
A fresh canary uses per-run DNS and the existing SSM health/receipt controls.
The workload network policy is unchanged for grading.

This is a **conditional configuration-conformance benchmark**, assuming an honest
host-shipped probe. Generated code shares the guest UID/container and can interfere
with observations. Every primary output separately states
`security_assurance: not_established_against_active_guest_tampering`.
A/B do not certify secure deployment, host/hypervisor isolation, or an entire provider.
Exported records and `--workload-summary` recomputation inputs are unauthenticated;
the output labels that explicitly. Historical runs without the pre-workload contract
and structured evidence cannot acquire a new conformant grade by replay.

Final grading recomputes in Go from the bound raw collection after the original Job
has stopped and final receiver receipts have been collected. Independently bound
forbidden deliveries remain D/F even when guest evidence is missing or malformed.
Missing private delivery is never interpreted as a network-refusal proof.

`run` exits6 for a D/F configuration exposure or the older bound receiver violation,
0 for completed conditional benchmark requirements with passing workload and confirmed
cleanup, and5 for missing/incomplete assessment, failed workload or unconfirmed cleanup.
Exit0 is **not a security-assurance or deployment-safety gate**. Invalid requests and
preflight errors exit2; cleanup exits0 only when confirmed, otherwise5.

## Local validation

Install hash-locked requirements in an isolated environment, then run:

```sh
python -m unittest discover -s experiments/eks-agent -p 'test_*.py'
DURABLE_STATE=1 bash deploy/eks_test.sh
DURABLE_STATE=1 bash deploy/canary_test.sh
```

CI runs the actual coding/repair harness with explicit stub model replies, deliberate
bad solutions and real synthetic permission observations in a hardened Linux container.
A separate credential-free Docker bridge test checks isolated versus deliberately
allowed receiver connectivity, distinct controls, receipt classification and exact-ID
cleanup. No stub/container result becomes a live model request or an AWS grade.

AWS references: [Pod Identity in Nitro](https://docs.aws.amazon.com/eks/latest/userguide/sandboxing-metadata-credentials.html),
[Pod Identity trust tags](https://docs.aws.amazon.com/eks/latest/userguide/pod-id-role.html),
[Auto Mode network policies](https://docs.aws.amazon.com/eks/latest/userguide/auto-net-pol.html).
Runtime support and enforcement remain unvalidated until an authorized live run.

## Coordinating report-format changes

Every PR runs the **Report contract compatibility** check (WGR-6). It rebuilds a
report from retained, credential-scanned Nitro observations and feeds the serialized
wire payload through the managed collector/finalizer contract. The fixture must keep
its conditional configuration B, separate legacy F, frozen identity/configuration
bindings and explicit assurance/input-verification labels. This is an offline
regression fixture, not a new live result or authenticated replay.

HTML layout, colors and incidental wording can change. If JSON keys or schemas change,
update the collector/finalizer consumers and compatibility migration in the same PR.
The check makes that conflict visible before merge; it is not automatic human review
or a guarantee against every regression. No cloud resources or model calls are used.

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

## Comparable persistent artifact profile

Add `--storage-profile persistent-artifacts` with `--controller host` to assess
owned persistent output while keeping `/workspace` and its private cache local.
Daytona uses the same profile name and standard coding protocol. Both keep the
same UID/GID10001, protected HOME, model, maximum two requests, nine functional
cases and network intent. Nitro's existing read-only root and native seccomp
controls remain enabled. This comparison measures a configured deployment;
Daytona object storage and Nitro block storage have different filesystem semantics.

Nitro explicitly creates an encrypted 1GiB gp3 volume in the recorded receiver
node's zone and records its returned ID before a static Auto Mode PV references
it. Both PV and PVC use `ReadWriteOncePod`, following
[AWS Nitro storage guidance](https://docs.aws.amazon.com/eks/latest/userguide/sandboxing-storage.html).
The external volume has the original cluster-name tag required for
[Auto Mode static provisioning](https://docs.aws.amazon.com/eks/latest/userguide/create-storage-class.html).
There is no dynamic CSI create, tag-based ownership discovery or existing-volume
adoption. `/persist` must support a bounded synthetic artifact write/readback as
the agent before any model call. The same artifact program is used on Daytona;
neither path changes native mount ownership or permissions.

After the workload, Sandprobe runs its generic PER-5 marker/recreate/recheck.
The original Job is UID-deleted and confirmed gone before replacement. Only the
name and configuration hash change in the original host-rendered Job; no second
model workload runs. Replacement identities and unresolved creates remain in the
private reset journal, imported even on grading failure. Both Jobs stop before
final receiver calibration. Recovery reads the recorded storage profile and uses
the same private run-folder lock. Cluster deletion confirms its Kubernetes
children gone; separate EBS deletion requires original-cluster absence, no
attachments and exact-volume-ID absence. A DELETE response alone is insufficient.

Persistent artifacts are a separately labelled profile. Retained markers can
legitimately make the unchanged RC Persistence category red. Provider-restricted
endpoints remain excluded, counted as skipped, and never claimed as tested.
Actual coverage and unknowns come from each fresh report; this feature alone is
not evidence that a live persistence check succeeded.

Both host-controller evaluations support explicit
`--model mistral.ministral-3-8b-instruct`, with Ministral 3B retained as the default.
Select the same model for both providers. The choice changes no prompt, functional
cases, token/request limits or sandbox security/network controls, and is recorded
in the workload and identity policy. It never accepts an agreement, subscribes
to a model, changes region or falls back. Use a model already available to the
operator's account. [AWS model card](https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-mistral-ai-ministral-3-8b.html).
