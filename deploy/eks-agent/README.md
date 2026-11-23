# Managed network-enabled EKS coding evaluation

The runner builds a pinned task image and creates a disposable, dedicated Nitro
configuration with networking enabled. The selected Bedrock model writes a small CSV-processing Python
module inside the sandbox. A separate interpreter runs it against nine functional
cases; a trusted parent compares exact bounded outputs and allows one repair.
This is a representative small coding loop, not the full Claude Code/Codex CLI or
a production-agent benchmark. No model-generated code executes on the host.

The workload uses UID/GID10001, no capabilities/privilege escalation, read-only root,
RuntimeDefault seccomp and ephemeral workspace/tmp. Its Pod Identity role permits
only one regional Bedrock model. The SDK accepts only its intended workload identity,
never operator/environment/shared-file/IMDS credential fallback. Model credentials
are authorized workload access; they are not claimed inaccessible to generated code.

The namespace policy allows model endpoint IPv4 addresses on443, actual cluster
node-local CoreDNS on53, and the Pod Identity surrogate on80. The DNS address is
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
python3 deploy/eks-agent/runner.py preflight --model "$SANDPROBE_MODEL_ID" --approval-ref "$AWS_EKS_TEST_APPROVAL_REF"
python3 deploy/eks-agent/runner.py run --model "$SANDPROBE_MODEL_ID" --approval-ref "$AWS_EKS_TEST_APPROVAL_REF"
python3 deploy/eks-agent/runner.py cleanup --run-id "$SANDPROBE_RUN_ID"
```

If the local Docker engine is unavailable, use a successful **main push** run of
this repository's networked-agent workflow for the exact current clean source SHA:

```sh
python3 deploy/eks-agent/runner.py run --model "$SANDPROBE_MODEL_ID" --approval-ref "$AWS_EKS_TEST_APPROVAL_REF" --image-run-id "$SANDPROBE_IMAGE_RUN_ID"
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
python -m unittest discover -s deploy/eks-agent -p 'test_*.py'
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
