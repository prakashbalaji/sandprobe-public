# AWS Nitro Sandboxes on EKS: `run aws-nitro`

**Status for 0.3.0, being validated:** Stable target. Last validated: pending. [All providers](README.md)

`run aws-nitro` creates one pod with the `isolated-sandbox` runtime class in an EKS Auto Mode cluster that only
Sandprobe uses, probes it and deletes it (the AWS Nitro row in SPEC.md).

## Prerequisites

- An installed `sandprobe`, and a clone of this repository for `deploy/eks.sh`.
- An AWS account of your own, and the AWS CLI with a profile for it. The cluster costs money until you delete it.
- `kubectl`, `python3` and `openssl`, which `deploy/eks.sh` uses.

## Credentials

| Name | What it is |
|-|-|
| `PROFILE` | The AWS CLI profile `deploy/eks.sh` uses to make and delete the cluster. It has no default. |

`deploy/eks.sh up` writes Sandprobe's own kubeconfig. Sandprobe uses that one, never yours.

## Run it

```sh
PROFILE=<your profile> deploy/eks.sh up        # the cluster, its two IAM roles and Sandprobe's kubeconfig
sandprobe plan aws-nitro -variant isolated
sandprobe run aws-nitro -variant isolated -y
sandprobe run aws-nitro -variant network-isolated -y
PROFILE=<your profile> deploy/eks.sh down      # deletes exactly what up recorded, and confirms each is gone
```

`-variant` picks the pod:

- `isolated`: the EKS docs' own example, `amazonlinux:2023` as its image's default user.
- `network-isolated`: the same, with `sandbox.amazonaws.com/network-isolated: "true"`, so it boots with no network
  device. AWS's [network isolation](https://docs.aws.amazon.com/eks/latest/userguide/sandboxing-network-isolation.html)
  page, read 23 Nov 2026, says the guest's vsock device "is accessible to all processes inside the guest, including
  container workloads". A run on 23 Nov 2026 found no `/dev/vsock` in this pod's container, so AMP-6 was skipped with "no vsock
  device". AMP-6 looks only for that device file, so on this pod it doesn't test the vsock channel AWS describes. The
  skip isn't a pass: the report lists AMP-6 as skipped, with that reason.
- `reference-open` and `reference-network-isolated`: an operator-hardened reference pod (user 10001, all
  capabilities dropped, read-only root, no service token).

Confidential mode denies `exec` and stdin, so it isn't supported.

### Exit 5: incomplete is expected

A run on the `isolated` or `network-isolated` pod is expected to finish incomplete, and exit 5. Incomplete means some
checks ended unknown: the probe couldn't settle them either way, and the report gives each one's reason. The grade
then carries the count, such as `C (incomplete: 3 unknown)`, and is never A or B (GRD-2). The run still finished: its
pod was confirmed deleted, since a pod that isn't makes the run exit 7 instead, and its reports were written.

In a script, treat 5 as "ran, with unknowns", and confirm it from the JSON report (`-o json`): `grade.valid` is true,
`grade.complete` is false, and `grade.unknown` lists the checks. Two other cases exit 5, with no letter: an invalid
run, whose `grade.valid` is false and whose `grade.invalid` says why, and a run that stopped on an error once its pod
was deleted, which prints the error instead of a report. A grade below `-min` exits 6, which outranks 5. The README
lists every exit code under [What it checks](../../README.md#what-it-checks), and SPEC.md's OUT-4 is the rule.

### Cost

The cluster costs money for as long as it's up. EKS charges for the cluster every hour it exists, and for the EC2
instances Auto Mode launches to run pods: Auto Mode's charge on top of each instance's own price. AWS's
[EKS pricing](https://aws.amazon.com/eks/pricing/) page has the rates. When you're done, always run
`PROFILE="$AWS_PROFILE" deploy/eks.sh down`. It deletes exactly what `up` recorded and confirms each is gone.

## Already have a Nitro cluster?

`run aws-nitro` uses only the cluster `deploy/eks.sh up` makes. For a cluster you already run:

- `run kubernetes` creates one throwaway pod in it, probes it and deletes it. Give the pod the `isolated-sandbox`
  runtime class with an overrides file, as in
  [AWS Nitro Sandboxes on your own EKS cluster](kubernetes.md#aws-nitro-sandboxes-on-your-own-eks-cluster).
- `run exec` probes your agent's own pod, already running, through `kubectl exec`, and never resets or deletes it:

```sh
KUBECONFIG="$HOME/.kube/my-eks.yaml"   # the kubeconfig that holds your cluster's context
CONTEXT=my-eks                         # that context's name
POD=my-agent                           # your agent's pod, in the context's namespace
AGENT_USER=agent                       # set it to the user your agent runs as in the pod
sandprobe run exec -as "$AGENT_USER" -y -- kubectl --kubeconfig "$KUBECONFIG" --context "$CONTEXT" exec -i "$POD" -- sh
```

`-as` checks the user and doesn't switch to it. `kubectl exec` runs as the container's user, so the run stops before
any check if that user isn't `$AGENT_USER`, or if the pod has no such user. `amazonlinux:2023`, the EKS docs'
example, runs as root. [`run exec`](exec.md#run-it) has the details.

Both commands leave SEC-4, EGR-3, AMP-6 and AMP-7 off by default: each contacts the provider's own endpoints, and
neither command knows who hosts your cluster. `run aws-nitro` excludes none of them. Read
[Terms and consent](#terms-and-consent) before you turn any on with `-provider-endpoints`.

## What's skipped, and why

No check is excluded for this provider. These are skipped:

| Check | Why |
|-|-|
| PER-5 | The pod has no persistent volume, so there's nothing a reset could keep. |
| EGR-6 | Contacting public upload sites isn't approved, on any run. |
| EGR-3 | Skipped when the pod's environment names no proxy, or names a local one you didn't approve with `-allow-local-proxy`. |
| AMP-6 | Skipped when the pod's container has no `/dev/vsock`. |

## Terms and consent

The AWS Nitro row records the AWS documentation it follows (the EKS user guide's Nitro Sandboxes pages, read 10 Nov
2026), not a review of AWS's terms. The cluster, its account and its pods are yours. AWS publishes its
[policy for security testing](https://aws.amazon.com/security/penetration-testing/); read it, and get any approval
it asks for, before a run.

## What the score can and can't reach

- Persistence rests on PER-1 to PER-4. Whether anything survives a reset isn't tested.
- Each pod is deleted by name once its UID is checked, inside a cluster only Sandprobe uses.

### Canary and Cloud access (0.3.0)

Test traffic goes to the hosted canary at `control.pub.probe.ac0.dev` by default. It keeps the box's public address,
with the run's nonces, for the run's lifetime (at most 30 minutes), and your machine's public address in a rate
counter for at most an hour, both in memory only. To use a canary you run, name it with
`-canary-url <url> -canary-pin <pin>`, or with `-canary <state file>` for one from `deploy/canary.sh`. Cloud access
is tested: SEC-4 asks the cloud metadata addresses `sandprobe plan aws-nitro` lists which identity the pod has, and
AMP-7 makes a TLS handshake, with no request, to the Kubernetes API the pod's environment names. The score is out of
six.
