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
| `PROFILE` | The AWS CLI profile `deploy/eks.sh` uses to make and delete the cluster. It has no default. The commands below take it from `AWS_PROFILE`; if that isn't set, write the profile's name instead. |

`deploy/eks.sh up` writes Sandprobe's own kubeconfig. Sandprobe uses that one, never yours.

## Run it

```sh
PROFILE="$AWS_PROFILE" deploy/eks.sh up        # the cluster, its two IAM roles and Sandprobe's kubeconfig
sandprobe plan aws-nitro -variant isolated
sandprobe run aws-nitro -variant isolated -y
sandprobe run aws-nitro -variant network-isolated -y
PROFILE="$AWS_PROFILE" deploy/eks.sh down      # deletes exactly what up recorded, and confirms each is gone
```

`-variant` picks the pod:

- `isolated`: the EKS docs' own example, `amazonlinux:2023` as its image's default user.
- `network-isolated`: the same, with `sandbox.amazonaws.com/network-isolated: "true"`, so it boots with no network
  device. AWS's [network isolation](https://docs.aws.amazon.com/eks/latest/userguide/sandboxing-network-isolation.html)
  page, read 23 Nov 2026, says the guest's vsock device "is accessible to all processes inside the guest, including
  container workloads". A run on 23 Nov 2026 found no `/dev/vsock` in this pod's container, so AMP-6 was skipped
  with "no vsock device". AMP-6 looks only for that device file, so on this pod it doesn't test the vsock channel AWS
  describes. The skip isn't a pass: the report lists AMP-6 as skipped, with that reason.
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

Both commands leave SEC-4, EGR-3, AMP-6 and AMP-7 off by default, since neither knows who hosts your cluster. SEC-4,
EGR-3 and AMP-7 would contact the provider's own endpoints: cloud metadata, the pod's proxy and the Kubernetes API.
AMP-6 contacts nothing: it only checks for a vsock device, and on `run exec`'s existing pod it doesn't run at all.
`run aws-nitro` excludes none of them. Read [Terms and consent](#terms-and-consent) before you turn any on with
`-provider-endpoints`.

## What's skipped, and why

No check is excluded for this provider. These are skipped:

| Check | Why |
|-|-|
| PER-5 | The pod has no persistent volume, so there's nothing a reset could keep. |
| EGR-6 | Contacting public upload sites isn't approved, on any run. |
| EGR-3 | Skipped when the pod's environment names no proxy, or names a local one you didn't approve with `-allow-local-proxy`. |
| AMP-6 | Skipped when the pod's container has no `/dev/vsock`. |

## Terms and consent

The AWS Nitro row in SPEC.md records AWS's terms as read on 23 Nov 2026. AWS's
[penetration testing policy](https://aws.amazon.com/security/penetration-testing/) says:

> AWS customers are welcome to carry out security assessments or penetration tests of their AWS infrastructure without
> prior approval for the services listed in the next section under “Permitted Services.”

Amazon EKS isn't on that list. Its EC2 and ECS lines read "Amazon EC2 instances, WAF, NAT Gateways, and Elastic Load
Balancers" and "Amazon Elastic Container Service". For a service that isn't listed, the policy says: "Customers seeking
to test non approved services will need to work directly with AWS Support or your account representative." It also says:
"Customers are not permitted to conduct any security assessments of AWS infrastructure or the AWS services themselves."
Its "security assessment" covers activity "performed remotely against your AWS assets, amongst/between your AWS assets,
or locally within the virtualized assets themselves".

AWS's [Acceptable Use Policy](https://aws.amazon.com/aup/) (last updated 1 July 2021) forbids using AWS's services "to
violate the security, integrity, or availability of any user, network, computer or communications system, software
application, or network or computing device".

What a run does: Sandprobe creates one pod in your own cluster and probes it from inside. SEC-4 asks the metadata
addresses the plan lists, your own node's instance metadata service among them, which role or identity the pod can
reach. It never asks for a role's credential document. AMP-7 makes only a TLS handshake, with no request, with your
own cluster's Kubernetes API. AMP-6 connects to nothing: it only checks for a vsock device. The other checks' test
traffic goes to the canary, and the canary's names are looked up through the pod's own resolver. EGR-3 sends its
attempt through a proxy only when the pod's environment names one. `deploy/eks.sh` makes and deletes the cluster
through AWS's API, and Sandprobe reaches the pod through `kubectl`, both with your own credentials.

A run doesn't carry AWS's permission, and Sandprobe doesn't claim AWS's approval. Read the policy yourself and
decide whether your run fits it, and whether to work with AWS Support or your account representative first.

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
