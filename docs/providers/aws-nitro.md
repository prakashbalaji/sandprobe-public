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
  device. Its vsock still reaches guest-bound ports.
- `reference-open` and `reference-network-isolated`: an operator-hardened reference pod (user 10001, all
  capabilities dropped, read-only root, no service token).

Confidential mode denies `exec` and stdin, so it isn't supported.

## What's skipped, and why

No check is excluded for this provider. These are skipped:

| Check | Why |
|-|-|
| PER-5 | The pod has no persistent volume, so there's nothing a reset could keep. |
| EGR-6 | Contacting public upload sites isn't approved, on any run. |
| EGR-3 | Skipped when the pod's environment names no proxy, or names a local one you didn't approve with `-allow-local-proxy`. |
| AMP-6 | Skipped when the pod has no vsock device. |

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
