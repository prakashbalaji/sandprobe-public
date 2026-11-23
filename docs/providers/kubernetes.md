# Kubernetes: `run kubernetes`

**Status for 0.3.0, being validated:** Stable target. Last validated: pending. [All providers](README.md)

`run kubernetes` makes one throwaway pod in a cluster you run, probes it and deletes it, through the shipped recipe
[`recipes/kubernetes.sh`](../../recipes/kubernetes.sh) and `kubectl` (PRV-16).

## Prerequisites

- An installed `sandprobe`. The recipe is built into it, so you don't need a clone of this repository.
- `kubectl`, and a kubeconfig context for the cluster.
- In the namespace you name: permission to create, get and delete pods, and to create `pods/exec`. The plan checks
  this with `kubectl auth can-i` before anything is created.

## Credentials

None of Sandprobe's own. `kubectl` uses the context you name. The current context is never used, since a kubeconfig
often holds production clusters too.

| Setting | What it is |
|-|-|
| `SANDPROBE_KUBE_CONTEXT` | Required. The kubeconfig context to create the pod in. |
| `SANDPROBE_KUBE_NAMESPACE` | Optional. Defaults to `default`. |
| `SANDPROBE_KUBE_IMAGE` | Optional. Defaults to the debian image pinned by digest in `test/probe.sh`. |
| `SANDPROBE_KUBE_OVERRIDES` | Optional. A JSON merge patch over the generated pod: your agent's `securityContext`, `serviceAccountName`, `runtimeClassName`, `nodeSelector` and so on. |

## Run it

```sh
SANDPROBE_KUBE_CONTEXT=my-cluster sandprobe plan kubernetes -as agent
SANDPROBE_KUBE_CONTEXT=my-cluster sandprobe run kubernetes -as agent -y
```

The pod carries `activeDeadlineSeconds: 3600`, so it stops on its own if cleanup never comes. It is deleted only
through its UID, as a precondition, so no other pod can be deleted. If the plan's context, API server, namespace or
cluster settings change during the run, every later call refuses.

## What's skipped, and why

| Check | Why |
|-|-|
| SEC-4, EGR-3, AMP-6, AMP-7 | Off by default. Whoever hosts the cluster has terms the recipe can't know, so the checks that contact a provider's own endpoints stay off (the recipe's header, PRV-16). |
| PER-5 | The recipe has no reset (RCP-3). |
| EGR-6 | Contacting public upload sites isn't approved, on any run. |

## Terms and consent

The recipe's header says: "Kubernetes is Apache-2.0 software and the cluster is yours. Whoever hosts it (EKS, GKE,
AKS) has terms this recipe can't know, so the checks that contact a provider's own endpoints stay off." Read your
host's terms before you turn any of them on.

## What the score can and can't reach

- Persistence rests on PER-1 to PER-4. Whether anything survives a pod's restart isn't tested.
- The pod is addressed by name, and each call first checks that the name still holds the UID its create returned.
  The race between that check and the call can't be closed, and the report says so.

### Canary and Cloud access (0.3.0)

Test traffic goes to the hosted canary at `control.pub.probe.ac0.dev` by default. It keeps the box's public address,
with the run's nonces, for the run's lifetime (at most 30 minutes), and your machine's public address in a rate
counter for at most an hour, both in memory only. To use a canary you run, name it with
`-canary-url <url> -canary-pin <pin>`, or with `-canary <state file>` for one from `deploy/canary.sh`. With
`-no-canary`, no test traffic leaves the pod: Exfiltration reads "Not tested", and the run can't grade above C.
Cloud access reads "Not tested" and stays red, since SEC-4 and AMP-7 are off. **New in 0.3.0:** if your host's terms
allow it on your own account, turn checks on by name with `-provider-endpoints SEC-4,AMP-7`; the plan lists each one
with your attestation before anything runs, and the report records it beside the check.
