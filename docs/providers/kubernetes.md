# Kubernetes: `run kubernetes`

**Status:** Stable target. Last validated: 25 Nov 2026, on AWS Nitro Sandboxes (EKS Auto Mode, starting with no node) and a
local kind cluster, with the code released as 0.3.6. [All providers](README.md)

`run kubernetes` makes one throwaway pod in a cluster you run, probes it and deletes it, through the shipped recipe
[`recipes/kubernetes.sh`](../../recipes/kubernetes.sh) and `kubectl` (PRV-16).

## Prerequisites

- An installed `sandprobe`. The recipe is built into it, so you don't need a clone of this repository.
- `kubectl`, and a kubeconfig context for the cluster. `kubectl` reads the kubeconfig that `KUBECONFIG` names, or
  `~/.kube/config` when it's unset. If your cluster's context is in another file, set `KUBECONFIG` to that file.
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
| `SANDPROBE_KUBE_OVERRIDES` | Optional. The path to a file that holds a JSON merge patch over the generated pod: your agent's `securityContext`, `serviceAccountName`, `runtimeClassName`, `nodeSelector` and so on. `kubectl` reads the file with `--patch-file`. Inline JSON isn't a file, so the run stops with "can't read SANDPROBE_KUBE_OVERRIDES". A `containers` list replaces the generated one, so give it the image and a long-running command. |
| `KUBECONFIG` | Optional, and `kubectl`'s own setting: the kubeconfig file that holds the context. If it's unset, `kubectl` reads `~/.kube/config`. |

## Run it

```sh
AGENT_USER=root   # set it to the user your agent runs as in the pod; the default debian image runs as root
SANDPROBE_KUBE_CONTEXT=my-cluster sandprobe plan kubernetes -as "$AGENT_USER"
SANDPROBE_KUBE_CONTEXT=my-cluster sandprobe run kubernetes -as "$AGENT_USER" -y
```

If the cluster's context is in another kubeconfig file, name that file with `KUBECONFIG`:

```sh
AGENT_USER=root   # the user your agent runs as in the pod
KUBECONFIG=$HOME/.kube/staging.yaml SANDPROBE_KUBE_CONTEXT=staging sandprobe run kubernetes -as "$AGENT_USER" -y
```

The pod carries `activeDeadlineSeconds: 3600`, so it stops on its own if cleanup never comes. It is deleted only
through its UID, as a precondition, so no other pod can be deleted. If the plan's context, API server, namespace or
cluster settings change during the run, every later call refuses.

### Who the probe runs as: `-as`

`-as` takes the user your agent really runs as in the pod: a name, or a numeric uid. It doesn't switch users.
`kubectl exec` runs as the container's user, and `-as` checks that user before any check runs. The default debian
image has no `agent` user and runs as root. To run as your agent's user, set it in your overrides
(`securityContext.runAsUser`), or use your agent's own image with `SANDPROBE_KUBE_IMAGE`.

- If the pod's `/etc/passwd` has no user by that name, the run stops before any check with
  `the box has no user "agent"`. The pod already exists by then, so Sandprobe deletes it, and the run exits 5 (7 if
  the delete isn't confirmed). A numeric uid, such as `-as 1000`, doesn't need a passwd entry.
- If the user exists but the pod runs as someone else, the run stops in the same way, for example with
  `the command runs as uids 0/0/0/0, not agent's 1000`.
- Without `-as`, the probe runs as the pod's user, and the report says that user isn't confirmed as the agent's.

### AWS Nitro Sandboxes on your own EKS cluster

To grade a pod with the `isolated-sandbox` runtime class, put the runtime class in an overrides file:

```sh
cat > nitro-overrides.json <<'EOF'
{"spec": {"runtimeClassName": "isolated-sandbox"}}
EOF
AGENT_USER=root   # the user your agent runs as in the pod
SANDPROBE_KUBE_CONTEXT=my-eks SANDPROBE_KUBE_OVERRIDES=./nitro-overrides.json \
  sandprobe run kubernetes -as "$AGENT_USER" -y
```

On EKS Auto Mode the first run may start a node. Sandprobe waits up to three minutes for the pod to be ready, then up
to 90 seconds for the node to take `kubectl exec`. If it still isn't ready, run again: the node may be up by then.

A run there is expected to finish incomplete and exit 5: the 25 Nov run ended with SEC-5 unknown, its score and reports
written and its pod confirmed deleted. [AWS Nitro on EKS](aws-nitro.md#exit-5-incomplete-is-expected) says how to tell
that from a run that stopped, which prints no score.

The cluster must offer that runtime class: `kubectl get runtimeclass isolated-sandbox` names it. For the cluster that
`deploy/eks.sh up` makes, `PROFILE="$AWS_PROFILE" deploy/eks.sh status` prints its kubeconfig and its
cluster name. Set `KUBECONFIG` to that kubeconfig and `SANDPROBE_KUBE_CONTEXT` to the cluster name, which is also
the context's name. The four checks below stay off by default under the recipe, while `run aws-nitro` excludes none
of them ([AWS Nitro on EKS](aws-nitro.md)).

## What's skipped, and why

| Check | Why |
|-|-|
| SEC-4, EGR-3, AMP-6, AMP-7 | Off by default, since whoever hosts the cluster has terms the recipe can't know (the recipe's header, PRV-16). SEC-4, EGR-3 and AMP-7 would contact the provider's own endpoints: cloud metadata, the pod's proxy, the Kubernetes API. AMP-6 only checks for a vsock device and connects to nothing. |
| PER-5 | The recipe has no reset (RCP-3). |
| EGR-6 | Contacting public upload sites isn't approved, on any run. |

## Terms and consent

The recipe's header says: "Kubernetes is Apache-2.0 software and the cluster is yours. Whoever hosts it (EKS, GKE,
AKS) has terms this recipe can't know, so the checks that contact a provider's own endpoints stay off." Read your
host's terms before you turn any of them on. For EKS, [AWS Nitro on EKS](aws-nitro.md#terms-and-consent) quotes
AWS's penetration testing policy.

## What the score can and can't reach

- Persistence rests on PER-1 to PER-4. Whether anything survives a pod's restart isn't tested.
- The pod is addressed by name, and each call first checks that the name still holds the UID its create returned.
  The race between that check and the call can't be closed, and the report says so.

### Canary and Cloud access (0.3.0)

Test traffic goes to the hosted canary at `control.pub.probe.ac0.dev` by default. It keeps the box's public address,
with the run's nonces, for the run's lifetime (at most 30 minutes), and your machine's public address in a rate
counter for at most an hour, both in memory only. To use a canary you run, name it with
`-canary-url <url> -canary-pin <pin>`, or with `-canary <state file>` for one from `deploy/canary.sh`. With
`-no-canary`, the probe sends no test traffic to any canary: Exfiltration reads "Not tested", and the run finishes
incomplete (exit 5). Checks you turn on with `-provider-endpoints` that don't need a canary still make the connections the
plan names: SEC-4's requests to the cloud metadata addresses and AMP-7's TLS handshake with the Kubernetes API.
EGR-3 doesn't run, since it needs a canary, and AMP-6 only checks for a vsock device and connects to nothing.
Cloud access reads "Not tested" and stays red, since SEC-4 and AMP-7 are off. **New in 0.3.0:** if your host's terms
allow it on your own account, turn checks on by name with `-provider-endpoints SEC-4,AMP-7`; the plan lists each one
with your attestation before anything runs, and the report records it beside the check.
