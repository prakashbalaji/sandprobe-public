# GKE Agent Sandbox: `run exec` through `kubectl exec`

**Status:** Beta: `run exec`, no adapter. Use 0.3.8 or later. Last validated: 25 Nov 2026, one sandbox, Agent
Sandbox v1.0.6 on GKE Autopilot, gVisor runtime. [All providers](README.md)

[Agent Sandbox](https://docs.cloud.google.com/kubernetes-engine/docs/how-to/how-install-agent-sandbox) runs each agent
in its own pod, in GKE's gVisor runtime or in microVMs; Google's recommended policy allows only gVisor. This page covers
gVisor, the runtime that was checked. Sandprobe checks a sandbox you already have with [`run exec`](exec.md),
through `kubectl exec`. It creates nothing in the pod but a scratch directory, which it removes, and never deletes the
sandbox.

In the gVisor sandbox checked on 25 Nov, `/proc/self/status` had no `NoNewPrivs` line, and 0.3.7 and earlier stopped
on it, so that run was invalid. From 0.3.8 the probe reports a missing line as absent: AMP-3 is then unknown, and AMP-2
counts it as possibly off (SBX-4). A gVisor version that reports it gets the usual checks.

## Prerequisites

- An installed `sandprobe` 0.3.8 or later.
- `kubectl`, with a context for the cluster, and permission to `exec` into the sandbox's pod.
- A running Sandbox. Its pod has the Sandbox's name when you create one directly; `kubectl get pods` shows it.

## Run it

```sh
AGENT_USER=1000      # the uid your sandbox runs as: runAsUser in its pod template
POD=my-sandbox       # the sandbox's pod
CONTAINER=runtime    # its container's name in the pod template
sandprobe plan exec -as "$AGENT_USER" -- kubectl --context <context> exec -i "$POD" -c "$CONTAINER" -- sh
sandprobe run exec -as "$AGENT_USER" -y -- kubectl --context <context> exec -i "$POD" -c "$CONTAINER" -- sh
```

Google's recommended policy requires `runAsNonRoot`. Google's direct-Sandbox example sets `runAsUser: 1000`, and in
its busybox image that uid had no passwd entry, so pass your pod's numeric uid to `-as`. The container needs `sh`, `mkdir`, `base64`, `chmod` and `rm`; busybox, the
image in Google's example, has them.

## What to expect

What follows is what one sandbox showed on 25 Nov 2026, made with Google's "create a Sandbox resource directly"
example: busybox as uid 1000, gVisor, no capabilities, no service account token, under Google's recommended policy.
Another template or setup can differ, so read your own report.

- **Containment and Persistence** were green.
- **Privilege**: AMP-2 passed, with no capability held. AMP-3 was unknown, since that sandbox's `/proc/self/status`
  had no `NoNewPrivs` line.
- **Secrets**: the agent could open other processes' environments (SEC-2), so give it no secret in its pod's
  environment.
- **Exfiltration** was open: that Sandbox had no NetworkPolicy, and every route reached our canary. Google's
  [Agent Sandbox page](https://docs.cloud.google.com/kubernetes-engine/docs/concepts/machine-learning/agent-sandbox)
  says the controller creates a default-deny NetworkPolicy for pods made from a SandboxTemplate, and "doesn't create a
  NetworkPolicy resource for a Sandbox resource that you create directly".
- With a NetworkPolicy denying all egress for the sandbox's pods, nothing reached the canary, and no route was
  refused: the attempts got no answer. A silent drop proves nothing, so Sandprobe reported those routes as unproven,
  not blocked. Another cluster's network setup may refuse instead, and then they can read blocked.
- **Cloud access** reads "Not tested" with the commands above, which name neither `-provider` nor
  `-provider-endpoints`. Turn SEC-4 and AMP-7 on with `-provider-endpoints SEC-4,AMP-7` only if you've read the
  terms below and decide they allow it for your project.

Sandprobe scores what the agent can reach inside the pod. It doesn't test gVisor's boundary.

## What's skipped, and why

| Check | Why |
|-|-|
| SEC-4, EGR-3, AMP-6, AMP-7 | Off on `run exec` by default, since they'd contact your provider's own endpoints (PRV-15). |
| PER-5 | An existing box is never reset. |
| EGR-6 | Contacting public upload sites isn't approved, on any run. |

## Terms

Google Cloud's [security FAQ](https://support.google.com/cloud/answer/6262505) says: "If you plan to evaluate the
security of your Cloud Platform infrastructure with penetration testing, you are not required to contact us. You will
have to abide by the Cloud Platform Acceptable Use Policy and Terms of Service, and ensure that your tests only affect
your projects (and not other customers' applications)." The [Acceptable Use Policy](https://cloud.google.com/terms/aup)
(last modified 12 October 2026) forbids using the Services "to test or reverse-engineer the Services in order to find
limitations or vulnerabilities, or to evade filtering capabilities, except as expressly permitted in the Agreement".
The [Service Specific Terms](https://cloud.google.com/terms/service-terms) let a customer "conduct benchmark tests of
the Services" and publicly disclose the results "only if (i) the public disclosure includes all necessary information
to replicate the Tests, and (ii) Customer allows Google to conduct benchmark tests of Customer's publicly available
products or services and publicly disclose the results of such tests", and never on behalf of a hyperscale public
cloud provider without Google's prior written consent. A run checks your own sandbox's configuration, in
your own project, and claims no permission from Google. Read them yourself and decide whether your run fits. If a
report suggests a flaw on Google's side, stop, don't repeat it, and report it through Google's Vulnerability Reward
Program.
