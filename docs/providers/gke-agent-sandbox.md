# GKE Agent Sandbox: `run exec` through `kubectl exec`

**Status:** Beta: `run exec`, no adapter. Needs 0.3.8 or later. Last validated: 25 Nov 2026, one sandbox, Agent
Sandbox v1.0.6 on GKE Autopilot (gVisor). [All providers](README.md)

[Agent Sandbox](https://docs.cloud.google.com/kubernetes-engine/docs/how-to/how-install-agent-sandbox) runs each agent
in its own pod, in GKE's gVisor runtime. Sandprobe checks a sandbox you already have with [`run exec`](exec.md),
through `kubectl exec`. It creates nothing in the pod but a scratch directory, which it removes, and never deletes the
sandbox.

Before 0.3.8, every run here was invalid: GKE's gVisor leaves `NoNewPrivs` out of `/proc/self/status`, and the probe
stopped. From 0.3.8 the probe reports it as absent, so AMP-3 is unknown, and AMP-2 counts it as possibly off (SBX-4).

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

Google's recommended policy requires `runAsNonRoot`, and its examples set `runAsUser: 1000`, often with no passwd
entry, so pass the numeric uid to `-as`. The container needs `sh`, `mkdir`, `base64`, `chmod` and `rm`; busybox, the
image in Google's example, has them.

## What to expect

What follows is what one sandbox showed on 25 Nov 2026, made with Google's "create a Sandbox resource directly"
example: busybox as uid 1000, gVisor, no capabilities, no service account token, under Google's recommended policy.
Another template or setup can differ, so read your own report.

- **Containment and Persistence** were green.
- **Privilege**: AMP-2 passed, with no capability held. AMP-3 was unknown, since gVisor doesn't report `NoNewPrivs`.
- **Secrets**: the agent could open other processes' environments (SEC-2), so give it no secret in its pod's
  environment.
- **Exfiltration** was open: that Sandbox had no NetworkPolicy, and every route reached our canary. Google's
  [Agent Sandbox page](https://docs.cloud.google.com/kubernetes-engine/docs/concepts/machine-learning/agent-sandbox)
  says the controller creates a default-deny NetworkPolicy for pods made from a SandboxTemplate, and "doesn't create a
  NetworkPolicy resource for a Sandbox resource that you create directly".
- With a NetworkPolicy denying all egress for the sandbox's pods, nothing reached the canary, but GKE drops blocked
  packets rather than refusing them, and a silent drop proves nothing. So Sandprobe reported those routes as unproven,
  not blocked.
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
The [Service Specific Terms](https://cloud.google.com/terms/service-terms) let a customer benchmark the Services and
publish the results only with everything needed to replicate them. A run checks your own sandbox's configuration, in
your own project, and claims no permission from Google. Read them yourself and decide whether your run fits. If a
report suggests a flaw on Google's side, stop, don't repeat it, and report it through Google's Vulnerability Reward
Program.
