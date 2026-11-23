# Sandprobe

Sandprobe answers one question about an AI agent's sandbox: **what could a hijacked agent reach?**

A small, read-only probe runs inside the box, as the agent. In about a minute it checks four things: secrets it can
read, ways out, persistence that survives a reset, and amplifiers such as sudo, capabilities and control sockets.
The host then grades the box from what was proven, and writes a JSON report and a self-contained HTML page.

**No false passes.** A check passes only on a negative proof, such as a refusal next to an allowed twin. Anything that
failed quietly is "unknown", never a pass. The probe never reads a secret's value.

> Early days: version 0.x. The rules are in [SPEC.md](SPEC.md), and every behaviour traces to a rule ID there.

## Quick start

You need Go 1.25, and Docker for `run docker` and the fixture tests.

```sh
git clone https://github.com/summationai/sandprobe
cd sandprobe
make                        # builds the Linux probes, then bin/sandprobe with them embedded
bin/sandprobe providers     # what's ready on this machine, and how to set up the rest
bin/sandprobe explain EGR-2 # what a check does, what a finding means, and the fix
```

## Check a sandbox

**A box you already have.** Give Sandprobe any command that opens a shell in it:

```sh
bin/sandprobe run exec -as agent -y -- docker exec -i my-agent-box sh
bin/sandprobe run exec -as agent -y -- kubectl exec -i pod/agent -c agent -- sh
bin/sandprobe run exec -as agent -y -- ssh agent@devbox sh
```

`-as` names the agent's user, and the run stops before any check if the command runs as anyone else. Sandprobe
creates nothing in your box but a scratch directory, which it removes, and never resets or deletes the box.

**A throwaway copy.** Sandprobe creates the box, probes it and deletes it:

```sh
bin/sandprobe run docker my-agent-image -as agent -y                        # a local Docker image
SANDPROBE_KUBE_CONTEXT=my-cluster bin/sandprobe run kubernetes -as agent -y  # a pod in your cluster
bin/sandprobe run sprites -y                                                # a provider adapter
```

Every run shows its plan first: what it will create, contact, mark and delete. Without `-y`, or a yes at the prompt,
nothing runs. A box Sandprobe creates is deleted by the ID its create returned. A few providers address boxes only by
name; there Sandprobe checks before each call that the name still holds the box its create returned, and the report
says what that check can't rule out. If the provider can't confirm a box gone, the run says so and exits 7.

## Where it runs

| Sandbox | How |
|-|-|
| Anything with a shell | `run exec` |
| Local Docker | `run docker` |
| Kubernetes, any cluster | `run kubernetes`, a [recipe](recipes/kubernetes.sh) |
| Fly Sprites, AWS Nitro on EKS, Baseten, E2B, Vercel, Cloudflare Sandboxes, Daytona, Boat, exe.dev | `run <provider>`, native adapters |
| Modal | a proof of concept (`make poc`) |

Read your provider's terms before you probe: some require consent for security testing. For `run exec` and recipes,
the checks that would contact a provider's own endpoints (cloud metadata, the Kubernetes API, the host over vsock,
the box's proxy) are off by default. The native adapters' rules for each provider are its PRV row in SPEC.md.

## What leaves your machine

- **Test traffic, to a canary.** The probe sends DNS lookups and HTTPS, TCP and UDP attempts that carry only this
  run's random nonces. A way out counts only when the canary logs the nonce, and the host gets that receipt from the
  canary directly, never through the box.
  - Every run but `run docker` uses the hosted canary at `control.pub.probe.ac0.dev` by default: `run exec`, recipes
    and the native provider adapters. It is run by Summation and trusted only under the control key this release
    pins. It sees two addresses. The box's public address, with the nonces its test traffic carries, is kept only for
    the run's lifetime, at most 30 minutes. The public address of the machine running Sandprobe, which reserves and
    arms the run, is kept in a rate counter for at most an hour. Both stay in memory: the canary writes no access log
    and stores nothing.
  - `run docker` starts its own canary container on your machine.
  - To use a canary you run yourself instead, name it: `-canary-url <url> -canary-pin <pin>` for a public canary, or
    `-canary <state file>` for one deployed with `deploy/canary.sh`. Sandprobe never picks one up on its own.
- **No test traffic, with `-no-canary`** (`run exec` and recipes): the probe sends nothing out of the box, and no
  canary is contacted. Your own command, or the provider's API, is still used to reach the box. Exfiltration is then
  reported as not tested, and the run can't grade above C.
- **Your reports stay with you.** Sandprobe uploads no report and has no telemetry.
- **Your provider's own API**, when Sandprobe creates or reaches a box for you, with your own credentials.

## How it works

```
 host: laptop, CI or an agent's shell                  the box under test
 ┌──────────────────────────────────────┐   create,    ┌─────────────────────────────────┐
 │ sandprobe                            │   copy, exec │ sandprobe-probe (static Go)     │
 │  plan:  what it creates and contacts ├─────────────▶│  runs as the agent              │
 │  grade: trusts nothing from the box  │◀─────────────┤  observations only, no grade    │
 │  report: JSON + HTML; then delete    │ observations └───────────────┬─────────────────┘
 └──────────────────┬───────────────────┘                              │ attempts carrying
                    │ receipts for this run's nonces                   │ this run's nonces
                    └───────────────▶ the canary ◀─────────────────────┘
```

The grader trusts nothing the box returns. A box that deceives the probe can fabricate its own observations, so the
report says what was proven, what is only an indicator, and what wasn't tested.

## What it checks

| Area | IDs | Examples |
|-|-|-|
| Secrets | SEC-1 to SEC-5 | secret-shaped variable names, other processes' environments and memory, credential files, cloud metadata credentials |
| Ways out | EGR-1 to EGR-6 | DNS to the canary's name server, HTTPS straight out or through a proxy, other ports, TLS interception |
| Persistence | PER-1 to PER-5 | writable startup, PATH, schedule and access files; storage that survives the provider's reset |
| Amplifiers | AMP-1 to AMP-8 | passwordless sudo, root or capabilities, setuid, control sockets, local daemons, vsock, the Kubernetes API, kernel settings |

The report leads with a score out of six (Secrets, Exfiltration, Containment, Privilege, Cloud access, Persistence)
and a letter grade, A to F. A category is green only when something in it was tested, nothing in it was left unknown,
and nothing above Info was found.

Exit codes: 0 graded, 2 usage, 3 needs approval, 4 needs login, 5 incomplete or invalid, 6 below `-min`, 7 a box not
confirmed deleted. `-o json` gives agents the plan, the report and every error as JSON.

## Contributing

[AGENTS.md](AGENTS.md) has the build, the layout and the hard rules, for people and coding agents alike. A behaviour
change starts in [SPEC.md](SPEC.md) under a rule ID, and comes with its test.

## Security

To report a vulnerability in Sandprobe, see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE). Copyright (c) 2026 Summation.
