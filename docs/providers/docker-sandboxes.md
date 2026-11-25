# Docker Sandboxes: `run exec` through `sbx exec`

**Status:** Beta: `run exec`, no adapter. Last validated: 25 Nov 2026, one local sandbox, `sbx` 0.54.1, with 0.3.7.
[All providers](README.md)

[Docker Sandboxes](https://docs.docker.com/ai/sandboxes/) run coding agents in a microVM on your machine, with Docker's
`sbx` CLI. Sandprobe checks a sandbox you already have with [`run exec`](exec.md), through `sbx exec`. It creates
nothing in the sandbox but a scratch directory, which it removes, and never stops or removes the sandbox.

## Prerequisites

- An installed `sandprobe`, and Docker's `sbx`, signed in: `brew install docker/tap/sbx`, then `sbx login` (Docker's
  [install page](https://docs.docker.com/ai/sandboxes/install/) has the other platforms).
- A local sandbox. `sbx` asks for a global network policy before the first one, `sbx policy init balanced` for
  example. That is a setting of your machine; Sandprobe doesn't change it.

`sbx` sends Docker usage data that includes your Docker username. `sbx settings set telemetry.disabled true` turns it
off, from the daemon's next restart (`sbx daemon restart`).

## Run it

```sh
sbx ls                                   # the sandbox's name
sandprobe plan exec -as agent -- sbx exec -i <sandbox> sh
sandprobe run exec -as agent -y -- sbx exec -i <sandbox> sh
```

Docker's agent templates run the agent as `agent` (uid 1000), and `sbx exec` runs as that user unless you pass `-u`.
To check a fresh sandbox rather than one an agent has used, make one without a workspace from your machine, check it,
then remove it yourself:

```sh
sbx create --name my-check --skills off shell
sandprobe run exec -as agent -y -- sbx exec -i my-check sh
sbx rm my-check
```

`sbx rm` removes a local sandbox by its name. Check that `sbx ls` shows the sandbox you mean first.

## What to expect

Docker builds this sandbox so that the microVM is the boundary, and gives the agent a lot inside it. Sandprobe scores
what the agent can reach inside the box, so several categories read red by design:

- **Privilege.** The agent has passwordless `sudo` and setuid programs. Removing `/etc/sudoers.d/agent` (as root,
  `sbx exec -u root <sandbox> rm /etc/sudoers.d/agent`) clears the sudo finding, as a rerun on 25 Nov showed; the
  setuid finding stays.
- **Containment.** The agent can reach the sandbox's own Docker daemon socket, which Docker provides on purpose.
- **Secrets.** Credential-shaped names such as `GH_TOKEN` can be in the agent's environment. Docker's
  [credentials page](https://docs.docker.com/ai/sandboxes/configuration/credentials/) says that when its proxy manages
  a credential "the sandbox sees only a sentinel value". Sandprobe never reads a value, so it can't tell a sentinel
  from a key and reports the name.
- **Exfiltration can't go green.** Outbound TCP goes through Docker's proxy on your machine, which accepts the
  connection and then applies your network policy. A connection the proxy accepted isn't a refusal, so Sandprobe
  reports HTTPS and TCP 22, 80 and 8080 as unproven, not blocked. Outbound UDP is off by default, and DNS goes through
  Docker's resolver.
- **Cloud access** reads "Not tested" with the commands above, which name neither `-provider` nor
  `-provider-endpoints`.

So read the report as what an agent can do inside its microVM, and Docker's own documentation for what keeps it
from your machine. Sandprobe doesn't test the microVM boundary.

## What's skipped, and why

| Check | Why |
|-|-|
| SEC-4, EGR-3, AMP-6, AMP-7 | Off on `run exec`, since they'd contact your provider's own endpoints, Docker's proxy among them (PRV-15). |
| PER-5 | An existing box is never reset. |
| EGR-6 | Contacting public upload sites isn't approved, on any run. |

## Terms

Docker's [Subscription Service Agreement](https://www.docker.com/legal/docker-subscription-service-agreement/), last
updated 26 August 2026, which `sbx login` asks you to accept, has no clause on testing your own sandbox that we found.
Among its use restrictions, you may not "reverse-engineer, decompile, disassemble, or attempt to derive the source
code for the Services", "access the Services for the purpose of developing or operating products or services intended
to be offered to third parties in competition with the Services", or "Use the Services other than as described in the
applicable Documentation". Docker's
[vulnerability disclosure policy](https://www.docker.com/trust/vulnerability-disclosure-policy/) asks security testers
to "only target your own accounts". A run checks your own sandbox from inside and claims no permission from Docker.
Read the agreement yourself and decide whether your run fits it. If a report suggests a flaw on Docker's side, stop,
don't repeat it, and report it to security@docker.com.

Cloud sandboxes (`sbx --cloud`) have their own credentials and network policy, and haven't been checked.
