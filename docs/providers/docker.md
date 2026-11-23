# Local Docker: `run docker`

**Status for 0.3.0, being validated:** Stable target. Last validated: pending. [All providers](README.md)

`run docker` grades a throwaway container made from a local image, on your own machine. No provider is involved
(PRV-14).

## Prerequisites

- An installed `sandprobe`. You don't need a clone of this repository.
- Docker, running.
- The image, already on this machine. Nothing is pulled.

## Credentials

None.

## Run it

```sh
sandprobe plan docker my-agent-image -as agent
sandprobe run docker my-agent-image -as agent -y
sandprobe run docker my-agent-image -as agent -y -- --read-only --cap-drop ALL --network none
```

Everything after `--` goes to `docker run` unchanged, so pass the options your agent's sandbox really uses. `--rm` is
refused: Sandprobe does its own teardown. `-as` names the agent's user; without it, the run uses the container's own
user, else root.

The run creates a bridge network, a canary container and the container under test, and deletes each by the ID Docker
returned. Its reset removes the container and creates it again from the same image and options. If any of it can't
be confirmed gone, the run says so, names its ID and exits 7.

## What's skipped, and why

No check is excluded for a provider. Only the skips every run has apply:

| Check | Why |
|-|-|
| EGR-6 | Contacting public upload sites isn't approved, on any run. |
| EGR-3 | Skipped when the agent's environment names no proxy, or names a local one you didn't approve with `-allow-local-proxy`. |
| AMP-6 | Skipped when the container has no vsock device. |

## Terms and consent

No provider's terms apply. The image and the machine are yours.

## What the score can and can't reach

- PER-5 runs: the reset recreates the container, so storage that survives it is tested.
- Egress is measured to a canary on a network Sandprobe made, with the box's resolver pointed at it. A receipt proves
  the box can send data to an address it was given, not that it reaches the internet. If your options name a network
  (`--network none`, say), the box keeps that network instead.

### Canary and Cloud access (0.3.0)

`run docker` always starts its own canary container on your machine, and refuses `-canary`, `-canary-url` and
`-canary-pin`. The canary's test traffic stays on your machine. Cloud access is tested: SEC-4 asks the cloud metadata
addresses `sandprobe plan docker` lists which identity the box has, and AMP-7 makes a TLS handshake, with no request,
to a Kubernetes API the box names. The score is out of six.
