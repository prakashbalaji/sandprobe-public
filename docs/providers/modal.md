# Modal: a proof of concept

**Status for 0.3.0, being validated:** Beta: a proof of concept, not in the release build. Last validated: pending.
[All providers](README.md)

The Modal proof of concept probes Modal Sandboxes in your own workspace: a default sandbox, a few locked-down network
setups, and a sidecar that watches the main container's traffic (SPEC.md, "Modal proof of concept"). It lives behind
a build tag. A release has no `poc` command, and there is no `sandprobe run modal`.

Its known gaps:

- You build it from source.
- It needs a canary you deploy yourself (see the last section).
- It runs one setup per invocation, and you read each setup's raw record before you render its reports.

## Prerequisites

- A clone of this repository and Go 1.25, to build `bin/sandprobe-poc` with `make poc`.
- A Modal workspace of your own, with Modal's token already in `~/.modal.toml`.
- A canary from `deploy/canary.sh`. That needs an AWS CLI profile (`PROFILE`), a Cloudflare DNS zone you control
  (`ZONE` and `DOMAIN`), the `cf` CLI and `jq`. The `domain-one` and `sidecar` setups also need its wildcard record:
  `deploy/canary.sh wildcard`.

## Credentials

| Name | What it is |
|-|-|
| `~/.modal.toml` | Modal's own token file. The SDK reads it on your machine. It never enters a sandbox, and Sandprobe never prints it. |
| `SANDPROBE_MODAL_WORKSPACE` | The one workspace the proof of concept may use. Nothing runs without it. |

## Run it

```sh
make poc
bin/sandprobe-poc poc modal run -variant default -canary <canary state file> -out <dir> -y
bin/sandprobe-poc poc modal render -variant default -out <dir>
bin/sandprobe-poc poc modal summary -out <dir>
bin/sandprobe-poc poc modal cleanup -out <dir> -y
```

`-variant` picks the setup: `default`, `domain-empty`, `domain-one`, `block`, `block-vm` or `sidecar`. Each sandbox
has a 15-minute timeout as a spend backstop and is terminated by its ID. The built images stay until `cleanup`, and
the App stays, named in the report.

## What's skipped, and why

| Check | Why |
|-|-|
| SEC-4, EGR-3, AMP-6, AMP-7 | Each would send a request to an endpoint Modal owns (PRV-5). |
| PER-5 | No reset: a terminate and recreate would test only a Volume, and the sandbox mounts none. |
| EGR-6 | Contacting public upload sites isn't approved, on any run. |

Also not tested: fronting through a shared CDN, inbound through unencrypted tunnels, GPU sandboxes, the Datadog
integration and the Outbound Policy (POC-4).

## Terms and consent

SPEC.md's Modal row records no terms link. It notes that Modal's terms say nothing about customers testing their own
sandboxes, and that Modal's security page asks bug-bounty research to use a workspace ending `-H1-<username>`. The
proof of concept runs in your own workspace, outside the bug bounty. If a result suggests a real flaw on Modal's
side, the run stops and exits 8, and keeps only a private note (POC-5).

## What the score can and can't reach

- Persistence rests on PER-1 to PER-4. Whether anything survives a reset isn't tested.
- Each setup is one configuration, chosen by `-variant`, not every way a Modal sandbox can be set up.

### Canary and Cloud access (0.3.0)

The proof of concept doesn't use the hosted canary. It needs `-canary <state file>`, naming a canary you deployed with
`deploy/canary.sh`, which it reaches over AWS SSM. Cloud access is not applicable here: PRV-5 excludes Modal's own
metadata and Kubernetes endpoints under Sandprobe's own rules of engagement, not Modal's terms, so the box holds no
cloud identity of yours to check. Cloud access is never green, the score is out of five, and a line under the score
says why. A credential of yours put into the box is still caught under Secrets.
