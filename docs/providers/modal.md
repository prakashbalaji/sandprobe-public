# Modal: `run modal`

**Status:** Beta. Last validated: 25 Nov 2026, `run modal` with the code released as 0.3.7. [All providers](README.md)

`run modal` creates one Modal Sandbox with Modal's defaults in your own workspace (root, open egress, CPU), probes it,
terminates it by its ID and confirms it's gone (PRV-18).

```sh
modal setup                                     # once: Modal's own login, which writes ~/.modal.toml
export SANDPROBE_MODAL_WORKSPACE=my-workspace   # the one workspace a run may use (modal profile list)
sandprobe plan modal
sandprobe run modal -y
```

- You need an installed `sandprobe`, a Modal workspace of your own, and a token for it. You don't need a clone of this
  repository or Modal's Python SDK in the run: `modal setup` only writes the token, and `MODAL_TOKEN_ID` and
  `MODAL_TOKEN_SECRET` work instead.
- Modal's own SDK, built into `sandprobe`, reads the token. No token enters a sandbox, report or journal. If the token
  is for another workspace, nothing is created.
- The sandbox has a 15-minute timeout as a spend backstop. A private journal in `~/.config/sandprobe` names it until
  it's confirmed gone; exit 7 names that journal.
- The image and Sandprobe put no credential in the sandbox but the image's own `/etc/shadow` and `GPG_KEY`. If the probe
  sees any other, it may be Modal's own: the run deletes the sandbox, writes no report, keeps a private note and exits
  8. Don't run it again; report it privately to Modal.
- The App `sandprobe` and the built image stay in your workspace. `modal app stop sandprobe` removes the App.
- Cloud access is not applicable and the score is out of five: SEC-4, EGR-3, AMP-6 and AMP-7 would contact endpoints
  Modal owns, and PRV-5 excludes them.

- A run is expected to finish incomplete and exit 5: as root with `CAP_SYS_PTRACE`, AMP-1, AMP-4 and AMP-8's block
  device check end unknown, as they did on 25 Nov. The score and reports are still written. A run that couldn't be
  cleared also exits 5, and prints no score.

It tests Modal's defaults, so a low score is a starting point. To test a sandbox set up the way your agents run, use
[`run exec`](#probe-your-own-modal-sandbox-with-run-exec), where the fixes below were proven.

## The proof of concept

The proof of concept (SPEC.md, "Modal proof of concept") compares Modal's locked-down network setups and runs a sidecar
that watches the main container's traffic. It lives behind a build tag and isn't in a release. You build it from
source, it needs a canary you deploy yourself, and it runs one setup per invocation.

### Prerequisites

- A clone of this repository and Go 1.25, to build `bin/sandprobe-poc` with `make poc`.
- A Modal workspace of your own, with Modal's token already in `~/.modal.toml`.
- A canary from `deploy/canary.sh`. That needs an AWS CLI profile (`PROFILE`), a Cloudflare DNS zone you control
  (`ZONE` and `DOMAIN`), the `cf` CLI and `jq`. The `domain-one` and `sidecar` setups also need its wildcard record:
  `deploy/canary.sh wildcard`.

### Credentials

| Name | What it is |
|-|-|
| `~/.modal.toml` | Modal's own token file. The SDK reads it on your machine. It never enters a sandbox, and Sandprobe never prints it. |
| `SANDPROBE_MODAL_WORKSPACE` | The one workspace the proof of concept may use. Nothing runs without it. |

### Run it

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

## Probe your own Modal sandbox with run exec

You don't need the proof of concept to probe a sandbox of your own: `run exec` reaches it through any command that
starts `sh` in it. [`examples/modal/bridge.py`](../../examples/modal/bridge.py) is one such command, built on
Modal's Python SDK (1.5.5 or later). It creates one throwaway sandbox in your own workspace, CPU only, with a
15-minute timeout as a spend backstop. It records the ID that create returned and a random tag, which it sets in the
create request itself, in a private state file it reserves before it creates anything. If anything fails after the
create, Ctrl-C included, it terminates that sandbox and confirms it finished. `sh` and `rm` act only on the one live
sandbox in the `sandprobe` app that carries the recorded tag and has the recorded ID; anything else, an edited or
copied state file included, refuses and touches nothing. The token stays with Modal's SDK in `~/.modal.toml`; the
script never reads or prints it (FIX-10).

```sh
pip install 'modal>=1.5.5'                             # then `modal setup`, once, for ~/.modal.toml
python3 examples/modal/bridge.py create round-0 r0.state
sandprobe run exec -as root -y -out round-0 -- python3 examples/modal/bridge.py sh r0.state
python3 examples/modal/bridge.py rm r0.state
sandprobe fix round-0/*.json -platform modal            # you name the platform; fix never guesses it
```

Then apply the top action, create a new sandbox, run again into `round-1` (with `-as agent` once the agent has its own
user), and `sandprobe compare round-0/*.json round-1/*.json`. It prints `Score: 0/6 → 3/6` and what "Got better";
DNS and UDP 53 under `block_network=True` show as "No longer found, but not proven", which isn't a fix. The script's
`round-1` and `round-2` setups are the fixes below.

If the sandbox ended at its timeout before `rm`, `rm` finds no live sandbox with the tag and refuses, touching
nothing. Once Modal shows that sandbox finished, delete the state file yourself. Exit 7 from any command means a
sandbox may still run: it prints the ID, and the sandbox ends at its timeout.

This bridge, guards included, has run the whole loop live on Modal (24 November 2026): three rounds with the
provider declared, 0/5 → 3/5 → 5/5, and every sandbox terminated with its termination confirmed. Its failure paths,
which a live run can't reach on demand, are tested against a fake of Modal's SDK (`examples/modal/bridge_test.py`).

`run exec` keeps SEC-4, EGR-3, AMP-6 and AMP-7 off, since each would contact an endpoint Modal owns. Leave them off:
on Modal they are outside Sandprobe's reviewed scope. Without a declared provider, Cloud access reads "Not tested",
and `fix` lists it as not an action for an agent. When you, the person, declare the provider yourself with
`run exec -provider modal` (PRV-17, [exec.md](exec.md)), that scope keeps them off and Cloud access reads not
applicable; an agent never adds the flag. `fix` still takes its platform only from `-platform`, never from the
report's declared provider.

### The fixes proven on Modal

Three rounds on 24 November 2026, one throwaway sandbox per round (python:3.12-slim-bookworm), each rerun through
`run exec` and compared with the round before (FIX-4):

| Round | `fix` action | The change | Score |
|-|-|-|-|
| 0 | | Modal's defaults: root, network open | 0/6 |
| 1 | `run-as-user` | In the image, `useradd -m -u 1000 -s /bin/bash agent`; run the agent's commands through `setpriv --reuid=1000 --regid=1000 --init-groups --inh-caps=-all --ambient-caps=-all --no-new-privs <cmd>` | 3/6, with `block-network`: Exfiltration, Containment and Privilege turn green |
| 1 | `block-network` | `modal.Sandbox.create(..., block_network=True)` | |
| 2 | `clean-env` | Add `--reset-env` to that `setpriv`, so the agent starts with a minimal environment | 4/6, with `protect-home`: Persistence turns green, and SEC-1 clears |
| 2 | `protect-home` | In the image, `chown -R root:root /home/agent; chmod 0755 /home/agent; mkdir -p /work; chown agent:agent /work`; `workdir="/work"` on exec | |

What it costs, and what stays:

- `block_network=True` also cuts the agent off from its model API. Its model calls must go through something outside
  the sandbox.
- DNS and UDP 53 then have no receipt, which isn't proof, so Exfiltration reads green with "not proven: DNS, UDP 53".
- Modal's domain and CIDR allowlists weren't tested in this loop, so nothing here says how they treat DNS.
- SEC-2 stayed red in every round, because the probe then counted the shell `run exec` started as another of the
  agent's processes. `run exec` now runs Sandprobe's own wrapper there and leaves it out (LNC-1 to LNC-5), so on a rerun
  SEC-2 should reflect only the box's own processes; these rounds predate that.
- Cloud access stays "Not tested", as above.

## What's skipped, and why

| Check | Why |
|-|-|
| SEC-4, EGR-3, AMP-6, AMP-7 | Each would send a request to an endpoint Modal owns (PRV-5). |
| PER-5 | No reset: a terminate and recreate would test only a Volume, and the sandbox mounts none. |
| EGR-6 | Contacting public upload sites isn't approved, on any run. |

Also not tested: fronting through a shared CDN, inbound through unencrypted tunnels, GPU sandboxes, the Datadog
integration and the Outbound Policy (POC-4).

## Terms and consent

SPEC.md's Modal row records Modal's [terms](https://modal.com/legal/terms) and
[security page](https://modal.com/docs/guide/security) as read on 25 Nov 2026. We found nothing in them on customers
testing their own sandboxes. Customers agree not to "reverse engineer, decompile, disassemble, or otherwise attempt to
discover the underlying structure, ideas, or algorithms of the Service". The security page, under its bug bounty, says
"When performing security research, you must use a Modal Workspace whose name ends in `-H1-<username>`". A run checks
your own sandbox's configuration from inside. It isn't bounty research, carries no permission from Modal, and contacts
no endpoint Modal owns through the four excluded checks. Read both yourself and decide whether your run fits them. If a
report suggests a flaw on Modal's side, stop, don't repeat it, and report it to Modal privately.

The proof of concept also runs in your own workspace, outside the bug bounty. If a result suggests a real flaw on Modal's
side, the run stops and exits 8, and keeps only a private note (POC-5).

## What the score can and can't reach

- Persistence rests on PER-1 to PER-4. Whether anything survives a reset isn't tested.
- `run modal` tests one configuration, Modal's defaults. Each proof of concept setup is one more, chosen by `-variant`.

### Canary and Cloud access (0.3.0)

`run modal` uses the hosted canary at `control.pub.probe.ac0.dev`, like the other providers. The proof of concept
doesn't. It needs `-canary <state file>`, naming a canary you deployed with
`deploy/canary.sh`, which it reaches over AWS SSM. Cloud access is not applicable here: PRV-5 excludes Modal's own
metadata and Kubernetes endpoints under Sandprobe's own rules of engagement, not Modal's terms, so the box holds no
cloud identity of yours to check. Cloud access is never green, the score is out of five, and a line under the score
says why. A credential of yours put into the box is still caught under Secrets.
