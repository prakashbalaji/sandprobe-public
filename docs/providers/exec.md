# Any box with a shell: `run exec`

**Status for 0.3.0, being validated:** Stable target. Last validated: pending. [All providers](README.md)

`run exec` checks a box you already have, through your own command. Sandprobe creates nothing in it but a scratch
directory, which it removes, and it never resets or deletes the box (PRV-15).

## Prerequisites

- An installed `sandprobe`. You don't need a clone of this repository.
- A command that starts a POSIX `sh` in the box with stdin attached: `docker exec -i`, `kubectl exec -i`, `ssh` and
  so on. It must run as the agent's user.
- `sh`, `mkdir`, `base64`, `chmod` and `rm` in the box.

## Credentials

None of Sandprobe's own. Your command reaches the box with whatever access it already uses.

## Run it

```sh
sandprobe plan exec -as agent -- docker exec -i my-agent-box sh
sandprobe run exec -as agent -y -- docker exec -i my-agent-box sh
sandprobe run exec -as agent -y -- kubectl exec -i pod/agent -c agent -- sh
sandprobe run exec -as agent -y -- ssh agent@devbox sh
```

`-as` names the agent's user. The run checks it before any check runs, and stops if the command runs as anyone
else. Without `-as`, the report says the user wasn't confirmed as the agent's. If `/tmp` isn't writable in the box,
name another absolute directory with `-scratch <dir>`.

## What's skipped, and why

| Check | Why |
|-|-|
| SEC-4, EGR-3, AMP-6, AMP-7 | Off by default. Sandprobe doesn't know who hosts the box, and each of these would contact the provider's own endpoints: cloud metadata, the box's proxy, the host over vsock, the Kubernetes API (PRV-15). |
| PER-5 | An existing box gets no markers and is never reset. |
| EGR-6 | Contacting public upload sites isn't approved, on any run. |

## Terms and consent

The box and its provider are yours, so the terms that apply are your provider's. Read them before you run. With the
four checks above off, the probe sends nothing to your provider's endpoints. Its only traffic is the run's test
traffic to the canary, and lookups of the canary's names through the box's own resolver.

## What the score can and can't reach

- Persistence rests on PER-1 to PER-4: what the agent could change for its next session. Whether anything survives
  your provider's reset isn't tested.
- Only non-mutating checks run on an existing box.
- The boundary is your word that this is the agent's box and not production (PRV-2). The report records it.

### Canary and Cloud access (0.3.0)

Test traffic goes to the hosted canary at `control.pub.probe.ac0.dev` by default. It keeps the box's public address,
with the run's nonces, for the run's lifetime (at most 30 minutes), and your machine's public address in a rate
counter for at most an hour, both in memory only. To use a canary you run, name it with
`-canary-url <url> -canary-pin <pin>`, or with `-canary <state file>` for one from `deploy/canary.sh`. With
`-no-canary`, no test traffic leaves the box: Exfiltration reads "Not tested", and the run can't grade above C.
Cloud access reads "Not tested" and stays red, since SEC-4 and AMP-7 are off. **New in 0.3.0:** if your provider's
terms allow it on your own account, turn checks on by name with `-provider-endpoints SEC-4,AMP-7`; the plan lists
each one with your attestation before anything runs, and the report records it beside the check.
