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
AGENT_USER=agent   # set it to the user your agent runs as in the box
sandprobe plan exec -as "$AGENT_USER" -- docker exec -i my-agent-box sh
sandprobe run exec -as "$AGENT_USER" -y -- docker exec -i my-agent-box sh
sandprobe run exec -as "$AGENT_USER" -y -- kubectl exec -i pod/agent -c agent -- sh
sandprobe run exec -as "$AGENT_USER" -y -- ssh "$AGENT_USER@devbox" sh
```

`-as` takes the user your agent really runs as in the box: a name, or a numeric uid. It doesn't switch users. Your
command must already run as that user (`docker exec -u "$AGENT_USER"`, the pod's `securityContext.runAsUser`,
`ssh "$AGENT_USER@devbox"`), and the run checks it before any check runs. Many images, debian and amazonlinux among them,
have no `agent` user and run as root.

- If the box's `/etc/passwd` has no user by that name, the run stops before any check with
  `the box has no user "agent"`, removes its scratch directory and exits 5 (7 if the removal isn't confirmed). A
  numeric uid, such as `-as 1000`, doesn't need a passwd entry.
- If the user exists but your command runs as someone else, the run stops in the same way, for example with
  `the command runs as uids 0/0/0/0, not agent's 1000`.
- Without `-as`, the report says the user wasn't confirmed as the agent's.

If `/tmp` isn't writable in the box, name another absolute directory with `-scratch <dir>`.

## What's skipped, and why

| Check | Why |
|-|-|
| SEC-4, EGR-3, AMP-6, AMP-7 | Off by default, since Sandprobe doesn't know who hosts the box (PRV-15). SEC-4, EGR-3 and AMP-7 would contact the provider's own endpoints: cloud metadata, the box's proxy, the Kubernetes API. AMP-6 only checks for a vsock device and connects to nothing, and on an existing box it doesn't run even when turned on. |
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
`-no-canary`, the probe sends no test traffic to any canary: Exfiltration reads "Not tested", and the run finishes
incomplete (exit 5). Checks you turn on with `-provider-endpoints` that don't need a canary still make the connections the
plan names: SEC-4's requests to the cloud metadata addresses and AMP-7's TLS handshake with the Kubernetes API. EGR-3
doesn't run, since it needs a canary, and AMP-6 never connects on an existing box.
Cloud access reads "Not tested" and stays red, since SEC-4 and AMP-7 are off. **New in 0.3.0:** if your provider's
terms allow it on your own account, turn checks on by name with `-provider-endpoints SEC-4,AMP-7`; the plan lists
each one with your attestation before anything runs, and the report records it beside the check.
