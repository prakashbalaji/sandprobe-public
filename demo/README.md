# Demo: the vibe-coded app, from the agent's side

A five-minute demo built on the r/TechLeader post about a vibe-coded booking app. The post found the
app's keys in its frontend bundle. Sandprobe asks the other half: **if the coding agent in that sandbox
were hijacked, what could it reach?**

Everything is local and synthetic. The boxes are throwaway Docker containers on this Mac, every key in
them is the fake value `sandprobe-fake`, and a local canary stands in for an attacker's server. No
provider is contacted.

## Once, before the demo

```sh
demo/setup.sh        # installs sandprobe into ~/.local/bin and builds the three demo images
```

## On stage

Start each rehearsal in a fresh, empty folder (`mkdir demo-1 && cd demo-1`): `compare` takes one report from each
folder, and a second run into the same folder adds another. Each run takes under 10 seconds. It creates the container, probes it as the agent, deletes everything
by ID, and prints the score. The full report is the `.html` file it names.

**1. The vibe-coded box: 1/6.**

```sh
sandprobe run docker sandprobe-demo/vibe -as agent -y -out vibe
```

This is the post's app as an agent left it:
- `.env` holds the Stripe, OpenAI, Resend and Supabase keys;
- the dev server runs as the agent, with every key in its environment;
- a Docker socket is mounted, because Supabase's local stack wants one (here a stand-in that does nothing);
- the network is open.

The report's first line says it plainly: *the agent can open a credential and send data out of the box,
so a hijacked agent could steal it.* One prompt injection in a README, and `cat .env | curl` works.

**2. The same app, hardened: 6/6.** The keys are gone, and five Docker options are added:

```sh
sandprobe run docker sandprobe-demo/hardened -as agent -y -out hardened -- \
  --read-only --cap-drop ALL --security-opt no-new-privileges --network none --tmpfs /tmp
```

There's no key in the box. In a real setup, a broker outside it holds the keys and makes the API calls.
This box has no network at all, so it shows the box's side only, not a working broker. Point at the grey
"not proven" lines: a DNS lookup can't be proven blocked, so Sandprobe says so instead of claiming it.

**3. The gate: 5/6.** Someone commits a `.env` again.

```sh
sandprobe run docker sandprobe-demo/regressed -as agent -y -out regressed -- \
  --read-only --cap-drop ALL --security-opt no-new-privileges --network none --tmpfs /tmp
sandprobe compare hardened/*.json regressed/*.json
```

`compare` says "Got worse: Secrets: Can the agent open credential files…?" and exits 6. In CI, that
fails the build, so the box can't quietly get worse.

`demo/reports/` holds all three reports, pre-generated, in case Docker misbehaves on the day.

## If asked

- **What's actually proven:** Sandprobe never reads a value. It proves the agent can open the file, and that
  data can leave the box.
- **What it doesn't catch:** the post's own leak, a key baked into the browser bundle. That needs an app scan.
  Sandprobe covers the agent side.
- **What the score means:** the number of categories where nothing was found and nothing was left unknown, the
  same bar as an A. Some checks can only look, never prove a block (a DNS lookup is one); a green that rests on one
  says "not proven". It's not a certification.
- **What a plain `docker run` scores:** 2/6 as root (Docker's default), 3/6 as a normal user. An open
  network and setuid programs are red by default.
