# Your own recipe: `run -recipe`

**Status:** Beta. It is on `main` and not yet in a release, and it has run end to end on local Docker only.
[All providers](README.md)

`run -recipe <file>` grades a throwaway box that your own recipe creates. A recipe is one small shell file that
tells Sandprobe how to create a box on your provider, how to open a shell in it as your agent, and how to delete it.
Sandprobe ships no recipe per provider. The recipe is yours: it lives in your repository, next to the setup it
describes (RCP-4).

Use it to end a fix loop. Run, fix, and run again until the score is what you want. Then bake the fixes into your
provider's reusable template (a saved snapshot, a template, an image), and point a recipe at that template. Each run
then creates a fresh box from the template and probes it, so the report shows what a new box of yours really is.

## A recipe is host code. Read it before you run it

A recipe runs on your machine, outside any sandbox, with your own credentials and permissions. Sandprobe hasn't
reviewed your recipe, and hasn't reviewed your provider's terms. The plan says both.

- Read a recipe before you run it, above all one a coding agent or someone else wrote.
- `sandprobe plan -recipe <file>` already runs the file: its `sp_ready`, and anything written outside a function.
  Naming the file is what allows that. Nothing is created until you approve the plan.
- Before that first execution, Sandprobe writes one line to stderr with the file's path and its full SHA-256, with
  `-o json` too. So the bytes that are about to run are on record even if the recipe then hangs.
- The plan shows the file's full SHA-256. Sandprobe reads the file once and runs only those bytes, so the SHA-256 is
  of what ran. Compare it with the copy you read.

## Run it

```sh
sandprobe plan -recipe ./my-recipe.sh -as agent      # runs sp_ready, creates nothing
sandprobe run -recipe ./my-recipe.sh -as agent -y    # creates the box, probes it, deletes it
```

There is no provider name: the file takes its place. `-as` names the user your agent runs as in the box, and the run
checks it before any check runs. The other flags work as they do for `run kubernetes`: `-out`, `-min`, `-theme`,
`-o json`, `-scratch`, `-no-canary`, `-canary-url` with `-canary-pin`, `-canary`, `-provider-endpoints` and
`-allow-local-proxy`. `-provider` is refused with `-recipe`, and so is anything after `--`.

The file must be a regular file of at most 64 KiB. Name the file itself: a path whose last part is a symlink is
refused. Sandprobe passes your settings to the recipe through the environment, never through flags.

Without `-y` outside a terminal, the run prints the plan, creates nothing and exits 3.

## The file

A recipe is a POSIX `sh` file. It starts with a header, then defines five functions.

```sh
# sandprobe-recipe: v1
# provider: Acme Sandboxes, one box from my hardened template
# docs: https://example.com/acme/cli
# terms: what you read in your provider's terms about testing your own boxes
# exclusions: SEC-4 EGR-3 AMP-6 AMP-7
# addressed-by: id
# env: SANDPROBE_ACME_TEMPLATE SANDPROBE_ACME_REGION
#
# Free comments start after a line that holds only "#".
```

| Line | Meaning |
|-|-|
| `# sandprobe-recipe: v1` | Required, and the first line. |
| `provider:` | Required. Your own words for where the box runs. The plan and the report show it as the recipe's own word. It is never matched against the providers Sandprobe has reviewed. |
| `terms:` | Required. Your note on your provider's terms. Sandprobe shows it nowhere and doesn't act on it. |
| `addressed-by:` | Required: `id`, or `name` when your provider can only address a box by its name. With `name`, define `sp_whois` too. |
| `docs:` | Optional. |
| `exclusions:` | Optional, and it changes nothing in a recipe of your own: SEC-4, EGR-3, AMP-6 and AMP-7 are always off. It may name only those four. |
| `env:` | Optional. The `SANDPROBE_` settings your recipe reads. Sandprobe names them when `sp_ready` fails. |

Each value is one line of printable ASCII, at most 400 characters. An unknown key, or a key given twice, is refused.

## The five functions

Sandprobe calls one function at a time. Each call is a new `sh` that reads the whole file and then runs that one
function, so no shell variable lives from one call to the next. `sp_ready` has one minute. The create, the delete and
each gone check have five minutes each, and the whole run has fifteen.
Keep everything inside functions: anything outside one runs on every call, `plan` included.

| Function | When | What it must do |
|-|-|-|
| `sp_ready` | Before the plan, so before you approve. | Check your settings. It may make read-only calls to your provider. It creates nothing. On success it prints exactly one line that names where the box will be made and from what, and exits 0. Any other exit means not ready: the run stops with exit 4. |
| `sp_create` | Once, after you approve. | Create one box and print only its ID: one line, at most 128 characters, of letters, digits and `. _ : -`, starting with a letter or digit. Return only when the box is ready for a shell. Print the ID before you wait, so a box that never becomes ready is still deleted. |
| `sp_shell` | Several times. | Become a POSIX `sh` inside the box, as your agent's user, with stdin attached. Sandprobe sends the probe through it. |
| `sp_delete` | Once, at the end, whenever the create returned an ID. | Delete the box named by `SANDPROBE_BOX`, and nothing else. |
| `sp_gone` | After the delete, every two seconds for up to two minutes. | Exit 0 only when your provider says the box doesn't exist. Exit 1 while it exists. Exit 2 when it can't tell: a failed call, a timeout, an answer you can't read. |

What Sandprobe gives each call, in the environment:

| Variable | Value |
|-|-|
| `SANDPROBE_NAME` | A fresh name, `sandprobe-<12 hex>`, made before the create. Give the box this name if your provider takes one. |
| `SANDPROBE_TARGET` | The line your `sp_ready` printed. Every later call should refuse when the place it would act on no longer matches that line. |
| `SANDPROBE_BOX` | The ID your `sp_create` printed. Set for `sp_shell`, `sp_delete`, `sp_gone` and `sp_whois`. |

Sandprobe sets these three itself. Your own values for them never reach the recipe.

The box needs `sh`, `mkdir`, `base64`, `chmod` and `rm`. The probe goes into a scratch directory under `/tmp`, or under
the directory you name with `-scratch`, and is removed after each use.

### Messages go to file descriptor 3

Your recipe speaks through three channels, and Sandprobe treats each differently.

- **Standard output is data.** `sp_ready` prints the target line and `sp_create` prints the ID. Print nothing else
  there.
- **Standard error is thrown away.** Tools print tokens and signed URLs there, so Sandprobe never shows it.
- **File descriptor 3 is your message to the person.** When a function fails, Sandprobe shows what the recipe wrote
  to fd 3, and only that, cut to its last 300 characters. Sandprobe keeps the first 4 KiB written there and discards
  the rest. It shows printable ASCII only: a newline or tab becomes a space, and every other byte is dropped.

Write messages with a small helper, and run every tool with fd 3 closed, so that only your recipe can write a message:

```sh
sp_say() { { echo "$*" >&3; } 2>/dev/null; }
sp_tool() { acme "$@"; } 3>&-
```

Never write a credential to fd 3.

### Identity and deletion

- Before the create, Sandprobe writes a record to `~/.config/sandprobe/recipe-own-<12 hex>-sandprobe-<12 hex>.state`
  (mode 600) and prints its path. The first 12 hex digits are from the recipe's SHA-256. If the record can't be
  written, nothing is created.
- The ID is whatever `sp_create` printed. If it isn't one sound ID line, the run stops, deletes nothing, keeps the
  record and exits 7: a box named `SANDPROBE_NAME` may exist, and Sandprobe never deletes by name.
- Once the ID is known it goes into the record, and the delete always runs, even when the run failed or ran out of
  time.
- The record is removed only when `sp_gone` exits 0. Otherwise the run exits 7 and names the ID and the record.
  Delete the box with your provider's own tool, by that ID, and then remove the record.
- With `addressed-by: name`, `sp_whois` prints the ID that holds the name now. Sandprobe calls it before each
  `sp_shell` and before `sp_delete`, and makes neither call once the answer isn't the ID the create returned.
  `sp_gone` still runs then, to check that the box with that ID is absent. The report says what that check can't
  rule out.
- Sandprobe gives `sp_delete` and `sp_gone` the ID, with the name and the target that every call gets, and requires
  them to act only on that ID. It can't enforce what your code does with them, so "confirmed gone" in the report
  means your `sp_gone` said so. Make it answer 0 only on a positive "not found".

## Start the box from your template

Two functions decide what the report is about.

**`sp_create` decides which box.** Start it from the template you hardened, not from a default image, and name the
template in the target line by something that can't move: an image digest, a snapshot ID, a template version. Then
the plan shows exactly what will be probed, and a template that changes between the plan and the create stops the
run.

**`sp_shell` decides who the probe is.** Open the shell through the same entry your agents really use, as the same
user, so the probe sees what a hijacked agent would see. If your agents run through a wrapper, a gateway or an SDK
call, go through that. A shell opened as root, or through an admin path your agents don't have, grades a different
box. `-as <user>` then checks the user before any check runs.

## A worked example: local Docker

[`examples/recipes/docker-template.sh`](../../examples/recipes/docker-template.sh) is a complete recipe. It stands
in for a provider's template with a local image. It is an example, not a shipped recipe: it isn't built into
`sandprobe`, and Sandprobe treats it like any file you name.

| Setting | What it is |
|-|-|
| `SANDPROBE_TEMPLATE` | Required. The local image to start the box from. The recipe never pulls. |
| `SANDPROBE_AGENT_USER` | The user your agent runs as in the box. Defaults to `agent`. |

```sh
cat > Dockerfile <<'EOF'
FROM debian:trixie-slim
RUN useradd -m -u 1000 agent
EOF
docker build -t my-agent:hardened .

SANDPROBE_TEMPLATE=my-agent:hardened sandprobe plan -recipe examples/recipes/docker-template.sh -as agent
SANDPROBE_TEMPLATE=my-agent:hardened sandprobe run -recipe examples/recipes/docker-template.sh -as agent -y
```

What each function does there:

- `sp_ready` checks that `docker` reaches its engine and that the image is local. Its line names the engine, the
  template, the image ID the template means right now, and the agent's user.
- `sp_create` refuses if any of that changed since the plan. It creates the container from the image ID, with
  `--pull never`, prints the ID `docker create` returned, and then starts it. The container removes itself when it
  stops, and stops by itself after an hour.
- `sp_shell` is `docker exec -i -u <agent user> <ID> sh`.
- `sp_delete` is `docker rm -f <ID>`.
- `sp_gone` lists containers with that ID: none is 0, ours is 1, and a `docker` failure is 2.

To make it yours, change `sp_create` to your provider's "create from template" call and `sp_shell` to the way your
agents get a shell, and keep the rest of the shape.

## What's skipped, and why

| Check | Why |
|-|-|
| SEC-4, EGR-3, AMP-6, AMP-7 | Always off for a recipe of your own, whatever its header says, since Sandprobe hasn't reviewed your provider's terms (RCP-4). SEC-4, EGR-3 and AMP-7 would contact the provider's own endpoints: cloud metadata, the box's proxy, the Kubernetes API. AMP-6 only checks for a vsock device and connects to nothing. |
| PER-5 | Recipe resets aren't built yet. A recipe that defines `sp_checkpoint`, `sp_restore` or `sp_recreate` still runs, and those functions are never called (RCP-3). |
| EGR-6 | Contacting public upload sites isn't approved, on any run. |

If your provider's terms allow one of the four on your own account, turn it on by name, for example
`-provider-endpoints SEC-4,AMP-7`. The plan lists each one with your attestation before anything runs, and the report
records it beside the check (PRV-15). A recipe's header can't do this.

Cloud access reads "Not tested" and stays red while SEC-4 and AMP-7 are off. It is never "not applicable" for a
recipe of your own: only Sandprobe's own reviewed scope for a provider can say that.

## What the report records

- `run.provider` is `recipe`. It says how the box was reached, as `exec` does. It is not a provider's name.
- `run.box.created_by_sandprobe` is `true`, and `run.box.provider_id` is the ID your create returned.
- `run.recipe` is the record to rely on. Only a run through a recipe of your own has it:

  ```json
  "recipe": {"own": true, "sha256": "<64 hex>"}
  ```

  `sha256` is of the recipe's bytes that ran. A report with the record declares `sandprobe/7`; every other report
  stays `sandprobe/6`. A saved report whose record is missing, misplaced or malformed is refused by every command
  that reads reports. `sandprobe compare` treats two reports whose records differ as a changed setup and exits 5.
- `provider_calls` lists your recipe's create, delete and last gone answer. Each names the recipe by its SHA-256, for
  example `own recipe sha256:<64 hex> sp_create`, with the exit code and the box's ID.
- `cleanup.residual` names the SHA-256 and your header's `provider:` line as the recipe's own word, quotes the
  target line, and says that nobody reviewed the recipe.

The report holds no path of the recipe file, and nothing the recipe printed but the target line in the residual.

## Terms and consent

Read your provider's terms before you run. Some require consent for security testing. Sandprobe hasn't read them for
you here, never presents a run as a provider's permission, and keeps every check that would contact a provider's own
endpoint off unless you turn it on by name.
