# Contributing to Sandprobe

Thanks for helping. Sandprobe makes one promise above all others: **no false passes.** A check passes only on a
negative proof, and anything that failed quietly is "unknown". Every rule below protects that promise.

[AGENTS.md](AGENTS.md) has the build, the layout and the hard rules, for people and coding agents alike. This page is
the short version.

## Report a false pass

A false pass is a check that passed when it shouldn't have: the agent could read a credential, or send data out, or
become root, and the report said it couldn't. These are the most important reports we get. Where one goes depends on
what caused it:

- **The probe or grader missed something on an ordinary box.** Open a
  [false-pass report](https://github.com/summationai/sandprobe/issues/new?template=false-pass.yml). Give the check's
  ID, its result and its evidence from the report's JSON, with every secret value, credential and private name removed.
- **A box can make the grader report a pass it didn't prove.** That's a vulnerability in Sandprobe. Report it
  privately, as [SECURITY.md](SECURITY.md) says, and don't open a public issue.
- **It looks like a flaw in the provider itself.** Don't report it here at all. Stop, don't confirm, repeat or widen
  it, delete the boxes, and report it privately to the provider (AGENTS.md, rule 7).

## Change behaviour: spec first

1. A behaviour change starts in [SPEC.md](SPEC.md), under an existing rule ID or a new one.
2. The code cites that rule.
3. Every rule has a test, listed in SPEC.md's "Tests" table. Add the test with the rule.

A documentation fix needs none of this. Provider status, setup and skips live in [docs/providers](docs/providers/README.md):
update the provider's page when its behaviour changes.

## Build and test

You need Go 1.25, and Docker for the fixture tests.

```sh
make                                           # the Linux probes, then bin/sandprobe; run it before make test
make test                                      # go vet ./... && go test ./...
gofmt -l .                                     # must print nothing
SANDPROBE_FIXTURES=1 go test ./internal/host   # adds the Docker fixture and exec tests
sh test/probe.sh                               # probe contract tests as root and nobody, without network
shellcheck -s sh recipes/*.sh examples/recipes/*.sh   # when you change a recipe
```

Every test runs on public data. Saved reports come from `demo/reports` and `test/reports`, which are runs of local
Docker boxes.

## Hard rules

The full list is in AGENTS.md. These are the ones a pull request most often meets:

- Never read a secret's value, and never print or log a credential. Provider and tool errors are sanitized before
  they reach any output.
- A run touches only the boxes it may: ones it created, deleted by the ID their create returned, or the existing box a
  person pointed `run exec` at, which is never reset or deleted.
- Test traffic goes only to the canary, or to names the probe only resolves.
- Never commit run data, reports of real accounts, credentials, kubeconfigs or `~/.config/sandprobe` state.

## Pull requests

- Every change goes through a pull request to `main`.
- Commit subjects are short and say what changed, often naming the rule, for example
  `Nitro: name recorded before create`.
- Fill in the pull request template, and add a line to the Unreleased section of [CHANGELOG.md](CHANGELOG.md) for a
  change a user would notice.
- [experiments/](experiments/README.md) holds research harnesses, not the product.

## Add a provider

Open a [provider request](https://github.com/summationai/sandprobe/issues/new?template=provider-request.yml) first.
An adapter needs a PRV row in SPEC.md that quotes the provider's security-research, bug-bounty, penetration-testing
and acceptable-use terms, and excludes the checks they rule out (PRV-5). A provider whose terms require written
consent for testing gets no shipped recipe until that consent is recorded (RCP-4).

## Code of conduct

Everyone taking part follows the [Code of Conduct](CODE_OF_CONDUCT.md).
