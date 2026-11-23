## What changes

<!-- What a user or a reviewer will notice. -->

## Rules

<!-- The SPEC.md rule IDs this implements or changes, such as PRV-15 or SCR-2. A behaviour change starts in SPEC.md. -->

## Tests

<!-- The test for each rule, as listed in SPEC.md's Tests table, and what you ran. -->

- [ ] `make test` passes, and `gofmt -l .` prints nothing.
- [ ] Every new or changed rule has its test.

## Checklist

- [ ] Nothing reads a secret's value, or prints or logs a credential.
- [ ] No run data, real reports, credentials, kubeconfigs or `~/.config/sandprobe` state are committed.
- [ ] A provider's page in `docs/providers/` is updated if its behaviour changed.
- [ ] `CHANGELOG.md` has a line under Unreleased, if a user would notice.
