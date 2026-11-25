# Test reports

Real Sandprobe reports of local Docker boxes, for the tests that need a saved report: `internal/analysis`,
`internal/report` and the CLI's `profile`, `compare`, `scorecard` and `assess` tests. Nothing here comes from a
provider; each box is a fixture in `test/fixtures`, run beside a local canary by `internal/host`'s `TestFixtures`.

| Report | The box |
|-|-|
| `egress-open.json` | `test/fixtures/net` as root, with every route out to the canary open: all six canary routes deliver |
| `egress-refused.json` | the same box and identity, with every TCP port to the canary refused with a reset and UDP to it rejected (`REFUSE_CANARY`): four TCP refusals proven, DNS and UDP silent, which proves nothing |
| `canary-down.json` | the same box with the canary paused: no network result counts, and the run is incomplete |

`bundles/` holds what each run produced: its manifest, the probe's own observations and the canary's evidence.
The reports are built from them by the grader and `report.BuildLegacy`, as a run built its own before `sandprobe/6`:
they declare `sandprobe/1` and carry a letter on purpose, so the tests read older reports. The tests build
`sandprobe/6` reports from the bundles.

## Rebuilding

With Docker running, from the repository root:

```sh
docker build -q -t sandprobe-fixture-net test/fixtures/net
SANDPROBE_FIXTURES=1 SANDPROBE_WRITE_FIXTURES=$PWD/test/reports/bundles go test ./internal/host -run 'TestFixtures/export-' -count=1
SANDPROBE_WRITE_FIXTURES=$PWD/test/reports go test ./internal/report -run TestGenerateFixtureReports -count=1
```

A rebuild gives new run IDs, nonces and container IDs, so the tests assert on what the boxes prove, never on those.
