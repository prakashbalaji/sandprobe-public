# Changelog

Every release lists what changed for someone using Sandprobe. Dates are in Pacific Time. Each release's files and
their build attestations are on [GitHub Releases](https://github.com/summationai/sandprobe/releases).

## Unreleased

Being validated for 0.3.0.

### Canary and score

- Every run but `run docker` and the Modal proof of concept uses the hosted canary by default, the native provider
  adapters included; the proof of concept needs `-canary <state file>`. A canary state file from `deploy/canary.sh`
  is used only when `-canary` names it, any canary flag sets every `SANDPROBE_CANARY*` variable aside, and
  `run docker` refuses canary flags (HCN-5).
- Cloud access now asks whether the agent can use your own cloud identity. On a native adapter whose provider's terms
  exclude its metadata and Kubernetes endpoints, Cloud access is not applicable and the score is out of five.
  `run exec` and recipes leave it "Not tested" (SCR-2). Reports that carry skip kinds declare the schema
  `sandprobe/2` (AGT-6).
- The score shows measurement coverage beside it: which checks have usable or conclusive results, and which stayed
  skipped, missing, scoped out, unknown or unproven (SCR-5).

### Checks

- `run exec` and `run kubernetes` take `-provider-endpoints`, which turns on named provider-endpoint checks, such as
  `SEC-4,AMP-7` for cloud access, each one attested as allowed by your provider's terms (PRV-15).
- Plans name all three SEC-4 metadata addresses the probe dials (UX-4).
- AMP-1 grades sudo-rs installs instead of ending unknown, and PER-5 names why each root is a gap.
- Write and read checks no longer pass a refusal the agent could undo through ownership or capabilities (TWN-4).
- AMP-3 passes only with `NoNewPrivs` 1. With `NoNewPrivs` 0, setuid-root files in the system binary directories are
  still a finding; otherwise AMP-3 is unknown, since the probe can't rule out a setuid-root file elsewhere or a file
  with file capabilities anywhere, either of which an exec could gain privilege through. Set no-new-privileges to settle
  it. A box without it and without setuid-root files used to pass AMP-3 and now ends incomplete. AMP-2's pass covers
  only the capabilities held now.

### Saved reports

- A saved `sandprobe/2` report with a field present but empty or null is refused (AGT-6).
- An invalid report keeps its attested rows, and they stay not graded (GRD-5, PRV-15).

### Web report

- The HTML report takes the landing page's look: a graphite room, raised panels, Inter Tight headings, and results
  as keys. A failure is a light key with a red legend; an unknown is a dashed key, never green. `graphite` is the
  default palette and `mission` the alternative. `-theme modern`, the retired cyan palette, renders `graphite`, and a
  page that remembered `modern` opens in `graphite` (UX-8). The page still fetches nothing, fonts included (OUT-2).

### Research harnesses

- The managed Nitro and Daytona coding evaluations moved to `experiments/`, with the TUI prototype. They aren't part
  of the product. They gained a host-controller mode, persistent workspaces, bounded TLS measurement of approved
  workload hosts, and more failure diagnostics.

### Documentation

- The README leads with install, verifying a download, and a 30-second demo.
- `docs/providers/` gives each provider's status, setup, command, skipped checks and terms.
- New: CONTRIBUTING.md, CODE_OF_CONDUCT.md, issue forms (including a false-pass report), a pull request template and
  this changelog.

## 0.2.1 (2026-11-21)

- Releases are reproducible and attested. `make release` builds the four binaries; the release workflow builds them
  twice on separate runners and publishes only when every file matches byte for byte (REL-1, REL-2). Each `.gz` and
  both checksum files carry a build attestation, and the release notes give the `gh attestation verify` command
  (REL-3).
- A release is authentic when its files verify, never because its tag exists (REL-3).
- SEC-3 checks the credential files of six AI coding tools: Claude Code, Codex, Gemini CLI, Aider, Cline and Goose.
- Every test runs on public data: saved reports come from local Docker boxes.

## 0.2.0 (2026-11-21)

The first open-source version, under the MIT license. It was published as source only, with no tag and no GitHub
release.

- `run exec` checks a box you already have, through your own command (PRV-15).
- `run docker` grades a throwaway container from a local image, beside its own local canary (PRV-14).
- `run kubernetes` grades a throwaway pod in your cluster, through the first shipped recipe (PRV-16).
- Native adapters for Fly Sprites, AWS Nitro on EKS, Baseten, E2B, Vercel Sandbox, Cloudflare Sandbox, Daytona, Boat
  and exe.dev, each run beside a canary you deploy with `deploy/canary.sh`.
- A Modal proof of concept, built only with `make poc`.
- The hosted canary for `run exec` and recipes, and `-no-canary` to send no test traffic to any canary.
- A six-category score beside the letter grade, a JSON report and a self-contained HTML page, and the offline
  `scorecard`, `profile`, `assess` and `compare` commands.
