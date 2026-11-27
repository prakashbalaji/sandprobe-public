# Process-refusal capability consistency

Scope: Sandprobe host grader consistency. Reproduction uses synthetic evidence only.

The probe applies TWN-4 before reporting a negative process-access observation: an agent holding effective or
permitted CAP_SETUID, CAP_SETGID, CAP_SYS_PTRACE, CAP_SYS_ADMIN or CAP_SYS_MODULE cannot use the observed
refusal as proof of isolation. The host validated the proof shape and UID/root flag, but did not cross-check the
same document's capabilities. A claimed SEC-2 or SEC-5 pass could therefore contradict its identity and still pass.

## Reproduce

`go test ./internal/grade -run TestProcessRefusalCapabilities -count=1`

The regression supplies a complete synthetic refusal proof, then adds one process-access capability to the
identity's effective or permitted set. Before the fix, the test fails with `unsupported negative accepted: pass`.
After the fix, the run remains valid and the affected negative is unknown. The test also covers missing permitted
capability evidence, bounding-only capabilities, verified disappearance, preserved findings, missing controls and
unknowns that must not turn into passes.

## Fix and limits

TWN-5 adds the host-side consistency check. It only removes unsupported negative results. Bounding capabilities
alone do not mean the process holds them. A real capability drop requires a new configuration and a new probe;
zero capabilities alone cannot replace target coverage, eligible refusals or the allowed/refused controls.

Saved report analysis does not authenticate or regrade historical claims. Apply a matching current collector/grader
to new raw evidence. This focused fix does not claim that the host can independently reconstruct every TWN-4
filesystem permission model from a guest's report.
