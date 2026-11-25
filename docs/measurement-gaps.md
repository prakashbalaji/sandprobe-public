# Interpreting measurement gaps

Sandprobe measures a provider configuration running a workload. A score is not an execution count or a certificate
that every feature was tested. Retain the source revision, workload contract, raw results, exclusions and cleanup
evidence when comparing configurations. Recomputing a saved report with newer scoring code is an offline analysis,
not a fresh measurement.

| Result or gap | Meaning | What can improve the evidence |
|---|---|---|
| `pass`, `finding`, verified `absent` | A conclusive result under that check's proof rules | Preserve the supporting evidence and measurement scope. |
| `not_found` | A find-only check found no exposure; containment is unproven | A supported stronger measurement, if one exists; never relabel as a pass. |
| `unknown` | The evidence does not decide the check | Inspect the recorded reason and attempts before changing code or rerunning. A check may have run and remained inconclusive. |
| `skipped` | The host did not select the check | Resolve the actual gate: permitted scope, required feature, lifecycle support or implementation. |
| `scoped_out` | A selected check reports that its defined discovery found no applicable target | Inspect the stated discovery scope. This is not proof that every possible custom target is absent. |

The managed Nitro and Daytona workloads deliberately exclude provider endpoints. Preserve those exclusions until
the provider terms and assessment scope permit a specific measurement. Do not assume a feature is absent because
its check was excluded; an exclusion can mask a separate feature or implementation prerequisite.

| Check | Prerequisites and current limitations |
|---|---|
| SEC-4 | Requires permitted metadata-endpoint scope. A configured cloud identity or its absence is a separate fact. |
| EGR-3 | Requires an actual configured workload proxy, permitted scope and, for a local proxy, explicit local-proxy approval. Installing a proxy solely to exercise this check changes the configuration. |
| AMP-6 | Host connectivity is not implemented. The handler checks `/dev/vsock` presence, but never connects; a present device yields unknown. A missing device or an exclusion can prevent selection. Neither approval nor device presence alone completes the measurement. |
| AMP-7 | Requires a Kubernetes API target named by the workload environment and permitted scope. This check makes a TLS handshake, not an authenticated permissions assessment. |
| AMP-8.blk | Uses sysfs names mapped to `/dev/<name>`, plus explicitly declared custom paths under EVD-13. An existing workload device can be declared with `run exec -block-device-path`; this never attaches a device or reads device data. Do not add a device just to reduce exclusions. |
| PER-5 | Requires a supported reset, run-owned storage and a safely identifiable run-owned marker. An inode mismatch remains unknown and unread; a claimed persistent volume alone does not prove marker survival. |

For network checks, a connected socket followed by a TLS reset or HTTP error, without an independent canary
receipt, proves neither delivery nor a refusal. A new protocol must be supported by the deployed canary and
explicitly selected under EVD-10. `canary check -require-http-marker-v1` checks that prerequisite without creating
a sandbox or proving guest delivery. Repeating the same unsupported exchange does not add proof.

Keep workload success, security findings, measurement completeness and cleanup as separate conclusions. Change
the workload configuration only for a workload or security requirement, and compare the changed configuration
explicitly against its baseline.
