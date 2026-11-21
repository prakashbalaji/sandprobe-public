# Diagnosing inconclusive network checks

EVD-6 adds shared, fixed diagnostics for observed HTTP403, HTTP407, other HTTP
status replies, connection reset, broken pipe and non-TLS record responses.
All providers use the same classification. Reply sampling is bounded to256bytes;
no response text, headers, bodies, certificates or raw errors are retained.
TLS certificate pinning and exact marker acknowledgement remain required.

These labels cannot establish a policy denial or identify the component producing
the response. An HTTP403 is a response, not an authenticated provider decision.
They cannot change a grade, resolve an unknown or trigger another request.
Kernel-backed refusal evidence and bound receiver receipts remain authoritative.

The latest retained Daytona run connected on443 but failed the TLS exchange, and
connected on80 with an unexpected reply. Its historical diagnostics are unchanged;
new labels require a future measurement and cannot be inferred retrospectively.
The [network documentation](https://www.daytona.io/docs/en/network-limits/) describes
different CIDR/domain policies and TLS interception for domain allowlists. That
does not establish the cause of our CIDR-policy observations. Sandprobe must not
disable certificate pinning or attribute a rejection solely from this documentation.

To close those unknowns, obtain supported effective-policy/decision evidence bound
to the original sandbox, exact target and attempt, or a validated observed network
refusal. A future policy-decision adapter needs its own proof specification and
negative/positive calibration; a requested allowlist plus silence is insufficient.
The current follow-up adds no targets, probes, traffic, policy changes or live run.
