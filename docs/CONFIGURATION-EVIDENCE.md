# Configuration evidence across providers

EVD-5 writes `configuration-evidence.json` before the first model request. The
versioned artifact binds the managed run, original sandbox and configuration hash.
It records image and private-container evidence separately, with fixed source and
reason fields. It is trusted host configuration readback, not runtime attestation,
and does not independently change grading or fill an unknown.

The Nitro controller already reads the original pod's immutable requested image
and runtime `imageID`, verifies stable container identity, and checks the private
PID/IPC/network flags, single-container structure, allowed mounts and security
settings. It rechecks the frozen context after the workload. EVD-5 now retains a
portable record of those guards and requires exact runtime image identity matching;
an embedded digest with an arbitrary prefix/suffix cannot satisfy the image guard.
Go and Python exercise the same identity fixtures.

Daytona's current adapter obtains snapshot/policy metadata without runtime image
digest or private-process configuration evidence. Its artifact explicitly records
those two measurements as unknown. A digest-shaped snapshot reference or
`public=false` cannot change that status. No API absence is asserted for the entire
provider; this describes the evidence collected by the current integration.

Closing the image gap requires supported readback binding the original running
sandbox to the expected immutable image content. Closing process attribution
requires supported configuration evidence for its isolation context, bound to the
same sandbox before/after workload. New adapters must satisfy the same proof rules.
Documentation, requested settings and guest self-observation alone do not substitute
for those readbacks. Neither change requires probing provider/host/other-tenant
surfaces. Historical records and grades remain unchanged.
