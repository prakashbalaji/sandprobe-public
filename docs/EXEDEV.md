# exe.dev adapter

The adapter evaluates one explicitly configured standalone Ubuntu 24.04 VM,
2 vCPU / 4GB, with Internet egress enabled. It does not evaluate the default
exeuntu/Shelley agent image, provider infrastructure, or an LLM coding workload.
The shared Linux probe and host grader are unchanged.

## Scope

exe.dev's terms (section 2.2) bar use "for benchmarking or competitive analysis of
the Service", so a live run needs your own clearance for this bounded test; it is
never represented as provider-written permission. The scope is one CPU baseline,
no automatic retry or continuous probing, with receiver-only marker traffic and
verified cleanup. See SPEC.md PRV-13.

## Transport and contract

Management uses `POST https://exe.dev/exec` with command text and JSON replies.
Guest execution uses the same endpoint with `Accept: application/x-ndjson`.
The host requires base64 output frames followed by exactly one zero exit-code
frame; missing completion, stderr, errors, oversized output and trailing events
are failures. It never logs request commands, provider bodies or token values.

Primary references checked 17 November 2026:

- https://exe.dev/docs/https-api
- https://exe.dev/docs/https-api-run-on-vm
- https://exe.dev/deploy/sandbox
- https://exe.dev/docs/terms-of-service
- Official generated response schemas:
  https://github.com/boldsoftware/exe-sdk-python/blob/67b4da39e65d65a6ff3a686f632c53a6b1615024/src/exedev/types.py
- Official stream framing/quoting implementation:
  https://github.com/boldsoftware/exe-sdk-python/blob/67b4da39e65d65a6ff3a686f632c53a6b1615024/src/exedev/_wire.py

There is no SDK runtime dependency. A probe is launched once in a private
scratch directory, then short commands poll its atomic exit-status marker.
The full probe has a guest timeout and host deadline; each HTTPS request stays
below the API's request limit. Probe and input uploads are chunked below the
64 KiB request limit and checked by SHA-256. The token remains on the host.

## Run after review and receiver preparation

```sh
make package
./bin/sandprobe plan exe.dev -o json
./bin/sandprobe run exe.dev -y \
  -exedev-key-file /path/to/owner-only-exedev.key \
  -canary "$HOME/.config/sandprobe/canary-<name>.state" \
  -out /tmp/sandprobe-exedev-results
```

The same review/receipt-based grading as the other providers applies. Guest
metadata, provider proxy, vsock and Kubernetes requests are excluded. Public
upload targets are not approved and resettable storage is absent; skipped
checks are not passes. No new grade policy or grading exception is introduced.

## Identity, cost and recovery

exe.dev's documented API addresses VMs by name, not immutable resource ID.
The adapter records the create-returned name and timestamp and checks region
and both run tags before execution and deletion. Guest boot identity is checked
in the same shell as each command. These checks cannot close the concurrent
same-account name-replacement race. Results must disclose that residual.

The owner-only `~/.config/sandprobe/exedev/exedev-active.state` journal is
created before the single create request and synced, including its parent
directory. An unresolved journal blocks another create. Name confirmation is
persisted before optional fields are interpreted. A timed-out create is not
retried or adopted from a list.

There is **no provider-enforced expiry** in this integration. A host crash can
leave billable compute. Cleanup uses a fresh independent deadline, persists
its delete intent, requires an explicit original-name deletion acknowledgment
and then authenticated scoped API absence. Visibility alone is not deletion
proof. This does not establish provider-internal data erasure.

```sh
./bin/sandprobe cleanup exe.dev -y \
  -exedev-key-file /path/to/owner-only-exedev.key \
  -exedev-state "$HOME/.config/sandprobe/exedev/exedev-active.state"
```

An ambiguous create/delete retains the journal for owner reconciliation and
returns cleanup exit 7. It never guesses a name, retries an ambiguous mutation,
or hides an unresolved cleanup behind a successful grade. Remove the receiver
through `deploy/canary.sh down` using its own recorded state, after saving the
run and independent cleanup evidence. No test resources are intended to remain.

## Local tests

```sh
go test ./internal/host ./cmd/sandprobe -run Exedev -count=1
go test -race ./internal/host -run Exedev -count=1
make test
```

Fixtures exercise both real shell-quoting layers, chunked byte preservation,
gzip/decompression/digest verification, one-launch asynchronous survey/full
execution, changed boot/provider identity, malformed terminal streams, crash
journals, credentials and rejected deletion acknowledgments. Fixture workloads
are harmless scripts, not live containment probes. Passing mocks do not
establish provider compatibility.
