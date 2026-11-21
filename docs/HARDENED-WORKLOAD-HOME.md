# Protected startup home, writable project

RUN-15 configures both managed workload runners with `HOME=/opt/sandprobe/home`,
a root-owned0555 directory whose ancestors cannot be replaced or written by the
agent. `/workspace` remains writable for code and outputs, `/workspace/.cache`
for tool caches, and `/tmp` for temporary files. Install project dependencies in a
workspace virtual environment; user-wide startup/tool configuration is protected.

The model workload, generated-code functional verifier and standard probe receive
the same HOME. This changes the actual execution configuration, rather than
pointing only the probe at an empty directory. Model identity, networking, prompt,
parser and nine functional cases are unchanged.

A shared metadata-only helper checks the owned home and every fixed ancestor.
Its canonical context hash is frozen in the pre-model contract and recomputed
after the workload. The helper does not inspect provider files or secret values,
and this owned-fixture evidence cannot verify provider image content or private
process namespaces. Those flags remain unchanged.

Offline calibration runs the unchanged nine-case task in a non-root, network-free
container. It verifies refused startup-file creation, successful project/cache
writes and the shared home metadata/hash. Both providers still require fresh
managed runs after review/CI/merge to establish their scorecard score (SCR-1) and workload result.
A lower Persistence exposure is an expected effect to test, not an assumed grade.
Reset survival and universal persistence prevention are not established.
