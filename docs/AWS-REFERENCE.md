# Paired AWS reference configurations

These opt-in variants prepare the next AWS calibration. They are not live results.

| Variant | Identity and image | Network |
|---|---|---|
| `isolated` | Existing example image/default user, unchanged | Existing open configuration |
| `network-isolated` | Existing example image/default user, unchanged | Existing network-isolated annotation |
| `reference-open` | Pinned Amazon Linux image; UID/GID10001; hardened settings below | Open configuration |
| `reference-network-isolated` | Exactly the same reference setup | Network-isolated annotation |

The reference pair differs only by the network annotation. The reference setup
is an operator-configured benchmark, not the provider default. Its image is the
public Amazon Linux 2023 multi-architecture index resolved on 18 November 2026:
`sha256:3f018977be7a3473a0a473ed105b244b8bdec8683ecb24962f675db23017137b`.
Changing this pin changes the benchmark configuration.

The profiles request no privilege escalation, capabilities drop ALL, a read-only
root filesystem, RuntimeDefault seccomp, no service-account-token automount or
service links, and no host network/PID/IPC. `/tmp` and `/workspace` are ephemeral
64Mi emptyDir volumes; CPU/memory limits remain 1 CPU/1Gi. The fixed task writes,
transforms, compares and checksums nonsecret text in `/workspace` before readiness.
The task exports HOME=/workspace, as does the separately exec'd probe. This is
a scripted file-work task, not an LLM/coding-agent evaluation.

The requested settings follow the relevant [Kubernetes security-context
controls](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
and [service-account-token opt-out](https://kubernetes.io/docs/concepts/security/service-accounts/).
Runtime support for these profiles is not established by Kubernetes documentation;
it must be validated on Nitro in a separately authorized run.

Before probe upload, a narrow nonsecret API projection checks the returned Pod UID,
runtime, image, identity/security settings, container/mount/volume set and file-task
command/readiness configuration. Injected env/envFrom, helpers, capabilities,
host namespaces, changed images and missing image IDs reject the reference setup.
No whole Pod JSON, env values or credential objects are exported. The same UID
checked teardown handles setup failures. Configuration and API-reported imageID
are recorded in existing report notes; they do not attest kernel enforcement.
The probe's actual identity and all findings remain unchanged. Offline comparison
compares only the fixed REF-2:/REF-3: reference context notes as opaque data, so a
different recorded image/profile cannot silently appear to have matching context.
Grader findings and lifecycle notes do not become configuration changes or mask
an observed-regression exit.

Inspect plans before either run:

```sh
./bin/sandprobe plan aws-nitro -variant reference-open
./bin/sandprobe plan aws-nitro -variant reference-network-isolated
```

The normal run approval and lifecycle apply. There is no automatic paired loop,
new cloud deployment, background job or live run in CI. Unsupported configurations
fail instead of silently falling back to root or skipping checks. Scheduling is
bounded 15 minutes, followed by two minutes for readiness, within the existing run
deadline; the existing cleanup path remains.

Do not promise these profiles will receive A. Removing root alone cannot remove
every F: the existing CHN-1 also treats readable process/file surfaces plus separate
marker delivery as Critical. A reference process runs as the agent's own UID, so
same-user helper access needs trustworthy role attribution before being called a
protected secret boundary. A future contextual grading policy must distinguish
that from confirmed protected access, without suppressing the recorded observation.
The new profiles collect a better-defined test; they do not reinterpret old reports
or change severity thresholds to produce more favorable grades.

## Structured context before the next probe

Reference runs now copy a `sandprobe.boundary-contract/1` declaration into the
host manifest before the full probe. It records the fixed workload, requested
image and identity, API-reported imageID, operator network-test requirement and
reset model. Protected-resource attribution stays `unestablished`. The declaration
is absent from probe stdin and is not proof of enforcement. Existing saved runs
retain missing context; none is reconstructed from their names or findings.

Offline assessment exports this declaration as unauthenticated context; comparison
flags addition, removal or changes. Legacy letters, findings and gates remain
unchanged. This is the first grading prerequisite, not the completed grading fix:
controlled agent-owned versus protected-resource fixtures and independent
calibration still precede a replacement overall assessment (SPEC BND-1–5).
