# Experiments

Research harnesses. **None of them is part of the product.** No release ships them, the `sandprobe` CLI never calls
them, and they may change or go away without notice. They stay here, with their tests, because some of the research
behind [SPEC.md](../SPEC.md) ran on them.

| Path | What it is |
|-|-|
| [`eks-agent/`](eks-agent/README.md) | A managed coding evaluation on AWS Nitro Sandboxes. A Bedrock model writes a small Python module for a network-enabled Nitro pod, a separate interpreter runs it against nine cases, and the pod is graded with workload-aware grading. By default the model runs inside the guest; its host-controller mode calls it from the host instead. Its host-side bridge is `cmd/sandprobe-agent-grade`. |
| [`daytona-agent/`](daytona-agent/README.md) | The same coding task on Daytona. The model is called from the host, and the code it writes runs only inside the sandbox. Its entrypoint is `cmd/sandprobe-daytona-workload`. |
| `proto/tui/` | The TUI and web report prototype, on demo data. It creates and probes nothing. It is its own Go module: `cd experiments/proto/tui && go run .` |

Compare Nitro and Daytona results only with that context: where the model runs changes what the box holds.

The two Go entrypoints stay in `cmd/` because they belong to the main Go module, and the harnesses still use shared
helpers in `deploy/`, such as `canary.sh` and `eks.sh`. A release builds only `cmd/sandprobe`.

A live run of either evaluation creates cloud resources that cost money, in an AWS account of your own
(`SANDPROBE_AWS_ACCOUNT`, `SANDPROBE_AWS_PROFILE`). It needs your own authorization for the provider, and Bedrock
model access. Each README lists the rest. Run records stay local: never commit them here. CI runs the offline tests
only, in [`test.yml`](../.github/workflows/test.yml) and [`networked-agent.yml`](../.github/workflows/networked-agent.yml).
