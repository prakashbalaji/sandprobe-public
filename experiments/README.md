# Experiments

Research harnesses. **None of them is part of the product.** No release ships them, the `sandprobe` CLI never calls
them, and they may change or go away without notice. They stay here, with their tests, because some of the research
behind [SPEC.md](../SPEC.md) ran on them.

| Path | What it is |
|-|-|
| [`eks-agent/`](eks-agent/README.md) | A managed coding evaluation on AWS Nitro Sandboxes. A Bedrock model writes a small Python module inside a network-enabled Nitro pod, a separate interpreter runs it against nine cases, and the pod is graded with workload-aware grading. Its host-side bridge is `cmd/sandprobe-agent-grade`. |
| [`daytona-agent/`](daytona-agent/README.md) | The same coding task on Daytona. The model is called from the host, and the code it writes runs only inside the sandbox. Its entrypoint is `cmd/sandprobe-daytona-workload`. |
| `proto/tui/` | The TUI and web report prototype, on demo data. It creates and probes nothing. It is its own Go module: `cd experiments/proto/tui && go run .` |

The two Go entrypoints stay in `cmd/` because they belong to the main Go module. A release builds only
`cmd/sandprobe`.

A live run of either evaluation creates cloud resources that cost money, in an AWS account of your own
(`SANDPROBE_AWS_ACCOUNT`, `SANDPROBE_AWS_PROFILE`). It needs your own authorization for the provider, and Bedrock
model access. Each README lists the rest. CI runs their offline tests only, in
[`test.yml`](../.github/workflows/test.yml) and [`networked-agent.yml`](../.github/workflows/networked-agent.yml).
