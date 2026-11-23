package host

import (
	_ "embed"
	"encoding/json"
	"sort"
)

//go:embed workload_environment.json
var workloadEnvironmentJSON []byte

// WorkloadEnvironment is RUN-18's shared prefix for workload and probe execution.
// It returns fresh arguments; no parent environment entry is forwarded.
func WorkloadEnvironment() []string {
	var env map[string]string
	if json.Unmarshal(workloadEnvironmentJSON, &env) != nil || len(env) == 0 {
		panic("invalid shipped workload environment")
	}
	keys := make([]string, 0, len(env))
	for key := range env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	args := []string{"/usr/bin/env", "-i"}
	for _, key := range keys {
		args = append(args, key+"="+env[key])
	}
	return args
}
