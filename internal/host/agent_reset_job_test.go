package host

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"testing"
)

func resetJobFixture(t *testing.T) (AgentPodBinding, []byte) {
	t.Helper()
	b := agentFixture()
	b.CleanEnvironment = true
	container := map[string]any{"name": "agent", "image": b.Image, "env": []any{map[string]any{"name": "HOME", "value": WorkloadHome}}, "securityContext": map[string]any{"allowPrivilegeEscalation": false, "capabilities": map[string]any{"drop": []any{"ALL"}}}}
	job := map[string]any{"apiVersion": "batch/v1", "kind": "Job", "metadata": map[string]any{"name": "model-task", "namespace": b.Namespace}, "spec": map[string]any{"backoffLimit": 0, "template": map[string]any{"spec": map[string]any{"containers": []any{container}}}}}
	raw, err := canonicalAgentJob(job)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(raw)
	b.ConfigSHA256 = hex.EncodeToString(hash[:])
	container["env"] = append(container["env"].([]any), map[string]any{"name": "SANDPROBE_CONFIG_SHA256", "value": b.ConfigSHA256})
	raw, err = canonicalAgentJob(job)
	if err != nil {
		t.Fatal(err)
	}
	return b, raw
}

func TestAgentResetClonesOnlyBoundOriginalJob(t *testing.T) {
	b, raw := resetJobFixture(t)
	updated, newHash, err := agentResetJob(raw, b)
	if err != nil || newHash == b.ConfigSHA256 {
		t.Fatal("reset job was not separately bound", err)
	}
	var original, next map[string]any
	json.Unmarshal(raw, &original)
	json.Unmarshal(updated, &next)
	next["metadata"].(map[string]any)["name"] = "model-task"
	container := next["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)
	container["env"].([]any)[1].(map[string]any)["value"] = b.ConfigSHA256
	if !reflect.DeepEqual(original, next) {
		t.Fatal("recreation changed workload or security intent")
	}
	// A changed field, even one not used by the clone code, must fail the
	// original digest check rather than becoming a new privileged workload.
	for _, key := range []string{"namespace", "name"} {
		var changed map[string]any
		json.Unmarshal(raw, &changed)
		changed["metadata"].(map[string]any)[key] = "another-target"
		bad, _ := json.Marshal(changed)
		if _, _, err = agentResetJob(bad, b); err == nil {
			t.Fatal("changed target accepted")
		}
	}
	var changed map[string]any
	json.Unmarshal(raw, &changed)
	changed["spec"].(map[string]any)["suspend"] = true
	bad, _ := json.Marshal(changed)
	if _, _, err = agentResetJob(bad, b); err == nil {
		t.Fatal("unbound job option accepted")
	}
}
