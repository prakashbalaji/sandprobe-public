package host

// RUN-23: recreate from the host's original, digest-bound manifest, not a GET of
// the runtime environment (which could disclose values injected by an admission hook).
import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"sandprobe/internal/strictjson"
)

func canonicalAgentJob(value any) ([]byte, error) {
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, errors.New("job configuration encoding failed")
	}
	return bytes.TrimSuffix(out.Bytes(), []byte("\n")), nil
}

func agentResetJob(raw []byte, b AgentPodBinding) ([]byte, string, error) {
	bad := errors.New("reset manifest does not match original workload configuration")
	var job map[string]any
	if strictjson.Decode(raw, 32768, &job) != nil {
		return nil, "", bad
	}
	meta, ok := job["metadata"].(map[string]any)
	if !ok || job["apiVersion"] != "batch/v1" || job["kind"] != "Job" || meta["name"] != "model-task" || meta["namespace"] != b.Namespace {
		return nil, "", bad
	}
	spec, ok := job["spec"].(map[string]any)
	if !ok {
		return nil, "", bad
	}
	template, ok := spec["template"].(map[string]any)
	if !ok {
		return nil, "", bad
	}
	pod, ok := template["spec"].(map[string]any)
	if !ok {
		return nil, "", bad
	}
	containers, ok := pod["containers"].([]any)
	if !ok || len(containers) != 1 {
		return nil, "", bad
	}
	container, ok := containers[0].(map[string]any)
	if !ok || container["name"] != "agent" || container["image"] != b.Image {
		return nil, "", bad
	}
	environment, ok := container["env"].([]any)
	if !ok {
		return nil, "", bad
	}
	stripped := make([]any, 0, len(environment))
	found := false
	for _, entry := range environment {
		variable, ok := entry.(map[string]any)
		if !ok {
			return nil, "", bad
		}
		if variable["name"] == "SANDPROBE_CONFIG_SHA256" {
			if found || len(variable) != 2 || variable["value"] != b.ConfigSHA256 {
				return nil, "", bad
			}
			found = true
		} else {
			stripped = append(stripped, entry)
		}
	}
	if !found {
		return nil, "", bad
	}
	container["env"] = stripped
	original, err := canonicalAgentJob(job)
	if err != nil {
		return nil, "", bad
	}
	digest := sha256.Sum256(original)
	if hex.EncodeToString(digest[:]) != b.ConfigSHA256 {
		return nil, "", bad
	}
	meta["name"] = "model-task-reset"
	updated, err := canonicalAgentJob(job)
	if err != nil {
		return nil, "", bad
	}
	digest = sha256.Sum256(updated)
	hash := hex.EncodeToString(digest[:])
	container["env"] = append(stripped, map[string]any{"name": "SANDPROBE_CONFIG_SHA256", "value": hash})
	result, err := canonicalAgentJob(job)
	return result, hash, err
}
