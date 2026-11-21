package host

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// RUN-8: use the real kubectl JSONPath parser against a local synthetic read-only
// API. No user's kubeconfig, credentials or cluster is used.
func TestAgentProjectionWithKubectlParser(t *testing.T) {
	kubectl, err := exec.LookPath("kubectl")
	if err != nil {
		t.Skip("kubectl not installed")
	}
	b := agentFixture()
	pod := map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": b.Name, "namespace": b.Namespace, "uid": b.UID,
		"labels": map[string]string{"sandprobe.run": b.RunID}, "ownerReferences": []any{map[string]any{"uid": b.JobUID, "controller": true}}},
		"spec":   map[string]any{"runtimeClassName": "isolated-sandbox", "nodeName": "own-node", "containers": []any{map[string]any{"name": "agent", "image": b.Image, "env": []any{map[string]string{"name": "SANDPROBE_CONFIG_SHA256", "value": b.ConfigSHA256}}}}},
		"status": map[string]any{"phase": "Running", "containerStatuses": []any{map[string]any{"name": "agent", "restartCount": 0, "imageID": b.Image, "containerID": b.ContainerID}}}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var result any
		switch r.URL.Path {
		case "/api":
			result = map[string]any{"kind": "APIVersions", "apiVersion": "v1", "versions": []string{"v1"}}
		case "/apis":
			result = map[string]any{"kind": "APIGroupList", "apiVersion": "v1", "groups": []any{}}
		case "/api/v1":
			result = map[string]any{"kind": "APIResourceList", "apiVersion": "v1", "groupVersion": "v1", "resources": []any{map[string]any{"name": "pods", "singularName": "pod", "namespaced": true, "kind": "Pod", "verbs": []string{"get"}}}}
		case "/api/v1/namespaces/" + b.Namespace + "/pods/" + b.Name:
			result = pod
		default:
			t.Errorf("unexpected local API path %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(result)
	}))
	defer server.Close()
	folder := t.TempDir()
	config := filepath.Join(folder, "config")
	if err := os.WriteFile(config, []byte("apiVersion: v1\nkind: Config\nclusters: []\ncontexts: []\nusers: []\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, kubectl, "--kubeconfig", config, "--server", server.URL, "--cache-dir", filepath.Join(folder, "cache"), "--namespace", b.Namespace,
		"get", "pod", b.Name, "-o", "jsonpath="+agentPodProjection()).CombinedOutput()
	if err != nil {
		t.Fatalf("kubectl parser rejected projection: %v: %s", err, output)
	}
	expected := []string{b.UID, b.RunID, b.JobUID, "Running", "isolated-sandbox", "agent", b.Image, b.ConfigSHA256, "own-node", "0", b.Image, b.ContainerID}
	if string(output) != strings.Join(expected, "\n") {
		t.Fatalf("projection mismatch: %q", output)
	}
}
