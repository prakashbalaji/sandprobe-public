package host

import (
	"context"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"
)

// REF-5: run the exact task in the pinned public image with Docker controls.
// This validates task/tool availability, not Nitro or its security enforcement.
func TestReferenceWorkloadDocker(t *testing.T) {
	if os.Getenv("SANDPROBE_REFERENCE_WORKLOAD") != "1" {
		t.Skip("opt-in local Docker workload check")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "create", "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--user", "10001:10001", "--cpus", "1", "--memory", "1g", "--workdir", "/workspace",
		"--tmpfs", "/tmp:rw,uid=10001,gid=10001,mode=0700,size=64m",
		"--tmpfs", "/workspace:rw,uid=10001,gid=10001,mode=0700,size=64m",
		ReferenceImage, "sh", "-c", referenceTask).Output()
	if err != nil {
		t.Fatal("reference workload container creation failed")
	}
	id := strings.TrimSpace(string(out))
	if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(id) {
		t.Fatal("no immutable local container identity returned")
	}
	t.Cleanup(func() {
		cleanupCtx, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		if exec.CommandContext(cleanupCtx, "docker", "rm", "-f", id).Run() != nil {
			t.Error("reference container cleanup failed")
			return
		}
		gone, err := exec.CommandContext(cleanupCtx, "docker", "inspect", id).CombinedOutput()
		if err == nil || !strings.Contains(string(gone), "No such object: "+id) {
			t.Error("reference container deletion not confirmed")
		}
	})
	if exec.CommandContext(ctx, "docker", "start", id).Run() != nil {
		t.Fatal("reference workload did not start")
	}
	for {
		if exec.CommandContext(ctx, "docker", "exec", id, "test", "-f", "/workspace/.sandprobe-reference-ready").Run() == nil {
			break
		}
		state, _ := exec.CommandContext(ctx, "docker", "inspect", "-f", "{{.State.Status}}", id).Output()
		if ctx.Err() != nil || strings.TrimSpace(string(state)) == "exited" {
			t.Fatal("reference task did not complete")
		}
		time.Sleep(100 * time.Millisecond)
	}
	uid, err := exec.CommandContext(ctx, "docker", "exec", id, "id", "-u").Output()
	if err != nil || strings.TrimSpace(string(uid)) != "10001" {
		t.Fatal("reference task did not run as requested user")
	}
	if exec.CommandContext(ctx, "docker", "exec", id, "sh", "-c", "sha256sum -c /workspace/task/output.sha256").Run() != nil {
		t.Fatal("reference output checksum failed")
	}
	t.Log("Pinned-image non-root file task completed; checksum verified; no network; teardown checks exact container ID.")
}
