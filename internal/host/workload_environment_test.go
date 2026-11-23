package host

import (
	"context"
	"encoding/json"
	"io"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

func TestSharedWorkloadEnvironmentDropsInheritedAuthority(t *testing.T) {
	args := append(WorkloadEnvironment(), "/usr/bin/env")
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = []string{"SANDPROBE_TEST_INHERITED_AUTH=synthetic-not-secret", "GPG_KEY=synthetic-public-fingerprint"}
	out, err := cmd.Output()
	if err != nil {
		t.Fatal("shared clean environment could not start")
	}
	want := WorkloadEnvironment()[2:]
	got := strings.Fields(string(out))
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(got, want) || strings.Contains(string(out), "INHERITED_AUTH") || strings.Contains(string(out), "GPG_KEY") {
		t.Fatal("workload inherited an undeclared environment entry")
	}
	changed := WorkloadEnvironment()
	changed[2] = "changed"
	if WorkloadEnvironment()[2] == "changed" {
		t.Fatal("caller changed shared policy")
	}
}

func TestNitroCleanProbeRequiresMatchingWorkloadCommand(t *testing.T) {
	t.Setenv("SANDPROBE_AWS_ACCOUNT", "111122223333")
	b := agentFixture()
	b.CleanEnvironment = true
	actual := append(WorkloadEnvironment(), "python", "-I", "-c", "import time;time.sleep(1800)")
	fields := []string{b.UID, b.RunID, b.JobUID, "Running", "isolated-sandbox", "agent", b.Image, b.ConfigSHA256, "own-node", "0", b.Image, b.ContainerID}
	launches := 0
	p := &PodBox{Kubeconfig: b.Kubeconfig, Context: b.Context, Namespace: b.Namespace, Name: b.Name, UID: b.UID, ProbePath: "/tmp/probe", agentBinding: &b}
	p.kubectl = func(_ context.Context, _ io.Reader, out, _ io.Writer, args ...string) error {
		s := strings.Join(args, " ")
		switch {
		case strings.Contains(s, "config view"):
			io.WriteString(out, b.Endpoint)
		case strings.Contains(s, "jsonpath={.metadata.uid}{"):
			io.WriteString(out, strings.Join(fields, "\n"))
		case strings.Contains(s, "jsonpath={.spec.containers[0].command}"):
			json.NewEncoder(out).Encode(actual)
		case strings.HasSuffix(s, "jsonpath={.metadata.uid}"):
			io.WriteString(out, b.UID)
		case strings.Contains(s, "exec -i"):
			launches++
			if !strings.Contains(s, "-- "+strings.Join(WorkloadEnvironment(), " ")+" /tmp/probe") {
				t.Fatal("probe did not use the workload environment")
			}
		default:
			t.Fatal("unexpected fixture command")
		}
		return nil
	}
	if _, err := p.Probe(context.Background(), []string{"-exec"}, nil); err != nil || launches != 1 {
		t.Fatalf("matched workload/probe profile: %v", err)
	}
	actual = []string{"python", "-I", "-c", "import time;time.sleep(1800)"}
	if _, err := p.Probe(context.Background(), []string{"-exec"}, nil); err == nil || launches != 1 {
		t.Fatal("measurement-only environment clearing was accepted")
	}
}
