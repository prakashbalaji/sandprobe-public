package host

import (
	"context"
	"io"
	"strings"
	"testing"
)

func agentFixture() AgentPodBinding {
	return AgentPodBinding{Kubeconfig: "/private/eks.kubeconfig", Context: "sandprobe-12345678", Endpoint: "https://own-cluster.eks.amazonaws.com",
		RunID: strings.Repeat("a", 16), Namespace: "sandprobe-agent-" + strings.Repeat("a", 16), Name: "model-task-abcde", UID: strings.Repeat("b", 32), JobUID: strings.Repeat("c", 32),
		Image:        "111122223333.dkr.ecr.us-west-2.amazonaws.com/sandprobe-agent-" + strings.Repeat("a", 16) + "@sha256:" + strings.Repeat("d", 64),
		ConfigSHA256: strings.Repeat("e", 64), ContainerID: "containerd://" + strings.Repeat("f", 64)}
}

func TestAgentPodBindingGuardsEveryInvocation(t *testing.T) {
	t.Setenv("SANDPROBE_AWS_ACCOUNT", "111122223333") // the operator's account; the fixture's image is in it
	b := agentFixture()
	fields := []string{b.UID, b.RunID, b.JobUID, "Running", "isolated-sandbox", "agent", b.Image, b.ConfigSHA256, "own-node", "0", b.Image, b.ContainerID}
	for _, mutation := range []int{-2, -1, 0, 1, 2, 3, 4, 5, 6, 7, 9, 10, 11} {
		t.Run(string(rune(mutation+65)), func(t *testing.T) {
			current := append([]string{}, fields...)
			endpoint := b.Endpoint
			launches := 0
			podCLI = func(_ context.Context, _ io.Reader, stdout, stderr io.Writer, args ...string) error {
				s := strings.Join(args, " ")
				if !strings.Contains(s, "--namespace "+b.Namespace) {
					t.Fatal("namespace missing", s)
				}
				switch {
				case strings.Contains(s, "config view"):
					io.WriteString(stdout, endpoint)
				case strings.Contains(s, "jsonpath={.metadata.uid} "):
					t.Fatal("unexpected projection")
				case strings.Contains(s, "jsonpath={.metadata.uid}{"):
					io.WriteString(stdout, strings.Join(current, "\n"))
				case strings.HasSuffix(s, "jsonpath={.metadata.uid}"):
					io.WriteString(stdout, b.UID)
				case strings.Contains(s, "jsonpath={.spec.nodeName}"):
					io.WriteString(stdout, "own-node")
				case strings.Contains(s, "jsonpath={.status.nodeInfo.architecture}"):
					io.WriteString(stdout, "amd64")
				case strings.Contains(s, "exec -i"):
					launches++
					io.WriteString(stdout, "bounded output")
				default:
					t.Fatal("unexpected kubectl", s)
				}
				return nil
			}
			defer func() { podCLI = nil }()
			p, err := AttachAgentPod(context.Background(), b)
			if err != nil {
				t.Fatal(err)
			}
			p.ProbePath = "/tmp/owned/probe"
			if mutation >= 0 {
				current[mutation] = "changed"
			} else if mutation == -1 {
				endpoint = "https://other-cluster.eks.amazonaws.com"
			}
			_, err = p.Probe(context.Background(), []string{"-survey"}, nil)
			if mutation == -2 {
				if err != nil || launches != 1 {
					t.Fatal(err, launches)
				}
			} else if err == nil || launches != 0 {
				t.Fatal("changed identity launched probe", err, launches)
			}
		})
	}
}

func TestAgentPodRejectsNonRunBindingBeforeKubectl(t *testing.T) {
	t.Setenv("SANDPROBE_AWS_ACCOUNT", "111122223333") // the operator's account; the fixture's image is in it
	original := agentFixture()
	for _, change := range []func(*AgentPodBinding){
		func(b *AgentPodBinding) { b.Namespace = "default" }, func(b *AgentPodBinding) { b.RunID = "bad" },
		func(b *AgentPodBinding) { b.UID = "" }, func(b *AgentPodBinding) { b.JobUID = "" },
		func(b *AgentPodBinding) { b.Image = strings.ReplaceAll(b.Image, "aaaa", "bbbb") },
		func(b *AgentPodBinding) { b.ContainerID = "" }, func(b *AgentPodBinding) { b.ConfigSHA256 = "" },
	} {
		b := original
		change(&b)
		podCLI = func(context.Context, io.Reader, io.Writer, io.Writer, ...string) error {
			t.Fatal("kubectl called for invalid binding")
			return nil
		}
		if _, err := AttachAgentPod(context.Background(), b); err == nil {
			t.Fatal("accepted invalid binding")
		}
	}
	podCLI = nil
}

// The image must be in the operator's own account: an unset or other account matches nothing.
func TestAgentImageNeedsTheOperatorsAccount(t *testing.T) {
	image := agentFixture().Image
	for account, want := range map[string]bool{"111122223333": true, "": false, "999999999999": false, "11112222333x": false, ".*": false} {
		t.Setenv("SANDPROBE_AWS_ACCOUNT", account)
		if agentImage(image) != want {
			t.Errorf("account %q: %v", account, !want)
		}
	}
}
