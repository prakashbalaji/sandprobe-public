package host

import (
	"context"
	"io"
	"strings"
	"testing"
)

func workspaceBindingFixture() (AgentPodBinding, map[string][]string) {
	b := agentFixture()
	b.CleanEnvironment = true
	b.Workspace = &AgentWorkspaceBinding{NamespaceUID: strings.Repeat("1", 32), ClaimUID: strings.Repeat("2", 32), PVUID: strings.Repeat("3", 32), ClassUID: strings.Repeat("4", 32), VolumeID: "vol-" + strings.Repeat("5", 17), Zone: "us-west-2a"}
	w := b.Workspace
	name := "sandprobe-workspace-" + b.RunID
	return b, map[string][]string{
		"namespace":             {w.NamespaceUID, b.RunID, ""},
		"persistentvolumeclaim": {w.ClaimUID, "Bound", name, name, ""},
		"persistentvolume":      {w.PVUID, "Bound", w.ClaimUID, b.Namespace, "workspace", "ebs.csi.eks.amazonaws.com", w.VolumeID, "ext4", name, "Filesystem", "1Gi", "ReadWriteOnce", "Retain", "topology.kubernetes.io/zone", "In", w.Zone, ""},
		"storageclass":          {w.ClassUID, "ebs.csi.eks.amazonaws.com", "Retain", "WaitForFirstConsumer", ""},
	}
}

func TestAgentWorkspaceReadbacksRefuseReplacementAndConfigurationDrift(t *testing.T) {
	b, fields := workspaceBindingFixture()
	p := &PodBox{Kubeconfig: b.Kubeconfig, Context: b.Context, Namespace: b.Namespace}
	var changedKind string
	changedIndex := -1
	p.kubectl = func(_ context.Context, _ io.Reader, out, errOut io.Writer, args ...string) error {
		command := strings.Join(args, " ")
		for kind, values := range fields {
			if strings.Contains(command, " get "+kind+" ") {
				current := append([]string(nil), values...)
				if kind == changedKind {
					current[changedIndex] = "replacement-or-changed"
				}
				io.WriteString(out, strings.Join(current, "\n"))
				return nil
			}
		}
		t.Fatal("non-read or unexpected Kubernetes operation", command)
		return nil
	}
	if err := p.checkWorkspaceBinding(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	for kind, values := range fields {
		for index := range values {
			changedKind, changedIndex = kind, index
			if err := p.checkWorkspaceBinding(context.Background(), b); err == nil {
				t.Fatalf("%s field %d drift accepted", kind, index)
			}
		}
	}
}

func TestAgentWorkspaceRejectsUnsafeDeclarationsBeforeKubernetes(t *testing.T) {
	t.Setenv("SANDPROBE_AWS_ACCOUNT", "111122223333")
	original, _ := workspaceBindingFixture()
	for _, edit := range []func(*AgentPodBinding){
		func(b *AgentPodBinding) { b.CleanEnvironment = false },
		func(b *AgentPodBinding) { b.Workspace.NamespaceUID = "other-namespace" },
		func(b *AgentPodBinding) { b.Workspace.ClaimUID = "claim-name" },
		func(b *AgentPodBinding) { b.Workspace.VolumeID = "named-existing-volume" },
		func(b *AgentPodBinding) { b.Workspace.Zone = "other-region-a" },
	} {
		b := original
		w := *original.Workspace
		b.Workspace = &w
		edit(&b)
		called := false
		podCLI = func(context.Context, io.Reader, io.Writer, io.Writer, ...string) error { called = true; return nil }
		_, err := AttachAgentPod(context.Background(), b)
		podCLI = nil
		if err == nil || called {
			t.Fatal("unsafe workspace declaration reached Kubernetes")
		}
	}
}
