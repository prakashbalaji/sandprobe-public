package host

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

func workspaceBindingFixture(profiles ...string) (AgentPodBinding, map[string][]string) {
	b := agentFixture()
	b.CleanEnvironment = true
	b.Workspace = &AgentWorkspaceBinding{NamespaceUID: strings.Repeat("1", 32), ClaimUID: strings.Repeat("2", 32), PVUID: strings.Repeat("3", 32), ClassUID: strings.Repeat("4", 32), VolumeID: "vol-" + strings.Repeat("5", 17), Zone: "us-west-2a"}
	w := b.Workspace
	claim := "workspace"
	if len(profiles) != 0 {
		w.StorageProfile = profiles[0]
		if profiles[0] == "persistent-artifacts" {
			claim = "artifacts"
		}
	}
	name := "sandprobe-" + claim + "-" + b.RunID
	return b, map[string][]string{
		"namespace":             {w.NamespaceUID, b.RunID, ""},
		"persistentvolumeclaim": {w.ClaimUID, "Bound", name, name, ""},
		"persistentvolume":      {w.PVUID, "Bound", w.ClaimUID, b.Namespace, claim, "ebs.csi.eks.amazonaws.com", w.VolumeID, "ext4", name, "Filesystem", "1Gi", "ReadWriteOnce", "Retain", "topology.kubernetes.io/zone", "In", w.Zone, ""},
		"storageclass":          {w.ClassUID, "ebs.csi.eks.amazonaws.com", "Retain", "WaitForFirstConsumer", ""},
	}
}

func TestAgentWorkspaceReadbacksRefuseReplacementAndConfigurationDrift(t *testing.T) {
	for _, profile := range []string{"", "persistent-workspace", "persistent-artifacts"} {
		t.Run(profile, func(t *testing.T) {
			b, fields := workspaceBindingFixture(profile)
			p := &PodBox{Kubeconfig: b.Kubeconfig, Context: b.Context, Namespace: b.Namespace}
			podReads := 0
			var changedKind string
			changedIndex := -1
			p.kubectl = func(_ context.Context, _ io.Reader, out, errOut io.Writer, args ...string) error {
				command := strings.Join(args, " ")
				if strings.Contains(command, " get pod ") {
					podReads++
					volumes := []map[string]any{{"name": "workspace", "emptyDir": map[string]any{"sizeLimit": "64Mi"}}, {"name": "scratch", "emptyDir": map[string]any{"sizeLimit": "64Mi"}}}
					mounts := []map[string]any{{"name": "workspace", "mountPath": "/workspace"}, {"name": "scratch", "mountPath": "/tmp"}}
					if profile == "persistent-artifacts" {
						volumes = append(volumes, map[string]any{"name": "artifacts", "persistentVolumeClaim": map[string]any{"claimName": "artifacts", "readOnly": false}})
						mounts = append(mounts, map[string]any{"name": "artifacts", "mountPath": "/persist", "readOnly": false})
					} else {
						volumes[0] = map[string]any{"name": "workspace", "persistentVolumeClaim": map[string]any{"claimName": "workspace"}}
					}
					var value any = volumes
					if strings.Contains(command, "volumeMounts") {
						value = mounts
					}
					return json.NewEncoder(out).Encode(value)
				}
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
			if podReads != 2 {
				t.Fatal("storage guard did not inspect actual pod volumes and mounts")
			}
			for kind, values := range fields {
				for index := range values {
					changedKind, changedIndex = kind, index
					if err := p.checkWorkspaceBinding(context.Background(), b); err == nil {
						t.Fatalf("%s field %d drift accepted", kind, index)
					}
				}
			}
		})
	}
}

func TestAgentWorkspaceRejectsUnsafeDeclarationsBeforeKubernetes(t *testing.T) {
	t.Setenv("SANDPROBE_AWS_ACCOUNT", "111122223333")
	original, _ := workspaceBindingFixture()
	for _, edit := range []func(*AgentPodBinding){
		func(b *AgentPodBinding) { b.CleanEnvironment = false },
		func(b *AgentPodBinding) { b.Workspace.StorageProfile = "custom" },
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

func TestAgentPersistentPodStorageRejectsMountRedirection(t *testing.T) {
	b, _ := workspaceBindingFixture("persistent-artifacts")
	p := &PodBox{}
	goodVolumes := `[{"name":"workspace","emptyDir":{"sizeLimit":"64Mi"}},{"name":"scratch","emptyDir":{"sizeLimit":"64Mi"}},{"name":"artifacts","persistentVolumeClaim":{"claimName":"artifacts"}}]`
	goodMounts := `[{"name":"workspace","mountPath":"/workspace"},{"name":"scratch","mountPath":"/tmp"},{"name":"artifacts","mountPath":"/persist"}]`
	for _, fixture := range []struct{ volumes, mounts string }{
		{strings.Replace(goodVolumes, `"claimName":"artifacts"`, `"claimName":"other"`, 1), goodMounts},
		{strings.Replace(goodVolumes, `"claimName":"artifacts"`, `"claimName":"artifacts","readOnly":true`, 1), goodMounts},
		{goodVolumes, strings.Replace(goodMounts, `"/persist"`, `"/other"`, 1)},
		{goodVolumes, strings.Replace(goodMounts, `"/persist"`, `"/persist","subPath":"other"`, 1)},
		{goodVolumes, strings.Replace(goodMounts, `"/persist"`, `"/persist","readOnly":true`, 1)},
		{goodVolumes, strings.Replace(goodMounts, `"/tmp"`, `"/tmp","mountPropagation":"Bidirectional"`, 1)},
	} {
		p.kubectl = func(_ context.Context, _ io.Reader, out, errOut io.Writer, args ...string) error {
			raw := fixture.volumes
			if strings.Contains(strings.Join(args, " "), "volumeMounts") {
				raw = fixture.mounts
			}
			_, e := io.WriteString(out, raw)
			return e
		}
		if p.checkWorkspacePodStorage(context.Background(), b) == nil {
			t.Fatal("unbound persistent pod storage accepted")
		}
	}
}
