package host

// RUN-23: storage identity comes from the managed creator's receipts. Namespace,
// claim, PV and class labels do not confer ownership, even when their names match.
import (
	"context"
	"errors"
	"reflect"
	"regexp"
	"sandprobe/internal/strictjson"
	"strings"
)

type AgentWorkspaceBinding struct {
	StorageProfile string `json:"storage_profile,omitempty"`
	NamespaceUID   string `json:"namespace_uid"`
	ClaimUID       string `json:"claim_uid"`
	PVUID          string `json:"pv_uid"`
	ClassUID       string `json:"class_uid"`
	VolumeID       string `json:"volume_id"`
	Zone           string `json:"zone"`
}

func validAgentWorkspace(b AgentPodBinding) bool {
	if b.Workspace == nil || !b.CleanEnvironment {
		return false
	}
	w := b.Workspace
	if w.StorageProfile != "" && w.StorageProfile != "persistent-workspace" && w.StorageProfile != "persistent-artifacts" {
		return false
	}
	for _, id := range []string{w.NamespaceUID, w.ClaimUID, w.PVUID, w.ClassUID} {
		if !agentUID.MatchString(id) {
			return false
		}
	}
	return regexp.MustCompile(`^vol-[a-f0-9]{17}$`).MatchString(w.VolumeID) && regexp.MustCompile(`^us-west-2[a-d]$`).MatchString(w.Zone)
}

func workspaceProjection(fields []string) string {
	parts := make([]string, len(fields))
	for i, field := range fields {
		parts[i] = "{" + field + "}"
	}
	return strings.Join(parts, `{"\n"}`)
}

func (p *PodBox) workspaceFields(ctx context.Context, kind, name string, fields, want []string) error {
	out, err := p.run(ctx, nil, "get", kind, name, "-o", "jsonpath="+workspaceProjection(fields))
	if err != nil || string(out) != strings.Join(want, "\n") {
		return errors.New("persistent workspace readback changed or unavailable")
	}
	return nil
}

func (p *PodBox) checkWorkspaceBinding(ctx context.Context, b AgentPodBinding) error {
	if !validAgentWorkspace(b) {
		return errors.New("persistent workspace declaration invalid")
	}
	w := b.Workspace
	if err := p.workspaceFields(ctx, "namespace", b.Namespace,
		[]string{".metadata.uid", `.metadata.labels.sandprobe\.run`, ".metadata.deletionTimestamp"},
		[]string{w.NamespaceUID, b.RunID, ""}); err != nil {
		return err
	}
	claim := "workspace"
	if w.StorageProfile == "persistent-artifacts" {
		claim = "artifacts"
	}
	name := "sandprobe-" + claim + "-" + b.RunID
	if err := p.workspaceFields(ctx, "persistentvolumeclaim", claim,
		[]string{".metadata.uid", ".status.phase", ".spec.volumeName", ".spec.storageClassName", ".metadata.deletionTimestamp"},
		[]string{w.ClaimUID, "Bound", name, name, ""}); err != nil {
		return err
	}
	if err := p.workspaceFields(ctx, "persistentvolume", name,
		[]string{".metadata.uid", ".status.phase", ".spec.claimRef.uid", ".spec.claimRef.namespace", ".spec.claimRef.name",
			".spec.csi.driver", ".spec.csi.volumeHandle", ".spec.csi.fsType", ".spec.storageClassName", ".spec.volumeMode",
			".spec.capacity.storage", ".spec.accessModes[*]", ".spec.persistentVolumeReclaimPolicy",
			".spec.nodeAffinity.required.nodeSelectorTerms[0].matchExpressions[0].key",
			".spec.nodeAffinity.required.nodeSelectorTerms[0].matchExpressions[0].operator",
			".spec.nodeAffinity.required.nodeSelectorTerms[0].matchExpressions[0].values[*]", ".metadata.deletionTimestamp"},
		[]string{w.PVUID, "Bound", w.ClaimUID, b.Namespace, claim, "ebs.csi.eks.amazonaws.com", w.VolumeID, "ext4", name, "Filesystem", "1Gi", "ReadWriteOnce", "Retain", "topology.kubernetes.io/zone", "In", w.Zone, ""}); err != nil {
		return err
	}
	return p.workspaceFields(ctx, "storageclass", name,
		[]string{".metadata.uid", ".provisioner", ".reclaimPolicy", ".volumeBindingMode", ".metadata.deletionTimestamp"},
		[]string{w.ClassUID, "ebs.csi.eks.amazonaws.com", "Retain", "WaitForFirstConsumer", ""})
}

// API defaults may explicitly spell readOnly=false. Every other additional
// volume/mount option changes the storage context and must be refused.
func (p *PodBox) checkWorkspacePodStorage(ctx context.Context, b AgentPodBinding) error {
	bad := errors.New("persistent pod storage changed or unavailable")
	wantVolumes := []map[string]any{{"name": "workspace", "emptyDir": map[string]any{"sizeLimit": "64Mi"}}, {"name": "scratch", "emptyDir": map[string]any{"sizeLimit": "64Mi"}}}
	wantMounts := []map[string]any{{"name": "workspace", "mountPath": "/workspace"}, {"name": "scratch", "mountPath": "/tmp"}}
	if b.Workspace.StorageProfile == "persistent-artifacts" {
		wantVolumes = append(wantVolumes, map[string]any{"name": "artifacts", "persistentVolumeClaim": map[string]any{"claimName": "artifacts"}})
		wantMounts = append(wantMounts, map[string]any{"name": "artifacts", "mountPath": "/persist"})
	} else {
		wantVolumes[0] = map[string]any{"name": "workspace", "persistentVolumeClaim": map[string]any{"claimName": "workspace"}}
	}
	for _, check := range []struct {
		field string
		want  []map[string]any
	}{{".spec.volumes", wantVolumes}, {".spec.containers[0].volumeMounts", wantMounts}} {
		raw, err := p.run(ctx, nil, "get", "pod", b.Name, "-o", "jsonpath={"+check.field+"}")
		var got []map[string]any
		if err != nil || strictjson.Decode(raw, 8192, &got) != nil || len(got) != len(check.want) {
			return bad
		}
		indexed := map[string]map[string]any{}
		for _, v := range got {
			name, ok := v["name"].(string)
			if !ok || indexed[name] != nil {
				return bad
			}
			if v["readOnly"] == false {
				delete(v, "readOnly")
			}
			if pvc, ok := v["persistentVolumeClaim"].(map[string]any); ok && pvc["readOnly"] == false {
				delete(pvc, "readOnly")
			}
			indexed[name] = v
		}
		for _, v := range check.want {
			if !reflect.DeepEqual(indexed[v["name"].(string)], v) {
				return bad
			}
		}
	}
	return nil
}
