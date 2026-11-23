package host

// RUN-23: storage identity comes from the managed creator's receipts. Namespace,
// claim, PV and class labels do not confer ownership, even when their names match.
import (
	"context"
	"errors"
	"regexp"
	"strings"
)

type AgentWorkspaceBinding struct {
	NamespaceUID string `json:"namespace_uid"`
	ClaimUID     string `json:"claim_uid"`
	PVUID        string `json:"pv_uid"`
	ClassUID     string `json:"class_uid"`
	VolumeID     string `json:"volume_id"`
	Zone         string `json:"zone"`
}

func validAgentWorkspace(b AgentPodBinding) bool {
	if b.Workspace == nil || !b.CleanEnvironment {
		return false
	}
	w := b.Workspace
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
	name := "sandprobe-workspace-" + b.RunID
	if err := p.workspaceFields(ctx, "persistentvolumeclaim", "workspace",
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
		[]string{w.PVUID, "Bound", w.ClaimUID, b.Namespace, "workspace", "ebs.csi.eks.amazonaws.com", w.VolumeID, "ext4", name, "Filesystem", "1Gi", "ReadWriteOnce", "Retain", "topology.kubernetes.io/zone", "In", w.Zone, ""}); err != nil {
		return err
	}
	return p.workspaceFields(ctx, "storageclass", name,
		[]string{".metadata.uid", ".provisioner", ".reclaimPolicy", ".volumeBindingMode", ".metadata.deletionTimestamp"},
		[]string{w.ClassUID, "ebs.csi.eks.amazonaws.com", "Retain", "WaitForFirstConsumer", ""})
}
