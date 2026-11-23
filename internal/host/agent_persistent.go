package host

// RUN-23: the parent owns the disposable cluster and EBS lifecycle. This adapter
// owns only one UID-preconditioned Job replacement for the generic PER-5 engine.
import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"sandprobe/internal/obs"
)

type AgentPersistentSpec struct {
	Journal     string          `json:"journal"`
	Authority   string          `json:"authority"`
	OriginalJob json.RawMessage `json:"original_job"`
}

type agentResetState struct {
	Schema            string `json:"schema"`
	RunID             string `json:"run_id"`
	Authority         string `json:"authority"`
	NamespaceUID      string `json:"namespace_uid"`
	VolumeID          string `json:"volume_id"`
	OriginalJobUID    string `json:"original_job_uid"`
	OriginalPodUID    string `json:"original_pod_uid"`
	OriginalConfigSHA string `json:"original_config_sha256"`
	Phase             string `json:"phase"`
	JobUID            string `json:"job_uid"`
	PodUID            string `json:"pod_uid"`
	PodName           string `json:"pod_name"`
	ConfigSHA         string `json:"config_sha256"`
	ContainerID       string `json:"container_id"`
}

type AgentPersistentBox struct {
	original, current              *PodBox
	binding                        AgentPodBinding
	binary, job                    []byte
	journal                        string
	state                          agentResetState
	originalVerified, resetStarted bool
}

func NewAgentPersistentBox(ctx context.Context, original *PodBox, binding AgentPodBinding, binary []byte, spec AgentPersistentSpec) (*AgentPersistentBox, error) {
	bad := errors.New("persistent Nitro reset declaration invalid")
	if original == nil || binding.Workspace == nil || !validAgentWorkspace(binding) || !binding.CleanEnvironment ||
		original.UID != binding.UID || original.Name != binding.Name || original.Namespace != binding.Namespace ||
		original.Kubeconfig != binding.Kubeconfig || original.Context != binding.Context ||
		len(binary) == 0 || len(binary) > 16<<20 || !filepath.IsAbs(spec.Journal) ||
		filepath.Base(spec.Journal) != "nitro-reset.state" || filepath.Dir(spec.Journal) != filepath.Dir(binding.Kubeconfig) ||
		!regexp.MustCompile(`^[a-f0-9]{48}$`).MatchString(spec.Authority) {
		return nil, bad
	}
	job, hash, err := agentResetJob(spec.OriginalJob, binding)
	if err != nil {
		return nil, bad
	}
	if err = original.checkAgentBinding(ctx, binding); err != nil {
		return nil, bad
	}
	if err = privateDaytonaVolumeDirectory(filepath.Dir(spec.Journal)); err != nil {
		return nil, bad
	}
	p := &AgentPersistentBox{original: original, current: original, binding: binding, binary: append([]byte(nil), binary...), job: job, journal: spec.Journal}
	p.state = agentResetState{Schema: "sandprobe.nitro-reset/1", RunID: binding.RunID, Authority: spec.Authority,
		NamespaceUID: binding.Workspace.NamespaceUID, VolumeID: binding.Workspace.VolumeID, OriginalJobUID: binding.JobUID,
		OriginalPodUID: binding.UID, OriginalConfigSHA: binding.ConfigSHA256, Phase: "prepared", ConfigSHA: hash}
	f, err := os.OpenFile(spec.Journal, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, bad
	}
	data, _ := json.Marshal(p.state)
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil || syncDaytonaDirectory(filepath.Dir(spec.Journal)) != nil {
		return nil, bad
	}
	return p, nil
}

func (p *AgentPersistentBox) save() error {
	bad := errors.New("Nitro reset journal update failed")
	data, err := json.Marshal(p.state)
	if err != nil {
		return bad
	}
	f, err := os.CreateTemp(filepath.Dir(p.journal), ".nitro-reset-")
	if err != nil {
		return bad
	}
	defer os.Remove(f.Name())
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil || os.Rename(f.Name(), p.journal) != nil || syncDaytonaDirectory(filepath.Dir(p.journal)) != nil {
		return bad
	}
	return nil
}
func (p *AgentPersistentBox) Calls() []obs.ProviderCall {
	calls := append([]obs.ProviderCall(nil), p.original.Calls...)
	if p.current != p.original {
		calls = append(calls, p.current.Calls...)
	}
	return calls
}

func (p *AgentPersistentBox) ID() string { return p.current.ID() }
func (p *AgentPersistentBox) Probe(ctx context.Context, args []string, input []byte) ([]byte, error) {
	return p.current.Probe(ctx, args, input)
}
func (p *AgentPersistentBox) volume() obs.Volume {
	path := "/workspace"
	if p.binding.Workspace.StorageProfile == "persistent-artifacts" {
		path = "/persist"
	}
	return obs.Volume{ID: p.binding.Workspace.VolumeID, MountPath: path}
}
func (p *AgentPersistentBox) Storage(ctx context.Context) (Storage, error) {
	if p.resetStarted {
		return Storage{}, errors.New("Nitro reset already attempted")
	}
	if err := p.original.checkAgentBinding(ctx, p.binding); err != nil {
		return Storage{}, errors.New("original Nitro storage unavailable")
	}
	return Storage{Model: "recreate", Volumes: []obs.Volume{p.volume()}}, nil
}
func (p *AgentPersistentBox) VerifyOriginalAfterCollection(ctx context.Context) error {
	if p.originalVerified {
		return nil
	}
	if p.resetStarted {
		return errors.New("original Nitro collection unverified")
	}
	if err := p.original.checkAgentBinding(ctx, p.binding); err != nil {
		return errors.New("original Nitro collection changed")
	}
	return nil
}
func resetWait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return errors.New("Nitro reset deadline")
	case <-time.After(time.Second):
		return nil
	}
}
func (p *AgentPersistentBox) Reset(ctx context.Context) (Box, *obs.ResetEvidence, error) {
	ev := &obs.ResetEvidence{Model: "recreate", OperationID: "nitro-job-recreate-" + p.binding.RunID, BoxBefore: p.binding.UID, Volumes: map[string][2]obs.Volume{}}
	bad := errors.New("Nitro reset incomplete; inspect private lifecycle state")
	if p.resetStarted {
		return p, ev, bad
	}
	p.resetStarted = true
	if p.original.checkAgentBinding(ctx, p.binding) != nil {
		return p, ev, bad
	}
	p.originalVerified = true
	p.state.Phase = "delete_intent"
	if p.save() != nil {
		return p, ev, bad
	}
	options, _ := json.Marshal(map[string]any{"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": map[string]string{"uid": p.binding.JobUID}, "propagationPolicy": "Foreground"})
	if _, err := p.original.run(ctx, bytes.NewReader(options), "delete", "--raw", "/apis/batch/v1/namespaces/"+p.binding.Namespace+"/jobs/model-task", "-f", "-"); err != nil {
		return p, ev, bad
	}
	for {
		job, err := p.original.run(ctx, nil, "get", "job", "model-task", "--ignore-not-found", "-o", "jsonpath={.metadata.uid}")
		if err != nil {
			return p, ev, bad
		}
		pod, err := p.original.run(ctx, nil, "get", "pod", p.binding.Name, "--ignore-not-found", "-o", "jsonpath={.metadata.uid}")
		if err != nil {
			return p, ev, bad
		}
		if (len(job) > 0 && string(job) != p.binding.JobUID) || (len(pod) > 0 && string(pod) != p.binding.UID) {
			return p, ev, bad
		}
		if len(job) == 0 && len(pod) == 0 {
			break
		}
		if resetWait(ctx) != nil {
			return p, ev, bad
		}
	}
	// Old job's pod selector must be empty as well, including unknown children.
	remaining, err := p.original.run(ctx, nil, "get", "pods", "-l", "job-name=model-task", "-o", "jsonpath={.items[*].metadata.uid}")
	if err != nil || len(bytes.TrimSpace(remaining)) != 0 {
		return p, ev, bad
	}
	if p.original.checkWorkspaceResources(ctx, p.binding) != nil {
		return p, ev, bad
	}
	// The old pod is gone; namespace and storage are verified again by the newly
	// attached pod before any probe upload. An unknown create stays create_intent.
	p.state.Phase = "create_intent"
	if p.save() != nil {
		return p, ev, bad
	}
	uid, err := p.original.run(ctx, bytes.NewReader(p.job), "create", "-f", "-", "-o", "jsonpath={.metadata.uid}")
	if err != nil || !agentUID.Match(uid) || string(uid) == p.binding.JobUID {
		return p, ev, bad
	}
	p.state.JobUID = string(uid)
	p.state.Phase = "created"
	if p.save() != nil {
		return p, ev, bad
	}
	for {
		raw, err := p.original.run(ctx, nil, "get", "pods", "-l", "job-name=model-task-reset", "-o", "jsonpath={.items[*].metadata.name}")
		names := strings.Fields(string(raw))
		if err != nil || len(names) > 1 {
			return p, ev, bad
		}
		if len(names) == 0 {
			if resetWait(ctx) != nil {
				return p, ev, bad
			}
			continue
		}
		name := names[0]
		if !regexp.MustCompile(`^model-task-reset-[a-z0-9-]+$`).MatchString(name) {
			return p, ev, bad
		}
		raw, err = p.original.run(ctx, nil, "get", "pod", name, "-o", "jsonpath="+agentPodProjection())
		if err != nil {
			return p, ev, bad
		}
		fields := strings.Split(string(raw), "\n")
		if len(fields) != 12 || !agentUID.MatchString(fields[0]) || fields[0] == p.binding.UID || fields[1] != p.binding.RunID || fields[2] != p.state.JobUID {
			return p, ev, bad
		}
		p.state.PodName, p.state.PodUID = name, fields[0]
		ev.BoxAfter = fields[0]
		if p.save() != nil {
			return p, ev, bad
		}
		if fields[3] != "Running" {
			if fields[3] != "Pending" || resetWait(ctx) != nil {
				return p, ev, bad
			}
			continue
		}
		nextBinding := p.binding
		nextBinding.Name = name
		nextBinding.UID = fields[0]
		nextBinding.JobUID = p.state.JobUID
		nextBinding.ConfigSHA256 = p.state.ConfigSHA
		nextBinding.ContainerID = fields[11]
		p.state.ContainerID = fields[11]
		if p.save() != nil {
			return p, ev, bad
		}
		next, err := AttachAgentPod(ctx, nextBinding)
		if err != nil || next.Arch != p.original.Arch {
			return p, ev, bad
		}
		p.current = next
		if next.Upload(ctx, p.binary) != nil {
			return p, ev, bad
		}
		if next.checkAgentBinding(ctx, nextBinding) != nil {
			return p, ev, bad
		}
		p.state.Phase = "ready"
		if p.save() != nil {
			return p, ev, bad
		}
		volume := p.volume()
		ev.Volumes[volume.MountPath] = [2]obs.Volume{volume, volume}
		ev.Done = true
		return p, ev, nil
	}
}

// The parent always tears down the full cluster and the exact external EBS ID.
// Execute does not call Teardown for mode=exec. Never invent cleanup proof here.
func (p *AgentPersistentBox) Teardown(context.Context, []obs.Volume) map[string]bool {
	return map[string]bool{"": false, p.binding.Workspace.VolumeID: false}
}
