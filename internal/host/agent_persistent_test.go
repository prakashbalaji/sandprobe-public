package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func persistentAgentFixture(t *testing.T, failure string) (*AgentPersistentBox, *[]string) {
	t.Helper()
	t.Setenv("SANDPROBE_AWS_ACCOUNT", "111122223333")
	b, fields := workspaceBindingFixture("persistent-artifacts")
	fixture, job := resetJobFixture(t)
	b.ConfigSHA256 = fixture.ConfigSHA256
	b.Kubeconfig = filepath.Join(t.TempDir(), "eks.kubeconfig")
	if os.Chmod(filepath.Dir(b.Kubeconfig), 0700) != nil {
		t.Fatal("private fixture directory")
	}
	nextJob := strings.Repeat("6", 32)
	nextPod := strings.Repeat("7", 32)
	nextName := "model-task-reset-xyz"
	_, nextHash, err := agentResetJob(job, b)
	if err != nil {
		t.Fatal(err)
	}
	binary := []byte("same embedded probe bytes")
	sum := sha256.Sum256(binary)
	deleted, created := false, false
	events := []string{}
	path := filepath.Join(filepath.Dir(b.Kubeconfig), "nitro-reset.state")
	readState := func() agentResetState {
		raw, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		var s agentResetState
		if json.Unmarshal(raw, &s) != nil {
			t.Fatal("invalid state")
		}
		return s
	}
	cli := func(_ context.Context, in io.Reader, out, errOut io.Writer, args ...string) error {
		command := strings.Join(args, " ")
		write := func(s string) error { _, e := io.WriteString(out, s); return e }
		switch {
		case strings.Contains(command, " config view "):
			return write(b.Endpoint)
		case strings.Contains(command, " delete --raw "):
			if readState().Phase != "delete_intent" {
				t.Fatal("delete before durable intent")
			}
			raw, _ := io.ReadAll(in)
			var options struct {
				Preconditions struct {
					UID string `json:"uid"`
				} `json:"preconditions"`
			}
			json.Unmarshal(raw, &options)
			if options.Preconditions.UID != b.JobUID {
				t.Fatal("delete without original UID")
			}
			events = append(events, "delete")
			if failure == "delete" {
				return errors.New("refused")
			}
			deleted = true
			return nil
		case strings.Contains(command, " create -f - "):
			if !deleted || readState().Phase != "create_intent" {
				t.Fatal("create before confirmed deletion and intent")
			}
			events = append(events, "create")
			created = true
			if failure == "lost-create" {
				return errors.New("response unavailable")
			}
			return write(nextJob)
		case strings.Contains(command, " get job model-task "):
			if deleted {
				return nil
			}
			return write(b.JobUID)
		case strings.Contains(command, " get pods "):
			if strings.Contains(command, "job-name=model-task-reset") {
				if !created {
					return nil
				}
				if readState().JobUID != nextJob {
					t.Fatal("discover before returned UID durable")
				}
				return write(nextName)
			}
			if !deleted {
				t.Fatal("old pod list before deletion")
			}
			return nil
		case strings.Contains(command, " get pod "):
			if strings.Contains(command, "jsonpath-as-json={.spec.securityContext}") {
				return write(`[{"runAsUser":10001,"runAsGroup":10001,"runAsNonRoot":true,"fsGroup":10001,"seccompProfile":{"type":"RuntimeDefault"}}]`)
			}
			if strings.Contains(command, "jsonpath-as-json={.spec.containers[0].securityContext}") {
				if created && failure == "replacement-root" {
					return write(`[{"runAsUser":0}]`)
				}
				return write(`[{"allowPrivilegeEscalation":false,"readOnlyRootFilesystem":true,"privileged":false,"capabilities":{"drop":["ALL"]}}]`)
			}
			if strings.Contains(command, ".spec.containers[*].name") {
				return write(strings.Join([]string{"agent", "", "", "model-task", "false", "", "", "", "", ""}, "\n"))
			}
			replacement := strings.Contains(command, " get pod "+nextName+" ")
			uid := b.UID
			if replacement {
				uid = nextPod
			}
			if strings.Contains(command, "--ignore-not-found") {
				if deleted {
					if failure == "replaced-original" {
						return write(strings.Repeat("8", 32))
					}
					events = append(events, "old-pod-gone")
					return nil
				}
				return write(uid)
			}
			if strings.HasSuffix(command, "jsonpath={.metadata.uid}") {
				return write(uid)
			}
			if strings.Contains(command, ".status.containerStatuses") {
				hash, jobUID := b.ConfigSHA256, b.JobUID
				if replacement {
					hash, jobUID = nextHash, nextJob
					if failure == "replacement-config" {
						hash = strings.Repeat("9", 64)
					}
				}
				return write(strings.Join([]string{uid, b.RunID, jobUID, "Running", "isolated-sandbox", "agent", b.Image, hash, "own-node", "0", b.Image, b.ContainerID}, "\n"))
			}
			if strings.Contains(command, ".spec.nodeName") {
				return write("own-node")
			}
			if strings.Contains(command, ".spec.containers[0].command") {
				return json.NewEncoder(out).Encode(append(WorkloadEnvironment(), "python", "-I", "-c", "import time;time.sleep(1800)"))
			}
			if strings.Contains(command, "volumeMounts") {
				return write(`[{"name":"workspace","mountPath":"/workspace"},{"name":"scratch","mountPath":"/tmp"},{"name":"artifacts","mountPath":"/persist"}]`)
			}
			if strings.Contains(command, ".spec.volumes") {
				return write(`[{"name":"workspace","emptyDir":{"sizeLimit":"64Mi"}},{"name":"scratch","emptyDir":{"sizeLimit":"64Mi"}},{"name":"artifacts","persistentVolumeClaim":{"claimName":"artifacts"}}]`)
			}
		case strings.Contains(command, " get node "):
			return write("amd64")
		case strings.Contains(command, " exec "):
			if !created {
				t.Fatal("exec before replacement created")
			}
			data, _ := io.ReadAll(in)
			if string(data) != string(binary) {
				t.Fatal("replacement binary changed")
			}
			events = append(events, "upload")
			return write(hex.EncodeToString(sum[:]) + "  probe")
		default:
			for kind, values := range fields {
				if strings.Contains(command, " get "+kind+" ") {
					return write(strings.Join(values, "\n"))
				}
			}
		}
		t.Fatalf("unexpected lifecycle operation: %s", command)
		return nil
	}
	original := &PodBox{Kubeconfig: b.Kubeconfig, Context: b.Context, Namespace: b.Namespace, Name: b.Name, UID: b.UID, Arch: "amd64", kubectl: cli, agentBinding: &b}
	podCLI = cli
	t.Cleanup(func() { podCLI = nil })
	if err := original.checkAgentBinding(context.Background(), b); err != nil {
		t.Fatal("fixture binding:", err)
	}
	if err := privateDaytonaVolumeDirectory(filepath.Dir(path)); err != nil {
		t.Fatal("fixture journal directory:", err)
	}
	p, err := NewAgentPersistentBox(context.Background(), original, b, binary, AgentPersistentSpec{Journal: path, Authority: strings.Repeat("a", 48), OriginalJob: job})
	if err != nil {
		t.Fatal(err)
	}
	return p, &events
}

func TestAgentPersistentResetUsesDurableUIDBoundLifecycle(t *testing.T) {
	p, events := persistentAgentFixture(t, "")
	storage, err := p.Storage(context.Background())
	if err != nil || storage.Model != "recreate" || storage.Volumes[0].MountPath != "/persist" {
		t.Fatal("storage", err)
	}
	after, proof, err := p.Reset(context.Background())
	if err != nil || !proof.Done || proof.BoxBefore == proof.BoxAfter || after.ID() != proof.BoxAfter {
		t.Fatal("reset", err)
	}
	if strings.Join(*events, ",") != "delete,old-pod-gone,create,upload" {
		t.Fatal("reset order", *events)
	}
	if proof.Volumes["/persist"][0] != proof.Volumes["/persist"][1] {
		t.Fatal("persistent backend changed")
	}
	if p.VerifyOriginalAfterCollection(context.Background()) != nil {
		t.Fatal("original collection lost")
	}
	if _, _, err = p.Reset(context.Background()); err == nil {
		t.Fatal("second reset accepted")
	}
	raw, _ := os.ReadFile(p.journal)
	var state agentResetState
	json.Unmarshal(raw, &state)
	if state.Phase != "ready" || state.JobUID == "" || state.PodUID != proof.BoxAfter {
		t.Fatal("ready journal incomplete")
	}
}
func TestAgentPersistentFailuresKeepReplacementUnconfirmed(t *testing.T) {
	for _, failure := range []string{"delete", "replaced-original", "lost-create", "replacement-config", "replacement-root"} {
		t.Run(failure, func(t *testing.T) {
			p, events := persistentAgentFixture(t, failure)
			_, proof, err := p.Reset(context.Background())
			if err == nil || proof.Done {
				t.Fatal("failure became completed reset")
			}
			if failure == "delete" || failure == "replaced-original" {
				for _, event := range *events {
					if event == "create" {
						t.Fatal("recreated before old box gone")
					}
				}
			}
			if failure == "lost-create" {
				raw, _ := os.ReadFile(p.journal)
				var state agentResetState
				json.Unmarshal(raw, &state)
				if state.Phase != "create_intent" || state.JobUID != "" {
					t.Fatal("lost create adopted an identity")
				}
			}
			if p.Teardown(context.Background(), nil)[""] {
				t.Fatal("parent teardown invented")
			}
		})
	}
}
func TestAgentPersistentConstructorCannotReuseResetAuthority(t *testing.T) {
	p, _ := persistentAgentFixture(t, "")
	// The existing exclusive state must block another reset driver before mutation.
	fixture, job := resetJobFixture(t)
	_ = fixture
	_, err := NewAgentPersistentBox(context.Background(), p.original, p.binding, p.binary, AgentPersistentSpec{Journal: p.journal, Authority: p.state.Authority, OriginalJob: job})
	if err == nil {
		t.Fatal("existing reset state reused")
	}
}
