package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

type persistentBoxFixture struct {
	fault         string
	creates       int
	deleted       map[string]bool
	commands      map[string][]string
	volumeDeleted *bool
}

func newPersistentBoxFixture(t *testing.T) (*DaytonaPersistentBox, *persistentBoxFixture) {
	t.Helper()
	c, dir, volumeDeleted, _ := volumeFixture(t)
	v, err := c.CreateDaytonaVolume(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	base := c.runtime
	f := &persistentBoxFixture{deleted: map[string]bool{}, commands: map[string][]string{}, volumeDeleted: volumeDeleted}
	boxes := map[string]map[string]any{}
	binary := []byte("trusted probe fixture, not live evidence")
	digest := sha256.Sum256(binary)
	c.runtime = func(ctx context.Context, in map[string]any) ([]byte, error) {
		op := in["op"].(string)
		var out any
		switch op {
		case "create":
			f.creates++
			id := fmt.Sprintf("%08d-1234-1234-1234-123456789abc", f.creates)
			if f.creates == 2 && !f.deleted["00000001-1234-1234-1234-123456789abc"] {
				t.Fatal("replacement created before original deletion")
			}
			boxes[id] = map[string]any{"id": id, "name": in["name"], "born": time.Now().UTC().Format(time.RFC3339Nano), "organization": "fixture-org", "labels": map[string]string{"sandprobe_run": in["nonce"].(string)}, "state": "started", "desired_state": "started", "user": "root", "public": false, "auto_delete": 0, "auto_stop": 15, "auto_pause": 0, "volumes": 1, "volume_bindings": []daytonaVolumeMount{{ID: v.ID(), MountPath: "/workspace"}}, "snapshot_id": testDaytonaVolumeID, "snapshot_ref": "fixture-snapshot-ref", "network_allow_list": "52.94.0.1/32", "network_block_all": false}
			if f.creates == 2 && f.fault == "lost-create" {
				return nil, errors.New("fixed create transport failure")
			}
			out = map[string]any{"id": id}
		case "lookup":
			id := in["id"].(string)
			if f.deleted[id] {
				return json.Marshal(map[string]any{"absent": true})
			}
			original, ok := boxes[id]
			if !ok {
				t.Fatal("lookup of an uncreated sandbox")
			}
			copy := map[string]any{}
			for k, value := range original {
				copy[k] = value
			}
			if id == "00000001-1234-1234-1234-123456789abc" && f.fault == "original-config" {
				copy["network_allow_list"] = "0.0.0.0/0"
			}
			if id == "00000002-1234-1234-1234-123456789abc" && f.fault == "replacement-mount" {
				copy["volume_bindings"] = []daytonaVolumeMount{{ID: v.ID(), MountPath: "/other"}}
			}
			out = copy
		case "delete":
			id := in["id"].(string)
			if boxes[id] == nil {
				t.Fatal("delete guessed an unreturned sandbox ID")
			}
			labels := boxes[id]["labels"].(map[string]string)
			if in["nonce"] != labels["sandprobe_run"] {
				t.Fatal("delete crossed ownership")
			}
			f.deleted[id] = true
			out = map[string]any{"id": id, "deleted_request": true}
		case "exec":
			id := in["id"].(string)
			command := in["command"].(string)
			f.commands[id] = append(f.commands[id], command)
			stdout := ""
			switch {
			case command == "uname -m":
				stdout = "x86_64\n"
			case command == "cat /proc/sys/kernel/random/boot_id":
				stdout = "12345678-1234-1234-1234-123456789def\n"
			case strings.Contains(command, `printf ',"setpriv":'`):
				stdout = `{"uid":0,"gid":0,"setpriv":true,"python":true,"sudo":false}`
			case strings.Contains(command, `s=os.stat("/opt/sandprobe/protected-marker"`):
				stdout = `{"device":1,"inode":2,"valid":true}`
			case strings.Contains(command, "sandprobe.workload-home/1"):
				home := homeContextFixture()
				if id == "00000002-1234-1234-1234-123456789abc" {
					for i := range home.Nodes {
						home.Nodes[i].Device = 2
						home.Nodes[i].Inode += 100
					}
				}
				raw, _ := json.Marshal(home)
				stdout = string(raw)
			case strings.Contains(command, "mktemp -d"):
				stdout = "/tmp/.sandprobe-abcdefghijkl\n"
			case strings.Contains(command, "sha256sum"):
				stdout = hex.EncodeToString(digest[:]) + " /tmp/.sandprobe-abcdefghijkl/probe\n"
			case strings.Contains(command, "for path in") && f.fault == "replacement-setup":
				return nil, errors.New("fixed persisted workspace check failure")
			}
			out = map[string]any{"id": id, "stdout": stdout, "exit_code": 0}
		case "upload":
			out = map[string]any{"id": in["id"], "uploaded": true}
		default:
			return base(ctx, in)
		}
		return json.Marshal(out)
	}
	b, err := c.CreateDaytonaWorkload(context.Background(), dir, testDaytonaVolumeID, "52.94.0.1/32", v)
	if err != nil {
		t.Fatal(err)
	}
	b.Arch = "amd64"
	b.probePrefix = daytonaDrop
	b.ProbePath = "/tmp/.sandprobe-abcdefghijkl/probe"
	p, err := NewDaytonaPersistentBox(context.Background(), b, binary)
	if err != nil {
		t.Fatal(err)
	}
	return p, f
}

func TestDaytonaPersistentRecreatePreservesVolumeAndAllCleanup(t *testing.T) {
	p, f := newPersistentBoxFixture(t)
	st, err := p.Storage(context.Background())
	if err != nil || st.Model != "recreate" || len(st.Volumes) != 1 {
		t.Fatal("reset not declared", err)
	}
	original := p.ID()
	box, ev, err := p.Reset(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if box != p || !ev.Done || ev.BoxBefore != original || ev.BoxAfter == original || ev.BoxAfter != p.ID() || !p.originalVerified {
		t.Fatal("reset evidence incomplete")
	}
	if ev.Volumes["/workspace"][0] != st.Volumes[0] || ev.Volumes["/workspace"][1] != st.Volumes[0] {
		t.Fatal("recreation changed storage identity")
	}
	for _, command := range f.commands[p.ID()] {
		if strings.Contains(command, "install -d -o 10001") {
			t.Fatal("reset normalized persisted workspace metadata")
		}
	}
	if _, _, err = p.Reset(context.Background()); err == nil || f.creates != 2 {
		t.Fatal("reset retried")
	}
	gone := p.Teardown(context.Background(), st.Volumes)
	if !gone[""] || !gone[p.volume.ID()] || !*f.volumeDeleted || len(f.deleted) != 2 {
		t.Fatal("cleanup lost an original or replacement resource", gone)
	}
}

func TestDaytonaPersistentFailureRetainsReplacementAndUnknownCreate(t *testing.T) {
	for _, fault := range []string{"original-config", "replacement-mount", "replacement-setup", "lost-create"} {
		t.Run(fault, func(t *testing.T) {
			p, f := newPersistentBoxFixture(t)
			st, err := p.Storage(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if err = p.VerifyOriginalAfterCollection(context.Background()); err != nil {
				t.Fatal(err)
			}
			f.fault = fault
			box, ev, err := p.Reset(context.Background())
			if err == nil || ev.Done || box != p {
				t.Fatal("failed reset became proven")
			}
			if fault == "original-config" && (f.creates != 1 || len(f.deleted) != 0) {
				t.Fatal("original drift did not stop recreation")
			}
			gone := p.Teardown(context.Background(), st.Volumes)
			if fault == "lost-create" {
				if gone[""] || gone[p.volume.ID()] || *f.volumeDeleted {
					t.Fatal("unknown create counted as deleted")
				}
			} else if !gone[""] || !gone[p.volume.ID()] {
				t.Fatal("known resources leaked after failure", gone)
			}
		})
	}
}

func TestDaytonaPersistentRecoveryReconcilesOnlyRecordedConsumerID(t *testing.T) {
	p, f := newPersistentBoxFixture(t)
	b := p.original
	// Simulate termination after the sandbox ID was written but before either
	// optional sandbox metadata or the second volume-journal write completed.
	b.journal.Born, b.journal.Organization = "", ""
	if err := b.save(); err != nil {
		t.Fatal(err)
	}
	p.volume.journal.Consumers[0].ID = ""
	if err := p.volume.save(); err != nil {
		t.Fatal(err)
	}
	id, proof, err := b.client.CleanupDaytonaState(context.Background(), b.state)
	if err != nil || id != b.ID() || proof == "" || !f.deleted[id] {
		t.Fatal("recorded partial create was not recovered", err)
	}
	v, err := b.client.RecoverDaytonaVolume(p.volume.path)
	if err != nil || len(v.journal.Consumers) != 1 || !v.journal.Consumers[0].Gone {
		t.Fatal("consumer deletion proof not durable", err)
	}
	if err = v.Destroy(context.Background()); err != nil || !*f.volumeDeleted {
		t.Fatal("recovered storage cleanup failed", err)
	}
}

func TestDaytonaPersistentFullRecoveryCoversReplacement(t *testing.T) {
	p, f := newPersistentBoxFixture(t)
	if _, _, err := p.Reset(context.Background()); err != nil {
		t.Fatal(err)
	}
	result, err := p.original.client.CleanupDaytonaPersistentState(context.Background(), p.volume.path)
	if err != nil || !result.Confirmed || !result.BoxesConfirmed || !result.StorageConfirmed || len(result.BoxIDs) != 2 || len(f.deleted) != 2 || !*f.volumeDeleted {
		t.Fatal("recovery missed a resource", result, err)
	}
}

func TestDaytonaPersistentFullRecoveryDoesNotWaiveUnknownReplacement(t *testing.T) {
	p, f := newPersistentBoxFixture(t)
	f.fault = "lost-create"
	if _, _, err := p.Reset(context.Background()); err == nil {
		t.Fatal("expected unknown replacement create")
	}
	result, err := p.original.client.CleanupDaytonaPersistentState(context.Background(), p.volume.path)
	if err == nil || result.Confirmed || result.BoxesConfirmed || result.StorageConfirmed || *f.volumeDeleted || len(f.deleted) != 1 {
		t.Fatal("unknown replacement was counted as absent", result, err)
	}
}
