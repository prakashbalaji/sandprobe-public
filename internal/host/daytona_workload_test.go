package host

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func workloadDaytonaFixture(t *testing.T) (*DaytonaBox, func() map[string]any) {
	t.Helper()
	c, _ := NewDaytonaClient("fixture-key", "")
	b := &DaytonaBox{client: c, journal: daytonaJournal{ID: "12345678-1234-1234-1234-123456789abc", Name: "fixture", Nonce: "nonce", Born: time.Now().UTC().Format(time.RFC3339Nano), Organization: "org", SnapshotID: "12345678-1234-1234-1234-123456789def", NetworkAllowList: "52.94.0.1/32"}, probePrefix: daytonaDrop, ProbePath: "/tmp/.sandprobe-abcdefghijkl/probe"}
	info := func() map[string]any {
		return map[string]any{"id": b.ID(), "name": b.journal.Name, "born": b.journal.Born, "organization": "org", "labels": map[string]string{"sandprobe_run": "nonce"}, "public": false, "auto_delete": 0, "auto_stop": 15, "auto_pause": 0, "volumes": 0, "user": "root", "snapshot_id": b.journal.SnapshotID, "snapshot_ref": "registry.example/snapshot:tag", "network_allow_list": b.journal.NetworkAllowList, "network_block_all": false, "domain_allow_list": "", "state": "started"}
	}
	return b, info
}
func TestDaytonaWorkloadSharesPrincipalAndRejectsDrift(t *testing.T) {
	b, info := workloadDaytonaFixture(t)
	var commands []string
	lookups := 0
	drift := false
	b.client.runtime = func(_ context.Context, in map[string]any) ([]byte, error) {
		var out any
		switch in["op"] {
		case "lookup":
			lookups++
			m := info()
			if drift && lookups%2 == 0 {
				m["network_allow_list"] = "0.0.0.0/0"
			}
			out = m
		case "exec":
			commands = append(commands, in["command"].(string))
			out = map[string]any{"id": b.ID(), "stdout": "{}", "exit_code": 0}
		case "upload":
			out = map[string]any{"id": b.ID(), "uploaded": true}
		default:
			t.Fatal("unexpected operation")
		}
		return json.Marshal(out)
	}
	if _, e := b.WorkloadCommand(context.Background(), "python3 /opt/sandprobe/worker.py"); e != nil {
		t.Fatal(e)
	}
	if _, e := b.Probe(context.Background(), nil, []byte("{}")); e != nil {
		t.Fatal(e)
	}
	for _, s := range commands {
		if !strings.Contains(s, daytonaDrop) || !strings.Contains(s, "cd /workspace &&") {
			t.Fatal("principal or cwd differs", s)
		}
	}
	drift = true
	lookups = 0
	if _, e := b.WorkloadCommand(context.Background(), "true"); e == nil {
		t.Fatal("configuration drift accepted")
	}
}
func TestDaytonaWorkloadCleanupDoesNotNeedSnapshotAPI(t *testing.T) {
	b, info := workloadDaytonaFixture(t)
	b.state = filepath.Join(t.TempDir(), "original.state")
	os.WriteFile(b.state, []byte("fixture"), 0600)
	deleted := false
	b.client.runtime = func(_ context.Context, in map[string]any) ([]byte, error) {
		if in["workload"] == true {
			t.Fatal("cleanup consulted snapshot API")
		}
		switch in["op"] {
		case "lookup":
			if deleted {
				return []byte(`{"absent":true}`), nil
			}
			return json.Marshal(info())
		case "delete":
			if in["id"] != b.ID() {
				t.Fatal("wrong ID")
			}
			deleted = true
			return json.Marshal(map[string]any{"id": b.ID(), "deleted_request": true})
		}
		t.Fatal("unexpected operation")
		return nil, nil
	}
	if e := b.Destroy(context.Background()); e != nil {
		t.Fatal(e)
	}
	if e := b.ConfirmWorkloadGone(context.Background()); e != nil {
		t.Fatal(e)
	}
}
func TestDaytonaWorkloadNetworkRejectsUnscopedTargets(t *testing.T) {
	c, _ := NewDaytonaClient("fixture-key", "")
	c.runtime = func(context.Context, map[string]any) ([]byte, error) {
		t.Fatal("invalid network made API call")
		return nil, nil
	}
	for _, network := range []string{"0.0.0.0/0", "127.0.0.1/32", "10.0.0.1/32", "::1/128", "224.0.0.1/32", ""} {
		if _, e := c.CreateDaytonaWorkload(context.Background(), t.TempDir(), "12345678-1234-1234-1234-123456789def", network); e == nil {
			t.Fatal("unscoped network accepted")
		}
	}
}

func TestDaytonaRepairWritesUseOnlyAgentPrivileges(t *testing.T) {
	b, _ := workloadDaytonaFixture(t)
	var script string
	b.client.runtime = func(_ context.Context, in map[string]any) ([]byte, error) {
		if in["op"] == "upload" {
			return json.Marshal(map[string]any{"id": b.ID(), "uploaded": true})
		}
		if in["op"] == "exec" {
			script = in["command"].(string)
			return json.Marshal(map[string]any{"id": b.ID(), "stdout": "", "exit_code": 0})
		}
		t.Fatal("unexpected operation")
		return nil, nil
	}
	if e := b.WorkloadUpload(context.Background(), "solution.py", []byte("fixed source data")); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(script, "install ") || !strings.Contains(script, daytonaDrop+"python3") || !strings.Contains(script, "os.O_NOFOLLOW") || !strings.Contains(script, "os.getuid()!=10001") {
		t.Fatal("repair crossed management privilege boundary")
	}
}

func TestDaytonaRepairNeverOverwritesReadOnlyStaging(t *testing.T) {
	b, _ := workloadDaytonaFixture(t)
	seen := map[string]bool{}
	b.client.runtime = func(_ context.Context, in map[string]any) ([]byte, error) {
		switch in["op"] {
		case "upload":
			path := in["path"].(string)
			if seen[path] {
				return nil, fmt.Errorf("nonroot manager cannot overwrite read-only staging")
			}
			if !strings.HasPrefix(path, filepath.Dir(b.ProbePath)+"/solution-s") || !strings.HasSuffix(path, ".py") {
				t.Fatal("unexpected staging path")
			}
			seen[path] = true
			return json.Marshal(map[string]any{"id": b.ID(), "uploaded": true})
		case "exec":
			if !strings.Contains(in["command"].(string), daytonaDrop+"python3") {
				t.Fatal("repair not written as the agent")
			}
			return json.Marshal(map[string]any{"id": b.ID(), "stdout": "", "exit_code": 0})
		}
		t.Fatal("unexpected operation")
		return nil, nil
	}
	for _, source := range []string{"first source", "repaired source"} {
		if e := b.WorkloadUpload(context.Background(), "solution.py", []byte(source)); e != nil {
			t.Fatal(e)
		}
	}
	if len(seen) != 2 {
		t.Fatal("repair reused staging")
	}
}

func TestNativeAllowListAcceptsOnlyUnusedNullableMode(t *testing.T) {
	b, info := workloadDaytonaFixture(t)
	for _, block := range []any{nil, false} {
		m := info()
		m["network_block_all"] = block
		raw, _ := json.Marshal(m)
		var d daytonaInfo
		json.Unmarshal(raw, &d)
		if e := b.match(d); e != nil {
			t.Fatal("unused mode rejected with exact positive allow list", e)
		}
		d.NetworkAllowList = ""
		if b.match(d) == nil {
			t.Fatal("missing allow list accepted")
		}
	}
	m := info()
	m["network_block_all"] = true
	raw, _ := json.Marshal(m)
	var d daytonaInfo
	json.Unmarshal(raw, &d)
	if b.match(d) == nil {
		t.Fatal("conflicting explicit block-all accepted")
	}
}

func TestManagerAdministrationIsSeparateFromAgent(t *testing.T) {
	for _, uid := range []int{0, 1000, 10001} {
		t.Run(fmt.Sprint(uid), func(t *testing.T) {
			b, _ := workloadDaytonaFixture(t)
			var usedAdmin bool
			b.client.runtime = func(_ context.Context, in map[string]any) ([]byte, error) {
				script := in["command"].(string)
				stdout := ""
				if strings.Contains(script, `printf '{"uid":'`) {
					raw, _ := json.Marshal(map[string]any{"uid": uid, "gid": uid, "setpriv": true, "python": true, "sudo": true})
					stdout = string(raw)
				}
				if strings.HasPrefix(script, "/usr/bin/sudo -n ") {
					usedAdmin = true
				}
				return json.Marshal(map[string]any{"id": b.ID(), "stdout": stdout, "exit_code": 0})
			}
			e := b.prepareManager(context.Background())
			if uid == 10001 {
				if e == nil || usedAdmin {
					t.Fatal("agent principal used management administrator")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			if usedAdmin != (uid != 0) {
				t.Fatal("incorrect administrator path")
			}
			if b.managerReadiness == nil || *b.managerReadiness.UID != uid {
				t.Fatal("actual manager UID not retained")
			}
		})
	}
}
