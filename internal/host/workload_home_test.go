package host

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestWorkloadHomeCanonicalHashMatchesSharedPythonFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/workload-home.json")
	if err != nil {
		t.Fatal(err)
	}
	got, err := workloadHomeHash(raw)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(bytes.TrimSpace(raw))
	if got != hex.EncodeToString(sum[:]) {
		t.Fatal("home canonical hash changed across languages")
	}
}

func homeContextFixture() workloadHomeContext {
	h := workloadHomeContext{Schema: "sandprobe.workload-home/1", Home: WorkloadHome}
	for i, p := range []string{"/", "/opt", "/opt/sandprobe", WorkloadHome} {
		mode := uint32(0755)
		if p == WorkloadHome {
			mode = 0555
		}
		h.Nodes = append(h.Nodes, workloadHomeNode{Path: p, Device: 1, Inode: uint64(i + 1), UID: 0, Mode: mode, Directory: true})
	}
	return h
}
func TestWorkloadHomeRejectsUnsafeAncestorsAndIdentityChanges(t *testing.T) {
	h := homeContextFixture()
	raw, _ := json.Marshal(h)
	original, err := workloadHomeHash(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, which := range []string{"writable-parent", "agent-owner", "symlink", "no-search", "wrong-home", "missing-parent", "writable-home"} {
		bad := homeContextFixture()
		switch which {
		case "writable-parent":
			bad.Nodes[2].Mode = 0777
		case "agent-owner":
			bad.Nodes[2].UID = 10001
		case "symlink":
			bad.Nodes[3].Directory = false
		case "no-search":
			bad.Nodes[2].Mode = 0700
		case "wrong-home":
			bad.Home = "/workspace"
		case "missing-parent":
			bad.Nodes = bad.Nodes[1:]
		case "writable-home":
			bad.Nodes[3].Mode = 0755
		}
		raw, _ = json.Marshal(bad)
		if _, err = workloadHomeHash(raw); err == nil {
			t.Fatal("unsafe home accepted", which)
		}
	}
	h.Nodes[3].Inode++
	raw, _ = json.Marshal(h)
	changed, err := workloadHomeHash(raw)
	if err != nil || changed == original || len(changed) != 64 || strings.Contains(changed, "/") {
		t.Fatal("replacement home did not change frozen identity")
	}
}
