//go:build linux

package probe

import (
	"os"
	"path/filepath"
	"testing"

	"sandprobe/internal/catalog"
	"sandprobe/internal/obs"
)

// WGR-2: run by test/probe.sh as root and nobody, with no network/credentials.
// A readable assigned file must not discard a denied target's evidence.
func TestWorkloadFindingKeepsRealFileControlsAndAllTargets(t *testing.T) {
	dir := t.TempDir()
	owned, locked := filepath.Join(dir, "owned-synthetic"), filepath.Join(dir, "denied-synthetic")
	if err := os.WriteFile(owned, []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(locked, []byte("synthetic"), 0000); err != nil {
		t.Fatal(err)
	}
	var targets []obs.Target
	for _, path := range []string{owned, locked} {
		target, _, err := readCheck(path, path)
		if err != nil {
			t.Fatal(err)
		}
		targets = append(targets, target)
	}
	twins, err := makeTwins()
	if err != nil {
		t.Fatal(err)
	}
	defer twins.close()
	ck, _ := catalog.Get("SEC-3")
	e := &env{root: os.Geteuid() == 0}
	got := e.judge(ck, targets, nil, twins.readOK, twins.readRefused, func([]obs.Target) (string, string) { return "nonempty", "synthetic target" })
	if got.Result != obs.Finding || got.Proof == nil || !got.Proof.Twin || len(got.Proof.Targets) != 2 {
		t.Fatalf("lost structured evidence: %+v", got)
	}
	if got.Proof.Targets[0].Device == 0 || got.Proof.Targets[0].Inode == 0 {
		t.Fatal("opened file identity missing")
	}
	if os.Geteuid() != 0 && (got.Proof.Targets[1].State != "refused" || !got.Proof.TwinRefused) {
		t.Fatal("denied-file control lost")
	}
}
