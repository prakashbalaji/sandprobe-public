package rundata

import (
	"os"
	"path/filepath"
	"testing"
)

// Skip only when runs/ doesn't exist; fail when it can't be read or a record is missing.
func TestDecide(t *testing.T) {
	dir := t.TempDir()
	runs := filepath.Join(dir, "runs")
	if skip, err := decide(runs, []string{filepath.Join(runs, "x.json")}); !skip || err != nil {
		t.Errorf("absent: skip %v, err %v", skip, err)
	}
	if err := os.MkdirAll(runs, 0o700); err != nil {
		t.Fatal(err)
	}
	if skip, err := decide(runs, []string{filepath.Join(runs, "x.json")}); skip || err == nil {
		t.Errorf("present without the record: skip %v, err %v", skip, err)
	}
	os.WriteFile(filepath.Join(runs, "x.json"), []byte("{}"), 0o600)
	if skip, err := decide(runs, []string{filepath.Join(runs, "x.json")}); skip || err != nil {
		t.Errorf("present and complete: skip %v, err %v", skip, err)
	}
	if os.Geteuid() == 0 {
		t.Skip("root reads through permissions, so the unreadable case can't be made here")
	}
	locked := filepath.Join(dir, "locked")
	os.Mkdir(locked, 0o700)
	t.Cleanup(func() { os.Chmod(locked, 0o700) })
	os.Chmod(locked, 0o000)
	if skip, err := decide(filepath.Join(locked, "runs"), nil); skip || err == nil {
		t.Errorf("unreadable: skip %v, err %v", skip, err)
	}
}
