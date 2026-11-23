package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestManagedAssessmentAndCleanupAreExclusive(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	first, err := lockManagedFolder(dir)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := lockManagedFolder(dir); err == nil {
		second.Close()
		first.Close()
		t.Fatal("concurrent recovery could rewrite active ledger")
	}
	first.Close()
	second, err := lockManagedFolder(dir)
	if err != nil {
		t.Fatal("closed assessment retained its lock", err)
	}
	second.Close()
}

func TestManagedLockRefusesUnsafePaths(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	target := filepath.Join(dir, "fixture")
	os.WriteFile(target, []byte("fixture"), 0600)
	lock := filepath.Join(dir, ".managed-run.lock")
	if err := os.Symlink(target, lock); err != nil {
		t.Fatal(err)
	}
	if file, err := lockManagedFolder(dir); err == nil {
		file.Close()
		t.Fatal("symlink lock accepted")
	}
	os.Remove(lock)
	os.WriteFile(lock, []byte(""), 0644)
	if file, err := lockManagedFolder(dir); err == nil {
		file.Close()
		t.Fatal("nonprivate lock accepted")
	}
}
