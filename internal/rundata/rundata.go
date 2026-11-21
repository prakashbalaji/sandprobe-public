// Package rundata lets tests use the saved provider runs in runs/, which stay private (AGENTS rule 10): the public
// tree doesn't carry them. A test that needs them is skipped only when runs/ doesn't exist, saying why; if runs/ can't
// be read, or exists without a record a test needs, the test fails, never skips quietly.
package rundata

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// root is runs/, from a package two levels below the repository's root.
var root = filepath.Join("..", "..", "runs")

// decide is the one decision every caller uses: skip only when dir doesn't exist; an error when it can't be read or
// a path is missing.
func decide(dir string, paths []string) (skip bool, err error) {
	_, err = os.Stat(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return true, nil
	case err != nil:
		return false, fmt.Errorf("the run data at %s can't be read: %w", dir, err)
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			return false, fmt.Errorf("the run data is here but %s isn't: %w", p, err)
		}
	}
	return false, nil
}

// Present says whether the private run data is in this tree, failing t if it can't tell.
func Present(t testing.TB) bool {
	t.Helper()
	skip, err := decide(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	return !skip
}

// Need skips t when the run data isn't in this tree, and fails it when the data can't be read or a path is missing.
func Need(t testing.TB, paths ...string) {
	t.Helper()
	skip, err := decide(root, paths)
	if err != nil {
		t.Fatal(err)
	}
	if skip {
		t.Skip("needs the private run data in runs/, which the public tree doesn't carry")
	}
}
