//go:build unix

package analysis

import (
	"golang.org/x/sys/unix"
	"io"
	"os"
)

// ANL-1: open without following the final symlink or blocking on a FIFO;
// validate the descriptor before reading. Nonregular descriptors are rejected.
func readFile(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrInput
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > MaxReport {
		return nil, ErrInput
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxReport+1))
	if err != nil || len(b) > MaxReport {
		return nil, ErrInput
	}
	return b, nil
}
