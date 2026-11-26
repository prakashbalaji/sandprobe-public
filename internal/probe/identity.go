//go:build linux

package probe

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"sandprobe/internal/obs"
)

// readIdentity is SBX-4: who the probe runs as, from /proc/self/status, and the setuid scan the host grades AMP-3 from.
func readIdentity() (*obs.Identity, error) {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return nil, err
	}
	id, err := parseStatus(b)
	if err != nil {
		return nil, err
	}
	id.SetuidScan = setuidScan()
	return id, nil
}

// parseStatus reads the identity fields of /proc/self/status (SBX-4).
func parseStatus(b []byte) (*obs.Identity, error) {
	id := &obs.Identity{}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		f := strings.Fields(v)
		switch k {
		case "Uid":
			id.UID, _ = strconv.Atoi(f[1]) // the effective UID
		case "Gid":
			id.GID, _ = strconv.Atoi(f[1])
		case "CapEff":
			id.CapEff = v
		case "CapInh":
			id.CapInh = v
		case "CapPrm":
			id.CapPrm = v
		case "CapBnd":
			id.CapBnd = v
		case "CapAmb":
			id.CapAmb = v
		case "NoNewPrivs": // absent is the kernel's silence (SBX-4); present, it must be 0 or 1
			n, err := strconv.Atoi(v)
			if err != nil || (n != 0 && n != 1) {
				return nil, errors.New("/proc/self/status reports a NoNewPrivs that isn't 0 or 1")
			}
			id.NoNewPrivs = &n
		case "Seccomp":
			id.Seccomp, _ = strconv.Atoi(v)
		}
	}
	if id.CapEff == "" { // SBX-4: a kernel may leave NoNewPrivs out (GKE's gVisor does); the grader reads that as unknown
		return nil, errors.New("/proc/self/status lacks CapEff")
	}
	return id, nil
}

var systemBinDirs = []string{"/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin", "/usr/local/sbin"}

// setuidScan lists setuid-root regular files in the system binary directories. Any directory or entry it can't read
// makes the scan incomplete, so an empty list never stands in for a failed scan.
func setuidScan() *obs.SetuidScan {
	s := &obs.SetuidScan{Complete: true}
	seen := map[string]bool{}
	for _, dir := range systemBinDirs {
		real, err := filepath.EvalSymlinks(dir) // /bin is a link to usr/bin on merged-/usr systems
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			s.Complete = false
			continue
		}
		if seen[real] {
			continue
		}
		seen[real] = true
		entries, err := os.ReadDir(real)
		if err != nil {
			s.Complete = false
			continue
		}
		for _, e := range entries {
			p := filepath.Join(real, e.Name())
			var st syscall.Stat_t
			if err := syscall.Lstat(p, &st); err != nil {
				if errnoOf(err) != syscall.ENOENT {
					s.Complete = false
				}
				continue
			}
			if st.Mode&syscall.S_IFMT == syscall.S_IFREG && st.Mode&syscall.S_ISUID != 0 && st.Uid == 0 {
				if len(s.Files) == 256 {
					s.Complete = false
					return s
				}
				s.Files = append(s.Files, p)
			}
		}
	}
	return s
}

// selfDigest is the probe's own digest, which the host compares with the one it shipped (SBX-5).
func selfDigest() (string, error) {
	f, err := os.Open("/proc/self/exe")
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
