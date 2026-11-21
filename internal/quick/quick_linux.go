//go:build linux

// Package quick implements QCK-1: partial, metadata-only local observation.
package quick

import (
	"bytes"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"unicode/utf8"
)

const MaxOutput = 256 << 10
const MaxPaths = 32

var ErrInput = errors.New("quick mode requires at most 32 absolute paths, each at most 1024 bytes and 32 components")
var secretName = regexp.MustCompile(`(?i)(KEY|TOKEN|SECRET|PASS|CREDENTIAL|AUTH|PRIVATE|DSN|_PAT$|DATABASE_URL)`)

type Identity struct {
	UID          int    `json:"effective_uid"`
	GID          int    `json:"effective_gid"`
	Status       string `json:"proc_status"`
	CapEffective string `json:"cap_effective,omitempty"`
	NoNewPrivs   *int   `json:"no_new_privs,omitempty"`
	Seccomp      *int   `json:"seccomp,omitempty"`
}
type Path struct {
	Name   string  `json:"path"`
	Status string  `json:"status"`
	Mode   *uint32 `json:"mode,omitempty"`
	UID    *uint32 `json:"uid,omitempty"`
	GID    *uint32 `json:"gid,omitempty"`
}
type Doc struct {
	Schema               string   `json:"schema"`
	Version              string   `json:"version"`
	GoVersion            string   `json:"go_version"`
	Architecture         string   `json:"architecture"`
	SourceRevision       string   `json:"source_revision"`
	SourceModified       bool     `json:"source_modified"`
	Verification         string   `json:"verification"`
	Identity             Identity `json:"identity"`
	EnvironmentNames     []string `json:"secret_shaped_environment_names"`
	EnvironmentTruncated bool     `json:"environment_inventory_incomplete"`
	Paths                []Path   `json:"paths"`
	Limits               []string `json:"limits"`
}

func ValidatePaths(paths []string) error {
	if len(paths) > MaxPaths {
		return ErrInput
	}
	for _, p := range paths {
		if len(p) > 1024 || !filepath.IsAbs(p) || strings.ContainsRune(p, 0) || filepath.Clean(p) != p || len(strings.Split(p, "/")) > 33 {
			return ErrInput
		}
	}
	return nil
}

// Observe never creates a twin or calls the full probe. The only content read is
// this process's explicitly allowed bounded /proc/self/status identity metadata.
func Observe(paths []string, version string) (Doc, error) {
	if err := ValidatePaths(paths); err != nil {
		return Doc{}, err
	}
	d := Doc{Schema: "sandprobe.quick/1", Version: version, Verification: "partial_self_observed_unauthenticated", Identity: Identity{UID: os.Geteuid(), GID: os.Getegid(), Status: "unknown"}, EnvironmentNames: []string{}, Paths: []Path{}, Limits: []string{
		"No grade, containment pass or secret-disclosure proof; metadata only.",
		"Egress, reset persistence, sudo, other-process access and provider boundaries are untested.",
		"Permission bits do not establish effective access: ACLs, namespaces and security modules may differ.",
		"Only explicitly named paths were inspected; symlinks were not followed; omitted paths are untested.",
	}}
	d.GoVersion = runtime.Version()
	d.Architecture = runtime.GOARCH
	d.SourceRevision = "unknown"
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" {
				d.SourceRevision = setting.Value
			}
			if setting.Key == "vcs.modified" {
				d.SourceModified = setting.Value == "true"
			}
		}
	}
	if b, err := readStatus(); err == nil {
		parseStatus(b, &d.Identity)
	}

	d.EnvironmentNames, d.EnvironmentTruncated = environment(os.Environ())
	for _, p := range paths {
		d.Paths = append(d.Paths, metadata(p))
	}
	return d, nil
}

func environment(env []string) ([]string, bool) {
	out := []string{}
	truncated := false
	for i, entry := range env {
		if i >= 256 {
			truncated = true
			break
		}
		// Values are never copied to the report or inspected.
		name, _, _ := strings.Cut(entry, "=")
		if len(name) > 256 || !utf8.ValidString(name) {
			truncated = true
			continue
		}
		if secretName.MatchString(name) {
			out = append(out, name)
		}
	}
	return out, truncated
}

func parseStatus(b []byte, id *Identity) {
	caps := ""
	var nnp, sec *int
	seen := map[string]bool{}
	for _, line := range bytes.Split(b, []byte{'\n'}) {
		field, value, ok := bytes.Cut(line, []byte{':'})
		if !ok {
			continue
		}
		key := string(field)
		if key != "CapEff" && key != "NoNewPrivs" && key != "Seccomp" {
			continue
		}
		if seen[key] {
			return
		}
		seen[key] = true
		v := strings.TrimSpace(string(value))
		switch key {
		case "CapEff":
			if len(v) != 16 || strings.IndexFunc(v, func(r rune) bool { return !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F') }) >= 0 {
				return
			}
			if _, err := strconv.ParseUint(v, 16, 64); err != nil {
				return
			}
			caps = v
		case "NoNewPrivs", "Seccomp":
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 || n > 2 || (key == "NoNewPrivs" && n > 1) {
				return
			}
			if key == "NoNewPrivs" {
				nnp = &n
			} else {
				sec = &n
			}
		}
	}
	if caps == "" || nnp == nil || sec == nil {
		return
	}
	id.Status = "observed"
	id.CapEffective = caps
	id.NoNewPrivs = nnp
	id.Seccomp = sec
}

// Resolve directory components through no-follow O_PATH descriptors; a raced
// symlink cannot redirect the metadata lookup. Final targets are never opened.
func metadata(path string) Path {
	out := Path{Name: path, Status: "unknown"}
	fd, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return out
	}
	defer func() { unix.Close(fd) }()
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for _, part := range parts[:len(parts)-1] {
		next, e := unix.Openat(fd, part, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			return out
		}
		unix.Close(fd)
		fd = next
	}
	last := parts[len(parts)-1]
	if last == "" {
		last = "."
	}
	var st unix.Stat_t
	if unix.Fstatat(fd, last, &st, unix.AT_SYMLINK_NOFOLLOW) != nil {
		return out
	}
	if st.Mode&unix.S_IFMT == unix.S_IFLNK {
		out.Status = "symlink_not_followed"
		return out
	}
	mode := st.Mode
	out.Mode = &mode
	out.UID = &st.Uid
	out.GID = &st.Gid
	out.Status = "metadata_observed"
	return out
}

// Pin every proc ancestor by descriptor, using the numeric current PID rather
// than the /proc/self symlink. A substituted non-proc file is never read.
func readStatus() ([]byte, error) {
	root, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(root)
	fd, err := unix.Openat(root, "proc", unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	return readStatusAt(fd, os.Getpid(), procFS)
}
func procFS(fd int) bool {
	var st unix.Statfs_t
	return unix.Fstatfs(fd, &st) == nil && uint64(st.Type) == uint64(unix.PROC_SUPER_MAGIC)
}
func readStatusAt(proc int, pid int, verify func(int) bool) ([]byte, error) {
	if !verify(proc) {
		return nil, errors.New("proc metadata unavailable")
	}
	// A procfs from a different PID namespace may number this process differently.
	// Read only the self link metadata, never follow it or guess another PID.
	var self [32]byte
	n, err := unix.Readlinkat(proc, "self", self[:])
	if err != nil || n >= len(self) || string(self[:n]) != strconv.Itoa(pid) {
		return nil, errors.New("proc identity unavailable")
	}
	dir, err := unix.Openat(proc, strconv.Itoa(pid), unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dir)
	if !verify(dir) {
		return nil, errors.New("proc metadata unavailable")
	}
	fd, err := unix.Openat(dir, "status", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "proc-status")
	defer f.Close()
	var st unix.Stat_t
	if !verify(fd) || unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, errors.New("proc metadata unavailable")
	}
	b, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if err != nil || len(b) > 64<<10 {
		return nil, errors.New("proc metadata unavailable")
	}
	return b, nil
}
