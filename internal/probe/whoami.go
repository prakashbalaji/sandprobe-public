//go:build linux

package probe

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"sandprobe/internal/obs"
)

// UIDs are the probe's real, effective, saved-set and filesystem uids, from the kernel's Uid: line (PRV-15).
func UIDs() ([4]int, error) {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return [4]int{}, err
	}
	return uidsFromStatus(string(b))
}

func uidsFromStatus(status string) ([4]int, error) {
	var u [4]int
	for _, line := range strings.Split(status, "\n") {
		v, ok := strings.CutPrefix(line, "Uid:")
		if !ok {
			continue
		}
		f := strings.Fields(v)
		if len(f) != 4 {
			return u, errors.New("the kernel's Uid line doesn't hold four uids")
		}
		for i, s := range f {
			n, err := strconv.ParseUint(s, 10, 32)
			if err != nil {
				return u, errors.New("the kernel's Uid line doesn't hold four uids")
			}
			u[i] = int(n)
		}
		return u, nil
	}
	return u, errors.New("the kernel's status has no Uid line")
}

// ExpectUID refuses unless all four of the probe's uids are want: the host's binding, checked before the survey or any
// check runs, so a box that switched users between invocations never gets probed as someone else (PRV-15).
func ExpectUID(want int) error {
	u, err := UIDs()
	if err != nil {
		return err
	}
	for _, v := range u {
		if v != want {
			return fmt.Errorf("running as uids %d/%d/%d/%d, not %d: refused before any check (PRV-15)", u[0], u[1], u[2], u[3], want)
		}
	}
	return nil
}

var userName = regexp.MustCompile(`^([a-z_][a-z0-9_.-]{0,31}|[0-9]{1,10})$`)

// ValidUserName is what -whoami and -as accept: a plain user name, or a numeric uid.
func ValidUserName(name string) bool { return userName.MatchString(name) }

// WhoAmI is the identity-only preflight (PRV-15): who the probe runs as, the uid the box's own passwd database gives
// name, and the temporary directory. It opens nothing else and runs no check.
func WhoAmI(name string) (obs.WhoAmI, error) {
	w := obs.WhoAmI{Schema: obs.WhoAmISchema, Name: name, TempDir: "/tmp"}
	var err error
	if w.UIDs, err = UIDs(); err != nil {
		return w, err
	}
	if t := filepath.Clean(os.TempDir()); filepath.IsAbs(t) && !strings.ContainsAny(t, "'\"\\$`\n") {
		w.TempDir = t
	}
	switch {
	case name == "":
	case !ValidUserName(name):
		return w, errors.New("not a user name")
	case strings.Trim(name, "0123456789") == "":
		if n, err := strconv.ParseUint(name, 10, 32); err == nil {
			uid := int(n)
			w.NameUID = &uid
		}
	default:
		if u, err := user.Lookup(name); err == nil {
			if n, err := strconv.ParseUint(u.Uid, 10, 32); err == nil {
				uid := int(n)
				w.NameUID = &uid
			}
		}
	}
	return w, nil
}
