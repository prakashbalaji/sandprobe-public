//go:build linux

package probe

import (
	"io"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"

	"sandprobe/internal/catalog"
	"sandprobe/internal/obs"
)

// DKR-2: SEC-2 and SEC-5 skip PID 1 only when the host named it Sandprobe's idle process, and never the probe's own
// PID or its twins by any other rule; an entry that isn't a plain PID is no process.
func TestOtherPIDs(t *testing.T) {
	names := []string{"1", "2", "40", "41", "self", "net", "01", "+3", "0"}
	twins := map[int]bool{41: true}
	if got, skipped, _ := otherPIDs(names, 40, twins, false, 0); !slices.Equal(got, []int{1, 2}) || skipped {
		t.Errorf("no PID named: want 1 and 2 counted, got %v (skipped %v)", got, skipped)
	}
	if got, skipped, _ := otherPIDs(names, 40, twins, true, 0); !slices.Equal(got, []int{2}) || !skipped {
		t.Errorf("PID 1 named: want only 2 counted and PID 1 skipped, got %v (skipped %v)", got, skipped)
	}
	if got, skipped, _ := otherPIDs([]string{"1", "2"}, 1, nil, true, 0); !slices.Equal(got, []int{2}) || skipped {
		t.Errorf("the probe is PID 1 itself: want 2 counted and no skip claimed, got %v (skipped %v)", got, skipped)
	}
	// LNC-3: a pinned wrapper is one more skip, and PID 1 is handled as before beside it.
	if got, init, wrap := otherPIDs(names, 40, twins, true, 2); len(got) != 0 || !init || !wrap {
		t.Errorf("PID 1 named and wrapper 2 pinned: want nothing counted, got %v (%v %v)", got, init, wrap)
	}
	if got, init, wrap := otherPIDs(names, 40, twins, false, 2); !slices.Equal(got, []int{1}) || init || !wrap {
		t.Errorf("wrapper 2 pinned only: want PID 1 counted, got %v (%v %v)", got, init, wrap)
	}
	if got, init, wrap := otherPIDs(names, 40, twins, false, 1); !slices.Equal(got, []int{2}) || init || !wrap {
		t.Errorf("the wrapper is PID 1: want it skipped as the wrapper, got %v (%v %v)", got, init, wrap)
	}
}

// DKR-2's spoof: a process that copies the idle process exactly (the probe's binary, its idle argument, and an
// environment holding a secret) at any PID but 1 is still counted, though the host named PID 1. test/probe.sh runs
// this as nobody and as root.
func TestIdleSpoofCounted(t *testing.T) {
	spoof := exec.Command("/proc/self/exe")
	spoof.Args = []string{"/opt/sandprobe/sandprobe-probe", "-idle"}
	spoof.Env = append(os.Environ(), twinEnv+"=dump", "SPOOF_SECRET=sandprobe-fake")
	in, err := spoof.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := spoof.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := spoof.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { in.Close(); spoof.Process.Kill(); spoof.Wait() }()
	if _, err := io.ReadFull(out, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	pid := strconv.Itoa(spoof.Process.Pid)
	e := testEnv(t, map[string][]string{})
	e.in.OwnInit = true
	for id, file := range map[string]string{"SEC-2": "environ", "SEC-5": "mem"} {
		ck, _ := catalog.Get(id)
		o := secProc(e, ck, file)
		if o.Result != obs.Finding || o.Proof == nil || !strings.Contains(o.Evidence, "/proc/"+pid+"/"+file) {
			t.Errorf("%s: a copy of the idle process at PID %s must be counted, got %+v", id, pid, o)
			continue
		}
		for _, tg := range o.Proof.Targets {
			if strings.HasPrefix(tg.Name, "/proc/1/") {
				t.Errorf("%s: PID 1 was named Sandprobe's idle process, yet %s was tested", id, tg.Name)
			}
		}
	}
}

// DKR-4: on a read-only root the twins live under the scratch the host mounted, and its write twin answers there.
func TestTwinsInScratch(t *testing.T) {
	scratch := t.TempDir()
	tw, err := makeTwinsIn(scratch)
	if err != nil {
		t.Fatal(err)
	}
	defer tw.close()
	if !strings.HasPrefix(tw.dir, scratch+"/sandprobe-") || !tw.writeOK || !tw.readOK {
		t.Fatalf("want the twins in a private directory under %s, writable: %+v", scratch, tw)
	}
}
