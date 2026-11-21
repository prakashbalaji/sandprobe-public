//go:build linux

package probe

import (
	"encoding/json"
	"os"
	"os/exec"
	"strconv"
	"testing"
)

func TestUIDsFromStatus(t *testing.T) {
	if u, err := uidsFromStatus("Name:\tx\nUid:\t1000\t1001\t1002\t1003\nGid:\t0\t0\t0\t0\n"); err != nil || u != [4]int{1000, 1001, 1002, 1003} {
		t.Fatalf("%v %v", u, err)
	}
	for _, s := range []string{"Gid:\t0\t0\t0\t0\n", "Uid:\t1\t2\t3\n", "Uid:\t1\t2\t3\tx\n", "Uid:\t1\t2\t3\t4\t5\n", "Uid:\t-1\t2\t3\t4\n"} {
		if _, err := uidsFromStatus(s); err == nil {
			t.Errorf("%q parsed", s)
		}
	}
}

// PRV-15 as this test's own user (test/probe.sh runs it as nobody and as root).
func TestExpectUIDAndWhoAmI(t *testing.T) {
	me := os.Getuid()
	if err := ExpectUID(me); err != nil {
		t.Fatalf("its own uid was refused: %v", err)
	}
	if err := ExpectUID(me + 1); err == nil {
		t.Fatal("another uid was accepted")
	}
	w, err := WhoAmI("root")
	if err != nil || w.UIDs != [4]int{me, me, me, me} || w.NameUID == nil || *w.NameUID != 0 || w.TempDir == "" || w.TempDir[0] != '/' {
		t.Fatalf("%+v %v", w, err)
	}
	if w, _ := WhoAmI("nobody"); w.NameUID == nil || *w.NameUID != 65534 {
		t.Fatalf("nobody: %+v", w)
	}
	if w, _ := WhoAmI("4242"); w.NameUID == nil || *w.NameUID != 4242 {
		t.Fatalf("numeric: %+v", w)
	}
	if w, err := WhoAmI("no-such-user"); err != nil || w.NameUID != nil {
		t.Fatalf("unknown user: %+v %v", w, err)
	}
	if _, err := WhoAmI("bad;name"); err == nil {
		t.Fatal("a malformed name was looked up")
	}
}

// PRV-15 end to end: bound to another uid, the shipped probe writes nothing and runs no survey or check; bound to its
// own, it runs. This is the user changing between the preflight and a later invocation.
func TestBoundProbeRefusesAnotherUser(t *testing.T) {
	const bin = "/sp/sandprobe-probe" // test/probe.sh mounts the built probe here
	if _, err := os.Stat(bin); err != nil {
		t.Skip("no shipped probe at " + bin)
	}
	me := os.Getuid()
	out, err := exec.Command(bin, "-expect-uid", strconv.Itoa(me+1), "-survey").Output()
	if err == nil || len(out) != 0 {
		t.Fatalf("a probe bound to another uid ran: %q %v", out, err)
	}
	out, err = exec.Command(bin, "-expect-uid", strconv.Itoa(me), "-survey").Output()
	if err != nil || !json.Valid(out) {
		t.Fatalf("a probe bound to its own uid didn't run: %v", err)
	}
	out, err = exec.Command(bin, "-whoami", "nobody").Output()
	var w struct {
		UIDs    [4]int `json:"uids"`
		NameUID *int   `json:"name_uid"`
	}
	if err != nil || json.Unmarshal(out, &w) != nil || w.UIDs != [4]int{me, me, me, me} || w.NameUID == nil || *w.NameUID != 65534 {
		t.Fatalf("-whoami: %q %v", out, err)
	}
}
