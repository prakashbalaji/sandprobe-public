//go:build linux

package probe

import "testing"

// SBX-4: GKE's gVisor leaves NoNewPrivs out of /proc/self/status; the probe reports it absent and goes on. A status
// with no CapEff still stops it.
func TestParseStatusWithoutNoNewPrivs(t *testing.T) {
	const gvisor = "Name:\tgrep\nUid:\t1000\t1000\t1000\t1000\nGid:\t0\t0\t0\t0\nCapInh:\t0000000000000000\n" +
		"CapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\nSeccomp:\t0\n"
	id, err := parseStatus([]byte(gvisor))
	if err != nil || id.NoNewPrivs != nil || id.UID != 1000 || id.CapEff != "0000000000000000" {
		t.Fatalf("%+v %v", id, err)
	}
	id, err = parseStatus([]byte(gvisor + "NoNewPrivs:\t1\n"))
	if err != nil || id.NoNewPrivs == nil || *id.NoNewPrivs != 1 {
		t.Fatalf("with NoNewPrivs: %+v %v", id, err)
	}
	if _, err := parseStatus([]byte("Uid:\t0\t0\t0\t0\n")); err == nil {
		t.Fatal("a status without CapEff was accepted")
	}
}
