package canary

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestMaintenanceDrainsAdmissionWithoutLosingReceipts(t *testing.T) {
	c, addr := httpFixture(t, 80)
	const src, nonce = "192.0.2.10", "maintenance-marker"
	s1, _ := reserveAndArm(t, c, src, "active", 1, Want{Nonce: nonce, Proto: "tcp", Port: 80})
	s2, h2 := secret(2)
	if a := pub(t, c, src, Request{Op: "reserve", SecretSHA256: h2, TTL: 600}); !a.OK {
		t.Fatal(a.Error)
	}
	pin := c.Pin
	for i := 0; i < 2; i++ {
		a := c.Handle(Request{Op: "drain"})
		if !a.OK || a.Pin != pin || !reflect.DeepEqual(a.Maintenance, &Maintenance{Draining: true, ActiveRuns: 1, Reservations: 1}) {
			t.Fatal("drain lost outstanding work", a.Maintenance)
		}
	}
	_, h3 := secret(3)
	if a := pub(t, c, src, Request{Op: "reserve", SecretSHA256: h3, TTL: 600}); a.OK {
		t.Fatal("new reservation admitted while draining")
	}
	if a := c.Handle(Request{Op: "arm", Run: "private-new", TTL: 60, Wants: []Want{{Nonce: "private-marker", Proto: "tcp", Port: 80}}}); a.OK {
		t.Fatal("new private run admitted while draining")
	}
	if a := pub(t, c, src, Request{Op: "arm", Run: "reserved", SecretSHA256: h2, TTL: 600, Wants: []Want{{Nonce: "reserved-marker", Proto: "tcp", Port: 80}}}); !a.OK {
		t.Fatal("preexisting reservation could not arm", a.Error)
	}
	response := httpRoundTrip(t, addr, markerRequest(t, nonce))
	if err := ReadHTTPMarkerAckV1(strings.NewReader(string(response)), nonce); err != nil {
		t.Fatal(err)
	}
	a := pub(t, c, src, Request{Op: "query", Run: "active", Secret: s1})
	if !a.OK || count(a, nonce).Count != 1 || a.Pin != pin {
		t.Fatal("drain lost receipt or changed boot pin")
	}
	if m := c.Handle(Request{Op: "maintenance"}).Maintenance; m == nil || !m.Draining || m.ActiveRuns != 2 || m.Reservations != 0 {
		t.Fatal("reserved arm accounting", m)
	}
	for id, s := range map[string]string{"active": s1, "reserved": s2} {
		if a := pub(t, c, src, Request{Op: "disarm", Run: id, Secret: s}); !a.OK {
			t.Fatal("drain prevented release", a.Error)
		}
	}
	if m := c.Handle(Request{Op: "maintenance"}).Maintenance; m == nil || !reflect.DeepEqual(m, &Maintenance{Draining: true}) {
		t.Fatal("drained state did not reach zero", m)
	}
	for i := 0; i < 2; i++ {
		if m := c.Handle(Request{Op: "resume"}).Maintenance; m == nil || m.Draining {
			t.Fatal("resume failed", m)
		}
	}
	if a := pub(t, c, src, Request{Op: "reserve", SecretSHA256: h3, TTL: 60}); !a.OK {
		t.Fatal("resume did not restore admissions", a.Error)
	}
}

func TestMaintenanceExpiresOutstandingWork(t *testing.T) {
	original, fixed := now, time.Now()
	now = func() time.Time { return fixed }
	t.Cleanup(func() { now = original })
	c, err := New("sandprobe.test")
	if err != nil {
		t.Fatal(err)
	}
	_, h := secret(1)
	if a := pub(t, c, "192.0.2.1", Request{Op: "reserve", SecretSHA256: h, TTL: 10}); !a.OK {
		t.Fatal(a.Error)
	}
	if a := c.Handle(Request{Op: "arm", Run: "private", TTL: 10, Wants: []Want{{Nonce: "expiring", Proto: "tcp", Port: 80}}}); !a.OK {
		t.Fatal(a.Error)
	}
	if m := c.Handle(Request{Op: "drain"}).Maintenance; m.ActiveRuns != 1 || m.Reservations != 1 {
		t.Fatal("work not counted", m)
	}
	fixed = fixed.Add(11 * time.Second)
	if m := c.Handle(Request{Op: "maintenance"}).Maintenance; m == nil || !reflect.DeepEqual(m, &Maintenance{Draining: true}) {
		t.Fatal("expired work did not drain", m)
	}
}

func TestMaintenanceIsPrivateAndLegacyAnswersStayUnchanged(t *testing.T) {
	c, err := New("sandprobe.test")
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{"maintenance", "drain", "resume"} {
		a := pub(t, c, "192.0.2.1", Request{Op: op})
		if a.OK || a.Maintenance != nil {
			t.Fatal("public maintenance allowed", op)
		}
	}
	if m := c.Handle(Request{Op: "maintenance"}).Maintenance; m.Draining {
		t.Fatal("public call changed admission state")
	}
	c.Handle(Request{Op: "drain"})
	pub(t, c, "192.0.2.1", Request{Op: "resume"})
	for _, public := range []bool{false, true} {
		for _, op := range []string{"status", "protocols"} {
			q := Request{Op: op}
			a := c.Handle(q)
			if public {
				a = pub(t, c, "192.0.2.1", q)
			}
			wire, _ := json.Marshal(a)
			if !a.OK || a.Maintenance != nil || strings.Contains(string(wire), `"maintenance"`) {
				t.Fatal("legacy answer exposed maintenance state", public, op)
			}
		}
	}
	if !c.Handle(Request{Op: "maintenance"}).Maintenance.Draining {
		t.Fatal("public resume changed drain state")
	}
}
