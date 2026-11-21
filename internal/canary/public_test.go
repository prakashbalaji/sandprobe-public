package canary

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// secret is a run's secret (hex) and its SHA-256 (hex), as the host would make them (HCN-2).
func secret(i int) (string, string) {
	b := sha256.Sum256([]byte(fmt.Sprint("secret ", i)))
	sum := sha256.Sum256(b[:])
	return hex.EncodeToString(b[:]), hex.EncodeToString(sum[:])
}

func pub(t *testing.T, c *Canary, src string, q Request) Answer {
	t.Helper()
	if q.Challenge == "" {
		q.Challenge = strings.Repeat("c", 64)
	}
	a := c.HandlePublic(q, src)
	if a.Pin != c.Pin {
		t.Fatalf("%s: the answer carries another pin", q.Op)
	}
	return a
}

// reserveAndArm runs the public path's first two steps for one run and fails the test if either is refused.
func reserveAndArm(t *testing.T, c *Canary, src, run string, i int, wants ...Want) (string, string) {
	t.Helper()
	s, h := secret(i)
	if a := pub(t, c, src, Request{Op: "reserve", SecretSHA256: h, TTL: 600}); !a.OK {
		t.Fatalf("reserve %s: %+v", run, a)
	}
	if a := pub(t, c, src, Request{Op: "arm", Run: run, TTL: 600, Wants: wants, SecretSHA256: h}); !a.OK {
		t.Fatalf("arm %s: %+v", run, a)
	}
	return s, h
}

// HCN-2: the box knows its run ID and nonces, never the secret. Nothing it can send reads, resets or re-arms its run,
// so it can't turn a receipt into a clean zero (a false pass).
func TestPublicSecretGuardsTheRun(t *testing.T) {
	c, tlsAddr, _, _ := start(t)
	w := Want{Nonce: "n1", Proto: "tcp", Port: 443}
	s, h := reserveAndArm(t, c, "203.0.113.7", "r1", 1, w)
	tls.Dial("tcp", tlsAddr, &tls.Config{ServerName: "n1.canary.sandprobe.test", InsecureSkipVerify: true}) // the box's way out

	box := "198.51.100.9" // the box, from its own address, with everything it knows
	other, otherHash := secret(2)
	for _, q := range []Request{
		{Op: "query", Run: "r1"},
		{Op: "query", Run: "r1", Secret: other},
		{Op: "query", Run: "r1", Secret: h}, // the hash isn't the secret
		{Op: "disarm", Run: "r1"},
		{Op: "disarm", Run: "r1", Secret: other},
	} {
		if a := pub(t, c, box, q); a.OK || len(a.Counts) != 0 {
			t.Fatalf("%s without the secret was answered: %+v", q.Op, a)
		}
	}
	pub(t, c, box, Request{Op: "reserve", SecretSHA256: otherHash, TTL: 60})
	if a := pub(t, c, box, Request{Op: "arm", Run: "r1", TTL: 60, Wants: []Want{w}, SecretSHA256: otherHash}); a.OK {
		t.Fatal("the box re-armed the host's run")
	}
	if a := pub(t, c, box, Request{Op: "arm", Run: "r2", TTL: 60, Wants: []Want{w}, SecretSHA256: otherHash}); a.OK {
		t.Fatal("the box armed the host's nonce in a run of its own")
	}
	time.Sleep(50 * time.Millisecond)
	a := pub(t, c, "203.0.113.7", Request{Op: "query", Run: "r1", Secret: s})
	if !a.OK || count(a, "n1").Count != 1 {
		t.Fatalf("the host lost its receipt: %+v", a)
	}
	if a := pub(t, c, "203.0.113.7", Request{Op: "disarm", Run: "r1", Secret: s}); !a.OK {
		t.Fatalf("the host couldn't disarm with its secret: %+v", a)
	}
}

// HCN-2: a run the operator armed over SSM or docker exec is out of the public path's reach.
func TestPublicCantTouchOperatorRuns(t *testing.T) {
	c, _, _, _ := start(t)
	arm(t, c, "op1", Want{Nonce: "n1", Proto: "tcp", Port: 443})
	s, _ := secret(1)
	for _, op := range []string{"query", "disarm"} {
		if a := pub(t, c, "203.0.113.7", Request{Op: op, Run: "op1", Secret: s}); a.OK {
			t.Fatalf("public %s reached an operator run", op)
		}
	}
	if a := query(t, c, "op1"); !a.OK {
		t.Fatal("the operator run is gone")
	}
}

// HCN-3: no arm without a reservation, a reservation holds its slot, and only the matching secret can use it.
func TestPublicReservation(t *testing.T) {
	c, _, _, _ := start(t)
	w := Want{Nonce: "n1", Proto: "tcp", Port: 443}
	_, h := secret(1)
	if a := pub(t, c, "203.0.113.7", Request{Op: "arm", Run: "r1", TTL: 60, Wants: []Want{w}, SecretSHA256: h}); a.OK ||
		!strings.Contains(a.Error, "reserve") {
		t.Fatalf("armed without a reservation: %+v", a)
	}
	for _, q := range []Request{
		{Op: "reserve", TTL: 60},
		{Op: "reserve", TTL: 60, SecretSHA256: "beef"},
		{Op: "reserve", TTL: maxPublicTTL + 1, SecretSHA256: h},
		{Op: "reserve", TTL: 0, SecretSHA256: h},
	} {
		if a := pub(t, c, "203.0.113.7", q); a.OK {
			t.Fatalf("a malformed reservation was held: %+v", q)
		}
	}
	if a := pub(t, c, "203.0.113.7", Request{Op: "reserve", TTL: 60, SecretSHA256: strings.ToUpper(h)}); !a.OK {
		t.Fatalf("reserve: %+v", a)
	}
	if a := pub(t, c, "203.0.113.7", Request{Op: "reserve", TTL: 60, SecretSHA256: h}); a.OK {
		t.Fatal("one secret held two slots")
	}
	if a := pub(t, c, "203.0.113.7", Request{Op: "arm", Run: "r1", TTL: 60, Wants: []Want{w}, SecretSHA256: h}); !a.OK {
		t.Fatalf("the reserved slot couldn't be armed: %+v", a)
	}

	// A reservation never armed is released by a disarm with its secret, and expires on its own.
	s2, h2 := secret(2)
	pub(t, c, "203.0.113.7", Request{Op: "reserve", TTL: 60, SecretSHA256: h2})
	if a := pub(t, c, "203.0.113.7", Request{Op: "disarm", Secret: s2}); !a.OK || len(c.held) != 0 {
		t.Fatalf("the reservation wasn't released: %+v", a)
	}
	_, h3 := secret(3)
	pub(t, c, "203.0.113.7", Request{Op: "reserve", TTL: 60, SecretSHA256: h3})
	defer func() { now = time.Now }()
	now = func() time.Time { return time.Now().Add(61 * time.Second) }
	if a := pub(t, c, "203.0.113.7", Request{Op: "arm", Run: "r3", TTL: 60, Wants: []Want{{Nonce: "n3", Proto: "tcp", Port: 443}}, SecretSHA256: h3}); a.OK {
		t.Fatal("an expired reservation was armed")
	}
}

// HCN-3: per-source bounds, counted at the reservation, so concurrent callers can't overbook.
func TestPublicBounds(t *testing.T) {
	c, _, _, _ := start(t)
	for i := 0; i < maxPublicRunsPerSource; i++ {
		_, h := secret(i)
		if a := pub(t, c, "203.0.113.7", Request{Op: "reserve", TTL: 60, SecretSHA256: h}); !a.OK {
			t.Fatalf("reservation %d: %+v", i, a)
		}
	}
	_, h := secret(99)
	if a := pub(t, c, "203.0.113.7", Request{Op: "reserve", TTL: 60, SecretSHA256: h}); a.OK {
		t.Fatalf("a source held more than %d slots", maxPublicRunsPerSource)
	}
	if a := pub(t, c, "203.0.113.8", Request{Op: "reserve", TTL: 60, SecretSHA256: h}); !a.OK {
		t.Fatalf("another source was refused: %+v", a)
	}

	// The hourly count: release each slot, then keep reserving from one source.
	c2, _, _, _ := start(t)
	for i := 0; i < maxPublicArmsPerHour; i++ {
		s, h := secret(100 + i)
		if a := pub(t, c2, "192.0.2.1", Request{Op: "reserve", TTL: 60, SecretSHA256: h}); !a.OK {
			t.Fatalf("reservation %d this hour: %+v", i, a)
		}
		pub(t, c2, "192.0.2.1", Request{Op: "disarm", Secret: s})
	}
	_, h = secret(200)
	if a := pub(t, c2, "192.0.2.1", Request{Op: "reserve", TTL: 60, SecretSHA256: h}); a.OK {
		t.Fatalf("more than %d reservations in an hour", maxPublicArmsPerHour)
	}
	defer func() { now = time.Now }()
	now = func() time.Time { return time.Now().Add(61 * time.Minute) }
	if a := pub(t, c2, "192.0.2.1", Request{Op: "reserve", TTL: 60, SecretSHA256: h}); !a.OK {
		t.Fatalf("an hour later, still refused: %+v", a)
	}
}

// HCN-3: the global bound counts runs and reservations together.
func TestPublicGlobalBound(t *testing.T) {
	c, _, _, _ := start(t)
	for i := 0; i < maxRuns; i++ {
		_, h := secret(i)
		if a := pub(t, c, fmt.Sprintf("192.0.2.%d", i+1), Request{Op: "reserve", TTL: 60, SecretSHA256: h}); !a.OK {
			t.Fatalf("reservation %d: %+v", i, a)
		}
	}
	_, h := secret(500)
	if a := pub(t, c, "198.51.100.1", Request{Op: "reserve", TTL: 60, SecretSHA256: h}); a.OK || !strings.Contains(a.Error, "busy") {
		t.Fatalf("past %d slots, want busy: %+v", maxRuns, a)
	}
}

func TestSourceOf(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.7:5000":                "203.0.113.7",
		"203.0.113.7":                     "203.0.113.7",
		"[::ffff:203.0.113.7]:443":        "203.0.113.7",
		"[2001:db8:1:2:aaaa::1]:443":      "2001:db8:1:2::/64",
		"[2001:db8:1:2:bbbb::9%eth0]:443": "2001:db8:1:2::/64",
		"not an address":                  "",
	} {
		if got := SourceOf(in); got != want {
			t.Errorf("SourceOf(%q) = %q, want %q", in, got, want)
		}
	}
}

// HCN-1: a public request without a fresh 32-byte challenge isn't answered, whatever it asks.
func TestPublicNeedsAChallenge(t *testing.T) {
	c, _, _, _ := start(t)
	_, h := secret(1)
	for _, ch := range []string{"", "abcd", strings.Repeat("z", 64)} {
		q := Request{Op: "reserve", TTL: 60, SecretSHA256: h, Challenge: ch}
		if ch == "" {
			q.Challenge = "" // pub would fill it in; call the canary directly
		}
		if a := c.HandlePublic(q, "203.0.113.7"); a.OK {
			t.Fatalf("challenge %q was accepted", ch)
		}
	}
}

// HCN-2: a run re-armed by anything that learned the secret answers with another generation, so the host never
// reads its fresh zero as the run it armed.
func TestPublicGenerationChangesOnRearm(t *testing.T) {
	c, _, _, _ := start(t)
	w := Want{Nonce: "n1", Proto: "tcp", Port: 443}
	s, h := secret(1)
	pub(t, c, "203.0.113.7", Request{Op: "reserve", SecretSHA256: h, TTL: 600})
	first := pub(t, c, "203.0.113.7", Request{Op: "arm", Run: "r1", TTL: 600, Wants: []Want{w}, SecretSHA256: h})
	if !first.OK || len(first.Generation) != 32 {
		t.Fatalf("arm: %+v", first)
	}
	if q := pub(t, c, "203.0.113.7", Request{Op: "query", Run: "r1", Secret: s}); q.Generation != first.Generation {
		t.Fatalf("a query changed the generation: %q, armed %q", q.Generation, first.Generation)
	}
	// Someone with the secret disarms, then re-arms the same run and nonce under a secret of their own.
	pub(t, c, "198.51.100.9", Request{Op: "disarm", Run: "r1", Secret: s})
	s2, h2 := secret(2)
	pub(t, c, "198.51.100.9", Request{Op: "reserve", SecretSHA256: h2, TTL: 600})
	if a := pub(t, c, "198.51.100.9", Request{Op: "arm", Run: "r1", TTL: 600, Wants: []Want{w}, SecretSHA256: h2}); !a.OK {
		t.Fatalf("re-arm: %+v", a)
	}
	if q := pub(t, c, "198.51.100.9", Request{Op: "query", Run: "r1", Secret: s2}); q.Generation == first.Generation {
		t.Fatal("a re-armed run kept its generation")
	}
}

// SBX-11 on the public path: a cap hit during a publicly armed run marks it overloaded, so it gives no negative.
func TestPublicOverloadAtACap(t *testing.T) {
	defer func(old int) { maxPerSource = old }(maxPerSource)
	maxPerSource = 1 // before the canary serves, as TestOverloadAtACap does
	c, _, tcpAddr, _ := start(t)
	s, _ := reserveAndArm(t, c, "203.0.113.7", "r1", 1, Want{Nonce: "n1", Proto: "tcp", Port: 22})
	held, err := net.Dial("tcp", tcpAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	time.Sleep(50 * time.Millisecond)
	line(t, tcpAddr, "n1") // a second connection from the same source: closed unread at the cap
	time.Sleep(50 * time.Millisecond)
	if a := pub(t, c, "203.0.113.7", Request{Op: "query", Run: "r1", Secret: s}); !a.OK || !a.Overloaded {
		t.Fatalf("want an overloaded public run, got %+v", a)
	}
}

// Every public answer stays bounded, whatever run label a caller sends, with or without a valid challenge.
func TestPublicAnswerBoundedForLongRun(t *testing.T) {
	c, _, _, _ := start(t)
	long := strings.Repeat("a", 15000)
	for _, ch := range []string{strings.Repeat("c", 64), "bad"} {
		for _, op := range []string{"status", "query", "disarm", "arm", "reserve"} {
			a := c.HandlePublic(Request{Op: op, Run: long, Challenge: ch}, "203.0.113.7")
			b, _ := json.Marshal(a)
			if a.OK || a.Run != "" || len(b) > 1000 {
				t.Fatalf("%s with a %d-byte run (challenge %q): ok=%v, %d-byte answer", op, len(long), ch, a.OK, len(b))
			}
		}
	}
}

// HCN-1: every public answer names the receipt address and domain the canary was given, so they're signed with it.
func TestPublicAnswersNameTheReceiptAddress(t *testing.T) {
	c, _, _, _ := start(t)
	c.PublicAddr = "198.51.100.20"
	for _, op := range []string{"status", "reserve", "query"} {
		if a := pub(t, c, "203.0.113.7", Request{Op: op}); a.Addr != "198.51.100.20" || a.Domain != "sandprobe.test" {
			t.Fatalf("%s names %q at %q", op, a.Addr, a.Domain)
		}
	}
	if a := c.Handle(Request{Op: "status"}); a.Addr != "" || a.Domain != "" { // the operator path is unchanged
		t.Fatalf("the operator path's answer changed: %+v", a)
	}
}
