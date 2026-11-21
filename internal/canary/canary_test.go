package canary

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"strings"
	"testing"
	"time"
)

// drops is what the stubbed kernel counters read; dropsErr makes them unreadable.
var (
	drops    uint64
	dropsErr error
)

func start(t *testing.T) (*Canary, string, string, string) {
	kernelDrops = func() (uint64, error) { return drops, dropsErr }
	drops, dropsErr = 0, nil
	t.Cleanup(func() { kernelDrops = readKernelDrops })
	c, err := New("sandprobe.test")
	if err != nil {
		t.Fatal(err)
	}
	tl, _ := net.Listen("tcp", "127.0.0.1:0")
	pl, _ := net.Listen("tcp", "127.0.0.1:0")
	dl, _ := net.ListenPacket("udp", "127.0.0.1:0")
	t.Cleanup(func() { tl.Close(); pl.Close(); dl.Close() })
	go c.ServeTLS(tl, 443)
	go c.ServeTCP(pl, 22)
	go c.ServeDNS(dl)
	return c, tl.Addr().String(), pl.Addr().String(), dl.LocalAddr().String()
}

func arm(t *testing.T, c *Canary, run string, wants ...Want) {
	t.Helper()
	if a := c.Handle(Request{Op: "arm", Run: run, TTL: 60, Wants: wants}); !a.OK || a.Pin != c.Pin {
		t.Fatalf("arm %s: %+v", run, a)
	}
}

func query(t *testing.T, c *Canary, run string) Answer {
	t.Helper()
	time.Sleep(50 * time.Millisecond) // let the handlers record
	return c.Handle(Request{Op: "query", Run: run})
}

// count is the answer's count for nonce.
func count(a Answer, nonce string) Count {
	for _, n := range a.Counts {
		if n.Nonce == nonce {
			return n
		}
	}
	return Count{}
}

func line(t *testing.T, addr, send string) string {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.Write([]byte(send + "\n"))
	reply, _ := bufio.NewReader(conn).ReadString('\n')
	return strings.TrimSpace(reply)
}

func TestTLSReceiptAndPin(t *testing.T) {
	c, tlsAddr, _, _ := start(t)
	arm(t, c, "r1", Want{"n-egr-2", "tcp", 443})
	var gotPin string
	conn, err := tls.Dial("tcp", tlsAddr, &tls.Config{ServerName: "n-egr-2.canary.sandprobe.test", InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error { gotPin = PinOf(cs.PeerCertificates[0]); return nil }})
	if err != nil {
		t.Fatal(err)
	}
	echo, _ := bufio.NewReader(conn).ReadString('\n')
	conn.Close()
	if gotPin != c.Pin || strings.TrimSpace(echo) != "sandprobe:n-egr-2" {
		t.Fatalf("pin %s (want %s), echo %q", gotPin, c.Pin, echo)
	}
	a := query(t, c, "r1")
	n := count(a, "n-egr-2")
	if !a.OK || a.Overloaded || a.Pin != c.Pin || n.Count != 1 || n.Elsewhere != 0 || n.FirstAt == "" ||
		!strings.HasPrefix(n.FirstFrom, "127.0.0.1:") {
		t.Fatalf("want one tcp/443 count with its first source, got %+v", a)
	}
}

func TestTLSReceiptWithoutHandshake(t *testing.T) {
	c, tlsAddr, _, _ := start(t)
	arm(t, c, "r1", Want{"n-x", "tcp", 443})
	// a client that refuses the canary's certificate still delivered its ClientHello, and so its nonce
	tls.Dial("tcp", tlsAddr, &tls.Config{ServerName: "n-x.canary.sandprobe.test"})
	if n := count(query(t, c, "r1"), "n-x"); n.Count != 1 {
		t.Fatalf("want the nonce counted at the ClientHello, got %+v", n)
	}
}

func TestTCPAndHealth(t *testing.T) {
	c, _, tcpAddr, _ := start(t)
	arm(t, c, "r1", Want{"n-egr-5-22", "tcp", 22})
	for _, n := range []string{"n-egr-5-22", "health", "Not A Nonce!"} {
		reply := line(t, tcpAddr, n)
		if n != "Not A Nonce!" && reply != "sandprobe:"+n {
			t.Errorf("%s: echo %q", n, reply)
		}
	}
	if a := query(t, c, "r1"); len(a.Counts) != 1 || count(a, "n-egr-5-22").Count != 1 {
		t.Fatalf("want only the armed nonce counted, not health or junk: %+v", a)
	}
}

// Nothing the host didn't arm is ever kept: nonce-shaped traffic from anyone leaves no state behind.
func TestUnarmedLeavesNothing(t *testing.T) {
	c, tlsAddr, tcpAddr, dnsAddr := start(t)
	line(t, tcpAddr, "n-junk")
	tls.Dial("tcp", tlsAddr, &tls.Config{ServerName: "n-junk2.canary.sandprobe.test", InsecureSkipVerify: true})
	conn, _ := net.Dial("udp", dnsAddr)
	conn.Write(DNSQuery(1, "n-junk3.dns.sandprobe.test"))
	conn.Close()
	arm(t, c, "r1", Want{"n-mine", "tcp", 22})
	line(t, tcpAddr, "n-junk4")
	time.Sleep(50 * time.Millisecond)
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.armed) != 1 || c.armed["n-mine"].Count != 0 || c.armed["n-mine"].Elsewhere != 0 {
		t.Fatalf("want only the armed nonce held, untouched: %+v", c.armed)
	}
}

// The armed nonce arriving on another port is counted apart, so it can never crowd out the attempt the grader
// matches.
func TestElsewhereCantCrowd(t *testing.T) {
	c, tlsAddr, tcpAddr, _ := start(t)
	arm(t, c, "r1", Want{"n-a", "tcp", 443})
	for i := 0; i < 10; i++ {
		line(t, tcpAddr, "n-a") // tcp/22, not the armed port
	}
	tls.Dial("tcp", tlsAddr, &tls.Config{ServerName: "n-a.canary.sandprobe.test", InsecureSkipVerify: true})
	if n := count(query(t, c, "r1"), "n-a"); n.Count != 1 || n.Elsewhere != 10 {
		t.Fatalf("want 1 on tcp/443 and 10 elsewhere, got %+v", n)
	}
}

func TestArmRefusals(t *testing.T) {
	c, _, _, _ := start(t)
	arm(t, c, "held", Want{"n-held", "tcp", 22})
	many := func(n int) []Want {
		var ws []Want
		for i := 0; i < n; i++ {
			ws = append(ws, Want{fmt.Sprintf("n-%d", i), "tcp", 22})
		}
		return ws
	}
	for name, q := range map[string]Request{
		"a malformed run":           {Run: "Bad Run", TTL: 60, Wants: many(1)},
		"a run already armed":       {Run: "held", TTL: 60, Wants: many(1)},
		"no lifetime":               {Run: "r", TTL: 0, Wants: many(1)},
		"a lifetime past an hour":   {Run: "r", TTL: 3601, Wants: many(1)},
		"no nonces":                 {Run: "r", TTL: 60},
		"too many nonces":           {Run: "r", TTL: 60, Wants: many(17)},
		"a malformed nonce":         {Run: "r", TTL: 60, Wants: []Want{{"N-Bad", "tcp", 22}}},
		"health":                    {Run: "r", TTL: 60, Wants: []Want{{"health", "tcp", 22}}},
		"a nonce twice":             {Run: "r", TTL: 60, Wants: []Want{{"n-1", "tcp", 22}, {"n-1", "tcp", 80}}},
		"a nonce another run holds": {Run: "r", TTL: 60, Wants: []Want{{"n-2", "tcp", 22}, {"n-held", "tcp", 22}}},
		"no such protocol":          {Run: "r", TTL: 60, Wants: []Want{{"n-1", "sctp", 22}}},
		"port 0":                    {Run: "r", TTL: 60, Wants: []Want{{"n-1", "tcp", 0}}},
		"port 65536":                {Run: "r", TTL: 60, Wants: []Want{{"n-1", "tcp", 65536}}},
	} {
		q.Op = "arm"
		if a := c.Handle(q); a.OK || a.Error == "" {
			t.Errorf("%s: want a refusal, got %+v", name, a)
		}
	}
	if len(c.runs) != 1 || len(c.armed) != 1 {
		t.Fatalf("a refused arm must leave nothing armed: %d runs, %d nonces", len(c.runs), len(c.armed))
	}
	for i := 1; i < maxRuns; i++ {
		arm(t, c, fmt.Sprintf("r%d", i), Want{fmt.Sprintf("n-r%d", i), "tcp", 22})
	}
	if a := c.Handle(Request{Op: "arm", Run: "one-more", TTL: 60, Wants: many(1)}); a.OK {
		t.Fatalf("want a refusal past %d armed runs, got %+v", maxRuns, a)
	}
}

// A query completes only for a run the canary still holds.
func TestQueryIncomplete(t *testing.T) {
	c, _, tcpAddr, _ := start(t)
	if a := c.Handle(Request{Op: "query", Run: "never"}); a.OK || a.Error == "" {
		t.Fatalf("an unknown run: %+v", a)
	}
	arm(t, c, "r1", Want{"n-1", "tcp", 22})
	if a := c.Handle(Request{Op: "disarm", Run: "r1"}); !a.OK {
		t.Fatalf("disarm: %+v", a)
	}
	if a := c.Handle(Request{Op: "query", Run: "r1"}); a.OK {
		t.Fatalf("a disarmed run: %+v", a)
	}
	arm(t, c, "r2", Want{"n-2", "tcp", 22})
	defer func() { now = time.Now }()
	now = func() time.Time { return time.Now().Add(61 * time.Second) }
	line(t, tcpAddr, "n-2")
	if a := query(t, c, "r2"); a.OK || len(c.armed) != 0 {
		t.Fatalf("an expired run: %+v, %d nonces still armed", a, len(c.armed))
	}
}

// An idle canary frees an expired run on its sweep, with nothing arriving.
func TestSweep(t *testing.T) {
	c, _, _, _ := start(t)
	arm(t, c, "r1", Want{"n-1", "tcp", 22})
	c.Sweep()
	if len(c.runs) != 1 {
		t.Fatal("a live run was swept")
	}
	defer func() { now = time.Now }()
	now = func() time.Time { return time.Now().Add(61 * time.Second) }
	c.Sweep()
	if len(c.runs) != 0 || len(c.armed) != 0 {
		t.Fatalf("want the expired run freed: %d runs, %d nonces", len(c.runs), len(c.armed))
	}
}

// Past a connection cap the canary closes unread, and every run armed at the time is overloaded.
func TestOverloadAtACap(t *testing.T) {
	for _, cap := range []string{"per source", "in all"} {
		t.Run(cap, func(t *testing.T) {
			defer func(o, s int) { maxOpen, maxPerSource = o, s }(maxOpen, maxPerSource)
			if cap == "per source" {
				maxPerSource = 2
			} else {
				maxOpen = 2
			}
			c, _, tcpAddr, _ := start(t)
			arm(t, c, "r1", Want{"n-1", "tcp", 22})
			var held []net.Conn
			for i := 0; i < 2; i++ {
				conn, _ := net.Dial("tcp", tcpAddr)
				held = append(held, conn)
			}
			time.Sleep(50 * time.Millisecond)
			if a := c.Handle(Request{Op: "query", Run: "r1"}); a.Overloaded {
				t.Fatalf("overloaded before any cap was hit: %+v", a)
			}
			if reply := line(t, tcpAddr, "n-1"); reply != "" {
				t.Fatalf("want the connection past the cap closed unread, got %q", reply)
			}
			for _, conn := range held {
				conn.Close()
			}
			if a := query(t, c, "r1"); !a.OK || !a.Overloaded || count(a, "n-1").Count != 0 {
				t.Fatalf("want the run overloaded and nothing counted, got %+v", a)
			}
		})
	}
}

// A rise in the kernel's drop counts, a count that can't be read at either end, or one that went backwards all
// mark the run overloaded.
func TestOverloadInTheKernel(t *testing.T) {
	c, _, _, _ := start(t)
	for name, tc := range map[string]struct {
		atArm, atQuery   uint64
		errArm, errQuery error
		want             bool
	}{
		"steady":                {5, 5, nil, nil, false},
		"a rise":                {5, 6, nil, nil, true},
		"backwards":             {5, 4, nil, nil, true},
		"unreadable when armed": {5, 5, errors.New("no /proc"), nil, true},
		"unreadable at query":   {5, 5, nil, errors.New("no /proc"), true},
	} {
		drops, dropsErr = tc.atArm, tc.errArm
		arm(t, c, "k", Want{"n-k", "tcp", 22})
		drops, dropsErr = tc.atQuery, tc.errQuery
		if a := c.Handle(Request{Op: "query", Run: "k"}); !a.OK || a.Overloaded != tc.want {
			t.Errorf("%s: want overloaded %v, got %+v", name, tc.want, a)
		}
		c.Handle(Request{Op: "disarm", Run: "k"})
	}
}

// The longest answer a query can give, with every field at its longest, stays under 8,000 characters (SBX-11).
func TestWorstCaseAnswer(t *testing.T) {
	c, _, _, _ := start(t)
	long := func(i int) string { return fmt.Sprintf("%02d", i) + strings.Repeat("a", 61) }
	var ws []Want
	for i := 0; i < maxWants; i++ {
		ws = append(ws, Want{long(i), "tcp", 65535})
	}
	run := strings.Repeat("r", 63)
	arm(t, c, run, ws...)
	for _, n := range c.runs[run].counts {
		n.Count, n.Elsewhere = math.MaxUint64, math.MaxUint64
		n.FirstAt = "2026-11-10T07:20:13.123456789Z"
		n.FirstFrom = "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff%abcdefghijklmno]:65535"
	}
	c.capHits++ // overloaded too, so every field is present
	a := c.Handle(Request{Op: "query", Run: run})
	b, _ := json.Marshal(a)
	if !a.OK || !a.Overloaded || len(a.Counts) != maxWants || len(b) >= 8000 {
		t.Fatalf("want a whole worst-case answer under 8,000 characters, got %d: ok %v", len(b), a.OK)
	}
	t.Logf("worst-case answer: %d characters", len(b))
}

func TestAnswerTooLong(t *testing.T) {
	defer func(n int) { maxAnswer = n }(maxAnswer)
	c, _, _, _ := start(t)
	arm(t, c, "r1", Want{"n-1", "tcp", 22}, Want{"n-2", "tcp", 80})
	maxAnswer = 100
	if a := c.Handle(Request{Op: "query", Run: "r1"}); a.OK || a.Counts != nil || a.Error == "" {
		t.Fatalf("want a refusal, not a long answer: %+v", a)
	}
}

// Peak healthy concurrency from one address: 8 runs' probes, one attempt each at a time, plus the host's health on
// four ports for each, all from one shared address, stay under the per-source cap.
func TestPeakFromOneAddress(t *testing.T) {
	c, _, tcpAddr, _ := start(t)
	peak := maxRuns * (1 + 4)
	if peak > maxPerSource {
		t.Fatalf("peak %d is over the per-source cap %d", peak, maxPerSource)
	}
	var held []net.Conn
	for i := 0; i < peak; i++ {
		conn, err := net.Dial("tcp", tcpAddr)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, conn)
	}
	for _, conn := range held {
		conn.Write([]byte("health\n"))
		if reply, _ := bufio.NewReader(conn).ReadString('\n'); strings.TrimSpace(reply) != "sandprobe:health" {
			t.Fatalf("want every connection served, got %q", reply)
		}
		conn.Close()
	}
	if c.capHits != 0 {
		t.Fatalf("want no cap hit at peak, got %d", c.capHits)
	}
}

func TestControl(t *testing.T) {
	c, _, tcpAddr, _ := start(t)
	ctl, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ctl.Close()
	go c.ServeControl(ctl)
	ask := func(q Request) Answer {
		a, err := Ask("tcp", ctl.Addr().String(), q)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	if a := ask(Request{Op: "status"}); !a.OK || a.Pin != c.Pin {
		t.Fatalf("status: %+v", a)
	}
	if a := ask(Request{Op: "arm", Run: "r1", TTL: 60, Wants: []Want{{"n-egr-5-22", "tcp", 22}}}); !a.OK || a.Run != "r1" {
		t.Fatalf("arm: %+v", a)
	}
	line(t, tcpAddr, "n-egr-5-22")
	time.Sleep(50 * time.Millisecond)
	if a := ask(Request{Op: "query", Run: "r1"}); !a.OK || a.Pin != c.Pin || count(a, "n-egr-5-22").Count != 1 {
		t.Fatalf("query: %+v", a)
	}
	if a := ask(Request{Op: "disarm", Run: "r1"}); !a.OK {
		t.Fatalf("disarm: %+v", a)
	}
	conn, _ := net.Dial("tcp", ctl.Addr().String())
	conn.Write([]byte(`{"op":"status","extra":1}` + "\n"))
	var a Answer
	if err := Decode(conn, &a); err != nil || a.OK || a.Error == "" {
		t.Fatalf("want a request with an unknown field refused, got %+v, %v", a, err)
	}
	conn.Close()
}

func TestDNS(t *testing.T) {
	c, _, _, dnsAddr := start(t)
	arm(t, c, "r1", Want{"n-egr-1", "dns", 53}, Want{"n-egr-5-53u", "udp", 53})
	conn, _ := net.Dial("udp", dnsAddr)
	defer conn.Close()
	for i, name := range []string{"n-egr-1.dns.sandprobe.test", "n-egr-5-53u.udp.sandprobe.test", "health.sandprobe.test", "other.example.com"} {
		q := DNSQuery(uint16(i+1), name)
		conn.Write(q)
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 512)
		n, err := conn.Read(buf)
		if err != nil || n < 12 || n > len(q) || buf[3]&0x0f != 3 || buf[0] != 0 || buf[1] != byte(i+1) {
			t.Fatalf("%s: want an NXDOMAIN reply no larger than the query, with its id, got %x %v", name, buf[:n], err)
		}
	}
	a := query(t, c, "r1")
	if count(a, "n-egr-1").Count != 1 || count(a, "n-egr-5-53u").Count != 1 {
		t.Fatalf("want a dns and a udp count, got %+v", a)
	}
}

func TestCounters(t *testing.T) {
	netstat := "TcpExt: SyncookiesSent ListenOverflows ListenDrops\nTcpExt: 1 2 3\nIpExt: InNoRoutes\nIpExt: 9\n"
	if v, err := counters(netstat, "TcpExt:", []string{"ListenOverflows", "ListenDrops"}); err != nil || v != 5 {
		t.Fatalf("want 5, got %d %v", v, err)
	}
	snmp := "Udp: InDatagrams InErrors RcvbufErrors\nUdp: 10 4 1\nUdpLite: InDatagrams InErrors RcvbufErrors\nUdpLite: 0 99 99\n"
	if v, err := counters(snmp, "Udp:", []string{"InErrors", "RcvbufErrors"}); err != nil || v != 5 {
		t.Fatalf("want Udp's 5, not UdpLite's, got %d %v", v, err)
	}
	for name, text := range map[string]string{
		"a missing field":    "TcpExt: ListenOverflows\nTcpExt: 2\n",
		"no values":          "TcpExt: ListenOverflows ListenDrops\n",
		"a short line":       "TcpExt: ListenOverflows ListenDrops\nTcpExt: 2\n",
		"not a number":       "TcpExt: ListenOverflows ListenDrops\nTcpExt: 2 x\n",
		"no counters at all": "",
	} {
		if _, err := counters(text, "TcpExt:", []string{"ListenOverflows", "ListenDrops"}); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}
