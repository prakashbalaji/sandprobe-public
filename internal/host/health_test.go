package host

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"testing"

	"sandprobe/internal/canary"
)

// serveCanary runs a real canary's TLS echo (as port 443) and a plain port (as port label) on loopback.
func serveCanary(t *testing.T, label int) (*canary.Canary, canary.Key, string, string) {
	t.Helper()
	c, err := canary.New("sandprobe.test")
	if err != nil {
		t.Fatal(err)
	}
	k, err := canary.KeyOf(c.Handle(canary.Request{Op: "status"}))
	if err != nil {
		t.Fatal(err)
	}
	tl, _ := net.Listen("tcp", "127.0.0.1:0")
	pl, _ := net.Listen("tcp", "127.0.0.1:0")
	t.Cleanup(func() { tl.Close(); pl.Close() })
	go c.ServeTLS(tl, 443)
	go c.ServeTCP(pl, label)
	return c, k, tl.Addr().String(), pl.Addr().String()
}

// impostor answers every connection with reply(the line it read).
func impostor(t *testing.T, reply func(line string) string) string {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			line, _ := bufio.NewReader(conn).ReadString('\n')
			io.WriteString(conn, reply(strings.TrimSpace(line))+"\n")
			conn.Close()
		}
	}()
	return ln.Addr().String()
}

// ask sends one line to addr and returns the answer.
func ask(t *testing.T, addr, line string) string {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	io.WriteString(conn, line+"\n")
	got, _ := bufio.NewReader(conn).ReadString('\n')
	return strings.TrimSpace(got)
}

// SBX-11: health counts only when the canary with the run's key answered. Every impostor below answers the way the
// canary's health used to be checked, or replays the real canary, and none of them may count: a health success it
// could fake would let a refusal on an unreachable canary pass as "no way out".
func TestHealthIsAuthenticated(t *testing.T) {
	ctx := context.Background()
	c, k, tlsAddr, plainAddr := serveCanary(t, 80)
	if !healthConnect(ctx, tlsAddr, 443, "sandprobe.test", k) || !healthConnect(ctx, plainAddr, 80, "sandprobe.test", k) {
		t.Fatal("want the real canary's health counted on 443 and 80")
	}
	captured := ask(t, plainAddr, "health 0123456789abcdef0123456789abcdef") // a real signature, for another challenge
	_, _, otherTLS, otherPlain := serveCanary(t, 80)
	real22 := plainPort(t, c, 22) // the same canary, the same key, on another port
	for name, tc := range map[string]struct {
		addr string
		port int
		key  canary.Key
	}{
		"a bare health line":                         {impostor(t, func(string) string { return "sandprobe:health" }), 80, k},
		"a replayed signature for another challenge": {impostor(t, func(string) string { return captured }), 80, k},
		"another canary's signature":                 {otherPlain, 80, k},
		"another canary's TLS key":                   {otherTLS, 443, k},
		"the real canary's signature for port 22":    {relay(t, real22), 80, k},
		"no key at all":                              {plainAddr, 80, canary.Key{}},
		"an endless line":                            {streamer(t), 80, k},
		"a valid signature in an oversized line":     {impostor(t, func(line string) string { return ask(t, plainAddr, line) + strings.Repeat(" ", 1<<20) }), 80, k},
	} {
		if healthConnect(ctx, tc.addr, tc.port, "sandprobe.test", tc.key) {
			t.Errorf("%s: counted as health", name)
		}
	}
}

// streamer answers every connection with a health prefix and then a megabyte with no newline.
func streamer(t *testing.T) string {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			io.WriteString(conn, "sandprobe:health:"+strings.Repeat("a", 1<<20))
			conn.Close()
		}
	}()
	return ln.Addr().String()
}

// plainPort serves c's plain port, as port label, on loopback.
func plainPort(t *testing.T, c *canary.Canary, label int) string {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	t.Cleanup(func() { ln.Close() })
	go c.ServeTCP(ln, label)
	return ln.Addr().String()
}

// relay forwards each line to the canary at to and its answer back: a real signature, made for to's port.
func relay(t *testing.T, to string) string {
	return impostor(t, func(line string) string { return ask(t, to, line) })
}

func TestKeyOf(t *testing.T) {
	c, _ := canary.New("sandprobe.test")
	a := c.Handle(canary.Request{Op: "status"})
	if _, err := canary.KeyOf(a); err != nil {
		t.Fatal(err)
	}
	other, _ := canary.New("sandprobe.test")
	for name, b := range map[string]canary.Answer{
		"no key":                  {Pin: a.Pin},
		"another canary's key":    {Pin: a.Pin, Key: other.Handle(canary.Request{Op: "status"}).Key},
		"a key that isn't base64": {Pin: a.Pin, Key: "%%%"},
	} {
		if _, err := canary.KeyOf(b); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}
