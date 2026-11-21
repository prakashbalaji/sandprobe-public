//go:build linux

package probe

import (
	"bufio"
	"io"
	"net"
	"net/textproto"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"sandprobe/internal/catalog"
	"sandprobe/internal/obs"
)

// proxy is a loopback CONNECT proxy that logs every connection it accepts and every CONNECT target. Its answer is
// split across writes, with an extra header, and the tunnel's first bytes can ride in the same write as its end.
type proxy struct {
	ln    net.Listener
	mu    sync.Mutex
	conns int
	dests []string
}

func startProxy(t *testing.T) *proxy {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &proxy{ln: ln}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go p.serve(c)
		}
	}()
	return p
}

func (p *proxy) serve(c net.Conn) {
	defer c.Close()
	p.mu.Lock()
	p.conns++
	p.mu.Unlock()
	tp := textproto.NewReader(bufio.NewReader(c))
	req, err := tp.ReadLine()
	if err != nil {
		return
	}
	tp.ReadMIMEHeader()
	f := strings.Fields(req)
	if len(f) < 2 || f[0] != "CONNECT" {
		return
	}
	p.mu.Lock()
	p.dests = append(p.dests, f[1])
	p.mu.Unlock()
	up, err := net.DialTimeout("tcp", f[1], 2*time.Second)
	if err != nil {
		io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer up.Close()
	io.WriteString(c, "HTTP/1.1 200 Connection established\r\n")
	time.Sleep(20 * time.Millisecond)
	io.WriteString(c, "Proxy-Agent: sandprobe-test\r\n\r\n")
	go io.Copy(up, c)
	io.Copy(c, up)
}

func (p *proxy) seen() (int, []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.conns, append([]string(nil), p.dests...)
}

func TestAgentProxy(t *testing.T) {
	for _, tc := range []struct {
		env  string
		want obs.ProxySetting
	}{
		{"proxy.internal:3128", obs.ProxySetting{Var: "HTTPS_PROXY", Scheme: "http", Addr: "proxy.internal:3128"}},
		{"http://proxy.internal", obs.ProxySetting{Var: "HTTPS_PROXY", Scheme: "http", Addr: "proxy.internal:80"}},
		{"http://user:hunter2@10.0.0.1:8080", obs.ProxySetting{Var: "HTTPS_PROXY", Scheme: "http", Addr: "10.0.0.1:8080", Credentials: true}},
		{"socks5://10.0.0.1", obs.ProxySetting{Var: "HTTPS_PROXY", Scheme: "socks5", Addr: "10.0.0.1:1080"}},
		{"http://", obs.ProxySetting{Var: "HTTPS_PROXY", Malformed: true}},
	} {
		t.Setenv("HTTPS_PROXY", tc.env)
		if got, set := agentProxy(); !set || got != tc.want {
			t.Errorf("%s: want %+v, got %+v", tc.env, tc.want, got)
		}
	}
	t.Setenv("HTTPS_PROXY", "")
	for _, k := range []string{"https_proxy", "ALL_PROXY", "all_proxy"} {
		t.Setenv(k, "")
	}
	if _, set := agentProxy(); set {
		t.Error("no proxy variable: want none")
	}
}

// The proxy's whole answer is read, however it is split, and tunnel bytes that arrive with its end aren't lost.
func TestConnectParsesWholeAnswer(t *testing.T) {
	ln, _ := net.Listen("tcp4", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		bufio.NewReader(c).ReadString('\n')
		io.WriteString(c, "HTTP/1.1 200 OK\r\n")
		time.Sleep(20 * time.Millisecond)
		io.WriteString(c, "Proxy-Agent: x\r\nVia: y\r\n\r\nfirst-tunnel-bytes\n")
	}()
	c, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	tc, err := connect(c, "203.0.113.10:443")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := bufio.NewReader(tc).ReadString('\n')
	if got != "first-tunnel-bytes\n" {
		t.Fatalf("want the tunnel's first bytes intact, got %q", got)
	}
}

// EGR-3 contacts only the proxy the plan named, a local one only with approval, never with credentials, and every
// attempt names the canary and the proxy it went through.
func TestProxyGate(t *testing.T) {
	ck, _ := catalog.Get("EGR-3")
	p := startProxy(t)
	addr := p.ln.Addr().String()
	e := testEnv(t, nil)
	ln, _ := net.Listen("tcp4", "127.0.0.1:0")
	defer ln.Close()
	e.start, e.ownPort = time.Now(), ln.Addr().(*net.TCPAddr).Port
	e.in.CanaryDomain, e.in.CanaryPin = "sandprobe.test", strings.Repeat("0", 64)
	e.in.Endpoints, e.in.CheckNonces = map[string]string{"EGR-3": "203.0.113.10:443"}, map[string]string{"EGR-3": "n-egr-3"}

	for _, tc := range []struct {
		name, env, plan string
		allow           bool
	}{
		{"a local proxy, not approved", "http://" + addr, addr, false},
		{"a proxy the plan didn't name", "http://" + addr, "proxy.internal:3128", true},
		{"no proxy planned", "http://" + addr, "", true},
		{"a proxy URL with credentials", "http://u:p@" + addr, addr, true},
		{"a proxy the client can't speak", "socks5://" + addr, addr, true},
	} {
		t.Setenv("HTTPS_PROXY", tc.env)
		e.in.Proxy, e.in.AllowLocal = tc.plan, tc.allow
		if o := egrProxy(e, ck); o.Result != obs.Unknown || len(o.Attempts) != 0 {
			t.Errorf("%s: want unknown with no attempt, got %+v", tc.name, o)
		}
		if n, _ := p.seen(); n != 0 {
			t.Fatalf("%s: the proxy was contacted", tc.name)
		}
	}

	t.Setenv("HTTPS_PROXY", "http://"+addr)
	e.in.Proxy, e.in.AllowLocal = addr, true
	o := egrProxy(e, ck)
	if o.Result != obs.Attempted || len(o.Attempts) == 0 {
		t.Fatalf("approved: want an attempt, got %+v", o)
	}
	for _, a := range o.Attempts {
		if a.Dest != "203.0.113.10:443" || a.Via != addr {
			t.Errorf("want dest the canary and via the proxy, got %+v", a)
		}
	}
	if n, dests := p.seen(); n != 1 || len(dests) != 1 || dests[0] != "203.0.113.10:443" {
		t.Fatalf("approved: want exactly one CONNECT, to the canary, got %d connections and %v", n, dests)
	}
}

// select's fd_set stops at 1024; a probe that inherits many descriptors must still wait on a connect.
func TestPollHighFD(t *testing.T) {
	var lim syscall.Rlimit
	if syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim) != nil || lim.Cur < 2100 {
		t.Skip("the descriptor limit is too low")
	}
	ln, _ := net.Listen("tcp4", "127.0.0.1:0")
	defer ln.Close()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	if err := syscall.Dup3(fd, 2048, syscall.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(2048)
	sa := &syscall.SockaddrInet4{Port: ln.Addr().(*net.TCPAddr).Port, Addr: [4]byte{127, 0, 0, 1}}
	if err := syscall.Connect(2048, sa); err != nil && err != syscall.EINPROGRESS {
		t.Fatal(err)
	}
	if !pollWritable(2048, 2*time.Second) {
		t.Fatal("want fd 2048 writable once its connect finishes")
	}
}
