// sandprobe-aux is the Modal proof of concept's helper (POC-6), never shipped with sandprobe. In the sidecar, `relay`
// passes the main container's routed TLS to our canary and logs each connection; on either side, `look` checks one
// row of the visibility matrix.
package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// nonce is the shape of a check nonce the host issues (internal/host's token("c")).
var nonce = regexp.MustCompile(`^c[0-9a-f]{24}$`)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: sandprobe-aux relay|look ...")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "relay":
		err = relayMain(os.Args[2:])
	case "look":
		err = lookMain(os.Args[2:], os.Stdin, os.Stdout)
	default:
		err = errors.New("no command " + os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "sandprobe-aux:", err)
		os.Exit(1)
	}
}

func relayMain(args []string) error {
	fs := flag.NewFlagSet("relay", flag.ContinueOnError)
	listen := fs.String("listen", ":443", "where the main container's routed TLS arrives")
	suffix := fs.String("suffix", "", "the only SNI suffix relayed: canary.<our domain>")
	to := fs.String("to", "", "the canary's pinned IP:443, the only upstream")
	dir := fs.String("dir", "/tmp/sp-relay", "where the log and the ready mark go")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if h, port, err := net.SplitHostPort(*to); *suffix == "" || err != nil || net.ParseIP(h) == nil || port != "443" {
		return errors.New("relay needs -suffix, and -to as the canary's pinned IP on port 443")
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return err
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	r, err := newRelay(*dir, *suffix, *to)
	if err != nil {
		return err
	}
	return r.serve(ln)
}

// relay is POC-6's relay: an owned nonce's SNI to the canary's pinned IP, never terminating TLS; everything else
// refused. One synced JSON line on accept and one on end; no payload, and no SNI it didn't accept.
type relay struct {
	suffix, to string
	dir        string
	mu         sync.Mutex
	log        logFile
	broken     bool
	conns      atomic.Uint64
}

func newRelay(dir, suffix, to string) (*relay, error) {
	f, err := os.OpenFile(dir+"/relay.jsonl", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	return &relay{suffix: strings.ToLower(suffix), to: to, dir: dir, log: f}, nil
}

// line writes one log line and syncs it. Once a line fails, the relay is broken: it forwards nothing more, so no
// receipt can come from a connection its log doesn't hold.
func (r *relay) line(v map[string]any) error {
	v["t"] = time.Now().UTC().Format(time.RFC3339Nano)
	b, _ := json.Marshal(v)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.broken {
		return errors.New("the log failed earlier")
	}
	if _, err := r.log.Write(append(b, '\n')); err != nil {
		r.broken = true
		return err
	}
	if err := r.log.Sync(); err != nil {
		r.broken = true
		return err
	}
	return nil
}

func (r *relay) serve(ln net.Listener) error {
	if err := r.line(map[string]any{"ev": "ready", "listen": ln.Addr().String()}); err != nil {
		return fmt.Errorf("the log can't be written, so the relay never says ready: %w", err)
	}
	if err := os.WriteFile(r.dir+"/ready", []byte("ready\n"), 0o600); err != nil {
		return err
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go r.handle(c, r.conns.Add(1))
	}
}

func (r *relay) handle(c net.Conn, id uint64) {
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	hello, sni := clientHello(c)
	n, ok := r.owned(sni)
	if !ok {
		r.line(map[string]any{"ev": "refused", "conn": id, "hello_len": len(hello)}) // never the SNI itself
		return
	}
	if r.line(map[string]any{"ev": "accept", "conn": id, "nonce": n}) != nil {
		return // never forwarded: nothing reaches the canary that the log doesn't hold
	}
	up, err := net.DialTimeout("tcp", r.to, 5*time.Second)
	if err != nil {
		r.line(map[string]any{"ev": "end", "conn": id, "nonce": n, "up": 0, "down": 0, "outcome": "upstream_failed"})
		return
	}
	defer up.Close()
	c.SetReadDeadline(time.Time{})
	var sent, got int64
	if _, err := up.Write(hello); err == nil {
		sent = int64(len(hello))
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			k, _ := io.Copy(up, c)
			sent += k
			if tc, ok := up.(*net.TCPConn); ok {
				tc.CloseWrite()
			}
		}()
		got, _ = io.Copy(c, up)
		c.Close()
		wg.Wait()
	}
	outcome := "relayed"
	if sent == 0 || got == 0 {
		outcome = "no_exchange"
	}
	r.line(map[string]any{"ev": "end", "conn": id, "nonce": n, "up": sent, "down": got, "outcome": outcome})
}

// owned is a check nonce under our suffix, and nothing else.
func (r *relay) owned(sni string) (string, bool) {
	n, ok := strings.CutSuffix(strings.TrimSuffix(strings.ToLower(sni), "."), "."+r.suffix)
	return n, ok && nonce.MatchString(n)
}

// clientHello reads the ClientHello, up to 16 KiB, through crypto/tls's own parser, and returns its bytes to replay
// and its SNI. Nothing is ever written back to the client.
func clientHello(c net.Conn) ([]byte, string) {
	rec := &recorder{r: io.LimitReader(c, 16<<10)}
	var sni string
	tls.Server(rec, &tls.Config{GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		sni = h.ServerName
		return nil, errors.New("read only")
	}}).Handshake()
	return rec.buf.Bytes(), sni
}

// recorder is a read-only conn that keeps what it read.
// logFile is the relay's log: a file, or a failing writer in tests.
type logFile interface {
	Write([]byte) (int, error)
	Sync() error
}

type recorder struct {
	r   io.Reader
	buf bytes.Buffer
}

func (x *recorder) Read(p []byte) (int, error) {
	n, err := x.r.Read(p)
	x.buf.Write(p[:n])
	return n, err
}
func (x *recorder) Write(p []byte) (int, error)      { return 0, io.EOF }
func (x *recorder) Close() error                     { return nil }
func (x *recorder) LocalAddr() net.Addr              { return nil }
func (x *recorder) RemoteAddr() net.Addr             { return nil }
func (x *recorder) SetDeadline(time.Time) error      { return nil }
func (x *recorder) SetReadDeadline(time.Time) error  { return nil }
func (x *recorder) SetWriteDeadline(time.Time) error { return nil }

// look checks one row of POC-6's matrix and prints one JSON line. The marker comes on stdin, so no process of this
// side carries it in its arguments. It never opens another process's descriptors.
func lookMain(args []string, stdin io.Reader, out io.Writer) error {
	fs := flag.NewFlagSet("look", flag.ContinueOnError)
	row := fs.String("row", "", "procs, files, volume or net")
	paths := fs.String("paths", "", "files: the exact paths, comma-separated; volume: the marker file")
	addr := fs.String("connect", "", "net: host:port")
	if err := fs.Parse(args); err != nil {
		return err
	}
	m, _ := bufio.NewReader(io.LimitReader(stdin, 128)).ReadString('\n')
	m = strings.TrimSpace(m)
	if !regexp.MustCompile(`^[a-z0-9]{8,64}$`).MatchString(m) {
		return errors.New("look needs a marker on stdin")
	}
	res := map[string]any{"row": *row}
	switch *row {
	case "procs":
		seen, scanned, err := procs("/proc", m)
		res["scanned"] = scanned
		if err != nil {
			res["unknown"] = err.Error()
		} else {
			res["seen"] = seen
		}
	case "files", "volume":
		seen, err := false, error(nil)
		for p := range strings.SplitSeq(*paths, ",") {
			if p == "" {
				continue
			}
			var e error
			if *row == "volume" {
				var b []byte
				if b, e = os.ReadFile(p); e == nil && strings.TrimSpace(string(b)) == m {
					seen = true
				}
			} else if _, e = os.Lstat(p); e == nil {
				seen = true
			}
			if e != nil && !errors.Is(e, os.ErrNotExist) && err == nil {
				err = fmt.Errorf("%s couldn't be checked", p) // only a definitive absence is "not seen"
			}
		}
		if seen || err == nil {
			res["seen"] = seen
		} else {
			res["unknown"] = err.Error()
		}
	case "net":
		c, err := net.DialTimeout("tcp", *addr, 3*time.Second)
		if err != nil {
			res["seen"], res["error"] = false, "connect failed"
			break
		}
		c.SetDeadline(time.Now().Add(3 * time.Second))
		l, _ := bufio.NewReader(io.LimitReader(c, 128)).ReadString('\n')
		c.Close()
		res["seen"] = strings.TrimSpace(l) == m
	default:
		return errors.New("no row " + *row)
	}
	return json.NewEncoder(out).Encode(res)
}

// procs looks for the marker in every visible process's arguments but this one's, and counts what it scanned. A
// listing that fails, a cmdline that can't be read for any reason but the process being gone, or no other process
// scanned at all, is an error: "not seen" needs the whole scan.
func procs(root, m string) (bool, int, error) {
	ents, err := os.ReadDir(root)
	if err != nil {
		return false, 0, errors.New("the process list couldn't be read")
	}
	self := fmt.Sprint(os.Getpid())
	n := 0
	for _, e := range ents {
		if e.Name() == self || strings.Trim(e.Name(), "0123456789") != "" {
			continue
		}
		b, err := os.ReadFile(root + "/" + e.Name() + "/cmdline")
		switch {
		case errors.Is(err, os.ErrNotExist):
			continue // gone since the listing
		case err != nil:
			return false, n, fmt.Errorf("process %s's arguments couldn't be read", e.Name())
		}
		n++
		if bytes.Contains(b, []byte(m)) {
			return true, n, nil
		}
	}
	if n == 0 {
		return false, 0, errors.New("no other process was visible to scan")
	}
	return false, n, nil
}
