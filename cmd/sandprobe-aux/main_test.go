package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// a stand-in canary: TLS with a pinned key, echoing the SNI's first label.
func canary(t *testing.T) (addr string, pin [32]byte) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(1), NotAfter: time.Now().Add(time.Hour)},
		&x509.Certificate{SerialNumber: big.NewInt(1)}, &key.PublicKey, key)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				tc := c.(*tls.Conn)
				if tc.Handshake() == nil {
					n, _, _ := strings.Cut(tc.ConnectionState().ServerName, ".")
					tc.Write([]byte("sandprobe:" + n + "\n"))
				}
			}()
		}
	}()
	return ln.Addr().String(), sha256.Sum256(der)
}

func dial(addr, sni string, pin [32]byte) (string, error) {
	c, err := tls.Dial("tcp", addr, &tls.Config{ServerName: sni, InsecureSkipVerify: true,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if sha256.Sum256(raw[0]) != pin {
				return errors.New("not the pinned key")
			}
			return nil
		}})
	if err != nil {
		return "", err
	}
	defer c.Close()
	l, err := bufio.NewReader(c).ReadString('\n')
	return strings.TrimSpace(l), err
}

// POC-6: an owned nonce reaches the pinned canary through the relay, with the pin intact; everything else is refused,
// and the log holds neither a refused SNI nor any payload.
func TestRelay(t *testing.T) {
	up, pin := canary(t)
	dir := t.TempDir()
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	r, err := newRelay(dir, "canary.probe.test", up)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "ready")); err == nil {
		t.Fatal("ready before listening")
	}
	go r.serve(ln)
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(filepath.Join(dir, "ready")); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	const n = "c0123456789abcdef01234567"
	if got, err := dial(ln.Addr().String(), n+".canary.probe.test", pin); err != nil || got != "sandprobe:"+n {
		t.Fatalf("an owned nonce through the relay: %q %v", got, err)
	}
	for _, sni := range []string{"example.com", "secret-value.canary.probe.test", n + ".canary.probe.test.elsewhere.example", ""} {
		if got, err := dial(ln.Addr().String(), sni, pin); err == nil {
			t.Errorf("%q was relayed: %q", sni, got)
		}
	}
	time.Sleep(100 * time.Millisecond)
	log, _ := os.ReadFile(filepath.Join(dir, "relay.jsonl"))
	var accepts, ends, refused int
	for _, l := range strings.Split(strings.TrimSpace(string(log)), "\n") {
		var v map[string]any
		if json.Unmarshal([]byte(l), &v) != nil {
			t.Fatalf("a log line doesn't parse: %s", l)
		}
		switch v["ev"] {
		case "accept":
			accepts++
		case "end":
			ends++
			if v["outcome"] != "relayed" || v["up"].(float64) == 0 || v["down"].(float64) == 0 {
				t.Errorf("the relayed connection's end: %v", v)
			}
		case "refused":
			refused++
		}
	}
	if accepts != 1 || ends != 1 || refused != 4 {
		t.Errorf("want 1 accept, 1 end, 4 refused, got %d %d %d:\n%s", accepts, ends, refused, log)
	}
	for _, leak := range []string{"example.com", "secret-value", "elsewhere", "sandprobe:"} {
		if bytes.Contains(log, []byte(leak)) {
			t.Errorf("the log holds %q", leak)
		}
	}
}

// a log that fails on the nth write.
type failingLog struct{ left int }

func (f *failingLog) Write(p []byte) (int, error) {
	if f.left--; f.left < 0 {
		return 0, errors.New("disk full")
	}
	return len(p), nil
}
func (f *failingLog) Sync() error { return nil }

// A relay whose log fails forwards nothing more, so the canary can't hold a receipt the log doesn't.
func TestRelayLogFailure(t *testing.T) {
	up, pin := canary(t)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	r := &relay{suffix: "canary.probe.test", to: up, dir: t.TempDir(), log: &failingLog{left: 1}} // ready only
	go r.serve(ln)
	time.Sleep(50 * time.Millisecond)
	if got, err := dial(ln.Addr().String(), "c0123456789abcdef01234567.canary.probe.test", pin); err == nil {
		t.Fatalf("forwarded with its accept line unwritten: %q", got)
	}
	r2 := &relay{suffix: "canary.probe.test", to: up, dir: t.TempDir(), log: &failingLog{left: 0}}
	if err := r2.serve(ln); err == nil {
		t.Fatal("said ready with no log")
	}
	if _, err := os.Stat(filepath.Join(r2.dir, "ready")); err == nil {
		t.Fatal("wrote ready with no log")
	}
}

// POC-6: look finds a planted marker and reports its absence, from the marker on stdin.
func TestLook(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "42"), 0o755)
	os.WriteFile(filepath.Join(root, "42", "cmdline"), []byte("sh\x00-c\x00loop\x00m0123456789\x00"), 0o644)
	if seen, n, err := procs(root, "m0123456789"); !seen || n != 1 || err != nil {
		t.Fatalf("a planted process marker: %v %d %v", seen, n, err)
	}
	if seen, _, err := procs(root, "m9999999999"); seen || err != nil {
		t.Fatalf("an absent marker: %v %v", seen, err)
	}
	if _, _, err := procs(filepath.Join(root, "nowhere"), "m0123456789"); err == nil {
		t.Fatal("an unreadable process list read as not seen")
	}
	os.MkdirAll(filepath.Join(root, "43", "cmdline"), 0o755) // a cmdline that can't be read as a file
	if _, _, err := procs(root, "m9999999999"); err == nil {
		t.Fatal("an unreadable cmdline read as not seen")
	}
	if _, _, err := procs(t.TempDir(), "m0123456789"); err == nil {
		t.Fatal("an empty scan read as not seen")
	}
	locked := filepath.Join(root, "locked")
	os.MkdirAll(locked, 0o000)
	defer os.Chmod(locked, 0o755)
	out0 := &bytes.Buffer{}
	lookMain([]string{"-row", "files", "-paths", filepath.Join(locked, "x")}, strings.NewReader("m0123456789\n"), out0)
	if os.Getuid() != 0 && !strings.Contains(out0.String(), `"unknown"`) {
		t.Fatalf("a path that couldn't be checked read as not seen: %s", out0.String())
	}
	f := filepath.Join(root, "sandprobe-m0123456789")
	os.WriteFile(f, []byte("m0123456789\n"), 0o600)
	var out bytes.Buffer
	if err := lookMain([]string{"-row", "files", "-paths", f + "," + f + "-absent"}, strings.NewReader("m0123456789\n"), &out); err != nil || !strings.Contains(out.String(), `"seen":true`) {
		t.Fatalf("files: %v %s", err, out.String())
	}
	out.Reset()
	if err := lookMain([]string{"-row", "volume", "-paths", f}, strings.NewReader("m0000000000\n"), &out); err != nil || !strings.Contains(out.String(), `"seen":false`) {
		t.Fatalf("volume with another marker: %v %s", err, out.String())
	}
	if err := lookMain([]string{"-row", "procs"}, strings.NewReader(""), &out); err == nil {
		t.Fatal("look ran without a marker")
	}
}

// The relay's only upstream is the canary's pinned IP on 443.
func TestRelayUpstream(t *testing.T) {
	for _, to := range []string{"203.0.113.5:8443", "canary.probe.test:443", "203.0.113.5", ""} {
		if err := relayMain([]string{"-suffix", "canary.probe.test", "-to", to, "-listen", "127.0.0.1:0", "-dir", t.TempDir()}); err == nil {
			t.Errorf("-to %q was accepted", to)
		}
	}
}
