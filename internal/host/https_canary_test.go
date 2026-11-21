package host

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"sandprobe/internal/canary"
	"sandprobe/internal/canarycontrol"
)

const controlName = "control.sandprobe.test"

// selfSigned is a certificate for name, standing in for a WebPKI one or for an interception root's leaf.
func selfSigned(t *testing.T, name string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// clientTo is a control client that trusts roots and always dials addr: a redirected name, as far as it knows.
func clientTo(addr string, roots *x509.CertPool) *http.Client {
	return &http.Client{Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: controlName},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, addr)
			}}}
}

// publicCanary runs a real canary with the public control path on a local port, and returns it, the address of that
// port, and an HTTPSCanary that trusts its control key.
func publicCanary(t *testing.T) (*canary.Canary, string, *HTTPSCanary) {
	t.Helper()
	c, err := canary.New("sandprobe.test")
	if err != nil {
		t.Fatal(err)
	}
	cert, roots := selfSigned(t, controlName)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pin, _ := canarycontrol.PinOf(&key.PublicKey)
	c.PublicAddr = "127.0.0.1" // the receipt address this canary signs
	stop := canarycontrol.Attach(c, controlName, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}}, key)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close(); stop() })
	go c.ServeTLS(ln, 443)
	addr := ln.Addr().String()
	return c, addr, &HTTPSCanary{URL: "https://" + controlName, Pins: []string{pin}, Addr: "127.0.0.1", Dom: "sandprobe.test",
		Client: clientTo(addr, roots)}
}

// HCN-1 to HCN-3 from the host: reserve before the box, arm into the slot, read the receipt, disarm.
func TestHTTPSCanaryRun(t *testing.T) {
	_, addr, hc := publicCanary(t)
	ctx := context.Background()
	st, err := hc.Ask(ctx, canary.Request{Op: "status"})
	if err != nil || !st.OK {
		t.Fatalf("status: %v %+v", err, st)
	}
	w := canary.Want{Nonce: "n-egr-2", Proto: "tcp", Port: 443}
	if _, err := hc.Ask(ctx, canary.Request{Op: "arm", Run: "r1", TTL: 60, Wants: []canary.Want{w}}); err == nil {
		t.Fatal("armed with nothing reserved")
	}
	if err := hc.Reserve(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if a, err := hc.Ask(ctx, canary.Request{Op: "arm", Run: "r1", TTL: 60, Wants: []canary.Want{w}}); err != nil || !a.OK || a.Pin != st.Pin {
		t.Fatalf("arm: %v %+v", err, a)
	}
	conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: "n-egr-2.canary.sandprobe.test", InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	bufio.NewReader(conn).ReadString('\n')
	conn.Close()
	time.Sleep(50 * time.Millisecond)
	q, err := hc.Ask(ctx, canary.Request{Op: "query", Run: "r1"})
	if err != nil || !q.OK || q.Run != "r1" || len(q.Counts) != 1 || q.Counts[0].Count != 1 {
		t.Fatalf("query: %v %+v", err, q)
	}
	if a, err := hc.Ask(ctx, canary.Request{Op: "disarm", Run: "r1"}); err != nil || !a.OK {
		t.Fatalf("disarm: %v %+v", err, a)
	}
}

// HCN-2: a run re-armed by anything that learned the secret on the path is an error to the host, never a clean zero.
func TestHTTPSCanaryRearmedRun(t *testing.T) {
	c, _, hc := publicCanary(t)
	ctx := context.Background()
	w := canary.Want{Nonce: "n1", Proto: "tcp", Port: 443}
	if err := hc.Reserve(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := hc.Ask(ctx, canary.Request{Op: "arm", Run: "r1", TTL: 60, Wants: []canary.Want{w}}); err != nil {
		t.Fatal(err)
	}
	stolen := hc.runs["r1"].raw
	ch := strings.Repeat("ab", 32)
	c.HandlePublic(canary.Request{Op: "disarm", Run: "r1", Secret: stolen, Challenge: ch}, "198.51.100.9")
	mine := strings.Repeat("11", 32)
	c.HandlePublic(canary.Request{Op: "reserve", TTL: 60, SecretSHA256: sha(mine), Challenge: ch}, "198.51.100.9")
	if a := c.HandlePublic(canary.Request{Op: "arm", Run: "r1", TTL: 60, Wants: []canary.Want{w}, SecretSHA256: sha(mine), Challenge: ch}, "198.51.100.9"); !a.OK {
		t.Fatalf("the re-arm failed: %+v", a)
	}
	// The host still holds the old secret, so its query is refused; even with the thief's, the generation differs.
	if q, err := hc.Ask(ctx, canary.Request{Op: "query", Run: "r1"}); err == nil && q.OK {
		t.Fatal("the host read a re-armed run")
	}
	s := hc.runs["r1"]
	s.raw = mine
	hc.runs["r1"] = s
	if _, err := hc.Ask(ctx, canary.Request{Op: "query", Run: "r1"}); err == nil || !strings.Contains(err.Error(), "generation") {
		t.Fatalf("a re-armed run's generation went unnoticed: %v", err)
	}
}

func sha(hexSecret string) string {
	b, _ := hexDecode(hexSecret)
	return hexSum(b)
}

// HCN-1: an impostor behind a trusted interception root and a redirected name answers everything "ok, nothing
// arrived". The host proves none of it, so Execute stops before the probe and no network negative exists.
func TestHTTPSCanaryImpostor(t *testing.T) {
	cert, roots := selfSigned(t, controlName)
	real := func() canary.Answer {
		c, _ := canary.New("sandprobe.test")
		return c.Handle(canary.Request{Op: "status"})
	}()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a := canary.Answer{Pin: real.Pin, Key: real.Key, OK: true, Generation: strings.Repeat("0", 32)}
		json.NewEncoder(w).Encode(a)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	defer srv.Close()
	_, _, hc := publicCanary(t) // only for its pin: the impostor doesn't hold that key
	hc.Client = clientTo(srv.Listener.Addr().String(), roots)
	ctx := context.Background()
	if _, err := hc.Ask(ctx, canary.Request{Op: "status"}); err == nil || !strings.Contains(err.Error(), "isn't proven") {
		t.Fatalf("an impostor's status was believed: %v", err)
	}
	if err := hc.Reserve(ctx, 1); err == nil {
		t.Fatal("an impostor's reservation was believed")
	}
	if _, err := Execute(ctx, surveyBox{}, hc, Options{Mode: "exec"}); err == nil || !strings.Contains(err.Error(), "HCN-3") {
		t.Fatalf("Execute ran the probe against an impostor: %v", err)
	}
}

// The control client follows no redirect and refuses an answer over the bound.
func TestHTTPSCanaryRefusesRedirectAndOversize(t *testing.T) {
	cert, roots := selfSigned(t, controlName)
	for name, h := range map[string]http.HandlerFunc{
		"redirect": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://elsewhere.test/", http.StatusFound)
		},
		"oversize": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(strings.Repeat(" ", canarycontrol.MaxBody+10)))
		},
	} {
		srv := httptest.NewUnstartedServer(h)
		srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
		srv.StartTLS()
		hc := &HTTPSCanary{URL: "https://" + controlName, Pins: []string{strings.Repeat("0", 64)}, Addr: "127.0.0.1", Dom: "sandprobe.test",
			Client: clientTo(srv.Listener.Addr().String(), roots)}
		if _, err := hc.Ask(context.Background(), canary.Request{Op: "status"}); err == nil {
			t.Errorf("%s: answered", name)
		}
		srv.Close()
	}
}

func TestNewHTTPSCanaryChecks(t *testing.T) {
	pin := strings.Repeat("a", 64)
	for _, tc := range []struct {
		url  string
		pins []string
	}{
		{"http://control.sandprobe.test", []string{pin}},
		{"https://control.sandprobe.test/v1", []string{pin}},
		{"https://user@control.sandprobe.test", []string{pin}},
		{"https://control.sandprobe.test", nil},
		{"https://control.sandprobe.test", []string{pin, pin, pin}},
		{"https://control.sandprobe.test", []string{"short"}},
		{"https://localhost", []string{pin}},
	} {
		if _, err := NewHTTPSCanary(context.Background(), tc.url, tc.pins); err == nil {
			t.Errorf("%s %v: accepted", tc.url, tc.pins)
		}
	}
}

func hexDecode(s string) ([]byte, error) { return hex.DecodeString(s) }
func hexSum(b []byte) string             { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// dropper loses the first request for path: before it's sent (the canary never acted), or after (the canary acted and
// its answer was lost). Either way the host can't know which.
type dropper struct {
	base    http.RoundTripper
	path    string
	before  bool
	dropped bool
}

func (d *dropper) RoundTrip(r *http.Request) (*http.Response, error) {
	if d.before && !d.dropped && r.URL.Path == d.path {
		d.dropped = true
		return nil, errors.New("the request was lost")
	}
	resp, err := d.base.RoundTrip(r)
	if err == nil && !d.dropped && r.URL.Path == d.path {
		d.dropped = true
		resp.Body.Close()
		return nil, errors.New("the answer was lost")
	}
	return resp, err
}

// HCN-3: an answer lost after the canary reserved, armed or didn't disarm never leaves a slot held past Close.
func TestHTTPSCanaryLostAnswersRelease(t *testing.T) {
	for _, tc := range []struct {
		op     string
		before bool
	}{{"reserve", false}, {"reserve", true}, {"arm", false}, {"arm", true}, {"disarm", false}, {"disarm", true}} {
		op := tc.op
		t.Run(fmt.Sprintf("%s lost %s", op, map[bool]string{true: "before", false: "after"}[tc.before]), func(t *testing.T) {
			c, _, hc := publicCanary(t)
			tr := hc.Client.Transport
			hc.Client.Transport = &dropper{base: tr, path: "/v1/" + op, before: tc.before}
			ctx := context.Background()
			w := canary.Want{Nonce: "n1", Proto: "tcp", Port: 443}
			if err := hc.Reserve(ctx, 1); (err != nil) != (op == "reserve") {
				t.Fatalf("reserve: %v", err)
			}
			if op != "reserve" {
				_, err := hc.Ask(ctx, canary.Request{Op: "arm", Run: "r1", TTL: 60, Wants: []canary.Want{w}})
				if (err != nil) != (op == "arm") {
					t.Fatalf("arm: %v", err)
				}
			}
			if op == "disarm" {
				if _, err := hc.Ask(ctx, canary.Request{Op: "disarm", Run: "r1"}); err == nil {
					t.Fatal("the lost disarm answered")
				}
			}
			if err := hc.Close(ctx); err != nil {
				t.Fatalf("close: %v", err)
			}
			// Nothing of this host's is held: its source still gets every slot it may hold at once.
			for i := 0; i < 4; i++ {
				q := canary.Request{Op: "reserve", TTL: 60, SecretSHA256: sha(fmt.Sprintf("%064x", i+1)), Challenge: strings.Repeat("ab", 32)}
				if a := c.HandlePublic(q, "127.0.0.1"); !a.OK {
					t.Fatalf("slot %d after close: %s", i, a.Error)
				}
			}
		})
	}
}

// HCN-6 isn't built: a public canary must not pass for a receiver until its sessions reserve and carry their scope.
func TestHTTPSCanaryIsNotAReceiverYet(t *testing.T) {
	if _, ok := any(&HTTPSCanary{}).(ReceiverCanary); ok {
		t.Fatal("HTTPSCanary claims to be a ReceiverCanary")
	}
}

// failing refuses every request: the control path is unreachable for now.
type failing struct{}

func (failing) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("unreachable")
}

// A Close that couldn't release keeps what it holds, so a later Close releases it rather than reporting success.
func TestHTTPSCanaryCloseRetries(t *testing.T) {
	c, _, hc := publicCanary(t)
	ctx := context.Background()
	if err := hc.Reserve(ctx, 2); err != nil {
		t.Fatal(err)
	}
	w := canary.Want{Nonce: "n1", Proto: "tcp", Port: 443}
	if _, err := hc.Ask(ctx, canary.Request{Op: "arm", Run: "r1", TTL: 60, Wants: []canary.Want{w}}); err != nil {
		t.Fatal(err)
	}
	tr := hc.Client.Transport
	hc.Client.Transport = failing{}
	if err := hc.Close(ctx); err == nil {
		t.Fatal("an unreachable canary was reported released")
	}
	hc.Client.Transport = tr
	if err := hc.Close(ctx); err != nil {
		t.Fatalf("the retry: %v", err)
	}
	for i := 0; i < 4; i++ {
		q := canary.Request{Op: "reserve", TTL: 60, SecretSHA256: sha(fmt.Sprintf("%064x", i+1)), Challenge: strings.Repeat("ab", 32)}
		if a := c.HandlePublic(q, "127.0.0.1"); !a.OK {
			t.Fatalf("slot %d after the retry: %s", i, a.Error)
		}
	}
}

// HCN-1: the receipt address and domain come from the signed status, never from where the control connection went:
// here the control name "resolves" to a relay (the client dials the listener), and the canary signs another address.
func TestHTTPSCanaryAddressFromSignedStatus(t *testing.T) {
	c, _, hc := publicCanary(t)
	c.PublicAddr = "198.51.100.20"
	got, err := newHTTPSCanary(context.Background(), "https://"+controlName, hc.Pins, hc.Client)
	if err != nil || got.Addr != "198.51.100.20" || got.Dom != "sandprobe.test" {
		t.Fatalf("want the signed address, got %+v, %v", got, err)
	}
	// An answer that later names another address is refused, so a plan never moves to it.
	c.PublicAddr = "203.0.113.99"
	if _, err := got.Ask(context.Background(), canary.Request{Op: "status"}); err == nil {
		t.Fatal("a changed signed address was accepted")
	}
	// A canary that signs no address can't be used.
	c.PublicAddr = ""
	if _, err := newHTTPSCanary(context.Background(), "https://"+controlName, hc.Pins, hc.Client); err == nil {
		t.Fatal("a canary without a signed address was accepted")
	}
}

// Errors never repeat a URL or pin a person pasted, which could carry a credential.
func TestHTTPSCanaryErrorsRedact(t *testing.T) {
	for _, u := range []string{"https://user:hunter2@control.sandprobe.test", "https://control.sandprobe.test/?token=hunter2",
		"https://control.sandprobe.test/#hunter2", "http://hunter2.sandprobe.test"} {
		_, err := NewHTTPSCanary(context.Background(), u, []string{strings.Repeat("a", 64)})
		if err == nil || strings.Contains(err.Error(), "hunter2") {
			t.Errorf("%v", err)
		}
	}
	if _, err := NewHTTPSCanary(context.Background(), "https://control.sandprobe.test", []string{"hunter2"}); err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Errorf("%v", err)
	}
}
