package canarycontrol

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sandprobe/internal/canary"
	"sandprobe/internal/strictjson"
)

const name = "control.sandprobe.test"

// start runs a canary's TLS port with the control name attached, under a test certificate standing in for the WebPKI
// one, and returns a client that trusts only that certificate and always dials the canary's port.
var pin string // the test control key's pin, set by start

func start(t *testing.T) (*canary.Canary, *http.Client, string) {
	t.Helper()
	c, err := canary.New("sandprobe.test")
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	leaf, _ := x509.ParseCertificate(der)
	ctl, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pin, _ = PinOf(&ctl.PublicKey)
	c.PublicAddr = "198.51.100.20"
	stop := Attach(c, name, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}},
		NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12}, ctl)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close(); stop() })
	go c.ServeTLS(ln, 443)
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	addr := ln.Addr().String()
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: name},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		}}}
	return c, client, addr
}

func challenge() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// post sends one request with a fresh challenge and accepts the answer only under the pinned control key.
func post(t *testing.T, client *http.Client, op string, q canary.Request) (int, canary.Answer) {
	t.Helper()
	q.Challenge = challenge()
	code, req, ans, key, sig := raw(t, client, op, q)
	var a canary.Answer
	if code == http.StatusOK {
		if err := Verify([]string{pin}, key, sig, "POST", "/v1/"+op, req, ans); err != nil {
			t.Fatalf("%s: %v", op, err)
		}
		if err := strictjson.Decode(ans, MaxBody, &a); err != nil {
			t.Fatalf("%s: %v", op, err)
		}
	}
	return code, a
}

func raw(t *testing.T, client *http.Client, op string, q canary.Request) (int, []byte, []byte, string, string) {
	t.Helper()
	req, _ := json.Marshal(q)
	resp, err := client.Post("https://"+name+"/v1/"+op, "application/json", bytes.NewReader(req))
	if err != nil {
		t.Fatalf("%s: %v", op, err)
	}
	defer resp.Body.Close()
	ans, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, req, ans, resp.Header.Get(KeyHeader), resp.Header.Get(SignatureHeader)
}

// HCN-1: the whole public path over HTTPS, answered by the canary itself under its pin.
func TestControlOverHTTPS(t *testing.T) {
	c, client, addr := start(t)
	b := make([]byte, 32)
	rand.Read(b)
	s, sum := hex.EncodeToString(b), sha256.Sum256(b)
	h := hex.EncodeToString(sum[:])

	if code, a := post(t, client, "status", canary.Request{}); code != 200 || !a.OK || a.Pin != c.Pin || a.Addr != "198.51.100.20" || a.Domain != "sandprobe.test" {
		t.Fatalf("status: %d %+v", code, a)
	}
	if _, a := post(t, client, "reserve", canary.Request{SecretSHA256: h, TTL: 60}); !a.OK {
		t.Fatalf("reserve: %+v", a)
	}
	w := canary.Want{Nonce: "n-egr-2", Proto: "tcp", Port: 443}
	_, armed := post(t, client, "arm", canary.Request{Run: "r1", TTL: 60, Wants: []canary.Want{w}, SecretSHA256: h})
	if !armed.OK || armed.Generation == "" {
		t.Fatalf("arm: %+v", armed)
	}
	// The box's way out on the same port still gets the pinned echo, and still counts.
	conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: "n-egr-2.canary.sandprobe.test", InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	if pin := canary.PinOf(conn.ConnectionState().PeerCertificates[0]); pin != c.Pin {
		t.Fatalf("the echo's key isn't the pin")
	}
	echo, _ := bufio.NewReader(conn).ReadString('\n')
	conn.Close()
	if strings.TrimSpace(echo) != "sandprobe:n-egr-2" {
		t.Fatalf("echo %q", echo)
	}
	time.Sleep(50 * time.Millisecond)
	if _, a := post(t, client, "query", canary.Request{Run: "r1"}); a.OK {
		t.Fatal("a query without the secret was answered")
	}
	_, a := post(t, client, "query", canary.Request{Run: "r1", Secret: s})
	if !a.OK || len(a.Counts) != 1 || a.Counts[0].Count != 1 || a.Generation != armed.Generation {
		t.Fatalf("query: %+v", a)
	}
	if _, a := post(t, client, "disarm", canary.Request{Run: "r1", Secret: s}); !a.OK {
		t.Fatalf("disarm: %+v", a)
	}
}

// HCN-1: the control name never gets the pinned key, and the box's names never reach the control server.
func TestControlNameIsSeparate(t *testing.T) {
	c, _, addr := start(t)
	conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: name, InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	if canary.PinOf(conn.ConnectionState().PeerCertificates[0]) == c.Pin {
		t.Fatal("the control name got the pinned key")
	}
	conn.Close()
	conn, err = tls.Dial("tcp", addr, &tls.Config{ServerName: "n1.canary.sandprobe.test", InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	conn.Write([]byte("POST /v1/status HTTP/1.1\r\nHost: " + name + "\r\nContent-Length: 2\r\n\r\n{}"))
	reply, _ := bufio.NewReader(conn).ReadString('\n')
	conn.Close()
	if strings.HasPrefix(reply, "HTTP/") {
		t.Fatalf("a box name reached the control server: %q", reply)
	}
}

func TestControlRefusals(t *testing.T) {
	_, client, _ := start(t)
	resp, err := client.Get("https://" + name + "/v1/status")
	if err != nil || resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET: %v %v", err, resp)
	}
	resp.Body.Close()
	for _, tc := range []struct {
		path, body string
		code       int
	}{
		{"/v1/nope", `{}`, 404},
		{"/status", `{}`, 404},
		{"/v1/status", `{"op":"status","extra":1}`, 400},
		{"/v1/status", `{"op":"status","op":"status"}`, 400},
		{"/v1/status", `{"op":"status","OP":"status"}`, 400},
		{"/v1/status", `{"op":"arm"}`, 400},
		{"/v1/status", `{} {}`, 400},
		{"/v1/status", `not json`, 400},
		{"/v1/status", `{"run":"` + strings.Repeat("a", MaxBody) + `"}`, 400},
	} {
		resp, err := client.Post("https://"+name+tc.path, "application/json", strings.NewReader(tc.body))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != tc.code {
			t.Errorf("%s %.40s: %d, want %d", tc.path, tc.body, resp.StatusCode, tc.code)
		}
	}
}

// HCN-1: an answer counts only under a pinned key, for exactly the request that asked: never replayed for another
// challenge, never altered, never under another key, whatever terminated TLS on the way.
func TestAnswersAreSignedForTheirRequest(t *testing.T) {
	_, client, _ := start(t)
	q := canary.Request{Challenge: challenge()}
	code, req, ans, key, sig := raw(t, client, "status", q)
	v := func(pins []string, key, sig, path string, req, ans []byte) error {
		return Verify(pins, key, sig, "POST", path, req, ans)
	}
	if code != 200 || v([]string{pin}, key, sig, "/v1/status", req, ans) != nil {
		t.Fatalf("a genuine answer didn't verify")
	}
	q2 := q
	q2.Challenge = challenge()
	req2, _ := json.Marshal(q2)
	if v([]string{pin}, key, sig, "/v1/status", req2, ans) == nil {
		t.Fatal("an answer was replayed for another challenge")
	}
	altered := bytes.Replace(ans, []byte(`"ok":true`), []byte(`"ok":false`), 1)
	if v([]string{pin}, key, sig, "/v1/status", req, altered) == nil {
		t.Fatal("an altered answer verified")
	}
	if v([]string{pin}, key, sig, "/v1/query", req, ans) == nil {
		t.Fatal("an answer verified for another path")
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherPin, _ := PinOf(&other.PublicKey)
	if v([]string{otherPin}, key, sig, "/v1/status", req, ans) == nil {
		t.Fatal("an answer verified under a key that isn't pinned")
	}
	forged, _ := ecdsa.SignASN1(rand.Reader, other, Digest("POST", "/v1/status", req, ans))
	spki, _ := x509.MarshalPKIXPublicKey(&other.PublicKey)
	if v([]string{pin}, base64.StdEncoding.EncodeToString(spki), base64.StdEncoding.EncodeToString(forged), "/v1/status", req, ans) == nil {
		t.Fatal("a re-signed answer verified")
	}
}

func TestControlKeyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.key")
	p, err := MakeKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := MakeKey(path); err == nil {
		t.Fatal("MakeKey overwrote a key")
	}
	k, err := LoadKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := PinOf(&k.PublicKey); got != p {
		t.Fatalf("pin %s, want %s", got, p)
	}
	os.Chmod(path, 0o644)
	if _, err := LoadKey(path); err == nil {
		t.Fatal("a key others can read was loaded")
	}
}

// Over HTTPS too, a long run label never makes a signed answer longer than the bound.
func TestControlAnswerBounded(t *testing.T) {
	_, client, _ := start(t)
	code, _, ans, _, _ := raw(t, client, "query", canary.Request{Run: strings.Repeat("a", MaxBody-200), Challenge: challenge()})
	if code != 200 || len(ans) > 1000 {
		t.Fatalf("status %d, %d-byte answer", code, len(ans))
	}
}

// A web page can't spend anonymous slots through its visitors: browsers send a cross-site POST unasked only with a
// simple content type, and mark it with Origin and Sec-Fetch-Site.
func TestControlRefusesBrowserPosts(t *testing.T) {
	_, client, _ := start(t)
	body := `{"secret_sha256":"` + strings.Repeat("a", 64) + `","ttl_s":60,"challenge":"` + challenge() + `"}`
	for _, tc := range []struct{ ctype, origin, site string }{
		{"text/plain", "", ""},
		{"text/plain;charset=UTF-8", "", ""},
		{"application/x-www-form-urlencoded", "", ""},
		{"multipart/form-data; boundary=x", "", ""},
		{"", "", ""},
		{"application/json", "https://evil.example", ""},
		{"application/json", "", "cross-site"},
	} {
		req, _ := http.NewRequest(http.MethodPost, "https://"+name+"/v1/reserve", strings.NewReader(body))
		if tc.ctype != "" {
			req.Header.Set("Content-Type", tc.ctype)
		}
		if tc.origin != "" {
			req.Header.Set("Origin", tc.origin)
		}
		if tc.site != "" {
			req.Header.Set("Sec-Fetch-Site", tc.site)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnsupportedMediaType {
			t.Errorf("%+v: %d, want 415", tc, resp.StatusCode)
		}
	}
	if code, a := post(t, client, "status", canary.Request{}); code != 200 || !a.OK {
		t.Fatal("a Sandprobe host's own request was refused")
	}
}

// HCN-1: the control key is read through one descriptor that follows no link, and only from a small regular file
// this user owns and no one else can open.
func TestLoadKeyFileSafety(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "control.key")
	if _, err := MakeKey(good); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.key")
	os.Symlink(good, link)
	big := filepath.Join(dir, "big.key")
	os.WriteFile(big, append([]byte(strings.Repeat("x", 5000)), '\n'), 0o600)
	trailing := filepath.Join(dir, "trailing.key")
	b, _ := os.ReadFile(good)
	os.WriteFile(trailing, append(b, []byte("extra")...), 0o600)
	group := filepath.Join(dir, "group.key")
	os.WriteFile(group, b, 0o640)
	os.Chmod(group, 0o640)
	sub := filepath.Join(dir, "a-directory")
	os.Mkdir(sub, 0o700)
	for name, p := range map[string]string{"symlink": link, "oversize": big, "trailing bytes": trailing, "group-readable": group, "directory": sub} {
		if _, err := LoadKey(p); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
	if _, err := LoadKey(good); err != nil {
		t.Fatalf("the real key: %v", err)
	}
}
