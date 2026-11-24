// Package canarycontrol is the canary's public control path (HCN-1): status, reserve, arm, query and disarm over
// HTTPS. Port 443 is shared with the pinned-key echo and chosen by SNI, so only the control name reaches this server.
// WebPKI protects the run secret in transit; trust rests on the control key, which signs every answer over the exact
// request and answer bytes, and whose pin the host holds independently. It lives apart from package canary because
// the in-box probe imports that one and must stay free of an HTTP server.
package canarycontrol

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"sandprobe/internal/canary"
	"sandprobe/internal/strictjson"
)

// MaxBody is the most a control request may carry (HCN-1).
const MaxBody = 16 << 10

var ops = map[string]bool{"protocols": true, "status": true, "reserve": true, "arm": true, "query": true, "disarm": true}

// The headers that carry an answer's proof (HCN-1).
const (
	KeyHeader       = "Sandprobe-Control-Key" // base64 DER SubjectPublicKeyInfo of the control key
	SignatureHeader = "Sandprobe-Signature"   // base64 ASN.1 ECDSA signature over Digest(request, answer)
)

// Digest is the one transcript the control key signs (HCN-1): a label, the request's method and path, the request
// body's length and exact bytes, then the answer body's exact bytes. The request carries the host's fresh challenge,
// so no answer can be replayed for another request, and the signature travels in a header, outside what it signs.
func Digest(method, path string, req, ans []byte) []byte {
	h := sha256.New()
	fmt.Fprintf(h, "sandprobe-control-v1\n%s %s\n%d\n", method, path, len(req))
	h.Write(req)
	h.Write(ans)
	return h.Sum(nil)
}

// Handler answers POST /v1/<op> with a JSON canary.Request body, and signs each answer with key. The caller's source
// is its connection's own address, never a header.
func Handler(c *canary.Canary, key *ecdsa.PrivateKey) http.Handler {
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		panic(err)
	}
	keyB64 := base64.StdEncoding.EncodeToString(spki)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		op, ok := strings.CutPrefix(r.URL.Path, "/v1/")
		if !ok || !ops[op] {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		// A browser can send a cross-site POST without asking only with a "simple" content type, so requiring JSON (and
		// refusing anything a browser marks as cross-origin) keeps web pages from spending anonymous slots through
		// their visitors. Sandprobe's own client sends no Origin.
		if mt, _, _ := strings.Cut(r.Header.Get("Content-Type"), ";"); !strings.EqualFold(strings.TrimSpace(mt), "application/json") ||
			r.Header.Get("Origin") != "" || r.Header.Get("Sec-Fetch-Site") != "" {
			http.Error(w, "the control path takes application/json from a Sandprobe host only", http.StatusUnsupportedMediaType)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBody))
		var q canary.Request
		if err != nil || strictjson.Decode(body, MaxBody, &q) != nil { // JON-1: no duplicate, ambiguous or unknown keys
			http.Error(w, "the request didn't parse", http.StatusBadRequest)
			return
		}
		if q.Op != "" && q.Op != op {
			http.Error(w, "the body's op isn't the path's", http.StatusBadRequest)
			return
		}
		q.Op = op
		ans, err := json.Marshal(c.HandlePublic(q, canary.SourceOf(r.RemoteAddr)))
		if err != nil {
			http.Error(w, "the answer didn't encode", http.StatusInternalServerError)
			return
		}
		sig, err := ecdsa.SignASN1(rand.Reader, key, Digest(r.Method, r.URL.Path, body, ans))
		if err != nil {
			http.Error(w, "the answer couldn't be signed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set(KeyHeader, keyB64)
		w.Header().Set(SignatureHeader, base64.StdEncoding.EncodeToString(sig))
		w.Write(ans)
	})
}

// Verify checks an answer's proof: its key is one of pins (hex SHA-256 of the key's SubjectPublicKeyInfo), and its
// signature covers exactly this request (method, path and body) and this answer. Parse only answers that verified.
func Verify(pins []string, keyB64, sigB64, method, path string, req, ans []byte) error {
	spki, err := base64.StdEncoding.DecodeString(keyB64)
	sig, serr := base64.StdEncoding.DecodeString(sigB64)
	if err != nil || serr != nil || len(spki) == 0 || len(sig) == 0 {
		return errors.New("the answer carries no control key or signature")
	}
	sum := sha256.Sum256(spki)
	pinned := false
	for _, p := range pins {
		pinned = pinned || strings.EqualFold(p, hex.EncodeToString(sum[:]))
	}
	if !pinned {
		return errors.New("the answer's control key isn't a pinned one")
	}
	pub, err := x509.ParsePKIXPublicKey(spki)
	ec, ok := pub.(*ecdsa.PublicKey)
	if err != nil || !ok {
		return errors.New("the control key isn't an ECDSA key")
	}
	if !ecdsa.VerifyASN1(ec, Digest(method, path, req, ans), sig) {
		return errors.New("the answer's signature doesn't verify")
	}
	return nil
}

// PinOf is a control key's pin: hex SHA-256 of its SubjectPublicKeyInfo.
func PinOf(pub *ecdsa.PublicKey) (string, error) {
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(spki)
	return hex.EncodeToString(sum[:]), nil
}

// MakeKey writes a new control key to path, which must not exist yet, readable by its owner only, and returns its pin.
func MakeKey(path string) (string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	if err := pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	return PinOf(&key.PublicKey)
}

// LoadKey reads a control key MakeKey wrote, through one descriptor opened without following a link: a regular file
// owned by this user that no one else can read or write, at most 4 KiB (HCN-1).
func LoadKey(path string) (*ecdsa.PrivateKey, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	switch {
	case !st.Mode().IsRegular():
		return nil, fmt.Errorf("%s isn't a regular file", path)
	case st.Mode().Perm()&0o077 != 0:
		return nil, fmt.Errorf("%s is open to others", path)
	case !ok || int(sys.Uid) != os.Getuid():
		return nil, fmt.Errorf("%s isn't this user's", path)
	case st.Size() > 4096:
		return nil, fmt.Errorf("%s is too long for a control key", path)
	}
	b, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil {
		return nil, err
	}
	if len(b) > 4096 {
		return nil, fmt.Errorf("%s is too long for a control key", path)
	}
	blk, rest := pem.Decode(b)
	if blk == nil || blk.Type != "EC PRIVATE KEY" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, fmt.Errorf("%s holds no control key", path)
	}
	return x509.ParseECPrivateKey(blk.Bytes)
}

// Attach routes c's port-443 connections for name to an HTTP server for Handler, with conf supplying the WebPKI
// certificate and key signing every answer. Call it before c starts serving TLS. The server keeps no log (HCN-4)
// and no connection past its request; stop closes it.
func Attach(c *canary.Canary, name string, conf *tls.Config, key *ecdsa.PrivateKey) (stop func()) {
	ln := &handoff{conns: make(chan net.Conn), done: make(chan struct{})}
	srv := &http.Server{Handler: Handler(c, key), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second,
		WriteTimeout: 5 * time.Second, IdleTimeout: time.Second, MaxHeaderBytes: 8 << 10, ErrorLog: log.New(io.Discard, "", 0)}
	srv.SetKeepAlivesEnabled(false)
	c.ControlName, c.ControlTLS, c.Control = strings.TrimSuffix(name, "."), conf, ln.serve
	go srv.Serve(ln)
	return func() { srv.Close(); ln.Close() }
}

// handoff is a listener fed by the canary's TLS port: serve gives it one finished handshake and waits until the HTTP
// server closes that connection, so the canary's connection slot (and its caps) covers the request's whole life.
type handoff struct {
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func (l *handoff) serve(conn net.Conn) {
	t := &tracked{Conn: conn, closed: make(chan struct{})}
	select {
	case l.conns <- t:
		<-t.closed
	case <-l.done:
	}
}

func (l *handoff) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *handoff) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *handoff) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4zero, Port: 443} }

type tracked struct {
	net.Conn
	once   sync.Once
	closed chan struct{}
}

func (t *tracked) Close() error {
	err := t.Conn.Close()
	t.once.Do(func() { close(t.closed) })
	return err
}
