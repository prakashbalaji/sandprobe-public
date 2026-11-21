// Package canary is Sandprobe's canary (SBX-11): the endpoint a box tries to reach. The host arms each run with the
// nonces it issued, each bound to the protocol and port its check uses; the canary counts only those, and answers the
// host over a control listener only it can reach, never through the box, or on a public canary (HCN) also over a path
// the box can reach, where each run is guarded by a secret only the host holds. It grades nothing.
package canary

import (
	"bufio"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Want is one armed nonce: the protocol and port its check uses.
type Want struct {
	Nonce string `json:"nonce"`
	Proto string `json:"proto"` // tcp, udp or dns
	Port  int    `json:"port"`
}

// Count is what the canary holds for one armed nonce: how often it arrived on its own protocol and port, the time
// (the canary's clock) and source address of the first such arrival, and how often it arrived anywhere else.
type Count struct {
	Want
	Count     uint64 `json:"count"`
	FirstAt   string `json:"first_at,omitempty"`
	FirstFrom string `json:"first_from,omitempty"`
	Elsewhere uint64 `json:"elsewhere"`
}

// Request is the host's question on the control channel: status, arm, query or disarm. On the public path (HCN-2) an
// arm carries the SHA-256 of a secret only the host holds, and a query or disarm carries the secret itself.
type Request struct {
	Op           string `json:"op"`
	Run          string `json:"run,omitempty"`
	TTL          int    `json:"ttl_s,omitempty"`         // arm: the run's lifetime in seconds
	Wants        []Want `json:"wants,omitempty"`         // arm: the run's nonces
	SecretSHA256 string `json:"secret_sha256,omitempty"` // public arm: hex SHA-256 of the run's secret
	Secret       string `json:"secret,omitempty"`        // public query and disarm: the run's secret, hex
	Challenge    string `json:"challenge,omitempty"`     // public: the host's fresh 32 bytes, hex, signed with the answer (HCN-1)
}

// Answer is the canary's reply, always with its pin. A query's answer is complete only when OK, under the run's pin,
// for the run asked about; Overloaded means no network negative may rest on it.
type Answer struct {
	Pin        string  `json:"pin"`
	OK         bool    `json:"ok"`
	Error      string  `json:"error,omitempty"`
	Run        string  `json:"run,omitempty"`
	Overloaded bool    `json:"overloaded,omitempty"`
	Counts     []Count `json:"counts,omitempty"`
	Key        string  `json:"key"`                  // the canary's public key (base64 DER SubjectPublicKeyInfo), whose SHA-256 is the pin
	Generation string  `json:"generation,omitempty"` // public arm and query: the run's random generation (HCN-2)
	Addr       string  `json:"addr,omitempty"`       // public: the receipt address boxes must reach, signed (HCN-1)
	Domain     string  `json:"domain,omitempty"`     // public: the canary's domain, signed (HCN-1)
}

// Key is the canary's public key, as an answer over the control channel gave it, checked against the answer's pin.
// The host verifies health with it (SBX-11).
type Key struct {
	Pin string
	Pub *ecdsa.PublicKey
}

// KeyOf reads the public key from an answer, and checks that its digest is the answer's pin.
func KeyOf(a Answer) (Key, error) {
	der, err := base64.StdEncoding.DecodeString(a.Key)
	if err != nil || len(der) == 0 {
		return Key{}, errors.New("the canary's answer carries no key")
	}
	if sum := sha256.Sum256(der); hex.EncodeToString(sum[:]) != a.Pin {
		return Key{}, errors.New("the canary's key isn't the one its pin names")
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	ec, ok := pub.(*ecdsa.PublicKey)
	if err != nil || !ok {
		return Key{}, errors.New("the canary's key isn't an ECDSA key")
	}
	return Key{Pin: a.Pin, Pub: ec}, nil
}

// HealthMessage is what the canary signs to confirm a health connect on a plain port: the port and the host's fresh
// challenge, so no answer can be replayed for another challenge or carried to another port.
func HealthMessage(port int, challenge string) []byte {
	return []byte(fmt.Sprintf("sandprobe-health\n%d\n%s", port, challenge))
}

// Verify checks a plain port's signed health answer.
func (k Key) Verify(port int, challenge, sigHex string) bool {
	sig, err := hex.DecodeString(sigHex)
	digest := sha256.Sum256(HealthMessage(port, challenge))
	return err == nil && k.Pub != nil && ecdsa.VerifyASN1(k.Pub, digest[:], sig)
}

var challengeRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

func (c *Canary) sign(port int, challenge string) ([]byte, error) {
	digest := sha256.Sum256(HealthMessage(port, challenge))
	return c.Cert.PrivateKey.(crypto.Signer).Sign(rand.Reader, digest[:], crypto.SHA256)
}

// The canary's bounds (SBX-11). A query's answer, with every field at its longest, stays under 8,000 characters.
var (
	maxRuns      = 8
	maxWants     = 16
	maxTTL       = 3600
	maxOpen      = 512
	maxPerSource = 64
	maxAnswer    = 16000
	now          = time.Now
	kernelDrops  = readKernelDrops

	// The public path's own bounds (HCN-3), per source: an IPv4 address, or an IPv6 /64.
	maxPublicTTL           = 1800
	maxPublicRunsPerSource = 4
	maxPublicArmsPerHour   = 30
	maxPublicSources       = 50000
)

// SetPublicBounds raises the shared bounds for a canary that serves the public path (HCN-3): more runs at once, and
// connection caps that fit many boxes behind one provider's NAT. Call it before the canary starts serving.
func SetPublicBounds() {
	maxRuns, maxOpen, maxPerSource = 256, 4096, 256
}

type run struct {
	counts  []*Count
	expires time.Time
	capHits uint64 // the canary's cap hits when the run was armed
	drops   uint64 // the kernel's drop counts when the run was armed
	dropsOK bool
	secret  []byte // public runs: SHA-256 of the host's secret (HCN-2)
	source  string // public runs: the source that armed it
	gen     string // public runs: drawn at random when armed, repeated in every query (HCN-2)
}

type Canary struct {
	Domain string
	Cert   tls.Certificate
	Pin    string // hex SHA-256 of the certificate's SubjectPublicKeyInfo, which the probe pins

	mu      sync.Mutex
	runs    map[string]*run
	armed   map[string]*Count // every armed nonce, across runs
	capHits uint64            // connections ever closed unread at a cap
	open    int
	perSrc  map[string]int
	arms    map[string][]time.Time  // public reservations per source in the last hour, in memory only (HCN-4)
	held    map[string]*reservation // public reservations not yet armed, by the hex SHA-256 of their secret (HCN-3)

	// The public control path (HCN-1), set before ServeTLS starts: a TLS connection whose SNI is ControlName gets
	// ControlTLS instead of the pinned key, and once its handshake completes, Control serves it and returns when done.
	ControlName string
	ControlTLS  *tls.Config
	Control     func(net.Conn)
	// PublicAddr is the receipt address every public answer names (HCN-1), so a host never plans from DNS.
	PublicAddr string
}

// New makes a canary for domain, with a fresh key and a self-signed certificate for *.canary.<domain>. The key is new
// on every start, so the pin also names this canary's lifetime: a restarted canary, which lost its armed runs, has
// another.
func New(domain string) (*Canary, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "sandprobe canary"},
		DNSNames: []string{"*.canary." + domain}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(30 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Canary{Domain: domain, Cert: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert},
		Pin: PinOf(cert), runs: map[string]*run{}, armed: map[string]*Count{}, perSrc: map[string]int{},
		arms: map[string][]time.Time{}, held: map[string]*reservation{}}, nil
}

func (c *Canary) key() string {
	return base64.StdEncoding.EncodeToString(c.Cert.Leaf.RawSubjectPublicKeyInfo)
}

// PinOf is the pin of a certificate: hex SHA-256 of its SubjectPublicKeyInfo.
func PinOf(c *x509.Certificate) string {
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

var nameRE = regexp.MustCompile(`^[a-z0-9-]{1,63}$`)

// nonceOf returns the nonce in "<nonce>.<zone>.<domain>", if name is one.
func (c *Canary) nonceOf(name, zone string) (string, bool) {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	n, ok := strings.CutSuffix(name, "."+zone+"."+c.Domain)
	if !ok || !nameRE.MatchString(n) || n == "health" {
		return "", false
	}
	return n, true
}

// Sweep forgets runs whose lifetime ran out, so an idle canary frees them too; main calls it every 30 s.
func (c *Canary) Sweep() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.purge()
	for src := range c.arms {
		c.recentArms(src)
	}
}

// purge forgets runs and reservations whose lifetime ran out. The caller holds mu.
func (c *Canary) purge() {
	t := now()
	for id, r := range c.runs {
		if !t.Before(r.expires) {
			c.drop(id, r)
		}
	}
	for h, v := range c.held {
		if !t.Before(v.expires) {
			delete(c.held, h)
		}
	}
}

// reservation is a public slot the host holds before it creates a box (HCN-3): it counts against every bound until an
// arm with the same secret uses it, it's released, or its lifetime ends.
type reservation struct {
	source  string
	expires time.Time
}

func (c *Canary) drop(id string, r *run) {
	for _, n := range r.counts {
		delete(c.armed, n.Nonce)
	}
	delete(c.runs, id)
}

// record counts an attempt carrying nonce, if the nonce is armed: on its own protocol and port, or elsewhere.
// Anything else is dropped unrecorded.
func (c *Canary) record(nonce, proto string, port int, from net.Addr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.purge()
	n, ok := c.armed[nonce]
	switch {
	case !ok:
	case n.Proto != proto || n.Port != port:
		n.Elsewhere++
	default:
		if n.Count == 0 {
			n.FirstAt, n.FirstFrom = now().UTC().Format(time.RFC3339Nano), from.String()
		}
		n.Count++
	}
}

// Handle answers one control request.
func (c *Canary) Handle(q Request) Answer {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.purge()
	a := Answer{Pin: c.Pin, Run: q.Run, Key: c.key()}
	switch q.Op {
	case "status":
		a.OK = true
	case "arm":
		if err := c.arm(q); err != nil {
			a.Error = err.Error()
		} else {
			a.OK = true
		}
	case "query":
		r, ok := c.runs[q.Run]
		if !ok {
			a.Error = "the run isn't armed: expired, disarmed or never armed"
			break
		}
		c.fill(r, &a)
	case "disarm":
		if r, ok := c.runs[q.Run]; ok {
			c.drop(q.Run, r)
			a.OK = true
		} else {
			a.Error = "the run isn't armed"
		}
	default:
		a.Error = "unknown op"
	}
	return c.bounded(a, q.Run)
}

// fill puts a run's counts in a query's answer. The caller holds mu.
func (c *Canary) fill(r *run, a *Answer) {
	drops, err := kernelDrops()
	a.OK = true
	a.Overloaded = c.capHits != r.capHits || !r.dropsOK || err != nil || drops != r.drops
	for _, n := range r.counts {
		a.Counts = append(a.Counts, *n)
	}
}

func (c *Canary) bounded(a Answer, run string) Answer {
	if b, err := json.Marshal(a); err != nil || len(b) > maxAnswer {
		return Answer{Pin: c.Pin, Run: run, Error: "the answer is too long", Key: c.key()}
	}
	return a
}

// HandlePublic answers one request from the public control path (HCN-1, HCN-2). src is SourceOf the caller's
// address. A public arm must carry its secret's SHA-256; a query or disarm must carry the secret, and reaches only a
// run armed publicly with it, so a box that knows its run ID and nonces can neither read nor reset its run. Runs armed
// on the operator's path are out of its reach.
func (c *Canary) HandlePublic(q Request, src string) Answer {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.purge()
	a := Answer{Pin: c.Pin, Key: c.key(), Addr: c.PublicAddr, Domain: c.Domain}
	if q.Run != "" && !nameRE.MatchString(q.Run) { // never echo a caller's long label: every answer stays bounded
		a.Error = "a malformed run"
		return a
	}
	a.Run = q.Run
	if b, err := hex.DecodeString(q.Challenge); err != nil || len(b) != 32 {
		a.Error = "a public request needs a fresh 32-byte challenge"
		return a
	}
	switch q.Op {
	case "status":
		a.OK = true
	case "reserve":
		if err := c.reserve(q, src); err != nil {
			a.Error = err.Error()
		} else {
			a.OK = true
		}
	case "arm":
		if err := c.armPublic(q); err != nil {
			a.Error = err.Error()
		} else {
			a.OK, a.Generation = true, c.runs[q.Run].gen
		}
	case "query", "disarm":
		r, ok := c.runs[q.Run]
		if !ok || !r.owns(q.Secret) {
			if h, held := c.heldBy(q.Secret); q.Op == "disarm" && held { // a run never armed releases its slot
				delete(c.held, h)
				a.OK = true
				break
			}
			a.Error = "the run isn't armed, or the secret doesn't match"
			break
		}
		if q.Op == "query" {
			c.fill(r, &a)
			a.Generation = r.gen
		} else {
			c.drop(q.Run, r)
			a.OK = true
		}
	default:
		a.Error = "unknown op"
	}
	return c.bounded(a, q.Run)
}

// owns reports whether secret (hex) is the one this run was armed with publicly.
func (r *run) owns(secret string) bool {
	b, err := hex.DecodeString(secret)
	if err != nil || len(b) != 32 || len(r.secret) != sha256.Size {
		return false
	}
	sum := sha256.Sum256(b)
	return subtle.ConstantTimeCompare(sum[:], r.secret) == 1
}

// reserve holds a public slot for a run the host is about to create a box for (HCN-3). The caller holds mu.
func (c *Canary) reserve(q Request, src string) error {
	hash, err := hex.DecodeString(q.SecretSHA256)
	switch {
	case err != nil || len(hash) != sha256.Size:
		return errors.New("a public run needs the SHA-256 of its secret")
	case q.TTL < 1 || q.TTL > maxPublicTTL:
		return fmt.Errorf("a lifetime outside 1 to %d s", maxPublicTTL)
	case src == "":
		return errors.New("an unknown source")
	case c.held[hex.EncodeToString(hash)] != nil:
		return errors.New("that secret already holds a slot")
	}
	for _, r := range c.runs {
		if subtle.ConstantTimeCompare(r.secret, hash) == 1 {
			return errors.New("that secret already holds a slot")
		}
	}
	live := 0
	for _, r := range c.runs {
		if r.source == src {
			live++
		}
	}
	for _, v := range c.held {
		if v.source == src {
			live++
		}
	}
	recent := c.recentArms(src)
	switch {
	case len(c.runs)+len(c.held) >= maxRuns:
		return errors.New("the canary is busy: try again later, or use your own")
	case live >= maxPublicRunsPerSource:
		return fmt.Errorf("at most %d runs at once from one source", maxPublicRunsPerSource)
	case len(recent) >= maxPublicArmsPerHour:
		return fmt.Errorf("at most %d runs an hour from one source", maxPublicArmsPerHour)
	case len(recent) == 0 && len(c.arms) >= maxPublicSources:
		return errors.New("the canary is busy: try again later, or use your own")
	}
	c.held[hex.EncodeToString(hash)] = &reservation{source: src, expires: now().Add(time.Duration(q.TTL) * time.Second)}
	c.arms[src] = append(recent, now())
	return nil
}

// armPublic arms a run in the slot its secret reserved, as the operator's path arms, and ends no later than the
// reservation would have. The caller holds mu.
func (c *Canary) armPublic(q Request) error {
	hash, err := hex.DecodeString(q.SecretSHA256)
	key := hex.EncodeToString(hash)
	v := c.held[key]
	switch {
	case err != nil || len(hash) != sha256.Size:
		return errors.New("a public run needs the SHA-256 of its secret")
	case v == nil:
		return errors.New("no slot is reserved for that secret: reserve one before creating the box")
	case q.TTL < 1 || q.TTL > maxPublicTTL:
		return fmt.Errorf("a lifetime outside 1 to %d s", maxPublicTTL)
	}
	var g [16]byte
	if _, err := rand.Read(g[:]); err != nil { // HCN-2: no generation, no run
		return errors.New("the canary couldn't draw a generation")
	}
	delete(c.held, key) // the run takes the slot, so the global bound in arm counts it once
	if err := c.arm(q); err != nil {
		c.held[key] = v
		return err
	}
	r := c.runs[q.Run]
	r.secret, r.source, r.gen = hash, v.source, hex.EncodeToString(g[:])
	if v.expires.Before(r.expires) {
		r.expires = v.expires
	}
	return nil
}

// heldBy finds the reservation secret (hex) holds, if any. The caller holds mu.
func (c *Canary) heldBy(secret string) (string, bool) {
	b, err := hex.DecodeString(secret)
	if err != nil || len(b) != 32 {
		return "", false
	}
	sum := sha256.Sum256(b)
	h := hex.EncodeToString(sum[:])
	_, ok := c.held[h]
	return h, ok
}

// recentArms is src's public arms in the last hour; it forgets older ones. The caller holds mu.
func (c *Canary) recentArms(src string) []time.Time {
	cutoff := now().Add(-time.Hour)
	ts := c.arms[src]
	i := 0
	for i < len(ts) && !ts[i].After(cutoff) {
		i++
	}
	if ts = ts[i:]; len(ts) == 0 {
		delete(c.arms, src)
		return nil
	}
	c.arms[src] = ts
	return ts
}

// SourceOf is the source a public bound counts against: the address of addr ("host:port" or a bare address), as an
// IPv4 address or an IPv6 /64, since one IPv6 host may hold a whole /64.
func SourceOf(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return ""
	}
	if ip = ip.Unmap(); ip.Is4() {
		return ip.String()
	}
	p, _ := ip.WithZone("").Prefix(64)
	return p.String()
}

// arm checks and holds a run. The caller holds mu.
func (c *Canary) arm(q Request) error {
	switch {
	case !nameRE.MatchString(q.Run):
		return errors.New("a malformed run")
	case c.runs[q.Run] != nil:
		return errors.New("the run is already armed")
	case len(c.runs) >= maxRuns:
		return errors.New("too many armed runs")
	case q.TTL < 1 || q.TTL > maxTTL:
		return fmt.Errorf("a lifetime outside 1 to %d s", maxTTL)
	case len(q.Wants) == 0 || len(q.Wants) > maxWants:
		return fmt.Errorf("a run arms 1 to %d nonces", maxWants)
	}
	seen := map[string]bool{}
	for _, w := range q.Wants {
		switch {
		case !nameRE.MatchString(w.Nonce) || w.Nonce == "health":
			return fmt.Errorf("a malformed nonce %q", w.Nonce)
		case seen[w.Nonce] || c.armed[w.Nonce] != nil:
			return fmt.Errorf("nonce %s is already armed", w.Nonce)
		case w.Proto != "tcp" && w.Proto != "udp" && w.Proto != "dns", w.Port < 1 || w.Port > 65535:
			return fmt.Errorf("nonce %s: no such protocol and port", w.Nonce)
		}
		seen[w.Nonce] = true
	}
	drops, err := kernelDrops()
	r := &run{expires: now().Add(time.Duration(q.TTL) * time.Second), capHits: c.capHits, drops: drops, dropsOK: err == nil}
	for _, w := range q.Wants {
		n := &Count{Want: w}
		r.counts = append(r.counts, n)
		c.armed[w.Nonce] = n
	}
	c.runs[q.Run] = r
	return nil
}

// admit takes a connection slot for conn's source, or closes conn unread and counts the cap hit, which marks every
// armed run overloaded.
func (c *Canary) admit(conn net.Conn) (release func(), ok bool) {
	src, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.open >= maxOpen || c.perSrc[src] >= maxPerSource {
		c.capHits++
		conn.Close()
		return nil, false
	}
	c.open++
	c.perSrc[src]++
	return func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.open--
		if c.perSrc[src]--; c.perSrc[src] == 0 {
			delete(c.perSrc, src)
		}
	}, true
}

// serve accepts connections on ln and handles each admitted one.
func (c *Canary) serve(ln net.Listener, handle func(net.Conn)) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		release, ok := c.admit(conn)
		if !ok {
			continue
		}
		go func() {
			defer release()
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			handle(conn)
		}()
	}
}

// ServeControl answers control requests on a listener only the host can reach, never one on the box's network: one
// JSON request in, one JSON answer out, per connection.
func (c *Canary) ServeControl(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			var q Request
			dec := json.NewDecoder(io.LimitReader(conn, 64<<10))
			dec.DisallowUnknownFields()
			a := Answer{Pin: c.Pin, Error: "the request didn't parse", Key: c.key()}
			if dec.Decode(&q) == nil {
				a = c.Handle(q)
			}
			json.NewEncoder(conn).Encode(a)
		}()
	}
}

// Ask sends one request to a canary's control listener and reads its answer.
func Ask(network, addr string, q Request) (Answer, error) {
	var a Answer
	conn, err := net.DialTimeout(network, addr, 5*time.Second)
	if err != nil {
		return a, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := json.NewEncoder(conn).Encode(q); err != nil {
		return a, err
	}
	return a, Decode(conn, &a)
}

// Decode reads exactly one answer, refusing unknown fields and anything longer than a canary may send.
func Decode(r io.Reader, a *Answer) error {
	dec := json.NewDecoder(io.LimitReader(r, int64(maxAnswer)+1))
	dec.DisallowUnknownFields()
	if err := dec.Decode(a); err != nil {
		return fmt.Errorf("the canary's answer didn't parse: %w", err)
	}
	return nil
}

// ServeTLS is the TLS echo (EGR-2, EGR-3): the nonce is the SNI's first label, recorded at the ClientHello, before
// any handshake can fail. A completed handshake gets "sandprobe:<nonce>" back.
func (c *Canary) ServeTLS(ln net.Listener, port int) error {
	return c.serve(ln, func(conn net.Conn) {
		var nonce string
		control := false
		cfg := &tls.Config{Certificates: []tls.Certificate{c.Cert}, MinVersion: tls.VersionTLS12,
			GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
				if c.ControlName != "" && strings.EqualFold(strings.TrimSuffix(h.ServerName, "."), c.ControlName) {
					control = true // HCN-1: the control name never counts as a receipt and never gets the pinned key
					return c.ControlTLS, nil
				}
				if n, ok := c.nonceOf(h.ServerName, "canary"); ok {
					nonce = n
					c.record(n, "tcp", port, conn.RemoteAddr())
				} else if strings.HasPrefix(h.ServerName, "health.") {
					nonce = "health"
				}
				return nil, nil
			}}
		tc := tls.Server(conn, cfg)
		err := tc.Handshake()
		if control {
			if err == nil && c.Control != nil {
				c.Control(tc)
			}
			return
		}
		if err == nil && nonce != "" {
			io.WriteString(tc, "sandprobe:"+nonce+"\n")
		}
	})
}

// ServeTCP is a plain port (EGR-5): the first line, up to 64 bytes, is the nonce. "health <challenge>" gets the
// canary's signature over this port and the challenge, which is what the host counts (SBX-11); a bare "health" gets
// an unsigned line, for an operator's check only.
func (c *Canary) ServeTCP(ln net.Listener, port int) error {
	return c.serve(ln, func(conn net.Conn) {
		line, _ := bufio.NewReader(io.LimitReader(conn, 64)).ReadString('\n')
		n := strings.TrimSpace(line)
		ch, signed := strings.CutPrefix(n, "health ")
		switch {
		case n == "health":
			io.WriteString(conn, "sandprobe:health\n")
		case signed && challengeRE.MatchString(ch):
			if sig, err := c.sign(port, ch); err == nil {
				io.WriteString(conn, "sandprobe:health:"+hex.EncodeToString(sig)+"\n")
			}
		case nameRE.MatchString(n):
			c.record(n, "tcp", port, conn.RemoteAddr())
			io.WriteString(conn, "sandprobe:"+n+"\n")
		}
	})
}

// ServeDNS is the authoritative server for dns.<domain> (EGR-1, through the box's resolver) and udp.<domain> (EGR-5's
// UDP 53, sent straight to the canary). Every query is answered NXDOMAIN, never larger than the query.
func (c *Canary) ServeDNS(pc net.PacketConn) error {
	buf := make([]byte, 512)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return err
		}
		q := buf[:n]
		name, end, err := questionName(q)
		if err != nil {
			continue
		}
		if nonce, ok := c.nonceOf(name, "dns"); ok {
			c.record(nonce, "dns", 53, from)
		} else if nonce, ok := c.nonceOf(name, "udp"); ok {
			c.record(nonce, "udp", 53, from)
		}
		pc.WriteTo(nxdomain(q, end), from)
	}
}

// questionName reads the first question's name from a DNS message, returning it and where the question ends.
func questionName(m []byte) (string, int, error) {
	if len(m) < 12 || m[4] != 0 || m[5] != 1 {
		return "", 0, errors.New("not a single-question query")
	}
	var labels []string
	i := 12
	for {
		if i >= len(m) {
			return "", 0, errors.New("truncated name")
		}
		l := int(m[i])
		i++
		if l == 0 {
			break
		}
		if l > 63 || i+l > len(m) {
			return "", 0, errors.New("bad label")
		}
		labels = append(labels, string(m[i:i+l]))
		i += l
	}
	if i+4 > len(m) {
		return "", 0, errors.New("truncated question")
	}
	return strings.Join(labels, "."), i + 4, nil
}

// nxdomain answers a query with its own question and RCODE 3.
func nxdomain(q []byte, end int) []byte {
	r := append([]byte(nil), q[:end]...)
	r[2] = 0x84 | (q[2] & 0x01) // QR, AA, and the query's RD
	r[3] = 0x03                 // NXDOMAIN
	r[6], r[7], r[8], r[9], r[10], r[11] = 0, 0, 0, 0, 0, 0
	return r
}

// DNSQuery builds a DNS query for name, for the probe and for the host's health checks.
func DNSQuery(id uint16, name string) []byte {
	m := []byte{byte(id >> 8), byte(id), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		m = append(m, byte(len(l)))
		m = append(m, l...)
	}
	return append(m, 0, 0, 1, 0, 1) // root, type A, class IN
}
