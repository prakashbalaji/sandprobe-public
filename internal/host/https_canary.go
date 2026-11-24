package host

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"sandprobe/internal/canary"
	"sandprobe/internal/canarycontrol"
	"sandprobe/internal/strictjson"
)

// HTTPSCanary is a public canary reached over HCN-1's signed control path: the hosted one, or one a person runs
// themselves. Its receipts and health use the same public ports as any canary. It isn't a ReceiverCanary yet: MEAS
// receiver sessions on a shared canary (HCN-6) need their own reservation and scope, which aren't built. Every control answer counts only when
// its signature verifies under one of Pins, for exactly the request this host sent (HCN-1). Each run the host arms is
// guarded by a secret only this host holds, reserved before any box exists (HCN-2, HCN-3).
type HTTPSCanary struct {
	URL       string   // the control origin, https://control.<domain>
	Pins      []string // the control keys this host trusts, hex SHA-256 of each key's SubjectPublicKeyInfo
	Addr, Dom string   // the canary's receipt address and domain, as boxes reach it

	// Client sends the control requests; tests replace it. Nil means a bounded default that follows no redirect.
	Client *http.Client

	mu      sync.Mutex
	pending []secret          // reserved, not yet armed
	runs    map[string]secret // armed, by run ID
	doubt   []secret          // an answer was lost: maybe reserved or armed, so Close releases them
}

// reserveTTL is a reservation's lifetime: the public maximum, so any arm the host makes after creating the box (the
// run's own, or a receiver session's) still fits (HCN-3).
const reserveTTL = 1800

type secret struct {
	raw, hash  string // hex
	generation string // set when armed (HCN-2)
	run        string // set once an arm was sent, so a release reaches an armed run as well as a reservation
}

// NewHTTPSCanary checks a control URL and pins, then asks the canary's status. The receipt address and domain come
// from that signed answer only, never from DNS: a redirected control name could otherwise put a relay in front of
// the box that forwards genuine control and health but drops the box's attempts (HCN-1). Errors never repeat the URL
// or pins, which a person might have pasted with a credential in them.
func NewHTTPSCanary(ctx context.Context, control string, pins []string) (*HTTPSCanary, error) {
	return newHTTPSCanary(ctx, control, pins, nil)
}

// NewHTTPSCanaryWithClient is NewHTTPSCanary with the person's own control client, such as one that accepts a staging
// certificate for `sandprobe canary check`. Trust still rests on the pins.
func NewHTTPSCanaryWithClient(ctx context.Context, control string, pins []string, client *http.Client) (*HTTPSCanary, error) {
	return newHTTPSCanary(ctx, control, pins, client)
}

var controlHost = regexp.MustCompile(`^[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63})+(:[0-9]{1,5})?$`)

// CheckCanaryURL checks a control URL and its pins with no network call, and returns them canonical: the origin
// https://<lowercase name>[:port], the domain after the name's first label, and the pins in lowercase. Its errors are
// fixed sentences that never repeat the input, which a person might have pasted with a credential in it.
func CheckCanaryURL(control string, pins []string) (origin, domain string, canonical []string, err error) {
	u, perr := url.Parse(control)
	if perr != nil || !strings.EqualFold(u.Scheme, "https") || u.Opaque != "" || u.User != nil || u.RawQuery != "" ||
		u.ForceQuery || u.Fragment != "" || u.Path != "" && u.Path != "/" || !controlHost.MatchString(strings.ToLower(u.Host)) {
		return "", "", nil, errors.New("a canary URL is https://control.<domain>, with nothing after the name")
	}
	if len(pins) == 0 || len(pins) > 2 {
		return "", "", nil, errors.New("a public canary needs one or two control-key pins (HCN-1)")
	}
	for _, p := range pins {
		if b, err := hex.DecodeString(p); err != nil || len(b) != sha256.Size {
			return "", "", nil, errors.New("a control-key pin is 64 hex digits")
		}
		canonical = append(canonical, strings.ToLower(p))
	}
	host := strings.ToLower(u.Host)
	_, domain, _ = strings.Cut(strings.ToLower(u.Hostname()), ".")
	return "https://" + host, domain, canonical, nil
}

func newHTTPSCanary(ctx context.Context, control string, pins []string, client *http.Client) (*HTTPSCanary, error) {
	origin, dom, pins, err := CheckCanaryURL(control, pins)
	if err != nil {
		return nil, err
	}
	c := &HTTPSCanary{URL: origin, Pins: pins, Client: client}
	a, err := c.call(ctx, "status", canary.Request{})
	if err != nil {
		return nil, err
	}
	ip, err := netip.ParseAddr(a.Addr)
	if !a.OK || err != nil || a.Domain != dom {
		return nil, errors.New("the canary's signed status doesn't name its receipt address for this domain")
	}
	c.Addr, c.Dom = ip.String(), a.Domain
	return c, nil
}

func (c *HTTPSCanary) IP() string     { return c.Addr }
func (c *HTTPSCanary) Domain() string { return c.Dom }

func (c *HTTPSCanary) Health(ctx context.Context, port int, k canary.Key) bool {
	return healthConnect(ctx, net.JoinHostPort(c.Addr, fmt.Sprint(port)), port, c.Dom, k)
}

// MustArm makes Execute stop before the probe when this canary didn't arm the run (HCN-3).
func (c *HTTPSCanary) MustArm() bool { return true }

// Reserve holds n slots on the canary, one for each run the host will arm, before any box is created (HCN-3). A
// refusal is the canary's own words, so the caller can stop before creating anything.
func (c *HTTPSCanary) Reserve(ctx context.Context, n int) error {
	for i := 0; i < n; i++ {
		var b [32]byte
		if _, err := rand.Read(b[:]); err != nil { // HCN-2: no randomness, no run
			return errors.New("no randomness for the run's secret")
		}
		sum := sha256.Sum256(b[:])
		s := secret{raw: hex.EncodeToString(b[:]), hash: hex.EncodeToString(sum[:])}
		a, err := c.call(ctx, "reserve", canary.Request{SecretSHA256: s.hash, TTL: reserveTTL})
		if err != nil { // no proven answer: the slot may be held, so Close releases it
			c.doubtful(s)
			return err
		}
		if !a.OK {
			return fmt.Errorf("the canary refused a reservation: %s", a.Error)
		}
		c.mu.Lock()
		c.pending = append(c.pending, s)
		c.mu.Unlock()
	}
	return nil
}

// Ask is SBX-11's control channel over the public path. An arm takes a reserved slot; a query or disarm carries the
// run's secret; a query whose generation isn't the one the arm answered with is an error, never a clean zero.
func (c *HTTPSCanary) Ask(ctx context.Context, q canary.Request) (canary.Answer, error) {
	switch q.Op {
	case "status", "protocols":
		return c.call(ctx, q.Op, canary.Request{})
	case "arm":
		c.mu.Lock()
		if len(c.pending) == 0 {
			c.mu.Unlock()
			return canary.Answer{}, errors.New("no reserved slot: reserve before creating the box (HCN-3)")
		}
		s := c.pending[0]
		c.pending = c.pending[1:]
		c.mu.Unlock()
		s.run = q.Run
		a, err := c.call(ctx, "arm", canary.Request{Run: q.Run, TTL: q.TTL, Wants: q.Wants, SecretSHA256: s.hash})
		if err != nil || !a.OK || len(a.Generation) != 32 {
			if c.release(ctx, s) != nil { // the slot isn't usable: give it back, run and reservation alike
				c.doubtful(s)
			}
			if err == nil {
				err = fmt.Errorf("the canary refused the arm: %s", a.Error)
			}
			return a, err
		}
		s.generation = a.Generation
		c.mu.Lock()
		if c.runs == nil {
			c.runs = map[string]secret{}
		}
		c.runs[q.Run] = s
		c.mu.Unlock()
		return a, nil
	case "query", "disarm":
		c.mu.Lock()
		s, ok := c.runs[q.Run]
		c.mu.Unlock()
		if !ok {
			return canary.Answer{}, fmt.Errorf("run %s wasn't armed here", q.Run)
		}
		a, err := c.call(ctx, q.Op, canary.Request{Run: q.Run, Secret: s.raw})
		if q.Op == "disarm" && err == nil { // a proven answer either way; a lost one leaves it for Close
			c.mu.Lock()
			delete(c.runs, q.Run)
			c.mu.Unlock()
		}
		if err == nil && q.Op == "query" && a.OK && a.Generation != s.generation {
			return canary.Answer{}, errors.New("the run's generation changed: it was re-armed (HCN-2)")
		}
		return a, err
	}
	return canary.Answer{}, fmt.Errorf("no canary op %q", q.Op)
}

// Close gives back everything this host may still hold: slots never armed, runs never disarmed, and any slot or run
// whose answer was lost. It reports what it couldn't confirm released and keeps those for another Close; failing that,
// they lapse on their own lifetime (HCN-3).
func (c *HTTPSCanary) Close(ctx context.Context) error {
	c.mu.Lock()
	left := append(c.pending, c.doubt...)
	for _, s := range c.runs {
		left = append(left, s)
	}
	c.pending, c.doubt, c.runs = nil, nil, nil
	c.mu.Unlock()
	var failed []secret
	for _, s := range left {
		if c.release(ctx, s) != nil {
			failed = append(failed, s)
		}
	}
	if len(failed) > 0 { // kept until a release is proven, so a later Close tries again
		c.mu.Lock()
		c.doubt = append(c.doubt, failed...)
		c.mu.Unlock()
		return fmt.Errorf("%d canary slots weren't confirmed released; they lapse within %d s", len(failed), reserveTTL)
	}
	return nil
}

// release disarms s's run if it was armed, or frees its reservation if not: the canary finds either by the secret.
// Only a proven answer counts; a proven refusal means there's nothing left to free.
func (c *HTTPSCanary) release(ctx context.Context, s secret) error {
	_, err := c.call(ctx, "disarm", canary.Request{Run: s.run, Secret: s.raw})
	return err
}

func (c *HTTPSCanary) doubtful(s secret) {
	c.mu.Lock()
	c.doubt = append(c.doubt, s)
	c.mu.Unlock()
}

// call sends one signed-transcript request: a fresh challenge, no redirect, a bounded answer that's parsed only after
// its signature verifies under a pin (HCN-1, JON-1).
func (c *HTTPSCanary) call(ctx context.Context, op string, q canary.Request) (canary.Answer, error) {
	var a canary.Answer
	var ch [32]byte
	if _, err := rand.Read(ch[:]); err != nil {
		return a, errors.New("no randomness for the challenge")
	}
	q.Op, q.Challenge = op, hex.EncodeToString(ch[:])
	body, err := json.Marshal(q)
	if err != nil {
		return a, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	path := "/v1/" + op
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL+path, bytes.NewReader(body))
	if err != nil {
		return a, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client().Do(req)
	if err != nil {
		return a, fmt.Errorf("the canary's control didn't answer: %w", err)
	}
	defer resp.Body.Close()
	ans, err := io.ReadAll(io.LimitReader(resp.Body, canarycontrol.MaxBody+1))
	switch {
	case err != nil:
		return a, errors.New("the canary's answer was cut short")
	case resp.StatusCode != http.StatusOK:
		return a, fmt.Errorf("the canary's control answered HTTP %d", resp.StatusCode)
	case len(ans) > canarycontrol.MaxBody:
		return a, errors.New("the canary's answer is too long")
	}
	if err := canarycontrol.Verify(c.Pins, resp.Header.Get(canarycontrol.KeyHeader), resp.Header.Get(canarycontrol.SignatureHeader),
		http.MethodPost, path, body, ans); err != nil {
		return a, fmt.Errorf("the canary's answer isn't proven: %w", err)
	}
	if err := strictjson.Decode(ans, canarycontrol.MaxBody, &a); err != nil {
		return a, errors.New("the canary's answer didn't parse")
	}
	if _, err := canary.KeyOf(a); err != nil {
		return a, err
	}
	if c.Addr != "" && (a.Addr != c.Addr || a.Domain != c.Dom) { // HCN-1: the signed address is the only one used
		return a, errors.New("the canary's signed answer names another receipt address")
	}
	return a, nil
}

func (c *HTTPSCanary) client() *http.Client {
	if c.Client != nil {
		return c.Client
	}
	return defaultControlClient
}

// The default control client follows no redirect and may use the person's HTTPS proxy: a proxy can relay or drop an
// answer but never forge one, since trust rests on the pinned key, not the connection (HCN-1).
var defaultControlClient = &http.Client{
	Timeout:       5 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 16 << 10},
}
