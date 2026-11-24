package host

import (
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"sandprobe/internal/canary"
	"sandprobe/internal/obs"
	"strings"
	"testing"
)

type markerProtocolCanary struct {
	*canary.Canary
	ops                     []string
	absent, changed, failed bool
}

func (c *markerProtocolCanary) IP() string                                   { return "198.51.100.1" }
func (c *markerProtocolCanary) Domain() string                               { return "canary.test" }
func (c *markerProtocolCanary) Health(context.Context, int, canary.Key) bool { return false }
func (c *markerProtocolCanary) Ask(_ context.Context, q canary.Request) (canary.Answer, error) {
	c.ops = append(c.ops, q.Op)
	a := c.Handle(q)
	if q.Op == "protocols" {
		if c.absent {
			a.Protocols = nil
		}
		if c.changed {
			a.Pin = "changed"
		}
		if c.failed {
			return a, errors.New("synthetic-sensitive-error")
		}
	}
	return a, nil
}
func TestHTTPMarkerCapabilitySamePinAndNoFallback(t *testing.T) {
	for _, tc := range []struct{ absent, changed, failed, want bool }{{false, false, false, true}, {true, false, false, false}, {false, true, false, false}, {false, false, true, false}} {
		node, err := canary.New("canary.test")
		if err != nil {
			t.Fatal(err)
		}
		c := &markerProtocolCanary{Canary: node, absent: tc.absent, changed: tc.changed, failed: tc.failed}
		err = RequireHTTPMarkerV1(context.Background(), c)
		if (err == nil) != tc.want {
			t.Fatal("capability accepted incorrectly", err)
		}
		if err != nil && strings.Contains(err.Error(), "sensitive") {
			t.Fatal("control error leaked")
		}
		if !reflect.DeepEqual(c.ops, []string{"status", "protocols"}) {
			t.Fatal("unexpected fallback/control traffic", c.ops)
		}
	}
}

type markerProtocolTransport func(*http.Request) (*http.Response, error)

func (f markerProtocolTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestHTTPMarkerSignedCapability(t *testing.T) {
	_, _, c := publicCanary(t)
	if err := RequireHTTPMarkerV1(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	base := c.Client.Transport
	c.Client.Transport = markerProtocolTransport(func(q *http.Request) (*http.Response, error) {
		r, err := base.RoundTrip(q)
		if err == nil && strings.HasSuffix(q.URL.Path, "/protocols") {
			data, e := io.ReadAll(r.Body)
			r.Body.Close()
			if e != nil {
				return nil, e
			}
			modified := strings.ReplaceAll(string(data), canary.HTTPMarkerV1, "forged-protocol")
			r.Body = io.NopCloser(strings.NewReader(modified))
			r.ContentLength = int64(len(modified))
		}
		return r, err
	})
	if err := RequireHTTPMarkerV1(context.Background(), c); err == nil {
		t.Fatal("unsigned capability mutation accepted")
	}
}
func TestHTTPMarkerPlanAndLegacyTargets(t *testing.T) {
	base := Options{Mode: "exec", ProbeSHA256: "fixture"}
	m0, _ := Plan(base, &obs.Survey{}, "fixture", Storage{}, "198.51.100.1", "canary.test", "pin")
	base.CanaryTCP80Protocol = canary.HTTPMarkerV1
	m, in := Plan(base, &obs.Survey{}, "fixture", Storage{}, "198.51.100.1", "canary.test", "pin")
	if m.CanaryTCP80Protocol != canary.HTTPMarkerV1 || in.CanaryTCP80Protocol != m.CanaryTCP80Protocol || !reflect.DeepEqual(m.Endpoints, m0.Endpoints) || !reflect.DeepEqual(m.Selected, m0.Selected) {
		t.Fatal("protocol selection changed scope")
	}
	if m0.CanaryTCP80Protocol != "" {
		t.Fatal("legacy default changed")
	}
}

type markerProtocolBox struct{ called bool }

func (b *markerProtocolBox) ID() string { return "fixture" }
func (b *markerProtocolBox) Probe(context.Context, []string, []byte) ([]byte, error) {
	b.called = true
	return nil, errors.New("fixture stop")
}
func TestInvalidHTTPMarkerOptionsStopBeforeSurvey(t *testing.T) {
	for _, o := range []Options{{CanaryTCP80Protocol: "untrusted-secret"}, {CanaryTCP80Protocol: canary.HTTPMarkerV1, NoCanary: true}} {
		b := &markerProtocolBox{}
		if _, err := Execute(context.Background(), b, nil, o); err == nil || b.called {
			t.Fatal("invalid option reached guest")
		}
	}
}
