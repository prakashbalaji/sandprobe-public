package host

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"sandprobe/internal/canary"
	"sandprobe/internal/obs"
)

type receiverFixture struct {
	id, pin, key                string
	wants                       []canary.Want
	seen                        map[string]bool
	dropBefore, dropAfter       bool
	ackFailBefore, ackFailAfter bool
	markers                     []string
	box                         *receiverBoxFixture
	postBeforeStop              bool
	overload                    bool
}

func newReceiverFixture(t *testing.T) *receiverFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pin := sha256.Sum256(der)
	return &receiverFixture{id: "original-receiver", pin: hex.EncodeToString(pin[:]), key: base64.StdEncoding.EncodeToString(der), seen: map[string]bool{}}
}
func (c *receiverFixture) IP() string                                   { return "127.0.0.1" }
func (c *receiverFixture) Domain() string                               { return "canary.test" }
func (c *receiverFixture) ReceiverID() string                           { return c.id }
func (c *receiverFixture) Health(context.Context, int, canary.Key) bool { return true }
func (c *receiverFixture) SendMarker(_ context.Context, _ int, nonce string, _ canary.Key) error {
	c.markers = append(c.markers, nonce)
	if len(c.wants) == 3 && nonce == c.wants[0].Nonce && c.dropBefore {
		return errors.New("control failed")
	}
	if len(c.wants) == 3 && nonce == c.wants[2].Nonce {
		if c.box == nil || !c.box.stopped || !c.box.confirmed {
			c.postBeforeStop = true
		}
		if c.dropAfter {
			return errors.New("control failed")
		}
	}
	c.seen[nonce] = true
	if nonce == c.wants[0].Nonce && c.ackFailBefore || nonce == c.wants[2].Nonce && c.ackFailAfter {
		return errors.New("ack failed after receipt")
	}
	return nil
}
func (c *receiverFixture) Ask(_ context.Context, q canary.Request) (canary.Answer, error) {
	a := canary.Answer{OK: true, Pin: c.pin, Key: c.key, Run: q.Run, Overloaded: c.overload}
	switch q.Op {
	case "arm":
		c.wants = q.Wants
	case "query":
		for _, w := range c.wants {
			n := uint64(0)
			if c.seen[w.Nonce] {
				n = 1
			}
			a.Counts = append(a.Counts, canary.Count{Want: w, Count: n})
		}
	}
	return a, nil
}

type receiverBoxFixture struct {
	id                                                                 string
	c                                                                  *receiverFixture
	secret                                                             []string
	deliver, invalid, stopped, confirmed, confirmFail, changeOnDestroy bool
	confirmCalls                                                       int
	input                                                              []byte
}

func (b *receiverBoxFixture) ID() string { return b.id }
func (b *receiverBoxFixture) Probe(_ context.Context, args []string, input []byte) ([]byte, error) {
	b.input = slices.Clone(input)
	if !slices.Equal(args, []string{"-receiver"}) {
		return nil, errors.New("wrong mode")
	}
	for _, s := range b.secret {
		if strings.Contains(string(input), s) {
			return nil, errors.New("host control nonce leaked")
		}
	}
	var in obs.ReceiverProbeInput
	if json.Unmarshal(input, &in) != nil {
		return nil, errors.New("bad input")
	}
	if b.deliver {
		b.c.seen[in.Nonce] = true
	}
	if b.invalid {
		return []byte(`{"invalid":true}`), nil
	}
	return json.Marshal(obs.ReceiverProbeDoc{Schema: obs.ReceiverAttemptSchema, RunID: in.RunID, BoxID: in.BoxID, Nonce: in.Nonce, UID: 10001, GID: 10001, Attempt: obs.Attempt{Dest: net.JoinHostPort(in.Address, fmt.Sprint(in.Port)), Outcome: "connected", EndMS: 5}})
}
func (b *receiverBoxFixture) Destroy(context.Context) error {
	b.stopped = true
	if b.changeOnDestroy {
		b.id = "replacement"
	}
	return nil
}
func (b *receiverBoxFixture) ConfirmWorkloadGone(context.Context) error {
	b.confirmCalls++
	if b.confirmFail {
		return errors.New("unconfirmed")
	}
	b.confirmed = true
	return nil
}

func receiverSessionFixture(t *testing.T) (*ReceiverSession, *receiverFixture, *receiverBoxFixture) {
	t.Helper()
	c := newReceiverFixture(t)
	b := &receiverBoxFixture{id: "original-box", c: c}
	c.box = b
	s, err := BeginReceiverSession(context.Background(), c, strings.Repeat("a", 16), b.ID(), 443)
	if err != nil {
		t.Fatal(err)
	}
	now := s.evidence.Before.CollectedAt.Add(time.Millisecond)
	s.now = func() time.Time { return now }
	s.wait = func(_ context.Context, at time.Time) error { now = at; return nil }
	decl := s.Binding()
	b.secret = []string{decl.Nonces[0], decl.Nonces[2]}
	return s, c, b
}
func TestSharedReceiverCalibratesAfterOriginalGuestStop(t *testing.T) {
	s, c, b := receiverSessionFixture(t)
	declaration := s.Binding()
	declaration.Nonces[0] = "mutated"
	if err := s.Attempt(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	if s.Evidence().Attempt == nil {
		t.Fatal("missing generic guest attempt")
	}
	stop, err := s.StopWorkload(context.Background(), b)
	if err != nil {
		t.Fatal(err)
	}
	e := s.Finalize(context.Background(), stop)
	if !e.Before.OK || !e.After.OK || c.postBeforeStop || !slices.Contains(e.After.Received, s.Binding().Nonces[2]) {
		t.Fatal("missing ordered calibrated evidence")
	}
	for _, secret := range b.secret {
		if strings.Contains(string(b.input), secret) {
			t.Fatal("control nonce entered guest")
		}
	}
	if len(c.markers) != 2 {
		t.Fatal("wrong number of host controls")
	}
}
func TestSharedReceiverNeverCalibratesUnconfirmedOrChangedResources(t *testing.T) {
	for _, name := range []string{"unconfirmed", "wrong-box", "wrong-receiver", "changed-key", "changed-on-destroy"} {
		t.Run(name, func(t *testing.T) {
			s, c, b := receiverSessionFixture(t)
			if err := s.Attempt(context.Background(), b); err != nil {
				t.Fatal(err)
			}
			if name == "changed-on-destroy" {
				b.changeOnDestroy = true
				if _, err := s.StopWorkload(context.Background(), b); err == nil || b.confirmCalls != 0 {
					t.Fatal("replacement queried for absence")
				}
				return
			}
			stop, err := s.StopWorkload(context.Background(), b)
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "unconfirmed":
				stop.Confirmed = false
			case "wrong-box":
				stop.BoxID = "replacement"
			case "wrong-receiver":
				c.id = "replacement"
			case "changed-key":
				c.pin = strings.Repeat("f", 64)
			}
			e := s.Finalize(context.Background(), stop)
			if e.After.OK || len(c.markers) != 1 {
				t.Fatal("post control used an unconfirmed/replaced resource")
			}
		})
	}
}
func TestSharedReceiverRetainsPositiveHostReceiptWithBadGuestOutput(t *testing.T) {
	s, _, b := receiverSessionFixture(t)
	b.deliver = true
	b.invalid = true
	if !errors.Is(s.Attempt(context.Background(), b), ErrReceiverDelivery) {
		t.Fatal("positive host delivery lost")
	}
	e := s.Evidence()
	if e.Attempt != nil || e.During == nil || !e.During.OK || !slices.Contains(e.During.Received, s.Binding().Nonces[1]) {
		t.Fatal("untrusted guest erased independent receipt")
	}
}
func TestSharedReceiverRequiresBeforeAndAfterPositiveControls(t *testing.T) {
	c := newReceiverFixture(t)
	c.dropBefore = true
	if _, err := BeginReceiverSession(context.Background(), c, strings.Repeat("a", 16), "owned-box", 443); err == nil {
		t.Fatal("missing pre control ignored")
	}
	s, c, b := receiverSessionFixture(t)
	s.Attempt(context.Background(), b)
	stop, _ := s.StopWorkload(context.Background(), b)
	c.dropAfter = true
	e := s.Finalize(context.Background(), stop)
	if slices.Contains(e.After.Received, s.Binding().Nonces[2]) {
		t.Fatal("failed post control invented")
	}
}

func TestSharedReceiverRejectsReceiptWithFailedControlExchange(t *testing.T) {
	c := newReceiverFixture(t)
	c.ackFailBefore = true
	s, err := BeginReceiverSession(context.Background(), c, strings.Repeat("a", 16), "owned-box", 443)
	if err == nil || s.Evidence().BeforeSent || !s.Evidence().Before.OK || !slices.Contains(s.Evidence().Before.Received, s.Binding().Nonces[0]) {
		t.Fatal("failed pre-control exchange accepted despite receipt")
	}
	s, c, b := receiverSessionFixture(t)
	s.Attempt(context.Background(), b)
	stop, _ := s.StopWorkload(context.Background(), b)
	c.ackFailAfter = true
	e := s.Finalize(context.Background(), stop)
	if e.AfterSent || !e.After.OK || !slices.Contains(e.After.Received, s.Binding().Nonces[2]) {
		t.Fatal("failed post-control exchange accepted despite receipt")
	}
}

func TestSharedReceiverDetectsLateDelivery(t *testing.T) {
	s, c, b := receiverSessionFixture(t)
	if err := s.Attempt(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	if s.DeliveryObserved() {
		t.Fatal("invented early delivery")
	}
	stop, _ := s.StopWorkload(context.Background(), b)
	c.seen[s.Binding().Nonces[1]] = true
	s.Finalize(context.Background(), stop)
	if !s.DeliveryObserved() {
		t.Fatal("late delivery escaped restricted handling")
	}
}
