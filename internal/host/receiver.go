package host

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"time"

	"sandprobe/internal/canary"
	"sandprobe/internal/obs"
	"sandprobe/internal/strictjson"
)

// MEAS-1: adapters provide transport and original receiver identity, not verdicts.
type ReceiverCanary interface {
	Canary
	ReceiverID() string
	SendMarker(context.Context, int, string, canary.Key) error
}

type ReceiverWorkload interface {
	Box
	Destroy(context.Context) error
	ConfirmWorkloadGone(context.Context) error
}

var ErrReceiverDelivery = errors.New("owned receiver delivery observed; retain restricted evidence")

type ReceiverSession struct {
	c        ReceiverCanary
	binding  obs.ReceiverBinding
	key      canary.Key
	evidence obs.ReceiverCalibration
	now      func() time.Time
	wait     func(context.Context, time.Time) error
}

func BeginReceiverSession(ctx context.Context, c ReceiverCanary, managedRunID, boxID string, port int) (*ReceiverSession, error) {
	status, err := c.Ask(ctx, canary.Request{Op: "status"})
	key, kerr := canary.KeyOf(status)
	if err != nil || kerr != nil || !status.OK || c.ReceiverID() == "" {
		return nil, errors.New("receiver identity unavailable")
	}
	b := obs.ReceiverBinding{Schema: obs.ReceiverBindingSchema, ManagedRunID: managedRunID, BoxID: boxID, RunID: token("r"), ReceiverID: c.ReceiverID(), Address: c.IP(), Domain: c.Domain(), Port: port, Pin: key.Pin, Scope: "owned_public_endpoint"}
	if ip, e := netip.ParseAddr(b.Address); e == nil && (ip.IsPrivate() || ip.IsLoopback()) {
		b.Scope = "owned_private_endpoint"
	}
	for i := 0; i < 3; i++ {
		var n [24]byte
		if _, err = rand.Read(n[:]); err != nil {
			return nil, errors.New("receiver nonce unavailable")
		}
		b.Nonces = append(b.Nonces, hex.EncodeToString(n[:]))
	}
	hash, err := obs.ReceiverBindingHash(b)
	if err != nil {
		return nil, err
	}
	s := &ReceiverSession{c: c, binding: b, key: key, now: time.Now, evidence: obs.ReceiverCalibration{Schema: obs.ReceiverEvidenceSchema, BindingSHA256: hash}}
	s.wait = func(ctx context.Context, until time.Time) error {
		d := time.Until(until)
		if d <= 0 {
			return nil
		}
		timer := time.NewTimer(d)
		defer timer.Stop()
		select {
		case <-timer.C:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	wants := make([]canary.Want, 0, 3)
	for _, nonce := range b.Nonces {
		wants = append(wants, canary.Want{Nonce: nonce, Proto: "tcp", Port: port})
	}
	armed, e := c.Ask(ctx, canary.Request{Op: "arm", Run: b.RunID, TTL: 900, Wants: wants})
	if e != nil || !s.answerBound(armed) {
		return s, errors.New("receiver arm unavailable")
	}
	s.evidence.BeforeSent = c.SendMarker(ctx, port, b.Nonces[0], key) == nil
	s.evidence.Before = s.collect(ctx)
	if !s.evidence.BeforeSent || !s.evidence.Before.OK || s.evidence.Before.Overloaded || !slices.Contains(s.evidence.Before.Received, b.Nonces[0]) || slices.Contains(s.evidence.Before.Received, b.Nonces[1]) {
		return s, errors.New("receiver positive control unavailable")
	}
	return s, nil
}

func (s *ReceiverSession) Binding() obs.ReceiverBinding {
	b := s.binding
	b.Nonces = slices.Clone(b.Nonces)
	return b
}
func (s *ReceiverSession) Evidence() obs.ReceiverCalibration {
	e := s.evidence
	e.Before.Received = slices.Clone(e.Before.Received)
	e.After.Received = slices.Clone(e.After.Received)
	if e.Attempt != nil {
		d := *e.Attempt
		e.Attempt = &d
	}
	if e.During != nil {
		d := *e.During
		d.Received = slices.Clone(d.Received)
		e.During = &d
	}
	return e
}
func (s *ReceiverSession) answerBound(a canary.Answer) bool {
	_, err := canary.KeyOf(a)
	return a.OK && err == nil && a.Pin == s.binding.Pin && a.Run == s.binding.RunID && s.c.ReceiverID() == s.binding.ReceiverID
}
func (s *ReceiverSession) collect(ctx context.Context) obs.ReceiverCollection {
	b := s.binding
	v := obs.ReceiverCollection{ReceiverID: s.c.ReceiverID(), RunID: b.RunID, Pin: b.Pin}
	if v.ReceiverID != b.ReceiverID {
		v.CollectedAt = s.now()
		return v
	}
	a, err := s.c.Ask(ctx, canary.Request{Op: "query", Run: b.RunID})
	v.CollectedAt = s.now()
	if err != nil || !s.answerBound(a) || len(a.Counts) != 3 {
		return v
	}
	seen := map[string]bool{}
	for _, count := range a.Counts {
		if !slices.Contains(b.Nonces, count.Nonce) || seen[count.Nonce] || count.Proto != "tcp" || count.Port != b.Port {
			return v
		}
		seen[count.Nonce] = true
		// Elsewhere proves the guest's marker reached the owned receiver, but it
		// cannot calibrate a positive control on the requested protocol/port.
		if count.Count > 0 || count.Nonce == b.Nonces[1] && count.Elsewhere > 0 {
			v.Received = append(v.Received, count.Nonce)
		}
	}
	v.OK = true
	v.Overloaded = a.Overloaded
	return v
}

// Attempt gives the guest only the middle nonce. Missing/invalid guest output is
// retained as unavailable; independently bound positive host receipts still count.
func (s *ReceiverSession) Attempt(ctx context.Context, b Box) error {
	if b.ID() != s.binding.BoxID {
		return errors.New("receiver box identity changed")
	}
	in := obs.ReceiverProbeInput{Schema: obs.ReceiverAttemptSchema, RunID: s.binding.RunID, BoxID: b.ID(), Nonce: s.binding.Nonces[1], Address: s.binding.Address, Domain: s.binding.Domain, Port: s.binding.Port, Pin: s.binding.Pin}
	raw, _ := json.Marshal(in)
	s.evidence.AttemptAt = s.now()
	out, err := b.Probe(ctx, []string{"-receiver"}, raw)
	var d obs.ReceiverProbeDoc
	if err == nil && strictjson.Decode(out, 16384, &d) == nil && d.Schema == obs.ReceiverAttemptSchema && d.RunID == in.RunID && d.BoxID == in.BoxID && d.Nonce == in.Nonce {
		s.evidence.Attempt = &d
	}
	during := s.collect(ctx)
	s.evidence.During = &during
	if s.DeliveryObserved() {
		return ErrReceiverDelivery
	}
	return nil
}

func (s *ReceiverSession) Finalize(ctx context.Context, stop obs.WorkloadStopProof) obs.ReceiverCalibration {
	s.evidence.Stop = stop
	if !stop.Confirmed || stop.BoxID != s.binding.BoxID || stop.Method != "provider_control_plane" || stop.At.IsZero() || s.evidence.AttemptAt.IsZero() || stop.At.Before(s.evidence.AttemptAt) || stop.At.After(s.now()) {
		return s.Evidence()
	}
	if s.c.ReceiverID() != s.binding.ReceiverID {
		return s.Evidence()
	}
	status, err := s.c.Ask(ctx, canary.Request{Op: "status"})
	_, keyError := canary.KeyOf(status)
	if err != nil || keyError != nil || !status.OK || status.Pin != s.binding.Pin {
		return s.Evidence()
	}
	s.evidence.AfterSent = s.c.SendMarker(ctx, s.binding.Port, s.binding.Nonces[2], s.key) == nil
	if s.wait(ctx, s.now().Add(receiptWait)) != nil {
		return s.Evidence()
	}
	s.evidence.After = s.collect(ctx)
	return s.Evidence()
}

// MEAS-2: a late host receipt is handled exactly like an immediate receipt.
func (s *ReceiverSession) DeliveryObserved() bool {
	if s.evidence.AttemptAt.IsZero() {
		return false
	}
	for _, collection := range []*obs.ReceiverCollection{s.evidence.During, &s.evidence.After} {
		if collection != nil && collection.OK && !collection.CollectedAt.Before(s.evidence.AttemptAt) && slices.Contains(collection.Received, s.binding.Nonces[1]) {
			return true
		}
	}
	return false
}
func (s *ReceiverSession) StopWorkload(ctx context.Context, b ReceiverWorkload) (obs.WorkloadStopProof, error) {
	if b.ID() != s.binding.BoxID {
		return obs.WorkloadStopProof{}, errors.New("receiver box identity changed")
	}
	if err := b.Destroy(ctx); err != nil {
		return obs.WorkloadStopProof{}, errors.New("receiver workload stop unconfirmed")
	}
	if b.ID() != s.binding.BoxID {
		return obs.WorkloadStopProof{}, errors.New("receiver box identity changed")
	}
	if err := b.ConfirmWorkloadGone(ctx); err != nil {
		return obs.WorkloadStopProof{}, errors.New("receiver workload absence unconfirmed")
	}
	if b.ID() != s.binding.BoxID {
		return obs.WorkloadStopProof{}, errors.New("receiver box identity changed")
	}
	return obs.WorkloadStopProof{BoxID: b.ID(), Confirmed: true, Method: "provider_control_plane", At: s.now()}, nil
}
func (s *ReceiverSession) Close(ctx context.Context) {
	if s.c.ReceiverID() == s.binding.ReceiverID {
		s.c.Ask(ctx, canary.Request{Op: "disarm", Run: s.binding.RunID})
	}
}
