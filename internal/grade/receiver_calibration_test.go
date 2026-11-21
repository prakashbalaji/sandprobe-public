package grade

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"sandprobe/internal/obs"
)

func calibratedReceiverCase(t *testing.T) (WorkloadReport, *obs.WorkloadContract, obs.ReceiverBinding, obs.ReceiverCalibration) {
	t.Helper()
	m, d, c := workloadCase()
	b := obs.ReceiverBinding{Schema: obs.ReceiverBindingSchema, ManagedRunID: m.WorkloadContract.ManagedRunID, BoxID: m.BoxID, RunID: "rreceiver123", ReceiverID: "owned-receiver", Address: "192.0.2.1", Domain: "canary.test", Port: 443, Pin: strings.Repeat("a", 64), Scope: "owned_public_endpoint", Nonces: []string{strings.Repeat("1", 48), strings.Repeat("2", 48), strings.Repeat("3", 48)}}
	hash, err := obs.ReceiverBindingHash(b)
	if err != nil {
		t.Fatal(err)
	}
	m.WorkloadContract.ReceiverBindingSHA256 = hash
	r := runWorkload(m, d, c, "reported_passed")
	now := time.Now()
	collection := func(at time.Time, received ...string) obs.ReceiverCollection {
		return obs.ReceiverCollection{OK: true, ReceiverID: b.ReceiverID, RunID: b.RunID, Pin: b.Pin, Received: received, CollectedAt: at}
	}
	e := obs.ReceiverCalibration{Schema: obs.ReceiverEvidenceSchema, BindingSHA256: hash, Before: collection(now, b.Nonces[0]), AttemptAt: now.Add(time.Second), Stop: obs.WorkloadStopProof{BoxID: b.BoxID, Confirmed: true, Method: "provider_control_plane", At: now.Add(2 * time.Second)}, After: collection(now.Add(5*time.Second), b.Nonces[0], b.Nonces[2]), Attempt: &obs.ReceiverProbeDoc{Schema: obs.ReceiverAttemptSchema, RunID: b.RunID, BoxID: b.BoxID, Nonce: b.Nonces[1], UID: 10001, GID: 10001, Attempt: obs.Attempt{Dest: fmt.Sprintf("%s:%d", b.Address, b.Port), Outcome: "connected", ExchangeStage: "read_reply", ExchangeResult: "unexpected_reply", EndMS: 10}}}
	e.BeforeSent, e.AfterSent = true, true
	return r, m.WorkloadContract, b, e
}
func TestReceiverCalibrationIsNotDenialProof(t *testing.T) {
	r, c, b, e := calibratedReceiverCase(t)
	got := AddReceiverCalibration(r, c, b, e)
	if got.ConfigurationGrade != "B" || !got.Complete {
		t.Fatalf("valid calibrated collection lost: %+v", got.Unknown)
	}
	row := got.Controls[len(got.Controls)-1]
	if row.ID != "receiver-calibration" || row.Result != obs.NotFound || !strings.Contains(row.Reason, "not proof of refusal") {
		t.Fatal("silence became pass", row)
	}
}
func TestReceiverCalibrationRejectsMissingOrReplayedEvidence(t *testing.T) {
	for _, name := range []string{"hash", "box", "receiver", "pin", "run", "controls", "before-send", "after-send", "overload", "stop", "order", "attempt", "duplicate"} {
		t.Run(name, func(t *testing.T) {
			r, c, b, e := calibratedReceiverCase(t)
			switch name {
			case "hash":
				c.ReceiverBindingSHA256 = strings.Repeat("f", 64)
			case "box":
				b.BoxID = "replacement-box"
			case "receiver":
				e.After.ReceiverID = "replacement"
			case "pin":
				e.After.Pin = strings.Repeat("f", 64)
			case "run":
				e.After.RunID = "unrelated"
			case "controls":
				e.After.Received = nil
			case "before-send":
				e.BeforeSent = false
			case "after-send":
				e.AfterSent = false
			case "overload":
				e.After.Overloaded = true
			case "stop":
				e.Stop.Confirmed = false
			case "order":
				e.After.CollectedAt = e.Stop.At
			case "attempt":
				e.Attempt = nil
			case "duplicate":
				e.After.Received = append(e.After.Received, e.After.Received[0])
			}
			got := AddReceiverCalibration(r, c, b, e)
			if got.ConfigurationGrade != "C" || got.Complete || got.BenchmarkRequirementsMet || len(got.Unknown) == 0 {
				t.Fatal("missing evidence earned complete result")
			}
		})
	}
}

func TestReceiverPositiveNeedsOrderedAttemptTimestamp(t *testing.T) {
	for _, missing := range []bool{true, false} {
		r, c, b, e := calibratedReceiverCase(t)
		e.After.Received = append(e.After.Received, b.Nonces[1])
		if missing {
			e.AttemptAt = time.Time{}
		} else {
			e.After.CollectedAt = e.AttemptAt.Add(-time.Second)
		}
		got := AddReceiverCalibration(r, c, b, e)
		if got.ConfigurationGrade != "C" || got.Complete {
			t.Fatal("unordered receipt attributed to guest")
		}
		for _, row := range got.Controls {
			if row.ID == "receiver-calibration" && row.Result == obs.Finding {
				t.Fatal("unordered positive finding")
			}
		}
	}
}
func TestReceiverPositiveHostReceiptSurvivesInvalidGuestAndControls(t *testing.T) {
	r, c, b, e := calibratedReceiverCase(t)
	r.Valid = false
	r.Complete = false
	r.ConfigurationGrade = ""
	e.Attempt = nil
	e.Before.OK = false
	e.After.Received = append(e.After.Received, b.Nonces[1])
	e.After.Overloaded = true
	got := AddReceiverCalibration(r, c, b, e)
	if got.ConfigurationGrade != "D" || got.BenchmarkRequirementsMet || !slices.Contains(got.Unknown, "receiver-calibration-attempt") {
		t.Fatal("positive host delivery erased")
	}
	r.Controls = append(r.Controls, WorkloadControl{"protected-marker", "required", obs.Finding, "fixture"})
	if AddReceiverCalibration(r, c, b, e).ConfigurationGrade != "F" {
		t.Fatal("combined protected access and delivery lost")
	}
	r.Controls = nil
	r.ConfigurationGrade = "F"
	if AddReceiverCalibration(r, c, b, e).ConfigurationGrade != "F" {
		t.Fatal("existing F was improved by a new finding")
	}
}
