package grade

import (
	"fmt"
	"net"
	"slices"
	"time"

	"sandprobe/internal/obs"
)

// MEAS-2: the same proof rules apply to every adapter. No provider selection or
// absence-as-refusal exception belongs in this function.
func AddReceiverCalibration(r WorkloadReport, c *obs.WorkloadContract, b obs.ReceiverBinding, e obs.ReceiverCalibration) WorkloadReport {
	unknown := func(id, reason string) {
		r.Controls = append(r.Controls, WorkloadControl{id, "review", obs.Unknown, reason})
		if !slices.Contains(r.Unknown, id) {
			r.Unknown = append(r.Unknown, id)
		}
		r.Complete = false
		r.BenchmarkRequirementsMet = false
		if r.Valid && (r.ConfigurationGrade == "A" || r.ConfigurationGrade == "B") {
			r.ConfigurationGrade = "C"
		}
	}
	hash, err := obs.ReceiverBindingHash(b)
	if err != nil || c == nil || obs.ValidateWorkloadContract(c) != nil || c.ReceiverBindingSHA256 == "" || c.ReceiverBindingSHA256 != hash ||
		b.BoxID != c.BoxID || b.BoxID != r.BoxID || b.ManagedRunID != c.ManagedRunID || !r.ContractBound || e.Schema != obs.ReceiverEvidenceSchema || e.BindingSHA256 != hash {
		unknown("receiver-calibration", "Missing or mismatched pre-workload receiver binding; no collection verdict.")
		return r
	}
	positiveAt := func(v obs.ReceiverCollection) bool {
		return !e.AttemptAt.IsZero() && !v.CollectedAt.Before(e.AttemptAt) && receiverCollectionBound(v, b) && slices.Contains(v.Received, b.Nonces[1])
	}
	positive := positiveAt(e.After)
	if e.During != nil && positiveAt(*e.During) {
		positive = true
	}
	if positive {
		r.Controls = append(r.Controls, WorkloadControl{"receiver-calibration", "review", obs.Finding, "Bound guest marker reached the run-owned receiver (" + b.Scope + "); route and secret-content exfiltration are not inferred."})
		if r.ConfigurationGrade != "F" {
			r.ConfigurationGrade = "D"
		}
		for _, control := range r.Controls {
			if control.ID == "protected-marker" && control.Result == obs.Finding {
				r.ConfigurationGrade = "F"
			}
		}
		r.BenchmarkRequirementsMet = false
	}
	ordered := e.Stop.Confirmed && e.Stop.BoxID == b.BoxID && e.Stop.Method == "provider_control_plane" && !e.Stop.At.IsZero() && !e.AttemptAt.IsZero() &&
		!e.Before.CollectedAt.After(e.AttemptAt) && !e.Stop.At.Before(e.AttemptAt) && !e.After.CollectedAt.Before(e.Stop.At.Add(2*time.Second))
	if !ordered {
		unknown("receiver-calibration-order", "Final receiver collection is not bound to confirmed original-guest shutdown and the receipt grace interval.")
	}
	controls := e.BeforeSent && e.AfterSent && receiverCollectionBound(e.Before, b) && receiverCollectionBound(e.After, b) && !e.Before.Overloaded && !e.After.Overloaded &&
		slices.Contains(e.Before.Received, b.Nonces[0]) && !slices.Contains(e.Before.Received, b.Nonces[1]) && slices.Contains(e.After.Received, b.Nonces[2])
	if !controls {
		unknown("receiver-calibration-controls", "Missing bound pre/post receiver controls, overloaded receiver or incomplete collection.")
	}
	uid, gid := 10001, 10001
	if c.AgentUID > 0 {
		uid, gid = c.AgentUID, c.AgentGID
	}
	d := e.Attempt
	attempt := d != nil && d.Schema == obs.ReceiverAttemptSchema && d.RunID == b.RunID && d.BoxID == b.BoxID && d.Nonce == b.Nonces[1] && d.UID == uid && d.GID == gid
	if attempt {
		a := d.Attempt
		attempt = a.Dest == net.JoinHostPort(b.Address, fmt.Sprint(b.Port)) && a.StartMS >= 0 && a.EndMS >= a.StartMS && a.EndMS <= 15000
		switch a.Outcome {
		case "refused", "timeout", "netunreach", "hostunreach", "eperm", "connected":
		default:
			attempt = false
		}
	}
	if !attempt {
		unknown("receiver-calibration-attempt", "Guest marker attempt is unavailable or differs from the frozen endpoint/principal; host positive receipts remain authoritative.")
	}
	if ordered && controls && attempt && !positive {
		r.Controls = append(r.Controls, WorkloadControl{"receiver-calibration", "not_assessed", obs.NotFound, "No guest marker observed at the calibrated run-owned receiver (" + b.Scope + "); silence is not proof of refusal."})
	}
	return r
}

func receiverCollectionBound(c obs.ReceiverCollection, b obs.ReceiverBinding) bool {
	if !c.OK || c.ReceiverID != b.ReceiverID || c.RunID != b.RunID || c.Pin != b.Pin || c.CollectedAt.IsZero() || len(c.Received) > 3 {
		return false
	}
	seen := map[string]bool{}
	for _, nonce := range c.Received {
		if !slices.Contains(b.Nonces, nonce) || seen[nonce] {
			return false
		}
		seen[nonce] = true
	}
	return true
}
