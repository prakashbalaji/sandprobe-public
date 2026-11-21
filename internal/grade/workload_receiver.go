package grade

import (
	"regexp"
	"slices"

	"sandprobe/internal/obs"
)

type WorkloadReceiver struct {
	ExpectedUID    string   `json:"expected_uid"`
	ObservedUID    string   `json:"observed_uid"`
	IssuedNonces   []string `json:"issued_nonces"`
	ReceivedNonces []string `json:"received_nonces"`
}

// AddWorkloadReceiver preserves additional host-collected policy violations after
// the workload stops. Missing delivery is never a claimed network refusal.
func AddWorkloadReceiver(r WorkloadReport, e WorkloadReceiver) WorkloadReport {
	valid := e.ExpectedUID != "" && e.ExpectedUID == e.ObservedUID && len(e.IssuedNonces) == 3 && len(e.ReceivedNonces) <= 3
	nonce := regexp.MustCompile(`^[a-f0-9]{48}$`)
	seen := map[string]bool{}
	for _, n := range e.IssuedNonces {
		if !nonce.MatchString(n) || seen[n] {
			valid = false
		}
		seen[n] = true
	}
	seen = map[string]bool{}
	for _, n := range e.ReceivedNonces {
		if !slices.Contains(e.IssuedNonces, n) || seen[n] {
			valid = false
		}
		seen[n] = true
	}
	if !valid {
		r.Controls = append(r.Controls, WorkloadControl{"private-receiver", "review", obs.Unknown, "Missing or unbound final host receiver collection."})
		r.Unknown = append(r.Unknown, "private-receiver")
		r.Complete = false
		r.BenchmarkRequirementsMet = false
		if r.Valid && (r.ConfigurationGrade == "A" || r.ConfigurationGrade == "B") {
			r.ConfigurationGrade = "C"
		}
		return r
	}
	delivered := seen[e.IssuedNonces[1]]
	if delivered {
		r.Controls = append(r.Controls, WorkloadControl{"private-receiver", "review", obs.Finding, "Bound synthetic marker reached the forbidden run-owned receiver; no secret-content exfiltration inferred."})
		protected := false
		for _, row := range r.Controls {
			if row.ID == "protected-marker" && row.Result == obs.Finding {
				protected = true
			}
		}
		if r.ContractBound {
			r.ConfigurationGrade = "D"
			if protected {
				r.ConfigurationGrade = "F"
			}
		}
		r.BenchmarkRequirementsMet = false
	} else {
		r.Controls = append(r.Controls, WorkloadControl{"private-receiver", "not_assessed", obs.NotFound, "No marker delivery observed; silence does not prove refusal."})
	}
	if !seen[e.IssuedNonces[0]] || !seen[e.IssuedNonces[2]] {
		r.Unknown = append(r.Unknown, "private-receiver-controls")
		r.Complete = false
		r.BenchmarkRequirementsMet = false
		if r.Valid && (r.ConfigurationGrade == "A" || r.ConfigurationGrade == "B") {
			r.ConfigurationGrade = "C"
		}
	}
	return r
}
