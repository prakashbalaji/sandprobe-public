package grade

import (
	"slices"
	"strings"

	"sandprobe/internal/catalog"
	"sandprobe/internal/obs"
)

// EVD-1: measurement coverage is separate from configuration conformance and
// the six-point exposure score (SCR-1). Missing support never creates a pass.
type EvidenceCoverage struct {
	Schema              string               `json:"schema"`
	Valid               bool                 `json:"valid"`
	RunID               string               `json:"run_id"`
	UnknownControls     int                  `json:"unknown_controls"`
	Categories          []EvidenceCategory   `json:"categories"`
	Context             []WorkloadControl    `json:"context_controls"`
	ConfigurationGuards []ConfigurationGuard `json:"host_declared_guards,omitempty"`
	Gaps                []EvidenceGap        `json:"gaps"`
	Exchanges           []ExchangeDiagnostic `json:"exchanges,omitempty"`
}

type ConfigurationGuard struct {
	Name     string `json:"name"`
	Verified bool   `json:"verified"`
}

type EvidenceCategory struct {
	Name     string            `json:"name"`
	Controls []WorkloadControl `json:"controls"`
}

type EvidenceGap struct {
	ID              string   `json:"id"`
	Source          string   `json:"source"`
	Controls        []string `json:"controls"`
	NextMeasurement string   `json:"next_measurement"`
}

type ExchangeDiagnostic struct {
	Check     string `json:"check"`
	Transport string `json:"transport"`
	Stage     string `json:"stage"`
	Result    string `json:"result"`
}

// EVD-1: names and membership follow the scorecard's six questions (SCR-1). These are
// workload-context rows, with no numeric score or all-clear category verdict.
var evidenceCategories = []struct {
	name   string
	checks []string
}{
	{"Secrets", []string{"SEC-1", "SEC-2", "SEC-3", "SEC-5", "protected-marker"}},
	{"Exfiltration", []string{"EGR-1", "EGR-2", "EGR-3", "EGR-4", "EGR-5.22", "EGR-5.80", "EGR-5.8080", "EGR-5.53u", "EGR-6", "private-receiver", "receiver-calibration"}},
	{"Containment", []string{"AMP-4", "AMP-5", "AMP-6", "AMP-8.sys", "AMP-8.blk"}},
	{"Privilege", []string{"AMP-1", "AMP-2", "AMP-3", "identity-configuration", "identity-capability-coverage"}},
	{"Cloud access", []string{"SEC-4", "AMP-7"}},
	{"Persistence", []string{"PER-1", "PER-2", "PER-3", "PER-4", "PER-5"}},
}

func WorkloadEvidenceCoverage(m obs.Manifest, raw []byte, r WorkloadReport) EvidenceCoverage {
	v := EvidenceCoverage{Schema: "sandprobe.evidence-coverage/1", RunID: r.RunID, UnknownControls: len(r.Unknown), Valid: r.Valid}
	if c := m.WorkloadContract; c != nil {
		v.ConfigurationGuards = []ConfigurationGuard{{"private_container", c.PrivateContainerVerified}, {"identity_configuration", c.IdentityConfigurationVerified}, {"protected_fixture", c.ProtectedFixtureVerified}}
	}
	for _, cat := range evidenceCategories {
		v.Categories = append(v.Categories, EvidenceCategory{Name: cat.name})
	}
	for _, c := range r.Controls {
		placed := false
		for i, cat := range evidenceCategories {
			if slices.Contains(cat.checks, c.ID) {
				v.Categories[i].Controls = append(v.Categories[i].Controls, c)
				placed = true
				break
			}
		}
		if !placed {
			v.Context = append(v.Context, c)
		}
	}
	remaining := slices.Clone(r.Unknown)
	gap := func(id, source, next string, ids ...string) {
		g := EvidenceGap{ID: id, Source: source, NextMeasurement: next}
		for _, k := range ids {
			if slices.Contains(remaining, k) {
				g.Controls = append(g.Controls, k)
				remaining = slices.DeleteFunc(remaining, func(s string) bool { return s == k })
			}
		}
		if len(g.Controls) > 0 {
			v.Gaps = append(v.Gaps, g)
		}
	}
	gap("image-content-evidence", "provider_or_host_configuration", "Bind the selected running image to verified immutable content; a snapshot ID/tag alone is insufficient.", "image-content-binding")
	if c := m.WorkloadContract; c != nil && !c.PrivateContainerVerified {
		gap("private-process-context", "provider_or_host_configuration", "Obtain supported private-process/container evidence. Guest observations alone are not provider verification; do not set the verification flag from public=false.", "host-context", "SEC-2", "SEC-5", "AMP-5")
	}
	gap("configuration-context", "host_configuration", "Identify which private-container, identity or protected-fixture guard lacks verification and collect that evidence.", "host-context")
	var network []string
	for _, id := range remaining {
		if strings.HasPrefix(id, "EGR-") {
			network = append(network, id)
		}
	}
	gap("network-proof", "guest_observation_and_host_receiver", "Retain transport/exchange stages, effective policy and calibrated host receipts. A connected socket or silent receiver does not establish a block.", network...)
	gap("final-receiver-collection", "host_collector", "Collect independently bound final receiver evidence and positive controls. Missing collection does not establish a provider limitation.", "private-receiver", "private-receiver-controls", "receiver-calibration", "receiver-calibration-controls", "receiver-calibration-order", "receiver-calibration-attempt")
	gap("other-required-evidence", "collector_or_configuration", "Collect the missing required measurement; unsupported or unimplemented evidence remains unknown.", slices.Clone(remaining)...)
	if d, err := obs.ParseDoc(raw); err == nil && r.Valid && r.RunID == m.RunID && r.BoxID == m.BoxID && validate(m, d) == nil {
		for _, o := range d.Observations {
			ck, known := catalog.Get(o.ID)
			if !known || !strings.HasPrefix(o.ID, "EGR-") || !slices.Contains(m.Selected, o.ID) || ck.Canary == nil || ck.Canary.Proto != "tcp" {
				continue
			}
			for _, a := range o.Attempts {
				t := "unrecognized"
				switch a.Outcome {
				case "refused", "timeout", "netunreach", "hostunreach", "eperm", "connected", "error":
					t = a.Outcome
				}
				stage, result := "unavailable", "unavailable"
				if obs.ValidExchangeDiagnostic(a.ExchangeStage, a.ExchangeResult) {
					stage, result = a.ExchangeStage, a.ExchangeResult
				}
				v.Exchanges = append(v.Exchanges, ExchangeDiagnostic{Check: o.ID, Transport: t, Stage: stage, Result: result})
			}
		}
	}
	return v
}
