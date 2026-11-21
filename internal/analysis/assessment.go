package analysis

import (
	"net"
	"strconv"

	"sandprobe/internal/catalog"
	"sandprobe/internal/obs"
	"sandprobe/internal/report"
)

const CanaryDenyProfile = "canary-egress-deny-v1"

const (
	ReportedRefusal  = "reported_refusal"
	ReportedDelivery = "reported_delivery"
	Inconclusive     = "inconclusive"
)

type RouteAssessment struct {
	CheckID string `json:"check_id"`
	Result  string `json:"result"`
	Reason  string `json:"reason"`
}

type Assessment struct {
	BoundaryContract *obs.BoundaryContract `json:"declared_boundary_context"`
	Schema           string                `json:"schema"`
	Verification     string                `json:"verification"`
	Profile          string                `json:"profile"`
	Provider         string                `json:"provider"`
	RunID            string                `json:"run_id"`
	Outcome          string                `json:"outcome"`
	DirectTCP        string                `json:"four_direct_tcp_routes"`
	SourceComplete   bool                  `json:"source_complete"`
	Counts           map[string]int        `json:"counts"`
	Routes           []RouteAssessment     `json:"routes"`
	LegacyDrivers    []string              `json:"reported_grade_driver_ids_unverified"`
	ObservedUID      *int                  `json:"observed_uid"`
	Coverage         Profile               `json:"coverage"`
	Limits           []string              `json:"limits"`
}

// Assess implements CAL-1..4. It interprets exported metadata; it does not rerun
// the host grader or authenticate a report. The profile is a hypothetical test
// requirement, never an inferred provider promise or operator policy.
func Assess(d *report.Doc, profile string) (Assessment, error) {
	if d == nil || profile != CanaryDenyProfile || Validate(d) != nil {
		return Assessment{}, ErrInput
	}
	a := Assessment{
		Schema: "sandprobe.assessment/1", Verification: "retrospective_structural_only_unauthenticated",
		Profile: profile, Provider: d.Run.Provider, RunID: d.Run.ID,
		Outcome: Inconclusive, DirectTCP: Inconclusive,
		SourceComplete: d.Grade.Valid && d.Grade.Complete && d.Identity != nil,
		Counts:         map[string]int{ReportedRefusal: 0, ReportedDelivery: 0, Inconclusive: 0},
		Routes:         []RouteAssessment{}, LegacyDrivers: []string{}, Coverage: Summarize(d),
		Limits: []string{
			"Hypothetical six-route deny-canary requirement, not a provider promise or evidence of policy bypass.",
			"Unauthenticated saved results only; raw observations, receipts and health controls are not reverified. No attestation or CI security verdict.",
			"DNS and UDP are find-only: silence cannot prove refusal. All-six requirements cannot be met by the current catalog; no overall sandbox letter is assigned.",
			"Four direct TCP routes are a subset, not all egress. Other destinations, proxies and host/hypervisor isolation are not assessed.",
			"Guest root/capabilities describe the agent's guest privileges; they alone do not establish a host escape. Namespace and process trust roles remain unverified.",
			"Process/file openability plus independent marker delivery does not prove that secret contents were read or exfiltrated.",
			"Writable startup files alone do not establish persistence across a reset. See PER-5 coverage separately.",
			"Saved legacy grades and run -min gates are unchanged; reported grade drivers are unverified, not recomputed severity judgments.",
		},
	}
	// BND-3: copied declared context, not authenticated role attribution.
	if d.Manifest.BoundaryContract != nil {
		contract := *d.Manifest.BoundaryContract
		a.BoundaryContract = &contract
	}
	a.Limits = append(a.Limits, "Boundary context is a host declaration in an unauthenticated report, not enforcement evidence or protected-resource attribution; absent context stays missing.")
	if !d.Grade.Valid {
		a.Limits = append(a.Limits, "Source run is invalid; no route assessed.")
		return a, nil
	}
	if d.Identity != nil {
		uid := d.Identity.UID
		a.ObservedUID = &uid
	}
	worst := -1
	for _, f := range d.Findings {
		s := severity(f.Severity)
		if s > worst {
			worst = s
			a.LegacyDrivers = []string{f.ID}
		} else if s == worst {
			a.LegacyDrivers = append(a.LegacyDrivers, f.ID)
		}
	}
	rows := map[string]report.Check{}
	for _, c := range d.Checks {
		rows[c.ID] = c
	}
	tcpRefusals, tcpDeliveries := 0, 0
	for _, id := range []string{"EGR-1", "EGR-2", "EGR-5.22", "EGR-5.80", "EGR-5.8080", "EGR-5.53u"} {
		r := assessRoute(rows[id], id, d.Manifest)
		a.Routes = append(a.Routes, r)
		a.Counts[r.Result]++
		if id != "EGR-1" && id != "EGR-5.53u" {
			if r.Result == ReportedRefusal {
				tcpRefusals++
			}
			if r.Result == ReportedDelivery {
				tcpDeliveries++
			}
		}
	}
	if a.Counts[ReportedDelivery] > 0 {
		a.Outcome = "reported_violation"
	}
	if tcpDeliveries > 0 {
		a.DirectTCP = "reported_violation"
	} else if tcpRefusals == 4 {
		a.DirectTCP = "reported_four_route_requirements_met"
	}
	return a, nil
}

func assessRoute(c report.Check, id string, manifest obs.Manifest) RouteAssessment {
	r := RouteAssessment{CheckID: id, Result: Inconclusive, Reason: "No exported negative proof or delivery for this required route."}
	found := false
	for _, s := range manifest.Selected {
		found = found || s == id
	}
	cat, ok := catalog.Get(id)
	if !ok || cat.Canary == nil || !found || c.Scope == nil || c.Scope.Port != strconv.Itoa(cat.Canary.Port) || c.Scope.Route != cat.Canary.Route || c.Proof == nil || c.Proof.Mechanism != "canary" || c.Proof.Result != c.Result {
		return r
	}
	if net.ParseIP(c.Scope.Destination) == nil || manifest.CheckNonces[id] == "" || manifest.Endpoints[id] != net.JoinHostPort(c.Scope.Destination, c.Scope.Port) {
		return r
	}
	if c.Result == obs.Finding && c.EvidenceClass == "proof" {
		r.Result, r.Reason = ReportedDelivery, "Saved report records delivery of this route's harmless marker to the canary."
	} else if c.Result == obs.Pass && cat.Kind == catalog.TwoSided {
		r.Result, r.Reason = ReportedRefusal, "Saved report records a refusal with canary proof metadata; underlying controls not reverified offline."
	}
	return r
}
