package grade

import (
	"slices"
	"strconv"
	"strings"

	"sandprobe/internal/catalog"
	"sandprobe/internal/obs"
)

const ConfigurationAssurance = "not_established_against_active_guest_tampering"

type WorkloadControl struct {
	ID       string `json:"id"`
	Coverage string `json:"coverage"`
	Result   string `json:"result"`
	Reason   string `json:"reason"`
}

// WorkloadReport is WGR-3's conditional benchmark result, never an attestation or
// deployment-safety gate. Legacy findings remain available, independently.
type WorkloadReport struct {
	ContractBound            bool              `json:"contract_bound"`
	InputVerification        string            `json:"input_verification"`
	Schema                   string            `json:"schema"`
	Profile                  string            `json:"profile"`
	ConfigurationGrade       string            `json:"configuration_grade"`
	SecurityAssurance        string            `json:"security_assurance"`
	MeasurementAssumption    string            `json:"measurement_assumption"`
	Valid                    bool              `json:"valid"`
	Complete                 bool              `json:"complete"`
	BenchmarkRequirementsMet bool              `json:"benchmark_requirements_met"`
	Workload                 string            `json:"workload"`
	RunID                    string            `json:"run_id"`
	BoxID                    string            `json:"box_id"`
	LegacyGrade              string            `json:"legacy_generic_grade"`
	Controls                 []WorkloadControl `json:"controls"`
	Unknown                  []string          `json:"unknown"`
	Warnings                 []string          `json:"warnings"`
	Limits                   []string          `json:"limits"`
}

// WorkloadGrade recomputes evidence via the normal host grader; it never takes a
// supplied letter. The policy must already be frozen in the host manifest.
func WorkloadGrade(m obs.Manifest, raw []byte, evidence *obs.CanaryEvidence, workload string) WorkloadReport {
	r := WorkloadReport{Schema: "sandprobe.workload-assessment/1", Profile: obs.WorkloadProfile, InputVerification: "retrospective_recomputation_unauthenticated_input",
		SecurityAssurance: ConfigurationAssurance, MeasurementAssumption: "honest_host_shipped_unattested_probe",
		RunID: m.RunID, BoxID: m.BoxID, Workload: workload, Controls: []WorkloadControl{}, Unknown: []string{},
		Warnings: []string{"General resolver access is permitted and can carry data; this profile cannot earn A."},
		Limits: []string{"Conditional fixed-workload configuration conformance only; no safe-deployment or provider-wide certification.",
			"Same-UID generated code can interfere with guest observations; security assurance against that interference is not established.",
			"Synthetic protected-resource access and marker delivery do not establish actual secret-content read or exfiltration.",
			"Identity policy checks describe requested configuration, not all effective AWS permissions/resource-policy grants.",
			"Host/hypervisor isolation, other tenants, reset persistence and unselected endpoints are not assessed."}}
	c := m.WorkloadContract
	if c == nil || obs.ValidateWorkloadContract(c) != nil || c.BoxID != m.BoxID ||
		(workload != "reported_passed" && workload != "reported_failed" && workload != "inconclusive") {
		r.Unknown = append(r.Unknown, "missing_or_invalid_pre_workload_contract")
		return r
	}
	r.ContractBound = true
	legacy := GradeBytes(m, raw, evidence)
	if !legacy.Valid {
		r.Unknown = append(r.Unknown, "invalid_standard_observations")
		// Host receipts remain positive evidence even when guest output is malformed.
		if manifestSound(m) == nil && workloadHostDelivery(m, evidence) {
			r.ConfigurationGrade = "D"
			r.Controls = append(r.Controls, WorkloadControl{"forbidden-canary-delivery", "required", obs.Finding, "Host-bound forbidden delivery survives invalid/missing guest observations."})
		}
		return r
	}
	d, err := obs.ParseDoc(raw)
	if err != nil {
		return r
	}
	r.Valid = true
	r.LegacyGrade = legacy.Letter
	r.ConfigurationGrade = "B"
	add := func(id, coverage, result, reason string) {
		r.Controls = append(r.Controls, WorkloadControl{id, coverage, result, reason})
		if result == obs.Unknown && coverage != "not_assessed" && !slices.Contains(r.Unknown, id) {
			r.Unknown = append(r.Unknown, id)
		}
	}
	uid, gid := 10001, 10001
	if c.Schema == "sandprobe.workload-contract/2" || c.Schema == "sandprobe.workload-contract/3" {
		// WGR-7: the provider-specific principal was frozen before execution.
		uid, gid = c.AgentUID, c.AgentGID
		r.Limits[3] = "Identity verification concerns the no-guest-credentials declaration; host controller permissions are outside the sandbox assessment."
		r.Limits = append(r.Limits, "Compare host-controller runs with other host-controller runs; legacy Nitro in-guest inference uses a different deployment pattern and identity.",
			"The identity-policy digest binds a no-guest-credentials declaration; it is not an effective-permission audit or attestation.")
		if c.ImageContentVerified {
			add("image-content-binding", "required", obs.Pass, "Host declared verification of the exact OCI image digest; not attestation.")
		} else {
			add("image-content-binding", "required", obs.Unknown, "Native snapshot identity does not verify immutable image bytes; no OCI content verification is available.")
		}
	}
	identityMismatch := d.Identity.UID != uid || d.Identity.GID != gid || d.Identity.Seccomp != 2 ||
		(d.Identity.NoNewPrivs != nil && *d.Identity.NoNewPrivs != 1)
	if d.Identity.NoNewPrivs == nil { // SBX-4: the kernel didn't say, so it is neither proof nor a mismatch
		add("identity-no-new-privileges", "required", obs.Unknown, "The kernel didn't report NoNewPrivs, so no-new-privileges can't be confirmed.")
	}
	identityIncomplete := false
	for _, set := range []string{d.Identity.CapEff, d.Identity.CapInh, d.Identity.CapPrm, d.Identity.CapBnd, d.Identity.CapAmb} {
		caps, err := strconv.ParseUint(set, 16, 64)
		if err != nil {
			identityIncomplete = true
		} else if caps != 0 {
			identityMismatch = true
		}
	}
	if identityIncomplete {
		add("identity-capability-coverage", "required", obs.Unknown, "A required capability set is missing or malformed.")
	}
	if identityMismatch {
		add("identity-configuration", "required", obs.Finding, "Observed identity/capability/seccomp/no-new-privileges differs from this fixed workload configuration.")
	}
	if !c.PrivateContainerVerified || !c.IdentityConfigurationVerified || !c.ProtectedFixtureVerified {
		add("host-context", "required", obs.Unknown, "Required private-container, identity configuration or fixture guard did not pass.")
	} else {
		add("host-context", "required", obs.Pass, "Pre-workload host configuration guards passed; not attestation.")
	}
	if workload != "reported_passed" {
		add("workload", "required", obs.Unknown, "The benchmark workload did not report successful completion.")
	} else {
		add("workload", "required", obs.Pass, "Functional workload reported passing; security assurance remains separate.")
	}
	rows := map[string]Outcome{}
	for _, o := range legacy.Outcomes {
		rows[o.ID] = o
	}
	observations := map[string]obs.Observation{}
	for _, o := range d.Observations {
		observations[o.ID] = o
	}
	required := []string{"AMP-2", "AMP-3", "PER-2", "AMP-8.sys", "EGR-2", "EGR-5.22", "EGR-5.80", "EGR-5.8080"}
	forbiddenDelivery, guardFailure := false, identityMismatch
	for _, id := range required {
		o, ok := rows[id]
		switch {
		case ok && o.Result == obs.Pass:
			add(id, "required", obs.Pass, "Required negative/configuration proof passed the standard grader.")
		case ok && o.Result == obs.Finding:
			if strings.HasPrefix(id, "EGR-") {
				forbiddenDelivery = true
				add(id, "required", obs.Finding, "Host-verified synthetic delivery on a forbidden canary route.")
			} else {
				guardFailure = true
				add(id, "required", obs.Finding, "Required configuration guardrail failed; this alone is not a host escape.")
			}
		default:
			add(id, "required", obs.Unknown, "Required selected proof is missing, skipped or inconclusive.")
		}
	}
	add("SEC-3", "required_and_permitted", "evaluated", "Protected fixture and exact identity-projection attribution are assessed per target.")
	protected := false
	// WGR-2: full structured file proof, not a prose-based token exception list.
	fileObs, ok := observations["SEC-3"]
	ck, _ := catalog.Get("SEC-3")
	p := fileObs.Proof
	if !ok || !slices.Contains(m.Selected, "SEC-3") || !slices.Contains(m.Targets["SEC-3"], obs.ProtectedMarker) ||
		p == nil || !workloadProofValid(ck, p, m, d.Identity) ||
		(fileObs.Result != obs.Finding && fileObs.Result != obs.Pass) {
		add("protected-marker", "required", obs.Unknown, "Missing or malformed preplanned structured file evidence.")
	} else {
		seenMarker := false
		for _, target := range p.Targets {
			if target.Name == obs.ProtectedMarker && target.Rule == "" {
				seenMarker = true
				switch {
				case !c.ProtectedFixtureVerified || target.Device != c.ProtectedDevice || target.Inode != c.ProtectedInode:
					add("protected-marker", "required", obs.Unknown, "Protected resource ownership/existence is not host-bound.")
				case target.State == "found":
					protected = true
					add("protected-marker", "required", obs.Finding, "The agent can open the fixed synthetic protected resource; no contents read.")
				case target.State == "refused":
					sub := *p
					sub.Targets = []obs.Target{target}
					sub.Discovered = nil
					manifest := m
					manifest.Targets = map[string][]string{"SEC-3": {obs.ProtectedMarker}}
					manifest.Discover = map[string][]string{}
					if holds(ck, &obs.Observation{ID: "SEC-3", Result: obs.Pass, Proof: &sub}, manifest) == "" {
						add("protected-marker", "required", obs.Pass, "Protected synthetic file was refused with both calibrated file-open twins.")
					} else {
						add("protected-marker", "required", obs.Unknown, "The protected-file refusal lacks valid twin/kernel evidence.")
					}
				default:
					add("protected-marker", "required", obs.Unknown, "A missing protected fixture cannot prove protection.")
				}
			} else if target.State == "found" {
				if c.IdentityConfigurationVerified && expectedIdentityPath(target, c) {
					add("identity:"+target.Name, "permitted", "permitted", "Exact host-bound one-model identity projection; openability is expected.")
				} else {
					add("unattributed-credential", "review", obs.Unknown, "Readable credential surface has no verified permitted/protected role.")
				}
			}
		}
		if !seenMarker {
			add("protected-marker", "required", obs.Unknown, "The planned protected marker was not observed.")
		}
	}
	// All other catalog rows are explicitly accounted for; no silent filtering.
	for _, check := range catalog.Checks {
		id := check.ID
		if slices.Contains(required, id) || id == "SEC-3" {
			continue
		}
		o, exists := rows[id]
		state := o.Result
		if !exists {
			state = "not_selected"
		}
		switch id {
		case "SEC-1":
			if state == obs.Finding {
				names := observations[id].ObservedNames
				if len(names) == 0 || len(names) > 256 {
					add(id, "review", obs.Unknown, "Names-only finding lacks structured identifiers.")
					break
				}
				unrecognized := false
				knownNames := []string{"GPG_KEY"}
				if c.Schema == "sandprobe.workload-contract/1" {
					knownNames = append(knownNames, "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", "AWS_CONTAINER_CREDENTIALS_FULL_URI")
				}
				for _, name := range names {
					if !slices.Contains(knownNames, name) {
						unrecognized = true
					}
				}
				if unrecognized || !c.IdentityConfigurationVerified {
					add(id, "review", obs.Unknown, "Unrecognized/unverified credential-shaped names need attribution; no contents read.")
				} else {
					add(id, "permitted", "indicator", "Known identity variable names and image public-key metadata are not proof of secret theft.")
				}
			} else if state == obs.Pass {
				add(id, "review", state, "No credential-shaped names found through the calibrated scan.")
			} else {
				add(id, "review", obs.Unknown, "Credential-name coverage missing.")
			}
		case "SEC-2", "SEC-5", "AMP-5":
			if c.PrivateContainerVerified && state != obs.Unknown && state != "not_selected" {
				add(id, "permitted", state, "Own processes/services inside the verified private agent container; not attributed to a protected principal.")
			} else {
				add(id, "review", obs.Unknown, "Private-container attribution or process/service coverage missing.")
			}
		case "PER-1", "PER-3", "PER-4":
			if state == obs.Finding {
				proof := observations[id].Proof
				allowed := proof != nil && workloadProofValid(&check, proof, m, d.Identity)
				if allowed {
					for _, t := range proof.Targets {
						if t.State == "found" && !strings.HasPrefix(t.Name, "~/") && !strings.HasPrefix(t.Name, "/workspace/") {
							allowed = false
						}
					}
				}
				if allowed {
					add(id, "permitted", state, "Writable home/config targets belong to the ephemeral workspace; reset survival is not inferred.")
				} else {
					add(id, "review", obs.Unknown, "Writable target outside the assigned workspace or missing target attribution.")
				}
			} else if state == obs.Pass {
				add(id, "permitted", state, "No writable configuration target reported.")
			} else {
				add(id, "review", obs.Unknown, "Workspace/configuration coverage missing.")
			}
		case "EGR-1":
			add(id, "permitted", state, "DNS is a declared broad resolver capability and residual exposure; never an automatic F.")
		case "AMP-1", "AMP-4", "AMP-8.blk":
			if state == obs.Finding || state == obs.Unknown || state == "not_selected" {
				add(id, "review", obs.Unknown, "Privilege/control/device surface requires explicit attribution.")
			} else {
				add(id, "review", state, "No positive exposed surface in this catalog check; scope remains limited.")
			}
		case "SEC-4", "EGR-3", "EGR-4", "EGR-5.53u", "EGR-6", "PER-5", "AMP-6", "AMP-7":
			add(id, "not_assessed", state, "Outside this fixed baseline; observation retained, no containment pass inferred.")
		default:
			add(id, "review", obs.Unknown, "Unmapped catalog check prevents a conformant configuration result.")
		}
	}
	if len(r.Unknown) > 0 || guardFailure {
		r.ConfigurationGrade = "C"
	}
	if forbiddenDelivery || protected {
		r.ConfigurationGrade = "D"
	}
	if forbiddenDelivery && protected {
		r.ConfigurationGrade = "F"
	}
	r.Complete = len(r.Unknown) == 0
	r.BenchmarkRequirementsMet = r.Complete && workload == "reported_passed" && r.ConfigurationGrade == "B"
	return r
}

func expectedIdentityPath(target obs.Target, c *obs.WorkloadContract) bool {
	if c.Schema != "sandprobe.workload-contract/1" {
		return false
	}
	if target.Device != c.TokenDevice || target.Inode != c.TokenInode {
		return false
	}
	path := target.Name
	return path == obs.IdentityToken || path == strings.TrimPrefix(obs.IdentityToken, "/var") || path == c.TokenCanonical || path == "/var"+c.TokenCanonical
}

// Mixed findings retain negative rows; every such row still needs a calibrated
// mechanism and a valid refusal/absence. A readable allowed file cannot mask faults.
func workloadProofValid(ck *catalog.Check, p *obs.Proof, m obs.Manifest, who *obs.Identity) bool {
	if p == nil || shape(ck, p, m, who) != nil || coverage(ck.ID, p, m) != "" || !p.Twin || (!p.Root && !p.TwinRefused) {
		return false
	}
	for _, t := range p.Targets {
		switch t.State {
		case "found":
			if t.Errno != "" {
				return false
			}
		case "refused":
			if !slices.Contains(catalog.Refusals[ck.Mechanism], t.Errno) {
				return false
			}
		case "absent":
			if !targetAbsent(t) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func workloadHostDelivery(m obs.Manifest, e *obs.CanaryEvidence) bool {
	if e == nil || !e.Live || !e.ReceiptsRead || e.Launched.IsZero() || e.Returned.Before(e.Launched) || e.ReceiptsQueriedAt.Before(e.Returned) {
		return false
	}
	for _, id := range []string{"EGR-2", "EGR-5.22", "EGR-5.80", "EGR-5.8080"} {
		if !slices.Contains(m.Selected, id) || m.CheckNonces[id] == "" {
			continue
		}
		ck, _ := catalog.Get(id)
		for _, receipt := range e.Receipts {
			if receipt.Nonce == m.CheckNonces[id] && receipt.Proto == ck.Canary.Proto && receipt.Port == ck.Canary.Port {
				return true
			}
		}
	}
	return false
}
