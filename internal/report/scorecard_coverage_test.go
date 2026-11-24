package report

import (
	"encoding/json"
	"strings"
	"testing"

	"sandprobe/internal/grade"
	"sandprobe/internal/obs"
)

func TestCoverageNeverEquatesSixGreenWithSixComplete(t *testing.T) {
	d := doc(obs.Skipped, nil)
	// One proven check per category is enough for SCR-2, not full coverage.
	for i := range d.Checks {
		for _, cat := range Categories {
			if d.Checks[i].ID == cat.Checks[0] {
				d.Checks[i].Result = obs.Pass
			}
		}
	}
	c := Score(d)
	if c.Score != 6 || c.Coverage == nil || c.Coverage.Complete || c.Coverage.CompleteCategories != 0 || c.Coverage.CategoriesWithResults != 6 {
		t.Fatalf("six green falsely implies full coverage: %+v", c)
	}
	if !validCardCoverage(c) {
		t.Fatal("computed coverage invalid")
	}
	for _, row := range c.Rows {
		if len(row.Coverage.Skipped) == 0 || row.Coverage.Conclusive != 1 {
			t.Fatal("lost skipped checks")
		}
	}
}

func TestCoverageCloudSkippedIsNotMeasuredAndUnknownWins(t *testing.T) {
	d := doc(obs.Pass, map[string]Check{
		"SEC-4": {Result: obs.Skipped}, "AMP-7": {Result: obs.Skipped},
		"AMP-1": {Result: obs.NotFound}, "PER-5": {Result: obs.ScopedOut},
		"EGR-2": {Result: obs.Finding, Severity: "high"},
	})
	d.Grade.Unknown = []string{"EGR-2", "AMP-8.blk"}
	var kept []Check
	for _, ck := range d.Checks {
		if ck.ID != "AMP-8.blk" {
			kept = append(kept, ck)
		}
	}
	d.Checks = kept
	c := Score(d)
	if c.Score != 3 || c.Coverage.CategoriesWithResults != 5 || c.Coverage.CompleteCategories != 1 || c.Coverage.Complete {
		t.Fatalf("wrong partial coverage %+v", c.Coverage)
	}
	cloud := row(t, c, "Cloud access").Coverage
	if cloud.UsableResults != 0 || cloud.Conclusive != 0 || len(cloud.Skipped) != 2 {
		t.Fatal("skipped cloud counted as tested")
	}
	if r := row(t, c, "Exfiltration"); len(r.Coverage.Unknown) != 1 || len(r.Coverage.Findings) != 0 {
		t.Fatal("unknown did not dominate finding")
	}
	if r := row(t, c, "Containment"); len(r.Coverage.Unknown) != 1 || len(r.Coverage.Missing) != 0 {
		t.Fatal("grading unknown must dominate missing row")
	}
	if !validCardCoverage(c) {
		t.Fatal("computed coverage invalid")
	}
}

func TestCoverageCompleteCanHaveFindingsAndNoSecurityPass(t *testing.T) {
	c := Score(doc(obs.Finding, nil))
	if c.Score != 0 || !c.Coverage.Complete || c.Coverage.CompleteCategories != 6 {
		t.Fatal("findings must complete measurement without green exposure")
	}
	for _, row := range c.Rows {
		if row.Coverage.Conclusive != row.Coverage.Total || len(row.Coverage.Proven) != 0 {
			t.Fatal("finding relabeled proof")
		}
	}
}

func TestCoveragePartitionsMissingAndMalformedWithoutBoxText(t *testing.T) {
	d := doc(obs.Pass, map[string]Check{"SEC-1": {Result: "box-secret-string"}, "EGR-4": {Result: obs.NotFound}, "AMP-1": {Result: obs.Absent}})
	var kept []Check
	for _, ck := range d.Checks {
		if ck.ID != "SEC-5" {
			kept = append(kept, ck)
		}
	}
	d.Checks = kept
	c := Score(d)
	r := row(t, c, "Secrets").Coverage
	if len(r.Unknown) != 1 || len(r.Missing) != 1 || r.Complete {
		t.Fatal("missing/malformed not retained")
	}
	if len(row(t, c, "Exfiltration").Coverage.Unproven) != 1 {
		t.Fatal("Info-only not-found still lacks proof")
	}
	b, _ := json.Marshal(c)
	if strings.Contains(string(b), "box-secret-string") {
		t.Fatal("coverage leaked box text")
	}
	if !validCardCoverage(c) {
		t.Fatal("computed coverage invalid")
	}
}

func TestCoverageInvalidAndHistoricalNeverGainCompleteStatus(t *testing.T) {
	if c := Score(Doc{}); c.Coverage != nil || len(c.Rows) != 0 {
		t.Fatal("invalid run claims coverage")
	}
	c := Score(doc(obs.Pass, nil))
	c.Coverage = nil
	for i := range c.Rows {
		c.Rows[i].Coverage = nil
	}
	x := WorkloadExposure{Schema: "sandprobe.workload-exposure/1", InputVerification: "proof_recomputation_unauthenticated_input", Card: c}
	if !validWorkloadExposure(x) {
		t.Fatal("historical scorecard rejected")
	}
	b, err := WorkloadExposureHTML(grade.WorkloadReport{}, grade.EvidenceCoverage{}, x)
	if err != nil || !strings.Contains(string(b), "Coverage unavailable for this historical scorecard") {
		t.Fatal("historical coverage invented", err)
	}
}

func TestCoverageRendererRejectsForgedCountsAndPartitions(t *testing.T) {
	for _, mutate := range []func(*Card){
		func(c *Card) { c.Coverage.CompleteCategories++ },
		func(c *Card) { c.Rows[0].Coverage.Conclusive-- },
		func(c *Card) { c.Rows[0].Coverage.Proven[0] = "AMP-7" },
		func(c *Card) { c.Rows[0].Coverage.Proven[1] = c.Rows[0].Coverage.Proven[0] },
		func(c *Card) { c.Rows[0].Coverage = nil },
		func(c *Card) { c.Coverage = nil },
	} {
		c := Score(doc(obs.Pass, nil))
		mutate(&c)
		x := WorkloadExposure{Schema: "sandprobe.workload-exposure/1", InputVerification: "proof_recomputation_unauthenticated_input", Card: c}
		if validWorkloadExposure(x) {
			t.Fatal("forged coverage accepted")
		}
	}
}

func TestCoverageVisibleInHTML(t *testing.T) {
	d := doc(obs.Pass, map[string]Check{"SEC-4": {Result: obs.Skipped}, "AMP-7": {Result: obs.Skipped}})
	c := Score(d)
	x := WorkloadExposure{Schema: "sandprobe.workload-exposure/1", InputVerification: "proof_recomputation_unauthenticated_input", Card: c}
	b, err := WorkloadExposureHTML(grade.WorkloadReport{}, grade.EvidenceCoverage{}, x)
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"5/6 categories have usable results", "skipped: SEC-4, AMP-7", "Coverage is separate from the exposure score"} {
		if !strings.Contains(string(b), text) {
			t.Fatal("missing coverage", text)
		}
	}
	b, err = HTML(d, "")
	if err != nil || !strings.Contains(string(b), "5/6 categories have usable results") {
		t.Fatal("standard HTML missing coverage", err)
	}
}

// SCR-5: derived display additions cannot make a previously valid v1 record unreadable.
func TestSavedExposureCoverageWithoutNewDisplayFields(t *testing.T) {
	x := WorkloadExposure{Schema: "sandprobe.workload-exposure/1", InputVerification: "proof_recomputation_unauthenticated_input", Card: Score(doc(obs.NotFound, nil))}
	// Keep actual coverage in the record: historical coverage-free cases alone
	// cannot catch a newly required presentation flag on a green/unproven row.
	found := false
	for _, r := range x.Rows {
		if r.Green && r.Coverage != nil && r.Coverage.Conclusive == 0 {
			found = true
		}
	}
	if !found {
		t.Fatal("fixture needs a green row without conclusive evidence")
	}
	b, err := json.Marshal(x)
	if err != nil {
		t.Fatal(err)
	}
	var legacy map[string]json.RawMessage
	if err := json.Unmarshal(b, &legacy); err != nil {
		t.Fatal(err)
	}
	var rows []map[string]json.RawMessage
	if err := json.Unmarshal(legacy["rows"], &rows); err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		delete(r, "green_not_proven")
	}
	legacy["rows"], err = json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	b, err = json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	var restored WorkloadExposure
	if err := json.Unmarshal(b, &restored); err != nil {
		t.Fatal(err)
	}
	if !validWorkloadExposure(restored) {
		t.Fatal("historical v1 coverage requires a new display field")
	}
	if _, err := WorkloadExposureHTML(grade.WorkloadReport{}, grade.EvidenceCoverage{}, restored); err != nil {
		t.Fatal("historical v1 exposure no longer renders:", err)
	}
}

func TestHistoricalDisplayFlagIsDerivedWithoutMutatingInput(t *testing.T) {
	c := Score(doc(obs.NotFound, nil))
	for i := range c.Rows {
		c.Rows[i].GreenNotProven = false
	}
	x := WorkloadExposure{Schema: "sandprobe.workload-exposure/1", InputVerification: "proof_recomputation_unauthenticated_input", Card: c}
	b, err := WorkloadExposureHTML(grade.WorkloadReport{}, grade.EvidenceCoverage{}, x)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "Green · not proven") && !strings.Contains(string(b), "GREEN · NOT PROVEN") {
		t.Fatal("historical row did not gain derived unproven label")
	}
	for _, r := range x.Rows {
		if r.GreenNotProven {
			t.Fatal("render changed caller's saved card")
		}
	}
	// A supplied positive flag that contradicts valid coverage remains invalid.
	c = Score(doc(obs.Pass, nil))
	c.Rows[0].GreenNotProven = true
	x.Card = c
	if validWorkloadExposure(x) {
		t.Fatal("contradictory supplied flag accepted")
	}
}
