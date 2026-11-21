package report

import (
	"bytes"
	"testing"

	"sandprobe/internal/grade"
)

func TestWorkloadHTMLKeepsConditionalGradeAndAssuranceSeparate(t *testing.T) {
	r := grade.WorkloadReport{ConfigurationGrade: "B", SecurityAssurance: grade.ConfigurationAssurance, MeasurementAssumption: "honest_host_shipped_unattested_probe", LegacyGrade: "F", Profile: "<script>bad</script>"}
	b, err := WorkloadHTML(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"Conditional configuration benchmark", grade.ConfigurationAssurance, "Legacy generic grade: F", "not a deployment-safety verdict"} {
		if !bytes.Contains(b, []byte(text)) {
			t.Fatal("missing grading boundary", text)
		}
	}
	if bytes.Contains(b, []byte("<script>")) {
		t.Fatal("unescaped report data")
	}
}

func TestWorkloadEvidenceHTMLKeepsCoverageSeparateAndEscaped(t *testing.T) {
	r := grade.WorkloadReport{ConfigurationGrade: "C", SecurityAssurance: grade.ConfigurationAssurance}
	v := grade.EvidenceCoverage{Gaps: []grade.EvidenceGap{{ID: "<script>bad</script>", Source: "host_collector", NextMeasurement: "Collect missing proof."}}}
	b, err := WorkloadEvidenceHTML(r, v)
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"Evidence coverage", "separate from RC's exposure score", "silence or an exchange error is not proof of blocking", "host_collector"} {
		if !bytes.Contains(b, []byte(text)) {
			t.Fatal("missing coverage boundary", text)
		}
	}
	if bytes.Contains(b, []byte("<script>bad")) {
		t.Fatal("coverage HTML injection")
	}
	old, err := WorkloadHTML(r)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(old, []byte("Evidence coverage")) {
		t.Fatal("historical mode gained new view")
	}
}
