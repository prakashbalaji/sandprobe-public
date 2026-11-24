package main

import (
	"bytes"
	"strings"
	"testing"

	"sandprobe/internal/report"
)

func TestPrintCardShowsCoverageWithoutChangingExposureScore(t *testing.T) {
	d := report.Doc{Grade: report.Grade{Valid: true}}
	for _, category := range report.Categories {
		for _, id := range category.Checks {
			result := "pass"
			if id == "SEC-4" || id == "AMP-7" {
				result = "skipped"
			}
			d.Checks = append(d.Checks, report.Check{ID: id, Result: result})
		}
	}
	var out bytes.Buffer
	printCard(opts{stdout: &out}, report.Score(d), "")
	for _, text := range []string{"Score 5/6", "5/6 categories have usable results", "skipped: SEC-4, AMP-7"} {
		if !strings.Contains(flat(out.String()), text) {
			t.Fatal("missing coverage", text)
		}
	}
	out.Reset()
	printCard(opts{stdout: &out}, report.Score(report.Doc{}), "")
	if strings.Contains(out.String(), "Coverage:") {
		t.Fatal("invalid run claims coverage")
	}
}
