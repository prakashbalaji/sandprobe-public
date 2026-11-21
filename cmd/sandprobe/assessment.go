package main

import (
	"fmt"

	"sandprobe/internal/analysis"
)

func assessSaved(o opts, args []string) (int, error) {
	if len(args) != 2 || args[1] != analysis.CanaryDenyProfile {
		return 0, fail("usage", "name a report and the supported assessment profile", "sandprobe assess <report.json> canary-egress-deny-v1 [-o json]", exitUsage)
	}
	d, err := analysis.Load(args[0])
	if err != nil {
		return 0, fail("report.input", "unsupported, inconsistent or unsafe report input", "Use a regular, unedited sandprobe/1 report file under 8 MiB.", exitUsage)
	}
	a, err := analysis.Assess(d, args[1])
	if err != nil {
		return 0, fail("report.input", "unsupported assessment input", "sandprobe assess <report.json> canary-egress-deny-v1", exitUsage)
	}
	if o.json() {
		o.emit(a)
	} else {
		fmt.Fprintf(o.stdout, "Retrospective assessment %s; source provider %q, run %q.\n", a.Profile, a.Provider, a.RunID)
		fmt.Fprintf(o.stdout, "Hypothetical deny-canary outcome: %s; four direct TCP routes: %s.\n", a.Outcome, a.DirectTCP)
		fmt.Fprintf(o.stdout, "Reported refusals %d/6; deliveries %d/6; inconclusive %d/6; source complete: %t.\n", a.Counts[analysis.ReportedRefusal], a.Counts[analysis.ReportedDelivery], a.Counts[analysis.Inconclusive], a.SourceComplete)
		fmt.Fprintf(o.stdout, "Saved grade %q (unverified); highest-severity finding IDs %q.\n", a.Coverage.ReportedGrade, a.LegacyDrivers)
		if a.ObservedUID != nil {
			fmt.Fprintf(o.stdout, "Observed guest UID: %d.\n", *a.ObservedUID)
		}
		for _, r := range a.Routes {
			fmt.Fprintf(o.stdout, "%s: %s — %s\n", r.CheckID, r.Result, r.Reason)
		}
		for _, area := range a.Coverage.Areas {
			fmt.Fprintf(o.stdout, "%s coverage: %v; findings %q\n", area.Name, area.Counts, area.Findings)
		}
		for _, limit := range a.Limits {
			fmt.Fprintln(o.stdout, limit)
		}
	}
	// CAL-3: uncertainty wins exit precedence without hiding a reported violation.
	if !a.SourceComplete || a.Counts[analysis.Inconclusive] > 0 {
		return exitPartial, nil
	}
	return exitBelowMin, nil // all-six-refused is impossible for current find-only checks
}
