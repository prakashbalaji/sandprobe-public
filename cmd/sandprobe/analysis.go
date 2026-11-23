package main

import (
	"fmt"
	"sandprobe/internal/analysis"
	"sandprobe/internal/report"
)

func offline(o opts, args []string, compare bool) (int, error) {
	n := 1
	if compare {
		n = 2
	}
	if len(args) != n {
		return 0, fail("usage", "name the saved report file(s)", "sandprobe profile <report.json>; sandprobe compare <before.json> <after.json>", exitUsage)
	}
	a, err := analysis.Load(args[0])
	if err != nil {
		return 0, fail("report.input", "unsupported, inconsistent or unsafe report input", reportInputFix, exitUsage)
	}
	if !compare {
		p := analysis.Summarize(a)
		if o.json() {
			o.emit(p)
		} else {
			fmt.Fprintf(o.stdout, "Provider %q; reported grade %q (unverified). Structural analysis only; no attestation.\n", p.Provider, p.ReportedGrade)
			for _, area := range p.Areas {
				fmt.Fprintf(o.stdout, "%s: %v; finding IDs %q\n", area.Name, area.Counts, area.Findings)
			}
			for _, limit := range p.Limits {
				fmt.Fprintln(o.stdout, limit)
			}
			fmt.Fprintln(o.stdout, report.SavedNote)
		}
		if !p.Valid || !p.Complete {
			return exitPartial, nil
		}
		return exitGraded, nil
	}
	b, err := analysis.Load(args[1])
	if err != nil {
		return 0, fail("report.input", "unsupported, inconsistent or unsafe report input", reportInputFix, exitUsage)
	}
	c := analysis.Compare(a, b)
	if o.json() {
		o.emit(c)
	} else {
		printComparison(o, c)
	}
	if c.Incomplete || len(c.ContextChanges) > 0 {
		return exitPartial, nil
	}
	if len(c.NewOrWorse) > 0 || len(c.CoverageLoss) > 0 {
		return exitBelowMin, nil
	}
	return exitGraded, nil
}

// printComparison is CMP-1's result in plain words, each check named by its category and question (SCR-3).
func printComparison(o opts, c analysis.Comparison) {
	list := func(title string, ids []string) {
		if len(ids) == 0 {
			fmt.Fprintf(o.stdout, "%s: none\n", title)
			return
		}
		fmt.Fprintf(o.stdout, "%s:\n", title)
		for _, id := range ids {
			if cat, ok := report.CategoryOf(id); ok {
				fmt.Fprintf(o.stdout, "  ● %s: %s\n", cat.Name, cat.Ask[id])
			} else {
				fmt.Fprintf(o.stdout, "  ● %q\n", id)
			}
		}
	}
	fmt.Fprintln(o.stdout)
	list("Got worse", c.NewOrWorse)
	list("No longer tested", c.CoverageLoss)
	if len(c.ContextChanges) > 0 {
		fmt.Fprintf(o.stdout, "Setup differs, so the two aren't a like-for-like pair: %q\n", c.ContextChanges)
	}
	worse := len(c.NewOrWorse) > 0 || len(c.CoverageLoss) > 0
	switch {
	case worse:
		fmt.Fprintln(o.stdout, "\nVerdict: worse. A gate should fail this change.")
	case c.NoObservedChange && !c.Incomplete:
		fmt.Fprintln(o.stdout, "\nVerdict: no change in what was tested.")
	}
	if c.Incomplete { // CMP-1: exit 5 outranks 6; a gate fails on any nonzero exit
		fmt.Fprintln(o.stdout, "Some checks couldn't be proven in at least one report, so an all-clear here wouldn't count either.")
	}
	fmt.Fprintln(o.stdout, "This compares the two reports only; it doesn't vouch for either box.")
	fmt.Fprintln(o.stdout, report.SavedNote)
}
