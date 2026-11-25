package main

import (
	"fmt"
	"io"
	"slices"
	"strings"

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
			fmt.Fprintf(o.stdout, "Provider %q. Structural analysis only; no attestation.\n", p.Provider)
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

// printComparison is CMP-1's and CMP-2's result in plain words, each check named by its category and question (SCR-3),
// every line within UX-9's 80 columns, in ASCII under a C or POSIX locale.
func printComparison(o opts, c analysis.Comparison) {
	// An item reads "Secrets › question": never "Secrets: ", which reads as a credential key (FBK-4).
	bullet, sep, arrow := "●", glyphsFor(false).sep, "→"
	if asciiLocale() {
		bullet, sep, arrow = "*", glyphsFor(true).sep, "->"
	}
	say := func(text string) { printWrapped(o.stdout, "", text, "", "") }
	list := func(title string, ids []string) {
		if len(ids) == 0 {
			say(title + ": none")
			return
		}
		say(title + ":")
		for _, id := range ids {
			text := fmt.Sprintf("%q", id)
			if cat, ok := report.CategoryOf(id); ok {
				text = cat.Name + " " + sep + " " + cat.Ask[id]
			}
			var b strings.Builder
			writeWrapped(&b, "  "+bullet+" ", "    ", text, maxTUIWidth, "", "")
			io.WriteString(o.stdout, b.String())
		}
	}
	fmt.Fprintln(o.stdout)
	list("Got worse", c.NewOrWorse)
	list("No longer tested", c.CoverageLoss)
	list("Got better", c.GotBetter)
	if len(c.NoLongerApplies) > 0 { // KND-1: never called better
		list("No longer applies (nothing left for it to check)", c.NoLongerApplies)
	}
	if len(c.NotProven) > 0 { // KND-2: never called better
		list("No longer found, but not proven", c.NotProven)
	}
	switch b, a := c.ScoreBefore, c.ScoreAfter; {
	case b != nil && a != nil:
		say(fmt.Sprintf("Score: %d/%d %s %d/%d", b.Score, b.Of, arrow, a.Score, a.Of))
	case b == nil && a == nil:
		say("No score: both reports' runs are invalid, so neither has one (GRD-5).")
	case b == nil:
		say("No score: the before report's run is invalid, so it has none (GRD-5).")
	default:
		say("No score: the after report's run is invalid, so it has none (GRD-5).")
	}
	if len(c.ContextChanges) > 0 {
		say(fmt.Sprintf("Setup differs, so the two aren't a like-for-like pair: %q", c.ContextChanges))
	}
	if slices.Contains(c.ContextChanges, "identity") {
		say("The agent's identity differs: its user, group, capabilities or privilege settings. That's expected when the fix was to change the agent's user or drop its privileges, but the two reports still measured different identities.")
	}
	worse := len(c.NewOrWorse) > 0 || len(c.CoverageLoss) > 0
	switch {
	case worse:
		fmt.Fprintln(o.stdout)
		say("Verdict: worse. A gate should fail this change.")
	case c.NoObservedChange && !c.Incomplete:
		fmt.Fprintln(o.stdout)
		say("Verdict: no change in what was tested.")
	}
	if c.Incomplete { // CMP-1: exit 5 outranks 6; a gate fails on any nonzero exit
		say("Some checks couldn't be proven in at least one report, so an all-clear here wouldn't count either.")
	}
	say("This compares the two reports only; it doesn't vouch for either box.")
	say(report.SavedNote)
}
