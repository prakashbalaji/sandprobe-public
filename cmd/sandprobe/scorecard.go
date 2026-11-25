package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf8"

	"sandprobe/internal/analysis"
	"sandprobe/internal/report"
)

// scorecard is SCR-3 offline: one saved report's headline, and its page re-rendered only when -out is given.
func scorecard(o opts, r runFlags, args []string) (int, error) {
	if len(args) != 1 {
		return 0, fail("usage", "name one saved report file", "sandprobe scorecard <report.json> [-out <dir>]", exitUsage)
	}
	d, err := analysis.Load(args[0])
	if err != nil {
		return 0, fail("report.input", "unsupported, inconsistent or unsafe report input", reportInputFix, exitUsage)
	}
	card := report.Score(*d)
	card.Verification = report.SavedVerification // ANL-1: a saved report is never re-verified
	if r.outSet {
		page, err := report.SavedHTML(*d, r.theme)
		if err != nil {
			return 0, err
		}
		if err := writeInside(r.outDir, reportFile(d.Run.Provider, d.Run.ID), page); err != nil {
			return 0, fail("report.output", "couldn't write the page inside "+r.outDir+": "+err.Error(), "choose an -out directory you own", exitUsage)
		}
	}
	if o.json() {
		o.emit(card)
	} else {
		printCard(o, card, d.Statement)
		fmt.Fprintln(o.stdout)
		printWrapped(o.stdout, "", report.SavedNote, "", "")
	}
	if !d.Grade.Valid || !d.Grade.Complete {
		return exitPartial, nil
	}
	return exitGraded, nil
}

// reportInputFix is the fix for a saved report this build refuses (ANL-1): it names the versions this build reads,
// so a report from a newer sandprobe says what it needs (AGT-6).
var reportInputFix = "Use a regular, unedited " + strings.Join(report.Schemas, " or ") + " report file under 8 MiB; a report that declares a later schema needs a newer sandprobe."

// A saved report is unauthenticated input (ANL-1): its provider and run ID name the page only when each is a plain
// name, never a path, and anything else gets a fixed name.
var (
	safeProvider = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}(\.[a-z0-9-]{1,20})?$`)
	safeRunID    = regexp.MustCompile(`^r[0-9a-f]{8,64}$`)
)

func reportFile(provider, id string) string {
	if safeProvider.MatchString(provider) && safeRunID.MatchString(id) {
		return "sandprobe-" + provider + "-" + id + ".html"
	}
	return "sandprobe-report.html"
}

// writeInside writes name, a plain file name, inside dir and nowhere else: never through a symlink already there.
func writeInside(dir, name string, data []byte) error {
	if name != filepath.Base(name) || name == "." || name == ".." {
		return fmt.Errorf("not a plain file name")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// printable is text from a box, CLI argument or saved report made safe for a terminal: every control character
// (ESC included), Unicode format character (category Cf: bidi overrides/isolates, ALM, zero-width, BOM) and line or
// paragraph separator is shown escaped, so untrusted text cannot move the cursor, recolor, reorder or hide output.
func printable(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) {
			if r <= 0xFFFF {
				fmt.Fprintf(&b, "\\u%04x", r)
			} else {
				fmt.Fprintf(&b, "\\U%08x", r)
			}
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// asciiLocale says the terminal's locale is C or POSIX (UX-9): the first of LC_ALL, LC_CTYPE and LANG that is set.
func asciiLocale() bool {
	for _, k := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return strings.EqualFold(v, "C") || strings.EqualFold(v, "POSIX")
		}
	}
	return false
}

// printCard writes the headline: the score, then one line per category, green, green not proven, red or not
// applicable (SCR-2).
func printCard(o opts, c report.Card, statement string) {
	green, unproven, red, reset := "", "", "", ""
	if detectTermCaps(o.stdout, false).color { // UX-9: a terminal, and neither NO_COLOR nor TERM=dumb
		green, unproven, red, reset = "\x1b[1;32m", "\x1b[32m", "\x1b[1;31m", "\x1b[0m"
	}
	redDot, greenDot, naDot := "●", "●", "●"
	gnpDot, gnpMark := "◌", "GREEN · NOT PROVEN"
	if asciiLocale() { // UX-9: ASCII symbols, as the run's summary uses
		redDot, greenDot, naDot = "x", "+", "-"
		gnpDot, gnpMark = "o", "GREEN . NOT PROVEN"
	}
	const indent = "                         " // 25 columns: where a row's other lines start
	w := o.stdout
	if !c.Valid {
		fmt.Fprintf(w, "\nScore: none (invalid run)\n")
		return
	}
	fmt.Fprintf(w, "\nScore %d/%d\n", c.Score, c.Of)
	for _, line := range c.NotCounted() {
		printWrapped(w, "", printable(line), "", "")
	}
	fmt.Fprintln(w)
	if c.Coverage != nil {
		printWrapped(w, "", printable(c.Coverage.Description()), "", "")
	}
	for _, row := range c.Rows {
		dot, mark, color := redDot, "RED  ", red
		switch {
		case row.Green && row.GreenNotProven: // SCR-2, UX-9: its own symbol and words, never plain GREEN
			dot, mark, color = gnpDot, gnpMark, unproven
		case row.Green:
			dot, mark, color = greenDot, "GREEN", green
		case row.NotApplicable: // SCR-2: never green, and out of the score
			dot, mark, color = naDot, "N/A  ", ""
		}
		if utf8.RuneCountInString(fmt.Sprintf("  %s %s  %-13s %s", dot, mark, row.Name, row.Question)) <= 80 {
			fmt.Fprintf(w, "  %s%s %s%s  %-13s %s\n", color, dot, mark, reset, row.Name, row.Question)
		} else { // UX-9: within 80 columns, the question moves under the row, where its other lines start
			fmt.Fprintf(w, "  %s%s %s%s  %s\n  %-22s %s\n", color, dot, mark, reset, row.Name, "", row.Question)
		}
		if row.Why != "" { // a not-applicable reason is the report's own skip reason: escaped like its other text
			printWrapped(w, indent, printable(row.Why), color, reset)
		}
		if row.NotProven != "" {
			printWrapped(w, indent, printable(row.NotProven), "", "")
		}
		if row.Coverage != nil {
			printWrapped(w, indent, printable(row.Coverage.Description()), "", "")
		}
	}
	if statement != "" {
		fmt.Fprintln(w)
		printWrapped(w, "", printable(statement), "", "")
	}
}

// printWrapped writes already-escaped text within UX-9's 80 columns, each line starting at indent.
func printWrapped(w io.Writer, indent, text, col, reset string) {
	var b strings.Builder
	writeWrapped(&b, indent, indent, text, maxTUIWidth, col, reset)
	_, _ = io.WriteString(w, b.String())
}
