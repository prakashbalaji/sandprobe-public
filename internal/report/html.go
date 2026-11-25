package report

import (
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"fmt"
	"html"
	"html/template"
	"math"
	"sort"
	"strings"
	"time"

	"sandprobe/internal/catalog"
	"sandprobe/internal/obs"
)

//go:embed report.html
var page string

var tmpl = template.Must(template.New("report").Parse(page))

type card struct {
	ID, Title, Cat, SevLabel, SevClass, Gets, Evidence, Reason, Fix, Class, Mark string
	Parts                                                                        []string
}

type group struct {
	Name   string
	Checks []card
}

type view struct {
	Nonce, Theme, Provider, Box, When, Lead, Statement, Boundary, Invalid string // SCR-3: no letter grade
	Complete, Valid                                                       bool
	Passed, Unknown, NotProvenN                                           int
	Map                                                                   template.HTML
	Findings, Unknowns, NotProven                                         []card
	Passes                                                                []group
	Skipped, Identity, Hosts, Markers, Reset, Calls, Attested             [][2]string
	ScopedOut, NotTested, Notes                                           []string
	Cleanup, Residual, Saved                                              string
	Data                                                                  Doc
	Card                                                                  Card // SCR-3: the headline
	Cats                                                                  []catView
	Chains                                                                []chain
	Groups                                                                []sevGroup // SCR-3: What to fix
	Rest                                                                  []test     // SCR-3: passed, or not proven
	RestLabel, Version                                                    string
	Strip                                                                 []stat
}

// catView is one of the six rows (SCR-2) with "x/y tests run" and a link to each of its tests (SCR-3).
type catView struct {
	Row
	Num        string
	Run, Total int
	Tests      []test
}

// sevGroup is one group of What to fix (SCR-3): a severity's failures, a chain's sentence first, or the unknowns.
type sevGroup struct {
	Key, Name, Word string
	Rows            []test
}

// stat is one cell of the strip beside the score, counted from the rows the page shows (SCR-3).
type stat struct {
	N            int
	Label, Class string
}

type test struct {
	ID, Ask, Result, Class, Detail, Fix, Sev, Cat, Would string
	Attested                                             string   // PRV-15: the person's attestation, beside the check
	Parts                                                []string // a chain's checks, each linked to its row
	order                                                int
}

type chain struct{ Sev, Text string }

// chainText says what each chain means, in plain words; a potential one says "may".
var chainText = map[string][2]string{
	"CHN-1": {"The agent can open a credential and send data out of the box, so a hijacked agent could steal it.",
		"The agent may be able to open a credential and send data out of the box, so a hijacked agent might steal it."},
	"CHN-2": {"The agent can become root, so every block above holds only against an agent that isn't root.",
		"The agent may be able to become root, so the blocks above may hold only against an agent that isn't root."},
	"CHN-3": {"The agent can read a Kubernetes token and reach the Kubernetes API, so it could act as the box's account.",
		"The agent may be able to read a Kubernetes token and reach the Kubernetes API, and act as the box's account."},
}

// ChainSentence returns the plain-English sentence for a chain ID (SCR-3, UX-6), or "" when id isn't a known chain.
func ChainSentence(id string, potential bool) string {
	t, ok := chainText[id]
	if !ok {
		return ""
	}
	if potential {
		return t[1]
	}
	return t[0]
}

// answer is one check's result as Pass, Fail or a plainer word when it is neither, never more than the result proves
// (AGENTS.md rule 1: a pass needs a negative proof). top says it belongs above the fold.
func answer(ck Check, ok bool) (result, class, detail string, top bool) {
	switch {
	case !ok:
		return "Not run", "grey", "not part of this run", false
	case ck.Result == obs.Skipped:
		return "Not run", "grey", ck.Reason, false
	case ck.Result == obs.Finding && ck.Severity == "info":
		return "Info", "grey", ck.Evidence, false
	case ck.Result == obs.Finding && ck.EvidenceClass == "indicator":
		return "Fail", "red", ck.Evidence + " (a sign we saw, not something we confirmed)", true
	case ck.Result == obs.Finding:
		if cat, ok := catalog.Get(ck.ID); ok && cat.Canary != nil { // the receipt, in words, from the catalog alone
			return "Fail", "red", "a tagged test message from the box reached our server over " + via(*cat.Canary), true
		}
		return "Fail", "red", ck.Evidence, true
	case ck.Result == obs.Pass:
		return "Pass", "green", "confirmed: we proved it, not just failed to see it", false
	case ck.Result == obs.Absent:
		return "Pass", "green", "there isn't one", false
	case ck.Result == obs.ScopedOut: // neither a refusal nor an absence: nothing was there to test
		return "N/A", "grey", "nothing like it is visible to the agent", false
	case ck.Result == obs.NotFound:
		return "No finding", "grey", "nothing turned up, though that doesn't prove there's none", false
	}
	return "Unknown", "amber", ck.Reason, true
}

// worst is a check's highest possible severity: what a failure here would have been.
func worst(id string) string {
	ck, ok := catalog.Get(id)
	if !ok {
		return ""
	}
	w := catalog.Info
	for _, v := range ck.Variants {
		w = max(w, v.Severity)
	}
	return w.String()
}

var sevOrder = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
var restOrder = map[string]int{"Pass": 0, "Info": 1, "N/A": 2, "No finding": 3, "Not run": 4}

// failGroups are What to fix's severities, worst first (SCR-3).
var failGroups = [][2]string{{"critical", "Critical"}, {"high", "High"}, {"medium", "Medium"}, {"low", "Low"}}

// via names a canary route in words.
func via(c catalog.Canary) string {
	switch {
	case c.Proto == "dns":
		return "a DNS lookup"
	case c.Proto == "tcp" && c.Port == 443:
		return "HTTPS"
	}
	return fmt.Sprintf("%s port %d", strings.ToUpper(c.Proto), c.Port)
}

// fixList builds SCR-3's page below the score: the six rows, each with its tests, then What to fix, where every test
// appears exactly once. Failures group by severity, each chain's sentence first in its own; unknowns follow on their
// own, never folded in with the passes; the rest fold away. A failure whose severity isn't one of the four (only an
// edited report has one) still shows, in a group of its own, so no test is ever dropped.
func fixList(d Doc, c Card) (cats []catView, groups []sevGroup, rest []test, restLabel string) {
	got := map[string]Check{}
	for _, ck := range d.Checks {
		got[ck.ID] = ck
	}
	bySev := map[string][]test{}
	for _, f := range d.Findings {
		if t, ok := chainText[f.ID]; ok {
			text := t[0]
			if f.Potential {
				text = t[1]
			}
			bySev[f.Severity] = append(bySev[f.Severity], test{ID: f.ID, Ask: text, Result: "Fail", Class: "red", Fix: f.Fix,
				Sev: f.Severity, Cat: "Chain", Parts: f.Checks})
		}
	}
	var unknown []test
	counts := map[string]int{}
	for i, cat := range Categories {
		cv := catView{Row: c.Rows[i], Num: fmt.Sprintf("%d", i+1), Total: len(cat.Checks)}
		for _, id := range cat.Checks {
			ck, ok := got[id]
			t := test{ID: id, Ask: cat.Ask[id], Sev: worst(id), Attested: ck.Attestation, Cat: cat.Name}
			var top bool
			t.Result, t.Class, t.Detail, top = answer(ck, ok)
			// SCR-6: scope discovery alone is not an executed access test.
			if ok && ck.Result != obs.Skipped && ck.Result != obs.ScopedOut {
				cv.Run++
			}
			if t.Sev != "" { // for a test that didn't fail, what a failure would have been
				t.Would = "would be " + t.Sev
			}
			switch {
			case t.Result == "Fail":
				t.Fix, t.Sev, t.Would = ck.Fix, ck.Severity, ""
				bySev[t.Sev] = append(bySev[t.Sev], t)
			case top: // what couldn't be told, worst first
				t.order = sevOrder[t.Sev]
				unknown = append(unknown, t)
			default:
				t.order = restOrder[t.Result]
				counts[t.Result]++
				rest = append(rest, t)
			}
			cv.Tests = append(cv.Tests, t)
		}
		cats = append(cats, cv)
	}
	for _, g := range failGroups {
		if rows := bySev[g[0]]; len(rows) > 0 {
			groups = append(groups, sevGroup{Key: g[0], Name: g[1], Word: "failing", Rows: rows})
		}
		delete(bySev, g[0])
	}
	var odd []string
	for sev := range bySev {
		odd = append(odd, sev)
	}
	sort.Strings(odd)
	var unrated []test
	for _, sev := range odd {
		unrated = append(unrated, bySev[sev]...)
	}
	if len(unrated) > 0 {
		groups = append(groups, sevGroup{Key: "unrated", Name: "Unrated", Word: "failing, with no known severity", Rows: unrated})
	}
	if len(unknown) > 0 {
		sort.SliceStable(unknown, func(a, b int) bool { return unknown[a].order < unknown[b].order })
		groups = append(groups, sevGroup{Key: "unknown", Name: "Unknown", Word: "couldn't be told either way, never a pass", Rows: unknown})
	}
	sort.SliceStable(rest, func(a, b int) bool { return rest[a].order < rest[b].order })
	var parts []string
	for _, r := range []string{"Pass", "Info", "N/A", "No finding", "Not run"} {
		if n := counts[r]; n > 0 {
			word := map[string]string{"Pass": "passed", "Info": "informational", "N/A": "with nothing to test",
				"No finding": "with no finding", "Not run": "not run"}[r]
			parts = append(parts, fmt.Sprintf("%d %s", n, word))
		}
	}
	return cats, groups, rest, "Show " + strings.Join(parts, ", ")
}

// strip is SCR-3's line beside the score: each failing severity, the passes and the unknowns, counted from the rows.
func strip(groups []sevGroup, rest []test) []stat {
	var out []stat
	unknown := 0
	for _, g := range groups {
		if g.Key == "unknown" {
			unknown = len(g.Rows)
			continue
		}
		out = append(out, stat{N: len(g.Rows), Label: strings.ToLower(g.Name) + " failing", Class: "red"})
	}
	if len(out) == 0 {
		out = append(out, stat{Label: "failing"})
	}
	passed := stat{Label: "passed"}
	for _, t := range rest {
		if t.Result == "Pass" {
			passed.N, passed.Class = passed.N+1, "green"
		}
	}
	gap := stat{N: unknown, Label: "unknown"}
	if unknown > 0 { // dashed, never green, and only when there is one to see
		gap.Class = "unk"
	}
	return append(out, passed, gap)
}

var catName = map[string]string{"SEC": "Secrets", "EGR": "Ways out", "PER": "Persistence", "AMP": "Amplifiers"}

func sevClass(s string) string {
	switch s {
	case "critical", "high":
		return "crit"
	case "medium":
		return "med"
	}
	return "low"
}

// SavedNote is ANL-1's plain statement on every offline rendering of a saved report.
const SavedNote = "From a saved report: structurally checked only. Its observations and canary receipts weren't re-verified, and an edited report can't be told apart (ANL-1)."

// SavedHTML is OUT-2 re-rendered from a saved report (SCR-3's -out): the same page, saying it wasn't re-verified. The
// page embeds an older report as sandprobe/6, with no letter and nothing else changed (ANL-1, AGT-6): without its
// letter it is no longer a report of the version it declared, and a reader would refuse it.
func SavedHTML(d Doc, theme string) ([]byte, error) {
	d.Schema, d.Grade.Letter = SchemaNoLetter, nil
	return render(d, theme, SavedNote)
}

// HTML renders OUT-2: one file that loads nothing, with a fresh script nonce, every box string escaped as text by
// html/template, and the OUT-1 document in a JSON data block.
func HTML(d Doc, theme string) ([]byte, error) { return render(d, theme, "") }

func render(d Doc, theme, saved string) ([]byte, error) {
	nonce := make([]byte, 18)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	if theme != "mission" { // UX-8: anything else, the retired "modern" included, is the default
		theme = "graphite"
	}
	when, _ := time.Parse(time.RFC3339, d.Run.StartedAt)
	v := view{Nonce: base64.RawURLEncoding.EncodeToString(nonce), Theme: theme, Provider: d.Run.Provider, Box: d.Run.Box.Name,
		When: when.Local().Format("Jan 2, 2006 3:04 PM MST"), Lead: d.Lead, Statement: d.Statement,
		Boundary: d.Boundary, Invalid: d.Grade.Invalid, Complete: d.Grade.Complete, Valid: d.Grade.Valid,
		Unknown: len(d.Grade.Unknown), ScopedOut: d.Limits.ScopedOut, NotTested: d.Limits.NotTested, Notes: d.Grade.Notes,
		Cleanup: d.Cleanup.Outcome, Residual: d.Cleanup.Residual, Saved: saved, Data: d, Card: Score(d)}
	if v.Box == "" {
		v.Box = d.Run.Box.ProviderID
	}
	for _, f := range d.Findings {
		c := card{ID: f.ID, Title: f.Title, SevLabel: strings.ToUpper(f.Severity), SevClass: sevClass(f.Severity), Gets: f.Gets,
			Fix: f.Fix, Class: f.Class, Parts: f.Parts()}
		if f.Potential {
			c.SevLabel += " · POTENTIAL"
		}
		for _, ck := range d.Checks {
			if ck.ID == f.ID {
				c.Cat, c.Evidence = catName[ck.Category], ck.Evidence
			}
		}
		if c.Cat == "" {
			c.Cat = "Chain"
		}
		v.Findings = append(v.Findings, c)
	}
	byCat := map[string]*group{}
	for _, ck := range d.Checks {
		c := card{ID: ck.ID, Title: ck.Title, Cat: catName[ck.Category], Evidence: ck.Evidence, Reason: ck.Reason, Fix: ck.Fix, Gets: ck.Gets}
		switch ck.Result {
		case obs.Unknown:
			c.SevLabel, c.SevClass = "UNKNOWN", "med"
			v.Unknowns = append(v.Unknowns, c)
		case obs.NotFound:
			c.SevLabel, c.SevClass = "NOT PROVEN", "med"
			v.NotProven = append(v.NotProven, c)
		case obs.Pass, obs.Absent: // a refusal proven next to its twin, or an absence verified; scoped out is neither
			c.Mark = "✓"
			if ck.Result == obs.Absent {
				c.Mark, c.Evidence = "∅", "verified absent: "+ck.Evidence
			}
			v.Passed++
			if byCat[ck.Category] == nil {
				byCat[ck.Category] = &group{Name: catName[ck.Category]}
			}
			byCat[ck.Category].Checks = append(byCat[ck.Category].Checks, c)
		case "skipped":
			v.Skipped = append(v.Skipped, [2]string{ck.ID + " · " + ck.Title, ck.Reason})
		}
		if ck.Attestation != "" { // PRV-15: shown for every run, valid or not
			result := ck.Result
			if ck.Reason != "" {
				result += " (" + ck.Reason + ")"
			}
			v.Attested = append(v.Attested, [2]string{ck.ID + " · " + ck.Title, ck.Attestation + " Result: " + result + "."})
		}
	}
	v.NotProvenN = len(v.NotProven)
	for _, cat := range []string{"SEC", "EGR", "PER", "AMP"} {
		if g := byCat[cat]; g != nil {
			v.Passes = append(v.Passes, *g)
		}
	}
	if id := d.Identity; id != nil {
		nnp := "unknown"
		if id.NoNewPrivs != nil {
			nnp = fmt.Sprint(*id.NoNewPrivs)
		}
		v.Identity = [][2]string{{"User", fmt.Sprintf("uid %d, gid %d", id.UID, id.GID)}, {"Mode", d.Run.Mode},
			{"CapEff", id.CapEff}, {"CapBnd", id.CapBnd}, {"NoNewPrivs", nnp}, {"Seccomp", fmt.Sprint(id.Seccomp)}}
	}
	v.Identity = append(v.Identity, [2]string{"Probe", "sha256 " + d.Probe.SHA256 + ", host-shipped, never attested"})
	tried := map[Contact]bool{}
	for _, c := range d.Contacted {
		tried[c] = true
	}
	for _, c := range d.Planned {
		state := c.Check + " · not tried"
		switch {
		case tried[c]:
			state = c.Check + " · tried"
		case c.Check == "SEC-4" || c.Check == "AMP-7":
			state = c.Check + " · cleared; this check reports what it found, not each attempt"
		}
		if c.When != "" {
			state += " · " + c.When
		}
		v.Hosts = append(v.Hosts, [2]string{c.Host + ":" + c.Port + " · " + strings.ToUpper(c.Proto), state})
		delete(tried, c)
	}
	for _, c := range d.Contacted {
		if tried[c] { // tried, yet not in the plan: the grader invalidates such a run
			v.Hosts = append(v.Hosts, [2]string{c.Host + ":" + c.Port + " · " + strings.ToUpper(c.Proto), c.Check + " · tried, not planned"})
		}
	}
	for _, m := range d.Markers {
		fate := m.Cleanup
		if !m.Confirmed {
			fate = "never placed: " + fate
		}
		v.Markers = append(v.Markers, [2]string{m.Path, fate})
	}
	if r := d.Reset; r != nil {
		v.Reset = [][2]string{{"Model", r.Model}, {"Operation", r.OperationID}, {"Done", fmt.Sprint(r.Done)},
			{"Box before → after", r.Before + " → " + r.After}}
		if r.Checkpoint != "" {
			v.Reset = append(v.Reset, [2]string{"Checkpoint", r.Checkpoint}, [2]string{"Restore ID before → after", r.RestoreBefore + " → " + r.RestoreAfter})
		}
	}
	for _, c := range d.ProviderCalls {
		state := "ok"
		if !c.OK {
			state = "failed: " + c.Error
		}
		v.Calls = append(v.Calls, [2]string{c.Call, c.At.Local().Format("3:04:05 PM") + " · " + state})
	}
	v.Map, v.Version = mapSVG(d), d.Probe.Version
	if v.Card.Valid {
		v.Cats, v.Groups, v.Rest, v.RestLabel = fixList(d, v.Card)
		v.Strip = strip(v.Groups, v.Rest)
		for _, f := range d.Findings {
			if t, ok := chainText[f.ID]; ok {
				text := t[0]
				if f.Potential {
					text = t[1]
				}
				v.Chains = append(v.Chains, chain{Sev: f.Severity, Text: text})
			}
		}
	}
	var b strings.Builder
	if err := tmpl.Execute(&b, v); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

// Parts lists a finding's checks, for the page.
func (f Finding) Parts() []string { return f.Checks }

// mapSVG draws UX-11's containment map: the agent in its box, each check a mark on the wall it tests. Every string in
// it comes from the catalog, never from the box, and is escaped anyway.
func mapSVG(d Doc) template.HTML {
	const x0, x1, y0, y1, ax, ay = 230.0, 590.0, 90.0, 300.0, 410.0, 195.0
	var marks []Check
	for _, c := range d.Checks {
		if c.Result != "skipped" && c.Result != obs.ScopedOut { // neither tested a wall
			marks = append(marks, c)
		}
	}
	n, idx := map[string]int{}, make([]int, len(marks))
	for i, c := range marks {
		idx[i] = n[c.Category]
		n[c.Category]++
	}
	pos := func(i int) (float64, float64) {
		c, k := marks[i], float64(idx[i])
		dd := math.Max(1, float64(n[c.Category]-1))
		switch c.Category {
		case "SEC":
			return 330 + k*230/dd, y0
		case "AMP":
			return 270 + k*290/dd, y1
		case "PER":
			return x0, 130 + k*140/dd
		}
		return x1, 115 + k*170/dd
	}
	esc := html.EscapeString
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f, a...) }
	w(`<svg class="map" viewBox="0 0 820 420" role="img" aria-label="Containment map: the agent in its box, each check on its wall">`)
	w(`<defs><marker id="arrow" viewBox="0 0 10 10" refX="7" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0L10,5L0,10z" class="arrowhead"/></marker>`)
	w(`<pattern id="grid" width="20" height="20" patternUnits="userSpaceOnUse"><path d="M20 0H0V20" class="grid"/></pattern></defs>`)
	w(`<rect width="820" height="420" fill="url(#grid)" class="gridbg"/>`)
	w(`<rect class="wall" x="%.0f" y="%.0f" width="%.0f" height="%.0f" rx="8"/>`, x0, y0, x1-x0, y1-y0)
	w(`<text class="cat" x="%.0f" y="%.0f">SECRETS</text><text class="cat" x="%.0f" y="%.0f">AMPLIFIERS</text>`, x0+16, y0+24, x0+16, y1-14)
	w(`<text class="cat" x="%.0f" y="%.0f" text-anchor="middle" transform="rotate(-90 %.0f %.0f)">PERSIST</text>`, x0+22, ay, x0+22, ay)
	w(`<text class="cat" x="%.0f" y="%.0f" text-anchor="middle" transform="rotate(90 %.0f %.0f)">EGRESS</text>`, x1-22, ay, x1-22, ay)
	w(`<circle class="agent-ring" cx="%.0f" cy="%.0f" r="18"/><circle class="agent" cx="%.0f" cy="%.0f" r="6"/>`, ax, ay, ax, ay)
	if d.Identity != nil {
		w(`<text class="agent-label" x="%.0f" y="%.0f" text-anchor="middle">agent · uid %d</text>`, ax, ay+34, d.Identity.UID)
	}
	for i, c := range marks {
		x, y := pos(i)
		delay := 0.3 + float64(i)*0.06
		w(`<g class="mark" style="animation-delay:%.2fs" data-target="%s"><title>%s</title>`, delay, esc(c.ID), esc(c.ID+" · "+c.Title+" · "+c.Result))
		switch c.Result {
		case obs.Pass, obs.Absent:
			if c.Category == "SEC" || c.Category == "AMP" {
				w(`<line class="seg" x1="%.1f" y1="%.0f" x2="%.1f" y2="%.0f"/>`, x-9, y, x+9, y)
			} else {
				w(`<line class="seg" x1="%.0f" y1="%.1f" x2="%.0f" y2="%.1f"/>`, x, y-9, x, y+9)
			}
		case obs.Finding:
			w(`<path class="crack" d="M%.1f,%.1fL%.1f,%.1fM%.1f,%.1fL%.1f,%.1f"/>`, x-6, y-6, x+6, y+6, x-6, y+6, x+6, y-6)
			label := esc(c.ID)
			switch c.Category {
			case "SEC":
				w(`<path class="breach" d="M%.1f,%.0fV%.0f" marker-end="url(#arrow)"/>`, x, y, y-30)
				w(`<text class="breach-label" x="%.1f" y="%.1f" text-anchor="middle" transform="rotate(-35 %.1f %.1f)">%s</text>`, x, y-38, x, y-38, label)
			case "EGR":
				w(`<path class="breach" d="M%.0f,%.1fH%.0f" marker-end="url(#arrow)"/><text class="breach-label" x="%.0f" y="%.1f">%s</text>`, x, y, x+48, x+56, y+4, label)
			case "PER":
				w(`<path class="breach" d="M%.0f,%.1fH%.0f" marker-end="url(#arrow)"/><text class="breach-label" x="%.0f" y="%.1f" text-anchor="end">%s</text>`, x, y, x-48, x-56, y+4, label)
			case "AMP":
				w(`<path class="breach" d="M%.1f,%.0fV%.0f" marker-end="url(#arrow)"/>`, x, y, y+30)
				w(`<text class="breach-label" x="%.1f" y="%.1f" transform="rotate(35 %.1f %.1f)">%s</text>`, x, y+40, x, y+40, label)
			}
		default: // unknown or not proven: never a pass
			w(`<circle class="unk" cx="%.1f" cy="%.1f" r="8"/><text class="unk-q" x="%.1f" y="%.1f" text-anchor="middle">?</text>`, x, y, x, y+4)
		}
		w(`<circle class="hit" cx="%.1f" cy="%.1f" r="12"/></g>`, x, y)
	}
	w(`</svg>`)
	return template.HTML(b.String())
}
