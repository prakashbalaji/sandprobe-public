package report

import (
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"fmt"
	"html"
	"html/template"
	"math"
	"slices"
	"sort"
	"strconv"
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
	Nonce, Theme, Provider, ProviderLabel, Box, UserShort, When string // SCR-3: no letter grade
	Lead, Statement, Boundary, Invalid                          string
	Complete, Valid                                             bool
	Passed, Unknown, NotProvenN                                 int
	Map                                                         template.HTML
	Findings, Unknowns, NotProven                               []card
	Passes                                                      []group
	Skipped, Identity, Hosts, Markers, Reset, Calls, Attested   [][2]string
	CoverageRows                                                [][2]string
	ScopedOut, NotTested, Notes                                 []string
	Cleanup, Residual, Saved                                    string
	Data                                                        Doc
	Card                                                        Card // SCR-3: the headline
	Cats                                                        []catView
	Chains                                                      []chain
	TopChainSev, HeroSecond, ScoreBreakdown                     string
	Groups                                                      []sevGroup // SCR-3: What to fix
	Rest                                                        []test     // SCR-3: other checks
	RestLabel, Version                                          string
	Strip                                                       []stat
}

// catView is one of the six rows (SCR-2) with "x/y run" and a link to each of its tests (SCR-3).
type catView struct {
	Row
	Num        string
	Run, Total int
	Tests      []test
}

// sevGroup is one group of What to fix (SCR-3): a severity's failures, a chain's sentence first, or the unknowns.
type sevGroup struct {
	Key, Name string
	Rows      []test
}

// stat is one cell of the hairline result ledger beside the score, counted from the rows the page shows (SCR-3).
type stat struct {
	N                  int
	Label, Class, Href string
}

type test struct {
	ID, Ask, Result, Class, Detail, Fix, Sev, Cat string
	Indicator                                     bool
	Attested                                      string   // PRV-15: the person's attestation, beside the check
	Parts                                         []string // a chain's checks, each linked to its row
	order                                         int
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

// providerLabel names what is being tested in plain words for the specification bar, never containing "-provider".
func providerLabel(provider, declared string) string {
	switch provider {
	case "docker":
		return "Docker · local container"
	case "docker-fixture":
		return "Docker · test fixture"
	case "aws-nitro":
		return "AWS Nitro Sandbox · EKS"
	case "modal":
		return "Modal Sandbox"
	case "sprites":
		return "Fly Sprites"
	case "daytona":
		return "Daytona Sandbox"
	case "e2b":
		return "E2B Sandbox"
	case "vercel":
		return "Vercel Sandbox"
	case "cloudflare":
		return "Cloudflare Sandbox"
	case "baseten":
		return "Baseten Sandbox"
	case "exe-dev", "exedev":
		return "exe.dev VM"
	case "boat":
		return "Boat Sandbox"
	case "kubernetes":
		return "Kubernetes Pod"
	case "recipe":
		return "Custom recipe sandbox"
	case "self":
		return "Current host · self"
	case "exec":
		if declared != "" {
			return "Existing sandbox · declared " + declared
		}
		return "Existing sandbox · exec"
	case "":
		return "Sandbox"
	}
	return provider
}

// passDetail explains a verified two-sided pass in plain English from the catalog alone, never from box strings.
func passDetail(id string, uid *int) string {
	switch id {
	case "SEC-1":
		return "Verified: inspected environment variable names; no secret-shaped names found."
	case "SEC-2":
		return "Blocked: kernel denied access to other processes' environment variables."
	case "SEC-3":
		return "Blocked: kernel denied read access on discovered credential files."
	case "SEC-5":
		return "Blocked: kernel denied read access to other processes' memory."
	case "EGR-2":
		return "Blocked: outbound HTTPS did not reach our external server while canary health was verified."
	case "EGR-5.22", "EGR-5.80", "EGR-5.8080":
		return "Blocked: outbound TCP connection did not reach our external server while canary health was verified."
	case "PER-1":
		return "Blocked: write access denied on shell startup files."
	case "PER-2":
		return "Blocked: write access denied on directories ahead of system PATH."
	case "PER-3":
		return "Blocked: write access denied on systemd and cron paths."
	case "PER-4":
		return "Blocked: write access denied on package, git, and SSH config paths."
	case "AMP-2":
		if uid != nil {
			return fmt.Sprintf("Verified: runs as non-root (uid %d) with no active Linux capabilities.", *uid)
		}
		return "Verified: runs as non-root with no active Linux capabilities."
	case "AMP-3":
		return "Verified: privilege lock (no_new_privs = 1) prevents setuid or file-capability escalation."
	case "AMP-4":
		return "Blocked: connect permission denied on container and host control sockets."
	case "AMP-5":
		return "Verified: checked local listening ports; no control daemon found."
	case "AMP-8.sys":
		return "Blocked: write access denied on kernel /proc/sys settings."
	case "AMP-8.blk":
		return "Blocked: read access denied on visible disk block devices."
	}
	return "Verified: access was actively blocked and confirmed."
}

// absentDetail explains a verified absence from the catalog alone.
func absentDetail(id string) string {
	switch id {
	case "SEC-3":
		return "Verified absent: none of the checked credential or token files exist in this sandbox."
	case "AMP-1":
		return "Verified absent: sudo is not installed in this sandbox."
	case "AMP-4":
		return "Verified absent: no Docker, containerd, Podman, or system control socket exists here."
	}
	return "Verified absent: target does not exist in this sandbox."
}

// scopedOutDetail explains why a check had nothing in scope to test (neither a pass nor a failure).
func scopedOutDetail(id string) string {
	switch id {
	case "SEC-2", "SEC-5":
		return "No other processes are visible in this PID namespace (neither a pass nor a failure)."
	case "AMP-8.blk":
		return "No raw disk devices are visible in this sandbox (neither a pass nor a failure)."
	}
	return "Nothing in scope is visible to test here (neither a pass nor a failure)."
}

// notFoundDetail explains a find-only no-finding result while keeping No false passes explicit ("doesn't prove").
func notFoundDetail(id string) string {
	switch id {
	case "SEC-4":
		return "No cloud metadata service answered; doesn't prove metadata is blocked on cloud hosts."
	case "EGR-1":
		return "Test DNS lookup did not reach our server; doesn't prove every DNS tunnel is blocked."
	case "EGR-3":
		return "Proxy request did not reach our server; doesn't prove all proxy routes are blocked."
	case "EGR-4":
		return "Our server's TLS certificate arrived untouched; doesn't prove other hosts aren't intercepted."
	case "EGR-5.53u":
		return "Test UDP packet on port 53 did not arrive; doesn't prove all UDP is blocked."
	case "EGR-6":
		return "Could not complete TLS handshakes to checked upload hosts; doesn't prove other hosts are blocked."
	case "PER-5":
		return "Test marker did not survive the sandbox reset; doesn't prove no other path persists."
	case "AMP-1":
		return "sudo did not allow passwordless commands; doesn't prove sudo cannot be invoked another way."
	case "AMP-6":
		return "No host vsock service accepted a connection; doesn't prove vsock is disabled."
	case "AMP-7":
		return "No reachable Kubernetes API answered; doesn't prove cluster network access is blocked."
	}
	return "Nothing turned up, though that doesn't prove a hard block."
}

func plainSkipReason(reason string) string {
	switch reason {
	case "no proxy":
		return "No HTTP proxy variable is configured in this sandbox."
	case "contacting its public hosts wasn't approved":
		return "Connecting to public third-party hosts was not enabled for this run."
	case "no vsock device":
		return "No /dev/vsock device exists in this sandbox."
	case "the Docker runner creates one container and doesn't reset it (DKR-5)":
		return "Docker containers are not reset mid-run; no persistent volume recheck ran."
	}
	return reason
}

func plainEvidence(ck Check, uid *int) string {
	if ck.Evidence == "graded by the host from the probe's identity" {
		switch ck.ID {
		case "AMP-3":
			return "no_new_privs is off (0) and setuid-root binaries exist in system folders, allowing privilege escalation."
		case "AMP-2":
			if uid != nil && *uid == 0 {
				return "The agent process is running as root (uid 0)."
			}
			return "The agent process holds elevated Linux capabilities (verified from process status)."
		}
	}
	return ck.Evidence
}

// canaryDetail describes a canary receipt in plain English from the catalog alone (SCR-3).
func canaryDetail(c catalog.Canary) string {
	switch {
	case c.Proto == "dns":
		return "A test DNS lookup from inside the sandbox reached our external server."
	case c.Proto == "tcp" && c.Port == 443 && c.Route == "proxy":
		return "Test HTTPS traffic sent through the sandbox proxy reached our external server."
	case c.Proto == "tcp" && c.Port == 443:
		return "Test HTTPS traffic from inside the sandbox reached our external server."
	case c.Proto == "udp":
		return fmt.Sprintf("Test UDP packets on port %d reached our external server directly.", c.Port)
	}
	return fmt.Sprintf("Test %s traffic on port %d reached our external server.", strings.ToUpper(c.Proto), c.Port)
}

// answer is one check's result as Pass, Fail or a plainer word when it is neither, never more than the result proves
// (AGENTS.md rule 1: a pass needs a negative proof). top says it belongs above the fold.
func answer(ck Check, uid *int, ok bool) (result, class, detail string, indicator, top bool) {
	switch {
	case !ok:
		return "Not run", "grey", "Not included in this run.", false, false
	case ck.Result == obs.Skipped:
		return "Skipped", "grey", plainSkipReason(ck.Reason), false, false
	case ck.Result == obs.Finding && ck.Severity == "info":
		return "Info", "grey", plainEvidence(ck, uid), false, false
	case ck.Result == obs.Finding && ck.EvidenceClass == "indicator":
		return "Fail", "red", plainEvidence(ck, uid), true, true
	case ck.Result == obs.Finding:
		if cat, ok := catalog.Get(ck.ID); ok && cat.Canary != nil {
			return "Fail", "red", canaryDetail(*cat.Canary), false, true
		}
		return "Fail", "red", plainEvidence(ck, uid), false, true
	case ck.Result == obs.Pass:
		return "Pass", "green", passDetail(ck.ID, uid), false, false
	case ck.Result == obs.Absent:
		return "Pass", "green", absentDetail(ck.ID), false, false
	case ck.Result == obs.ScopedOut: // neither a refusal nor an absence: nothing was there to test
		return "N/A", "grey", scopedOutDetail(ck.ID), false, false
	case ck.Result == obs.NotFound:
		return "No finding", "grey", notFoundDetail(ck.ID), false, false
	}
	return "Unknown", "amber", ck.Reason, false, true
}

// worst is a check's highest possible severity: used to order unknowns worst-first.
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
var restOrder = map[string]int{"Pass": 0, "Info": 1, "N/A": 2, "No finding": 3, "Skipped": 4, "Not run": 5}

// failGroups are What to fix's severities, worst first (SCR-3).
var failGroups = [][2]string{{"critical", "Critical"}, {"high", "High"}, {"medium", "Medium"}, {"low", "Low"}}

// fixList builds SCR-3's page below the score: the six rows, each with its tests, then What to fix, where every test
// appears exactly once. Failures group by severity, each chain's sentence first in its own; unknowns follow on their
// own, never folded in with the passes; the rest fold away. A failure whose severity isn't one of the four (only an
// edited report has one) still shows, in a group of its own, so no test is ever dropped.
func fixList(d Doc, c Card) (cats []catView, groups []sevGroup, rest []test, restLabel string) {
	got := map[string]Check{}
	for _, ck := range d.Checks {
		got[ck.ID] = ck
	}
	var uid *int
	if d.Identity != nil {
		u := d.Identity.UID
		uid = &u
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
			t.Result, t.Class, t.Detail, t.Indicator, top = answer(ck, uid, ok)
			// SCR-6: scope discovery alone is not an executed access test.
			if ok && ck.Result != obs.Skipped && ck.Result != obs.ScopedOut {
				cv.Run++
			}
			switch {
			case t.Result == "Fail":
				t.Fix, t.Sev = ck.Fix, ck.Severity
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
			groups = append(groups, sevGroup{Key: g[0], Name: g[1], Rows: rows})
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
		groups = append(groups, sevGroup{Key: "unrated", Name: "Unrated", Rows: unrated})
	}
	if len(unknown) > 0 {
		sort.SliceStable(unknown, func(a, b int) bool { return unknown[a].order < unknown[b].order })
		groups = append(groups, sevGroup{Key: "unknown", Name: "Unknown", Rows: unknown})
	}
	sort.SliceStable(rest, func(a, b int) bool { return rest[a].order < rest[b].order })
	var parts []string
	for _, r := range []string{"Pass", "Info", "N/A", "No finding", "Skipped", "Not run"} {
		if n := counts[r]; n > 0 {
			word := map[string]string{"Pass": "passed", "Info": "info", "N/A": "N/A",
				"No finding": "unproven", "Skipped": "skipped", "Not run": "not run"}[r]
			parts = append(parts, fmt.Sprintf("%d %s", n, word))
		}
	}
	return cats, groups, rest, "Show " + strings.Join(parts, ", ")
}

// strip is SCR-3's hairline ledger under the headline: each failing severity, the passes, unproven/skipped counts when
// present, and the unknowns, every number counted directly from the rows shown on the page.
func strip(groups []sevGroup, rest []test) []stat {
	var out []stat
	unknown := 0
	for _, g := range groups {
		if g.Key == "unknown" {
			unknown = len(g.Rows)
			continue
		}
		out = append(out, stat{N: len(g.Rows), Label: strings.ToLower(g.Name), Class: "red", Href: "#sev-" + g.Key})
	}
	if len(out) == 0 {
		out = append(out, stat{Label: "failing"})
	}
	restHref := ""
	if len(rest) > 0 {
		restHref = "#sev-rest"
	}
	passed, unproven, skipped := 0, 0, 0
	for _, t := range rest {
		switch t.Result {
		case "Pass":
			passed++
		case "No finding":
			unproven++
		case "Skipped", "Not run":
			skipped++
		}
	}
	passStat := stat{N: passed, Label: "passed", Href: restHref}
	if passed > 0 {
		passStat.Class = "green"
	}
	out = append(out, passStat)
	if unproven > 0 {
		out = append(out, stat{N: unproven, Label: "unproven", Href: restHref})
	}
	if skipped > 0 {
		out = append(out, stat{N: skipped, Label: "skipped", Href: restHref})
	}
	gap := stat{N: unknown, Label: "unknown"}
	if unknown > 0 { // dashed, never green, and linked to its group
		gap.Class, gap.Href = "unk", "#sev-unknown"
	}
	return append(out, gap)
}

func scoreSummary(c Card) (breakdown, second string) {
	if !c.Valid {
		return "", ""
	}
	proven, unproven, exposed, na := 0, 0, 0, 0
	lastGreen := ""
	for _, r := range c.Rows {
		switch {
		case r.NotApplicable:
			na++
		case r.Green && r.GreenNotProven:
			unproven++
			lastGreen = strings.ToLower(r.Name)
		case r.Green:
			proven++
			lastGreen = strings.ToLower(r.Name)
		default:
			exposed++
		}
	}
	var parts []string
	if exposed > 0 {
		parts = append(parts, fmt.Sprintf("%d exposed", exposed))
	}
	if proven > 0 && exposed == 0 {
		parts = append(parts, fmt.Sprintf("%d proven", proven))
	}
	if unproven > 0 {
		parts = append(parts, fmt.Sprintf("%d unproven", unproven))
	}
	if na > 0 {
		parts = append(parts, fmt.Sprintf("%d N/A", na))
	}
	breakdown = strings.Join(parts, " · ")

	switch {
	case c.Score == 0:
		second = "Every applicable category had an exposure or an unverified check."
	case c.Score == c.Of && unproven > 0:
		second = "No exposures surfaced, though unproven categories still lack a hard block proof."
	case c.Score == c.Of:
		second = "Every applicable category was tested with verified blocks or absences."
	case c.Score == 1 && unproven == 1:
		second = "Only " + lastGreen + " showed no issue, and couldn't be proven blocked."
	default:
		second = fmt.Sprintf("%d of %d applicable categories are clear, with no finding above Info.", c.Score, c.Of)
	}
	return breakdown, second
}

func decodeCaps(hexStr string) string {
	s := strings.TrimSpace(hexStr)
	if s == "" {
		return "unknown"
	}
	v, err := strconv.ParseUint(s, 16, 64)
	if err != nil {
		return hexStr
	}
	if v == 0 {
		return "none (0x0)"
	}
	names := catalog.CapList(v)
	if len(names) <= 4 {
		return strings.Join(names, ", ")
	}
	return fmt.Sprintf("%d capabilities (%s, and %d more)", len(names), strings.Join(names[:4], ", "), len(names)-4)
}

func decodeNoNewPrivs(p *int) string {
	if p == nil {
		return "unknown"
	}
	switch *p {
	case 1:
		return "enabled (1, setuid escalation blocked)"
	case 0:
		return "disabled (0, setuid escalation allowed)"
	}
	return fmt.Sprint(*p)
}

func decodeSeccomp(s int) string {
	switch s {
	case 0:
		return "disabled (0)"
	case 1:
		return "strict mode (1)"
	case 2:
		return "bpf filter active (2)"
	}
	return fmt.Sprint(s)
}

func probeDigestLabel(sha string) string {
	s := strings.TrimSpace(sha)
	if len(s) > 16 {
		s = s[:16] + "…"
	}
	if s == "" {
		return "in-box probe (not attested)"
	}
	return "sha256 " + s + " (in-box, not attested)"
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
// letter it is no longer a report of the version it declared, and a reader would refuse it. A sandprobe/7 report has
// no letter and stays sandprobe/7: as sandprobe/6 its run.recipe would be refused.
func SavedHTML(d Doc, theme string) ([]byte, error) {
	if d.Schema != SchemaOwnRecipe {
		d.Schema = SchemaNoLetter
	}
	d.Grade.Letter = nil
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
	switch theme {
	case "light", "graphite", "mission":
	case "dark": // UX-8: another name for graphite; the page only ever says graphite
		theme = "graphite"
	default: // UX-8: anything else, the retired "modern" included, is the default, which follows the viewer's system
		theme = "auto"
	}
	when, _ := time.Parse(time.RFC3339, d.Run.StartedAt)
	boundary := d.Boundary
	if boundary == oldBoundary {
		boundary = Boundary
	}
	notTested := d.Limits.NotTested
	if slices.Equal(notTested, oldNotTested) {
		notTested = NotTested
	}
	leadText := d.Lead
	if strings.HasPrefix(leadText, "No finding among the checks that ran: each two-sided one") ||
		leadText == "No finding, but not every check could be proven, so this is not a clean result." {
		leadText = lead(d)
	}
	v := view{Nonce: base64.RawURLEncoding.EncodeToString(nonce), Theme: theme, Provider: d.Run.Provider,
		ProviderLabel: providerLabel(d.Run.Provider, d.Manifest.DeclaredProvider), Box: d.Run.Box.Name,
		When: when.Local().Format("Jan 2, 2006 3:04 PM MST"), Lead: leadText, Statement: d.Statement,
		Boundary: boundary, Invalid: d.Grade.Invalid, Complete: d.Grade.Complete, Valid: d.Grade.Valid,
		Unknown: len(d.Grade.Unknown), ScopedOut: d.Limits.ScopedOut, NotTested: notTested, Notes: d.Grade.Notes,
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
		user := fmt.Sprintf("uid %d, gid %d", id.UID, id.GID)
		v.UserShort = fmt.Sprintf("uid %d", id.UID)
		if id.UID == 0 {
			user += " (root)"
			v.UserShort += " (root)"
		}
		v.Identity = [][2]string{
			{"Linux user", user},
			{"Launch mode", d.Run.Mode},
			{"Active capabilities", decodeCaps(id.CapEff)},
			{"Bounding capabilities", decodeCaps(id.CapBnd)},
			{"Privilege lock (no_new_privs)", decodeNoNewPrivs(id.NoNewPrivs)},
			{"Syscall filter (seccomp)", decodeSeccomp(id.Seccomp)},
		}
	}
	v.Identity = append(v.Identity, [2]string{"Probe binary", probeDigestLabel(d.Probe.SHA256)})
	tried := map[Contact]bool{}
	for _, c := range d.Contacted {
		tried[c] = true
	}
	for _, c := range d.Planned {
		state := c.Check + " · not contacted"
		switch {
		case tried[c]:
			state = c.Check + " · contacted"
		case c.Check == "SEC-4" || c.Check == "AMP-7":
			state = c.Check + " · in plan (individual attempts not logged)"
		}
		if c.When != "" {
			state += " · " + c.When
		}
		v.Hosts = append(v.Hosts, [2]string{c.Host + ":" + c.Port + " · " + strings.ToUpper(c.Proto), state})
		delete(tried, c)
	}
	for _, c := range d.Contacted {
		if tried[c] { // tried, yet not in the plan: the grader invalidates such a run
			v.Hosts = append(v.Hosts, [2]string{c.Host + ":" + c.Port + " · " + strings.ToUpper(c.Proto), c.Check + " · contacted (outside plan)"})
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
		v.ScoreBreakdown, v.HeroSecond = scoreSummary(v.Card)
		for _, r := range v.Card.Rows {
			if r.Coverage != nil {
				v.CoverageRows = append(v.CoverageRows, [2]string{r.Name, r.Coverage.Description()})
			}
		}
		for _, f := range d.Findings {
			if t, ok := chainText[f.ID]; ok {
				text := t[0]
				if f.Potential {
					text = t[1]
				}
				if v.TopChainSev == "" && f.Severity != "" {
					v.TopChainSev = strings.ToUpper(f.Severity[:1]) + f.Severity[1:]
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
	w(`<svg class="map" viewBox="0 0 820 420" role="img" aria-label="Sandbox containment map: the agent inside its sandbox, each check on the wall it tests">`)
	w(`<defs><marker id="arrow" viewBox="0 0 10 10" refX="7" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0L10,5L0,10z" class="arrowhead"/></marker>`)
	w(`<pattern id="grid" width="20" height="20" patternUnits="userSpaceOnUse"><path d="M20 0H0V20" class="grid"/></pattern></defs>`)
	w(`<rect width="820" height="420" fill="url(#grid)" class="gridbg"/>`)
	w(`<rect class="wall" x="%.0f" y="%.0f" width="%.0f" height="%.0f"/>`, x0, y0, x1-x0, y1-y0)
	w(`<text class="cat" x="%.0f" y="%.0f">SECRETS</text><text class="cat" x="%.0f" y="%.0f">CONTAINMENT &amp; PRIV</text>`, x0+16, y0+24, x0+16, y1-14)
	w(`<text class="cat" x="%.0f" y="%.0f" text-anchor="middle" transform="rotate(-90 %.0f %.0f)">PERSIST</text>`, x0+22, ay, x0+22, ay)
	w(`<text class="cat" x="%.0f" y="%.0f" text-anchor="middle" transform="rotate(90 %.0f %.0f)">EXFILTRATION</text>`, x1-22, ay, x1-22, ay)
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
