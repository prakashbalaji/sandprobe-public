// Package report writes what a run found: OUT-1's JSON document and OUT-2's self-contained web page. It adds nothing
// the run didn't establish, and every string that came from the box is treated as text.
package report

import (
	"fmt"
	"net"
	"slices"
	"sort"
	"strings"
	"time"

	"sandprobe/internal/catalog"
	"sandprobe/internal/grade"
	"sandprobe/internal/host"
	"sandprobe/internal/obs"
)

// Schema is OUT-1's first version, which every report declares that needs none of a later version's fields (AGT-6).
const Schema = "sandprobe/1"

// SchemaSkipKinds is OUT-1's version that adds the manifest's SkipKinds (SCR-2), and its Attested with a check's
// attestation (PRV-15). A new field is a breaking change, since readers refuse unknown fields (JON-1), so it bumps the
// version (AGT-6); both arrive in one release, so they share it.
const SchemaSkipKinds = "sandprobe/2"

// Schemas are the versions this build reads, oldest first.
var Schemas = []string{Schema, SchemaSkipKinds}

// SchemaFor is AGT-6: the lowest version whose fields a report with this manifest needs. Build declares it, and a
// reader requires a report to declare exactly it, so older readers keep reading every report that needs nothing new.
func SchemaFor(m obs.Manifest) string {
	if len(m.SkipKinds) > 0 || len(m.Attested) > 0 {
		return SchemaSkipKinds
	}
	return Schema
}

// Boundary is SBX-10, which every report states beside the grade.
const Boundary = "No false passes holds against faults, misconfiguration, wrappers and shims in the agent's environment, " +
	"for the host-shipped probe run as the agent. It does not hold against a box that deceives the probe: one that " +
	"substitutes or tampers with it can report the expected digest and fabricate every observation, and the host can't " +
	"tell. The only evidence from outside the box is the canary's receipts, which can prove a way out but never a refusal."

// NotTested is the rest of SBX-10: what no check here covers.
var NotTested = []string{
	"interception in the kernel or hypervisor",
	"escapes below the probe",
	"resource exhaustion",
	"anything a box does only to other processes",
}

// Meta is what the host knows about a run beyond the run itself.
type Meta struct {
	Version            string // Sandprobe's own version
	Provider, BoxName  string
	CreatedBySandprobe bool
	StartedAt          time.Time
	Duration           time.Duration
	Calls              []obs.ProviderCall
	Cleanup            string // how the box's teardown ended
	Residual           string // a provider's stated residual risk (PRV-1)
}

// Doc is OUT-1.
type Doc struct {
	Schema        string             `json:"schema"`
	Probe         Probe              `json:"probe"`
	Run           Run                `json:"run"`
	Grade         Grade              `json:"grade"`
	Statement     string             `json:"statement"` // GRD-4
	Boundary      string             `json:"boundary"`  // SBX-10
	Lead          string             `json:"lead"`      // what a hijacked agent can do, in one sentence
	Findings      []Finding          `json:"findings"`
	Checks        []Check            `json:"checks"`
	Limits        Limits             `json:"limits"`
	Identity      *obs.Identity      `json:"identity"`
	Toolchain     []any              `json:"toolchain"`
	Overrides     []string           `json:"overrides"`
	Contacted     []Contact          `json:"contacted"` // destinations the probe reported trying
	Planned       []Contact          `json:"planned"`   // every destination the plan cleared, tried or not
	Receipts      []obs.Receipt      `json:"receipts"`
	Markers       []Marker           `json:"markers"`
	Reset         *Reset             `json:"reset,omitempty"`
	ProviderCalls []obs.ProviderCall `json:"provider_calls"`
	Cleanup       Cleanup            `json:"cleanup"`
	Manifest      obs.Manifest       `json:"manifest"`
}

type Probe struct {
	Version     string `json:"version"`
	SHA256      string `json:"sha256"`
	HostShipped bool   `json:"host_shipped"`
	Attested    bool   `json:"attested"` // never: SBX-10
}

type Run struct {
	ID         string `json:"id"`
	Nonce      string `json:"nonce"`
	StartedAt  string `json:"started_at"`
	DurationMS int64  `json:"duration_ms"`
	Mode       string `json:"mode"`
	Provider   string `json:"provider"`
	Box        Box    `json:"box"`
	NoCanary   bool   `json:"no_canary,omitempty"` // HCN-5, set by the host from its manifest, never by the box
}

type Box struct {
	ProviderID         string `json:"provider_id"`
	Name               string `json:"name"`
	CreatedBySandprobe bool   `json:"created_by_sandprobe"`
}

type Grade struct {
	Letter   string         `json:"letter"`
	Complete bool           `json:"complete"`
	Valid    bool           `json:"valid"`
	Invalid  string         `json:"invalid,omitempty"`
	Unknown  []string       `json:"unknown"`
	Counts   map[string]int `json:"counts"`
	Notes    []string       `json:"notes,omitempty"`
}

type Finding struct {
	ID        string   `json:"id"`
	Severity  string   `json:"severity"`
	Class     string   `json:"class"`
	Potential bool     `json:"potential,omitempty"`
	Title     string   `json:"title"`
	Checks    []string `json:"checks"`
	Gets      string   `json:"gets"`
	Fix       string   `json:"fix"`
}

type Check struct {
	ID            string `json:"id"`
	Category      string `json:"category"`
	Title         string `json:"title"`
	Kind          string `json:"kind"`
	Result        string `json:"result"`
	EvidenceClass string `json:"evidence_class,omitempty"`
	Severity      string `json:"severity,omitempty"`
	Scope         *Scope `json:"scope,omitempty"`
	Evidence      string `json:"evidence,omitempty"`
	Reason        string `json:"reason,omitempty"`
	Proof         *Proof `json:"proof,omitempty"`
	Gets          string `json:"gets"`
	Fix           string `json:"fix"`
	Attestation   string `json:"attestation,omitempty"` // PRV-15: the person's attestation, for a check they turned on
}

// Attestation is what a report says beside a check PRV-15's -provider-endpoints turned on: a fixed sentence, never
// text from the command line.
const Attestation = "You attested that your provider's terms allow this check on your own account (-provider-endpoints, PRV-15)."

type Scope struct {
	Destination string `json:"destination"`
	Port        string `json:"port"`
	Route       string `json:"route"`
}

type Proof struct {
	Mechanism string `json:"mechanism"`
	Result    string `json:"result"`
}

type Limits struct {
	NotTested []string          `json:"not_tested"`
	NotProven []string          `json:"not_proven"`
	ScopedOut []string          `json:"scoped_out"`
	Skipped   map[string]string `json:"skipped"`
}

type Contact struct {
	Host  string `json:"host"`
	Port  string `json:"port"`
	Proto string `json:"proto"`
	Check string `json:"check"`
	When  string `json:"when,omitempty"` // a condition on a planned destination; empty when always cleared
}

type Marker struct {
	Path      string `json:"path"`
	Dev       uint64 `json:"dev"`
	Inode     uint64 `json:"inode"`
	Confirmed bool   `json:"confirmed"`
	Gone      bool   `json:"gone"`
	Cleanup   string `json:"cleanup"`
}

type Reset struct {
	Model         string `json:"model"`
	OperationID   string `json:"operation_id"`
	Checkpoint    string `json:"checkpoint,omitempty"`
	Done          bool   `json:"done"`
	Before        string `json:"before"`
	After         string `json:"after"`
	RestoreBefore string `json:"restore_before,omitempty"`
	RestoreAfter  string `json:"restore_after,omitempty"`
}

// Retention records an intentionally live resource, distinct from failed cleanup.
type Retention struct {
	ExpiresAt      string   `json:"expires_at"`
	StateFile      string   `json:"state_file"`
	CleanupCommand []string `json:"cleanup_command"`
}

type Cleanup struct {
	Retention *Retention `json:"retention,omitempty"`
	Outcome   string     `json:"outcome"`
	Residual  string     `json:"residual,omitempty"`
}

// Build makes OUT-1 from a run.
func Build(r *host.Run, m Meta) Doc {
	rep, man := r.Report, r.Manifest
	d := Doc{Schema: SchemaFor(man), Statement: "", Boundary: Boundary, Manifest: man,
		Probe: Probe{Version: m.Version, SHA256: man.ProbeSHA256, HostShipped: true},
		Run: Run{ID: man.RunID, Nonce: man.Nonce, StartedAt: m.StartedAt.UTC().Format(time.RFC3339), DurationMS: m.Duration.Milliseconds(),
			Mode: man.Mode, Provider: m.Provider, Box: Box{ProviderID: man.BoxID, Name: m.BoxName, CreatedBySandprobe: m.CreatedBySandprobe},
			NoCanary: man.NoCanary},
		Toolchain: []any{}, Overrides: []string{}, Contacted: []Contact{}, Receipts: r.Evidence.Receipts, Markers: []Marker{},
		ProviderCalls: m.Calls, Cleanup: Cleanup{Outcome: m.Cleanup, Residual: m.Residual},
		Limits: Limits{NotTested: NotTested, NotProven: rep.NotProven, ScopedOut: rep.ScopedOut, Skipped: rep.Skipped}}
	if d.Receipts == nil {
		d.Receipts = []obs.Receipt{}
	}
	if d.ProviderCalls == nil {
		d.ProviderCalls = []obs.ProviderCall{}
	}
	doc, _ := obs.ParseDoc(r.Doc)
	observed := map[string]obs.Observation{}
	if doc != nil {
		d.Identity = doc.Identity
		for k, v := range doc.Overrides {
			d.Overrides = append(d.Overrides, k+"="+v)
		}
		sort.Strings(d.Overrides)
		for _, o := range doc.Observations {
			observed[o.ID] = o
		}
	}

	d.Grade = Grade{Letter: rep.Letter, Complete: rep.Complete, Valid: rep.Valid, Invalid: rep.Invalid, Unknown: rep.Unknown,
		Notes: rep.Notes, Counts: map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}}
	if d.Grade.Unknown == nil {
		d.Grade.Unknown = []string{}
	}
	for _, f := range rep.Findings {
		a := catalog.Guide[f.ID]
		d.Findings = append(d.Findings, Finding{ID: f.ID, Severity: f.Severity.String(), Class: string(f.Class), Potential: f.Potential,
			Title: f.Title, Checks: f.Parts, Gets: a.Gets, Fix: a.Fix})
		d.Grade.Counts[f.Severity.String()]++
	}
	if d.Findings == nil {
		d.Findings = []Finding{}
	}

	outcome := map[string]grade.Outcome{}
	for _, o := range rep.Outcomes {
		outcome[o.ID] = o
	}
	graded := 0
	for _, ck := range catalog.Checks {
		a := catalog.Guide[ck.ID]
		c := Check{ID: ck.ID, Category: ck.Category, Title: ck.Title, Kind: kind(ck.Kind), Gets: a.Gets, Fix: a.Fix}
		if slices.Contains(man.Attested, ck.ID) {
			c.Attestation = Attestation
		}
		if why, skipped := rep.Skipped[ck.ID]; skipped {
			c.Result, c.Reason = "skipped", why
			d.Checks = append(d.Checks, c)
			continue
		}
		o, ok := outcome[ck.ID]
		if !ok {
			continue // not in this run's manifest at all
		}
		graded++
		c.Result, c.Evidence, c.Reason = o.Result, o.Evidence, o.Reason
		if o.Result == obs.Finding {
			c.Severity, c.EvidenceClass = o.Severity.String(), string(o.Class)
		}
		if ck.Canary != nil {
			h, p, _ := net.SplitHostPort(man.Endpoints[ck.ID])
			c.Scope = &Scope{Destination: h, Port: p, Route: ck.Canary.Route}
			c.Proof = &Proof{Mechanism: "canary", Result: o.Result}
		} else if ob, ok := observed[ck.ID]; ok && ob.Proof != nil {
			c.Proof = &Proof{Mechanism: ob.Proof.Mechanism, Result: o.Result}
		}
		d.Checks = append(d.Checks, c)
	}
	d.Statement = fmt.Sprintf("Graded on %d checks for this box at %s, from a host-shipped probe's own observations; not a certification.",
		graded, m.StartedAt.Local().Format("Jan 2, 2006 3:04 PM MST"))
	d.Lead = lead(d)
	d.Contacted, d.Planned = contacted(observed), planned(man)
	for i, pm := range man.Marks {
		mk := Marker{Path: pm.Path, Dev: pm.Dev, Inode: pm.Ino}
		if i < len(r.Markers) {
			mk.Confirmed, mk.Gone, mk.Cleanup = r.Markers[i].Confirmed, r.Markers[i].Gone, r.Markers[i].How
		}
		d.Markers = append(d.Markers, mk)
	}
	if ev := r.Evidence.Reset; ev != nil {
		d.Reset = &Reset{Model: ev.Model, OperationID: ev.OperationID, Checkpoint: ev.Checkpoint, Done: ev.Done,
			Before: ev.BoxBefore, After: ev.BoxAfter, RestoreBefore: ev.RestoreBefore, RestoreAfter: ev.RestoreAfter}
	}
	return d
}

func kind(k catalog.Kind) string {
	if k == catalog.FindOnly {
		return "find_only"
	}
	return "two_sided"
}

// lead is UX-11's one sentence: what a hijacked agent can do here, from the worst findings, or that it found nothing.
func lead(d Doc) string {
	switch {
	case !d.Grade.Valid:
		return "This run is invalid, so it says nothing about the box: " + d.Grade.Invalid
	case len(d.Findings) == 0 && d.Grade.Complete:
		skipped := ""
		switch n := len(d.Limits.Skipped); {
		case n == 1:
			skipped = " One more was skipped, so it says nothing either way."
		case n > 1:
			skipped = fmt.Sprintf(" %d more were skipped, so they say nothing either way.", n)
		}
		return "No finding among the checks that ran: each two-sided one ended in a verified refusal, a verified absence " +
			"or nothing in scope, and the find-only ones found nothing, which proves nothing." + skipped
	case len(d.Findings) == 0:
		return "No finding, but not every check could be proven, so this is not a clean result."
	}
	var proven, exposed []string
	for _, f := range d.Findings {
		switch {
		case f.Gets == "" || f.ID == "CHN-2":
		case f.Class == string(catalog.Proof) && !f.Potential:
			if len(proven) < 3 {
				proven = append(proven, f.Gets)
			}
		case len(exposed) < 2:
			exposed = append(exposed, f.Gets)
		}
	}
	note := " (an indicator, not a proof)."
	if len(exposed) > 1 {
		note = " (indicators, not proof)."
	}
	switch {
	case len(proven) > 0 && len(exposed) > 0:
		return "A hijacked agent here " + join(proven) + ". It also " + join(exposed) + note
	case len(proven) > 0:
		return "A hijacked agent here " + join(proven) + "."
	case len(exposed) > 0:
		return "Nothing here is proven, but a hijacked agent " + join(exposed) + note
	}
	return "A hijacked agent here has findings to answer for; see them below."
}

// join lists clauses as a sentence does.
func join(xs []string) string {
	switch len(xs) {
	case 1:
		return xs[0]
	case 2:
		return xs[0] + ", and " + xs[1]
	}
	return strings.Join(xs[:len(xs)-1], ", ") + ", and " + xs[len(xs)-1]
}

// metadata are SEC-4's fixed addresses, each with its condition; it reports what it found, not each attempt.
var metadata = [][2]string{{"169.254.169.254:80", ""},
	{"169.254.170.2:80", "only if the agent's environment names the ECS credential endpoint"},
	{"169.254.170.23:80", "only if the agent's environment names EKS Pod Identity"}}

// lister collects destinations once each.
type lister struct {
	seen map[Contact]bool
	cs   []Contact
}

func (l *lister) add(addr, proto, check string) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil || h == "" {
		return
	}
	c := Contact{Host: h, Port: p, Proto: proto, Check: check}
	if l.seen == nil {
		l.seen = map[Contact]bool{}
	}
	if !l.seen[c] {
		l.seen[c] = true
		l.cs = append(l.cs, c)
	}
}

func (l *lister) list() []Contact {
	if l.cs == nil {
		return []Contact{}
	}
	return l.cs
}

// planned is every destination the plan cleared for the box (UX-4, OUT-3), whether or not the probe tried it.
func planned(m obs.Manifest) []Contact {
	var l lister
	for _, ck := range catalog.Checks {
		if ep := m.Endpoints[ck.ID]; ep != "" && ck.Canary != nil {
			l.add(ep, ck.Canary.Proto, ck.ID)
		}
	}
	if m.Proxy != "" {
		l.add(m.Proxy, "tcp", "EGR-3")
	}
	if m.KubeAPI != "" {
		l.add(m.KubeAPI, "tcp", "AMP-7")
	}
	if _, skipped := m.Skipped["SEC-4"]; !skipped { // skipped by a provider's rules of engagement (PRV-5): not planned
		for _, a := range metadata {
			l.add(a[0], "tcp", "SEC-4")
			l.cs[len(l.cs)-1].When = a[1]
		}
	}
	return l.list()
}

// contacted is OUT-3's list of destinations the probe reported trying, from its attempts.
func contacted(observed map[string]obs.Observation) []Contact {
	var l lister
	ids := make([]string, 0, len(observed))
	for id := range observed {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		for _, a := range observed[id].Attempts {
			proto := "tcp"
			if ck, ok := catalog.Get(id); ok && ck.Canary != nil {
				proto = ck.Canary.Proto
			}
			l.add(a.Dest, proto, id)
		}
	}
	return l.list()
}

// Title gives a check's or chain's title, for the page.
func Title(id string) string {
	if ck, ok := catalog.Get(id); ok {
		return ck.Title
	}
	return strings.TrimSpace(id)
}
