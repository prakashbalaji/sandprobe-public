package report

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"sandprobe/internal/catalog"
	"sandprobe/internal/grade"
	"sandprobe/internal/host"
	"sandprobe/internal/obs"
)

// evil is text a box controls, aimed at every way out of an HTML text node, an attribute and a script block.
const evil = `</script><script>alert(1)</script><img src=x onerror=alert(2)>"'&<!--`

func run() *host.Run {
	one := 0
	doc, _ := json.Marshal(obs.Doc{Schema: obs.Schema, RunID: "r1", Nonce: "n1", BoxID: "box-1", ProbeSHA256: "abc",
		Identity: &obs.Identity{UID: 1001, GID: 1001, CapEff: "0000000000000000", NoNewPrivs: &one}})
	return &host.Run{
		Manifest: obs.Manifest{RunID: "r1", Nonce: "n1", BoxID: "box-1", ProbeSHA256: "abc", Mode: "exec",
			Endpoints: map[string]string{"EGR-2": "203.0.113.5:443"},
			Marks:     []obs.PlannedMark{{Root: "/tmp", Path: "/tmp/.sandprobe-r1", Dev: 7, Ino: 9}}},
		Doc: doc,
		Report: grade.Report{Valid: true, Letter: "C", Complete: false, Unknown: []string{"AMP-1"},
			Outcomes: []grade.Outcome{
				{ID: "SEC-1", Result: obs.Pass, Evidence: "no secret-shaped names"},
				{ID: "EGR-2", Result: obs.Finding, Evidence: evil, Severity: catalog.Medium, Class: catalog.Proof},
				{ID: "SEC-4", Result: obs.NotFound, Reason: evil},
				{ID: "AMP-1", Result: obs.Unknown, Reason: evil},
			},
			Findings:  []grade.Finding{{ID: "EGR-2", Title: "A nonce sent by HTTPS straight out reaches our canary", Severity: catalog.Medium, Class: catalog.Proof}},
			NotProven: []string{"SEC-4"}, Skipped: map[string]string{"EGR-3": "no proxy"}},
		Evidence: obs.CanaryEvidence{Receipts: []obs.Receipt{{Nonce: "c1", Proto: "tcp", Port: 443, From: "198.51.100.9:4000"}}},
		Markers:  []obs.Cleanup{{Path: "/tmp/.sandprobe-r1", Confirmed: true, Gone: true, How: "the box deleted, the provider confirming it"}},
	}
}

func meta() Meta {
	return Meta{Version: "0.1.0", Provider: "sprites", BoxName: evil, CreatedBySandprobe: true, StartedAt: time.Unix(1794290000, 0),
		Duration: 15 * time.Second, Cleanup: "deleted", Residual: "name only",
		Calls: []obs.ProviderCall{{At: time.Unix(1794290000, 0), Call: "sprite create " + evil, OK: true}}}
}

func TestBuild(t *testing.T) {
	d := Build(run(), meta())
	if d.Schema != "sandprobe/1" || !d.Probe.HostShipped || d.Probe.Attested || d.Grade.Counts["medium"] != 1 ||
		!strings.Contains(d.Statement, "not a certification") || d.Boundary == "" || len(d.Limits.NotTested) == 0 {
		t.Fatalf("doc: %+v", d)
	}
	if len(d.Markers) != 1 || d.Markers[0].Inode != 9 || !d.Markers[0].Gone || d.Planned[0].Host != "203.0.113.5" {
		t.Fatalf("markers %+v, planned %+v", d.Markers, d.Planned)
	}
	var egr2, egr3 Check
	for _, c := range d.Checks {
		switch c.ID {
		case "EGR-2":
			egr2 = c
		case "EGR-3":
			egr3 = c
		}
	}
	if egr2.Scope == nil || egr2.Scope.Port != "443" || egr2.Severity != "medium" || egr2.Fix == "" || egr3.Result != "skipped" {
		t.Fatalf("EGR-2 %+v, EGR-3 %+v", egr2, egr3)
	}
	if !strings.HasPrefix(d.Lead, "A hijacked agent here can send data straight out") {
		t.Fatalf("lead: %q", d.Lead)
	}
}

var (
	cspRE    = regexp.MustCompile(`<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-([A-Za-z0-9_-]+)'`)
	scriptRE = regexp.MustCompile(`<script[^>]*>`)
	dataRE   = regexp.MustCompile(`(?s)<script id="report-data" type="application/json">(.*?)</script>`)
)

// OUT-2: box text stays text, only the nonced script runs, nothing loads from the network, and the data round-trips.
func TestHTMLIsSafe(t *testing.T) {
	d := Build(run(), meta())
	b, err := HTML(d, "modern")
	if err != nil {
		t.Fatal(err)
	}
	page := string(b)
	m := cspRE.FindStringSubmatch(page)
	if m == nil {
		t.Fatal("no CSP with a script nonce")
	}
	for _, tag := range scriptRE.FindAllString(page, -1) {
		if tag != `<script id="report-data" type="application/json">` && tag != `<script nonce="`+m[1]+`">` {
			t.Errorf("a script that isn't the data block or the nonced one: %s", tag)
		}
	}
	if n := len(scriptRE.FindAllString(page, -1)); n != 2 {
		t.Errorf("want exactly 2 script tags, got %d", n)
	}
	for _, bad := range []string{"<script>alert", "<img src=x", "<!--"} { // escaped, the rest is inert text
		if strings.Contains(page, bad) {
			t.Errorf("box text reached the page as markup: %q", bad)
		}
	}
	if regexp.MustCompile(`(?i)(src|href)="(https?:)?//`).MatchString(page) || strings.Contains(page, "<link") || strings.Contains(page, "@import") {
		t.Error("the page loads something from the network")
	}
	data := dataRE.FindStringSubmatch(page)
	if data == nil {
		t.Fatal("no data block")
	}
	var back Doc
	if err := json.Unmarshal([]byte(data[1]), &back); err != nil {
		t.Fatalf("the data block doesn't parse: %v", err)
	}
	if back.Run.Box.Name != evil || back.Checks[0].ID != d.Checks[0].ID {
		t.Fatalf("the data block didn't round-trip: %q", back.Run.Box.Name)
	}
	if strings.Contains(data[1], "</script") {
		t.Error("the data block can be closed from inside")
	}
	again, _ := HTML(d, "modern")
	if n := cspRE.FindStringSubmatch(string(again)); n == nil || n[1] == m[1] {
		t.Error("want a fresh nonce for every page")
	}
}

func TestHTMLInvalid(t *testing.T) {
	r := run()
	r.Report = grade.Report{Invalid: "a duplicate check ID"}
	b, err := HTML(Build(r, meta()), "mission")
	if err != nil || !strings.Contains(string(b), "INVALID RUN") || !strings.Contains(string(b), "a duplicate check ID") || !strings.Contains(string(b), `data-theme="mission"`) {
		t.Fatalf("want an invalid run shown as invalid, with no grade: %v", err)
	}
}

// A complete run with no finding still holds not-proven and scoped-out checks: neither is a refusal, and the page
// and the lead mustn't say so.
func TestNoFindingIsNotAllRefusals(t *testing.T) {
	r := run()
	r.Report = grade.Report{Valid: true, Letter: "A", Complete: true, NotProven: []string{"SEC-4"}, ScopedOut: []string{"SEC-2"},
		Skipped: map[string]string{"EGR-3": "no proxy", "EGR-6": "not approved"},
		Outcomes: []grade.Outcome{
			{ID: "SEC-1", Result: obs.Pass, Evidence: "no secret-shaped names"},
			{ID: "SEC-2", Result: obs.ScopedOut, Evidence: "no other process"},
			{ID: "SEC-3", Result: obs.Absent, Evidence: "none of the files exist"},
			{ID: "SEC-4", Result: obs.NotFound, Reason: "no role listed"},
		}}
	d := Build(r, meta())
	if strings.Contains(d.Lead, "refusal at every check") || !strings.Contains(d.Lead, "proves nothing") ||
		!strings.Contains(d.Lead, "among the checks that ran") || !strings.Contains(d.Lead, "2 more were skipped") {
		t.Fatalf("lead: %q", d.Lead)
	}
	b, _ := HTML(d, "modern")
	page := string(b)
	if r := rowOf(page, "SEC-1"); !strings.Contains(r, `class="green"`) || !strings.Contains(r, `<td class="res">Pass</td>`) ||
		!strings.Contains(r, "we proved it") || !strings.Contains(rowOf(page, "SEC-3"), "there isn&#39;t one") ||
		!strings.Contains(rowOf(page, "SEC-2"), `<td class="res">N/A</td>`) {
		t.Fatal("want the pass and the absence verified, and the scoped-out check not counted as either")
	}
	if strings.Contains(string(mapSVG(d)), `data-target="SEC-2"`) {
		t.Fatal("a scoped-out check tested no wall: it isn't on the map")
	}
}

// An indicator reads as observed exposure, never as a proven capability, in the lead and on its card.
func TestIndicatorsStayIndicators(t *testing.T) {
	r := run()
	r.Report.Outcomes = append(r.Report.Outcomes, grade.Outcome{ID: "AMP-4", Result: obs.Finding, Evidence: "connect permission on /.sprite/api.sock (never connected)",
		Severity: catalog.High, Class: catalog.Indicator})
	r.Report.Findings = append(r.Report.Findings, grade.Finding{ID: "AMP-4", Title: "Control sockets", Severity: catalog.High, Class: catalog.Indicator})
	d := Build(r, meta())
	if !strings.Contains(d.Lead, "can send data straight out") || !strings.Contains(d.Lead, "It also has connect permission") ||
		!strings.Contains(d.Lead, "(an indicator, not a proof)") || strings.Contains(d.Lead, "can connect to a control socket") {
		t.Fatalf("lead: %q", d.Lead)
	}
	b, _ := HTML(d, "modern")
	if r := rowOf(string(b), "AMP-4"); !strings.Contains(r, `<td class="res">Fail</td>`) ||
		!strings.Contains(r, "a sign we saw, not something we confirmed") {
		t.Fatal("the indicator's card doesn't say what kind of claim it is")
	}
	only := run()
	only.Report.Findings = []grade.Finding{{ID: "AMP-4", Severity: catalog.High, Class: catalog.Indicator}}
	if l := Build(only, meta()).Lead; !strings.HasPrefix(l, "Nothing here is proven") {
		t.Fatalf("indicators alone: %q", l)
	}
}

// contacted is only what the probe reports trying; planned is everything the plan cleared.
func TestPlannedIsNotContacted(t *testing.T) {
	r := run()
	d := Build(r, meta())
	if len(d.Contacted) != 0 {
		t.Fatalf("nothing was tried, yet contacted lists %+v", d.Contacted)
	}
	has := func(cs []Contact, host, check string) bool {
		for _, c := range cs {
			if c.Host == host && c.Check == check {
				return true
			}
		}
		return false
	}
	if !has(d.Planned, "203.0.113.5", "EGR-2") || !has(d.Planned, "169.254.169.254", "SEC-4") {
		t.Fatalf("planned: %+v", d.Planned)
	}
	for _, c := range d.Planned { // ECS and Pod Identity are contacted only when the box names them
		if (c.Host == "169.254.170.2" || c.Host == "169.254.170.23") != (c.When != "") {
			t.Errorf("%s: condition %q", c.Host, c.When)
		}
	}
	one := 0
	doc, _ := json.Marshal(obs.Doc{Schema: obs.Schema, RunID: "r1", Nonce: "n1", BoxID: "box-1", ProbeSHA256: "abc",
		Identity:     &obs.Identity{UID: 1001, NoNewPrivs: &one},
		Observations: []obs.Observation{{ID: "EGR-2", Result: obs.Attempted, Attempts: []obs.Attempt{{Dest: "203.0.113.5:443"}}}}})
	r.Doc = doc
	d = Build(r, meta())
	if !has(d.Contacted, "203.0.113.5", "EGR-2") || len(d.Contacted) != 1 {
		t.Fatalf("contacted: %+v", d.Contacted)
	}
	page, _ := HTML(d, "modern")
	if !strings.Contains(string(page), "EGR-2 · tried") || !strings.Contains(string(page), "SEC-4 · cleared; this check reports") {
		t.Fatal("want each planned destination marked tried, or what its check reports")
	}
}

// rowOf is one check's table row on the page.
func rowOf(page, id string) string {
	i := strings.Index(page, `id="`+id+`"`)
	if i < 0 {
		return ""
	}
	i = strings.LastIndex(page[:i], "<tr") // the row's class comes before its id
	j := strings.Index(page[i:], "</tr>")
	return page[i : i+j]
}
