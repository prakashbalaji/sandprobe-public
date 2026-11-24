package host

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"regexp"
	"slices"
	"strings"
	"testing"

	"sandprobe/internal/canary"
	"sandprobe/internal/catalog"
	"sandprobe/internal/grade"
	"sandprobe/internal/obs"
)

func TestPlan(t *testing.T) {
	for _, tc := range []struct {
		name    string
		proxy   *obs.ProxySetting
		allow   bool
		planned string // "" when EGR-3 must be skipped, or ends unknown having planned nothing
		unknown bool   // EGR-3 stays selected with no proxy planned, to end unknown
	}{
		{"no proxy", nil, false, "", false},
		{"a remote proxy", &obs.ProxySetting{Var: "HTTPS_PROXY", Scheme: "http", Addr: "proxy.internal:3128"}, false, "proxy.internal:3128", false},
		{"a proxy with credentials stays planned, to end unknown", &obs.ProxySetting{Scheme: "http", Addr: "10.0.0.1:8080", Credentials: true}, false, "10.0.0.1:8080", false},
		{"a loopback proxy, unapproved", &obs.ProxySetting{Scheme: "http", Addr: "127.0.0.1:3128"}, false, "", false},
		{"localhost, unapproved", &obs.ProxySetting{Scheme: "http", Addr: "localhost:3128"}, false, "", false},
		{"a loopback proxy, approved", &obs.ProxySetting{Scheme: "http", Addr: "127.0.0.1:3128"}, true, "127.0.0.1:3128", false},
		{"a malformed setting stays selected, to end unknown", &obs.ProxySetting{Var: "HTTPS_PROXY", Malformed: true}, false, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &obs.Survey{Schema: obs.SurveySchema, Proxy: tc.proxy}
			m, in := Plan(Options{Mode: "exec", ProbeSHA256: "abc", AllowLocalProxy: tc.allow}, s, "box-1", Storage{}, "203.0.113.10", "sandprobe.test", "pin")
			if got := slices.Contains(m.Selected, "EGR-3"); got != (tc.planned != "" || tc.unknown) || m.Proxy != tc.planned ||
				in.Proxy != tc.planned || m.ProxyMalformed != tc.unknown {
				t.Fatalf("EGR-3 selected %v with proxy %q (input %q), want proxy %q", got, m.Proxy, in.Proxy, tc.planned)
			}
			if tc.planned == "" && !tc.unknown && m.Skipped["EGR-3"] == "" {
				t.Fatal("a skipped EGR-3 must say why")
			}
			if m.Skipped["EGR-6"] == "" || slices.Contains(m.Selected, "EGR-6") {
				t.Fatal("EGR-6 is skipped until it's approved")
			}
			for id := range m.Skipped {
				if ck, _ := catalog.Get(id); ck.Gate == "" {
					t.Errorf("%s skipped, but GRD-3 never skips it", id)
				}
			}
			if len(m.Selected)+len(m.Skipped) != len(catalog.Checks) {
				t.Errorf("%d selected and %d skipped of %d checks", len(m.Selected), len(m.Skipped), len(catalog.Checks))
			}
			nonce := regexp.MustCompile(`^[a-z0-9-]{1,63}$`)
			seen := map[string]bool{m.Nonce: true}
			for _, id := range m.Selected {
				ck, _ := catalog.Get(id)
				if ck.Canary == nil {
					continue
				}
				n := m.CheckNonces[id]
				if !nonce.MatchString(n) || seen[n] || in.CheckNonces[id] != n {
					t.Errorf("%s: nonce %q isn't fresh, unique and one the canary accepts", id, n)
				}
				seen[n] = true
			}
			// the grader takes the manifest as sound: a document with no observations is valid, every check unknown
			d := &obs.Doc{Schema: obs.Schema, RunID: m.RunID, Nonce: m.Nonce, BoxID: m.BoxID, ProbeSHA256: m.ProbeSHA256,
				Identity: &obs.Identity{CapEff: "0", NoNewPrivs: new(int), SetuidScan: &obs.SetuidScan{Complete: true}}}
			if r := grade.Grade(m, d, nil); !r.Valid {
				t.Fatalf("the grader finds the manifest unsound: %s", r.Invalid)
			}
		})
	}
}

func TestPlanBlockDevicePaths(t *testing.T) {
	paths := []string{"/dev/workload/disk"}
	m, in := Plan(Options{BlockDevicePaths: paths}, &obs.Survey{}, "box-1", Storage{}, "", "", "")
	paths[0] = "/changed-after-plan"
	for _, targets := range []map[string][]string{m.Targets, in.Targets} {
		if !slices.Equal(targets["AMP-8.blk"], []string{"/dev/workload/disk"}) {
			t.Fatal("host declaration not frozen", targets["AMP-8.blk"])
		}
	}
	if !slices.Contains(m.Discover["AMP-8.blk"], "block_devices") || !slices.Contains(in.Discover["AMP-8.blk"], "block_devices") {
		t.Fatal("declaration replaced discovery")
	}
}

func TestExecuteRejectsInvalidBlockDevicePaths(t *testing.T) {
	// A nil box/canary would panic if validation tried to contact either.
	if _, err := Execute(context.Background(), nil, nil, Options{BlockDevicePaths: []string{"relative"}}); err == nil {
		t.Fatal("invalid declaration reached execution")
	}
}

// The survey's Kubernetes API reaches the manifest and the probe's input; a vsock device keeps AMP-6 selected, and
// without one it's skipped (GRD-3).
func TestPlanSurvey(t *testing.T) {
	s := &obs.Survey{Schema: obs.SurveySchema, KubeAPI: "10.96.0.1:443", Vsock: true}
	m, in := Plan(Options{Mode: "exec"}, s, "box-1", Storage{}, "203.0.113.10", "sandprobe.test", "pin")
	if m.KubeAPI != "10.96.0.1:443" || in.KubeAPI != m.KubeAPI || !slices.Contains(m.Selected, "AMP-6") {
		t.Fatalf("want the API planned and AMP-6 selected, got %q %q %v", m.KubeAPI, in.KubeAPI, m.Skipped)
	}
	s.Vsock = false
	if m, _ := Plan(Options{Mode: "exec"}, s, "box-1", Storage{}, "203.0.113.10", "sandprobe.test", "pin"); m.Skipped["AMP-6"] == "" {
		t.Fatal("no vsock device: want AMP-6 skipped")
	}
}

// The plan's marker rule, resolved against the survey (UX-4, TWN-3): recreate marks only Sandprobe's volumes; restore
// marks home, the working directory and declared mounts, one per directory, never an undeclared mount.
func TestPlanMarks(t *testing.T) {
	s := &obs.Survey{Schema: obs.SurveySchema, Roots: []obs.Root{
		{Path: "/home/agent", Kinds: []string{"home", "wd"}, Dev: 1, Ino: 10},
		{Path: "/data", Kinds: []string{"mount"}, Dev: 2, Ino: 20},
		{Path: "/scratch", Kinds: []string{"mount"}, Dev: 3, Ino: 30},
	}}
	plan := func(st Storage) obs.Manifest {
		m, _ := Plan(Options{Mode: "exec"}, s, "box-1", st, "203.0.113.10", "sandprobe.test", "pin")
		return m
	}
	roots := func(m obs.Manifest) (rs []string) {
		for _, pm := range m.Marks {
			rs = append(rs, pm.Root)
			if pm.Path != pm.Root+"/"+obs.MarkerPrefix+m.RunID {
				t.Errorf("marker path %s isn't <root>/.sandprobe-<run id>", pm.Path)
			}
		}
		return rs
	}
	m := plan(Storage{Model: "recreate", Volumes: []obs.Volume{{ID: "v1@t", MountPath: "/data"}, {ID: "v2@t", MountPath: "/gone"}}})
	if got := roots(m); !slices.Equal(got, []string{"/data", "/gone"}) || m.Marks[0].Ino != 20 || m.Marks[1].Ino != 0 || m.Reset != "recreate" {
		t.Errorf("recreate: want Sandprobe's two volumes, the one the survey missed with no identity, got %+v", m.Marks)
	}
	m = plan(Storage{Model: "restore", Mounts: []string{"/scratch", "/missing"}})
	if got := roots(m); !slices.Equal(got, []string{"/home/agent", "/scratch", "/missing"}) || m.Marks[2].Ino != 0 {
		t.Errorf("restore: want home (once) and every declared mount, the one the survey missed with no identity, never /data; got %+v", m.Marks)
	}
	for _, st := range []Storage{{}, {Model: "recreate"}} {
		if m := plan(st); m.Skipped["PER-5"] == "" || len(m.Marks) != 0 || m.Reset != "" {
			t.Errorf("%+v: want PER-5 skipped with nothing planned, got %v %+v", st, m.Skipped["PER-5"], m.Marks)
		}
	}
}

// fakeReset is a box whose provider confirms only some deletions.
type fakeReset struct {
	DockerBox
	gone map[string]bool
}

func (f *fakeReset) Teardown(context.Context, []obs.Volume) map[string]bool { return f.gone }

// A box deleted while its volume stays: the volume's marker is never reported cleaned up (SBX-1).
func TestTeardownUnconfirmed(t *testing.T) {
	r := &Run{Box: &fakeReset{gone: map[string]bool{"": true}}, Manifest: obs.Manifest{Marks: []obs.PlannedMark{
		{Root: "/data", Path: "/data/.sandprobe-r1", Volume: &obs.Volume{ID: "v1@t", MountPath: "/data"}},
		{Root: "/home/agent", Path: "/home/agent/.sandprobe-r1"},
	}}, Markers: []obs.Cleanup{{Path: "/data/.sandprobe-r1", Confirmed: true}, {Path: "/home/agent/.sandprobe-r1"}}}
	Teardown(context.Background(), r)
	if r.Markers[0].Gone || !strings.Contains(r.Markers[0].How, "may remain") {
		t.Errorf("the volume wasn't confirmed deleted: want an unresolved item, got %+v", r.Markers[0])
	}
	if !r.Markers[1].Gone {
		t.Errorf("the box was confirmed deleted: want its marker gone, got %+v", r.Markers[1])
	}
}

// fakeBox answers -mark by placing every planned marker, and resets into next, with resetErr.
type fakeBox struct {
	id       string
	next     *fakeBox
	resetErr error
	torn     bool
	reset    bool
	tamper   func(*obs.MarkDoc)
}

func (f *fakeBox) ID() string { return f.id }
func (f *fakeBox) Probe(_ context.Context, args []string, stdin []byte) ([]byte, error) {
	if len(args) == 1 && args[0] == "-mark" {
		var in obs.MarkInput
		json.Unmarshal(stdin, &in)
		d := obs.MarkDoc{Schema: obs.MarkSchema, RunID: in.RunID, Nonce: in.Nonce, BoxID: in.BoxID}
		for _, pm := range in.Marks {
			d.Marks = append(d.Marks, obs.Placed{Root: pm.Root, Path: pm.Path, Placed: true, Ino: 1, Size: 2})
		}
		if f.tamper != nil {
			f.tamper(&d)
		}
		return json.Marshal(d)
	}
	return nil, errors.New("not in this test")
}
func (f *fakeBox) Storage(context.Context) (Storage, error) { return Storage{Model: "recreate"}, nil }
func (f *fakeBox) Reset(context.Context) (Box, *obs.ResetEvidence, error) {
	f.reset = true
	if f.next == nil {
		return nil, &obs.ResetEvidence{Model: "recreate"}, f.resetErr
	}
	return f.next, &obs.ResetEvidence{Model: "recreate", BoxAfter: f.next.id}, f.resetErr
}
func (f *fakeBox) Teardown(context.Context, []obs.Volume) map[string]bool {
	f.torn = true
	return map[string]bool{"": true}
}

// A reset that created a new box and then failed: the new box is what teardown deletes, and PER-5 has no recheck.
func TestResetErrorKeepsNewBox(t *testing.T) {
	next := &fakeBox{id: "box-2"}
	old := &fakeBox{id: "box-1", next: next, resetErr: errors.New("volume evidence unreadable")}
	r := &Run{Box: old, Manifest: obs.Manifest{RunID: "r1", Nonce: "n1", BoxID: "box-1", Reset: "recreate",
		Marks: []obs.PlannedMark{{Root: "/data", Path: "/data/.sandprobe-r1", Volume: &obs.Volume{ID: "v@t", MountPath: "/data"}}}}}
	ev := persist(context.Background(), old, r)
	if r.Box != Box(next) || ev.Recheck != nil || ev.Mark == nil {
		t.Fatalf("want the new box kept, the mark recorded and no recheck; got box %s, %+v", r.Box.ID(), ev)
	}
	if !r.Markers[0].Confirmed {
		t.Error("the mark reported the marker placed: want it confirmed")
	}
	Teardown(context.Background(), r)
	if !next.torn || old.torn {
		t.Errorf("want the new box torn down, not the old one: new %v, old %v", next.torn, old.torn)
	}
}

// A mark document that names anything but the plan's markers is never acted on: no reset, no recheck of what it names.
func TestPersistRejectsUnplannedMark(t *testing.T) {
	plan := obs.Manifest{RunID: "r1", Nonce: "n1", BoxID: "box-1", Reset: "recreate",
		Marks: []obs.PlannedMark{{Root: "/data", Path: "/data/.sandprobe-r1", Volume: &obs.Volume{ID: "v@t", MountPath: "/data"}}}}
	for name, tamper := range map[string]func(*obs.MarkDoc){
		"an unplanned root": func(d *obs.MarkDoc) { d.Marks[0].Root, d.Marks[0].Path = "/etc", "/etc/.sandprobe-r1" },
		"an extra marker": func(d *obs.MarkDoc) {
			d.Marks = append(d.Marks, obs.Placed{Root: "/etc", Path: "/etc/x", Placed: true})
		},
		"another run's":        func(d *obs.MarkDoc) { d.RunID = "r9" },
		"another box's":        func(d *obs.MarkDoc) { d.BoxID = "box-9" },
		"placed with no inode": func(d *obs.MarkDoc) { d.Marks[0].Ino = 0 },
	} {
		b := &fakeBox{id: "box-1", next: &fakeBox{id: "box-2"}, tamper: tamper}
		r := &Run{Box: b, Manifest: plan}
		ev := persist(context.Background(), b, r)
		if b.reset || ev.Recheck != nil || ev.Mark == nil || r.Box != Box(b) {
			t.Errorf("%s: want no reset and no recheck, the document kept for the grader; reset=%v", name, b.reset)
		}
	}
}

// plainBox can be probed but not torn down.
type plainBox struct{ id string }

func (p *plainBox) ID() string { return p.id }
func (p *plainBox) Probe(context.Context, []string, []byte) ([]byte, error) {
	return nil, errors.New("no")
}

// A reset whose new box has no teardown path: never a silent no-op, an error and every marker unresolved.
func TestTeardownNoPath(t *testing.T) {
	r := &Run{Box: &plainBox{id: "box-2"}, Volumes: []obs.Volume{{ID: "v@t", MountPath: "/data"}},
		Manifest: obs.Manifest{Marks: []obs.PlannedMark{{Root: "/data", Path: "/data/.sandprobe-r1", Volume: &obs.Volume{ID: "v@t", MountPath: "/data"}}}},
		Markers:  []obs.Cleanup{{Path: "/data/.sandprobe-r1", Confirmed: true}}}
	if err := Teardown(context.Background(), r); err == nil {
		t.Fatal("want an error naming the box to delete by hand")
	}
	if r.Markers[0].Gone || !strings.Contains(r.Markers[0].How, "may remain") {
		t.Errorf("want the marker unresolved, got %+v", r.Markers[0])
	}
}

// A delete the provider didn't confirm is loud, whether or not PER-5 placed markers (PRV-3).
func TestTeardownLoud(t *testing.T) {
	vols := []obs.Volume{{ID: "v1@t", MountPath: "/a"}, {ID: "v2@t", MountPath: "/b"}}
	for name, gone := range map[string]map[string]bool{
		"the box":    {"v1@t": true, "v2@t": true},
		"one volume": {"": true, "v1@t": true},
	} {
		r := &Run{Box: &fakeReset{gone: gone}, Volumes: vols}
		r.Box.(*fakeReset).Container = "box-1"
		err := Teardown(context.Background(), r)
		if err == nil {
			t.Errorf("%s not confirmed deleted, with no markers: want an error", name)
			continue
		}
		if name == "the box" && !strings.Contains(err.Error(), "box box-1") || name == "one volume" && !strings.Contains(err.Error(), "volume v2@t") {
			t.Errorf("%s: the error must name it: %v", name, err)
		}
	}
	r := &Run{Box: &fakeReset{gone: map[string]bool{"": true, "v1@t": true, "v2@t": true}}, Volumes: vols}
	if err := Teardown(context.Background(), r); err != nil {
		t.Errorf("everything confirmed deleted: want no error, got %v", err)
	}
}

// HCN-5: without a canary its checks stay in the manifest, to be graded unknown, but the probe never sees them: no
// nonce, no endpoint, no health port, and nothing of the canary's in the probe's input.
func TestPlanNoCanary(t *testing.T) {
	m, in := Plan(Options{Mode: "exec", NoCanary: true}, &obs.Survey{}, "box-1", Storage{}, "", "", "")
	if !m.NoCanary || len(m.CheckNonces) != 0 || len(m.Endpoints) != 0 || len(healthPorts(m)) != 0 || in.CanaryDomain != "" {
		t.Fatalf("a run without a canary planned one: %+v", m)
	}
	for _, id := range []string{"EGR-1", "EGR-2", "EGR-4", "EGR-5.22", "EGR-5.80", "EGR-5.8080", "EGR-5.53u"} {
		if !slices.Contains(m.Selected, id) || slices.Contains(in.Selected, id) {
			t.Errorf("%s: graded %v, sent to the probe %v", id, slices.Contains(m.Selected, id), slices.Contains(in.Selected, id))
		}
	}
	if !slices.Contains(in.Selected, "SEC-3") || !slices.Contains(in.Selected, "AMP-2") {
		t.Error("the rest of the run went missing")
	}
	if err := grade.ManifestSound(m); err != nil {
		t.Fatalf("the grader refused the manifest: %v", err)
	}
	m.CheckNonces["EGR-2"], m.Endpoints["EGR-2"] = "c-1", "203.0.113.1:443"
	if grade.ManifestSound(m) == nil {
		t.Error("a canary planned for a run without one passed")
	}
}

// SCR-2 and GRD-3: Plan gives a kind only to the host's own provider-endpoint exclusions, never to a skip the survey
// drove (no vsock, no proxy) or EGR-6's and PER-5's, and never in the probe's input; the grader refuses a kind it
// can't have, and Execute refuses a kind that isn't one.
func TestPlanRecordsSkipKinds(t *testing.T) {
	m, in := Plan(Options{Mode: "exec"}, &obs.Survey{}, "box-1", Storage{}, "", "", "")
	if m.Skipped["AMP-6"] == "" || m.Skipped["EGR-3"] == "" || m.SkipKinds != nil {
		t.Fatalf("survey-driven skips got a kind: %v %v", m.Skipped, m.SkipKinds)
	}
	for kind, excluded := range map[string]map[string]string{obs.SkipOptIn: ExecExclusions(), obs.SkipProviderTerms: E2BExclusions()} {
		m, in = Plan(Options{Mode: "exec", Excluded: excluded, ExcludedKind: kind}, &obs.Survey{Vsock: true}, "box-1", Storage{}, "", "", "")
		want := map[string]string{"SEC-4": kind, "EGR-3": kind, "AMP-6": kind, "AMP-7": kind}
		if !maps.Equal(m.SkipKinds, want) || m.Skipped["SEC-4"] != excluded["SEC-4"] {
			t.Errorf("%s: kinds %v, SEC-4's reason %q", kind, m.SkipKinds, m.Skipped["SEC-4"])
		}
		if b, _ := json.Marshal(in); strings.Contains(string(b), kind) {
			t.Errorf("%s: the probe's input carries the kind: %s", kind, b)
		}
		if err := grade.ManifestSound(m); err != nil {
			t.Fatalf("%s: the grader refused the manifest: %v", kind, err)
		}
	}
	m, _ = Plan(Options{Mode: "exec", Excluded: E2BExclusions()}, &obs.Survey{}, "box-1", Storage{}, "", "", "")
	if m.SkipKinds != nil {
		t.Errorf("no kind was given, yet the plan records %v", m.SkipKinds)
	}
	for name, kinds := range map[string]map[string]string{
		"not skipped":        {"AMP-2": obs.SkipProviderTerms},
		"not an endpoint":    {"EGR-6": obs.SkipProviderTerms},
		"not a kind":         {"SEC-4": "terms"},
		"skipped by nothing": {"PER-1": obs.SkipOptIn},
	} {
		m, _ = Plan(Options{Mode: "exec", Excluded: E2BExclusions(), ExcludedKind: obs.SkipProviderTerms}, &obs.Survey{}, "box-1", Storage{}, "", "", "")
		maps.Copy(m.SkipKinds, kinds)
		if grade.ManifestSound(m) == nil {
			t.Errorf("%s: a kind the host can't record passed", name)
		}
	}
	if _, err := Execute(context.Background(), surveyBox{}, nil, Options{Mode: "exec", ExcludedKind: "terms"}); err == nil {
		t.Error("Execute took a kind that isn't one")
	}
}

// HCN-5 in Execute: a run without a canary asks no canary anything.
func TestExecuteNoCanaryAsksNothing(t *testing.T) {
	c := &fakeCanary{answer: func(q canary.Request) canary.Answer { t.Fatalf("asked the canary %s", q.Op); return canary.Answer{} }}
	r, err := Execute(context.Background(), surveyBox{}, c, Options{Mode: "exec", NoCanary: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(c.asks) != 0 || r.Evidence.Live || len(r.Evidence.Health) != 0 {
		t.Fatalf("asks %v, live %v, health %v", c.asks, r.Evidence.Live, r.Evidence.Health)
	}
	if in := r.Input; in.CanaryPin != "" || in.CanaryDomain != "" || len(in.Endpoints) != 0 || len(in.CheckNonces) != 0 {
		t.Fatalf("the probe was told of a canary: %+v", in)
	}
}

// PRV-15 in Plan and Execute: attested checks are selected and recorded, sorted, in the manifest only; the rest keep
// their opt-in kind; AMP-6 never connects on an existing box, whatever was attested; and Execute refuses an
// attestation that isn't a provider endpoint, is named twice, or is still excluded.
func TestPlanAttested(t *testing.T) {
	off := map[string]string{}
	for id, why := range ExecExclusions() {
		if id != "SEC-4" && id != "AMP-7" {
			off[id] = why
		}
	}
	m, in := Plan(Options{Mode: "exec", Excluded: off, ExcludedKind: obs.SkipOptIn, Attested: []string{"SEC-4", "AMP-7"}, Existing: true},
		&obs.Survey{KubeAPI: "10.96.0.1:443"}, "box-1", Storage{}, "", "", "")
	if !slices.Equal(m.Attested, []string{"AMP-7", "SEC-4"}) || !slices.Contains(m.Selected, "SEC-4") || !slices.Contains(m.Selected, "AMP-7") ||
		!maps.Equal(m.SkipKinds, map[string]string{"EGR-3": obs.SkipOptIn, "AMP-6": obs.SkipOptIn}) || m.KubeAPI != "10.96.0.1:443" {
		t.Fatalf("attested %v, selected %v, kinds %v", m.Attested, m.Selected, m.SkipKinds)
	}
	if b, _ := json.Marshal(in); strings.Contains(string(b), "ttest") || !slices.Contains(in.Selected, "SEC-4") || in.KubeAPI != "10.96.0.1:443" {
		t.Errorf("the probe's input: %s", b)
	}
	if err := grade.ManifestSound(m); err != nil {
		t.Fatalf("the grader refused the manifest: %v", err)
	}
	delete(off, "AMP-6")
	for existing, want := range map[bool]string{true: "an existing box gets no vsock connects (PRV-1)", false: ""} {
		m, _ = Plan(Options{Mode: "exec", Excluded: off, ExcludedKind: obs.SkipOptIn, Attested: []string{"AMP-6"}, Existing: existing},
			&obs.Survey{Vsock: true}, "box-1", Storage{}, "", "", "")
		if m.Skipped["AMP-6"] != want || m.SkipKinds["AMP-6"] != "" || slices.Contains(m.Selected, "AMP-6") == existing {
			t.Errorf("existing %v: AMP-6 skipped %q, kind %q", existing, m.Skipped["AMP-6"], m.SkipKinds["AMP-6"])
		}
	}
	// EGR-3 turned on: through the agent's proxy, a state no run reached before; without a canary it's graded unknown
	// and never sent to the probe; a loopback proxy still needs -allow-local-proxy, and its skip has no kind.
	egr3 := map[string]string{"AMP-6": "off"}
	m, in = Plan(Options{Mode: "exec", Excluded: egr3, ExcludedKind: obs.SkipOptIn, Attested: []string{"EGR-3"}, Existing: true, NoCanary: true},
		&obs.Survey{Proxy: &obs.ProxySetting{Addr: "198.51.100.7:3128"}}, "box-1", Storage{}, "", "", "")
	if err := grade.ManifestSound(m); err != nil || !slices.Contains(m.Selected, "EGR-3") || slices.Contains(in.Selected, "EGR-3") || m.Proxy != "198.51.100.7:3128" {
		t.Errorf("EGR-3 without a canary: %v, selected %v, sent %v, proxy %q", err, m.Selected, in.Selected, m.Proxy)
	}
	m, _ = Plan(Options{Mode: "exec", Excluded: egr3, ExcludedKind: obs.SkipOptIn, Attested: []string{"EGR-3"}, Existing: true},
		&obs.Survey{Proxy: &obs.ProxySetting{Addr: "127.0.0.1:3128"}}, "box-1", Storage{}, "", "", "")
	if m.Skipped["EGR-3"] == "" || m.SkipKinds["EGR-3"] != "" || m.Proxy != "" || grade.ManifestSound(m) != nil {
		t.Errorf("a loopback proxy without approval: skipped %q, kind %q, proxy %q", m.Skipped["EGR-3"], m.SkipKinds["EGR-3"], m.Proxy)
	}
	for name, mutate := range map[string]func(*obs.Manifest){
		"not an endpoint":   func(m *obs.Manifest) { m.Attested = append(m.Attested, "SEC-3") },
		"named twice":       func(m *obs.Manifest) { m.Attested = append(m.Attested, m.Attested[0]) },
		"still a skip kind": func(m *obs.Manifest) { m.Attested = append(m.Attested, "EGR-3") },
	} {
		m, _ := Plan(Options{Mode: "exec", Excluded: map[string]string{"EGR-3": "off"}, ExcludedKind: obs.SkipOptIn, Attested: []string{"SEC-4"}},
			&obs.Survey{}, "box-1", Storage{}, "", "", "")
		mutate(&m)
		if grade.ManifestSound(m) == nil {
			t.Errorf("%s: the grader took it", name)
		}
	}
	for _, o := range []Options{{Attested: []string{"AMP-2"}}, {Attested: []string{"SEC-4", "SEC-4"}},
		{Excluded: map[string]string{"SEC-4": "off"}, Attested: []string{"SEC-4"}}} {
		o.Mode = "exec"
		if _, err := Execute(context.Background(), surveyBox{}, nil, o); err == nil {
			t.Errorf("Execute took %+v", o)
		}
	}
}

// DKR-2 and DKR-4: the adapter's own facts reach the probe's input only, never the manifest (whose fields are OUT-1's
// schema), and Sandprobe's scratch mount is never a root PER-5 may mark, whatever the survey says of it.
func TestPlanOwnInitAndScratch(t *testing.T) {
	s := &obs.Survey{Roots: []obs.Root{{Path: "/home/agent", Kinds: []string{"home"}}, {Path: "/opt/sandprobe/scratch", Kinds: []string{"wd", "mount"}}}}
	m, in := Plan(Options{Mode: "exec", OwnInit: true, Scratch: "/opt/sandprobe/scratch"}, s, "box-1", Storage{Model: "restore"}, "203.0.113.10", "sandprobe.test", "pin")
	if !in.OwnInit || in.Scratch != "/opt/sandprobe/scratch" {
		t.Errorf("want both facts in the probe's input, got own_init %v, scratch %q", in.OwnInit, in.Scratch)
	}
	if len(m.Marks) != 1 || m.Marks[0].Root != "/home/agent" {
		t.Errorf("want only the home marked, never Sandprobe's scratch: %+v", m.Marks)
	}
	if len(s.Roots) != 2 {
		t.Errorf("the survey itself is left as the box reported it: %+v", s.Roots)
	}
	if _, in := Plan(Options{Mode: "exec"}, s, "box-1", Storage{}, "203.0.113.10", "sandprobe.test", "pin"); in.OwnInit || in.Scratch != "" {
		t.Errorf("no adapter fact: want neither in the input, got %+v", in)
	}
	for _, bad := range []string{"/tmp", "/", "scratch", "/opt/sandprobe/../tmp"} {
		if _, err := Execute(context.Background(), &fakeBox{id: "box-1"}, nil, Options{Mode: "exec", Scratch: bad}); err == nil || !strings.Contains(err.Error(), "DKR-4") {
			t.Errorf("scratch %q: want a refusal before the survey, got %v", bad, err)
		}
	}
}
