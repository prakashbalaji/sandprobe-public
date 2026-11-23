package grade

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"sandprobe/internal/catalog"
	"sandprobe/internal/obs"
)

var t0 = time.Date(2026, 11, 9, 23, 0, 0, 0, time.UTC)

// base is a clean box: every two-sided check proven over its whole plan, every find-only check not_found, an
// unprivileged identity, and the canary live and healthy across the host's launch-to-return bracket.
func base() (obs.Manifest, *obs.Doc, *obs.CanaryEvidence) {
	ids := catalog.IDs()
	targets, discover := catalog.Plan(ids)
	m := obs.Manifest{RunID: "r1", Nonce: "n1", BoxID: "box-1", ProbeSHA256: "abc", Mode: "exec", Selected: ids,
		Targets: targets, Discover: discover, CheckNonces: map[string]string{}, Endpoints: map[string]string{}, Proxy: "proxy.example:3128"}
	d := &obs.Doc{Schema: obs.Schema, RunID: "r1", Nonce: "n1", BoxID: "box-1", ProbeSHA256: "abc", DurationMS: 9600,
		Identity: &obs.Identity{UID: 1001, GID: 1001, CapEff: "0000000000000000", CapPrm: "0000000000000000", CapInh: "0000000000000000",
			CapBnd: "000001ffffffffff", CapAmb: "0000000000000000", NoNewPrivs: ptr(1), SetuidScan: &obs.SetuidScan{Complete: true}}}
	// PER-5 needs a reset; the base box is one whose provider leaves no storage to test, so it's skipped (GRD-3).
	m.Selected = slices.DeleteFunc(m.Selected, func(id string) bool { return id == "PER-5" })
	m.Skipped = map[string]string{"PER-5": "the provider's reset leaves no storage to test"}
	for _, ck := range catalog.Checks {
		if ck.Derived || ck.Recheck {
			continue // the host grades AMP-2 and AMP-3 from the identity, and PER-5 from the reset; the probe doesn't report them
		}
		o := obs.Observation{ID: ck.ID}
		switch {
		case ck.Canary != nil:
			m.CheckNonces[ck.ID], m.Endpoints[ck.ID] = "n-"+ck.ID, fmt.Sprintf("203.0.113.10:%d", ck.Canary.Port)
			a := try(m, ck.ID, obs.Attempt{Outcome: "refused", SynSent: true, LoopbackTwin: true})
			if ck.Canary.Route == "proxy" {
				a.Via = "198.51.100.7:3128" // what proxy.example resolved to in the box
			}
			o.Result, o.Attempts = obs.Attempted, []obs.Attempt{a}
		case ck.Kind == catalog.TwoSided:
			o.Result, o.Proof = obs.Pass, proofFor(ck.ID)
		default:
			o.Result = obs.NotFound
		}
		d.Observations = append(d.Observations, o)
	}
	c := &obs.CanaryEvidence{Live: true, Launched: t0, Returned: t0.Add(10 * time.Second), Health: map[string][]time.Time{},
		ReceiptsRead: true, ReceiptsQueriedAt: t0.Add(13 * time.Second)}
	for _, key := range []string{"tcp/443", "tcp/22", "tcp/80", "tcp/8080", "udp/53", "dns/53"} {
		for t := t0.Add(-500 * time.Millisecond); !t.After(t0.Add(11 * time.Second)); t = t.Add(time.Second) {
			c.Health[key] = append(c.Health[key], t)
		}
	}
	return m, d, c
}

func ptr(n int) *int { return &n }

// proofFor is a passing proof over the check's whole plan: every planned target refused with an eligible error, every
// discovery rule reported, and one discovered target where nothing is planned.
func proofFor(id string) *obs.Proof {
	ck, _ := catalog.Get(id)
	p := &obs.Proof{Mechanism: ck.Mechanism, Twin: true, Discovered: map[string]int{}}
	if catalog.Counted[ck.Mechanism] {
		p.Count = 12
	}
	for _, rule := range ck.Discover {
		p.Discovered[rule] = 0
	}
	refusals, refusalBased := catalog.Refusals[ck.Mechanism]
	if !refusalBased {
		return p
	}
	p.TwinRefused = true
	for _, name := range ck.Targets {
		p.Targets = append(p.Targets, obs.Target{Name: name, State: "refused", Errno: refusals[0]})
	}
	if len(p.Targets) == 0 {
		rule := ck.Discover[0]
		p.Discovered[rule] = 1
		p.Targets = append(p.Targets, obs.Target{Name: "/discovered/1", Rule: rule, State: "refused", Errno: refusals[0]})
	}
	return p
}

// absentProof: every planned target verified absent, every discovery rule finding nothing.
func absentProof(id string) *obs.Proof {
	ck, _ := catalog.Get(id)
	p := &obs.Proof{Mechanism: ck.Mechanism, Discovered: map[string]int{}}
	for _, rule := range ck.Discover {
		p.Discovered[rule] = 0
	}
	for _, name := range ck.Targets {
		p.Targets = append(p.Targets, obs.Target{Name: name, State: "absent", Errno: "ENOENT", ParentSearchable: true})
	}
	return p
}

// try fills in an attempt's planned destination and offsets inside the probe's run.
func try(m obs.Manifest, id string, a obs.Attempt) obs.Attempt {
	if a.Dest == "" {
		a.Dest = m.Endpoints[id]
	}
	if a.EndMS == 0 {
		a.StartMS, a.EndMS = 2000, 2500
	}
	return a
}

func at(d *obs.Doc, id string) *obs.Observation {
	for i := range d.Observations {
		if d.Observations[i].ID == id {
			return &d.Observations[i]
		}
	}
	panic(id)
}

// add reports an observation the base doesn't carry (AMP-2 and AMP-3 are graded from the identity).
func add(d *obs.Doc, o obs.Observation) { d.Observations = append(d.Observations, o) }

func find(d *obs.Doc, id, variant string) {
	o := at(d, id)
	o.Result, o.Variant, o.Proof, o.Evidence = obs.Finding, variant, nil, "planted"
}

func receipt(c *obs.CanaryEvidence) {
	c.Receipts = append(c.Receipts, obs.Receipt{Nonce: "n-EGR-2", Proto: "tcp", Port: 443})
}

// asRoot runs the whole box as uid 0: every proof says so, and AMP-2 is the finding the identity demands.
func asRoot(d *obs.Doc) {
	d.Identity.UID = 0
	for i := range d.Observations {
		if p := d.Observations[i].Proof; p != nil {
			p.Root = true
		}
	}
}

type mutation func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence)

func attempts(as ...obs.Attempt) mutation {
	return func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
		o := at(d, "EGR-2")
		o.Attempts = nil
		for _, a := range as {
			o.Attempts = append(o.Attempts, try(*m, "EGR-2", a))
		}
	}
}

func outcome(r Report, id string) Outcome {
	for _, o := range r.Outcomes {
		if o.ID == id {
			return o
		}
	}
	return Outcome{}
}

func hasFinding(r Report, id string) (Finding, bool) {
	for _, f := range r.Findings {
		if f.ID == id {
			return f, true
		}
	}
	return Finding{}, false
}

func TestInvalidRuns(t *testing.T) {
	cases := map[string]mutation{
		"duplicate check": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			d.Observations = append(d.Observations, *at(d, "SEC-2"))
		},
		"ID not in the catalog": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			d.Observations = append(d.Observations, obs.Observation{ID: "SEC-99", Result: obs.Unknown})
		},
		"skipped check reported": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			m.Selected = slices.DeleteFunc(m.Selected, func(s string) bool { return s == "AMP-6" })
			m.Skipped["AMP-6"] = "no vsock device"
		},
		"AMP-2 and AMP-3 skipped": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			m.Selected = slices.DeleteFunc(m.Selected, func(s string) bool { return s == "AMP-2" || s == "AMP-3" })
			m.Skipped["AMP-2"] = "not wanted"
			m.Skipped["AMP-3"] = "not wanted"
		},
		"every check skipped": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			m.Skipped = map[string]string{}
			for _, id := range m.Selected {
				m.Skipped[id] = "not wanted"
			}
			m.Selected, d.Observations = nil, nil
		},
		"a gated check skipped among ungated ones": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			m.Selected = slices.DeleteFunc(m.Selected, func(s string) bool { return s == "SEC-2" || s == "EGR-6" })
			m.Skipped["SEC-2"] = "not wanted"
			m.Skipped["EGR-6"] = "not approved"
			d.Observations = slices.DeleteFunc(d.Observations, func(o obs.Observation) bool { return o.ID == "SEC-2" || o.ID == "EGR-6" })
		},
		"a check neither selected nor skipped": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			m.Selected = slices.DeleteFunc(m.Selected, func(s string) bool { return s == "SEC-2" })
			d.Observations = slices.DeleteFunc(d.Observations, func(o obs.Observation) bool { return o.ID == "SEC-2" })
		},
		"a check both selected and skipped": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			m.Skipped["AMP-6"] = "no vsock device"
		},
		"a check selected twice": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			m.Selected = append(m.Selected, "SEC-1")
		},
		"a skip without a reason": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			m.Selected = slices.DeleteFunc(m.Selected, func(s string) bool { return s == "AMP-6" })
			m.Skipped["AMP-6"] = ""
			d.Observations = slices.DeleteFunc(d.Observations, func(o obs.Observation) bool { return o.ID == "AMP-6" })
		},
		"a skipped ID not in the catalog": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			m.Skipped["SEC-99"] = "not a check"
		},
		"EGR-3 with a planned proxy, marked unparseable": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			m.ProxyMalformed = true
		},
		"an attempt through a proxy the plan couldn't parse": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			m.Proxy, m.ProxyMalformed = "", true
		},
		"forged pass on find-only": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			o := at(d, "AMP-1")
			o.Result, o.Proof = obs.Pass, proofFor("AMP-1")
		},
		"pass without proof":       func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) { at(d, "SEC-2").Proof = nil },
		"proof with any mechanism": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) { at(d, "PER-1").Proof.Mechanism = "x" },
		"pass holding a found target": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			at(d, "SEC-3").Proof.Targets[0].State = "found"
		},
		"unknown target state": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			at(d, "SEC-3").Proof.Targets[0].State = "maybe"
		},
		"an unplanned target": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			p := at(d, "SEC-3").Proof
			p.Targets = append(p.Targets, obs.Target{Name: "/etc/hosts", State: "refused", Errno: "EACCES"})
		},
		"a target listed twice": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			p := at(d, "SEC-3").Proof
			p.Targets = append(p.Targets, p.Targets[0])
		},
		"a target from an unplanned rule": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			p := at(d, "SEC-3").Proof
			p.Targets = append(p.Targets, obs.Target{Name: "/x", Rule: "bogus", State: "refused", Errno: "EACCES"})
		},
		"an unplanned discovery rule": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			at(d, "SEC-3").Proof.Discovered["bogus"] = 0
		},
		"absent on a check that can't be": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			at(d, "PER-1").Result = obs.Absent
		},
		"absent without proof": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			o := at(d, "SEC-3")
			o.Result, o.Proof = obs.Absent, nil
		},
		"proof on a finding": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			find(d, "SEC-1", "names")
			at(d, "SEC-1").Proof = proofFor("SEC-1")
		},
		"attempt to another endpoint": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			at(d, "EGR-2").Attempts[0].Dest = "198.51.100.7:443"
		},
		"nonce mismatch":        func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) { d.Nonce = "other" },
		"box ID mismatch":       func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) { d.BoxID = "box-2" },
		"probe digest mismatch": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) { d.ProbeSHA256 = "def" },
		"run ID mismatch":       func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) { d.RunID = "r2" },
		"wrong schema":          func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) { d.Schema = "sandprobe.obs/0" },
		"negative run time":     func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) { d.DurationMS = -1 },
		"no identity":           func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) { d.Identity = nil },
		"a CapEff that isn't hex": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			d.Identity.CapEff = "all of them"
		},
		"a root flag the identity contradicts": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			p := at(d, "PER-1").Proof
			p.Root, p.TwinRefused = true, false
		},
		"AMP-2 passing with dangerous capabilities": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			d.Identity.CapEff = "0000000000200000"
			add(d, obs.Observation{ID: "AMP-2", Result: obs.Pass})
		},
		"AMP-2 claiming root as an ordinary user": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			add(d, obs.Observation{ID: "AMP-2", Result: obs.Finding, Variant: "root"})
		},
		"AMP-2 scoped out while running as root": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			asRoot(d)
			add(d, obs.Observation{ID: "AMP-2", Result: obs.ScopedOut, Reason: "not applicable"})
		},
		"AMP-2 unknown while the identity is known": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			add(d, obs.Observation{ID: "AMP-2", Result: obs.Unknown})
		},
		"AMP-3 finding with NoNewPrivs set": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			add(d, obs.Observation{ID: "AMP-3", Result: obs.Finding, Variant: "new_privs"})
		},
		"NoNewPrivs missing": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) { d.Identity.NoNewPrivs = nil },
		"NoNewPrivs 2":       func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) { d.Identity.NoNewPrivs = ptr(2) },
		"AMP-3 passing while the setuid scan failed": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			d.Identity.NoNewPrivs, d.Identity.SetuidScan = ptr(0), &obs.SetuidScan{Complete: false}
			add(d, obs.Observation{ID: "AMP-3", Result: obs.Pass})
		},
		"AMP-3 finding with no setuid file": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			d.Identity.NoNewPrivs = ptr(0)
			add(d, obs.Observation{ID: "AMP-3", Result: obs.Finding, Variant: "new_privs"})
		},
		"AMP-3 passing with setuid files and NoNewPrivs 0": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			d.Identity.NoNewPrivs, d.Identity.SetuidScan = ptr(0), &obs.SetuidScan{Complete: true, Files: []string{"/usr/bin/passwd"}}
			add(d, obs.Observation{ID: "AMP-3", Result: obs.Pass})
		},
		"a canary check without a nonce": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			delete(m.CheckNonces, "EGR-2")
			(*c).Receipts = []obs.Receipt{{Proto: "tcp", Port: 443}}
		},
		"two canary checks sharing a nonce": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			m.CheckNonces["EGR-3"] = m.CheckNonces["EGR-2"]
		},
		"a canary check without an endpoint": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			delete(m.Endpoints, "EGR-5.22")
			at(d, "EGR-5.22").Attempts = nil
		},
		"scoped_out on a check that can't be": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			o := at(d, "PER-1")
			o.Result, o.Reason = obs.ScopedOut, "not applicable"
		},
		"scoped_out without proof": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			o := at(d, "SEC-2")
			o.Result, o.Reason, o.Proof = obs.ScopedOut, "hidepid=2", nil
		},
		"scoped_out without its discovery count": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			o := at(d, "SEC-2")
			o.Result, o.Reason, o.Proof = obs.ScopedOut, "hidepid=2", &obs.Proof{Mechanism: "proc_open"}
		},
		"oversized evidence": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			at(d, "SEC-1").Evidence = strings.Repeat("x", obs.MaxField+1)
		},
		"unrecognised override": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			d.Overrides = map[string]string{"SANDPROBE_TEST_CANARY": "127.0.0.1"}
		},
		"canary finding claimed": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			o := at(d, "EGR-2")
			o.Result, o.Variant = obs.Finding, "receipt"
		},
		"canary pass claimed":      func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) { at(d, "EGR-2").Result = obs.Pass },
		"attempts on a file check": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) { at(d, "SEC-2").Attempts = []obs.Attempt{{}} },
		"variant not in catalog":   func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) { find(d, "SEC-1", "bogus") },
		"variant on a pass":        func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) { at(d, "SEC-2").Variant = "readable" },
		"scoped_out without reason": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			o := at(d, "SEC-2")
			o.Result, o.Proof = obs.ScopedOut, nil
		},
		"absent on find-only": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) { at(d, "SEC-4").Result = obs.Absent },
		"not_found on two-sided": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			o := at(d, "SEC-2")
			o.Result, o.Proof = obs.NotFound, nil
		},
		"skipped claimed by probe": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			o := at(d, "SEC-2")
			o.Result, o.Proof = obs.Skipped, nil
		},
		// the manifest alone is unsound here: the probe contacted nothing
		"EGR-3 selected with no planned proxy": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			m.Proxy = ""
			*at(d, "EGR-3") = obs.Observation{ID: "EGR-3", Result: obs.Unknown, Reason: "no proxy"}
		},
		"EGR-3 planned through a loopback proxy nobody approved": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			m.Proxy = "localhost:3128"
			*at(d, "EGR-3") = obs.Observation{ID: "EGR-3", Result: obs.Unknown, Reason: "not approved"}
		},
		"EGR-3 planned through 127.0.0.1, unapproved": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			m.Proxy = "127.0.0.1:3128"
			*at(d, "EGR-3") = obs.Observation{ID: "EGR-3", Result: obs.Unknown, Reason: "not approved"}
		},
		"a proxy-route attempt that doesn't name its proxy": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			at(d, "EGR-3").Attempts[0].Via = ""
		},
		"an attempt through a proxy on another port": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			at(d, "EGR-3").Attempts[0].Via = "198.51.100.7:8080"
		},
		"an attempt through another proxy than the planned address": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			m.Proxy = "198.51.100.7:3128"
			at(d, "EGR-3").Attempts[0].Via = "198.51.100.8:3128"
		},
		"a planned name that resolved to loopback, unapproved": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			at(d, "EGR-3").Attempts[0].Via = "127.0.0.1:3128"
		},
		"a direct attempt through a proxy": func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			at(d, "EGR-2").Attempts[0].Via = "198.51.100.7:3128"
		},
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			m, d, c := base()
			mut(&m, d, &c)
			r := Grade(m, d, c)
			if r.Valid || r.Invalid == "" || r.Letter != "" {
				t.Fatalf("want an invalid run with no letter, got valid=%v letter=%q", r.Valid, r.Letter)
			}
		})
	}
}

func TestGrades(t *testing.T) {
	cases := []struct {
		name   string
		mut    mutation
		letter string
		check  func(t *testing.T, r Report)
	}{
		{"clean box", nil, "A", func(t *testing.T, r Report) {
			if !r.Complete || len(r.Unknown) > 0 {
				t.Fatalf("want complete, got unknown %v", r.Unknown)
			}
			for _, id := range []string{"SEC-4", "EGR-1", "EGR-3", "EGR-5.53u", "AMP-1", "AMP-6"} {
				if !slices.Contains(r.NotProven, id) {
					t.Errorf("%s should be listed as not proven", id)
				}
			}
		}},
		{"an omitted check is unknown and caps at C", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			d.Observations = slices.DeleteFunc(d.Observations, func(o obs.Observation) bool { return o.ID == "SEC-2" })
		}, "C", func(t *testing.T, r Report) {
			if r.Complete || !slices.Contains(r.Unknown, "SEC-2") {
				t.Fatal("want SEC-2 unknown and the run incomplete")
			}
		}},
		{"a skipped check is listed, not graded", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			m.Selected = slices.DeleteFunc(m.Selected, func(s string) bool { return s == "AMP-6" })
			m.Skipped["AMP-6"] = "no vsock device"
			d.Observations = slices.DeleteFunc(d.Observations, func(o obs.Observation) bool { return o.ID == "AMP-6" })
		}, "A", func(t *testing.T, r Report) {
			if r.Skipped["AMP-6"] == "" {
				t.Fatal("want AMP-6 listed as skipped")
			}
		}},
		{"scoped out with discovery finding nothing", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			o := at(d, "SEC-2")
			o.Result, o.Reason = obs.ScopedOut, "hidepid=2: no other process visible"
			o.Proof = &obs.Proof{Mechanism: "proc_open", Discovered: map[string]int{"proc_pids": 0}}
		}, "A", func(t *testing.T, r Report) {
			if !slices.Contains(r.ScopedOut, "SEC-2") {
				t.Fatal("want SEC-2 scoped out")
			}
		}},
		{"test overrides are flagged", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			m.Overrides = []string{"SANDPROBE_TEST_CANARY"}
			d.Overrides = map[string]string{"SANDPROBE_TEST_CANARY": "10.0.0.5"}
		}, "A", func(t *testing.T, r Report) {
			if !r.TestEndpoints {
				t.Fatal("want TEST ENDPOINTS flagged")
			}
		}},
		{"box text is kept as data", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			find(d, "SEC-1", "names")
			at(d, "SEC-1").Evidence = "<script>alert(1)</script>"
		}, "D", func(t *testing.T, r Report) {
			if outcome(r, "SEC-1").Evidence != "<script>alert(1)</script>" {
				t.Fatal("the grader must not alter evidence; the renderer escapes it")
			}
		}},

		// coverage and verified absence (TWN-1, TWN-2)
		{"sudo verified absent at every planned path", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			o := at(d, "AMP-1")
			o.Result, o.Proof = obs.Absent, absentProof("AMP-1")
		}, "A", nil},
		{"sudo absent at /usr/bin but /bin/sudo omitted: unknown", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			o := at(d, "AMP-1")
			o.Result, o.Proof = obs.Absent, absentProof("AMP-1")
			o.Proof.Targets = slices.DeleteFunc(o.Proof.Targets, func(t obs.Target) bool { return t.Name == "/bin/sudo" })
		}, "C", nil},
		{"credential files verified absent", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			o := at(d, "SEC-3")
			o.Result, o.Proof = obs.Absent, absentProof("SEC-3")
		}, "A", nil},
		{"one credential path absent, another omitted: unknown", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			o := at(d, "SEC-3")
			o.Result, o.Proof = obs.Absent, absentProof("SEC-3")
			o.Proof.Targets = o.Proof.Targets[:1]
		}, "C", nil},
		{"absence without a searchable parent: unknown", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			o := at(d, "SEC-3")
			o.Result, o.Proof = obs.Absent, absentProof("SEC-3")
			o.Proof.Targets[3].ParentSearchable = false
		}, "C", nil},
		{"a pass with a planned target omitted: unknown", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			p := at(d, "SEC-3").Proof
			p.Targets = p.Targets[:len(p.Targets)-1]
		}, "C", nil},
		{"a discovery count that doesn't match its targets: unknown", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			at(d, "SEC-2").Proof.Discovered["proc_pids"] = 2
		}, "C", nil},
		{"a discovery rule not reported: unknown", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			delete(at(d, "SEC-3").Proof.Discovered, "dotenv")
		}, "C", nil},
		{"a pass whose absent target isn't verified: unknown", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			t := &at(d, "SEC-3").Proof.Targets[1]
			t.State, t.Errno = "absent", "ENOTDIR"
		}, "C", nil},
		{"a refusal this mechanism doesn't count: unknown", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			at(d, "PER-1").Proof.Targets[0].Errno = "EPERM"
		}, "C", nil},
		{"no twin: unknown", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) { at(d, "SEC-1").Proof.Twin = false }, "C", nil},
		{"the twin's refusing side missing: unknown", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			at(d, "PER-1").Proof.TwinRefused = false
		}, "C", nil},
		// an agent whose capabilities pass the read call (CAP_DAC_READ_SEARCH, CAP_DAC_OVERRIDE) opens its own 0000 file,
		// so the file-read twin can't refuse, and no non-root pass stands (TWN-1, TWN-4)
		{"the file-read twin's refusing side missing: unknown", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			at(d, "SEC-3").Proof.TwinRefused = false
		}, "C", nil},
		{"an environment read of nothing: unknown", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) { at(d, "SEC-1").Proof.Count = 0 }, "C", nil},
		{"a socket table read of nothing: unknown", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) { at(d, "AMP-5").Proof.Count = 0 }, "C", nil},

		{"scoped out while discovery found devices: unknown", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			o := at(d, "AMP-8.blk")
			o.Result, o.Reason = obs.ScopedOut, "no block devices"
			o.Proof = &obs.Proof{Mechanism: "read_perm", Discovered: map[string]int{"block_devices": 1}}
		}, "C", nil},

		// identity decides AMP-2 and AMP-3, reported or not
		{"running as root is F with AMP-2 omitted", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) { asRoot(d) }, "F", func(t *testing.T, r Report) {
			if len(r.Notes) == 0 || outcome(r, "AMP-2").Variant != "root" {
				t.Fatal("want AMP-2 root from the identity, and the CHN-2 note")
			}
		}},
		{"AMP-2 reported in agreement", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			asRoot(d)
			add(d, obs.Observation{ID: "AMP-2", Result: obs.Finding, Variant: "root"})
		}, "F", nil},
		{"dangerous capabilities are F", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) { d.Identity.CapEff = "0000000000200000" }, "F", nil},
		{"other capabilities are D", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) { d.Identity.CapEff = "0000000000000400" }, "D", nil},
		{"NoNewPrivs 0 with no setuid file and a bounding set: unknown", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			d.Identity.NoNewPrivs = ptr(0)
		}, "C", func(t *testing.T, r Report) {
			if o := outcome(r, "AMP-3"); o.Result != obs.Unknown || !strings.Contains(o.Reason, "file capabilities") {
				t.Fatalf("want AMP-3 unknown naming file capabilities, got %+v", o)
			}
		}},
		{"NoNewPrivs 0 with no setuid file and empty bounding and inheritable sets passes", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			d.Identity.NoNewPrivs, d.Identity.CapBnd = ptr(0), "0000000000000000"
		}, "A", nil},
		{"NoNewPrivs 0 with no setuid scan: unknown", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			d.Identity.NoNewPrivs, d.Identity.SetuidScan = ptr(0), nil
		}, "C", func(t *testing.T, r Report) {
			if outcome(r, "AMP-3").Result != obs.Unknown {
				t.Fatal("want AMP-3 unknown")
			}
		}},
		{"NoNewPrivs 0 with a failed setuid scan: unknown", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			d.Identity.NoNewPrivs, d.Identity.SetuidScan = ptr(0), &obs.SetuidScan{Complete: false}
		}, "C", nil},
		{"NoNewPrivs 0 with setuid files is a Medium finding", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			d.Identity.NoNewPrivs, d.Identity.SetuidScan = ptr(0), &obs.SetuidScan{Complete: true, Files: []string{"/usr/bin/passwd"}}
		}, "C", func(t *testing.T, r Report) {
			if outcome(r, "AMP-3").Variant != "new_privs" {
				t.Fatal("want AMP-3 new_privs from the identity")
			}
		}},
		{"setuid files with NoNewPrivs set pass", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			d.Identity.SetuidScan = &obs.SetuidScan{Complete: true, Files: []string{"/usr/bin/passwd"}}
		}, "A", nil},

		// letters
		{"a Low indicator is B", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) { find(d, "PER-1", "writable") }, "B", nil},
		{"an empty credential file is Info", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) { find(d, "SEC-3", "empty") }, "A", nil},
		{"named NOPASSWD is High", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) { find(d, "AMP-1", "nopasswd_named") }, "D", nil},
		{"NOPASSWD ALL is F with the CHN-2 note", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) { find(d, "AMP-1", "nopasswd_all") }, "F", func(t *testing.T, r Report) {
			if len(r.Notes) == 0 {
				t.Fatal("want the CHN-2 note")
			}
		}},
		{"a control-socket indicator never triggers CHN-2", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) { find(d, "AMP-4", "control_socket") }, "D", func(t *testing.T, r Report) {
			if len(r.Notes) > 0 {
				t.Fatal("indicators must not trigger CHN-2")
			}
		}},

		// the canary decides network results
		{"a receipt is a finding", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) { receipt(*c) }, "C", func(t *testing.T, r Report) {
			if o := outcome(r, "EGR-2"); o.Result != obs.Finding || o.Class != catalog.Proof {
				t.Fatalf("want EGR-2 a proven finding, got %+v", o)
			}
		}},
		{"another run's receipt doesn't count", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			(*c).Receipts = []obs.Receipt{{Nonce: "n0-EGR-2", Proto: "tcp", Port: 443}}
		}, "A", nil},
		{"a proxy-only receipt doesn't count as direct", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			(*c).Receipts = []obs.Receipt{{Nonce: "n-EGR-3", Proto: "tcp", Port: 443}}
		}, "C", func(t *testing.T, r Report) {
			if outcome(r, "EGR-3").Result != obs.Finding || outcome(r, "EGR-2").Result != obs.Pass {
				t.Fatalf("want EGR-3 found and EGR-2 still passing, got %+v and %+v", outcome(r, "EGR-3"), outcome(r, "EGR-2"))
			}
		}},
		{"no live canary: network unknown", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) { (*c).Live = false }, "C", func(t *testing.T, r Report) {
			for _, id := range []string{"EGR-1", "EGR-2", "EGR-5.22"} {
				if outcome(r, id).Result != obs.Unknown {
					t.Errorf("%s should be unknown", id)
				}
			}
		}},
		{"no canary at all: network unknown", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) { *c = nil }, "C", nil},
		{"a failed receipt fetch: network unknown, never a pass", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			(*c).ReceiptsRead = false
		}, "C", func(t *testing.T, r Report) {
			for _, id := range []string{"EGR-1", "EGR-2", "EGR-5.22"} {
				if outcome(r, id).Result != obs.Unknown {
					t.Errorf("%s should be unknown", id)
				}
			}
		}},
		{"a receipt query sent right after the probe returned: unknown", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			(*c).ReceiptsQueriedAt = (*c).Returned.Add(100 * time.Millisecond) // whatever the canary's own clock says
		}, "C", func(t *testing.T, r Report) {
			if outcome(r, "EGR-2").Result != obs.Unknown {
				t.Fatal("a query sent before the grace period must not authorize a pass")
			}
		}},
		{"a receipt query sent 2 s after return counts", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			(*c).ReceiptsQueriedAt = (*c).Returned.Add(2 * time.Second)
		}, "A", nil},
		{"an overloaded canary: no network negative, pass or not_found", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			(*c).Overloaded = true
		}, "C", func(t *testing.T, r Report) {
			for _, id := range []string{"EGR-1", "EGR-2", "EGR-5.22", "EGR-5.53u"} {
				if o := outcome(r, id); o.Result != obs.Unknown || !strings.Contains(o.Reason, "overloaded") {
					t.Errorf("%s: want unknown for the overload, got %+v", id, o)
				}
			}
		}},
		{"a receipt still finds when the canary was overloaded", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			(*c).Overloaded = true
			receipt(*c)
		}, "C", func(t *testing.T, r Report) {
			if o := outcome(r, "EGR-2"); o.Result != obs.Finding || !strings.Contains(o.Evidence, "not that this route carried it") {
				t.Fatalf("want a finding that claims only that the nonce got out, got %+v", o)
			}
		}},
		{"a receipt still counts when the fetch was partial", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			(*c).ReceiptsRead = false
			receipt(*c)
		}, "C", func(t *testing.T, r Report) {
			if outcome(r, "EGR-2").Result != obs.Finding {
				t.Fatal("a receipt in hand is a finding whatever else failed")
			}
		}},
		{"a health gap on the port: unknown", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			(*c).Health["tcp/443"] = slices.DeleteFunc((*c).Health["tcp/443"], func(t time.Time) bool { return t.After(t0.Add(3*time.Second)) && t.Before(t0.Add(7*time.Second)) })
		}, "C", func(t *testing.T, r Report) {
			if outcome(r, "EGR-2").Result != obs.Unknown || outcome(r, "EGR-5.22").Result != obs.Pass {
				t.Fatal("want only the port with the gap unknown")
			}
		}},
		{"health that stops before the probe returned: unknown", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			(*c).Health["tcp/443"] = slices.DeleteFunc((*c).Health["tcp/443"], func(t time.Time) bool { return t.After(t0.Add(9 * time.Second)) })
		}, "C", nil},
		{"health from another time than the bracket: unknown", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			(*c).Launched, (*c).Returned = t0.Add(time.Hour), t0.Add(time.Hour+10*time.Second)
		}, "C", func(t *testing.T, r Report) {
			if outcome(r, "EGR-2").Result != obs.Unknown {
				t.Fatal("want EGR-2 unknown")
			}
		}},
		{"a probe run longer than the bracket: unknown", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) { d.DurationMS = 20000 }, "C", nil},
		{"an attempt beyond the probe's run: unknown", attempts(obs.Attempt{Outcome: "refused", SynSent: true, LoopbackTwin: true, StartMS: 9000, EndMS: 99000}), "C", nil},
		{"no loopback twin: unknown", attempts(obs.Attempt{Outcome: "refused", SynSent: true}), "C", nil},
		{"skipped connect (no SYN_SENT): unknown", attempts(obs.Attempt{Outcome: "refused", LoopbackTwin: true}), "C", nil},
		{"immediate ECONNREFUSED: unknown", attempts(obs.Attempt{Immediate: true, Outcome: "refused", SynSent: true, LoopbackTwin: true}), "C", nil},
		{"immediate EPERM beside a filter: unknown", attempts(obs.Attempt{Immediate: true, Outcome: "eperm", SynSent: true, LoopbackTwin: true}), "C", nil},
		{"immediate unreachable, route lookup agrees: pass", attempts(obs.Attempt{Immediate: true, Outcome: "netunreach", RouteLookup: "none", LoopbackTwin: true}), "A", nil},
		{"immediate unreachable, route lookup disagrees: unknown", attempts(obs.Attempt{Immediate: true, Outcome: "netunreach", RouteLookup: "ok", LoopbackTwin: true}), "C", nil},
		{"one timeout: unknown", attempts(obs.Attempt{Outcome: "timeout", SynSent: true, SynRetrans: 3, LoopbackTwin: true}), "C", nil},
		{"two timeouts with retransmits: pass", attempts(
			obs.Attempt{Outcome: "timeout", SynSent: true, SynRetrans: 3, LoopbackTwin: true},
			obs.Attempt{Outcome: "timeout", SynSent: true, SynRetrans: 3, LoopbackTwin: true}), "A", nil},
		{"timeouts without retransmits: unknown", attempts(
			obs.Attempt{Outcome: "timeout", SynSent: true, LoopbackTwin: true},
			obs.Attempt{Outcome: "timeout", SynSent: true, LoopbackTwin: true}), "C", nil},
		{"a timeout then a refusal: unknown", attempts(
			obs.Attempt{Outcome: "timeout", SynSent: true, SynRetrans: 3, LoopbackTwin: true},
			obs.Attempt{Outcome: "refused", SynSent: true, LoopbackTwin: true}), "C", nil},
		{"connected with no receipt: unknown", attempts(obs.Attempt{Outcome: "connected", SynSent: true, LoopbackTwin: true}), "C", nil},
		{"no attempt recorded: unknown", attempts(), "C", nil},
		{"TLS interception makes EGR-2 unknown", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) { find(d, "EGR-4", "intercepted") }, "C", func(t *testing.T, r Report) {
			if outcome(r, "EGR-2").Result != obs.Unknown {
				t.Fatal("want EGR-2 unknown under interception")
			}
		}},
		{"a find-only canary check with no attempt: unknown", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			o := at(d, "EGR-1")
			o.Result, o.Attempts = obs.Unknown, nil
		}, "C", nil},

		// chains
		{"proven surface plus receipt: confirmed CHN-1, F", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			find(d, "SEC-2", "readable")
			receipt(*c)
		}, "F", func(t *testing.T, r Report) {
			if f, ok := hasFinding(r, "CHN-1"); !ok || f.Potential || f.Severity != catalog.Critical {
				t.Fatalf("want confirmed critical CHN-1, got %+v", f)
			}
		}},
		{"a secret-shaped name plus receipt: potential CHN-1", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			find(d, "SEC-1", "names")
			receipt(*c)
		}, "D", func(t *testing.T, r Report) {
			if f, ok := hasFinding(r, "CHN-1"); !ok || !f.Potential || f.Severity != catalog.High {
				t.Fatalf("want potential high CHN-1, got %+v", f)
			}
		}},
		{"an empty credential file plus receipt: potential CHN-1", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			find(d, "SEC-3", "empty")
			receipt(*c)
		}, "D", func(t *testing.T, r Report) {
			if f, _ := hasFinding(r, "CHN-1"); !f.Potential {
				t.Fatal("want CHN-1 potential")
			}
		}},
		{"a proven surface plus a handshake only: potential CHN-1", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			find(d, "SEC-2", "readable")
			find(d, "EGR-6", "handshake")
		}, "D", func(t *testing.T, r Report) {
			if f, _ := hasFinding(r, "CHN-1"); !f.Potential {
				t.Fatal("want CHN-1 potential")
			}
		}},
		{"a proven surface with no way out: no chain", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) { find(d, "SEC-2", "readable") }, "D", func(t *testing.T, r Report) {
			if _, ok := hasFinding(r, "CHN-1"); ok {
				t.Fatal("no CHN-1 without a way out")
			}
		}},
		{"a token and the Kubernetes API: CHN-3", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			find(d, "SEC-3", "k8s_token")
			find(d, "AMP-7", "k8s_api")
		}, "D", func(t *testing.T, r Report) {
			if _, ok := hasFinding(r, "CHN-3"); !ok {
				t.Fatal("want CHN-3")
			}
		}},
		{"an unparseable proxy keeps EGR-3 unknown, and the run incomplete", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			m.Proxy, m.ProxyMalformed = "", true
			*at(d, "EGR-3") = obs.Observation{ID: "EGR-3", Result: obs.Unknown, Reason: "HTTPS_PROXY isn't a URL the probe can use"}
		}, "C", func(t *testing.T, r Report) {
			if r.Complete || !slices.Contains(r.Unknown, "EGR-3") {
				t.Fatalf("want EGR-3 unknown and the run incomplete, got unknown %v", r.Unknown)
			}
		}},
		{"an approved loopback proxy", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			m.Proxy, m.AllowLocalProxy = "localhost:3128", true
			at(d, "EGR-3").Attempts[0].Via = "127.0.0.1:3128"
		}, "A", nil},
		{"findings are worst first", func(m *obs.Manifest, d *obs.Doc, c **obs.CanaryEvidence) {
			find(d, "PER-1", "writable")
			find(d, "AMP-1", "nopasswd_all")
		}, "F", func(t *testing.T, r Report) {
			if r.Findings[0].ID != "AMP-1" {
				t.Fatalf("want AMP-1 first, got %s", r.Findings[0].ID)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, d, c := base()
			if tc.mut != nil {
				tc.mut(&m, d, &c)
			}
			r := Grade(m, d, c)
			if !r.Valid {
				t.Fatalf("unexpectedly invalid: %s", r.Invalid)
			}
			if r.Letter != tc.letter {
				t.Fatalf("want %s, got %s (findings %+v, unknown %v, outcomes %+v)", tc.letter, r.Letter, r.Findings, r.Unknown, unknownReasons(r))
			}
			if tc.check != nil {
				tc.check(t, r)
			}
		})
	}
}

func unknownReasons(r Report) []string {
	var s []string
	for _, o := range r.Outcomes {
		if o.Result == obs.Unknown {
			s = append(s, o.ID+": "+o.Reason)
		}
	}
	return s
}

func TestParseDoc(t *testing.T) {
	m, d, c := base()
	good, _ := json.Marshal(d)
	if r := GradeBytes(m, good, c); !r.Valid || r.Letter != "A" {
		t.Fatalf("a well-formed document should grade A, got %+v", r.Invalid)
	}
	for name, b := range map[string][]byte{
		"an unknown field":  []byte(strings.Replace(string(good), `"schema"`, `"grade":"A","schema"`, 1)),
		"two JSON values":   append(append([]byte{}, good...), good...),
		"over the size cap": append(append([]byte{}, good[:len(good)-1]...), []byte(`,"pad":"`+strings.Repeat("x", obs.MaxDoc)+`"}`)...),
		"not JSON":          []byte("<html>"),
	} {
		if r := GradeBytes(m, b, c); r.Valid || r.Letter != "" {
			t.Errorf("%s: want invalid, got valid letter %q", name, r.Letter)
		}
	}
}

// HCN-5 in the grader: a run without a canary grades its canary checks unknown, with the host's reason, so the run is
// incomplete and never above C; a box that answers a check it was never asked about invalidates the run.
func TestNoCanaryIsUnknownNeverAnswered(t *testing.T) {
	m, d, _ := base()
	m.NoCanary, m.CheckNonces, m.Endpoints = true, map[string]string{}, map[string]string{}
	d.Observations = slices.DeleteFunc(d.Observations, func(o obs.Observation) bool {
		ck, _ := catalog.Get(o.ID)
		return catalog.NeedsCanary(ck)
	})
	r := Grade(m, d, &obs.CanaryEvidence{})
	if !r.Valid {
		t.Fatalf("invalid: %s", r.Invalid)
	}
	for _, id := range []string{"EGR-1", "EGR-2", "EGR-3", "EGR-4", "EGR-5.22", "EGR-5.80", "EGR-5.8080", "EGR-5.53u"} {
		if o := outcome(r, id); o.Result != obs.Unknown || o.Reason != NoCanaryReason {
			t.Errorf("%s: %s %q", id, o.Result, o.Reason)
		}
	}
	if r.Complete || r.Letter < "C" {
		t.Errorf("a run without a canary graded %s, complete %v", r.Letter, r.Complete)
	}
	add(d, obs.Observation{ID: "EGR-2", Result: obs.Unknown})
	if r := Grade(m, d, &obs.CanaryEvidence{}); r.Valid {
		t.Error("an answer to a check the probe was never asked for was accepted")
	}
}

// AMP-2 counts every capability the agent holds, effective, permitted or ambient, at the same severity, and names each
// one effective or only permitted; an inheritable one, with NoNewPrivs 0, leaves a pass unknown (AMP-2's row).
func TestAMP2CapabilitySets(t *testing.T) {
	zero, one := 0, 1
	const none, drs, raw = "0000000000000000", "0000000000000004", "0000000000002000" // CAP_DAC_READ_SEARCH, CAP_NET_RAW
	for _, tc := range []struct {
		name                      string
		uid                       int
		eff, prm, inh, amb        string
		nnp                       *int
		result, variant, mentions string
	}{
		{"nothing held", 1000, none, none, none, none, &zero, obs.Pass, "", "no capability held"},
		{"a dangerous capability only permitted", 1000, none, drs, none, none, &one, obs.Finding, "dangerous_caps",
			"CAP_DAC_READ_SEARCH (permitted, not effective"},
		{"a dangerous capability effective", 1000, drs, drs, none, none, &one, obs.Finding, "dangerous_caps",
			"CAP_DAC_READ_SEARCH (effective)"},
		{"another capability only permitted", 1000, none, raw, none, none, &one, obs.Finding, "other_caps",
			"CAP_NET_RAW (permitted, not effective"},
		{"an ambient capability", 1000, none, none, none, raw, &one, obs.Finding, "other_caps", "CAP_NET_RAW"},
		{"inheritable, NoNewPrivs 0", 1000, none, none, drs, none, &zero, obs.Unknown, "", "inheritable set holds CAP_DAC_READ_SEARCH"},
		{"inheritable, NoNewPrivs 1", 1000, none, none, drs, none, &one, obs.Pass, "", "no capability held"},
		{"no CapPrm reported", 1000, none, "", none, none, &one, obs.Unknown, "", "doesn't report CapPrm"},
		{"no CapPrm, but CapEff finds", 1000, drs, "", none, none, &one, obs.Finding, "dangerous_caps", "CAP_DAC_READ_SEARCH"},
		{"no CapInh, NoNewPrivs 0", 1000, none, none, "", none, &zero, obs.Unknown, "", "doesn't report CapInh"},
		{"no CapInh, NoNewPrivs 1", 1000, none, none, "", none, &one, obs.Pass, "", "no capability held"},
		{"root", 0, none, none, none, none, &one, obs.Finding, "root", "uid 0"},
	} {
		id := &obs.Identity{UID: tc.uid, CapEff: tc.eff, CapPrm: tc.prm, CapInh: tc.inh, CapAmb: tc.amb, NoNewPrivs: tc.nnp}
		res, v, why, ev := derive("AMP-2", id)
		if res != tc.result || v != tc.variant || !strings.Contains(why+ev, tc.mentions) {
			t.Errorf("%s: want %s %s mentioning %q, got %s %s %q %q", tc.name, tc.result, tc.variant, tc.mentions, res, v, why, ev)
		}
	}
}

// AMP-3 asks whether an execve could give the agent a privilege it doesn't hold now. With NoNewPrivs 0 a file's
// capabilities can grant whatever the bounding set (permitted) or the inheritable set allows, and the probe doesn't
// look for such files, so a capability the agent lacks there leaves a pass unknown (AMP-3's row): the identity the
// review of #34 reproduced, uid 65534 holding nothing under Docker's bounding set, can't pass.
func TestAMP3ExecGains(t *testing.T) {
	zero, one := 0, 1
	const none, docker, dac = "0000000000000000", "00000000a80425fb", "0000000000000002" // CAP_DAC_OVERRIDE
	clean, setuid := &obs.SetuidScan{Complete: true}, &obs.SetuidScan{Complete: true, Files: []string{"/usr/bin/passwd"}}
	for _, tc := range []struct {
		name                      string
		uid                       int
		prm, inh, bnd             string
		nnp                       *int
		scan                      *obs.SetuidScan
		result, variant, mentions string
	}{
		{"nothing held, Docker's bounding set", 65534, none, none, docker, &zero, clean, obs.Unknown, "", "CAP_DAC_OVERRIDE"},
		{"the same with NoNewPrivs 1", 65534, none, none, docker, &one, clean, obs.Pass, "", "NoNewPrivs is 1"},
		{"only an inheritable capability", 1000, none, dac, none, &zero, clean, obs.Unknown, "", "CAP_DAC_OVERRIDE"},
		{"empty bounding and inheritable sets", 1000, none, none, none, &zero, clean, obs.Pass, "", "no capability the agent lacks"},
		{"the bounding set holds only what's held", 1000, dac, none, dac, &zero, clean, obs.Pass, "", "no capability the agent lacks"},
		{"root holding its bounding set", 0, docker, none, docker, &zero, clean, obs.Pass, "", "no capability the agent lacks"},
		{"no CapBnd reported", 1000, none, none, "", &zero, clean, obs.Unknown, "", "doesn't report CapBnd"},
		{"no CapInh reported", 1000, none, "", none, &zero, clean, obs.Unknown, "", "doesn't report CapBnd or CapInh"},
		{"setuid-root files", 1000, none, none, docker, &zero, setuid, obs.Finding, "new_privs", ""},
		{"an incomplete scan", 1000, none, none, none, &zero, &obs.SetuidScan{}, obs.Unknown, "", "setuid scan didn't complete"},
		{"setuid-root files with NoNewPrivs 1", 1000, none, none, docker, &one, setuid, obs.Pass, "", "NoNewPrivs is 1"},
	} {
		id := &obs.Identity{UID: tc.uid, CapEff: none, CapPrm: tc.prm, CapInh: tc.inh, CapBnd: tc.bnd, CapAmb: none,
			NoNewPrivs: tc.nnp, SetuidScan: tc.scan}
		res, v, why, ev := derive("AMP-3", id)
		if res != tc.result || v != tc.variant || !strings.Contains(why+ev, tc.mentions) {
			t.Errorf("%s: want %s %s mentioning %q, got %s %s %q %q", tc.name, tc.result, tc.variant, tc.mentions, res, v, why, ev)
		}
		if a2, _, _, _ := derive("AMP-2", id); res == obs.Pass && a2 == obs.Pass && *tc.nnp == 0 && tc.bnd != none {
			t.Errorf("%s: AMP-2 and AMP-3 both pass with NoNewPrivs 0 and a bounding set the agent doesn't hold", tc.name)
		}
	}
}
