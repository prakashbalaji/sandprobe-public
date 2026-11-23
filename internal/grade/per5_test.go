package grade

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"sandprobe/internal/obs"
)

// per5Case is a run with PER-5 selected: two roots, the first marker surviving a proven reset, the second gone.
type per5Case struct {
	m      obs.Manifest
	d      *obs.Doc
	c      *obs.CanaryEvidence
	mark   *obs.MarkDoc
	check  *obs.RecheckDoc
	reset  *obs.ResetEvidence
	noMark bool
	noRe   bool
}

func per5Base(model string) *per5Case {
	m, d, c := base()
	delete(m.Skipped, "PER-5")
	m.Selected, m.Reset = append(m.Selected, "PER-5"), model
	pc := &per5Case{m: m, d: d, c: c}
	after := "box-1"
	if model == "recreate" {
		after = "box-2"
	}
	pc.mark = &obs.MarkDoc{Schema: obs.MarkSchema, RunID: "r1", Nonce: "n1", BoxID: "box-1", BootID: "boot-a"}
	pc.check = &obs.RecheckDoc{Schema: obs.RecheckSchema, RunID: "r1", Nonce: "n1", BoxID: after, BootID: "boot-b"}
	pc.reset = &obs.ResetEvidence{Model: model, OperationID: "op-1", Done: true, BoxBefore: "box-1", BoxAfter: after,
		Volumes: map[string][2]obs.Volume{}, RootIdentity: map[string][2]string{}}
	if model == "restore" {
		pc.reset.Checkpoint = "cp-1"
	}
	for i, root := range []string{"/data", "/cache"} {
		pm := obs.PlannedMark{Root: root, Path: root + "/" + obs.MarkerPrefix + "r1", Dev: 1, Ino: uint64(10 + i)}
		if model == "recreate" {
			v := obs.Volume{ID: fmt.Sprintf("vol-%d", i), MountPath: root}
			pm.Volume = &v
			pc.reset.Volumes[root] = [2]obs.Volume{v, v}
		} else {
			pc.reset.RootIdentity[root] = [2]string{fmt.Sprintf("disk-%d", i), fmt.Sprintf("disk-%d", i)}
		}
		pc.m.Marks = append(pc.m.Marks, pm)
		pc.mark.Marks = append(pc.mark.Marks, obs.Placed{Root: root, Path: pm.Path, Placed: true, Ino: uint64(100 + i), Size: 2})
		state := []string{"survived", "absent"}[i]
		pc.check.Marks = append(pc.check.Marks, obs.Rechecked{Root: root, State: state})
	}
	for _, n := range StartupTargets() { // every target the host asks for, none replaceable
		path := n
		if strings.HasPrefix(n, "~/") {
			path = "/home/agent/" + n[2:]
		}
		pc.check.Startup = append(pc.check.Startup, obs.Startup{Name: n, Path: path, State: "refused"})
	}
	return pc
}

// startup sets one startup observation by name.
func (pc *per5Case) startup(name, path, state string) {
	for i := range pc.check.Startup {
		if pc.check.Startup[i].Name == name {
			pc.check.Startup[i].Path, pc.check.Startup[i].State = path, state
		}
	}
}

// refuse makes mark i a consistent refusal.
func (pc *per5Case) refuse(i int) {
	pc.mark.Marks[i] = obs.Placed{Root: pc.mark.Marks[i].Root, Path: pc.mark.Marks[i].Path, Why: "the root can't be opened: EACCES"}
}

func (pc *per5Case) grade() Report {
	r := *pc.reset
	if !pc.noMark {
		r.Mark, _ = json.Marshal(pc.mark)
	}
	if !pc.noRe {
		r.Recheck, _ = json.Marshal(pc.check)
	}
	pc.c.Reset = &r
	return Grade(pc.m, pc.d, pc.c)
}

func TestPER5(t *testing.T) {
	for _, tc := range []struct {
		name, model     string
		mut             func(pc *per5Case)
		result, variant string
	}{
		{"recreate: a marker survived on the same volume", "recreate", nil, obs.Finding, "survived"},
		{"restore: a marker survived the named checkpoint's restore", "restore", nil, obs.Finding, "survived"},
		{"restore proven by the restore ID alone", "restore", func(pc *per5Case) {
			pc.check.BootID, pc.reset.RestoreBefore, pc.reset.RestoreAfter = "boot-a", "rs-1", "rs-2"
		}, obs.Finding, "survived"},
		{"a startup path that lies in the surviving root, replaceable", "recreate", func(pc *per5Case) {
			pc.startup("~/.bashrc", "/data/.bashrc", "found")
		}, obs.Finding, "survived_startup"},
		{"a replaceable startup path elsewhere", "recreate", func(pc *per5Case) {
			pc.startup("~/.bashrc", "/home/agent/.bashrc", "found")
		}, obs.Finding, "survived"},
		{"a startup path in the root, but not replaceable", "recreate", func(pc *per5Case) {
			pc.startup("~/.bashrc", "/data/.bashrc", "refused")
		}, obs.Finding, "survived"},
		{"every marker gone after a proven reset", "recreate", func(pc *per5Case) { pc.check.Marks[0].State = "absent" }, obs.NotFound, ""},
		{"one root refused its marker, the other survived", "recreate", func(pc *per5Case) { pc.refuse(1) }, obs.Finding, "survived"},
		{"one root refused its marker, the other gone", "recreate", func(pc *per5Case) {
			pc.refuse(1)
			pc.check.Marks[0].State = "absent"
		}, obs.Unknown, ""},
		{"a substitute at one root, the other gone", "recreate", func(pc *per5Case) {
			pc.check.Marks[0].State, pc.check.Marks[0].Why = "unknown", "not the placed marker"
		}, obs.Unknown, ""},
		{"a recreate that kept the box ID", "recreate", func(pc *per5Case) { pc.reset.BoxAfter, pc.check.BoxID = "box-1", "box-1" }, obs.Unknown, ""},
		{"a reset the provider didn't report done", "recreate", func(pc *per5Case) { pc.reset.Done = false }, obs.Unknown, ""},
		{"no reset operation", "recreate", func(pc *per5Case) { pc.reset.OperationID = "" }, obs.Unknown, ""},
		{"a reset of another box", "recreate", func(pc *per5Case) { pc.reset.BoxBefore = "box-9" }, obs.Unknown, ""},
		{"a reset of another model", "recreate", func(pc *per5Case) { pc.reset.Model = "restore" }, obs.Unknown, ""},
		{"restore: an empty provider identity for the surviving root", "restore", func(pc *per5Case) { pc.reset.RootIdentity["/data"] = [2]string{} }, obs.Finding, "survived"},
		{"the surviving root's volume was replaced", "recreate", func(pc *per5Case) {
			v := pc.reset.Volumes["/data"]
			v[1].ID = "vol-other"
			pc.reset.Volumes["/data"] = v
		}, obs.Unknown, ""},
		{"the surviving root's volume at another subpath", "recreate", func(pc *per5Case) {
			v := pc.reset.Volumes["/data"]
			v[1].Subpath = "other"
			pc.reset.Volumes["/data"] = v
		}, obs.Unknown, ""},
		{"restore: a reboot, with no checkpoint named", "restore", func(pc *per5Case) { pc.reset.Checkpoint = "" }, obs.Unknown, ""},
		{"restore: neither boot nor restore ID changed", "restore", func(pc *per5Case) { pc.check.BootID = "boot-a" }, obs.Unknown, ""},
		{"restore: a new box ID", "restore", func(pc *per5Case) { pc.reset.BoxAfter, pc.check.BoxID = "box-2", "box-2" }, obs.Unknown, ""},
		{"restore: no provider identity for the surviving root", "restore", func(pc *per5Case) { delete(pc.reset.RootIdentity, "/data") }, obs.Finding, "survived"},
		{"restore: no provider identity anywhere, a marker survived (Sprites)", "restore", func(pc *per5Case) { pc.reset.RootIdentity = nil }, obs.Finding, "survived"},
		{"restore: no provider identity anywhere, every marker gone: never not_found", "restore", func(pc *per5Case) {
			pc.reset.RootIdentity = nil
			pc.check.Marks[0].State = "absent"
		}, obs.Unknown, ""},
		{"restore: identity for the gone root only, every marker gone", "restore", func(pc *per5Case) {
			delete(pc.reset.RootIdentity, "/data")
			pc.check.Marks[0].State = "absent"
		}, obs.Unknown, ""},
		{"restore: every marker gone, every root identified", "restore", func(pc *per5Case) { pc.check.Marks[0].State = "absent" }, obs.NotFound, ""},
		{"restore: the surviving root's identity changed", "restore", func(pc *per5Case) {
			pc.reset.RootIdentity["/data"] = [2]string{"disk-0", "disk-9"}
		}, obs.Unknown, ""},
		{"no mark document", "recreate", func(pc *per5Case) { pc.noMark = true }, obs.Unknown, ""},
		{"two planned roots the survey didn't find, neither marked", "recreate", func(pc *per5Case) {
			for i := range pc.m.Marks {
				pc.m.Marks[i].Dev, pc.m.Marks[i].Ino = 0, 0
				pc.refuse(i)
				pc.check.Marks[i].State = "unknown"
			}
		}, obs.Unknown, ""},
		{"no recheck after the reset", "recreate", func(pc *per5Case) { pc.noRe = true }, obs.Unknown, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pc := per5Base(tc.model)
			if tc.mut != nil {
				tc.mut(pc)
			}
			r := pc.grade()
			if !r.Valid {
				t.Fatalf("unexpectedly invalid: %s", r.Invalid)
			}
			o := outcome(r, "PER-5")
			if o.Result != tc.result || o.Variant != tc.variant {
				t.Fatalf("want %s %s, got %+v", tc.result, tc.variant, o)
			}
			if o.Result == obs.Unknown && (r.Complete || !slices.Contains(r.Unknown, "PER-5")) {
				t.Fatal("an unknown PER-5 must leave the run incomplete")
			}
		})
	}
}

// An unknown PER-5 names each gap's cause (TWN-3): the mark's own reason for a root that took no marker, and whether
// the provider gave a root no identity or a different one. A reason from the box is bounded before it is repeated.
func TestPER5GapReasons(t *testing.T) {
	for _, tc := range []struct {
		name, model string
		mut         func(pc *per5Case)
		want        []string
	}{
		{"a root that took no marker, with the mark's reason", "recreate", func(pc *per5Case) {
			pc.refuse(1)
			pc.check.Marks[0].State = "absent"
		}, []string{"/cache took no marker: the root can't be opened: EACCES"}},
		{"restore: no provider identity for any root, every marker gone", "restore", func(pc *per5Case) {
			pc.reset.RootIdentity = nil
			pc.check.Marks[0].State = "absent"
		}, []string{"/data has no identity from the provider", "/cache has no identity from the provider"}},
		{"restore: a different provider identity", "restore", func(pc *per5Case) {
			pc.reset.RootIdentity["/cache"] = [2]string{"disk-1", "disk-9"}
			pc.check.Marks[0].State = "absent"
		}, []string{"/cache isn't the same storage, by the provider's identity"}},
		{"a long reason from the box", "recreate", func(pc *per5Case) {
			pc.refuse(1)
			pc.mark.Marks[1].Why = strings.Repeat("x", 5000)
			pc.check.Marks[0].State = "absent"
		}, []string{"/cache took no marker: xxx", "x..."}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pc := per5Base(tc.model)
			tc.mut(pc)
			o := outcome(pc.grade(), "PER-5")
			if o.Result != obs.Unknown || len(o.Reason) > 1024 {
				t.Fatalf("want a bounded unknown, got %s with a %d-byte reason", o.Result, len(o.Reason))
			}
			for _, w := range tc.want {
				if !strings.Contains(o.Reason, w) {
					t.Errorf("want the reason to say %q, got %q", w, o.Reason)
				}
			}
		})
	}
}

func TestPER5Invalid(t *testing.T) {
	for name, mut := range map[string]func(pc *per5Case){
		"the recheck from another box": func(pc *per5Case) { pc.check.BoxID = "box-9" },
		"the mark from another box":    func(pc *per5Case) { pc.mark.BoxID = "box-9" },
		"the mark from another run":    func(pc *per5Case) { pc.mark.RunID = "r9" },
		"a mark the plan didn't name":  func(pc *per5Case) { pc.mark.Marks[1].Path = "/etc/cron.d/x" },
		"a recheck short of a root":    func(pc *per5Case) { pc.check.Marks = pc.check.Marks[:1] },
		"a recheck observing a non-PER path": func(pc *per5Case) {
			pc.check.Startup[0] = obs.Startup{Name: "/etc/shadow", Path: "/etc/shadow", State: "found"}
		},
		"a recheck missing a startup target":   func(pc *per5Case) { pc.check.Startup = pc.check.Startup[:len(pc.check.Startup)-1] },
		"an extra startup observation":         func(pc *per5Case) { pc.check.Startup = append(pc.check.Startup, pc.check.Startup[0]) },
		"a recheck repeating a startup target": func(pc *per5Case) { pc.check.Startup[1] = pc.check.Startup[0] },
		"a placed marker with no inode":        func(pc *per5Case) { pc.mark.Marks[0].Ino = 0 },
		"a placed marker of another length":    func(pc *per5Case) { pc.mark.Marks[0].Size = 64 },
		"a placed marker giving a reason":      func(pc *per5Case) { pc.mark.Marks[0].Why = "odd" },
		"a refusal claiming an inode":          func(pc *per5Case) { pc.refuse(1); pc.mark.Marks[1].Ino = 7 },
		"a refusal with no reason":             func(pc *per5Case) { pc.refuse(1); pc.mark.Marks[1].Why = "" },
		"the main run reporting PER-5": func(pc *per5Case) {
			pc.d.Observations = append(pc.d.Observations, obs.Observation{ID: "PER-5", Result: obs.NotFound})
		},
		"PER-5 selected with no marker planned": func(pc *per5Case) { pc.m.Marks, pc.noMark, pc.noRe = nil, true, true },
		"PER-5 selected with no reset model":    func(pc *per5Case) { pc.m.Reset = "" },
		"a marker path that isn't this run's":   func(pc *per5Case) { pc.m.Marks[0].Path = "/data/.bashrc" },
		"one root planned twice": func(pc *per5Case) {
			pc.m.Marks[1].Root, pc.m.Marks[1].Path, pc.m.Marks[1].Volume.MountPath = "/data", pc.m.Marks[0].Path, "/data"
			pc.mark.Marks[1].Root, pc.mark.Marks[1].Path, pc.check.Marks[1].Root = "/data", pc.m.Marks[0].Path, "/data"
		},
		"one directory planned under two names":              func(pc *per5Case) { pc.m.Marks[1].Ino = pc.m.Marks[0].Ino },
		"a recreate marking storage Sandprobe didn't create": func(pc *per5Case) { pc.m.Marks[0].Volume = nil },
		"a volume mounted elsewhere than its root":           func(pc *per5Case) { pc.m.Marks[0].Volume.MountPath = "/elsewhere" },
		"PER-5 skipped with markers planned": func(pc *per5Case) {
			pc.m.Selected = slices.DeleteFunc(pc.m.Selected, func(id string) bool { return id == "PER-5" })
			pc.m.Skipped["PER-5"] = "no storage"
		},
	} {
		t.Run(name, func(t *testing.T) {
			pc := per5Base("recreate")
			mut(pc)
			if r := pc.grade(); r.Valid || r.Letter != "" {
				t.Fatalf("want an invalid run with no letter, got valid=%v letter=%q", r.Valid, r.Letter)
			}
		})
	}
	pc := per5Base("restore")
	pc.m.Marks[0].Volume = &obs.Volume{ID: "vol-x", MountPath: "/data"}
	if r := pc.grade(); r.Valid {
		t.Error("a restore in place marking a volume: want invalid")
	}
}
