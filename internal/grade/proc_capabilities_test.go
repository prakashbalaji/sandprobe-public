package grade

import (
	"fmt"
	"sandprobe/internal/obs"
	"testing"
)

func TestProcessRefusalCapabilities(t *testing.T) {
	for _, id := range []string{"SEC-2", "SEC-5"} {
		for _, bit := range []uint{6, 7, 16, 19, 21} {
			for _, set := range []string{"effective", "permitted"} {
				t.Run(fmt.Sprintf("%s/%d/%s", id, bit, set), func(t *testing.T) {
					m, d, c := base()
					if set == "effective" {
						d.Identity.CapEff = fmt.Sprintf("%016x", uint64(1)<<bit)
					} else {
						d.Identity.CapPrm = fmt.Sprintf("%016x", uint64(1)<<bit)
					}
					r := Grade(m, d, c)
					if !r.Valid {
						t.Fatal("identity made unrelated assessment invalid")
					}
					for _, o := range r.Outcomes {
						if o.ID == id && o.Result != obs.Unknown {
							t.Fatalf("unsupported negative accepted: %s", o.Result)
						}
					}
				})
			}
		}
		t.Run(id+"/finding-preserved", func(t *testing.T) {
			m, d, c := base()
			d.Identity.CapPrm = "00000000000000c0"
			find(d, id, "readable")
			r := Grade(m, d, c)
			if !r.Valid {
				t.Fatal(r.Invalid)
			}
			for _, o := range r.Outcomes {
				if o.ID == id && o.Result != obs.Finding {
					t.Fatal("finding hidden")
				}
			}
		})
		t.Run(id+"/unknown-stays-unknown", func(t *testing.T) {
			m, d, c := base()
			o := at(d, id)
			o.Result = obs.Unknown
			o.Proof = nil
			r := Grade(m, d, c)
			for _, got := range r.Outcomes {
				if got.ID == id && got.Result != obs.Unknown {
					t.Fatal("unknown promoted without proof")
				}
			}
		})
		for _, missing := range []string{"negative-twin", "eligible-refusal", "coverage"} {
			t.Run(id+"/missing-"+missing, func(t *testing.T) {
				m, d, c := base()
				p := at(d, id).Proof
				switch missing {
				case "negative-twin":
					p.TwinRefused = false
				case "eligible-refusal":
					p.Targets[0].Errno = "EIO"
				case "coverage":
					p.Targets = nil
				}
				r := Grade(m, d, c)
				for _, got := range r.Outcomes {
					if got.ID == id && got.Result == obs.Pass {
						t.Fatal("zero capabilities substituted for complete negative proof")
					}
				}
			})
		}
		t.Run(id+"/missing-permitted", func(t *testing.T) {
			m, d, c := base()
			d.Identity.CapPrm = ""
			r := Grade(m, d, c)
			for _, o := range r.Outcomes {
				if o.ID == id && o.Result != obs.Unknown {
					t.Fatal("missing permitted evidence accepted")
				}
			}
		})
		t.Run(id+"/bounding-only", func(t *testing.T) {
			m, d, c := base()
			d.Identity.CapBnd = "00000000000000c0"
			r := Grade(m, d, c)
			for _, o := range r.Outcomes {
				if o.ID == id && o.Result != obs.Pass {
					t.Fatal("bounding is not a held capability")
				}
			}
		})
		t.Run(id+"/dropping-is-not-proof", func(t *testing.T) {
			m, d, c := base()
			at(d, id).Proof.Twin = false
			r := Grade(m, d, c)
			for _, o := range r.Outcomes {
				if o.ID == id && o.Result != obs.Unknown {
					t.Fatal("zero capabilities substituted for proof")
				}
			}
		})
		t.Run(id+"/genuine-negative", func(t *testing.T) {
			m, d, c := base()
			r := Grade(m, d, c)
			for _, o := range r.Outcomes {
				if o.ID == id && o.Result != obs.Pass {
					t.Fatal("genuine negative lost")
				}
			}
		})
		t.Run(id+"/absent-is-not-refusal", func(t *testing.T) {
			m, d, c := base()
			d.Identity.CapPrm = "00000000000000c0"
			for i := range at(d, id).Proof.Targets {
				target := &at(d, id).Proof.Targets[i]
				target.State = "absent"
				target.Errno = "ENOENT"
				target.ParentSearchable = true
			}
			r := Grade(m, d, c)
			for _, o := range r.Outcomes {
				if o.ID == id && o.Result != obs.Pass {
					t.Fatal("verified disappearance changed")
				}
			}
		})
	}
}
