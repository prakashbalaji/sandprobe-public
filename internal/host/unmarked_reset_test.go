package host

import (
	"context"
	"encoding/json"
	"errors"
	"sandprobe/internal/obs"
	"testing"
)

type unmarkedResetBox struct {
	t          *testing.T
	somePlaced bool
	resets     int
}

func (b *unmarkedResetBox) ID() string                                             { return "box" }
func (b *unmarkedResetBox) Storage(context.Context) (Storage, error)               { return Storage{}, nil }
func (b *unmarkedResetBox) Teardown(context.Context, []obs.Volume) map[string]bool { return nil }
func (b *unmarkedResetBox) Reset(context.Context) (Box, *obs.ResetEvidence, error) {
	b.resets++
	return b, &obs.ResetEvidence{Model: "recreate", BoxBefore: b.ID()}, errors.New("fixture reset stop")
}
func (b *unmarkedResetBox) Probe(_ context.Context, args []string, raw []byte) ([]byte, error) {
	if len(args) != 1 || args[0] != "-mark" {
		b.t.Fatal("unneeded post-reset probe")
	}
	var in obs.MarkInput
	if json.Unmarshal(raw, &in) != nil {
		b.t.Fatal("invalid fixture input")
	}
	d := obs.MarkDoc{Schema: obs.MarkSchema, RunID: in.RunID, Nonce: in.Nonce, BoxID: in.BoxID, BootID: "boot-before"}
	for i, m := range in.Marks {
		p := obs.Placed{Root: m.Root, Path: m.Path, Why: "marker unavailable: EPERM"}
		if b.somePlaced && i == 0 {
			p.Placed = true
			p.Ino = 100
			p.Why = ""
		}
		d.Marks = append(d.Marks, p)
	}
	return json.Marshal(d)
}

func TestNoPlacedMarkersAvoidUnnecessaryReset(t *testing.T) {
	for _, partial := range []bool{false, true} {
		b := &unmarkedResetBox{t: t, somePlaced: partial}
		m := obs.Manifest{RunID: "r1", Nonce: "n1", BoxID: b.ID(), Reset: "recreate"}
		for _, root := range []string{"/data", "/cache"} {
			m.Marks = append(m.Marks, obs.PlannedMark{Root: root, Path: root + "/" + obs.EmptyMarkerPrefix + m.RunID})
		}
		r := &Run{Manifest: m, Box: b}
		ev := persist(context.Background(), b, r)
		want := 0
		if partial {
			want = 1
		}
		if b.resets != want || ev.Mark == nil || ev.Recheck != nil || len(r.Markers) != 2 || r.Box != b {
			t.Fatalf("incorrect reset/placement lifecycle: resets=%d evidence=%+v", b.resets, ev)
		}
	}
}
