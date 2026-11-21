package host

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sync"
	"testing"

	"sandprobe/internal/canary"
	"sandprobe/internal/catalog"
	"sandprobe/internal/obs"
)

// fakeCanary answers the control channel from a script and remembers every request.
type fakeCanary struct {
	mu     sync.Mutex
	asks   []canary.Request
	answer func(q canary.Request) canary.Answer
}

func (f *fakeCanary) IP() string                                   { return "203.0.113.5" }
func (f *fakeCanary) Domain() string                               { return "sandprobe.test" }
func (f *fakeCanary) Health(context.Context, int, canary.Key) bool { return true }
func (f *fakeCanary) Ask(_ context.Context, q canary.Request) (canary.Answer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asks = append(f.asks, q)
	return f.answer(q), nil
}

// surveyBox answers the survey; its main run fails, which still leaves the canary evidence gathered.
type surveyBox struct{}

func (surveyBox) ID() string { return "box-1" }
func (surveyBox) Probe(_ context.Context, args []string, _ []byte) ([]byte, error) {
	if slices.Equal(args, []string{"-survey"}) {
		return json.Marshal(obs.Survey{Schema: obs.SurveySchema})
	}
	return nil, errors.New("no probe here")
}

// real is a real canary's status, for a pin and key that belong together.
var real = func() canary.Answer {
	c, _ := canary.New("sandprobe.test")
	return c.Handle(canary.Request{Op: "status"})
}()

// whole is a canary that answers everything under the real pin: the first armed nonce counted once, the rest not at
// all.
func whole(q canary.Request, armed []canary.Want) canary.Answer {
	a := canary.Answer{Pin: real.Pin, Key: real.Key, OK: true, Run: q.Run}
	if q.Op == "query" {
		for i, w := range armed {
			n := canary.Count{Want: w}
			if i == 0 {
				n.Count, n.FirstFrom = 1, "198.51.100.7:5353"
			}
			a.Counts = append(a.Counts, n)
		}
	}
	return a
}

// SBX-11 on the host: arm exactly the plan's check nonces, query that run, disarm it, and trust an answer only under
// the run's pin, for the run, complete.
func TestExecuteArmsTheRun(t *testing.T) {
	for _, tc := range []struct {
		name              string
		edit              func(q canary.Request, a *canary.Answer)
		ops               []string
		live, read, overl bool
		receipts          int
	}{
		{"armed and whole", nil, []string{"status", "arm", "query", "disarm"}, true, true, false, 1},
		{"overloaded: still read, a receipt still in hand", func(q canary.Request, a *canary.Answer) {
			a.Overloaded = q.Op == "query"
		}, []string{"status", "arm", "query", "disarm"}, true, true, true, 1},
		{"no status: never armed", func(q canary.Request, a *canary.Answer) {
			a.OK = a.OK && q.Op != "status"
		}, []string{"status", "query"}, false, false, false, 0},
		{"a refused arm: not live", func(q canary.Request, a *canary.Answer) {
			a.OK = a.OK && q.Op != "arm"
		}, []string{"status", "arm", "query"}, false, false, false, 1},
		{"an arm under another pin: not live", func(q canary.Request, a *canary.Answer) {
			if q.Op == "arm" {
				a.Pin = "p2"
			}
		}, []string{"status", "arm", "query"}, false, false, false, 1},
		{"a query under another pin: a restarted canary, nothing read", func(q canary.Request, a *canary.Answer) {
			if q.Op == "query" {
				a.Pin, a.Overloaded = "p2", true
			}
		}, []string{"status", "arm", "query", "disarm"}, true, false, false, 0},
		{"a query answering another run: nothing read", func(q canary.Request, a *canary.Answer) {
			if q.Op == "query" {
				a.Run = "r-other"
			}
		}, []string{"status", "arm", "query", "disarm"}, true, false, false, 0},
		{"a query that isn't ok: nothing read", func(q canary.Request, a *canary.Answer) {
			a.OK = a.OK && q.Op != "query"
		}, []string{"status", "arm", "query", "disarm"}, true, false, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var armed []canary.Want
			c := &fakeCanary{}
			c.answer = func(q canary.Request) canary.Answer {
				if q.Op == "arm" {
					armed = q.Wants
				}
				a := whole(q, armed)
				if tc.edit != nil {
					tc.edit(q, &a)
				}
				return a
			}
			r, err := Execute(context.Background(), surveyBox{}, c, Options{Mode: "exec"})
			if err != nil {
				t.Fatal(err)
			}
			var ops []string
			for _, q := range c.asks {
				ops = append(ops, q.Op)
				if q.Op != "status" && q.Run != r.Manifest.RunID {
					t.Errorf("%s for run %q, not the plan's %q", q.Op, q.Run, r.Manifest.RunID)
				}
			}
			ev := r.Evidence
			if !slices.Equal(ops, tc.ops) || ev.Live != tc.live || ev.ReceiptsRead != tc.read || ev.Overloaded != tc.overl ||
				len(ev.Receipts) != tc.receipts {
				t.Fatalf("ops %v live %v read %v overloaded %v receipts %+v", ops, ev.Live, ev.ReceiptsRead, ev.Overloaded, ev.Receipts)
			}
			if tc.receipts > 0 && ev.Receipts[0].From != "198.51.100.7:5353" {
				t.Errorf("want the receipt's source carried, got %+v", ev.Receipts[0])
			}
			if armed == nil {
				return
			}
			m := r.Manifest
			want := 0
			for _, id := range m.Selected {
				if ck, _ := catalog.Get(id); ck.Canary != nil {
					want++
					if !slices.Contains(armed, canary.Want{Nonce: m.CheckNonces[id], Proto: ck.Canary.Proto, Port: ck.Canary.Port}) {
						t.Errorf("%s isn't armed with its protocol and port: %+v", id, armed)
					}
				}
			}
			if len(armed) != want || slices.ContainsFunc(armed, func(w canary.Want) bool { return w.Nonce == m.Nonce }) {
				t.Errorf("want exactly the %d check nonces armed, never the document nonce: %+v", want, armed)
			}
		})
	}
}
