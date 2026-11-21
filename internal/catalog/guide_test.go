package catalog

import "testing"

// Every check and chain has advice, and nothing else does.
func TestGuideIsWhole(t *testing.T) {
	want := map[string]bool{"CHN-1": true, "CHN-2": true, "CHN-3": true}
	for _, c := range Checks {
		want[c.ID] = true
	}
	for id := range want {
		a, ok := Guide[id]
		if !ok || a.Gets == "" || a.Fix == "" || a.Mark == "" {
			t.Errorf("%s: no whole advice: %+v", id, a)
		}
	}
	for id := range Guide {
		if !want[id] {
			t.Errorf("%s: advice for a check that doesn't exist", id)
		}
	}
}
