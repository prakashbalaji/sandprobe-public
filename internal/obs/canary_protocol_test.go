package obs

import (
	"sandprobe/internal/canary"
	"testing"
)

func TestCanaryTCP80ProtocolDeclaration(t *testing.T) {
	for _, tc := range []struct {
		protocol             string
		none, selected, want bool
	}{
		{"", false, false, true}, {canary.HTTPMarkerV1, false, true, true}, {canary.HTTPMarkerV1, true, true, false}, {canary.HTTPMarkerV1, false, false, false}, {"untrusted-secret", false, true, false},
	} {
		m := Manifest{CanaryTCP80Protocol: tc.protocol, NoCanary: tc.none}
		if tc.selected {
			m.Selected = []string{"EGR-5.80"}
		}
		if got := ValidateCanaryTCP80Protocol(m) == nil; got != tc.want {
			t.Fatal("protocol declaration acceptance", got, tc.want)
		}
	}
}
