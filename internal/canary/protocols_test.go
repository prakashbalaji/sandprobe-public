package canary

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestProtocolAdvertisementDoesNotChangeLegacyStatus(t *testing.T) {
	c, _, _, _ := start(t)
	for _, public := range []bool{false, true} {
		ask := func(q Request) Answer {
			if public {
				q.Challenge = strings.Repeat("a", 64)
				return c.HandlePublic(q, "192.0.2.1")
			}
			return c.Handle(q)
		}
		old := ask(Request{Op: "status"})
		raw, _ := json.Marshal(old)
		if !old.OK || len(old.Protocols) != 0 || strings.Contains(string(raw), `"protocols"`) {
			t.Fatal("legacy status gained new fields")
		}
		a := ask(Request{Op: "protocols"})
		if !a.OK || a.Pin != old.Pin || len(a.Protocols) != 1 || a.Protocols[0] != HTTPMarkerV1 {
			t.Fatal("capability not bound to boot pin")
		}
	}
}
