package host

import (
	"testing"

	"sandprobe/internal/obs"
)

// POC-5: the gate on each setup's own counts, including the twin's nonce elsewhere and a nonce counted elsewhere.
func TestModalGate(t *testing.T) {
	tcp := func(n string, port int) obs.Receipt { return obs.Receipt{Nonce: n, Proto: "tcp", Port: port} }
	dns := obs.Receipt{Nonce: "cdns", Proto: "udp", Port: 53}
	viaResolver := obs.Receipt{Nonce: "cegr1", Proto: "dns", Port: 53} // the canary's label for EGR-1's lookup (live, 10 Nov)
	for _, tc := range []struct {
		name, setup string
		rs          []obs.Receipt
		elsewhere   map[string]uint64
		trip        bool
	}{
		{"default lets anything through", "default", []obs.Receipt{tcp("c1", 443), tcp("c2", 22), dns}, nil, false},
		{"block: DNS trips", "block", []obs.Receipt{dns}, nil, true},
		{"block-vm: TCP trips", "block-vm", []obs.Receipt{tcp("c1", 80)}, nil, true},
		{"block: nothing passes", "block", nil, nil, false},
		{"domain-empty: DNS is documented", "domain-empty", []obs.Receipt{dns}, nil, false},
		{"domain-empty: a lookup through the resolver is documented", "domain-empty", []obs.Receipt{viaResolver}, nil, false},
		{"domain-one: a lookup through the resolver is documented", "domain-one", []obs.Receipt{viaResolver, tcp("ctwin", 443)}, nil, false},
		{"sidecar: a lookup through the resolver is documented", "sidecar", []obs.Receipt{viaResolver}, nil, false},
		{"block: a lookup through the resolver trips", "block", []obs.Receipt{viaResolver}, nil, true},
		{"block-vm: a lookup through the resolver trips", "block-vm", []obs.Receipt{viaResolver}, nil, true},
		{"domain-empty: dns on another port trips", "domain-empty", []obs.Receipt{{Nonce: "cx", Proto: "dns", Port: 5353}}, nil, true},
		{"domain-empty: 443 trips", "domain-empty", []obs.Receipt{tcp("c1", 443)}, nil, true},
		{"domain-empty: 8080 trips", "domain-empty", []obs.Receipt{tcp("c1", 8080)}, nil, true},
		{"domain-one: the twin on 443 passes", "domain-one", []obs.Receipt{tcp("ctwin", 443), dns}, nil, false},
		{"domain-one: EGR-2's own nonce trips", "domain-one", []obs.Receipt{tcp("c1", 443)}, nil, true},
		{"domain-one: the twin on another port trips", "domain-one", []obs.Receipt{tcp("ctwin", 80)}, nil, true},
		{"domain-one: the twin counted elsewhere trips", "domain-one", []obs.Receipt{tcp("ctwin", 443)}, map[string]uint64{"ctwin": 1}, true},
		{"domain-empty: a nonce counted elsewhere trips", "domain-empty", nil, map[string]uint64{"c1": 2}, true},
		{"sidecar: 443 is the relay's to judge", "sidecar", []obs.Receipt{tcp("c1", 443), dns}, nil, false},
		{"sidecar: 22 trips", "sidecar", []obs.Receipt{tcp("c2", 22)}, nil, true},
		{"sidecar: elsewhere trips", "sidecar", nil, map[string]uint64{"c1": 1}, true},
		{"an unknown setup trips", "open", []obs.Receipt{dns}, nil, true},
	} {
		if got := ModalGate(tc.setup, "ctwin", tc.rs, tc.elsewhere); (got != "") != tc.trip {
			t.Errorf("%s: trip=%q", tc.name, got)
		}
	}
}

// POC-5, POC-6: a 443 count with no relay in a complete log trips; a truncated or missing log is unknown, never a
// bypass.
func TestRelayGate(t *testing.T) {
	ready := `{"t":"1","ev":"ready","listen":":443"}`
	full := ready + "\n" + `{"t":"2","ev":"accept","conn":1,"nonce":"c1"}` + "\n" + `{"t":"3","ev":"end","conn":1,"nonce":"c1","up":500,"down":900,"outcome":"relayed"}` + "\n"
	r443 := []obs.Receipt{{Nonce: "c1", Proto: "tcp", Port: 443}}
	if trip, unk := RelayGate(r443, ParseRelayLog([]byte(full))); trip != "" || unk != "" {
		t.Fatalf("a relayed nonce: %q %q", trip, unk)
	}
	other := []obs.Receipt{{Nonce: "c9", Proto: "tcp", Port: 443}}
	if trip, _ := RelayGate(other, ParseRelayLog([]byte(full))); trip == "" {
		t.Fatal("a 443 receipt the complete log never relayed passed")
	}
	for name, log := range map[string]string{
		"empty":            "",
		"truncated":        full[:len(full)-20],
		"no end":           ready + "\n" + `{"t":"2","ev":"accept","conn":1,"nonce":"c1"}` + "\n",
		"no ready line":    `{"t":"2","ev":"accept","conn":1,"nonce":"c1"}` + "\n",
		"end, not relayed": ready + "\n" + `{"t":"2","ev":"accept","conn":1,"nonce":"c1"}` + "\n" + `{"t":"3","ev":"end","conn":1,"nonce":"c1","outcome":"upstream_failed"}` + "\n",
	} {
		trip, unk := RelayGate(r443, ParseRelayLog([]byte(log)))
		if name == "end, not relayed" {
			if trip == "" {
				t.Errorf("%s: a receipt for a connection the relay didn't carry passed", name)
			}
			continue
		}
		if trip != "" || unk == "" {
			t.Errorf("%s: want unknown, never a bypass: %q %q", name, trip, unk)
		}
	}
}
