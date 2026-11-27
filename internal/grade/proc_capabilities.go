package grade

import (
	"sandprobe/internal/catalog"
	"sandprobe/internal/obs"
	"strconv"
)

// TWN-5: the host cannot accept a claimed process refusal that the same
// document's capability identity says the agent can bypass. This adds no proof.
func processRefusalCapabilityReason(ck *catalog.Check, o *obs.Observation, id *obs.Identity) string {
	if ck.Mechanism != "proc_open" || o.Proof == nil {
		return ""
	}
	refusal := false
	for _, target := range o.Proof.Targets {
		refusal = refusal || target.State == "refused"
	}
	if !refusal {
		return ""
	}
	if id == nil {
		return "process-refusal capability evidence unavailable (TWN-5)"
	}
	var held uint64
	for _, set := range []string{id.CapEff, id.CapPrm} {
		bits, err := strconv.ParseUint(set, 16, 64)
		if err != nil {
			return "process-refusal capability evidence unavailable (TWN-5)"
		}
		held |= bits
	}
	const bypass = uint64(1<<6 | 1<<7 | 1<<16 | 1<<19 | 1<<21)
	if held&bypass != 0 {
		return "reported effective or permitted capabilities can bypass a process refusal (TWN-5)"
	}
	return ""
}
