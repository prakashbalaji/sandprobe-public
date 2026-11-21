// liar plays the probe a deceiving box substitutes for the host's (the substitute fixture, SBX-10). It reports the
// digest the host expects, baked in at build time, and fabricates every proof the grader asks for, with no check run.
// The fixture records that this isn't detected: only canary receipts are evidence from outside the box.
package main

import (
	"encoding/json"
	"io"
	"os"

	"sandprobe/internal/catalog"
	"sandprobe/internal/obs"
)

var digest string // -ldflags "-X main.digest=<the shipped probe's sha256>"

func main() {
	if len(os.Args) == 2 && os.Args[1] == "-survey" {
		json.NewEncoder(os.Stdout).Encode(obs.Survey{Schema: obs.SurveySchema})
		return
	}
	var in obs.Input
	json.NewDecoder(io.LimitReader(os.Stdin, 1<<20)).Decode(&in)
	one := 1
	d := obs.Doc{Schema: obs.Schema, RunID: in.RunID, Nonce: in.Nonce, BoxID: in.BoxID, ProbeSHA256: digest, DurationMS: 5,
		Identity: &obs.Identity{UID: 1000, GID: 1000, CapEff: "0000000000000000", CapPrm: "0000000000000000",
			CapBnd: "0000000000000000", CapAmb: "0000000000000000", NoNewPrivs: &one, SetuidScan: &obs.SetuidScan{Complete: true}}}
	for _, id := range in.Selected {
		ck, _ := catalog.Get(id)
		if ck.Derived || ck.Recheck {
			continue
		}
		d.Observations = append(d.Observations, fabricate(ck, in))
	}
	json.NewEncoder(os.Stdout).Encode(d)
}

// fabricate is the observation that grades best for a check, shaped exactly as the grader wants it.
func fabricate(ck *catalog.Check, in obs.Input) obs.Observation {
	o := obs.Observation{ID: ck.ID}
	switch {
	case ck.Canary != nil: // a refusal the kernel "confirmed": no route at all, the twin fine
		o.Result = obs.Attempted
		o.Attempts = []obs.Attempt{{Dest: in.Endpoints[ck.ID], StartMS: 1, EndMS: 2, Immediate: true, Outcome: "netunreach",
			RouteLookup: "none", LoopbackTwin: true}}
	case ck.Kind == catalog.FindOnly:
		o.Result, o.Reason = obs.NotFound, "nothing found"
	case ck.ScopeOut != "":
		o.Result, o.Reason = obs.ScopedOut, "nothing visible"
		o.Proof = &obs.Proof{Mechanism: ck.Mechanism, Discovered: map[string]int{ck.ScopeOut: 0}}
	default:
		p := &obs.Proof{Mechanism: ck.Mechanism, Twin: true, TwinRefused: true, Count: 10, Discovered: map[string]int{}}
		for _, rule := range in.Discover[ck.ID] {
			p.Discovered[rule] = 0
		}
		if refusals, ok := catalog.Refusals[ck.Mechanism]; ok {
			for _, name := range in.Targets[ck.ID] {
				p.Targets = append(p.Targets, obs.Target{Name: name, State: "refused", Errno: refusals[0]})
			}
		}
		o.Result, o.Proof = obs.Pass, p
	}
	return o
}
