package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"sandprobe/internal/catalog"
)

type explained struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Category  string `json:"category,omitempty"`
	Kind      string `json:"kind,omitempty"`
	Mechanism string `json:"mechanism,omitempty"`
	Gets      string `json:"if_found"`
	Fix       string `json:"fix"`
}

var chains = map[string]string{
	"CHN-1": "A readable credential or process surface, with a proven way out",
	"CHN-2": "A proven root-equivalent amplifier caps everything",
	"CHN-3": "Credentials and the Kubernetes API",
}

func explain(o opts, args []string) error {
	if len(args) != 1 {
		return fail("usage", "explain takes one check, such as EGR-2", "sandprobe explain EGR-2", exitUsage)
	}
	var id string
	for k := range catalog.Guide {
		if strings.EqualFold(k, args[0]) {
			id = k
		}
	}
	a, ok := catalog.Guide[id]
	if !ok {
		return fail("usage", "no check "+args[0], "sandprobe explain SEC-1 (checks: SEC-1 to 5, EGR-1 to 6, PER-1 to 5, AMP-1 to 8, CHN-1 to 3)", exitUsage)
	}
	e := explained{ID: id, Gets: "A hijacked agent " + a.Gets + ".", Fix: a.Fix, Title: chains[id]}
	if ck, ok := catalog.Get(id); ok {
		e.Title, e.Category, e.Mechanism = ck.Title, ck.Category, ck.Mechanism
		e.Kind = "two-sided: a pass needs a refusal proven next to an allowed twin"
		if ck.Kind == catalog.FindOnly {
			e.Kind = "find-only: it can find, never prove a refusal"
		}
	}
	if o.json() {
		o.emit(e)
		return nil
	}
	fmt.Fprintf(o.stdout, "%s  %s\n", e.ID, e.Title)
	if e.Kind != "" {
		fmt.Fprintf(o.stdout, "  kind:  %s\n", e.Kind)
	}
	fmt.Fprintf(o.stdout, "  found: %s\n  fix:   %s\n", e.Gets, e.Fix)
	return nil
}

func jsonIndent(v any) ([]byte, error) { return json.MarshalIndent(v, "", "  ") }
