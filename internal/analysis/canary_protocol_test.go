package analysis

import (
	"encoding/json"
	"sandprobe/internal/canary"
	"sandprobe/internal/report"
	"slices"
	"testing"
)

func TestHTTPMarkerReportVersionAndComparison(t *testing.T) {
	a, b := baseline(t), baseline(t)
	b.Manifest.CanaryTCP80Protocol = canary.HTTPMarkerV1
	b.Schema = report.SchemaCanaryHTTP
	wire, _ := json.Marshal(b)
	if _, err := Parse(wire); err != nil {
		t.Fatal("new declared schema rejected", err)
	}
	if !slices.Contains(Compare(a, b).ContextChanges, "declared_configuration") {
		t.Fatal("protocol change hidden in comparison")
	}
	b.Schema = report.Schema
	wire, _ = json.Marshal(b)
	if _, err := Parse(wire); err == nil {
		t.Fatal("new protocol accepted under old schema")
	}
	b.Schema = report.SchemaCanaryHTTP
	b.Manifest.CanaryTCP80Protocol = "untrusted-secret"
	wire, _ = json.Marshal(b)
	if _, err := Parse(wire); err == nil {
		t.Fatal("unknown protocol accepted")
	}
}

func TestHTTPMarkerEmptyDeclarationIsNotLegacy(t *testing.T) {
	for _, value := range []string{`null`, `""`} {
		wire, _ := json.Marshal(baseline(t))
		var doc map[string]json.RawMessage
		json.Unmarshal(wire, &doc)
		var manifest map[string]json.RawMessage
		json.Unmarshal(doc["manifest"], &manifest)
		manifest["canary_tcp80_protocol"] = json.RawMessage(value)
		doc["manifest"], _ = json.Marshal(manifest)
		wire, _ = json.Marshal(doc)
		if _, err := Parse(wire); err == nil {
			t.Fatal("empty new field hidden under legacy schema")
		}
	}
}
