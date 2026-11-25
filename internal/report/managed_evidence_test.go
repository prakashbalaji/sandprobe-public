package report

import (
	"encoding/json"
	"sandprobe/internal/obs"
	"sandprobe/internal/strictjson"
	"strings"
	"testing"
)

func TestManagedEvidenceVersion(t *testing.T) {
	d := Doc{}
	d.Schema = "sandprobe/6"
	b := NewManagedEvidence(d, "{}", obs.CanaryEvidence{Reset: &obs.ResetEvidence{FailureStage: "create_replacement"}}, obs.Input{}, "")
	raw, e := json.Marshal(b)
	if e != nil {
		t.Fatal(e)
	}
	var decoded ManagedEvidence
	if strictjson.Decode(raw, 1<<20, &decoded) != nil || decoded.Schema != ManagedEvidenceSchema || decoded.Report.Schema != d.Schema || decoded.Evidence.Reset.FailureStage != "create_replacement" {
		t.Fatal("version or raw evidence lost")
	}
	if strings.Contains(string(raw), `"html"`) {
		t.Fatal("HTML added to saved raw evidence")
	}
	// An old strict envelope must reject the explicit new boundary, rather than silently accept it.
	var legacy struct {
		Report       Doc                `json:"report"`
		Observations string             `json:"observations"`
		Evidence     obs.CanaryEvidence `json:"evidence"`
		Input        obs.Input          `json:"input"`
	}
	if strictjson.Decode(raw, 1<<20, &legacy) == nil {
		t.Fatal("version2 silently read as legacy")
	}
}
