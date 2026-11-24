package grade

import (
	"encoding/json"
	"reflect"
	canarywire "sandprobe/internal/canary"
	"sandprobe/internal/obs"
	"testing"
)

func TestHTTPMarkerSelectionDoesNotChangeProofRequirements(t *testing.T) {
	m, d, c := workloadCase()
	raw, _ := json.Marshal(d)
	baseline := GradeBytes(m, raw, c)
	if !baseline.Valid {
		t.Fatal("invalid calibration fixture")
	}
	m.CanaryTCP80Protocol = canarywire.HTTPMarkerV1
	if r := GradeBytes(m, raw, c); !reflect.DeepEqual(r, baseline) {
		t.Fatal("protocol declaration changed the grade")
	}
	o := observation(d, "EGR-5.80")
	o.Attempts[0].Outcome = "connected"
	o.Attempts[0].ExchangeStage = "read_reply"
	o.Attempts[0].ExchangeResult = "completed"
	raw, _ = json.Marshal(d)
	withHTTP := GradeBytes(m, raw, c)
	m.CanaryTCP80Protocol = ""
	legacy := GradeBytes(m, raw, c)
	if !reflect.DeepEqual(withHTTP, legacy) {
		t.Fatal("HTTP completion changed evidence rules")
	}
	if outcome(withHTTP, "EGR-5.80").Result != "unknown" {
		t.Fatal("completion without receipt gained proof")
	}
	c.Receipts = append(c.Receipts, obs.Receipt{Nonce: m.CheckNonces["EGR-5.80"], Proto: "tcp", Port: 80})
	m.CanaryTCP80Protocol = canarywire.HTTPMarkerV1
	if outcome(GradeBytes(m, raw, c), "EGR-5.80").Result != "finding" {
		t.Fatal("independent TCP/80 delivery receipt lost its finding")
	}
}
