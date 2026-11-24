package report

import (
	"sandprobe/internal/canary"
	"sandprobe/internal/obs"
	"testing"
)

func TestHTTPMarkerNeedsNewReportSchema(t *testing.T) {
	m := obs.Manifest{}
	if SchemaFor(m) != Schema {
		t.Fatal("legacy minimum schema changed")
	}
	m.SkipKinds = map[string]string{"SEC-4": obs.SkipOptIn}
	if SchemaFor(m) != SchemaSkipKinds {
		t.Fatal("skip-kind schema changed")
	}
	m.CanaryTCP80Protocol = canary.HTTPMarkerV1
	if SchemaFor(m) != SchemaCanaryHTTP {
		t.Fatal("new protocol hidden in old schema")
	}
	r := run()
	r.Manifest.CanaryTCP80Protocol = canary.HTTPMarkerV1
	d := Build(r, meta())
	if d.Schema != SchemaCanaryHTTP || len(d.Toolchain) == 0 {
		t.Fatal("protocol choice not disclosed")
	}
}
