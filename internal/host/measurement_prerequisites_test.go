package host

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sandprobe/internal/obs"
	"strings"
	"testing"
)

func TestMeasurementPrerequisites(t *testing.T) {
	r := &Run{Manifest: obs.Manifest{RunID: "fixture-run", Nonce: "fixture-nonce", BoxID: "fixture-box", ProbeSHA256: strings.Repeat("a", 64)}, Survey: &obs.Survey{Proxy: &obs.ProxySetting{Addr: "localhost:8080", Credentials: true}, KubeAPI: "NEVER_EXPORT_ENDPOINT", Vsock: true}}
	folder := t.TempDir()
	if err := SaveMeasurementPrerequisites(folder, r); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(folder, "measurement-prerequisites.json")
	raw, _ := os.ReadFile(path)
	var p obs.MeasurementPrerequisites
	if json.Unmarshal(raw, &p) != nil || !p.Valid() || p.Proxy != "local_unapproved" || p.KubeAPI != "present" || p.Vsock != "present" || p.ProxyCredentials != "present_not_used" || p.ProxyProtocol != "unsupported" {
		t.Fatal("wrong prerequisites")
	}
	for _, secret := range []string{"localhost", "8080", "NEVER_EXPORT", "proxy-secret-value"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("private value serialized")
		}
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0600 {
		t.Fatal("not private")
	}
	if SaveMeasurementPrerequisites(folder, r) == nil {
		t.Fatal("replaced artifact")
	}
	after, _ := os.ReadFile(path)
	if string(raw) != string(after) {
		t.Fatal("existing artifact changed")
	}
	victim := filepath.Join(t.TempDir(), "victim")
	os.WriteFile(victim, []byte("keep"), 0600)
	dir := t.TempDir()
	os.Symlink(victim, filepath.Join(dir, "measurement-prerequisites.json"))
	if SaveMeasurementPrerequisites(dir, r) == nil {
		t.Fatal("followed symlink")
	}
	after, _ = os.ReadFile(victim)
	if string(after) != "keep" {
		t.Fatal("victim changed")
	}
	for _, bad := range []*Run{nil, {Manifest: r.Manifest}, {Survey: r.Survey}} {
		if SaveMeasurementPrerequisites(t.TempDir(), bad) == nil {
			t.Fatal("absence presented as surveyed prerequisite")
		}
	}
	for _, proxy := range []*obs.ProxySetting{nil, {Malformed: true, Addr: "NEVER_EXPORT"}, {Addr: "192.0.2.1:80"}} {
		r.Survey = &obs.Survey{Proxy: proxy}
		dir = t.TempDir()
		if SaveMeasurementPrerequisites(dir, r) != nil {
			t.Fatal("survey rejected")
		}
		raw, _ = os.ReadFile(filepath.Join(dir, "measurement-prerequisites.json"))
		json.Unmarshal(raw, &p)
		if p.KubeAPI != "absent" || p.Vsock != "absent" {
			t.Fatal("invented feature")
		}
		if proxy == nil && p.Proxy != "not_configured" || proxy != nil && proxy.Malformed && p.Proxy != "malformed" || proxy != nil && !proxy.Malformed && p.Proxy != "configured" {
			t.Fatal("wrong proxy prerequisite")
		}
	}
}
