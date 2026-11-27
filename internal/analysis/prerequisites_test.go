package analysis

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sandprobe/internal/obs"
	"strings"
	"testing"
)

func TestGapPrerequisiteInput(t *testing.T) {
	p := obs.MeasurementPrerequisites{Schema: obs.MeasurementPrerequisitesSchema, RunID: "run", Nonce: "nonce", BoxID: "box", ProbeSHA256: strings.Repeat("a", 64), Proxy: "configured", ProxyCredentials: "absent", ProxyProtocol: "http_connect", KubeAPI: "present", Vsock: "absent"}
	raw, _ := json.Marshal(p)
	path := filepath.Join(t.TempDir(), "p.json")
	os.WriteFile(path, raw, 0600)
	if _, err := LoadPrerequisites(path); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	os.Symlink(path, link)
	if _, err := LoadPrerequisites(link); err == nil {
		t.Fatal("followed symlink")
	}
	for _, bad := range []string{"null", "{}", string(raw) + "{}", strings.Replace(string(raw), `"schema":`, `"unknown":1,"schema":`, 1), strings.Replace(string(raw), `"proxy":"configured"`, `"proxy":"configured","proxy":"absent"`, 1), strings.Replace(string(raw), `"kube_api":"present"`, `"kube_api":null`, 1), strings.Replace(string(raw), `"proxy_credentials":"absent"`, `"proxy_credentials":"not_applicable"`, 1), strings.Repeat(" ", 16385) + string(raw)} {
		os.WriteFile(path, []byte(bad), 0600)
		if _, err := LoadPrerequisites(path); err == nil {
			t.Fatal("accepted malformed/unsupported sidecar")
		}
	}
}
