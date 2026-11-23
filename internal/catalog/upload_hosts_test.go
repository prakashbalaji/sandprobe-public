package catalog

import (
	"slices"
	"strings"
	"testing"
)

func TestUploadHostSelection(t *testing.T) {
	for _, input := range []string{"", "github.com", "pypi.org,files.pythonhosted.org,bedrock-runtime.us-west-2.amazonaws.com"} {
		if _, err := ParseUploadHosts(input); err != nil {
			t.Errorf("approved selection: %v", err)
		}
	}
	for _, input := range []string{"*", "all", "GITHUB.COM", " github.com", "github.com.", "github.com,", "github.com,github.com", "https://github.com", "github.com:443", "127.0.0.1", "169.254.169.254", "provider.internal", "api.openai.com/path?credential=fixture", "github.com,pypi.org,files.pythonhosted.org,api.openai.com,api.anthropic.com"} {
		if _, err := ParseUploadHosts(input); err == nil || strings.Contains(err.Error(), "credential") {
			t.Errorf("invalid selection accepted or echoed")
		}
	}
}

func TestFrozenUploadBindings(t *testing.T) {
	hosts := []string{"github.com", "bedrock-runtime.us-west-2.amazonaws.com"}
	addresses := map[string]string{hosts[1]: "1.1.1.1"}
	targets, err := BindUploadHosts(hosts, addresses)
	if err != nil || !slices.Equal(targets, []string{"github.com", "bedrock-runtime.us-west-2.amazonaws.com=1.1.1.1"}) {
		t.Fatal(targets, err)
	}
	endpoints, err := ParseUploadTargets(targets)
	if err != nil || endpoints[0].Address.IsValid() || endpoints[1].Host != hosts[1] || endpoints[1].Address.String() != "1.1.1.1" {
		t.Fatal("binding semantics changed", err)
	}
	addresses[hosts[1]] = "8.8.8.8"
	if targets[1] != "bedrock-runtime.us-west-2.amazonaws.com=1.1.1.1" {
		t.Fatal("binding was not frozen")
	}
	for _, target := range []string{"github.com=127.0.0.1", "github.com=169.254.169.254", "github.com=10.0.0.1", "github.com=100.64.0.1", "github.com=192.0.2.1", "github.com=64:ff9b::101:101", "github.com=::ffff:1.1.1.1", "github.com=1.1.1.1=8.8.8.8", "unknown.invalid=1.1.1.1", "github.com=1.1.1.1:443", "github.com="} {
		if ValidateUploadTargets([]string{target}) == nil {
			t.Fatal("invalid target accepted")
		}
	}
	if ValidateUploadTargets([]string{"github.com=1.1.1.1", "github.com=8.8.8.8"}) == nil {
		t.Fatal("duplicate host binding accepted")
	}
	if _, err := BindUploadHosts([]string{"github.com"}, map[string]string{"pypi.org": "1.1.1.1"}); err == nil {
		t.Fatal("unselected host added through bindings")
	}
}
