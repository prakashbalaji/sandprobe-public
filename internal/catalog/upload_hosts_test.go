package catalog

import (
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
