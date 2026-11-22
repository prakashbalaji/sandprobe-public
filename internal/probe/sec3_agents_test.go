//go:build linux

package probe

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"sandprobe/internal/catalog"
	"sandprobe/internal/obs"
)

// SEC-3: an AI coding tool's own login, where its vendor documents it on Linux, is a credential file like any other.
// Each is planted alone in an otherwise empty home; the finding must name it, so a finding from elsewhere (root reading
// /etc/shadow, say) can't stand in for it.
func TestSEC3FindsAgentLogins(t *testing.T) {
	targets, _ := catalog.Plan([]string{"SEC-3"})
	ck, _ := catalog.Get("SEC-3")
	for _, f := range []string{
		"~/.claude/.credentials.json", "~/.codex/auth.json", "~/.codex/.credentials.json", "~/.gemini/oauth_creds.json",
		"~/.aider/oauth-keys.env", "~/.cline/data/secrets.json",
		"~/.config/goose/secrets.yaml",
	} {
		if !slices.Contains(targets["SEC-3"], f) {
			t.Errorf("%s isn't a SEC-3 target", f)
			continue
		}
		e := testEnv(t, map[string][]string{"SEC-3": targets["SEC-3"]})
		e.home = t.TempDir()
		chdir(t, t.TempDir())
		p := e.expand(f)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("sandprobe-fake"), 0o600); err != nil {
			t.Fatal(err)
		}
		o := sec3(e, ck)
		if o.Result != obs.Finding || !(strings.Contains(o.Evidence, f) || strings.Contains(o.Evidence, p)) {
			t.Errorf("%s readable: want a SEC-3 finding naming it, got %s %q", f, o.Result, o.Evidence)
		}
	}
}
