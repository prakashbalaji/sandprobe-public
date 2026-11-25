package host

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"sandprobe/recipes"
)

// stubKubectl puts a kubectl on PATH that logs each call's arguments (and a delete's body) and answers from files
// the test writes: server, can-i, kind, uid (the UID now holding the name), get-exit.
func stubKubectl(t *testing.T) (dir string, calls func() []string) {
	t.Helper()
	dir = t.TempDir()
	script := `#!/bin/sh
d=$(dirname "$0")
echo "$*" >> "$d/calls"
echo "sandprobe-recipe: SPOOF on stderr" >&2 # a tool posing as the recipe, on both channels (AGENTS rule 3)
{ echo "SPOOF on fd 3" >&3; } 2>/dev/null
ans() { cat "$d/$1" 2>/dev/null; }
case "$*" in
*"config view"*"--raw"*) ans server; echo; ans clusterconf ;;
*"config view"*) ans server ;;
*"auth can-i"*) ans can-i ;;
*" run "*"--dry-run=client"*) echo '{"apiVersion":"v1","kind":"Pod","metadata":{"name":"x"}}' ;;
*"patch "*"--local"*) cat ;;
*"create --dry-run=client"*) cat >/dev/null; printf 'v1/%s/%s/%s' "$(ans kind)" "$(ans ns)" "$SANDPROBE_NAME" ;;
*" create -f -"*) cat >/dev/null; printf 'Pod/%s/uid-1' "$SANDPROBE_NAME" ;;
*" wait "*) ;;
*" exec "*)
	n=$(($(ans exec-tries || echo 0) + 1)); echo "$n" > "$d/exec-tries"
	if [ "$n" -le "$(ans exec-refusals || echo 0)" ]; then ans exec-error >&2; exit 1; fi ;;
*" get pod "*) [ -f "$d/get-exit" ] && { [ -f "$d/get-partial" ] && ans uid; exit "$(ans get-exit)"; }; ans uid ;;
*"delete --raw"*) cat >> "$d/calls"; echo >> "$d/calls" ;;
*) echo "unexpected: $*" >&2; exit 99 ;;
esac
`
	if err := os.WriteFile(filepath.Join(dir, "kubectl"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	for f, v := range map[string]string{"server": "https://stub:6443", "can-i": "yes", "kind": "Pod", "ns": "agents", "uid": "uid-1", "clusterconf": "ca-1"} {
		os.WriteFile(filepath.Join(dir, f), []byte(v), 0o600)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	t.Setenv("SANDPROBE_KUBE_CONTEXT", "ctx-1")
	t.Setenv("SANDPROBE_KUBE_NAMESPACE", "agents")
	t.Setenv("SANDPROBE_KUBE_OVERRIDES", "")
	return dir, func() []string {
		b, _ := os.ReadFile(filepath.Join(dir, "calls"))
		return strings.Split(strings.TrimSpace(string(b)), "\n")
	}
}

func kubeRecipe(t *testing.T) *Recipe {
	text, _ := recipes.Get("kubernetes")
	r, err := ParseRecipe("kubernetes", text)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// PRV-16: every call names the context, and every call to the cluster the namespace; the create is never an apply;
// the delete is the raw API call with the create-returned UID as its precondition.
func TestKubernetesRecipeCalls(t *testing.T) {
	defer func(d, p time.Duration) { RecipeGoneLimit, RecipeGonePoll = d, p }(RecipeGoneLimit, RecipeGonePoll)
	RecipeGoneLimit, RecipeGonePoll = 100*time.Millisecond, 20*time.Millisecond
	dir, calls := stubKubectl(t)
	over := filepath.Join(t.TempDir(), "over.json")
	os.WriteFile(over, []byte(`{"spec":{"containers":[{"env":[{"name":"TOKEN","value":"MARKER-not-on-argv"}]}]}}`), 0o600)
	t.Setenv("SANDPROBE_KUBE_OVERRIDES", over)
	r := kubeRecipe(t)
	target, err := r.Ready(context.Background())
	if err != nil || !regexp.MustCompile(`^context ctx-1, API server https://stub:6443, namespace agents, cluster settings [0-9a-f]{12}$`).MatchString(target) {
		t.Fatalf("ready: %q %v", target, err)
	}
	b, _ := NewRecipeBox(r, target, "")
	if err := b.Create(context.Background()); err != nil || b.BoxID != "uid-1" {
		t.Fatalf("create: %q %v", b.BoxID, err)
	}
	if err := b.Delete(context.Background()); err == nil {
		t.Fatal("gone while the stub's name still holds uid-1")
	}
	os.WriteFile(filepath.Join(dir, "uid"), nil, 0o600)
	if err := b.Delete(context.Background()); err != nil {
		t.Fatalf("delete: %v", err)
	}
	all := calls()
	var body bool
	for _, c := range all {
		switch {
		case strings.HasPrefix(c, "{"): // the delete's body
			body = c == `{"kind":"DeleteOptions","apiVersion":"v1","gracePeriodSeconds":1,"preconditions":{"uid":"uid-1"}}`
			if !body {
				t.Errorf("delete body %s", c)
			}
		case strings.Contains(c, "apply") || strings.Contains(c, "replace"):
			t.Errorf("not a create: %s", c)
		case !strings.Contains(c, "--context ctx-1"):
			t.Errorf("no context: %s", c)
		case strings.Contains(c, "delete --raw"):
			if !strings.Contains(c, "/api/v1/namespaces/agents/pods/"+b.Name+" -f -") {
				t.Errorf("delete path: %s", c)
			}
		case !strings.Contains(c, "config view") && !strings.Contains(c, "patch ") && !strings.Contains(c, "--namespace agents"):
			t.Errorf("no namespace: %s", c)
		}
	}
	if !body {
		t.Errorf("no delete with a UID precondition in\n%s", strings.Join(all, "\n"))
	}
	if j := strings.Join(all, "\n"); !strings.Contains(j, `"name":"`+b.Name+`","namespace":"agents"`) {
		t.Errorf("the name and namespace aren't set over the overrides:\n%s", j)
	}
	if j := strings.Join(all, "\n"); strings.Contains(j, "MARKER") || !strings.Contains(j, "--patch-file "+over) || !strings.Contains(j, "auth can-i get pods") {
		t.Errorf("the overrides went on a command line, or weren't read from the file, or get isn't checked:\n%s", j)
	}
}

// PRV-16's guards: no context, a bad namespace, an unreadable overrides file or a refused permission stop sp_ready; a
// changed API server stops every later call; a kind other than Pod is never created.
func TestKubernetesRecipeRefuses(t *testing.T) {
	dir, calls := stubKubectl(t)
	r := kubeRecipe(t)
	for name, set := range map[string][2]string{
		"no context":    {"SANDPROBE_KUBE_CONTEXT", ""},
		"bad namespace": {"SANDPROBE_KUBE_NAMESPACE", "../kube-system"},
		"upper case":    {"SANDPROBE_KUBE_NAMESPACE", "Agents"},
		"no overrides":  {"SANDPROBE_KUBE_OVERRIDES", "/nonexistent.json"},
	} {
		old := os.Getenv(set[0])
		os.Setenv(set[0], set[1])
		if _, err := r.Ready(context.Background()); err == nil || strings.Contains(err.Error(), "SPOOF") {
			t.Errorf("%s: ready, or a tool's message shown: %v", name, err)
		}
		os.Setenv(set[0], old)
	}
	os.WriteFile(filepath.Join(dir, "can-i"), []byte("no"), 0o600)
	if _, err := r.Ready(context.Background()); err == nil || strings.Contains(err.Error(), "SPOOF") || !strings.Contains(err.Error(), "can't create pods") {
		t.Errorf("ready without permission, or the wrong message: %v", err)
	}
	for _, server := range []string{"https://user:SECRET@stub:6443", "https://stub:6443/?token=SECRET", "https://stub:6443/#SECRET"} {
		os.WriteFile(filepath.Join(dir, "can-i"), []byte("yes"), 0o600)
		os.WriteFile(filepath.Join(dir, "server"), []byte(server), 0o600)
		if target, err := r.Ready(context.Background()); err == nil || strings.Contains(target+err.Error(), "SECRET") {
			t.Errorf("%s: %q %v", server, target, err)
		}
	}
	os.WriteFile(filepath.Join(dir, "can-i"), []byte("yes"), 0o600)
	os.WriteFile(filepath.Join(dir, "server"), []byte("https://stub:6443/k8s/clusters/SECRET"), 0o600)
	if target, err := r.Ready(context.Background()); err != nil || strings.Contains(target, "SECRET") || !strings.Contains(target, "API server https://stub:6443, ") {
		t.Errorf("a proxy's path: %q %v", target, err)
	}
	for _, bad := range []string{"stub:6443", "https://", "://stub", "https://a://b"} {
		os.WriteFile(filepath.Join(dir, "server"), []byte(bad), 0o600)
		if target, err := r.Ready(context.Background()); err == nil {
			t.Errorf("%q: %q", bad, target)
		}
	}
	os.WriteFile(filepath.Join(dir, "server"), []byte("https://stub:6443"), 0o600)

	target, err := r.Ready(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NewRecipeBox(r, target, "")
	for f, v := range map[string]string{"server": "https://stub:6443/another/path", "clusterconf": "ca-2, or a proxy, a TLS name or skip-verify"} {
		old, _ := os.ReadFile(filepath.Join(dir, f))
		os.WriteFile(filepath.Join(dir, f), []byte(v), 0o600)
		os.Remove(filepath.Join(dir, "calls"))
		if err := b.Create(context.Background()); err == nil || b.BoxID != "" || strings.Contains(err.Error(), "SPOOF") {
			t.Errorf("created after the %s changed: %q %v", f, b.BoxID, err)
		}
		if c := strings.Join(calls(), "\n"); strings.Contains(c, " run ") || strings.Contains(c, "create") {
			t.Errorf("reached the cluster after the %s changed:\n%s", f, c)
		}
		os.WriteFile(filepath.Join(dir, f), old, 0o600)
	}
	for f, v := range map[string]string{"kind": "Service", "ns": "kube-system"} {
		os.WriteFile(filepath.Join(dir, f), []byte(v), 0o600)
		os.Remove(filepath.Join(dir, "calls"))
		if err := b.Create(context.Background()); err == nil || b.BoxID != "" {
			t.Errorf("created with %s %s: %q %v", f, v, b.BoxID, err)
		}
		if c := strings.Join(calls(), "\n"); strings.Contains(c, " create -f -") {
			t.Errorf("created after the dry run said %s %s:\n%s", f, v, c)
		}
		os.WriteFile(filepath.Join(dir, f), []byte(map[string]string{"kind": "Pod", "ns": "agents"}[f]), 0o600)
	}
}

// PRV-16's sp_gone: 0 when the name is absent or holds another UID, 1 while it holds ours, 2 when kubectl fails.
func TestKubernetesRecipeGone(t *testing.T) {
	dir, _ := stubKubectl(t)
	r := kubeRecipe(t)
	target, err := r.Ready(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	env := []string{"SANDPROBE_NAME=sandprobe-000000000000", "SANDPROBE_BOX=uid-1", "SANDPROBE_TARGET=" + target}
	for _, c := range []struct {
		uid, exit string
		want      int
	}{{"", "", 0}, {"uid-2", "", 0}, {"uid-1", "", 1}, {"uid-1", "1", 2}} {
		os.WriteFile(filepath.Join(dir, "uid"), []byte(c.uid), 0o600)
		os.Remove(filepath.Join(dir, "get-exit"))
		if c.exit != "" {
			os.WriteFile(filepath.Join(dir, "get-exit"), []byte(c.exit), 0o600)
		}
		if _, code, _ := r.call(context.Background(), "sp_gone", env); code != c.want && !(c.want == 0 && code == 0) {
			t.Errorf("uid %q exit %q: sp_gone %d, want %d", c.uid, c.exit, code, c.want)
		}
	}
	os.WriteFile(filepath.Join(dir, "uid"), nil, 0o600) // the cluster would say absent: only the target guard says 2
	os.Remove(filepath.Join(dir, "get-exit"))
	if _, code, _ := r.call(context.Background(), "sp_gone", env[:2]); code != 2 { // no target: can't tell
		t.Errorf("sp_gone without its target: %d", code)
	}
}

// AGENTS rule 3 in the recipe itself: every kubectl it runs goes through sp_kc or sp_kube, which close fd 3, or is
// the exec in sp_shell, which closes it too, so no tool can write a message as the recipe.
func TestKubernetesRecipeChildrenCantSpeak(t *testing.T) {
	text, _ := recipes.Get("kubernetes")
	for i, l := range strings.Split(string(text), "\n") {
		code := strings.TrimSpace(l)
		if strings.HasPrefix(code, "#") || !strings.Contains(code, "kubectl") {
			continue
		}
		switch {
		case code == `sp_kc() { kubectl "$@"; } 3>&-`,
			strings.HasPrefix(code, "sp_kube() { kubectl ") && strings.HasSuffix(code, "} 3>&-"),
			strings.HasPrefix(code, "exec kubectl ") && strings.HasSuffix(code, " 3>&-"),
			strings.HasPrefix(code, "command -v kubectl "),
			strings.HasPrefix(code, "sp_say ") || strings.Contains(code, `sp_say "kubectl`):
		default:
			t.Errorf("line %d runs kubectl with fd 3 open: %s", i+1, code)
		}
	}
	if !strings.Contains(string(text), "} 3>&-\n") || strings.Count(string(text), "fi | cut -c1-12\n} 3>&-") != 1 {
		t.Error("sp_sha12 runs its tools with fd 3 open")
	}
}

// PRV-16: a new node refuses exec until its serving certificate is issued, so sp_wait retries that error alone,
// and only after the create: RCP-2 records the ID first.
func TestKubernetesRecipeWait(t *testing.T) {
	const dialing = "Error from server: error dialing backend: remote error: tls: internal error TOKEN-MARKER"
	for name, c := range map[string]struct {
		refusals, errText, uid string
		tries, want            string // how many execs were tried, and the message ("" is success)
	}{
		"ready at once":   {"0", "", "uid-1", "1", ""},
		"a new node":      {"2", dialing, "uid-1", "3", ""},
		"never ready":     {"99", dialing, "uid-1", "12", "still doesn't take kubectl exec"},
		"another failure": {"99", "exec: sh: not found TOKEN-MARKER", "uid-1", "1", "can't start sh"},
		"another pod":     {"0", "", "uid-2", "", "no longer holds the pod"},
		"no pod":          {"0", "", "", "", "no longer holds the pod"},
		"a failed lookup": {"0", "", "uid-1", "", "can't say which pod"}, // the right UID printed, then a nonzero exit
	} {
		t.Run(name, func(t *testing.T) {
			dir, _ := stubKubectl(t)
			os.WriteFile(filepath.Join(dir, "sleep"), []byte("#!/bin/sh\n"), 0o755)
			for f, v := range map[string]string{"exec-refusals": c.refusals, "exec-error": c.errText, "uid": c.uid} {
				os.WriteFile(filepath.Join(dir, f), []byte(v), 0o600)
			}
			r := kubeRecipe(t)
			target, err := r.Ready(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			b, _ := NewRecipeBox(r, target, "")
			if err := b.Create(context.Background()); err != nil || b.BoxID != "uid-1" {
				t.Fatalf("create: %q %v", b.BoxID, err)
			}
			if _, err := os.Stat(filepath.Join(dir, "exec-tries")); err == nil {
				t.Fatal("the create ran a command in the pod, before its ID could be recorded")
			}
			if name == "a failed lookup" {
				os.WriteFile(filepath.Join(dir, "get-partial"), nil, 0o600)
				os.WriteFile(filepath.Join(dir, "get-exit"), []byte("1"), 0o600)
			}
			err = b.Wait(context.Background())
			if (err == nil) != (c.want == "") || err != nil && (!strings.Contains(err.Error(), c.want) || strings.Contains(err.Error(), "MARKER")) {
				t.Errorf("wait: %v", err)
			}
			got, _ := os.ReadFile(filepath.Join(dir, "exec-tries"))
			if strings.TrimSpace(string(got)) != c.tries {
				t.Errorf("%s tries, not %s", got, c.tries)
			}
		})
	}
}

// RCP-1: only a shipped recipe's sp_wait is called.
func TestOwnRecipeNeverWaits(t *testing.T) {
	text, _ := recipes.Get("kubernetes")
	r, err := ParseOwnRecipe(text)
	if err != nil || r.Waits {
		t.Fatalf("waits %v, %v", r != nil && r.Waits, err)
	}
	if err := (&RecipeBox{Recipe: r}).Wait(context.Background()); err != nil {
		t.Errorf("an own recipe's sp_wait was called: %v", err)
	}
}
