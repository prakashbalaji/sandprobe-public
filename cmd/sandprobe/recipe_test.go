package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sandprobe/internal/host"
)

// cliKubectl puts a kubectl on PATH that answers sp_ready and logs every call; anything past sp_ready fails loudly.
func cliKubectl(t *testing.T) func() string {
	t.Helper()
	dir := t.TempDir()
	script := `#!/bin/sh
echo "$*" >> "$(dirname "$0")/calls"
case "$*" in
*"config view"*) printf 'https://stub:6443' ;;
*"auth can-i"*) echo yes ;;
*) echo "unexpected: $*" >&2; exit 99 ;;
esac
`
	if err := os.WriteFile(filepath.Join(dir, "kubectl"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SANDPROBE_CANARY", "")
	t.Setenv("SANDPROBE_CANARY_URL", "")
	t.Setenv("SANDPROBE_CANARY_PIN", "")
	t.Setenv("SANDPROBE_KUBE_CONTEXT", "ctx-1")
	t.Setenv("SANDPROBE_KUBE_NAMESPACE", "")
	t.Setenv("SANDPROBE_KUBE_OVERRIDES", "")
	return func() string { b, _ := os.ReadFile(filepath.Join(dir, "calls")); return string(b) }
}

// PRV-16 and RCP-1 at the command line, through plan and an unapproved run only: nothing is created.
func TestRecipePlan(t *testing.T) {
	calls := cliKubectl(t)
	var out, errs bytes.Buffer
	if code := run([]string{"plan", "kubernetes", "-no-canary", "-as", "agent"}, &out, &errs); code != 0 {
		t.Fatalf("plan: exit %d, %s", code, errs.String())
	}
	for _, want := range []string{"context ctx-1, API server https://stub:6443, namespace default", "sandprobe-", "only by the ID its create returned",
		"sp_whois must name the box", "you chose -no-canary", "SEC-4, EGR-3, AMP-6, AMP-7 are off", "PER-5 is skipped (RCP-3)", "with your own credentials"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the plan doesn't say %q:\n%s", want, out.String())
		}
	}
	out.Reset()
	if code := run([]string{"run", "kubernetes", "-no-canary"}, &out, &errs); code != exitApproval {
		t.Errorf("an unapproved run: exit %d", code)
	}
	if c := calls(); strings.Contains(c, " run ") || strings.Contains(c, "create -f") || strings.Contains(c, "delete --raw") || strings.Contains(c, "unexpected") {
		t.Errorf("reached past sp_ready:\n%s", c)
	}
	t.Setenv("SANDPROBE_KUBE_CONTEXT", "")
	if code := run([]string{"plan", "kubernetes", "-no-canary"}, &out, &errs); code != exitLogin {
		t.Errorf("no context: exit %d", code)
	}
	t.Setenv("SANDPROBE_KUBE_CONTEXT", "ctx-1")
	for _, args := range [][]string{
		{"plan", "kubernetes", "-no-canary", "--", "sh"},
		{"plan", "kubernetes", "-no-canary", "-canary-url", "https://control.sandprobe.test", "-canary-pin", testPin},
		{"plan", "kubernetes", "-as", "bad user"},
	} {
		if code := run(args, &out, &errs); code != exitUsage {
			t.Errorf("%q: exit %d", args, code)
		}
	}
}

// PRV-16 live, on a kind cluster only: SANDPROBE_KIND_KUBECONFIG names its own kubeconfig file (never ~/.kube/config)
// and SANDPROBE_KIND_CONTEXT its context. The run goes without a canary, so nothing leaves the machine.
func TestKubernetesRecipeLive(t *testing.T) {
	kc, ctx := os.Getenv("SANDPROBE_KIND_KUBECONFIG"), os.Getenv("SANDPROBE_KIND_CONTEXT")
	if kc == "" || !strings.HasPrefix(ctx, "kind-") {
		t.Skip("set SANDPROBE_KIND_KUBECONFIG and SANDPROBE_KIND_CONTEXT (kind-...) to run against a kind cluster")
	}
	t.Setenv("KUBECONFIG", kc)
	t.Setenv("HOME", t.TempDir()) // the run's record goes here, and must be gone after
	t.Setenv("SANDPROBE_KUBE_CONTEXT", ctx)
	t.Setenv("SANDPROBE_KUBE_NAMESPACE", "")
	t.Setenv("SANDPROBE_KUBE_OVERRIDES", "")
	var out, errs bytes.Buffer
	code := run([]string{"run", "kubernetes", "-no-canary", "-y", "-o", "json", "-out", t.TempDir()}, &out, &errs)
	if code != exitPartial {
		t.Fatalf("exit %d (want incomplete, %d): %s", code, exitPartial, errs.String())
	}
	var d struct {
		Run struct {
			NoCanary bool `json:"no_canary"`
		} `json:"run"`
		Cleanup json.RawMessage `json:"cleanup"`
	}
	if err := json.Unmarshal(out.Bytes(), &d); err != nil || !d.Run.NoCanary || !strings.Contains(string(d.Cleanup), "confirmed gone") {
		t.Fatalf("report: %v %s", err, d.Cleanup)
	}
	noneLeft := func() {
		t.Helper()
		left, err := exec.Command("kubectl", "--context", ctx, "get", "pods", "-A", "-l", "app.kubernetes.io/managed-by=sandprobe", "-o", "name").Output()
		if err != nil || len(bytes.TrimSpace(left)) != 0 {
			t.Fatalf("pods left: %s %v", left, err)
		}
		if j, _ := filepath.Glob(filepath.Join(configDir(), "recipe-*.state")); len(j) != 0 {
			t.Fatalf("records left: %v", j)
		}
	}
	noneLeft()
	// PRV-15 through a recipe: the default pod runs as root, so -as nobody stops before any check, and it's deleted.
	errs.Reset()
	if code := run([]string{"run", "kubernetes", "-no-canary", "-as", "nobody", "-y", "-out", t.TempDir()}, &out, &errs); code != exitPartial || !strings.Contains(errs.String(), "confirmed gone") {
		t.Fatalf("-as nobody on a root pod: exit %d, %s", code, errs.String())
	}
	noneLeft()
}

// lifecycleKubectl is a kubectl for a whole run up to the probe: files in its directory make the create return no ID
// (noid), the readiness wait sleep and fail (waitsleep), and the name hold a UID (uid).
func lifecycleKubectl(t *testing.T) (string, func() string) {
	t.Helper()
	dir := t.TempDir()
	script := `#!/bin/sh
d=$(dirname "$0")
echo "$*" >> "$d/calls"
case "$*" in
*"config view"*) printf 'https://stub:6443' ;;
*"auth can-i"*) echo yes ;;
*" run "*"--dry-run=client"*) echo '{}' ;;
*"patch "*"--local"*) cat ;;
*"create --dry-run=client"*) cat >/dev/null; printf 'v1/Pod/default/%s' "$SANDPROBE_NAME" ;;
*" create -f -"*) cat >/dev/null; [ -f "$d/noid" ] && { echo "Error from server (Forbidden)" >&2; exit 1; }
	[ -f "$d/lockrecord" ] && chmod 500 "$HOME/.config/sandprobe"; printf 'Pod/%s/uid-1' "$SANDPROBE_NAME" ;;
*" wait "*) if [ -f "$d/waitsleep" ]; then sleep "$(cat "$d/waitsleep")"; exit 1; fi ;;
*" get pod "*) cat "$d/uid" 2>/dev/null ;;
*"delete --raw"*) cat >/dev/null; [ -f "$d/sticky" ] || : > "$d/uid" ;;
*) echo "unexpected: $*" >&2; exit 99 ;;
esac
`
	if err := os.WriteFile(filepath.Join(dir, "kubectl"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "uid"), nil, 0o600)
	cliKubectl(t) // the rest of the environment
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	return dir, func() string { b, _ := os.ReadFile(filepath.Join(dir, "calls")); return string(b) }
}

// RCP-2 at the command line: a create with no ID exits 7 naming the box, deletes nothing and keeps its record; an ID
// whose box never became ready, and isn't confirmed gone, exits 7 naming the ID, after a delete that still had its
// own budget though the run had used more than that budget already.
func TestRecipeRunCleanupExits(t *testing.T) {
	dir, calls := lifecycleKubectl(t)
	os.WriteFile(filepath.Join(dir, "noid"), nil, 0o600)
	var out, errs bytes.Buffer
	if code := run([]string{"run", "kubernetes", "-no-canary", "-y"}, &out, &errs); code != exitCleanup {
		t.Fatalf("no ID: exit %d, %s", code, errs.String())
	}
	if c := calls(); strings.Contains(c, "delete --raw") || strings.Contains(c, " get pod ") {
		t.Errorf("acted on a box with no ID:\n%s", c)
	}
	journals, _ := filepath.Glob(filepath.Join(configDir(), "recipe-kubernetes-sandprobe-*.state"))
	if len(journals) != 1 || !strings.Contains(errs.String(), journals[0]) {
		t.Fatalf("the box isn't recorded and named: %v\n%s", journals, errs.String())
	}
	os.Remove(journals[0])

	defer func(d, g, p time.Duration) { recipeDeleteLimit, host.RecipeGoneLimit, host.RecipeGonePoll = d, g, p }(recipeDeleteLimit, host.RecipeGoneLimit, host.RecipeGonePoll)
	recipeDeleteLimit, host.RecipeGoneLimit, host.RecipeGonePoll = time.Second, 200*time.Millisecond, 50*time.Millisecond
	os.Remove(filepath.Join(dir, "noid"))
	os.Remove(filepath.Join(dir, "calls"))
	os.WriteFile(filepath.Join(dir, "waitsleep"), []byte("1.5"), 0o600) // longer than the delete's whole budget
	os.WriteFile(filepath.Join(dir, "uid"), []byte("uid-1"), 0o600)
	os.WriteFile(filepath.Join(dir, "sticky"), nil, 0o600) // the delete leaves it: not gone
	errs.Reset()
	if code := run([]string{"run", "kubernetes", "-no-canary", "-y"}, &out, &errs); code != exitCleanup || !strings.Contains(errs.String(), "uid-1") {
		t.Fatalf("not gone: exit %d, %s", code, errs.String())
	}
	if c := calls(); !strings.Contains(c, "delete --raw") {
		t.Errorf("the delete was never asked:\n%s", c)
	}
	journals, _ = filepath.Glob(filepath.Join(configDir(), "recipe-kubernetes-sandprobe-*.state"))
	if len(journals) != 1 {
		t.Fatalf("records: %v", journals)
	}
	if b, _ := os.ReadFile(journals[0]); !strings.Contains(string(b), `"id": "uid-1"`) {
		t.Errorf("the record lacks the ID: %s", b)
	}
}

// AGENTS rule 8 and RCP-2: a box whose ID can't be recorded on disk gets nothing run in it, and is deleted by that ID.
func TestRecipeRunStopsWithoutRecord(t *testing.T) {
	dir, calls := lifecycleKubectl(t)
	t.Cleanup(func() { os.Chmod(configDir(), 0o700) })
	os.WriteFile(filepath.Join(dir, "lockrecord"), nil, 0o600)
	os.WriteFile(filepath.Join(dir, "uid"), []byte("uid-1"), 0o600) // the create's pod, until the delete
	var out, errs bytes.Buffer
	code := run([]string{"run", "kubernetes", "-no-canary", "-y"}, &out, &errs)
	if code != exitPartial || !strings.Contains(errs.String(), "couldn't be recorded on disk") || !strings.Contains(errs.String(), "confirmed gone") {
		t.Fatalf("exit %d, %s", code, errs.String())
	}
	c := calls()
	if strings.Contains(c, " exec ") || !strings.Contains(c, "delete --raw") {
		t.Errorf("ran in a box whose ID isn't on disk, or didn't delete it:\n%s", c)
	}
}
