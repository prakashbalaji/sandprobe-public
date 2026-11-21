package host

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"sandprobe/recipes"
)

const fakeHeader = "# sandprobe-recipe: v1\n# provider: a fake\n# terms: none\n# exclusions: SEC-4 EGR-3 AMP-6 AMP-7\n# addressed-by: %s\n"

// fakeRecipe is a recipe whose functions log each call, with the values the host gave it, to $SANDPROBE_TEST_LOG.
func fakeRecipe(t *testing.T, addressed, body string) (*Recipe, string) {
	t.Helper()
	log := filepath.Join(t.TempDir(), "log")
	t.Setenv("SANDPROBE_TEST_LOG", log)
	text := strings.Replace(fakeHeader, "%s", addressed, 1) + `
note() { echo "$1 box=$SANDPROBE_BOX name=$SANDPROBE_NAME target=$SANDPROBE_TARGET" >> "$SANDPROBE_TEST_LOG"; }
sp_ready() { note ready; echo "a fake place"; }
` + body
	r, err := ParseRecipe("fake", []byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return r, log
}

func logOf(t *testing.T, log string) string {
	b, _ := os.ReadFile(log)
	return string(b)
}

// RCP-1: the header and the functions, and the shipped recipe itself.
func TestParseRecipe(t *testing.T) {
	text, ok := recipes.Get("kubernetes")
	if !ok {
		t.Fatal("no shipped kubernetes recipe")
	}
	r, err := ParseRecipe("kubernetes", text)
	if err != nil || r.AddressedBy != "name" || strings.Join(r.Exclusions, " ") != "SEC-4 EGR-3 AMP-6 AMP-7" || len(r.SHA256) != 64 {
		t.Fatalf("the shipped recipe: %+v %v", r, err)
	}
	fns := "sp_ready() {\n:\n}\nsp_create() {\n:\n}\nsp_shell() {\n:\n}\nsp_delete() {\n:\n}\nsp_gone() {\n:\n}\n"
	ok1 := strings.Replace(fakeHeader, "%s", "id", 1) + fns
	if _, err := ParseRecipe("x", []byte(ok1)); err != nil {
		t.Fatalf("a sound recipe: %v", err)
	}
	for name, bad := range map[string]string{
		"no header":         fns,
		"no provider":       "# sandprobe-recipe: v1\n# terms: x\n# addressed-by: id\n" + fns,
		"no addressed-by":   "# sandprobe-recipe: v1\n# provider: x\n# terms: x\n" + fns,
		"unknown key":       strings.Replace(ok1, "# terms: none", "# terms: none\n# colour: red", 1),
		"twice":             strings.Replace(ok1, "# terms: none", "# terms: none\n# terms: again", 1),
		"excludes SEC-1":    strings.Replace(ok1, "AMP-7", "AMP-7 SEC-1", 1),
		"env not ours":      strings.Replace(ok1, "# terms: none", "# terms: none\n# env: HOME", 1),
		"env claims BOX":    strings.Replace(ok1, "# terms: none", "# terms: none\n# env: SANDPROBE_BOX", 1),
		"no sp_gone":        strings.Replace(ok1, "sp_gone() {", "gone() {", 1),
		"name without who":  strings.Replace(ok1, "addressed-by: id", "addressed-by: name", 1),
		"over 64 KiB":       ok1 + "#" + strings.Repeat("x", 64<<10) + "\n",
		"addressed-by what": strings.Replace(ok1, "addressed-by: id", "addressed-by: tag", 1),
	} {
		if _, err := ParseRecipe("x", []byte(bad)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

// RCP-1, RCP-2: each function gets the host's values only, never the process's own, and stdin from /dev/null; the ID
// is the create's whole stdout; a delete is by that ID and done only when sp_gone says 0.
func TestRecipeLifecycle(t *testing.T) {
	t.Setenv("SANDPROBE_BOX", "from-the-environment")
	t.Setenv("SANDPROBE_TARGET", "somewhere-else")
	r, log := fakeRecipe(t, "id", `
sp_create() { note create; x=$(cat); [ -z "$x" ] || exit 9; echo box-1; }
sp_shell() { note shell; exec sh; }
sp_delete() { note delete; }
sp_gone() { note gone; }
`)
	target, err := r.Ready(context.Background())
	if err != nil || target != "a fake place" {
		t.Fatalf("ready: %q %v", target, err)
	}
	b, err := NewRecipeBox(r, target, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(b.Name, "sandprobe-") || len(b.Name) != len("sandprobe-")+12 {
		t.Fatalf("name %q", b.Name)
	}
	if err := b.Create(context.Background()); err != nil || b.BoxID != "box-1" {
		t.Fatalf("create: %q %v", b.BoxID, err)
	}
	// sp_shell's stdin is PRV-15's script: through it, the wrapper's own uname answers.
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		if _, err := b.Arch(context.Background()); err != nil {
			t.Fatalf("through sp_shell: %v", err)
		}
	}
	if err := b.Delete(context.Background()); err != nil {
		t.Fatalf("delete: %v", err)
	}
	got := logOf(t, log)
	for _, want := range []string{
		"ready box= name= target=\n",
		"create box= name=" + b.Name + " target=a fake place\n",
		"shell box=box-1 name=" + b.Name + " target=a fake place\n",
		"delete box=box-1 name=" + b.Name + " target=a fake place\n",
		"gone box=box-1 name=" + b.Name + " target=a fake place\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("no %q in\n%s", want, got)
		}
	}
	if strings.Contains(got, "from-the-environment") || strings.Contains(got, "somewhere-else") {
		t.Errorf("the process's own SANDPROBE_ values reached the recipe:\n%s", got)
	}
}

// RCP-2: a create whose stdout isn't one ID line leaves the name reported and nothing deleted; one that prints an ID
// and then fails is still deleted by it.
func TestRecipeCreateWithoutID(t *testing.T) {
	for name, create := range map[string]string{
		"empty":     `sp_create() { note create; }`,
		"two lines": `sp_create() { note create; echo a; echo b; }`,
		"bad chars": `sp_create() { note create; echo 'a b'; }`,
		"too long":  `sp_create() { note create; printf 'a%.0s' $(seq 1 200); echo; }`,
		"failed":    `sp_create() { note create; echo "Error from server" >&2; exit 1; }`,
	} {
		r, log := fakeRecipe(t, "id", create+"\nsp_shell() { :; }\nsp_delete() { note delete; }\nsp_gone() { note gone; }\n")
		b, _ := NewRecipeBox(r, "t", "")
		err := b.Create(context.Background())
		if err == nil || b.BoxID != "" || !strings.Contains(err.Error(), b.Name) {
			t.Errorf("%s: %q %v", name, b.BoxID, err)
		}
		if err := b.Delete(context.Background()); err == nil || strings.Contains(logOf(t, log), "delete") {
			t.Errorf("%s: deleted without an ID: %v\n%s", name, err, logOf(t, log))
		}
	}
	r, log := fakeRecipe(t, "id", "sp_create() { echo box-2; exit 1; }\nsp_shell() { :; }\nsp_delete() { note delete; }\nsp_gone() { :; }\n")
	b, _ := NewRecipeBox(r, "t", "")
	if err := b.Create(context.Background()); err == nil || b.BoxID != "box-2" {
		t.Fatalf("an ID with a failed create: %q %v", b.BoxID, err)
	}
	if err := b.Delete(context.Background()); err != nil || !strings.Contains(logOf(t, log), "delete box=box-2") {
		t.Errorf("not deleted by its ID: %v", err)
	}
}

// RCP-2: only sp_gone's 0 is gone. 1 (it exists) and 2 (can't tell) are not, and the error names the ID.
func TestRecipeGone(t *testing.T) {
	defer func(d, p time.Duration) { RecipeGoneLimit, RecipeGonePoll = d, p }(RecipeGoneLimit, RecipeGonePoll)
	RecipeGoneLimit, RecipeGonePoll = 100*time.Millisecond, 20*time.Millisecond
	for code, want := range map[string]string{"1": "it still exists", "2": "couldn't say", "7": "couldn't say"} {
		r, _ := fakeRecipe(t, "id", "sp_create() { echo box-3; }\nsp_shell() { :; }\nsp_delete() { :; }\nsp_gone() { exit "+code+"; }\n")
		b, _ := NewRecipeBox(r, "t", "")
		b.Create(context.Background())
		if err := b.Delete(context.Background()); err == nil || !strings.Contains(err.Error(), "box-3") || !strings.Contains(err.Error(), want) {
			t.Errorf("gone %s: %v", code, err)
		}
	}
}

// RCP-2: a name-addressed box is reached only while sp_whois names the ID the create returned: no invocation, and no
// delete, once the name holds another box.
func TestRecipeWhoisGuards(t *testing.T) {
	r, log := fakeRecipe(t, "name", `
sp_create() { echo uid-1; }
sp_whois() { note whois; cat "$SANDPROBE_TEST_LOG.who" 2>/dev/null; }
sp_shell() { note shell; exec sh; }
sp_delete() { note delete; }
sp_gone() { note gone; }
`)
	b, _ := NewRecipeBox(r, "t", "")
	if err := b.Create(context.Background()); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(log+".who", []byte("uid-2\n"), 0o600)
	if _, err := b.Arch(context.Background()); err == nil || !strings.Contains(err.Error(), "no longer names") {
		t.Errorf("an invocation ran on a name that holds another box: %v", err)
	}
	if err := b.Delete(context.Background()); err != nil {
		t.Errorf("gone said 0: %v", err)
	}
	got := logOf(t, log)
	if strings.Contains(got, "shell") || strings.Contains(got, "delete") || !strings.Contains(got, "whois") {
		t.Errorf("the guard didn't hold:\n%s", got)
	}
	if !strings.Contains(RecipeResidual(r, "t"), "can't be ruled out") || strings.Contains(RecipeResidual(&Recipe{Name: "x", AddressedBy: "id"}, "t"), "ruled out") {
		t.Error("the residual doesn't report the name's race, or reports it for an ID")
	}
}

// RCP-1 and AGENTS rule 3: an error carries only what the recipe said on fd 3, never its stderr, marked or not.
func TestRecipeErrorsWithhold(t *testing.T) {
	r, _ := fakeRecipe(t, "id", `
sp_create() { echo "sandprobe-recipe: token=SECRET-1 from a plugin" >&2; echo "the create failed" >&3; exit 1; }
sp_shell() { :; }
sp_delete() { echo "Authorization: Bearer SECRET-2" >&2; exit 1; }
sp_gone() { :; }
`)
	_, _, err := r.call(context.Background(), "sp_create", nil)
	if err == nil || !strings.Contains(err.Error(), "the create failed") || strings.Contains(err.Error(), "SECRET") {
		t.Errorf("create: %v", err)
	}
	_, _, err = r.call(context.Background(), "sp_delete", nil)
	if err == nil || !strings.Contains(err.Error(), "no message of its own") || strings.Contains(err.Error(), "SECRET") {
		t.Errorf("delete: %v", err)
	}
}

// AGENTS rule 3: the message file has no name while the recipe runs, so a tool with fd 3 closed can't reopen it to
// write a message as the recipe.
func TestRecipeMessagesCantBeReopened(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	r, _ := fakeRecipe(t, "id", `
sp_create() {
	( for f in "$TMPDIR"/*; do [ -f "$f" ] && echo "REOPENED-SECRET" >> "$f"; done ) 3>&-
	echo "its own message" >&3
	exit 1
}
sp_shell() { :; }
sp_delete() { :; }
sp_gone() { :; }
`)
	_, _, err := r.call(context.Background(), "sp_create", nil)
	if err == nil || strings.Contains(err.Error(), "REOPENED") || !strings.Contains(err.Error(), "its own message") {
		t.Errorf("%v", err)
	}
	if left, _ := filepath.Glob(filepath.Join(os.Getenv("TMPDIR"), "sandprobe-recipe-says-*")); len(left) != 0 {
		t.Errorf("message files left: %v", left)
	}
}
