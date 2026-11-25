package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"sandprobe/internal/analysis"
	"sandprobe/internal/host"
	"sandprobe/internal/obs"
	"sandprobe/internal/report"
	"sandprobe/recipes"
)

// ownBody is a recipe's functions for these tests, all plain sh: each logs its name to $SANDPROBE_TEST_LOG, the
// create returns box-1, and sp_shell fails, so a run stops before any check and goes to its cleanup.
const ownBody = `
note() { echo "$1" >> "$SANDPROBE_TEST_LOG"; }
sp_ready() { note ready; echo "a test place"; }
sp_create() { note create; echo box-1; }
sp_shell() { note shell; exit 1; }
sp_delete() { note delete; }
sp_gone() { note gone; }
`

// ownHeader is a header whose provider and terms lines claim what nobody reviewed.
func ownHeader(exclusions string) string {
	return "# sandprobe-recipe: v1\n# provider: modal\n# terms: MARKER-IN-THE-FILE Modal allows every test\n" + exclusions + "# addressed-by: id\n"
}

// ownFile writes a recipe file named my-recipe.sh and isolates the run: its records go under a temporary HOME, and
// the environment names no canary. It returns the file's path, the SHA-256 of its bytes, and a reader of the log.
func ownFile(t *testing.T, text string) (string, string, func() string) {
	t.Helper()
	isolateCanary(t)
	dir := t.TempDir()
	log := filepath.Join(dir, "log")
	t.Setenv("SANDPROBE_TEST_LOG", log)
	path := filepath.Join(dir, "my-recipe.sh")
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(text))
	return path, hex.EncodeToString(sum[:]), func() string { b, _ := os.ReadFile(log); return string(b) }
}

// RCP-4 at the command line: where -recipe applies, and what it takes with it. Nothing here reaches sp_ready unless
// the plan is sound.
func TestOwnRecipeUsage(t *testing.T) {
	path, _, calls := ownFile(t, ownHeader("")+ownBody)
	for _, args := range [][]string{
		{"plan", "kubernetes", "-recipe", path},
		{"run", "exec", "-recipe", path, "-y", "--", "sh"},
		{"run", "docker", "debian", "-recipe", path, "-y"},
		{"providers", "-recipe", path},
		{"scorecard", "-recipe", path, "report.json"},
		{"plan", "-recipe", ""},
		{"plan", "-recipe", path, "-provider", "modal"},
		{"plan", "-recipe", path, "-no-canary", "--", "sh"},
		{"plan", "-recipe", path, "-block-device-path", "/dev/x"},
		{"plan", "-recipe", path, "-setup", path},
		{"plan", "-recipe", path, "-keep-sandbox"},
		{"plan", "-recipe", path, "-as", "bad user"},
		{"run", "-recipe", path, "-min", "9", "-y"},
		{"plan", "-recipe", path, "-no-canary", "-canary-url", "https://control.sandprobe.test", "-canary-pin", testPin},
		{"plan", "-recipe", path, "-no-canary", "-provider-endpoints", "all"},
		{"plan", "-recipe", path, "-no-canary", "-provider-endpoints", "SEC-1"},
		{"plan", "-recipe", path, "-o", "yaml"},
	} {
		var out, errs bytes.Buffer
		if code := run(args, &out, &errs); code != exitUsage {
			t.Errorf("%q: exit %d, %s", args, code, errs.String())
		}
	}
	if c := calls(); c != "" {
		t.Errorf("a usage error ran the recipe:\n%s", c)
	}
	for _, args := range [][]string{
		{"plan", "-recipe", path, "-no-canary"},
		{"plan", "-recipe", path, "-no-canary", "-as", "agent", "-scratch", "/var/tmp"},
		{"plan", "-recipe", path, "-no-canary", "-as", "1000", "-o", "json", "-out", t.TempDir(), "-min", "full", "-theme", "mission"},
		{"plan", "-recipe", path, "-canary-url", "https://control.sandprobe.test", "-canary-pin", testPin, "-provider-endpoints", "EGR-3", "-allow-local-proxy"},
		{"plan", "-recipe", path, "-no-canary", "-provider-endpoints", "SEC-4,AMP-7"},
	} {
		var out, errs bytes.Buffer
		if code := run(args, &out, &errs); code != exitGraded {
			t.Errorf("%q: exit %d, %s", args, code, errs.String())
		}
	}
	if c := calls(); strings.Contains(c, "create") || !strings.Contains(c, "ready") {
		t.Errorf("a plan ran more than sp_ready, or not even that:\n%s", c)
	}
}

// RCP-4: the file is opened with ANL-1's care, and checked as a shipped recipe is. A file that isn't a sound recipe
// is a usage error that echoes nothing from it, and none of its code runs.
func TestOwnRecipeFile(t *testing.T) {
	good := ownHeader("") + ownBody
	path, _, calls := ownFile(t, good)
	dir := filepath.Dir(path)
	write := func(name, text string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	link := filepath.Join(dir, "link.sh")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "fifo.sh")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]string{
		"missing":           filepath.Join(dir, "none.sh"),
		"over 64 KiB":       write("big.sh", good+"# "+strings.Repeat("x", 64<<10)+"\n"),
		"a directory":       dir,
		"a FIFO":            fifo,
		"a symlink":         link,
		"empty":             write("empty.sh", ""),
		"no header":         write("nohead.sh", ownBody),
		"no sp_gone":        write("nogone.sh", strings.Replace(good, "sp_gone() {", "gone() {", 1)),
		"no provider":       write("noprov.sh", strings.Replace(good, "# provider: modal\n", "", 1)),
		"an escape":         write("esc.sh", strings.Replace(good, "provider: modal", "provider: mo\x1b[2Jdal", 1)),
		"excludes SEC-1":    write("sec1.sh", ownHeader("# exclusions: SEC-1\n")+ownBody),
		"name, no sp_whois": write("name.sh", strings.Replace(good, "addressed-by: id", "addressed-by: name", 1)),
	} {
		for _, mode := range []string{"text", "json"} {
			var out, errs bytes.Buffer
			code := run([]string{"plan", "-recipe", p, "-no-canary", "-o", mode}, &out, &errs)
			said := out.String() + errs.String()
			if code != exitUsage || strings.Contains(said, "MARKER-IN-THE-FILE") || strings.Contains(said, "\x1b") {
				t.Errorf("%s (%s): exit %d, %q", name, mode, code, said)
			}
			if mode == "json" && !strings.Contains(out.String(), `"error": "usage"`) {
				t.Errorf("%s: no usage error document: %s", name, out.String())
			}
		}
	}
	if c := calls(); c != "" {
		t.Errorf("a refused file's code ran:\n%s", c)
	}
	// Exactly 64 KiB is still a recipe.
	fill := 64<<10 - len(good) - len("# \n")
	var out, errs bytes.Buffer
	if code := run([]string{"plan", "-recipe", write("max.sh", good+"# "+strings.Repeat("x", fill)+"\n"), "-no-canary"}, &out, &errs); code != exitGraded {
		t.Errorf("a 64 KiB recipe: exit %d, %s", code, errs.String())
	}
}

// RCP-4 and UX-4: the plan names the file as given, the full SHA-256 of its bytes, that it's the person's own recipe
// nobody reviewed, the provider as the recipe's own word, that it's trusted host code, where the box will be made and
// the exclusions, in text and JSON; and an unapproved run exits 3 having created nothing (AGT-3).
func TestOwnRecipePlan(t *testing.T) {
	path, sum, calls := ownFile(t, ownHeader("# exclusions: SEC-4 EGR-3 AMP-6 AMP-7\n")+ownBody+"sp_recreate() { note recreate; }\n")
	t.Chdir(filepath.Dir(path))
	var out, errs bytes.Buffer
	if code := run([]string{"plan", "-recipe", "my-recipe.sh", "-no-canary", "-as", "agent"}, &out, &errs); code != exitGraded {
		t.Fatalf("plan: exit %d, %s", code, errs.String())
	}
	for _, want := range []string{"The plan for your own recipe", "the file my-recipe.sh, SHA-256 " + sum, "it is your own recipe, not one Sandprobe ships",
		"Sandprobe hasn't reviewed it", `it names its provider as "modal": that is the recipe's own word`, "Sandprobe hasn't reviewed that provider's terms",
		"it is trusted host code", "with your own credentials and permissions", "its sp_ready has already run", "where the box will be made: a test place",
		"SEC-4, EGR-3, AMP-6, AMP-7 are off", "its header can't turn on any of SEC-4, EGR-3, AMP-6, AMP-7", "through your recipe's sp_delete, which gets only the ID its create returned",
		"sandprobe-", "as agent, checked before any check runs", "you chose -no-canary", "recipe resets aren't built yet, so it's never called", "PER-5 is skipped (RCP-3)"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the plan doesn't say %q:\n%s", want, out.String())
		}
	}
	for _, never := range []string{"MARKER-IN-THE-FILE", "provider_terms", "reviewed scope", "not applicable"} {
		if strings.Contains(out.String(), never) {
			t.Errorf("the plan says %q:\n%s", never, out.String())
		}
	}
	out.Reset()
	if code := run([]string{"plan", "-recipe", "my-recipe.sh", "-no-canary", "-o", "json"}, &out, &errs); code != exitGraded {
		t.Fatalf("plan -o json: exit %d, %s", code, errs.String())
	}
	var p planDoc
	if err := json.Unmarshal(out.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	own := strings.Join(p.OwnRecipe, "\n")
	if p.Provider != "recipe" || p.RecipeFile != "my-recipe.sh" || p.RecipeSHA256 != sum || p.NeedsApproval || len(p.OwnRecipe) != 6 ||
		!strings.Contains(own, "your own recipe") || !strings.Contains(own, "hasn't reviewed") || !strings.Contains(own, "trusted host code") ||
		!strings.Contains(own, "a test place") || !strings.Contains(p.Creates[0], "a test place") || !strings.Contains(p.BoxNamed[0], "SEC-4, EGR-3, AMP-6, AMP-7 are off") ||
		!strings.Contains(p.Residual, sum) {
		t.Errorf("the plan document: %+v", p)
	}
	// A path that isn't plain is shown quoted, never raw.
	odd := filepath.Join(filepath.Dir(path), "my recipe\x1b.sh")
	os.Rename("my-recipe.sh", odd)
	out.Reset()
	if code := run([]string{"plan", "-recipe", odd, "-no-canary"}, &out, &errs); code != exitGraded || strings.Contains(out.String(), "\x1b") || !strings.Contains(out.String(), `my recipe\x1b.sh"`) {
		t.Errorf("an odd path: exit %d\n%s", code, out.String())
	}
	os.Rename(odd, "my-recipe.sh")

	// AGT-3: without -y nothing is created, in text and in JSON.
	out.Reset()
	errs.Reset()
	if code := run([]string{"run", "-recipe", "my-recipe.sh", "-no-canary"}, &out, &errs); code != exitApproval ||
		!strings.Contains(errs.String(), "nothing was created: only your recipe's sp_ready ran") || !strings.Contains(out.String(), sum) {
		t.Errorf("an unapproved run: exit %d, %s", code, errs.String())
	}
	out.Reset()
	if code := run([]string{"run", "-recipe", "my-recipe.sh", "-no-canary", "-o", "json"}, &out, &errs); code != exitApproval {
		t.Errorf("an unapproved run, -o json: exit %d", code)
	}
	p = planDoc{}
	if err := json.Unmarshal(out.Bytes(), &p); err != nil || !p.NeedsApproval || p.RecipeSHA256 != sum {
		t.Errorf("the unapproved plan: %v %+v", err, p)
	}
	if c := calls(); strings.Trim(c, "ready\n") != "" {
		t.Errorf("reached past sp_ready:\n%s", c)
	}
	if j, _ := filepath.Glob(filepath.Join(configDir(), "recipe-*.state")); len(j) != 0 {
		t.Errorf("an unapproved run left a record: %v", j)
	}
	// RCP-2: a name-addressed recipe of a person's own gets the same sp_whois guard, and the same race is reported.
	named, _, _ := ownFile(t, strings.Replace(ownHeader(""), "addressed-by: id", "addressed-by: name", 1)+ownBody+"sp_whois() { echo box-1; }\n")
	out.Reset()
	if code := run([]string{"plan", "-recipe", named, "-no-canary"}, &out, &errs); code != exitGraded ||
		!strings.Contains(out.String(), "sp_whois must name the box the create returned") || !strings.Contains(out.String(), "can't be ruled out (RCP-2)") {
		t.Errorf("a name-addressed recipe: exit %d\n%s", code, out.String())
	}
	// sp_ready failing is a login error that carries only what the recipe said on fd 3, never its stderr.
	bad, _, _ := ownFile(t, ownHeader("# env: SANDPROBE_MY_TEMPLATE\n")+strings.Replace(ownBody, `sp_ready() { note ready; echo "a test place"; }`,
		`sp_ready() { echo "token=hunter2" >&2; echo "no template named" >&3; return 1; }`, 1))
	out.Reset()
	errs.Reset()
	if code := run([]string{"plan", "-recipe", bad, "-no-canary"}, &out, &errs); code != exitLogin || !strings.Contains(errs.String(), "your own recipe isn't ready") ||
		!strings.Contains(errs.String(), "no template named") || !strings.Contains(errs.String(), "SANDPROBE_MY_TEMPLATE") || strings.Contains(errs.String(), "hunter2") {
		t.Errorf("sp_ready failing: exit %d, %s", code, errs.String())
	}
}

// RCP-4: an own recipe can't widen what runs. Whatever its header lists, all four provider-endpoint checks are off,
// and only -provider-endpoints turns one on, by name.
func TestOwnRecipeExclusions(t *testing.T) {
	for name, line := range map[string]string{"one": "# exclusions: SEC-4\n", "none": "", "three": "# exclusions: SEC-4 EGR-3 AMP-6\n"} {
		path, _, _ := ownFile(t, ownHeader(line)+ownBody)
		rc, err := ownRecipe(path)
		if err != nil || !slices.Equal(rc.Exclusions, host.RecipeDefaultExclusions) {
			t.Fatalf("%s: %v %v", name, rc, err)
		}
		for id, why := range recipeExclusions(rc) {
			if strings.Contains(why, "MARKER-IN-THE-FILE") || !strings.Contains(why, "hasn't reviewed") {
				t.Errorf("%s: %s's reason is %q", name, id, why)
			}
		}
		var out, errs bytes.Buffer
		if code := run([]string{"plan", "-recipe", path, "-no-canary", "-o", "json"}, &out, &errs); code != exitGraded {
			t.Fatalf("%s: exit %d, %s", name, code, errs.String())
		}
		var p planDoc
		if err := json.Unmarshal(out.Bytes(), &p); err != nil || len(p.Attested) != 0 || !strings.Contains(p.BoxNamed[0], "SEC-4, EGR-3, AMP-6, AMP-7 are off") ||
			!strings.Contains(p.Residual, "(SEC-4, EGR-3, AMP-6, AMP-7) were off") {
			t.Errorf("%s: %v %+v", name, err, p)
		}
		// AMP-7 isn't in any of these headers, yet it is off, so it is there to turn on; nothing else comes with it.
		out.Reset()
		if code := run([]string{"plan", "-recipe", path, "-no-canary", "-provider-endpoints", "AMP-7", "-o", "json"}, &out, &errs); code != exitGraded {
			t.Fatalf("%s, attesting AMP-7: exit %d, %s", name, code, errs.String())
		}
		p = planDoc{}
		if err := json.Unmarshal(out.Bytes(), &p); err != nil || len(p.Attested) != 1 || !strings.HasPrefix(p.Attested[0], "AMP-7 ") ||
			!strings.Contains(strings.Join(p.BoxNamed, "\n"), "nothing else: AMP-6, EGR-3, SEC-4 stay off") {
			t.Errorf("%s, attesting AMP-7: %v %+v", name, err, p)
		}
	}
}

// RCP-2 at the command line, for an own recipe: a create that returns no ID exits 7 naming the box, deletes nothing
// and keeps its record, named from the SHA-256 and never the path, mode 600; a box whose sp_gone never says 0 exits 7
// naming its ID with the record kept; one it confirms gone exits 5 with the record removed.
func TestOwnRecipeCleanupExits(t *testing.T) {
	defer func(d, g, p time.Duration) { recipeDeleteLimit, host.RecipeGoneLimit, host.RecipeGonePoll = d, g, p }(recipeDeleteLimit, host.RecipeGoneLimit, host.RecipeGonePoll)
	recipeDeleteLimit, host.RecipeGoneLimit, host.RecipeGonePoll = 2*time.Second, 200*time.Millisecond, 50*time.Millisecond
	records := func(sum string) []string {
		j, _ := filepath.Glob(filepath.Join(configDir(), "recipe-own-"+sum[:12]+"-sandprobe-*.state"))
		all, _ := filepath.Glob(filepath.Join(configDir(), "*.state"))
		if len(all) != len(j) {
			t.Errorf("records under another name: %v", all)
		}
		return j
	}
	for name, create := range map[string]string{
		"two lines": `sp_create() { note create; echo box-1; echo box-2; }`,
		"bad chars": `sp_create() { note create; echo 'box 1; rm -rf /'; }`,
		"nothing":   `sp_create() { note create; }`,
		"failed":    `sp_create() { note create; echo "password=hunter2" >&2; echo "the template is gone" >&3; exit 1; }`,
	} {
		path, sum, calls := ownFile(t, ownHeader("")+strings.Replace(ownBody, `sp_create() { note create; echo box-1; }`, create, 1))
		var out, errs bytes.Buffer
		if code := run([]string{"run", "-recipe", path, "-no-canary", "-y"}, &out, &errs); code != exitCleanup {
			t.Fatalf("%s: exit %d, %s", name, code, errs.String())
		}
		if c := calls(); strings.Contains(c, "delete") || strings.Contains(c, "gone") || strings.Contains(c, "shell") {
			t.Errorf("%s: acted on a box with no ID:\n%s", name, c)
		}
		j := records(sum)
		if len(j) != 1 || !strings.Contains(errs.String(), j[0]) || !strings.Contains(errs.String(), "sandprobe-") || strings.Contains(errs.String(), "hunter2") ||
			strings.Contains(filepath.Base(j[0]), "my-recipe") {
			t.Fatalf("%s: the box isn't recorded and named: %v\n%s", name, j, errs.String())
		}
		if name == "failed" && !strings.Contains(errs.String(), "the template is gone") {
			t.Errorf("%s: the recipe's own message isn't shown: %s", name, errs.String())
		}
		st, _ := os.Stat(j[0])
		dir, _ := os.Stat(configDir())
		b, _ := os.ReadFile(j[0])
		abs, _ := filepath.Abs(path)
		var rec recipeJournal
		if err := json.Unmarshal(b, &rec); err != nil || st.Mode().Perm() != 0o600 || dir.Mode().Perm() != 0o700 || rec.Recipe != "own-"+sum[:12] ||
			rec.SHA256 != sum || rec.File != abs || rec.Target != "a test place" || rec.ID != "" || !strings.HasPrefix(rec.Name, "sandprobe-") {
			t.Errorf("%s: the record: mode %v, dir %v, %s (%v)", name, st.Mode(), dir.Mode(), b, err)
		}
	}

	// An ID, then nothing runs in the box (sp_shell fails), and sp_gone keeps saying it exists.
	path, sum, calls := ownFile(t, ownHeader("")+strings.Replace(ownBody, "sp_gone() { note gone; }", "sp_gone() { note gone; return 1; }", 1))
	var out, errs bytes.Buffer
	if code := run([]string{"run", "-recipe", path, "-no-canary", "-y"}, &out, &errs); code != exitCleanup ||
		!strings.Contains(errs.String(), "box-1 isn't confirmed deleted") || !strings.Contains(errs.String(), "NOT confirmed deleted") {
		t.Fatalf("not gone: exit %d, %s", code, errs.String())
	}
	if c := calls(); !strings.Contains(c, "delete") || !strings.Contains(c, "gone") {
		t.Errorf("the delete was never asked:\n%s", c)
	}
	j := records(sum)
	if len(j) != 1 || !strings.Contains(errs.String(), j[0]) {
		t.Fatalf("the record: %v\n%s", j, errs.String())
	}
	if b, _ := os.ReadFile(j[0]); !strings.Contains(string(b), `"id": "box-1"`) {
		t.Errorf("the record lacks the ID: %s", b)
	}
	// sp_gone can't tell (2): still not gone.
	path, sum, _ = ownFile(t, ownHeader("")+strings.Replace(ownBody, "sp_gone() { note gone; }", "sp_gone() { return 2; }", 1))
	errs.Reset()
	if code := run([]string{"run", "-recipe", path, "-no-canary", "-y"}, &out, &errs); code != exitCleanup || len(records(sum)) != 1 {
		t.Fatalf("can't tell: exit %d, %s", code, errs.String())
	}
	// Confirmed gone: the failure itself decides the exit, and the record goes.
	path, sum, calls = ownFile(t, ownHeader("")+ownBody)
	errs.Reset()
	if code := run([]string{"run", "-recipe", path, "-no-canary", "-y"}, &out, &errs); code != exitPartial || !strings.Contains(errs.String(), "confirmed gone") {
		t.Fatalf("gone: exit %d, %s", code, errs.String())
	}
	if c := calls(); !strings.Contains(c, "create") || !strings.Contains(c, "delete") || len(records(sum)) != 0 {
		t.Errorf("gone: calls\n%s\nrecords %v", c, records(sum))
	}
}

// The worked example is a sound recipe of a person's own, and isn't shipped: it gets no PRV row (RCP-4).
func TestExampleRecipe(t *testing.T) {
	rc, err := ownRecipe("../../examples/recipes/docker-template.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !rc.Own || rc.AddressedBy != "id" || rc.Reset || !slices.Equal(rc.Env, []string{"SANDPROBE_TEMPLATE", "SANDPROBE_AGENT_USER"}) {
		t.Errorf("the example: %+v", rc)
	}
	if _, ok := recipes.Get("docker-template"); ok || recipes.Shipped["docker-template"] != "" {
		t.Error("the example is shipped")
	}
}

// RCP-4 end to end (SANDPROBE_FIXTURES=1): the example recipe starts a container from a local image, the probe runs in
// it as nobody through docker exec, and the container is deleted by the ID its create returned. Without a canary the
// run is incomplete (exit 5). The saved report loads under ANL-1 and records the recipe's SHA-256.
func TestOwnRecipeDocker(t *testing.T) {
	if os.Getenv("SANDPROBE_FIXTURES") == "" {
		t.Skip("set SANDPROBE_FIXTURES=1 to run against Docker")
	}
	const image = "debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2"
	if exec.Command("docker", "image", "inspect", image).Run() != nil { // the recipe never pulls
		if b, err := exec.Command("docker", "pull", image).CombinedOutput(); err != nil {
			t.Fatalf("pulling the test image: %v %s", err, b)
		}
	}
	if os.Getenv("DOCKER_CONFIG") == "" { // docker keeps its own settings, while HOME moves for the run's records
		home, _ := os.UserHomeDir()
		t.Setenv("DOCKER_CONFIG", filepath.Join(home, ".docker"))
	}
	isolateCanary(t)
	t.Setenv("SANDPROBE_TEMPLATE", image)
	t.Setenv("SANDPROBE_AGENT_USER", "nobody")
	recipe, _ := filepath.Abs("../../examples/recipes/docker-template.sh")
	text, err := os.ReadFile(recipe)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(text)
	sha := hex.EncodeToString(sum[:])
	gone := func(id string) {
		t.Helper()
		left, err := exec.Command("docker", "ps", "-a", "--no-trunc", "--filter", "id="+id, "--format", "{{.ID}}").Output()
		if err != nil || len(bytes.TrimSpace(left)) != 0 {
			t.Errorf("the container is still there: %s %v", left, err)
		}
		if j, _ := filepath.Glob(filepath.Join(configDir(), "*.state")); len(j) != 0 {
			t.Errorf("records left: %v", j)
		}
	}
	t.Cleanup(func() { // a run that died leaves its container named in its record: remove exactly that one
		j, _ := filepath.Glob(filepath.Join(configDir(), "recipe-own-*.state"))
		for _, f := range j {
			var rec recipeJournal
			if b, _ := os.ReadFile(f); json.Unmarshal(b, &rec) == nil && rec.ID != "" {
				exec.Command("docker", "rm", "-f", rec.ID).Run()
			}
		}
	})
	dir := t.TempDir()
	var out, errs bytes.Buffer
	code := run([]string{"run", "-recipe", recipe, "-as", "nobody", "-no-canary", "-y", "-o", "json", "-out", dir}, &out, &errs)
	if code != exitPartial { // HCN-5: without a canary the run is incomplete
		t.Fatalf("exit %d: %s", code, errs.String())
	}
	files, _ := filepath.Glob(filepath.Join(dir, "sandprobe-recipe-*.json"))
	if len(files) != 1 {
		t.Fatalf("reports: %v", files)
	}
	d, err := analysis.Load(files[0])
	if err != nil {
		t.Fatalf("the saved report doesn't load: %v", err)
	}
	if !d.Grade.Valid || d.Run.Provider != "recipe" || d.Run.Mode != "exec" || !d.Run.Box.CreatedBySandprobe || d.Schema != report.SchemaSkipKinds ||
		len(d.Manifest.SkipKinds) != 4 || len(d.Manifest.Attested) != 0 || d.Manifest.DeclaredProvider != "" {
		t.Errorf("run %+v, schema %s, valid %v (%s), kinds %v", d.Run, d.Schema, d.Grade.Valid, d.Grade.Invalid, d.Manifest.SkipKinds)
	}
	for _, id := range host.RecipeDefaultExclusions {
		if d.Manifest.SkipKinds[id] != obs.SkipOptIn || !strings.Contains(d.Manifest.Skipped[id], "your own recipe") {
			t.Errorf("%s: kind %q, %q", id, d.Manifest.SkipKinds[id], d.Manifest.Skipped[id])
		}
	}
	if len(d.ProviderCalls) != 3 {
		t.Fatalf("provider calls: %+v", d.ProviderCalls)
	}
	for i, fn := range []string{"sp_create", "sp_delete", "sp_gone"} {
		if c := d.ProviderCalls[i]; c.Call != "own recipe sha256:"+sha+" "+fn || !c.OK || c.Exit != 0 || c.ID != d.Run.Box.ProviderID || len(c.ID) != 64 {
			t.Errorf("%s: %+v", fn, c)
		}
	}
	if !strings.Contains(d.Cleanup.Outcome, "confirmed gone") || !strings.Contains(d.Cleanup.Residual, sha) || !strings.Contains(d.Cleanup.Residual, "hasn't reviewed") {
		t.Errorf("cleanup: %+v", d.Cleanup)
	}
	if raw, _ := os.ReadFile(files[0]); bytes.Contains(raw, []byte("docker-template")) || bytes.Contains(raw, []byte(filepath.Dir(recipe))) {
		t.Error("the report holds the recipe's path")
	}
	if id := d.Identity; id == nil || id.UID != 65534 {
		t.Errorf("the probe ran as %+v, not nobody", id)
	}
	gone(d.Run.Box.ProviderID)
	c := report.Score(*d)
	t.Logf("score %d/%d, exit %d, %s", c.Score, c.Of, code, d.Cleanup.Outcome)
	if r := c.Rows[4]; r.Name != "Cloud access" || r.NotApplicable || !strings.HasPrefix(r.Why, "Not tested") {
		t.Errorf("Cloud access: %+v", r)
	}

	// PRV-15 through an own recipe: the box runs the probe as nobody, so -as root stops before any check, and the
	// container is still deleted by its ID.
	errs.Reset()
	if code := run([]string{"run", "-recipe", recipe, "-as", "root", "-no-canary", "-y", "-out", t.TempDir()}, &out, &errs); code != exitPartial || !strings.Contains(errs.String(), "confirmed gone") {
		t.Fatalf("-as root on a box that runs as nobody: exit %d, %s", code, errs.String())
	}
	if j, _ := filepath.Glob(filepath.Join(configDir(), "*.state")); len(j) != 0 {
		t.Errorf("records left: %v", j)
	}
	// A template that isn't a local image stops at sp_ready, before any plan: nothing is pulled or created.
	t.Setenv("SANDPROBE_TEMPLATE", "sandprobe-no-such-template:none")
	errs.Reset()
	if code := run([]string{"plan", "-recipe", recipe, "-no-canary"}, &out, &errs); code != exitLogin || !strings.Contains(errs.String(), "this recipe never pulls") {
		t.Fatalf("no such template: exit %d, %s", code, errs.String())
	}
}
