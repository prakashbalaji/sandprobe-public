package host

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"

	"sandprobe/internal/obs"
)

// Recipe is a recipe file (RCP-1): a POSIX sh file with a header and the sp_ functions, held as the bytes read once,
// so the file can't change between the plan and the calls.
type Recipe struct {
	Name, Provider, Docs, Terms, AddressedBy string
	Exclusions                               []string // check IDs, each one PRV-15's provider endpoints may name
	Env                                      []string // the settings it reads from the person's environment
	Text                                     []byte
	SHA256                                   string
	// Reset says the recipe defines sp_checkpoint, sp_restore or sp_recreate. Resets aren't built, so none is ever
	// called, and the plan and report say so (RCP-3).
	Reset bool
	// Waits says a shipped recipe defines sp_wait, called once the create's ID is on disk (RCP-1, RCP-2). A person's own
	// recipe has no such call: its sp_create returns only when the box is ready for a shell.
	Waits bool
	// Own marks a person's own recipe file (run -recipe, RCP-4): nobody reviewed it, so it always carries all four
	// default exclusions, and its header is only its own word. File is its path as given, for the plan and the record
	// alone: never a report, and never the record's name.
	Own  bool
	File string
}

// OwnRecipeProvider is what a report's run.provider reads for a person's own recipe (RCP-4): the way the box was
// reached, as "exec" is, never a provider's name.
const OwnRecipeProvider = "recipe"

// RecipeDefaultExclusions are PRV-15's four, which a person's own recipe always carries (RCP-4).
var RecipeDefaultExclusions = []string{"SEC-4", "EGR-3", "AMP-6", "AMP-7"}

var (
	recipeKey  = regexp.MustCompile(`^# ([a-z-]+): (.+)$`)
	recipeEnv  = regexp.MustCompile(`^SANDPROBE_[A-Z0-9_]{1,40}$`)
	recipeID   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`) // RCP-2
	recipeLine = regexp.MustCompile(`^[\x20-\x7e]{1,400}$`)
	// RecipeCallLimit bounds one function call; sp_create waits for the box to be ready inside it.
	RecipeCallLimit = 5 * time.Minute
	// RecipeWaitLimit bounds sp_wait whatever its commands do: kubectl has no request timeout of its own.
	RecipeWaitLimit = 90 * time.Second
	// RecipeGoneLimit bounds the wait for sp_gone's 0 after the delete, asked every RecipeGonePoll; tests shorten both.
	RecipeGoneLimit = 2 * time.Minute
	RecipeGonePoll  = 2 * time.Second
)

// recipeSaysMax bounds what the host keeps of a recipe's fd 3, and recipeSaysLinger how long a child left holding fd 3
// can delay a call after the recipe exits (RCP-1).
var (
	recipeSaysMax    = 4 << 10
	recipeSaysLinger = time.Second
)

// RecipeMax bounds a recipe's bytes (RCP-1).
const RecipeMax = 64 << 10

// ParseOwnRecipe checks a person's own recipe as ParseRecipe checks a shipped one, then gives it what nobody's review
// could change (RCP-4): a name from its SHA-256, never from its path, and all four default exclusions, whatever its
// header lists.
func ParseOwnRecipe(text []byte) (*Recipe, error) {
	r, err := ParseRecipe("", text)
	if err != nil {
		return nil, err
	}
	r.Name, r.Own, r.Waits, r.Exclusions = "own-"+r.SHA256[:12], true, false, slices.Clone(RecipeDefaultExclusions)
	return r, nil
}

// Label is how a message names the recipe.
func (r *Recipe) Label() string {
	if r.Own {
		return "your own recipe"
	}
	return "the " + r.Name + " recipe"
}

// RunProvider is the report's run.provider for a run of this recipe.
func (r *Recipe) RunProvider() string {
	if r.Own {
		return OwnRecipeProvider
	}
	return r.Name
}

// ParseRecipe checks a recipe's header and functions (RCP-1). Its errors echo nothing from the recipe but a header
// key's own name, lowercase letters and hyphens, cut to 32 characters: a person's own file reaches it too (RCP-4).
func ParseRecipe(name string, text []byte) (*Recipe, error) {
	if len(text) > RecipeMax {
		return nil, fmt.Errorf("the recipe is over %d KiB", RecipeMax>>10)
	}
	lines := strings.Split(string(text), "\n")
	if lines[0] != "# sandprobe-recipe: v1" {
		return nil, errors.New("the recipe's first line isn't # sandprobe-recipe: v1")
	}
	sum := sha256.Sum256(text)
	r := &Recipe{Name: name, Text: text, SHA256: hex.EncodeToString(sum[:])}
	seen := map[string]bool{}
	for _, l := range lines[1:] {
		m := recipeKey.FindStringSubmatch(l)
		if m == nil {
			break
		}
		if seen[m[1]] {
			return nil, fmt.Errorf("the recipe's header names %.32s twice", m[1])
		}
		seen[m[1]] = true
		if !recipeLine.MatchString(m[2]) { // RCP-1: plans and reports show a header's values
			return nil, fmt.Errorf("the recipe's header value for %.32s isn't printable ASCII of at most 400 characters (RCP-1)", m[1])
		}
		switch v := m[2]; m[1] {
		case "provider":
			r.Provider = v
		case "docs":
			r.Docs = v
		case "terms":
			r.Terms = v
		case "addressed-by":
			r.AddressedBy = v
		case "exclusions":
			r.Exclusions = strings.Fields(v)
		case "env":
			r.Env = strings.Fields(v)
		default:
			return nil, fmt.Errorf("the recipe's header has an unknown key %.32s", m[1])
		}
	}
	switch {
	case r.Provider == "" || r.Terms == "":
		return nil, errors.New("the recipe's header needs provider and terms (RCP-1)")
	case r.AddressedBy != "id" && r.AddressedBy != "name":
		return nil, errors.New("the recipe's header needs addressed-by: id or name (RCP-1)")
	}
	for _, id := range r.Exclusions {
		if !excludable[id] {
			return nil, errors.New("the recipe's exclusions name something other than SEC-4, EGR-3, AMP-6 and AMP-7, the checks a provider's endpoints may exclude (GRD-3)")
		}
	}
	for _, e := range r.Env {
		if !recipeEnv.MatchString(e) || e == "SANDPROBE_BOX" || e == "SANDPROBE_NAME" || e == "SANDPROBE_TARGET" {
			return nil, errors.New("the recipe's env names something that isn't a SANDPROBE_ setting of its own")
		}
	}
	need := []string{"sp_ready", "sp_create", "sp_shell", "sp_delete", "sp_gone"}
	if r.AddressedBy == "name" {
		need = append(need, "sp_whois")
	}
	for _, fn := range need {
		if !regexp.MustCompile(`(?m)^` + fn + `\(\) *\{`).Match(text) {
			return nil, fmt.Errorf("the recipe has no %s() (RCP-1)", fn)
		}
	}
	r.Waits = regexp.MustCompile(`(?m)^sp_wait\(\) *\{`).Match(text)
	r.Reset = regexp.MustCompile(`(?m)^sp_(checkpoint|restore|recreate)\(\) *\{`).Match(text)
	return r, nil
}

// call runs one function: sh over the recipe's bytes, then the function's name, with stdin from /dev/null and only
// the host's values for SANDPROBE_BOX, SANDPROBE_NAME and SANDPROBE_TARGET (RCP-1, RCP-2). It returns stdout, and an
// error carrying the exit code and what the recipe said on fd 3. Its stderr goes to /dev/null: kubectl and an exec
// plugin write there, and it can carry a credential (AGENTS rule 3). A recipe runs its child commands with fd 3
// closed, so none of them can write a message as the recipe.
//
// fd 3 is a pipe the host drains while the recipe runs, keeping the first recipeSaysMax bytes and discarding the
// rest: the text has no file and no name, and a recipe that floods it grows nothing (RCP-1).
func (r *Recipe) call(ctx context.Context, fn string, env []string) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(ctx, RecipeCallLimit)
	defer cancel()
	return r.callIn(ctx, fn, env, false)
}

// callIn is call under ctx alone. With group, the recipe runs in its own process group and the end of ctx kills all
// of it: killing only the sh would leave a command below it, a stalled kubectl say, running into the cleanup.
func (r *Recipe) callIn(ctx context.Context, fn string, env []string, group bool) ([]byte, int, error) {
	listen, speak, err := os.Pipe()
	if err != nil {
		return nil, -1, fmt.Errorf("%s didn't run: no pipe for its messages: %w", fn, err)
	}
	says, drained := &capped{max: recipeSaysMax}, make(chan struct{})
	go func() {
		io.Copy(says, listen)
		close(drained)
	}()
	cmd := exec.CommandContext(ctx, "sh", "-c", string(r.Text)+"\n"+fn)
	cmd.Env, cmd.WaitDelay = recipeEnviron(env), 5*time.Second
	out := &capped{max: 64 << 10}
	cmd.Stdout, cmd.ExtraFiles = out, []*os.File{speak} // fd 3
	if group {
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	}
	err = cmd.Run()
	// The recipe has exited. Once the host's own end is closed the drain ends, unless a child the recipe left behind
	// still holds fd 3: that gets a moment and no more, and closing the reading end stops the drain either way.
	speak.Close()
	select {
	case <-drained:
	case <-time.After(recipeSaysLinger):
	}
	listen.Close()
	<-drained
	if err == nil {
		return out.Bytes(), 0, nil
	}
	code := -1
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	}
	msg := printable(says.Bytes())
	if msg == "" {
		msg = "no message of its own (its other output isn't shown, since it can carry a credential)"
	}
	return out.Bytes(), code, fmt.Errorf("%s exited %d: %s", fn, code, msg)
}

// recipeEnviron is this process's environment without any SANDPROBE_BOX, SANDPROBE_NAME or SANDPROBE_TARGET, then
// the host's own.
func recipeEnviron(env []string) []string {
	var out []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if k != "SANDPROBE_BOX" && k != "SANDPROBE_NAME" && k != "SANDPROBE_TARGET" {
			out = append(out, kv)
		}
	}
	return append(out, env...)
}

// printable keeps the last line or so of what a recipe wrote to fd 3, as printable ASCII only, for an error message
// or a report (RCP-1): a newline or tab becomes a space and every other byte is dropped. So no control character, C1
// control such as U+009B, Unicode format character such as U+202E, or invalid UTF-8 reaches a terminal or a report.
func printable(b []byte) string {
	var keep strings.Builder
	for _, c := range b {
		switch {
		case c == '\n' || c == '\t':
			keep.WriteByte(' ')
		case c >= 0x20 && c <= 0x7e:
			keep.WriteByte(c)
		}
	}
	s := strings.TrimSpace(keep.String())
	if len(s) > 300 {
		s = "…" + s[len(s)-300:]
	}
	return s
}

// Ready runs sp_ready: the recipe's settings are sound, and the one line it prints names where boxes will be made
// (RCP-1). The plan shows it, and every later call gets it back as SANDPROBE_TARGET.
func (r *Recipe) Ready(ctx context.Context) (string, error) {
	out, _, err := r.call(ctx, "sp_ready", nil)
	if err != nil {
		return "", err
	}
	t := strings.TrimSuffix(string(out), "\n")
	if !recipeLine.MatchString(t) {
		return "", errors.New("sp_ready didn't print one line naming where boxes are made")
	}
	return t, nil
}

// RecipeBox is the box a recipe creates, reaches with sp_shell, and deletes by the ID its create returned (RCP-2).
type RecipeBox struct {
	*ExecBox
	Recipe *Recipe
	Name   string // sandprobe-<12 hex>, made before the create and reported if the create returns no ID
	BoxID  string // sp_create's whole stdout, once it matched RCP-2's form
	Target string // sp_ready's line
	Calls  []obs.ProviderCall
}

// record lists one call for the report (PRV-3, RCP-2): the recipe by its SHA-256, the function, how it exited and the
// create-returned ID. Nothing the recipe printed is kept.
func (b *RecipeBox) record(at time.Time, fn string, code int, err error) {
	who := b.Recipe.Name
	if b.Recipe.Own {
		who = "own"
	}
	c := obs.ProviderCall{At: at.UTC(), Call: who + " recipe sha256:" + b.Recipe.SHA256 + " " + fn, OK: err == nil, Exit: code}
	if b.BoxID != "" {
		c.ID = b.ID()
	}
	if err != nil {
		c.Error = "the recipe's function failed"
	}
	b.Calls = append(b.Calls, c)
}

// NewRecipeBox fixes the name and the scratch path before anything is created.
func NewRecipeBox(r *Recipe, target, scratch string) (*RecipeBox, error) {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, errors.New("no randomness for the box's name")
	}
	rb := &RecipeBox{Recipe: r, Name: "sandprobe-" + hex.EncodeToString(b[:]), Target: target}
	eb, err := NewExecBox([]string{"sh", "-c", string(r.Text) + "\nsp_shell"}, nil, scratch)
	if err != nil {
		return nil, err
	}
	eb.Env = recipeEnviron(rb.env())
	if r.AddressedBy == "name" {
		eb.Guard = rb.whois // RCP-2: before every invocation, the name must still be the box the create returned
	}
	rb.ExecBox = eb
	return rb, nil
}

func (b *RecipeBox) env() []string {
	env := []string{"SANDPROBE_NAME=" + b.Name, "SANDPROBE_TARGET=" + b.Target}
	if b.BoxID != "" {
		env = append(env, "SANDPROBE_BOX="+b.BoxID)
	}
	return env
}

// ID is the create-returned ID (PRV-1), with the name for a name-addressed box.
func (b *RecipeBox) ID() string {
	if b.Recipe.AddressedBy == "name" {
		return b.Name + " (" + b.BoxID + ")"
	}
	return b.BoxID
}

// Create runs sp_create. Its whole stdout must be one ID line (RCP-2). An ID with a failed create is kept, so the
// box it names is still deleted; no ID leaves only the name, reported and never deleted.
func (b *RecipeBox) Create(ctx context.Context) error {
	at := time.Now()
	out, code, err := b.Recipe.call(ctx, "sp_create", b.env())
	id := strings.TrimSuffix(string(out), "\n")
	if !recipeID.MatchString(id) {
		why := "its output isn't one ID line"
		if err != nil {
			why = err.Error()
		}
		err = fmt.Errorf("the create returned no ID (%s); a box named %s may exist and wasn't deleted (RCP-2)", why, b.Name)
		b.record(at, "sp_create", code, err)
		return err
	}
	b.BoxID = id
	b.ExecBox.Env = recipeEnviron(b.env())
	b.record(at, "sp_create", code, err)
	return err
}

// Wait runs a shipped recipe's sp_wait, if it defines one: the box takes sp_shell, or the recipe says why not. It may
// run a command in the box, so the caller records the ID first (RCP-2). RecipeWaitLimit or a cancel kills it and
// everything it started, so no cluster client is left running when the cleanup begins.
func (b *RecipeBox) Wait(ctx context.Context) error {
	if !b.Recipe.Waits {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, RecipeWaitLimit)
	defer cancel()
	_, _, err := b.Recipe.callIn(ctx, "sp_wait", b.env(), true)
	if err != nil && ctx.Err() != nil {
		return fmt.Errorf("sp_wait was stopped before the box took a shell (%w); its limit is %s", ctx.Err(), RecipeWaitLimit)
	}
	return err
}

// whois runs sp_whois and refuses unless the name still holds the box the create returned (RCP-2).
func (b *RecipeBox) whois(ctx context.Context) error {
	out, _, err := b.Recipe.call(ctx, "sp_whois", b.env())
	if err != nil {
		return err
	}
	if got := strings.TrimSuffix(string(out), "\n"); got != b.BoxID {
		return fmt.Errorf("%s no longer names the box the create returned (%s), so nothing more is sent to it", b.Name, b.BoxID)
	}
	return nil
}

// Delete runs sp_delete by the create-returned ID, then waits for sp_gone's 0: the provider's positive answer that
// it's gone (RCP-2). Anything else is not gone, and the error names the ID.
func (b *RecipeBox) Delete(ctx context.Context) error {
	if b.BoxID == "" {
		return fmt.Errorf("nothing to delete by ID: the create returned none, and %s is never deleted by name", b.Name)
	}
	deleteErr := errors.New("not asked")
	if b.Recipe.AddressedBy != "name" || b.whois(ctx) == nil { // a name that holds another box isn't deleted
		at := time.Now()
		var code int
		_, code, deleteErr = b.Recipe.call(ctx, "sp_delete", b.env())
		b.record(at, "sp_delete", code, deleteErr)
	}
	deadline := time.Now().Add(RecipeGoneLimit)
	last := "never answered"
	for {
		at := time.Now()
		_, code, err := b.Recipe.call(ctx, "sp_gone", b.env())
		over := time.Now().After(deadline) || ctx.Err() != nil
		if err == nil || over {
			b.record(at, "sp_gone", code, err) // the last answer only
		}
		switch {
		case err == nil:
			return nil
		case code == 1:
			last = "it still exists"
		default:
			last = "the provider couldn't say: " + err.Error()
		}
		if over {
			return fmt.Errorf("%s isn't confirmed deleted (%s; the delete: %v)", b.ID(), last, deleteErr)
		}
		select {
		case <-ctx.Done():
		case <-time.After(RecipeGonePoll):
		}
	}
}

// RecipeResidual is what a recipe run's report says it can't vouch for (PRV-1, RCP-2, RCP-3, RCP-4).
func RecipeResidual(r *Recipe, target string, attested []string) string {
	s := "This box was made for this run through the " + r.Name + " recipe in " + target + ", reached through its " +
		"sp_shell, and deleted only by the ID its create returned."
	if r.Own { // RCP-4: nobody reviewed it, and what its functions did with the ID is its own code
		s = "This box was made for this run through your own recipe (SHA-256 " + r.SHA256 + "), which names its provider as \"" +
			r.Provider + "\": that is the recipe's own word, and Sandprobe hasn't reviewed the recipe or that provider's " +
			"terms (RCP-4). It was made in " + target + ", reached through the recipe's sp_shell, and deleted through its " +
			"sp_delete, which was given the ID its create returned, with the name and the target, and is required to act " +
			"only on that ID: Sandprobe can't enforce what the recipe does with them, and that the box is gone is the " +
			"recipe's sp_gone saying so."
	}
	s += " The recipe ran on this machine with your own credentials and permissions. Persistence across a reset (PER-5) isn't tested: "
	if r.Reset {
		s += "the recipe defines a reset, but recipe resets aren't built yet, so it was never called (RCP-3)."
	} else {
		s += "the recipe has no reset (RCP-3)."
	}
	var off []string
	for _, id := range r.Exclusions {
		if !slices.Contains(attested, id) {
			off = append(off, id)
		}
	}
	if len(off) > 0 {
		s += " The checks that would contact your provider's own endpoints (" + strings.Join(off, ", ") + ") were off (RCP-4)."
	}
	if len(attested) > 0 {
		s += " You turned on " + strings.Join(attested, ", ") + " with -provider-endpoints, attesting that your provider's terms allow them on your own account (PRV-15)."
	}
	if r.AddressedBy == "name" {
		s += " The box is reached by its name: sp_whois confirmed the name still held it before each call, but a box " +
			"replaced between that check and the call can't be ruled out (RCP-2)."
	}
	return s
}
