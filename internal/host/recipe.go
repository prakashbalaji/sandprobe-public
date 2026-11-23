package host

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Recipe is a recipe file (RCP-1): a POSIX sh file with a header and the sp_ functions, held as the bytes read once,
// so the file can't change between the plan and the calls.
type Recipe struct {
	Name, Provider, Docs, Terms, AddressedBy string
	Exclusions                               []string // check IDs, each one PRV-15's provider endpoints may name
	Env                                      []string // the settings it reads from the person's environment
	Text                                     []byte
	SHA256                                   string
}

var (
	recipeKey  = regexp.MustCompile(`^# ([a-z-]+): (.+)$`)
	recipeEnv  = regexp.MustCompile(`^SANDPROBE_[A-Z0-9_]{1,40}$`)
	recipeID   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`) // RCP-2
	recipeLine = regexp.MustCompile(`^[\x20-\x7e]{1,400}$`)
	// RecipeCallLimit bounds one function call; sp_create waits for the box to be ready inside it.
	RecipeCallLimit = 5 * time.Minute
	// RecipeGoneLimit bounds the wait for sp_gone's 0 after the delete, asked every RecipeGonePoll; tests shorten both.
	RecipeGoneLimit = 2 * time.Minute
	RecipeGonePoll  = 2 * time.Second
)

const recipeMax = 64 << 10

// ParseRecipe checks a recipe's header and functions (RCP-1).
func ParseRecipe(name string, text []byte) (*Recipe, error) {
	if len(text) > recipeMax {
		return nil, fmt.Errorf("the recipe is over %d KiB", recipeMax>>10)
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
			return nil, fmt.Errorf("the recipe's header names %s twice", m[1])
		}
		seen[m[1]] = true
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
			return nil, fmt.Errorf("the recipe's header has an unknown key %s", m[1])
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
			return nil, fmt.Errorf("the recipe excludes %s, which only a provider's endpoints may exclude (GRD-3)", id)
		}
	}
	for _, e := range r.Env {
		if !recipeEnv.MatchString(e) || e == "SANDPROBE_BOX" || e == "SANDPROBE_NAME" || e == "SANDPROBE_TARGET" {
			return nil, fmt.Errorf("the recipe's env names %q, not a SANDPROBE_ setting of its own", e)
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
	return r, nil
}

// call runs one function: sh over the recipe's bytes, then the function's name, with stdin from /dev/null and only
// the host's values for SANDPROBE_BOX, SANDPROBE_NAME and SANDPROBE_TARGET (RCP-1, RCP-2). It returns stdout, and an
// error carrying the exit code and what the recipe said on fd 3. Its stderr goes to /dev/null: kubectl and an exec
// plugin write there, and it can carry a credential (AGENTS rule 3). A recipe runs its child commands with fd 3
// closed, so none of them can write a message as the recipe.
func (r *Recipe) call(ctx context.Context, fn string, env []string) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(ctx, RecipeCallLimit)
	defer cancel()
	says, err := os.CreateTemp("", "sandprobe-recipe-says-*")
	if err != nil {
		return nil, -1, fmt.Errorf("%s didn't run: no file for its messages: %w", fn, err)
	}
	defer says.Close()
	// Unlinked before the recipe starts: only the open descriptor reaches it, so no tool can reopen it by its name.
	if err := os.Remove(says.Name()); err != nil {
		return nil, -1, fmt.Errorf("%s didn't run: its message file couldn't be unlinked: %w", fn, err)
	}
	cmd := exec.CommandContext(ctx, "sh", "-c", string(r.Text)+"\n"+fn)
	cmd.Env, cmd.WaitDelay = recipeEnviron(env), 5*time.Second
	out := &capped{max: 64 << 10}
	cmd.Stdout, cmd.ExtraFiles = out, []*os.File{says} // fd 3
	err = cmd.Run()
	if err == nil {
		return out.Bytes(), 0, nil
	}
	code := -1
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	}
	said := make([]byte, 4<<10)
	n, _ := says.ReadAt(said, 0)
	msg := printable(said[:n])
	if n == 0 {
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

// printable keeps the last line or so of a recipe's stderr, printable only, for an error message.
func printable(b []byte) string {
	s := strings.TrimSpace(strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return ' '
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, string(b)))
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
	out, _, err := b.Recipe.call(ctx, "sp_create", b.env())
	id := strings.TrimSuffix(string(out), "\n")
	if !recipeID.MatchString(id) {
		why := "its output isn't one ID line"
		if err != nil {
			why = err.Error()
		}
		return fmt.Errorf("the create returned no ID (%s); a box named %s may exist and wasn't deleted (RCP-2)", why, b.Name)
	}
	b.BoxID = id
	b.ExecBox.Env = recipeEnviron(b.env())
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
		_, _, deleteErr = b.Recipe.call(ctx, "sp_delete", b.env())
	}
	deadline := time.Now().Add(RecipeGoneLimit)
	last := "never answered"
	for {
		_, code, err := b.Recipe.call(ctx, "sp_gone", b.env())
		switch {
		case err == nil:
			return nil
		case code == 1:
			last = "it still exists"
		default:
			last = "the provider couldn't say: " + err.Error()
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
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
		"sp_shell, and deleted only by the ID its create returned. The recipe ran on this machine with your own " +
		"credentials and permissions. Persistence across a reset (PER-5) isn't tested: the recipe has no reset (RCP-3)."
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
