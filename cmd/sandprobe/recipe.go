package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"sandprobe/internal/catalog"
	"sandprobe/internal/host"
	"sandprobe/internal/obs"
	"sandprobe/internal/probes"
	"sandprobe/internal/report"
	"sandprobe/recipes"
)

// recipeRunTimeout bounds a whole recipe run, from sp_create to the probe's last invocation. The cleanup starts its
// own budgets when it begins, whatever the run used: the scratch removal, then recipeDeleteLimit for the delete.
var (
	recipeRunTimeout  = 15 * time.Minute
	recipeDeleteLimit = 5 * time.Minute
)

// recipeJournal names a recipe's box on disk before its create, and its ID after, so a run that dies still leaves it
// named (AGENTS rule 8). It's removed once the box is confirmed gone, and kept, and named, otherwise.
type recipeJournal struct {
	Recipe  string    `json:"recipe"`
	File    string    `json:"file,omitempty"` // a person's own recipe: its absolute path (RCP-2)
	SHA256  string    `json:"recipe_sha256"`
	Target  string    `json:"target"`
	Name    string    `json:"name"`
	ID      string    `json:"id,omitempty"`
	Created time.Time `json:"created"`
}

func (j recipeJournal) path() string {
	return filepath.Join(configDir(), "recipe-"+j.Recipe+"-"+j.Name+".state")
}

func (j recipeJournal) write() error {
	if err := os.MkdirAll(configDir(), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(j, "", "  ")
	tmp := j.path() + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, j.path())
}

// shippedRecipe loads a recipe from recipes/ (RCP-4).
func shippedRecipe(name string) (*host.Recipe, error) {
	text, ok := recipes.Get(name)
	if !ok {
		return nil, fail("usage", "no recipe "+name, "sandprobe providers", exitUsage)
	}
	rc, err := host.ParseRecipe(name, text)
	if err != nil {
		return nil, fail("internal", "the shipped recipe "+name+" doesn't parse: "+err.Error(), "report this", exitUsage)
	}
	return rc, nil
}

// ownRecipe loads a person's own recipe file (run -recipe, RCP-4). It opens the path once, without following a symlink
// at its last component and without blocking (so a pipe there can't hang the open), then checks the descriptor it
// opened, not the path: a regular file of at most 64 KiB, read through that bound. Those bytes are the only ones
// hashed and run. That error is fixed; a parse error names at most a header key (host.ParseRecipe).
func ownRecipe(path string) (*host.Recipe, error) {
	fix := "sandprobe plan -recipe <file> (docs/providers/recipe.md)"
	bad := fail("usage", "-recipe takes a regular file of at most 64 KiB, named itself and not through a symlink (RCP-4)", fix, exitUsage)
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, bad
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > host.RecipeMax {
		return nil, bad
	}
	text, err := io.ReadAll(io.LimitReader(f, host.RecipeMax+1))
	if err != nil || len(text) > host.RecipeMax {
		return nil, bad
	}
	rc, err := host.ParseOwnRecipe(text)
	if err != nil {
		return nil, fail("usage", "your recipe isn't one Sandprobe can run: "+err.Error(), fix, exitUsage)
	}
	rc.File = path
	return rc, nil
}

var plainPath = regexp.MustCompile(`^[A-Za-z0-9_@%+=:,./~-]+$`)

// shownPath is a path as the person gave it, quoted unless it is plain, so nothing in it reaches a terminal raw.
func shownPath(p string) string {
	if plainPath.MatchString(p) {
		return p
	}
	return strconv.Quote(p)
}

// recipeExclusions are the recipe's provider-endpoint exclusions (RCP-4), each with its reason. A person's own
// recipe's reason quotes nothing from its header: nobody reviewed it.
func recipeExclusions(rc *host.Recipe) map[string]string {
	why := "the " + rc.Name + " recipe keeps checks that contact the provider's own endpoints off (RCP-4): " + rc.Terms
	if rc.Own {
		why = "your own recipe keeps checks that contact a provider's own endpoints off, since Sandprobe hasn't reviewed that provider's terms (RCP-4)"
	}
	out := map[string]string{}
	for _, id := range rc.Exclusions {
		out[id] = why
	}
	return out
}

func recipePlan(b *host.RecipeBox, as string, c canaryChoice, attested []string, allowLocalProxy bool) planDoc {
	sec3, _ := catalog.Get("SEC-3")
	rc := b.Recipe
	user := "whoever the box runs it as, which the report calls unconfirmed as the agent's user"
	if as != "" {
		user = as + ", checked before any check runs"
	}
	named := "none"
	if len(rc.Exclusions) > 0 {
		named = "none: " + strings.Join(rc.Exclusions, ", ") + " are off, since they'd contact your provider's own endpoints (RCP-4)"
	}
	launch := "the recipe's sp_shell, as " + user + "; it first asks the box's machine type (uname -m) to pick the probe, then who it runs as, before any check"
	if rc.AddressedBy == "name" {
		launch += ". Before every invocation sp_whois must name the box the create returned (RCP-2)"
	}
	through := "the " + rc.Name + " recipe (" + rc.Provider + ")"
	runs := "on this machine, the recipe's sp_ functions, with your own credentials and permissions (recipe SHA-256 " + rc.SHA256[:12] + "…)"
	deletes := "the box, only by the ID its create returned, then waits for the provider to say it's gone; if it can't, the run exits 7 naming it"
	reset := "the recipe has no reset"
	if rc.Reset { // RCP-3
		reset = "the recipe defines a reset, but recipe resets aren't built yet, so it's never called"
	}
	var own []string
	if rc.Own { // RCP-4: what nobody reviewed, before anything else
		through = "your own recipe"
		runs = "on this machine, your recipe's sp_ functions, with your own credentials and permissions (recipe SHA-256 " + rc.SHA256 + ")"
		deletes = "the box, through your recipe's sp_delete, which is given the ID its create returned, with the name and the target, and is required to act only on that ID (Sandprobe can't enforce what your recipe does with them); then waits for its sp_gone to say the box is gone, and if it doesn't, the run exits 7 naming it"
		own = []string{
			"the file " + shownPath(rc.File) + ", SHA-256 " + rc.SHA256 + ": the bytes Sandprobe read once, and the only ones it runs",
			"it is your own recipe, not one Sandprobe ships: Sandprobe hasn't reviewed it",
			"it names its provider as \"" + rc.Provider + "\": that is the recipe's own word, and Sandprobe hasn't reviewed that provider's terms",
			"it is trusted host code: it runs on this machine, outside the box, with your own credentials and permissions, so read it before you approve",
			"its sp_ready has already run, to check your settings and name where the box will be made: " + b.Target,
			"its header can't turn on any of " + strings.Join(rc.Exclusions, ", ") + ": only -provider-endpoints does, one by one, on your attestation (PRV-15)",
		}
	}
	residual := withRetention(host.RecipeResidual(rc, b.Target, attested), c)
	contacts, boxNamed := []string{c.describe}, []string{named}
	if c.none { // HCN-5: the connections the attested checks still make are named, never hidden behind "no canary"
		contacts[0] = noCanaryLine(attested)
	}
	lines, extra, attestedNamed := attestedPlan(attested, recipeExclusions(rc), false, c.none, "RCP-4")
	if len(attested) > 0 {
		contacts, boxNamed = append(contacts, extra...), attestedNamed
	}
	p := planDoc{Provider: rc.RunProvider(), OwnRecipe: own,
		Creates: []string{"one box, " + b.Name + ", through " + through + " in " + b.Target + "; its ID is what the create returns",
			"a scratch directory " + b.Scratch + " in the box (mode 700) for each invocation, removed on exit"},
		LaunchPath:    launch,
		Probe:         "decoded from base64 into the scratch directory, run there, and removed with it",
		Markers:       "none: " + reset + ", so PER-5 is skipped (RCP-3)",
		Attested:      lines,
		Contacts:      contacts,
		BoxNamed:      boxNamed,
		OpensReadOnly: append(append([]string{}, sec3.Targets...), "private SSH keys, /run/secrets and .env files it finds", "/proc/<pid>/environ and /proc/<pid>/mem of other processes"),
		Runs:          []string{"the probe, and sudo -n -l, which runs no command", "the wrapper's sh, mkdir, base64, chmod, rm and uname", runs},
		Reset:         "none: " + reset,
		Deletes:       deletes,
		LocalProxy:    localProxy(attested, allowLocalProxy, c.none),
		Time:          "a minute or two, plus the box's start-up",
		Residual:      residual,
	}
	if rc.Own {
		p.RecipeFile, p.RecipeSHA256 = rc.File, rc.SHA256
	}
	return p
}

// runRecipe runs a shipped recipe by its name, or, with -recipe, a person's own file (RCP-4).
func runRecipe(o opts, r runFlags, name string, planOnly bool, stderr io.Writer) (int, error) {
	var rc *host.Recipe
	var err error
	// via names the recipe in the live view; again is the command that runs it; nothing is what an unapproved run did.
	via, again, nothing := name, "sandprobe run "+name+" -y", "nothing ran"
	if r.recipeSet {
		rc, err = ownRecipe(r.recipe)
		name, via, again = host.OwnRecipeProvider, "your own recipe", "sandprobe run -recipe "+shownPath(r.recipe)+" -y"
		nothing = "nothing was created: only your recipe's sp_ready ran"
	} else {
		rc, err = shippedRecipe(name)
	}
	if err != nil {
		return 0, err
	}
	ready := "set " + strings.Join(rc.Env, ", ") + " (see recipes/" + name + ".sh)"
	if rc.Own {
		ready = "see what your recipe's sp_ready checks"
		if len(rc.Env) > 0 {
			ready = "set " + strings.Join(rc.Env, ", ") + ", the settings your recipe's header lists, or " + ready
		}
	}
	if r.as != "" && !validExecUser(r.as) {
		return 0, fail("usage", "-as takes a plain user name or a uid", "-as agent", exitUsage)
	}
	choice, err := r.chooseCanary()
	if err != nil {
		return 0, err
	}
	attested, err := providerEndpoints(r.providerEndpoints, r.providerEndpointsSet, recipeExclusions(rc))
	if err != nil {
		return 0, err
	}
	allowLocal := r.allowLocalProxy && slices.Contains(attested, "EGR-3") // SBX-1 (e): only once EGR-3 is on
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ownSHA := "" // RCP-4: the report's run.recipe, for a person's own recipe alone
	if rc.Own {
		ownSHA = rc.SHA256
		// The file's first execution is next (sp_ready, and anything at its top level), before any approval. Its
		// bytes go on record first, whatever the output mode, in case it hangs or misbehaves.
		fmt.Fprintf(stderr, "sandprobe: running your own recipe %s (SHA-256 %s): its sp_ready runs now, before the plan\n", shownPath(rc.File), rc.SHA256)
	}
	rctx, rcancel := context.WithTimeout(ctx, time.Minute)
	target, err := rc.Ready(rctx) // RCP-1: settings checked, and where the box will be, before the plan
	rcancel()
	if err != nil {
		return 0, fail("not_logged_in", rc.Label()+" isn't ready: "+err.Error(), ready, exitLogin)
	}
	box, err := host.NewRecipeBox(rc, target, r.scratch)
	if err != nil {
		return 0, fail("usage", err.Error(), again, exitUsage)
	}
	p := recipePlan(box, r.as, choice, attested, allowLocal)
	if planOnly {
		if o.json() {
			o.emit(p)
		} else {
			printPlan(o.stdout, p)
		}
		return 0, nil
	}
	switch {
	case o.yes:
	case o.tty():
		printPlan(o.stdout, p)
		fmt.Fprint(o.stdout, "\nCreate this box, probe it, and delete it? [y/N] ")
		answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(answer)); a != "y" && a != "yes" {
			return exitApproval, fail("needs_approval", nothing+": the plan wasn't approved", again, exitApproval)
		}
	default: // AGT-3
		p.NeedsApproval = true
		if o.json() {
			o.emit(p)
		} else {
			printPlan(o.stdout, p)
			fmt.Fprintln(stderr, "\nsandprobe: "+nothing+". Show your person this plan, then run again with -y.")
		}
		return exitApproval, nil
	}
	lv := newLive(o, stderr, name, livePhasesFor(name, choice.none, false))
	defer lv.close(false)
	ctx, cancel := context.WithTimeout(ctx, recipeRunTimeout)
	defer cancel()
	start := time.Now()
	c, public, err := r.openCanary(ctx, choice, lv.stepFunc("canary"))
	if err != nil {
		return 0, err
	}
	j := recipeJournal{Recipe: rc.Name, SHA256: rc.SHA256, Target: target, Name: box.Name, Created: time.Now().UTC()}
	if rc.Own { // RCP-2: the record's name comes from the SHA-256; only its contents hold the path
		j.File, _ = filepath.Abs(rc.File)
	}
	if err := j.write(); err != nil { // nothing is created that isn't named on disk first
		closeCanary(public, stderr)
		return 0, fail("local_error", "the box couldn't be recorded before its create, so nothing was created: "+err.Error(), "check that "+configDir()+" is writable", exitUsage)
	}
	lv.quiet("box", "creating %s through %s in %s", box.Name, via, target)
	if !lv.inPlace {
		fmt.Fprintf(stderr, "sandprobe: creating %s through %s in %s (recorded in %s)\n", box.Name, rc.Label(), target, j.path())
	}
	if err := box.Create(ctx); err != nil && box.BoxID == "" {
		lv.close(false)
		closeCanary(public, stderr)
		return 0, fail("provider_error", err.Error()+"; it stays recorded in "+j.path(), "look for "+box.Name+" yourself; Sandprobe deletes only by a returned ID", exitCleanup)
	} else {
		j.ID = box.BoxID
		if jerr := j.write(); jerr != nil && err == nil { // AGENTS rule 8: an ID that isn't on disk stops the run here
			err = fmt.Errorf("its ID %s couldn't be recorded on disk (%v), so nothing runs in it", box.BoxID, jerr)
		}
		if err != nil {
			err = fmt.Errorf("the create returned %s, then: %w", box.BoxID, err)
			lv.quiet("delete", "deleting %s", box.BoxID)
			cleanup, cleaned := recipeCleanup(box, j, stderr)
			lv.close(cleaned)
			closeCanary(public, stderr)
			return 0, fail("provider_error", err.Error()+"; "+cleanup, "see the message", failExit(cleaned))
		}
	}
	var run *host.Run
	err = func() error {
		lv.phase("box", "asking the box which probe it runs")
		arch, err := box.Arch(ctx)
		if err != nil {
			return err
		}
		bin, sum, err := probes.Probe(arch)
		if err != nil {
			return err
		}
		box.Binary = bin
		lv.phase("box", "checking who the box runs it as, before anything else")
		w, err := box.Preflight(ctx, r.as)
		if err != nil {
			return err
		}
		lv.phase("probe", "running the probe as uid %d through the recipe", w.UIDs[1])
		run, err = host.Execute(ctx, box, c, host.Options{Mode: "exec", ProbeSHA256: sum, Excluded: lift(recipeExclusions(rc), attested),
			ExcludedKind: obs.SkipOptIn, Attested: attested, AllowLocalProxy: allowLocal, NoCanary: choice.none})
		if err == nil {
			lv.done("probe", "")
		}
		return err
	}()
	lv.quiet("delete", "deleting %s", box.ID())
	cleanup, cleaned := recipeCleanup(box, j, stderr)
	lv.close(cleaned)
	closeCanary(public, stderr)
	if err != nil {
		return 0, fail("provider_error", err.Error()+"; "+cleanup, "see the message", failExit(cleaned))
	}
	d := report.Build(run, report.Meta{Version: Version, Provider: name, BoxName: box.ID(), CreatedBySandprobe: true,
		StartedAt: start, Duration: time.Since(start), Calls: box.Calls, Cleanup: cleanup, Residual: p.Residual, OwnRecipeSHA256: ownSHA})
	if r.as == "" {
		d.Grade.Notes = append(d.Grade.Notes, "The probe ran as whoever the box runs it as; that user isn't confirmed as the agent's (PRV-15).")
	} else {
		d.Grade.Notes = append(d.Grade.Notes, "The probe ran as "+r.as+", bound before any check ran (PRV-15).")
	}
	return finish(o, r, d, cleaned)
}

// recipeCleanup removes the scratch directory, then deletes the box by its ID and waits for the provider to confirm
// it's gone (RCP-2), each under a budget that starts here, so a long run can't leave the delete without time. Only the
// box's confirmed deletion counts as cleaned: the scratch directory goes with it.
func recipeCleanup(box *host.RecipeBox, j recipeJournal, stderr io.Writer) (string, bool) {
	scratch := "the scratch directory " + box.Scratch + " is confirmed gone"
	if box.BoxID != "" { // with no ID nothing more is sent to the box
		sctx, scancel := context.WithTimeout(context.Background(), 2*time.Minute)
		if cerr := box.Cleanup(sctx); cerr != nil {
			scratch = "the scratch directory wasn't confirmed removed (" + cerr.Error() + ")"
		}
		scancel()
	}
	dctx, dcancel := context.WithTimeout(context.Background(), recipeDeleteLimit)
	defer dcancel()
	if err := box.Delete(dctx); err != nil {
		msg := "NOT confirmed deleted: " + err.Error() + "; it stays recorded in " + j.path() + "; " + scratch
		fmt.Fprintf(stderr, "sandprobe: %s\n", msg)
		return msg, false
	}
	os.Remove(j.path())
	return box.ID() + " deleted by its ID and confirmed gone; " + scratch, true
}
