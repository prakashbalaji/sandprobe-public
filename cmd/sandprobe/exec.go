package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"maps"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"sandprobe/internal/canary"
	"sandprobe/internal/catalog"
	"sandprobe/internal/host"
	"sandprobe/internal/obs"
	"sandprobe/internal/probes"
	"sandprobe/internal/report"
)

// execRunTimeout bounds a whole run exec, from the first invocation to the last; cleanup has its own.
var execRunTimeout = 10 * time.Minute

// The hosted canary (HCN-5, HCN-7): deployed by deploy/canary.sh PUBLIC=1. Its
// control key was made on its instance; this release trusts exactly that key. A rotation ships a release with both.
var (
	hostedCanaryURL  = host.HostedCanaryURL
	hostedCanaryPins = host.HostedCanaryPins()
)

// newPublicCanary asks a public canary for its signed status (HCN-1). Tests replace it, so no test reaches the real
// hosted canary.
var newPublicCanary = host.NewHTTPSCanary

// publicCanaryRetention is HCN-4's retention, the one sentence every plan that names a public canary states before
// approval (HCN-5): both addresses the canary sees, how long it keeps each, and that it stores nothing.
const publicCanaryRetention = host.PublicCanaryRetention

// canaryChoice is the canary a run uses (HCN-5): none (-no-canary), an operator canary from deploy/canary.sh that
// -canary names, a public one named by -canary-url and pinned by -canary-pin, or the hosted canary.
type canaryChoice struct {
	none       bool     // -no-canary (HCN-5)
	state      string   // an operator canary's state file
	url        string   // a public canary's control
	pins       []string // its control-key pins
	describe   string   // for the plan
	retainNote string   // HCN-4's retention, for a public canary
}

// settleCanary is HCN-5's rule that the command line beats the environment: once any canary flag is given, the
// SANDPROBE_CANARY* values the flags took as defaults are all set aside, so the flags name the whole choice and a stale
// value can never outrank them. given holds the flags set on the command line.
func (r *runFlags) settleCanary(given map[string]bool) {
	r.canaryFlags = given["canary"] || given["canary-url"] || given["canary-pin"]
	if !r.canaryFlags && !given["no-canary"] {
		return // no canary flag: the environment's values stand in for them
	}
	if !given["canary"] {
		r.canary = ""
	}
	if !given["canary-url"] {
		r.canaryURL = ""
	}
	if !given["canary-pin"] {
		r.canaryPin = ""
	}
}

// chooseCanary is HCN-5's precedence, with no network call: -canary, -canary-url, then the hosted canary (run docker
// never asks: it always starts its own, PRV-14). A canary-*.state file is used only when -canary names it, never found
// on its own.
func (r runFlags) chooseCanary() (canaryChoice, error) {
	if r.noCanary { // HCN-5: the person's own choice, never combined with naming a canary
		if r.canary != "" || r.canaryURL != "" || r.canaryPin != "" {
			return canaryChoice{}, fail("usage", "-no-canary can't be combined with -canary, -canary-url or -canary-pin", "pick one", exitUsage)
		}
		return canaryChoice{none: true, describe: noCanaryLine(nil)}, nil
	}
	if r.canaryPin != "" && r.canaryURL == "" { // a pin names a canary the person trusts: never quietly use another one
		return canaryChoice{}, fail("usage", "-canary-pin (or SANDPROBE_CANARY_PIN) needs -canary-url: the canary that pin is for", "-canary-url https://control.<domain> -canary-pin <pin>", exitUsage)
	}
	if r.canary != "" {
		return canaryChoice{state: r.canary, describe: "the operator canary in " + r.canary + ", which you run (deploy/canary.sh), reached over SSM: DNS, HTTPS 443, TCP 22, 80 and 8080, UDP 53, each carrying only this run's random nonces"}, nil
	}
	if r.canaryURL != "" {
		var pins []string
		for _, p := range strings.Split(r.canaryPin, ",") {
			if p = strings.TrimSpace(p); p != "" {
				pins = append(pins, p)
			}
		}
		if len(pins) == 0 {
			return canaryChoice{}, fail("usage", "-canary-url needs -canary-pin: the control key the canary signs with (HCN-1)", "sandprobe-canary -make-control-key prints it", exitUsage)
		}
		// Checked before anything is shown: the plan may be shared, so it carries only the canonical, validated values.
		origin, _, pins, err := host.CheckCanaryURL(r.canaryURL, pins)
		if err != nil {
			return canaryChoice{}, fail("usage", err.Error(), "-canary-url https://control.<domain> -canary-pin <64 hex digits>", exitUsage)
		}
		return canaryChoice{url: origin, pins: pins,
			describe:   "the public canary you named at " + origin + ", trusted only under control key " + pins[0][:12] + "…: DNS, HTTPS 443, TCP 22, 80 and 8080, UDP 53, each carrying only this run's random nonces",
			retainNote: publicCanaryRetention}, nil
	}
	return canaryChoice{url: hostedCanaryURL, pins: hostedCanaryPins,
		describe:   "the hosted canary at " + hostedCanaryURL + ", run by Summation and trusted only under the control key this release pins: DNS, HTTPS 443, TCP 22, 80 and 8080, UDP 53, each carrying only this run's random nonces",
		retainNote: publicCanaryRetention}, nil
}

// declaredProvider reads PRV-17's -provider: a key of this binary's PRV-row table, exactly as the table spells it.
// A name it lacks is never echoed, since it may be pasted text; and a check that table entry excludes can't also be
// attested with -provider-endpoints. The name is the operator's word: nothing here infers it.
func declaredProvider(value string, set bool, attested []string) (string, error) {
	if !set {
		return "", nil
	}
	names := strings.Join(host.DeclarableProviders(), ", ")
	entry := host.DeclaredExclusions(value)
	if entry == nil {
		return "", fail("usage", "-provider takes only a provider Sandprobe has a reviewed scope for, spelled exactly: "+names+" (PRV-17)",
			"give the name the operator named, from that list, or leave -provider out; an agent never chooses it", exitUsage)
	}
	for _, id := range attested {
		if _, ok := entry[id]; ok {
			return "", fail("usage", "-provider-endpoints can't turn on "+id+": "+report.ReviewedScope(value)+", and the operator declared "+value+" (PRV-17)",
				"leave out -provider-endpoints for the checks that scope excludes", exitUsage)
		}
	}
	return value, nil
}

// execExclusions is run exec's exclusions (PRV-15), with a declared provider's PRV-row entry in place of the default for
// each check it excludes (PRV-17), and the attested checks lifted.
func execExclusions(declared string, attested []string) map[string]string {
	excluded := host.ExecExclusions()
	maps.Copy(excluded, host.DeclaredExclusions(declared))
	return lift(excluded, attested)
}

func execPlan(box *host.ExecBox, as string, c canaryChoice, attested []string, allowLocalProxy bool, declared string) planDoc {
	sec3, _ := catalog.Get("SEC-3")
	user := "whoever it runs as, which the report calls unconfirmed as the agent's user"
	if as != "" {
		user = as + ", checked before any check runs"
	}
	residual := withRetention(host.ExecResidual, c)
	if len(attested) > 0 {
		residual += " You turned on " + strings.Join(attested, ", ") + " with -provider-endpoints, attesting that your provider's terms allow them on your own account (PRV-15)."
	}
	contacts, named := []string{c.describe}, []string{"none: SEC-4, EGR-3, AMP-6 and AMP-7 are off, since they'd contact your provider's own endpoints (PRV-15)"}
	if c.none { // HCN-5: the connections the attested checks still make are named, never hidden behind "no canary"
		contacts[0] = noCanaryLine(attested)
	}
	off, entry := host.ExecExclusions(), host.DeclaredExclusions(declared)
	var declaredLines []string
	var declaredOff string
	if entry != nil { // PRV-17: the declared provider's PRV row decides its checks; the operator's word, never verified
		ids := slices.Sorted(maps.Keys(entry))
		declaredLines = []string{"Cloud access: not applicable — " + report.ReviewedScope(declared) + ". " + report.DeclaredUnverified(declared) + "."}
		for _, id := range ids {
			declaredLines = append(declaredLines, id+" ("+endpointNames[id]+") stays off: "+entry[id])
			delete(off, id)
		}
		declaredOff = strings.Join(ids, ", ") + " stay off: " + report.ReviewedScope(declared) + " (PRV-17)"
		named = []string{"none: " + declaredOff}
		if rest := slices.Sorted(maps.Keys(off)); len(rest) > 0 {
			named = append(named, strings.Join(rest, ", ")+" stay off, since they'd contact your provider's own endpoints (PRV-15)")
		}
		residual += " The operator declared the provider as " + declared + " with -provider; Sandprobe did not verify it, and Cloud access isn't counted on that word alone (PRV-17)."
	}
	lines, extra, boxNamed := attestedPlan(attested, off, true, c.none, "PRV-15")
	if len(attested) > 0 {
		contacts, named = append(contacts, extra...), boxNamed
		if declaredOff != "" {
			named = append([]string{declaredOff}, named...)
		}
	}
	return planDoc{Provider: "exec", DeclaredProvider: declared, Declared: declaredLines,
		Creates: []string{"nothing: your existing box, reached by: " + strings.Join(box.Command, " "),
			"a scratch directory " + box.Scratch + " in the box (mode 700) for each invocation, removed on exit and confirmed gone after each"},
		LaunchPath:    "your command, as " + user + "; it must start sh reading stdin. It first asks the box's machine type (uname -m) to pick the probe, then who it runs as, before any check",
		Probe:         "decoded from base64 into the scratch directory, run there, and removed with it",
		Markers:       "none: an existing box gets no markers and isn't reset, so PER-5 is skipped",
		Attested:      lines,
		Contacts:      contacts,
		BoxNamed:      named,
		OpensReadOnly: append(append([]string{}, sec3.Targets...), "private SSH keys, /run/secrets and .env files it finds", "/proc/<pid>/environ and /proc/<pid>/mem of other processes"),
		Runs:          []string{"the probe, and sudo -n -l, which runs no command", "the wrapper's sh, mkdir, base64, chmod, rm and uname"},
		Reset:         "none: your box isn't reset",
		Deletes:       "nothing of your box; only the scratch directory",
		LocalProxy:    localProxy(attested, allowLocalProxy, c.none),
		Time:          "about a minute, plus your command's own start-up",
		Residual:      residual,
	}
}

// openCanary sets up the canary a run chose (HCN-5), after approval and before the box is created (for run exec,
// before anything runs in it): none; a public one, proven by its signed status and with the run's slot reserved
// (HCN-1, HCN-3); or an operator canary, which must answer its status over SSM. A public one is returned too, for
// closeCanary after the run.
func (r *runFlags) openCanary(ctx context.Context, choice canaryChoice, step func(string, ...any)) (host.Canary, *host.HTTPSCanary, error) {
	switch {
	case choice.none: // HCN-5: Execute asks no canary anything
		return nil, nil, nil
	case choice.url != "":
		step("asking the public canary for its signed status")
		public, err := newPublicCanary(ctx, choice.url, choice.pins)
		if err != nil {
			return nil, nil, fail("needs_login", "the public canary isn't answering under its pin: "+err.Error(), "check -canary-url and -canary-pin, or try again; run exec and recipes can also run with -no-canary (Exfiltration is then not tested)", exitLogin)
		}
		if err = public.Reserve(ctx, 1); err != nil { // HCN-3: before anything runs in the box
			public.Close(context.WithoutCancel(ctx))
			return nil, nil, fail("needs_login", err.Error(), "try again later, or use a canary you run", exitLogin)
		}
		return public, public, nil
	}
	r.canary = choice.state
	ssm, err := r.liveCanary()
	if err != nil {
		return nil, nil, err
	}
	step("asking the operator canary for its status over SSM")
	if a, err := ssm.Ask(ctx, canary.Request{Op: "status"}); err != nil || !a.OK {
		return nil, nil, fail("provider_error", "the operator canary didn't answer over SSM", "deploy/canary.sh status", exitPartial)
	}
	return ssm, nil, nil
}

// closeCanary gives back a public canary's slots (HCN-3) under its own budget, even after Ctrl-C or a run that used
// all of its own. A slot it can't confirm released lapses on its lifetime, and the person is told.
func closeCanary(public *host.HTTPSCanary, stderr io.Writer) {
	if public == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := public.Close(ctx); err != nil {
		fmt.Fprintf(stderr, "sandprobe: %s\n", err)
	}
}

func runExec(o opts, r runFlags, planOnly bool, stderr io.Writer) (int, error) {
	if err := catalog.ValidateBlockDevicePaths(r.blockDevicePaths); err != nil {
		return 0, fail("usage", err.Error(), "use an existing absolute sandbox device path", exitUsage)
	}
	if len(r.dockerOpts) == 0 {
		return 0, fail("usage", "run exec needs your command after --: one that starts sh in the box with stdin attached", "sandprobe run exec -y -- docker exec -i mybox sh", exitUsage)
	}
	if r.as != "" && !validExecUser(r.as) {
		return 0, fail("usage", "-as takes a plain user name or a uid", "-as agent", exitUsage)
	}
	box, err := host.NewExecBox(r.dockerOpts, nil, r.scratch)
	if err != nil {
		return 0, fail("usage", err.Error(), "sandprobe run exec -y -- docker exec -i mybox sh", exitUsage)
	}
	choice, err := r.chooseCanary()
	if err != nil {
		return 0, err
	}
	attested, err := providerEndpoints(r.providerEndpoints, r.providerEndpointsSet, host.ExecExclusions())
	if err != nil {
		return 0, err
	}
	declared, err := declaredProvider(r.provider, r.providerSet, attested)
	if err != nil {
		return 0, err
	}
	allowLocal := r.allowLocalProxy && slices.Contains(attested, "EGR-3") // SBX-1 (e): only once EGR-3 is on
	p := execPlan(box, r.as, choice, attested, allowLocal, declared)
	for _, path := range r.blockDevicePaths {
		p.OpensReadOnly = append(p.OpensReadOnly, "block-device metadata only (never opened for I/O): "+path)
	}
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
		fmt.Fprint(o.stdout, "\nRun the probe in this box through your command? [y/N] ")
		answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(answer)); a != "y" && a != "yes" {
			return exitApproval, fail("needs_approval", "nothing ran: the plan wasn't approved", "sandprobe run exec -y -- <command>", exitApproval)
		}
	default: // AGT-3
		p.NeedsApproval = true
		if o.json() {
			o.emit(p)
		} else {
			printPlan(o.stdout, p)
			fmt.Fprintln(stderr, "\nsandprobe: nothing ran. Show your person this plan, then run again with -y.")
		}
		return exitApproval, nil
	}
	lv := newLive(o, stderr, "exec", livePhasesFor("exec", choice.none, false))
	defer lv.close(false)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, execRunTimeout)
	defer cancel()
	start := time.Now()

	c, public, err := r.openCanary(ctx, choice, lv.stepFunc("canary"))
	if err != nil {
		return 0, err
	}
	var run *host.Run
	err = func() error {
		lv.phase("preflight", "asking the box which probe it runs")
		arch, err := box.Arch(ctx)
		if err != nil {
			return err
		}
		bin, sum, err := probes.Probe(arch)
		if err != nil {
			return err
		}
		box.Binary = bin
		lv.phase("preflight", "checking who your command runs as, before anything else")
		w, err := box.Preflight(ctx, r.as)
		if err != nil {
			return err
		}
		lv.phase("probe", "running the probe as uid %d through your command", w.UIDs[1])
		run, err = host.Execute(ctx, box, c, host.Options{Mode: "exec", ProbeSHA256: sum, Excluded: execExclusions(declared, attested),
			ExcludedKind: obs.SkipOptIn, Attested: attested, DeclaredProvider: declared, Existing: true, AllowLocalProxy: allowLocal,
			NoCanary: choice.none, BlockDevicePaths: r.blockDevicePaths})
		if err == nil {
			lv.done("probe", "")
		}
		return err
	}()
	lv.quiet("cleanup", "removing scratch directory %s", box.Scratch)
	cleanup, cleaned := execTeardown(box, box.Scratch, public, stderr)
	lv.close(cleaned)
	if err != nil {
		return 0, fail("provider_error", err.Error(), "see the message; the cleanup is above", failExit(cleaned))
	}
	d := report.Build(run, report.Meta{Version: Version, Provider: "exec", BoxName: box.ID(), CreatedBySandprobe: false,
		StartedAt: start, Duration: time.Since(start), Cleanup: cleanup, Residual: p.Residual})
	if r.as == "" {
		d.Grade.Notes = append(d.Grade.Notes, "The probe ran as whoever your command runs as; that user isn't confirmed as the agent's (PRV-15).")
	} else {
		d.Grade.Notes = append(d.Grade.Notes, "The probe ran as "+r.as+", bound before any check ran (PRV-15).")
	}
	return finish(o, r, d, cleaned)
}

// execCleanupLimit bounds the scratch directory's removal after a run exec; the canary's slots have their own budget.
var execCleanupLimit = 2 * time.Minute

// execTeardown removes the scratch directory under its own budget, then gives back the canary's slots under theirs
// (closeCanary), so a cleanup that used all of its time can't keep a slot held until it lapses (HCN-3, HCN-5).
func execTeardown(box interface{ Cleanup(context.Context) error }, scratch string, public *host.HTTPSCanary, stderr io.Writer) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), execCleanupLimit) // even after Ctrl-C
	defer cancel()
	cleanup, cleaned := "nothing of your box was created or deleted; the scratch directory "+scratch+" is confirmed gone", true
	if err := box.Cleanup(ctx); err != nil {
		cleanup, cleaned = "NOT confirmed removed: "+err.Error(), false
		fmt.Fprintf(stderr, "sandprobe: %s\n", cleanup)
	}
	closeCanary(public, stderr)
	return cleanup, cleaned
}

// validExecUser is what -as takes for run exec: the probe's own rule for -whoami.
func validExecUser(s string) bool {
	if s == "" || len(s) > 32 {
		return false
	}
	for i, c := range s {
		ok := c >= 'a' && c <= 'z' || c == '_' || i > 0 && (c >= '0' && c <= '9' || c == '.' || c == '-')
		if !ok && strings.Trim(s, "0123456789") != "" {
			return false
		}
	}
	return true
}
