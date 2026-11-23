package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

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
	hostedCanaryURL  = "https://control.pub.probe.ac0.dev"
	hostedCanaryPins = []string{"37b7b9ffebd2a547d10eeaf75f791d78a28973c5498d8c6ce2aa521369f620d0"}
)

// execCanary is the canary a run exec uses (HCN-5): an operator canary from deploy/canary.sh, a public one named by
// -canary-url and pinned by -canary-pin, or the hosted canary.
type execCanary struct {
	none       bool     // -no-canary (HCN-5)
	state      string   // an operator canary's state file
	url        string   // a public canary's control
	pins       []string // its control-key pins
	describe   string   // for the plan
	retainNote string   // HCN-4's retention, for a public canary
}

func (r runFlags) execCanaryChoice() (execCanary, error) {
	retain := "That canary sees the box's public address and this run's random nonces, keeps them in memory for at most 30 minutes, and stores nothing (HCN-4)."
	if r.noCanary { // HCN-5: the person's own choice, never combined with naming a canary
		if r.canary != "" || r.canaryURL != "" || r.canaryPin != "" {
			return execCanary{}, fail("usage", "-no-canary can't be combined with -canary, -canary-url or -canary-pin", "pick one", exitUsage)
		}
		return execCanary{none: true, describe: "none: you chose -no-canary, so no test traffic leaves the box and the exfiltration checks aren't tested (the run can't grade above C)"}, nil
	}
	if r.canaryPin != "" && r.canaryURL == "" { // a pin names a canary the person trusts: never quietly use another one
		return execCanary{}, fail("usage", "-canary-pin (or SANDPROBE_CANARY_PIN) needs -canary-url: the canary that pin is for", "-canary-url https://control.<domain> -canary-pin <pin>", exitUsage)
	}
	if r.canary != "" {
		return execCanary{state: r.canary, describe: "the operator canary in " + r.canary + " (deploy/canary.sh)"}, nil
	}
	if r.canaryURL != "" {
		var pins []string
		for _, p := range strings.Split(r.canaryPin, ",") {
			if p = strings.TrimSpace(p); p != "" {
				pins = append(pins, p)
			}
		}
		if len(pins) == 0 {
			return execCanary{}, fail("usage", "-canary-url needs -canary-pin: the control key the canary signs with (HCN-1)", "sandprobe-canary -make-control-key prints it", exitUsage)
		}
		// Checked before anything is shown: the plan may be shared, so it carries only the canonical, validated values.
		origin, _, pins, err := host.CheckCanaryURL(r.canaryURL, pins)
		if err != nil {
			return execCanary{}, fail("usage", err.Error(), "-canary-url https://control.<domain> -canary-pin <64 hex digits>", exitUsage)
		}
		return execCanary{url: origin, pins: pins,
			describe:   "the public canary at " + origin + ", trusted only under control key " + pins[0][:12] + "…: DNS, HTTPS 443, TCP 22, 80 and 8080, UDP 53, each carrying only this run's random nonces",
			retainNote: retain}, nil
	}
	if found, _ := filepath.Glob(filepath.Join(configDir(), "canary-*.state")); len(found) == 1 {
		return execCanary{state: found[0], describe: "the operator canary in " + found[0] + " (deploy/canary.sh)"}, nil
	}
	return execCanary{url: hostedCanaryURL, pins: hostedCanaryPins,
		describe:   "the hosted canary at " + hostedCanaryURL + ", run by Summation and trusted only under the control key this release pins: DNS, HTTPS 443, TCP 22, 80 and 8080, UDP 53, each carrying only this run's random nonces",
		retainNote: retain}, nil
}

func execPlan(box *host.ExecBox, as string, c execCanary, attested []string, allowLocalProxy bool) planDoc {
	sec3, _ := catalog.Get("SEC-3")
	user := "whoever it runs as, which the report calls unconfirmed as the agent's user"
	if as != "" {
		user = as + ", checked before any check runs"
	}
	residual := host.ExecResidual
	if len(attested) > 0 {
		residual += " You turned on " + strings.Join(attested, ", ") + " with -provider-endpoints, attesting that your provider's terms allow them on your own account (PRV-15)."
	}
	if c.retainNote != "" {
		residual += " " + c.retainNote
	}
	contacts, named := []string{c.describe}, []string{"none: SEC-4, EGR-3, AMP-6 and AMP-7 are off, since they'd contact your provider's own endpoints (PRV-15)"}
	lines, extra, boxNamed := attestedPlan(attested, host.ExecExclusions(), true, "PRV-15")
	if len(attested) > 0 {
		contacts, named = append(contacts, extra...), boxNamed
	}
	return planDoc{Provider: "exec",
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
		LocalProxy:    localProxy(attested, allowLocalProxy),
		Time:          "about a minute, plus your command's own start-up",
		Residual:      residual,
	}
}

// openCanary sets up the canary a run exec or recipe run chose (HCN-5): none, a public one (reserved before anything
// runs in the box, HCN-3), or an operator canary. A public one is returned too, for its Close after the run.
func (r *runFlags) openCanary(ctx context.Context, choice execCanary, step func(string, ...any)) (host.Canary, *host.HTTPSCanary, error) {
	switch {
	case choice.none: // HCN-5: Execute asks no canary anything
		return nil, nil, nil
	case choice.url != "":
		step("asking the public canary for its signed status")
		public, err := host.NewHTTPSCanary(ctx, choice.url, choice.pins)
		if err != nil {
			return nil, nil, fail("needs_login", "the public canary isn't answering under its pin: "+err.Error(), "check -canary-url and -canary-pin, try again, or run with -no-canary (Exfiltration is then not tested)", exitLogin)
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
	return ssm, nil, nil
}

func runExec(o opts, r runFlags, planOnly bool, stderr io.Writer) (int, error) {
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
	choice, err := r.execCanaryChoice()
	if err != nil {
		return 0, err
	}
	attested, err := providerEndpoints(r.providerEndpoints, r.providerEndpointsSet, host.ExecExclusions())
	if err != nil {
		return 0, err
	}
	allowLocal := r.allowLocalProxy && slices.Contains(attested, "EGR-3") // SBX-1 (e): only once EGR-3 is on
	p := execPlan(box, r.as, choice, attested, allowLocal)
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
	step := func(f string, a ...any) {
		if !o.json() {
			fmt.Fprintf(stderr, "· "+f+"\n", a...)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, execRunTimeout)
	defer cancel()
	start := time.Now()

	c, public, err := r.openCanary(ctx, choice, step)
	if err != nil {
		return 0, err
	}
	var run *host.Run
	err = func() error {
		step("asking the box which probe it runs")
		arch, err := box.Arch(ctx)
		if err != nil {
			return err
		}
		bin, sum, err := probes.Probe(arch)
		if err != nil {
			return err
		}
		box.Binary = bin
		step("checking who your command runs as, before anything else")
		w, err := box.Preflight(ctx, r.as)
		if err != nil {
			return err
		}
		step("running the probe as uid %d through your command", w.UIDs[1])
		run, err = host.Execute(ctx, box, c, host.Options{Mode: "exec", ProbeSHA256: sum, Excluded: lift(host.ExecExclusions(), attested),
			ExcludedKind: obs.SkipOptIn, Attested: attested, Existing: true, AllowLocalProxy: allowLocal, NoCanary: choice.none})
		return err
	}()
	cctx, ccancel := context.WithTimeout(context.Background(), 2*time.Minute) // even after Ctrl-C
	defer ccancel()
	cleanup, cleaned := "nothing of your box was created or deleted; the scratch directory "+box.Scratch+" is confirmed gone", true
	if cerr := box.Cleanup(cctx); cerr != nil {
		cleanup, cleaned = "NOT confirmed removed: "+cerr.Error(), false
		fmt.Fprintf(stderr, "sandprobe: %s\n", cleanup)
	}
	if public != nil {
		if cerr := public.Close(cctx); cerr != nil {
			fmt.Fprintf(stderr, "sandprobe: %s\n", cerr)
		}
	}
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
