package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"sandprobe/internal/catalog"
	"sandprobe/internal/host"
	"sandprobe/internal/probes"
	"sandprobe/internal/report"
)

func basetenClient(r runFlags) (*host.BasetenClient, error) {
	key, err := host.BasetenKey(r.basetenKeyFile)
	if err != nil {
		return nil, fail("not_logged_in", err.Error(), "set SANDPROBE_BASETEN_KEY_FILE to your owner-only key file, or BASETEN_API_KEY", exitLogin)
	}
	c, err := host.NewBasetenClient(key, r.basetenTeam)
	if err != nil {
		return nil, fail("usage", err.Error(), "check BASETEN_TEAM_ID", exitUsage)
	}
	return c, nil
}
func basetenPlan(c canaryChoice, r runFlags) planDoc {
	sec3, _ := catalog.Get("SEC-3")
	team := r.basetenTeam
	if team == "" {
		team = "the key's only accessible team (multiple teams require -baseten-team)"
	}
	region := r.basetenRegion
	if region == "" {
		region = "provider default"
	}
	p := planDoc{Provider: "baseten", Creates: []string{"one CPU sandbox in " + team + ", region " + region + ", image " + host.BasetenImage + ", default resources; no secrets, previews or volumes", "15-minute automatic DELETE expiry; owner-only lifecycle journal before the single create request"},
		LaunchPath:    "Baseten /process API as the image's default user, with no restart and a 95-second command timeout",
		Probe:         "host-shipped binary in a private /tmp/sandprobe-<random> directory, digest verified before execution",
		Markers:       "none: PER-5 is skipped because there is no run-owned persistent volume",
		Contacts:      []string{c.describe, "its DNS names, through the sandbox resolver"},
		BoxNamed:      []string{"none: SEC-4, EGR-3, AMP-6 and AMP-7 excluded by the initial Baseten scope (PRV-6)"},
		OpensReadOnly: append(append([]string{}, sec3.Targets...), "credential-shaped paths and other-process environment/memory accessibility; never collect secret values"),
		Runs:          []string{"sudo -n -l (policy listing only), plus probe upload/digest and architecture helpers"},
		Reset:         "none: suspend/resume is not a reset; PER-5 is skipped",
		Deletes:       "only the create-returned incarnation; verify TERMINATED or 404, otherwise retain journal and exit 7",
		LocalProxy:    "excluded by Baseten scope even with -allow-local-proxy", Time: "one sandbox at a time, ten-minute run deadline and three-minute independent cleanup", Residual: withRetention(host.BasetenResidual, c)}
	if r.keepSandbox {
		p.Creates[1] = "one-hour automatic DELETE expiry from creation; lifecycle journal retained for inspection and verified cleanup"
		p.Deletes = "after a valid complete run: intentionally retain the verified original sandbox until its fixed one-hour expiry; errors and interruptions still delete"
		p.Residual += " Inspection retention is requested; the report and private journal identify the expiry and cleanup command."
	}
	return p
}
func approveBaseten(o opts, p planDoc, stderr io.Writer) (bool, error) {
	if o.yes {
		return true, nil
	}
	if o.tty() {
		printPlan(o.stdout, p)
		fmt.Fprint(o.stdout, "\nCreate the sandbox, run and delete it? [y/N] ")
		answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(answer)); a == "y" || a == "yes" {
			return true, nil
		}
		return false, fail("needs_approval", "nothing was created: the plan wasn't approved", "sandprobe run baseten -y", exitApproval)
	}
	p.NeedsApproval = true
	if o.json() {
		o.emit(p)
	} else {
		printPlan(o.stdout, p)
		fmt.Fprintln(stderr, "\nsandprobe: nothing was created. Review the plan, then run again with -y.")
	}
	return false, nil
}
func runBaseten(o opts, r runFlags, plan bool, stderr io.Writer) (int, error) {
	// Plan/approval comes before authentication or any resource creation (AGT-3).
	choice, err := r.chooseCanary()
	if err != nil {
		return 0, err
	}
	p := basetenPlan(choice, r)
	if plan {
		if o.json() {
			o.emit(p)
		} else {
			printPlan(o.stdout, p)
		}
		return 0, nil
	}
	approved, err := approveBaseten(o, p, stderr)
	if err != nil {
		return 0, err
	}
	if !approved {
		return exitApproval, nil
	}
	client, err := basetenClient(r)
	if err != nil {
		return 0, err
	}
	for _, arch := range []string{"amd64", "arm64"} {
		if _, _, err := probes.Probe(arch); err != nil {
			return 0, fail("usage", err.Error(), "make", exitUsage)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	if err = client.Available(ctx); err != nil {
		return 0, fail("not_logged_in", err.Error(), "check Baseten team access and API key", exitLogin)
	}
	c, public, err := r.openCanary(ctx, choice, progress(o, stderr)) // HCN-5: proven, and its slot reserved, before the sandbox exists
	if err != nil {
		return 0, err
	}
	defer closeCanary(public, stderr)
	step := func(s string) {
		if !o.json() {
			fmt.Fprintln(stderr, "· "+s)
		}
	}
	started := time.Now()
	if r.keepSandbox {
		step("creating one Baseten inspection sandbox with one-hour delete expiry")
	} else {
		step("creating one Baseten sandbox with 15-minute delete expiry")
	}
	var box *host.BasetenBox
	var createErr error
	if r.keepSandbox {
		box, createErr = client.CreateBasetenForInspection(ctx, configDir(), r.basetenRegion)
	} else {
		box, createErr = client.CreateBaseten(ctx, configDir(), r.basetenRegion)
	}
	if box == nil {
		return 0, fail("provider_error", createErr.Error(), "check local lifecycle state directory", exitPartial)
	}
	pending := true
	defer func() {
		if pending {
			_, _, _, e := completeBasetenLifecycle(context.Background(), box, nil, errors.New("Baseten run aborted"), false)
			if e != nil {
				fmt.Fprintln(stderr, "sandprobe: "+e.Error()+"; journal "+box.StatePath())
			}
		}
	}()
	var run *host.Run
	err = createErr
	if err == nil {
		err = box.DetectArch(ctx)
	}
	if err == nil {
		var bin []byte
		var sum string
		bin, sum, err = probes.Probe(box.Arch)
		if err == nil {
			step("uploading and verifying the probe")
			err = box.Upload(ctx, bin)
		}
		if err == nil {
			step("running canary-only Baseten checks")
			run, err = host.Execute(ctx, box, c, host.Options{Mode: "exec", ProbeSHA256: sum, Excluded: host.BasetenExclusions()})
		}
	}
	cleanup, retention, cleaned, err := completeBasetenLifecycle(ctx, box, run, err, r.keepSandbox)
	pending = false
	if retention != nil || !cleaned {
		fmt.Fprintln(stderr, "sandprobe: "+cleanup)
	}
	if err != nil && run == nil {
		return 0, fail("provider_error", err.Error(), cleanup, failExit(cleaned))
	}
	d := report.Build(run, report.Meta{Version: Version, Provider: "baseten", BoxName: box.Name, CreatedBySandprobe: true, StartedAt: started, Duration: time.Since(started), Calls: box.Calls, Cleanup: cleanup, Residual: host.BasetenResidual})
	d.Cleanup.Retention = retention
	return finishBaseten(o, r, d, cleaned, err)
}

// PRV-6/OUT-4: failed report output cannot mask an unconfirmed deletion.
func finishBaseten(o opts, r runFlags, d report.Doc, cleaned bool, lifecycleErr error) (int, error) {
	if lifecycleErr != nil {
		d.Grade.Notes = append(d.Grade.Notes, "Lifecycle handling: "+lifecycleErr.Error())
	}
	code, err := finish(o, r, d, cleaned)
	if err != nil {
		return 0, fail("provider_error", "Baseten report could not be written", d.Cleanup.Outcome, failExit(cleaned))
	}
	if lifecycleErr != nil && code == exitGraded {
		return exitPartial, nil
	}
	return code, nil
}

// A separate lifecycle boundary makes retention and recovery testable without clouds.
type basetenLifecycle interface {
	ID() string
	StatePath() string
	Retain(context.Context) (time.Time, error)
	Destroy(context.Context) error
}

func completeBasetenLifecycle(ctx context.Context, b basetenLifecycle, run *host.Run, runErr error, keep bool) (string, *report.Retention, bool, error) {
	if keep && runErr == nil && run != nil && run.Report.Valid && run.Report.Complete && ctx.Err() == nil {
		expiry, e := b.Retain(ctx)
		if e == nil && ctx.Err() == nil {
			command := []string{"sandprobe", "cleanup", "baseten", "-baseten-state", b.StatePath(), "-y"}
			retained := &report.Retention{ExpiresAt: expiry.UTC().Format(time.RFC3339Nano), StateFile: b.StatePath(), CleanupCommand: command}
			outcome := fmt.Sprintf("INTENTIONALLY RETAINED: %s; automatic deletion by %s (one hour from creation); journal %s; cleanup with sandprobe cleanup baseten -baseten-state '%s' -y", b.ID(), retained.ExpiresAt, b.StatePath(), strings.ReplaceAll(b.StatePath(), "'", "'\\''"))
			return outcome, retained, true, nil
		}
		if e == nil {
			e = errors.New("Baseten run interrupted during retention; sandbox will be deleted")
		}
		runErr = e
	} else if keep && ctx.Err() != nil && runErr == nil {
		runErr = errors.New("Baseten run interrupted; sandbox will not be retained")
	}
	cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if e := b.Destroy(cleanup); e != nil {
		return "NOT confirmed deleted: inspect Baseten lifecycle journal " + b.StatePath(), nil, false, errors.Join(runErr, e)
	}
	return "the sandbox was deleted; the provider confirmed TERMINATED or not found", nil, true, runErr
}

func cleanupBaseten(o opts, r runFlags, args []string, stderr io.Writer) (int, error) {
	if len(args) != 1 || args[0] != "baseten" || r.basetenState == "" {
		return 0, fail("usage", "cleanup requires baseten and -baseten-state <journal>", "sandprobe cleanup baseten -baseten-state <journal> -y", exitUsage)
	}
	if !o.yes {
		if o.json() {
			o.emit(map[string]any{"provider": "baseten", "needs_approval": true, "state_file": r.basetenState, "deletes": "only the create-confirmed incarnation recorded in the private journal"})
		} else {
			fmt.Fprintf(o.stdout, "Verify and delete the Baseten incarnation recorded in %s. Nothing was contacted or deleted; add -y to approve.\n", r.basetenState)
		}
		return exitApproval, nil
	}
	client, err := basetenClient(r)
	if err != nil {
		return 0, err
	}
	b, err := client.LoadBasetenJournal(r.basetenState)
	if err != nil {
		return 0, fail("provider_error", err.Error(), "retain the journal; do not adopt or delete a replacement", exitCleanup)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if err = b.Destroy(ctx); err != nil {
		return 0, fail("provider_error", err.Error(), "cleanup unconfirmed; retain journal "+r.basetenState, exitCleanup)
	}
	if o.json() {
		o.emit(map[string]any{"provider": "baseten", "sandbox": b.ID(), "deleted": true, "state_file": r.basetenState})
	} else {
		fmt.Fprintln(o.stdout, "Baseten sandbox deletion confirmed; journal retired:", b.ID())
	}
	return exitGraded, nil
}
