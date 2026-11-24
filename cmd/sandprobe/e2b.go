package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"sandprobe/internal/catalog"
	"sandprobe/internal/host"
	"sandprobe/internal/obs"
	"sandprobe/internal/probes"
	"sandprobe/internal/report"
)

type e2bLifecycle interface{ Destroy(context.Context) error }

// PRV-8: an interrupted run cannot cancel its cleanup.
func deleteE2B(box e2bLifecycle) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	return box.Destroy(ctx)
}

func e2bClient(r runFlags) (*host.E2BClient, error) {
	key, err := host.E2BKey(r.e2bKeyFile)
	if err != nil {
		return nil, fail("not_logged_in", err.Error(), "set SANDPROBE_E2B_KEY_FILE to an owner-only API key file, or E2B_API_KEY", exitLogin)
	}
	return host.NewE2BClient(key, r.e2bPython)
}
func e2bPlan(c canaryChoice) planDoc {
	sec3, _ := catalog.Get("SEC-3")
	return planDoc{Provider: "e2b",
		Creates:       []string{"one E2B default base CPU sandbox; secure access, no injected secrets, volumes or previews", "900-second timeout, autoPause=false; private lifecycle journal before one create request"},
		LaunchPath:    "official e2b==2.63.0 Python SDK runtime; explicit user; exec mode, 95-second command timeout",
		Probe:         "existing static Go probe in private random scratch directory, SHA-256 verified before execution",
		Markers:       "none: PER-5 skipped without resettable run-owned persistent storage",
		Contacts:      []string{c.describe},
		BoxNamed:      []string{"none: SEC-4, EGR-3, AMP-6 and AMP-7 excluded by E2B approved scope (PRV-8)"},
		OpensReadOnly: append(append([]string{}, sec3.Targets...), "credential-shaped files and other-process accessibility; never read secret values"),
		Runs:          []string{"sudo policy listing only; architecture, private-directory, upload checksum helpers", "host Python interpreter with preinstalled e2b==2.63.0; no implicit installation"},
		Reset:         "none: pause/resume is not a reset; PER-5 skipped",
		Deletes:       "delete only create-returned immutable ID after matching run metadata; confirm GET 404; unresolved cleanup exits 7",
		LocalProxy:    "excluded even with -allow-local-proxy", Time: "one CPU sandbox; ten-minute run deadline; independent three-minute cleanup; fifteen-minute automatic timeout",
		Residual: withRetention(host.E2BResidual, c)}
}
func runE2B(o opts, r runFlags, plan bool, stderr io.Writer) (int, error) {
	choice, err := r.chooseCanary() // HCN-5, with no network call
	if err != nil {
		return 0, err
	}
	p := e2bPlan(choice)
	if plan {
		if o.json() {
			o.emit(p)
		} else {
			printPlan(o.stdout, p)
		}
		return 0, nil
	}
	// AGT-3: no credential read, SDK invocation or provider call before approval.
	if !o.yes {
		p.NeedsApproval = true
		if o.json() {
			o.emit(p)
		} else {
			printPlan(o.stdout, p)
			fmt.Fprintln(stderr, "Review the plan, then run sandprobe run e2b -y.")
		}
		return exitApproval, nil
	}
	client, err := e2bClient(r)
	if err != nil {
		return 0, err
	}
	for _, arch := range []string{"amd64", "arm64"} {
		if _, _, err = probes.Probe(arch); err != nil {
			return 0, fail("usage", err.Error(), "make", exitUsage)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	if err = client.CheckSDK(ctx); err != nil {
		return 0, fail("cli_missing", err.Error(), "install internal/host/e2b-requirements.lock with pip --require-hashes --only-binary=:all: in a venv; set SANDPROBE_E2B_PYTHON to its python", exitLogin)
	}
	if err = client.Available(ctx); err != nil {
		return 0, fail("not_logged_in", err.Error(), "check E2B account and key", exitLogin)
	}
	lv := newLive(o, stderr, "e2b", livePhasesFor("e2b", choice.none, false)) // UX-5: the plan's own phases
	defer lv.close(false)
	c, public, err := r.openCanary(ctx, choice, lv.stepFunc("canary")) // HCN-5: proven, and its slot reserved, before the sandbox exists
	if err != nil {
		return 0, err
	}
	defer closeCanary(public, stderr)
	started := time.Now()
	lv.phase("box", "creating one E2B sandbox with a fifteen-minute timeout")
	box, createErr := client.CreateE2B(ctx, configDir())
	if box == nil {
		return 0, fail("provider_error", createErr.Error(), "check private journal directory", exitPartial)
	}
	cleaned := false
	pending := true
	defer func() {
		if pending {
			if e := deleteE2B(box); e != nil {
				fmt.Fprintln(stderr, "sandprobe: cleanup unresolved; journal "+box.StatePath())
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
			lv.phase("box", "uploading and verifying probe")
			err = box.Upload(ctx, bin)
		}
		if err == nil {
			lv.phase("probe", "running scoped E2B baseline checks")
			run, err = host.Execute(ctx, box, c, host.Options{Mode: "exec", ProbeSHA256: sum, Excluded: host.E2BExclusions(), ExcludedKind: obs.SkipProviderTerms})
			if err == nil {
				lv.done("probe", "")
			}
		}
	}
	lv.phase("delete", "deleting recorded E2B sandbox and verifying absence")
	cleanupErr := deleteE2B(box)
	pending = false
	cleaned = cleanupErr == nil
	lv.close(cleaned)
	cleanup := "E2B sandbox deleted; provider GET confirmed 404"
	if !cleaned {
		cleanup = "NOT confirmed deleted; inspect private journal " + box.StatePath()
		fmt.Fprintln(stderr, "sandprobe: "+cleanup)
	}
	err = errors.Join(err, cleanupErr)
	if run == nil {
		return 0, fail("provider_error", err.Error(), cleanup, failExit(cleaned))
	}
	d := report.Build(run, report.Meta{Version: Version, Provider: "e2b", BoxName: box.ID(), CreatedBySandprobe: true, StartedAt: started, Duration: time.Since(started), Calls: box.Calls, Cleanup: cleanup, Residual: host.E2BResidual})
	code, reportErr := finish(o, r, d, cleaned)
	if reportErr != nil {
		return 0, fail("provider_error", "E2B report could not be written", cleanup, failExit(cleaned))
	}
	if !cleaned {
		return exitCleanup, nil
	}
	if err != nil && code == exitGraded {
		return exitPartial, nil
	}
	return code, nil
}
