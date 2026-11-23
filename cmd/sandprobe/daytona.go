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

	"sandprobe/internal/host"
	"sandprobe/internal/obs"
	"sandprobe/internal/probes"
	"sandprobe/internal/report"
)

type daytonaLifecycle interface{ Destroy(context.Context) error }

// PRV-8: an interrupted run cannot cancel its cleanup.
func deleteDaytona(box daytonaLifecycle) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	return box.Destroy(ctx)
}

func daytonaClient(r runFlags) (*host.DaytonaClient, error) {
	key, err := host.DaytonaKey(r.daytonaKeyFile)
	if err != nil {
		return nil, fail("not_logged_in", err.Error(), "set SANDPROBE_DAYTONA_KEY_FILE to an owner-only API key file, or DAYTONA_API_KEY", exitLogin)
	}
	return host.NewDaytonaClient(key, r.daytonaPython)
}
func daytonaPlan(c canaryChoice) planDoc {
	return planDoc{Provider: "daytona", Creates: []string{"one US default prebuilt CPU sandbox; private, autoDeleteInterval=0, autoStopInterval=15, autoPauseInterval=0; no secrets or volumes"}, LaunchPath: "pinned daytona0.198.0 isolated host Python SDK, fixed US proxy, original sandbox ID and boot identity", Probe: "static Go probe, private upload with original SHA-256 verification", Contacts: []string{c.describe}, BoxNamed: []string{"metadata/proxy/vsock/Kubernetes excluded"}, Reset: "none; PER-5 skipped", Deletes: "original sandbox ID; verify provider404 or identity-bound destroyed state per SDK; terminal metadata residual explicit", Time: "one of two total authorized baselines; idle15min backstop, no separate smoke/retry", Residual: withRetention(host.DaytonaResidual, c)}
}
func runDaytona(o opts, r runFlags, plan bool, stderr io.Writer) (int, error) {
	choice, err := r.chooseCanary() // HCN-5, with no network call
	if err != nil {
		return 0, err
	}
	p := daytonaPlan(choice)
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
			fmt.Fprintln(stderr, "Review the plan, then run sandprobe run daytona -y.")
		}
		return exitApproval, nil
	}
	client, err := daytonaClient(r)
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
		return 0, fail("cli_missing", err.Error(), "install internal/host/daytona-requirements.lock with pip --require-hashes --only-binary=:all: in a venv; set SANDPROBE_DAYTONA_PYTHON to its python", exitLogin)
	}
	if err = client.Available(ctx); err != nil {
		return 0, fail("not_logged_in", err.Error(), "check Daytona account and key", exitLogin)
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
	step("creating one Daytona sandbox with a fifteen-minute timeout")
	box, createErr := client.CreateDaytona(ctx, configDir())
	if box == nil {
		return 0, fail("provider_error", createErr.Error(), "check private journal directory", exitPartial)
	}
	cleaned := false
	pending := true
	defer func() {
		if pending {
			if e := deleteDaytona(box); e != nil {
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
			step("uploading and verifying probe")
			err = box.Upload(ctx, bin)
		}
		if err == nil {
			step("running scoped Daytona baseline checks")
			run, err = host.Execute(ctx, box, c, host.Options{Mode: "exec", ProbeSHA256: sum, Excluded: host.DaytonaExclusions(), ExcludedKind: obs.SkipProviderTerms})
		}
	}
	step("deleting recorded Daytona sandbox and verifying absence")
	cleanupErr := deleteDaytona(box)
	pending = false
	cleaned = cleanupErr == nil
	cleanup := "Daytona sandbox deleted; " + box.CleanupProof
	if !cleaned {
		cleanup = "NOT confirmed deleted; inspect private journal " + box.StatePath()
		fmt.Fprintln(stderr, "sandprobe: "+cleanup)
	}
	err = errors.Join(err, cleanupErr)
	if run == nil {
		return 0, fail("provider_error", err.Error(), cleanup, failExit(cleaned))
	}
	d := report.Build(run, report.Meta{Version: Version, Provider: "daytona", BoxName: box.ID(), CreatedBySandprobe: true, StartedAt: started, Duration: time.Since(started), Calls: box.Calls, Cleanup: cleanup, Residual: host.DaytonaResidual})
	code, reportErr := finish(o, r, d, cleaned)
	if reportErr != nil {
		return 0, fail("provider_error", "Daytona report could not be written", cleanup, failExit(cleaned))
	}
	if !cleaned {
		return exitCleanup, nil
	}
	if err != nil && code == exitGraded {
		return exitPartial, nil
	}
	return code, nil
}
