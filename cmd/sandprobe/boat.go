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

	"sandprobe/internal/canary"
	"sandprobe/internal/host"
	"sandprobe/internal/obs"
	"sandprobe/internal/probes"
	"sandprobe/internal/report"
)

type boatLifecycle interface{ Destroy(context.Context) error }

// PRV-11: an interrupted run cannot cancel its cleanup.
func deleteBoat(box boatLifecycle) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	return box.Destroy(ctx)
}

func boatClient(r runFlags) (*host.BoatClient, error) {
	key, e := host.BoatKey(r.boatKeyFile)
	if e != nil {
		return nil, e
	}
	return host.NewBoatClient(key)
}
func boatPlan(c *host.SSMCanary, r runFlags) planDoc {
	return planDoc{Provider: "boat", Creates: []string{"one small CPU base VM; noEnv=true, snapshots=false, monitoring=false; run label; ttlSeconds=900 (archive, not deletion)"}, LaunchPath: "native Boat API command transport, fixed origin; no credentials in guest", Probe: "static probe, gzip upload under 5MiB, original SHA-256 verified", Contacts: []string{"our canary " + c.Addr + " (" + c.Dom + ") only"}, BoxNamed: []string{"metadata/proxy/vsock/Kubernetes excluded"}, Reset: "none; PER-5 skipped", Deletes: "original-ID permanent delete; completed original-target deletion operation plus sandbox404", Time: "one fresh CPU sandbox per invocation; bounded attempt budget recorded in PRV-11; no automatic retry", Residual: host.BoatResidual}
}
func runBoat(o opts, r runFlags, plan bool, stderr io.Writer) (int, error) {
	c, canaryErr := r.liveCanary()
	if c == nil {
		c = &host.SSMCanary{Addr: "<canary-ip>", Dom: "<canary-domain>"}
	}
	p := boatPlan(c, r)
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
			fmt.Fprintln(stderr, "Review the plan, then run sandprobe run boat -y.")
		}
		return exitApproval, nil
	}
	if canaryErr != nil {
		return 0, canaryErr
	}
	client, err := boatClient(r)
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
	if err = client.Available(ctx); err != nil {
		return 0, fail("not_logged_in", err.Error(), "check Boat team/project access and token", exitLogin)
	}
	if answer, e := c.Ask(ctx, canary.Request{Op: "status"}); e != nil || !answer.OK {
		return 0, fail("provider_error", "canary did not answer over SSM", "deploy/canary.sh status", exitPartial)
	}
	step := func(s string) {
		if !o.json() {
			fmt.Fprintln(stderr, "· "+s)
		}
	}
	started := time.Now()
	step("creating one Boat sandbox with a fifteen-minute timeout")
	box, createErr := client.CreateBoat(ctx, configDir())
	if box == nil {
		return 0, fail("provider_error", createErr.Error(), "check private journal directory", exitPartial)
	}
	if box.ID() != "" {
		step("recorded Boat sandbox " + box.ID())
	}
	cleaned := false
	pending := true
	defer func() {
		if pending {
			if e := deleteBoat(box); e != nil {
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
			step("running scoped Boat baseline checks")
			run, err = host.Execute(ctx, box, c, host.Options{Mode: "exec", ProbeSHA256: sum, Excluded: host.BoatExclusions(), ExcludedKind: obs.SkipProviderTerms})
		}
	}
	step("deleting recorded Boat sandbox and verifying absence")
	cleanupErr := deleteBoat(box)
	pending = false
	cleaned = cleanupErr == nil
	cleanup := "Boat deletion operation " + box.DeletionOperation() + " completed for original sandbox " + box.ID() + "; GET confirmed 404"
	if !cleaned {
		cleanup = "NOT confirmed deleted; inspect private journal " + box.StatePath()
		fmt.Fprintln(stderr, "sandprobe: "+cleanup)
	}
	err = errors.Join(err, cleanupErr)
	if run == nil {
		return 0, fail("provider_error", err.Error(), cleanup, failExit(cleaned))
	}
	d := report.Build(run, report.Meta{Version: Version, Provider: "boat", BoxName: box.ID(), CreatedBySandprobe: true, StartedAt: started, Duration: time.Since(started), Calls: box.Calls, Cleanup: cleanup, Residual: host.BoatResidual})
	code, reportErr := finish(o, r, d, cleaned)
	if reportErr != nil {
		return 0, fail("provider_error", "Boat report could not be written", cleanup, failExit(cleaned))
	}
	if !cleaned {
		return exitCleanup, nil
	}
	if err != nil && code == exitGraded {
		return exitPartial, nil
	}
	return code, nil
}
