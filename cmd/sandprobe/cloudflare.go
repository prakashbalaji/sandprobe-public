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

type cloudflareLifecycle interface{ Destroy(context.Context) error }

// PRV-9: an interrupted run cannot cancel its cleanup.
func deleteCloudflare(box cloudflareLifecycle) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	return box.Destroy(ctx)
}

func cloudflareClient(r runFlags) (*host.CloudflareBox, error) {
	return host.NewCloudflareBox(r.cloudflareSetup)
}
func cloudflarePlan(c *host.SSMCanary, r runFlags) planDoc {
	return planDoc{Provider: "cloudflare", Creates: []string{"one fresh native container through a dedicated authenticated Sandprobe Worker; built-in cloudflare/debian-trixie; lite CPU instance; no guest service credentials", "persisted 15-minute deadline and 2-minute inactivity backstop; exclusive private intent before create"}, LaunchPath: "native Durable Object Container API exec; image default identity, inherited PATH only", Probe: "static Go probe, private mktemp directory and SHA-256 verification", Contacts: []string{"our canary " + c.Addr + " (" + c.Dom + ") only; TCP 443/22/80/8080, UDP53 and DNS markers"}, BoxNamed: []string{"metadata, proxy, vsock and Kubernetes API excluded (PRV-10)"}, Reset: "none; PER-5 skipped", Deletes: "destroy immutable DO-owned container, verify fenced/stopped; additionally remove recorded controller resources with manage.py down", Time: "one CPU container; 15-minute hard expiry; no create retries", Residual: host.CloudflareResidual}
}
func runCloudflare(o opts, r runFlags, plan bool, stderr io.Writer) (int, error) {
	c, canaryErr := r.liveCanary()
	if c == nil {
		c = &host.SSMCanary{Addr: "<canary-ip>", Dom: "<canary-domain>"}
	}
	p := cloudflarePlan(c, r)
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
			fmt.Fprintln(stderr, "Review the plan, then run sandprobe run cloudflare -y.")
		}
		return exitApproval, nil
	}
	if canaryErr != nil {
		return 0, canaryErr
	}
	client, err := cloudflareClient(r)
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
		return 0, fail("not_logged_in", err.Error(), "check dedicated Cloudflare controller setup and capability", exitLogin)
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
	step("creating one Cloudflare sandbox with a fifteen-minute timeout")
	box, createErr := client, client.Create(ctx)
	if box == nil {
		return 0, fail("provider_error", createErr.Error(), "check private journal directory", exitPartial)
	}
	cleaned := false
	pending := true
	defer func() {
		if pending {
			if e := deleteCloudflare(box); e != nil {
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
			step("running scoped Cloudflare baseline checks")
			run, err = host.Execute(ctx, box, c, host.Options{Mode: "exec", ProbeSHA256: sum, Excluded: host.CloudflareExclusions(), ExcludedKind: obs.SkipProviderTerms})
		}
	}
	step("deleting recorded Cloudflare sandbox and verifying absence")
	cleanupErr := deleteCloudflare(box)
	pending = false
	cleaned = cleanupErr == nil
	cleanup := cloudflareCleanupEvidence(box.OwnedIntent())
	if !cleaned {
		cleanup = "NOT confirmed deleted; inspect private journal " + box.StatePath()
		fmt.Fprintln(stderr, "sandprobe: "+cleanup)
	}
	err = errors.Join(err, cleanupErr)
	if run == nil {
		return 0, fail("provider_error", err.Error(), cleanup, failExit(cleaned))
	}
	d := report.Build(run, report.Meta{Version: Version, Provider: "cloudflare", BoxName: box.ID(), CreatedBySandprobe: true, StartedAt: started, Duration: time.Since(started), Calls: box.Calls, Cleanup: cleanup, Residual: host.CloudflareResidual})
	code, reportErr := finish(o, r, d, cleaned)
	if reportErr != nil {
		return 0, fail("provider_error", "Cloudflare report could not be written", cleanup, failExit(cleaned))
	}
	if !cleaned {
		return exitCleanup, nil
	}
	if err != nil && code == exitGraded {
		return exitPartial, nil
	}
	return code, nil
}

func cloudflareCleanupEvidence(owned bool) string {
	if !owned {
		return "nothing created by this client; existing controller untouched"
	}
	return "Cloudflare container destruction confirmed by authenticated controller: fenced and not running; controller resources require manage.py down"
}
