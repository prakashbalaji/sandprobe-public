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

type vercelLifecycle interface{ Destroy(context.Context) error }

// PRV-9: an interrupted run cannot cancel its cleanup.
func deleteVercel(box vercelLifecycle) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	return box.Destroy(ctx)
}

func vercelClient(r runFlags) (*host.VercelClient, error) {
	key, err := host.VercelKey(r.vercelKeyFile)
	if err != nil {
		return nil, fail("not_logged_in", err.Error(), "set SANDPROBE_VERCEL_KEY_FILE and explicit VERCEL_TEAM_ID / VERCEL_PROJECT_ID", exitLogin)
	}
	return host.NewVercelClient(key, r.vercelTeam, r.vercelProject)
}
func vercelPlan(c canaryChoice, r runFlags) planDoc {
	sec3, _ := catalog.Get("SEC-3")
	return planDoc{Provider: "vercel",
		Creates:       []string{"one Vercel universal-image sandbox in team " + r.vercelTeam + ", project " + r.vercelProject + "; two CPU cores, no injected secrets, mounts or ports", "900000ms timeout, persistent=false; private lifecycle journal before one create request"},
		LaunchPath:    "native HTTPS command stream targeting create-returned session ID; ordinary image user, sudo=false; 95000ms command timeout",
		Probe:         "existing static Go probe in private random scratch directory, SHA-256 verified before execution",
		Markers:       "none: PER-5 skipped without resettable run-owned persistent storage",
		Contacts:      []string{c.describe},
		BoxNamed:      []string{"none: SEC-4, EGR-3, AMP-6 and AMP-7 excluded by Vercel approved scope (PRV-9)"},
		OpensReadOnly: append(append([]string{}, sec3.Targets...), "credential-shaped files and other-process accessibility; never read secret values"),
		Runs:          []string{"sudo policy listing only; architecture, private-directory, upload checksum helpers", "native Go HTTPS; no runtime SDK dependency, no automatic resume or persistence"},
		Reset:         "none: pause/resume is not a reset; PER-5 skipped",
		Deletes:       "stop only the immutable session and verify terminal/404; then identity-guarded sandbox-name deletion and GET404; unresolved cleanup exits7",
		LocalProxy:    "excluded even with -allow-local-proxy", Time: "one CPU sandbox; ten-minute run deadline; independent three-minute cleanup; fifteen-minute automatic timeout",
		Residual: withRetention(host.VercelResidual, c)}
}
func runVercel(o opts, r runFlags, plan bool, stderr io.Writer) (int, error) {
	choice, err := r.chooseCanary() // HCN-5, with no network call
	if err != nil {
		return 0, err
	}
	p := vercelPlan(choice, r)
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
			fmt.Fprintln(stderr, "Review the plan, then run sandprobe run vercel -y.")
		}
		return exitApproval, nil
	}
	client, err := vercelClient(r)
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
		return 0, fail("not_logged_in", err.Error(), "check Vercel team/project access and token", exitLogin)
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
	step("creating one Vercel sandbox with a fifteen-minute timeout")
	box, createErr := client.CreateVercel(ctx, configDir())
	if box == nil {
		return 0, fail("provider_error", createErr.Error(), "check private journal directory", exitPartial)
	}
	cleaned := false
	pending := true
	defer func() {
		if pending {
			if e := deleteVercel(box); e != nil {
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
			step("running scoped Vercel baseline checks")
			run, err = host.Execute(ctx, box, c, host.Options{Mode: "exec", ProbeSHA256: sum, Excluded: host.VercelExclusions(), ExcludedKind: obs.SkipProviderTerms})
		}
	}
	step("deleting recorded Vercel sandbox and verifying absence")
	cleanupErr := deleteVercel(box)
	pending = false
	cleaned = cleanupErr == nil
	cleanup := "Vercel sandbox deleted; provider GET confirmed 404"
	if !cleaned {
		cleanup = "NOT confirmed deleted; inspect private journal " + box.StatePath()
		fmt.Fprintln(stderr, "sandprobe: "+cleanup)
	}
	err = errors.Join(err, cleanupErr)
	if run == nil {
		return 0, fail("provider_error", err.Error(), cleanup, failExit(cleaned))
	}
	d := report.Build(run, report.Meta{Version: Version, Provider: "vercel", BoxName: box.Name(), CreatedBySandprobe: true, StartedAt: started, Duration: time.Since(started), Calls: box.Calls, Cleanup: cleanup, Residual: host.VercelResidual})
	code, reportErr := finish(o, r, d, cleaned)
	if reportErr != nil {
		return 0, fail("provider_error", "Vercel report could not be written", cleanup, failExit(cleaned))
	}
	if !cleaned {
		return exitCleanup, nil
	}
	if err != nil && code == exitGraded {
		return exitPartial, nil
	}
	return code, nil
}
