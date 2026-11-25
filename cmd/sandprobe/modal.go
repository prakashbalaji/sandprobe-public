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

type modalLifecycle interface{ Destroy(context.Context) error }

// deleteModal is PRV-18's deletion: an interrupted run cannot cancel it.
func deleteModal(box modalLifecycle) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	return box.Destroy(ctx)
}

// modalWorkspace is the one workspace run modal may use, named by the operator (PRV-18). It reads no token.
func modalWorkspace() (string, error) {
	w := os.Getenv("SANDPROBE_MODAL_WORKSPACE")
	if err := host.ModalWorkspace(w); err != nil {
		return "", fail("not_logged_in", err.Error(), "run modal setup once, then set SANDPROBE_MODAL_WORKSPACE to your workspace's name (modal profile list)", exitLogin)
	}
	return w, nil
}

func modalPlan(c canaryChoice) planDoc {
	sec3, _ := catalog.Get("SEC-3")
	w := os.Getenv("SANDPROBE_MODAL_WORKSPACE")
	if host.ModalWorkspace(w) != nil {
		w = "the one SANDPROBE_MODAL_WORKSPACE names (not set yet)"
	}
	return planDoc{Provider: "modal",
		Creates: []string{"one CPU sandbox at Modal's default size in workspace " + w + ", App " + host.ModalApp + ", image " + host.ModalImage +
			"; open egress, Modal's default; no injected secrets, volumes, tunnels or GPU; 15-minute timeout",
			"the App " + host.ModalApp + " and the built image, if the workspace lacks them; both stay",
			"a private journal in " + configDir() + ", written before the create and removed once the sandbox is confirmed gone"},
		LaunchPath:    "Modal's Go SDK, Sandbox.Exec with stdin, as the image's default user (root)",
		Probe:         "existing static Go probe in a fresh directory under /tmp, SHA-256 verified before execution",
		Markers:       "none: PER-5 skipped, the sandbox mounts no volume",
		Contacts:      []string{c.describe},
		BoxNamed:      []string{"none: SEC-4, EGR-3, AMP-6 and AMP-7 would contact Modal's own endpoints (PRV-5)"},
		OpensReadOnly: append(append([]string{}, sec3.Targets...), "credential-shaped files and other-process accessibility; never read secret values"),
		Runs:          []string{"the probe, and sudo policy listing only; uname, private-directory and upload checksum helpers", "Modal's SDK on this machine, built into sandprobe, which reads your token from ~/.modal.toml or its own variables; it is never printed, logged or sent into the sandbox"},
		Reset:         "none: PER-5 skipped",
		Deletes:       "terminate only the create-returned sandbox ID; confirm it polls finished and nothing runs with this run's tag; unresolved cleanup exits 7",
		LocalProxy:    "excluded even with -allow-local-proxy", Time: "ten-minute run deadline; independent three-minute cleanup; fifteen-minute automatic timeout",
		Residual: withRetention(host.ModalResidual, c)}
}

func runModal(o opts, r runFlags, plan bool, stderr io.Writer) (int, error) {
	if r.variantSet { // it would ask for a sandbox this run doesn't make, aws-nitro's default name included
		return 0, fail("usage", "run modal makes one default sandbox and takes no -variant (PRV-18)", "sandprobe plan modal; for a sandbox you configure, docs/providers/modal.md", exitUsage)
	}
	choice, err := r.chooseCanary() // HCN-5, with no network call
	if err != nil {
		return 0, err
	}
	p := modalPlan(choice)
	if plan {
		if o.json() {
			o.emit(p)
		} else {
			printPlan(o.stdout, p)
		}
		return 0, nil
	}
	if !o.yes { // AGT-3: no SDK call, token read or provider call before approval
		p.NeedsApproval = true
		if o.json() {
			o.emit(p)
		} else {
			printPlan(o.stdout, p)
			fmt.Fprintln(stderr, "Review the plan, then run sandprobe run modal -y.")
		}
		return exitApproval, nil
	}
	workspace, err := modalWorkspace()
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
	lv := newLive(o, stderr, "modal", livePhasesFor("modal", choice.none, false))
	defer lv.close(false)
	c, public, err := r.openCanary(ctx, choice, lv.stepFunc("canary")) // HCN-5: before anything exists in the workspace
	if err != nil {
		return 0, err
	}
	defer closeCanary(public, stderr)
	started := time.Now()
	lv.phase("box", "building %s in App %s of workspace %s", host.ModalImage, host.ModalApp, workspace)
	sdk, err := host.NewModalSDK(ctx, workspace, host.ModalApp, host.ModalImage)
	if err != nil {
		return 0, fail("provider_error", err.Error(), "check that your token is for workspace "+workspace+" (modal profile list); no sandbox was created", exitPartial)
	}
	defer sdk.Close()
	spec, err := host.ModalSetup("default", "", "")
	if err != nil {
		return 0, err
	}
	lv.phase("box", "creating one Modal sandbox with a fifteen-minute timeout")
	box, err := host.CreateModalRecorded(ctx, sdk, spec, configDir(), workspace, sdk.ImageID)
	if box == nil {
		return 0, fail("provider_error", err.Error(), "check that "+configDir()+" is writable", exitPartial)
	}
	pending := true
	defer func() { // a panic on the way still asks for the delete
		if pending {
			if e := deleteModal(box); e != nil {
				fmt.Fprintln(stderr, "sandprobe: cleanup unresolved; journal "+box.StatePath())
			}
		}
	}()
	var run *host.Run
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
			lv.phase("probe", "running the probe as the image's default user")
			run, err = host.Execute(ctx, box, c, host.Options{Mode: "exec", ProbeSHA256: sum, Excluded: host.ModalExcluded, ExcludedKind: obs.SkipProviderTerms})
			if err == nil {
				lv.done("probe", "")
			}
		}
	}
	lv.phase("delete", "terminating the recorded Modal sandbox and confirming it's gone")
	cleanupErr := deleteModal(box)
	pending = false
	cleaned := cleanupErr == nil
	lv.close(cleaned)
	cleanup := "Modal sandbox terminated by its ID; it polls finished and nothing runs with this run's tag"
	if !cleaned {
		cleanup = "NOT confirmed deleted; inspect private journal " + box.StatePath()
		fmt.Fprintln(stderr, "sandprobe: "+cleanup)
	}
	err = errors.Join(err, cleanupErr)
	if run == nil {
		return 0, fail("provider_error", err.Error(), cleanup, failExit(cleaned))
	}
	d := report.Build(run, report.Meta{Version: Version, Provider: "modal", BoxName: box.ID(), CreatedBySandprobe: true, StartedAt: started, Duration: time.Since(started), Calls: box.Calls, Cleanup: cleanup, Residual: host.ModalResidual})
	code, reportErr := finish(o, r, d, cleaned)
	if reportErr != nil {
		return 0, fail("provider_error", "Modal report could not be written", cleanup, failExit(cleaned))
	}
	if !cleaned {
		return exitCleanup, nil
	}
	if err != nil && code == exitGraded {
		return exitPartial, nil
	}
	return code, nil
}
