package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"sandprobe/internal/host"
	"sandprobe/internal/obs"
	"sandprobe/internal/probes"
	"sandprobe/internal/report"
)

type exedevLifecycle interface{ Destroy(context.Context) error }

// PRV-13: an interrupted run cannot cancel its cleanup.
func deleteExedev(box exedevLifecycle) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	return box.Destroy(ctx)
}

func exedevClient(r runFlags) (*host.ExedevClient, error) {
	key, e := host.ExedevKey(r.exedevKeyFile)
	if e != nil {
		return nil, e
	}
	return host.NewExedevClient(key)
}
func exedevDir() string { return filepath.Join(configDir(), "exedev") }
func exedevPlan(c canaryChoice, r runFlags) planDoc {
	return planDoc{Provider: "exe.dev", Creates: []string{"one standalone Ubuntu 24.04 CPU VM, 2 vCPU/4GB; egress=all; unique sandprobe run tag; no supplied integrations or service credentials"}, LaunchPath: "native HTTPS /exec with one launch and bounded polls as image user; token stays on host", Probe: "shared static amd64/arm64 probe; chunked gzip upload, SHA-256 verified", Contacts: []string{c.describe}, BoxNamed: []string{"guest metadata/proxy/vsock/Kubernetes requests excluded"}, Reset: "none; PER-5 skipped", Deletes: "original create-returned NAME with birth/region/run-tag checks; acknowledged rm plus scoped API absence, not immutable-ID deletion", Time: "one fresh CPU VM; no automatic create retry; NO provider-enforced expiry", Residual: withRetention(host.ExedevResidual, c)}
}
func runExedev(o opts, r runFlags, plan bool, stderr io.Writer) (int, error) {
	choice, err := r.chooseCanary() // HCN-5, with no network call
	if err != nil {
		return 0, err
	}
	p := exedevPlan(choice, r)
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
			fmt.Fprintln(stderr, "Review the plan, then run sandprobe run exe.dev -y.")
		}
		return exitApproval, nil
	}
	client, err := exedevClient(r)
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
		return 0, fail("not_logged_in", err.Error(), "check exe.dev token and account access", exitLogin)
	}
	c, public, err := r.openCanary(ctx, choice, progress(o, stderr)) // HCN-5: proven, and its slot reserved, before the VM exists
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
	step("creating one exe.dev CPU VM; no provider-enforced expiry")
	box, createErr := client.CreateExedev(ctx, exedevDir())
	if box == nil {
		return 0, fail("provider_error", createErr.Error(), "check private journal directory", exitPartial)
	}
	if box.CreationConfirmed() {
		step("recorded exe.dev create-returned name " + box.ID())
	} else {
		step("recorded create intent only; exe.dev VM identity is not confirmed")
	}
	cleaned := false
	pending := true
	defer func() {
		if pending {
			if e := deleteExedev(box); e != nil {
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
			step("running scoped Exedev baseline checks")
			run, err = host.Execute(ctx, box, c, host.Options{Mode: "exec", ProbeSHA256: sum, Excluded: host.ExedevExclusions(), ExcludedKind: obs.SkipProviderTerms})
		}
	}
	step("deleting recorded Exedev sandbox and verifying absence")
	cleanupErr := deleteExedev(box)
	pending = false
	cleaned = cleanupErr == nil
	cleanup := "exe.dev acknowledged deletion of original name " + box.ID() + "; scoped API absence confirmed (name-addressed exception PRV-13)"
	if !cleaned {
		cleanup = "NOT confirmed deleted; inspect private journal " + box.StatePath()
		fmt.Fprintln(stderr, "sandprobe: "+cleanup)
	}
	err = errors.Join(err, cleanupErr)
	if run == nil {
		return 0, fail("provider_error", err.Error(), cleanup, failExit(cleaned))
	}
	d := report.Build(run, report.Meta{Version: Version, Provider: "exe.dev", BoxName: box.ID(), CreatedBySandprobe: true, StartedAt: started, Duration: time.Since(started), Calls: box.Calls, Cleanup: cleanup, Residual: host.ExedevResidual})
	code, reportErr := finish(o, r, d, cleaned)
	if reportErr != nil {
		return 0, fail("provider_error", "Exedev report could not be written", cleanup, failExit(cleaned))
	}
	if !cleaned {
		return exitCleanup, nil
	}
	if err != nil && code == exitGraded {
		return exitPartial, nil
	}
	return code, nil
}

// PRV-13: cleanup never creates a box and is available after interruption.
func cleanupExedev(o opts, r runFlags, stderr io.Writer) (int, error) {
	if !o.yes {
		if o.json() {
			o.emit(map[string]any{"provider": "exe.dev", "needs_approval": true, "action": "delete only the original journaled VM after identity checks"})
		} else {
			fmt.Fprintln(o.stdout, "Review the journal, then add -y to delete the original exe.dev VM.")
		}
		return exitApproval, nil
	}
	if r.exedevState == "" {
		return 0, fail("usage", "exe.dev cleanup needs -exedev-state", "sandprobe cleanup exe.dev -exedev-state <journal> -y", exitUsage)
	}
	client, err := exedevClient(r)
	if err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if err = client.Available(ctx); err != nil {
		return 0, fail("not_logged_in", err.Error(), "refresh exe.dev token", exitLogin)
	}
	box, err := client.LoadExedev(r.exedevState)
	if err != nil {
		return 0, fail("cleanup_failed", err.Error(), "retain journal for owner reconciliation; do not delete by guessed name", exitCleanup)
	}
	if err = deleteExedev(box); err != nil {
		return 0, fail("cleanup_failed", err.Error(), "retain journal "+box.StatePath(), exitCleanup)
	}
	if o.json() {
		o.emit(map[string]any{"provider": "exe.dev", "name": box.ID(), "deleted": true, "proof": "acknowledged named deletion and scoped API absence"})
	} else {
		fmt.Fprintln(o.stdout, "Deleted original exe.dev name "+box.ID()+"; scoped API absence confirmed.")
	}
	return 0, nil
}
