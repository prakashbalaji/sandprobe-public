//go:build poc

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sandprobe/internal/grade"
	"sandprobe/internal/host"
	"sandprobe/internal/report"
)

// modalResidual is what the Modal adapter leaves that no check closes (PRV-1, POC-9).
const modalResidual = "Each sandbox is addressed by the ID its create returned and confirmed by a fresh poll and a list by " +
	"its run tag. A create that never returned an ID stays unresolved, and Modal ends any such sandbox at its 15-minute " +
	"timeout. The App and its built images stay until `sandprobe poc modal cleanup`."

func readRecord(out, setup string) (*rawRecord, error) {
	b, err := os.ReadFile(filepath.Join(out, "raw", setup, "record.json"))
	if err != nil {
		return nil, fail("usage", "no raw record for "+setup, "sandprobe poc modal run -variant "+setup+" -y", exitUsage)
	}
	var rec rawRecord
	if err := json.Unmarshal(b, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

// pocRender renders a cleared setup's OUT-1 and OUT-2 from its raw record (POC-5: only after the operator read it).
func pocRender(o opts, r runFlags) (int, error) {
	rec, err := readRecord(r.outDir, r.variant)
	if err != nil {
		return 0, err
	}
	if err := recordSound(rec, r.variant); err != nil { // only a setup that passed every gate is rendered
		return 0, fail("usage", err.Error(), "see its raw record; run the setup again if it ended early", exitPartial)
	}
	run := &host.Run{Survey: rec.Survey, Manifest: rec.Manifest, Input: rec.Input, Doc: rec.Doc, Evidence: rec.Evidence}
	run.Report = grade.GradeBytes(rec.Manifest, rec.Doc, &rec.Evidence)
	d := report.Build(run, report.Meta{Version: Version, Provider: "modal", BoxName: rec.SandboxID + " (" + rec.Setup + ")",
		CreatedBySandprobe: true, StartedAt: rec.Started, Duration: rec.Ended.Sub(rec.Started), Calls: rec.Calls,
		Cleanup: rec.Cleanup, Residual: modalResidual})
	rr := r
	rr.outDir = filepath.Join(r.outDir, "reports", rec.Setup)
	return finish(o, rr, d, rec.Cleaned)
}

// pocCleanup deletes the images the PoC built, by ID, through a client bound to the operator's workspace (POC-9).
func pocCleanup(o opts, r runFlags, stderr io.Writer) (int, error) {
	if !o.yes {
		return exitApproval, fail("needs_approval", "nothing was deleted: cleanup runs only with -y", "sandprobe poc modal cleanup -y", exitApproval)
	}
	workspace, err := pocWorkspace()
	if err != nil {
		return 0, err
	}
	list, err := readImages(r.outDir, false) // missing or malformed is a failure, never "nothing to clean"
	if err != nil {
		return 0, fail("usage", "the image list can't be read: "+err.Error(), "find the image IDs in the run output", exitCleanup)
	}
	if list.Workspace != workspace { // the images are deleted only in the workspace that built them
		return 0, fail("usage", "the image list is for workspace "+list.Workspace+", not "+workspace, "SANDPROBE_MODAL_WORKSPACE="+list.Workspace, exitCleanup)
	}
	ids := list.IDs
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	sdk, err := host.NewModalSDK(ctx, workspace, pocApp, "")
	if err != nil {
		return 0, fail("provider_error", err.Error(), "modal profile list", exitPartial)
	}
	defer sdk.Close()
	left := 0
	for _, id := range ids {
		if err := sdk.Client.Images.Delete(ctx, id, nil); err != nil {
			fmt.Fprintf(stderr, "image %s: not deleted (%v)\n", id, host.Sanitize("image delete", err))
			left++
			continue
		}
		fmt.Fprintf(stderr, "image %s: deleted\n", id)
	}
	fmt.Fprintf(stderr, "the empty App %s stays: `modal app stop %s` removes it\n", pocApp, pocApp)
	if left > 0 {
		return exitCleanup, nil
	}
	return 0, nil
}

// recordSound is what a raw record needs before it may become a report or summary input: its own setup, every gate
// passed, the probe's evidence, and each setup's own extra evidence (POC-3, POC-6).
func recordSound(rec *rawRecord, setup string) error {
	switch {
	case rec.Setup != setup:
		return fmt.Errorf("the raw record under %s is for %s", setup, rec.Setup)
	case !rec.GatesPassed:
		return fmt.Errorf("%s didn't pass every gate: %s", setup, strings.Join(rec.Notes, "; "))
	case rec.Survey == nil || len(rec.Doc) == 0:
		return fmt.Errorf("%s has no probe evidence", setup)
	case setup == "domain-one" && (rec.Twin == nil || !rec.Twin.Read):
		return fmt.Errorf("domain-one has no read twin (POC-3)")
	case setup == "sidecar" && (rec.Relay == nil || !rec.Relay.Complete || len(rec.Look) == 0):
		return fmt.Errorf("sidecar has no complete relay log or look rows (POC-6)")
	}
	return nil
}
