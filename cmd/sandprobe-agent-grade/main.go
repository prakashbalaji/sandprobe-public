// RUN-8: private host-side bridge for the managed, same-pod Nitro evaluation.
// No cloud lifecycle, saved-evidence regrading, or score overrides live here.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"sandprobe/internal/catalog"
	"sandprobe/internal/host"
	"sandprobe/internal/obs"
	"sandprobe/internal/probes"
	"sandprobe/internal/report"
	"sandprobe/internal/strictjson"
)

type request struct {
	PersistenceMarker   string                    `json:"persistence_marker,omitempty"`
	CanaryTCP80Protocol string                    `json:"canary_tcp80_protocol,omitempty"`
	UploadAddresses     map[string]string         `json:"upload_addresses,omitempty"`
	UploadHosts         []string                  `json:"upload_hosts,omitempty"`
	Contract            *obs.WorkloadContract     `json:"contract"`
	Pod                 host.AgentPodBinding      `json:"pod"`
	CanaryState         string                    `json:"canary_state"`
	Persistent          *host.AgentPersistentSpec `json:"persistent,omitempty"`
}

func run(ctx context.Context, in io.Reader, out io.Writer) (err error) {
	var q request
	raw, err := io.ReadAll(io.LimitReader(in, 65537))
	if err != nil || strictjson.Decode(raw, 65536, &q) != nil {
		return errors.New("invalid grading request")
	}
	if !obs.ValidPersistenceMarker(q.PersistenceMarker) || (q.PersistenceMarker != "" && q.Persistent == nil) {
		return errors.New("unsupported persistence marker or profile")
	}
	if (q.Pod.Workspace != nil) != (q.Persistent != nil) {
		return errors.New("persistent storage and lifecycle must be declared together")
	}
	if _, err := catalog.BindUploadHosts(q.UploadHosts, q.UploadAddresses); err != nil {
		return err
	}
	if q.Contract == nil || (q.Contract.Schema != "sandprobe.workload-contract/1" && q.Contract.Schema != "sandprobe.workload-contract/3") || obs.ValidateWorkloadContract(q.Contract) != nil || q.Contract.BoxID != q.Pod.UID ||
		q.Contract.ManagedRunID != q.Pod.RunID || q.Contract.Image != q.Pod.Image || q.Contract.ConfigSHA256 != q.Pod.ConfigSHA256 {
		return errors.New("frozen workload contract mismatch")
	}
	if q.Pod.CleanEnvironment != (q.Contract.Schema == "sandprobe.workload-contract/3") {
		return errors.New("workload environment does not match its identity contract")
	}
	c, err := host.LoadSSMCanary(q.CanaryState)
	if err != nil || c.Profile == "" || c.Profile != os.Getenv("SANDPROBE_AWS_PROFILE") || c.Region != "us-west-2" || c.Domain() != "agent-"+q.Pod.RunID+".probe.ac0.dev" {
		return errors.New("invalid run canary binding")
	}
	public, err := host.OpenHostedCanary(ctx) // MEAS-5: c remains the separately owned receiver only.
	if err != nil {
		return err
	}
	defer func() {
		if host.CloseHostedCanary(public) != nil {
			err = errors.New("hosted canary release unconfirmed")
		}
	}()
	if !obs.ValidCanaryTCP80Protocol(q.CanaryTCP80Protocol) {
		return errors.New("invalid canary TCP/80 protocol")
	}
	if q.CanaryTCP80Protocol != "" {
		if err = host.RequireHTTPMarkerV1(ctx, public); err != nil {
			return err
		}
	}
	p, err := host.AttachAgentPod(ctx, q.Pod)
	if err != nil {
		return errors.New("workload binding rejected")
	}
	b, sha, err := probes.Probe(p.Arch)
	if err != nil {
		return errors.New("standard probe unavailable")
	}
	if err = p.Upload(ctx, b); err != nil {
		return errors.New("standard probe upload failed")
	}
	var box host.Box = p
	var persistent *host.AgentPersistentBox
	if q.Persistent != nil {
		persistent, err = host.NewAgentPersistentBox(ctx, p, q.Pod, b, *q.Persistent)
		if err != nil {
			return errors.New("persistent workload reset binding rejected")
		}
		box = persistent
	}
	start := time.Now()
	excluded := map[string]string{}
	for _, id := range []string{"SEC-4", "AMP-6", "AMP-7", "EGR-3"} {
		excluded[id] = "RUN-8 defensive audit scope excludes provider-owned endpoints"
	}
	r, err := host.Execute(ctx, box, public, host.Options{Mode: "exec", ProbeSHA256: sha, Excluded: excluded, WorkloadContract: q.Contract, UploadHosts: q.UploadHosts, UploadAddresses: q.UploadAddresses, CanaryTCP80Protocol: q.CanaryTCP80Protocol, PersistenceMarker: q.PersistenceMarker})
	if err != nil {
		return errors.New("standard probe assessment failed")
	}
	if persistent != nil && persistent.VerifyOriginalAfterCollection(ctx) != nil {
		return errors.New("original persistent workload collection unverified")
	}
	residual := "RUN-8: workload configuration only; no reset or provider-endpoint assessment. "
	if persistent != nil {
		residual = "RUN-23: workload configuration and supported owned-storage recreation assessment; provider endpoints excluded. "
	}
	// RUN-8: invalid runs preserve grading semantics without SDK/exec stderr.
	sanitizeInvalid(r)
	calls := p.Calls
	if persistent != nil {
		calls = persistent.Calls()
	}
	doc := report.BuildLegacy(r, report.Meta{Version: "0.1.0", Provider: "aws-nitro", BoxName: q.Pod.Name,
		CreatedBySandprobe: true, StartedAt: start, Duration: time.Since(start), Calls: calls, Cleanup: "pending",
		Residual: residual + "UID-checked name addressing retains a check-to-call race. Final exact-ID cleanup is recorded separately by the managed runner. Standard checks use the shared hosted canary. " + host.PublicCanaryRetention})
	// EVD-22: supplementary context must not discard a completed assessment.
	if host.SaveMeasurementPrerequisites(filepath.Dir(q.CanaryState), r) != nil {
		fmt.Fprintln(os.Stderr, "measurement prerequisites unavailable")
	}
	html, err := report.HTML(doc, "dark")
	if err != nil {
		return errors.New("standard report rendering failed")
	}
	return json.NewEncoder(out).Encode(report.NewManagedEvidence(doc, string(r.Doc), r.Evidence, r.Input, string(html)))
}

func main() {
	if len(os.Args) == 3 && os.Args[1] == "--workload-summary" && os.Args[2] == "--include-coverage" {
		if err := summarizeWorkloadEvidence(os.Stdin, os.Stdout, true); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "--workload-summary" {
		if err := summarizeWorkload(os.Stdin, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "unsupported host grading mode")
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 18*time.Minute)
	defer cancel()
	if err := run(ctx, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func sanitizeInvalid(r *host.Run) {
	if !r.Report.Valid {
		r.Report.Invalid = "standard probe returned invalid or unavailable evidence"
	}
}
