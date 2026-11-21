package main

import (
	"bytes"
	"context"
	"encoding/json"
	"sandprobe/internal/grade"
	"sandprobe/internal/host"
	"sandprobe/internal/obs"
	"strings"
	"testing"
)

func TestInvalidBridgeRequestsNeverEmitAssessment(t *testing.T) {
	for _, q := range []string{`{`, `{"unknown":"field"}`, `{} {}`, `{"pod":{},"pod":{}}`, `{"pod":{},"POD":{}}`, "{}" + strings.Repeat(" ", 65536), `{"pod":{},"canary_state":"/nonexistent"}`} {
		var out bytes.Buffer
		if err := run(context.Background(), strings.NewReader(q), &out); err == nil {
			t.Fatal("accepted invalid request")
		}
		if out.Len() != 0 {
			t.Fatal("failure produced assessment")
		}
	}
}

func TestInvalidRunReasonCannotExposeExecStderr(t *testing.T) {
	r := &host.Run{Report: grade.Report{Invalid: "synthetic-private-detail"}}
	sanitizeInvalid(r)
	if strings.Contains(r.Report.Invalid, "private") || r.Report.Valid {
		t.Fatal("unsafe invalid report", r.Report)
	}
}

// WGR-7: the Nitro-specific live bridge must not execute another provider's contract.
func TestNitroBridgeRejectsPortableContract(t *testing.T) {
	c := &obs.WorkloadContract{Schema: "sandprobe.workload-contract/2", Profile: obs.WorkloadProfile, Provider: "daytona", IdentityMode: "host_controller_no_guest_credentials", AgentUID: 1001, AgentGID: 1001,
		ManagedRunID: strings.Repeat("a", 16), BoxID: "original", Image: "registry.example/agent@sha256:" + strings.Repeat("b", 64), ConfigSHA256: strings.Repeat("c", 64), IdentityPolicySHA256: strings.Repeat("d", 64), ProtectedDevice: 3, ProtectedInode: 4}
	if err := obs.ValidateWorkloadContract(c); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(request{Contract: c, Pod: host.AgentPodBinding{UID: c.BoxID, RunID: c.ManagedRunID, Image: c.Image, ConfigSHA256: c.ConfigSHA256}, CanaryState: "/nonexistent"})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run(context.Background(), bytes.NewReader(payload), &out); err == nil || err.Error() != "frozen workload contract mismatch" || out.Len() != 0 {
		t.Fatal("portable contract reached Nitro lifecycle", err)
	}
}
