package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sandprobe/internal/host"
	"strings"
	"testing"
)

type diagnosedSurveyBox struct{ cause error }

func (b diagnosedSurveyBox) ID() string { return "fixture" }
func (b diagnosedSurveyBox) Probe(context.Context, []string, []byte) ([]byte, error) {
	return nil, b.cause
}
func TestCollectionFailureSidecarIsBounded(t *testing.T) {
	for _, test := range []struct {
		cause error
		want  string
	}{
		{errors.New("Daytona lookup HTTP 503"), "sdk_http_503"},
		{errors.New("Daytona lookup failed: sdk_request_timeout"), "sdk_request_timeout"},
		{errors.New("Daytona lookup failed: sdk_response_schema_invalid"), "sdk_response_schema_invalid"},
		{errors.New("Daytona lookup refused: identity_policy_guard"), "bridge_identity_policy_guard"},
		{errors.New("NEVER_EXPORT_PROVIDER_SECRET"), "managed_step_failed"},
	} {
		_, cause := host.Execute(context.Background(), diagnosedSurveyBox{test.cause}, nil, host.Options{Mode: "exec"})
		wrapped := fmt.Errorf("standard configuration collection failed: %w", cause)
		folder := t.TempDir()
		if err := saveCollectionFailure(folder, wrapped); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(filepath.Join(folder, "collection-failure.json"))
		if err != nil {
			t.Fatal(err)
		}
		var got collectionFailureDiagnostic
		if json.Unmarshal(raw, &got) != nil || got.Schema != "sandprobe.collection-failure/1" || got.Stage != "survey_execution" || got.FailureCategory != test.want || got.AssessmentAvailable {
			t.Fatal("failure misclassified", string(raw))
		}
		if strings.Contains(string(raw), "NEVER_EXPORT") || strings.Contains(string(raw), "standard configuration collection failed") {
			t.Fatal("raw error serialized")
		}
	}
}
