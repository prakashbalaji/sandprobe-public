package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"sandprobe/internal/host"
	"sandprobe/internal/obs"
)

type surveyStopBox struct{ called bool }

func (b *surveyStopBox) ID() string { return "fixture" }
func (b *surveyStopBox) Probe(context.Context, []string, []byte) ([]byte, error) {
	b.called = true
	return nil, errors.New("offline survey stop")
}

func TestManagedCollectionOptionsReachSurveyWithoutPublicUploads(t *testing.T) {
	o := collectionOptions("fixture-sha", nil)
	b := &surveyStopBox{}
	if _, err := host.Execute(context.Background(), b, nil, o); err == nil || !b.called {
		t.Fatal("managed options rejected before survey")
	}
	m, _ := host.Plan(o, &obs.Survey{}, b.ID(), host.Storage{}, "192.0.2.1", "canary.invalid", "")
	if m.Skipped["EGR-6"] == "" {
		t.Fatal("public upload was enabled")
	}
	for _, id := range m.Selected {
		if id == "EGR-6" {
			t.Fatal("public upload selected")
		}
	}
}

func TestManagedCommandHelper(t *testing.T) {
	if os.Getenv("SANDPROBE_MANAGED_TEST_CHILD") != "1" {
		return
	}
	if os.Getenv("SANDPROBE_MANAGED_TEST_WAIT") == "1" {
		time.Sleep(30 * time.Second)
		os.Exit(0)
	}
	json.NewEncoder(os.Stdout).Encode(map[string]any{"dns_credential_present": os.Getenv("SANDPROBE_CF_TOKEN") != "", "endpoint_override_present": os.Getenv("AWS_ENDPOINT_URL") != "", "attempts": os.Getenv("AWS_MAX_ATTEMPTS"), "ignore_endpoints": os.Getenv("AWS_IGNORE_CONFIGURED_ENDPOINT_URLS")})
	os.Exit(0)
}
func TestManagedCommandsStripCredentialAndEndpointOverrides(t *testing.T) {
	t.Setenv("SANDPROBE_MANAGED_TEST_CHILD", "1")
	t.Setenv("SANDPROBE_CF_TOKEN", "synthetic-not-a-secret")
	t.Setenv("AWS_ENDPOINT_URL", "https://example.invalid")
	t.Setenv("AWS_MAX_ATTEMPTS", "9")
	exe, _ := os.Executable()
	raw, e := command(context.Background(), nil, exe, "-test.run=^TestManagedCommandHelper$")
	if e != nil {
		t.Fatal(e)
	}
	var out struct {
		Credential bool   `json:"dns_credential_present"`
		Override   bool   `json:"endpoint_override_present"`
		Attempts   string `json:"attempts"`
		Ignore     string `json:"ignore_endpoints"`
	}
	if json.Unmarshal(raw, &out) != nil || out.Credential || out.Override || out.Attempts != "1" || out.Ignore != "true" {
		t.Fatal("managed environment boundary failed")
	}
}
func TestManagedCommandIsDeadlineBound(t *testing.T) {
	t.Setenv("SANDPROBE_MANAGED_TEST_CHILD", "1")
	t.Setenv("SANDPROBE_MANAGED_TEST_WAIT", "1")
	exe, _ := os.Executable()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, e := command(ctx, nil, exe, "-test.run=^TestManagedCommandHelper$")
	if e == nil || time.Since(start) > 3*time.Second {
		t.Fatal("deadline did not stop command")
	}
}
func TestManagedArtifactsArePrivateAndNeverOverwritten(t *testing.T) {
	dir := t.TempDir()
	if e := save(dir, "artifact.json", map[string]bool{"fixed": true}); e != nil {
		t.Fatal(e)
	}
	if e := save(dir, "artifact.json", nil); e == nil {
		t.Fatal("artifact overwritten")
	}
	st, e := os.Stat(dir + "/artifact.json")
	if e != nil || st.Mode().Perm() != 0600 {
		t.Fatal("artifact not private")
	}
	if e := save(dir, "nested/file", nil); e == nil {
		t.Fatal("non-basename accepted")
	}
	if !strings.Contains(fmt.Sprint(st.Name()), "artifact") {
		t.Fatal("unexpected artifact")
	}
}

func TestFailureCategoriesNeverEchoUntrustedText(t *testing.T) {
	if failureCategory(errors.New("synthetic-sensitive-detail")) != "managed_step_failed" {
		t.Fatal("arbitrary error text escaped")
	}
	if failureCategory(errors.New("Daytona workload configuration changed")) != "native_configuration_mismatch" {
		t.Fatal("missing safe native failure label")
	}
}

func TestSDKCategoriesRetainOnlyStatusAndFixedGuard(t *testing.T) {
	if failureCategory(errors.New("Daytona exec HTTP 403")) != "sdk_http_403" {
		t.Fatal("HTTP status lost")
	}
	if failureCategory(errors.New("Daytona exec refused: runtime_proxy_guard")) != "bridge_runtime_proxy_guard" {
		t.Fatal("guard label lost")
	}
	if failureCategory(errors.New("Daytona exec refused: arbitrary-sensitive-detail")) != "managed_step_failed" {
		t.Fatal("arbitrary SDK content escaped")
	}
}

func TestModelRequestCountsRetainTransportUncertainty(t *testing.T) {
	r := taskResult{}
	if _, ok := decodeModelResponse(nil, errors.New("timeout"), &r); ok || !r.ModelRequestCountUncertain {
		t.Fatal("timeout claimed no request")
	}
	r = taskResult{}
	if _, ok := decodeModelResponse([]byte(`{"converse_attempted":true,"response":{"output":{}}}`), nil, &r); !ok || r.ModelRequests != 1 || r.ModelRequestCountUncertain {
		t.Fatal("successful request miscounted")
	}
	r = taskResult{}
	decodeModelResponse([]byte(`{"converse_attempted":false,"error":"model_account_mismatch"}`), nil, &r)
	if r.ModelRequests != 0 || r.ModelRequestCountUncertain {
		t.Fatal("pre-request refusal miscounted")
	}
	r = taskResult{}
	decodeModelResponse([]byte(`{"invalid":true}`), nil, &r)
	if !r.ModelRequestCountUncertain {
		t.Fatal("missing request metadata claimed zero")
	}
}

func TestUploadMeasurementUsesFrozenWorkloadPolicy(t *testing.T) {
	name := "bedrock-runtime.us-west-2.amazonaws.com"
	addresses, err := workloadUploadAddresses([]string{name}, "1.1.1.1/32,8.8.8.8/32")
	if err != nil || len(addresses) != 1 || addresses[name] != "1.1.1.1" {
		t.Fatal("measurement differs from workload policy", err)
	}
	for _, bad := range []string{"", "1.1.1.1", "1.1.1.1/24", "169.254.169.254/32", "10.0.0.1/32", "2001:4860:4860::8888/32"} {
		if _, err := workloadUploadAddresses([]string{name}, bad); err == nil {
			t.Fatal("unsafe/non-workload binding accepted")
		}
	}
	if addresses, err := workloadUploadAddresses([]string{"github.com"}, ""); err != nil || len(addresses) != 0 {
		t.Fatal("binding added an unselected model destination")
	}
}
