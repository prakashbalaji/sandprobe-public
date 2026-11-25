// RUN-10: private managed entrypoint. Run through experiments/daytona-agent/run.py.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"sandprobe/internal/catalog"
	"sandprobe/internal/grade"
	"sandprobe/internal/host"
	"sandprobe/internal/obs"
	"sandprobe/internal/probes"
	"sandprobe/internal/report"
)

var sourceCommit string
var hexRun = regexp.MustCompile(`^[a-f0-9]{16}$`)

type options struct{ key, python, modelPython, folder, canary, runID, snapshot, network, root, uploadHosts, storageProfile, model, canaryProtocol, persistenceMarker string }
type taskResult struct {
	Schema                     string `json:"schema"`
	Workload                   string `json:"workload"`
	ModelRequests              int    `json:"model_requests"`
	ModelRequestCountUncertain bool   `json:"model_request_count_uncertain,omitempty"`
	FunctionalTests            int    `json:"functional_tests"`
	Independent                string `json:"independent_verification"`
	SHA                        string `json:"artifact_sha256"`
	Model                      string `json:"model"`
	Pattern                    string `json:"deployment_pattern"`
	Stage                      string `json:"failure_stage,omitempty"`
	FailureCategory            string `json:"failure_category,omitempty"`
	PreparationArtifact        string `json:"preparation_artifact,omitempty"`
}
type cleanupResult struct {
	ID        string `json:"box_id"`
	Confirmed bool   `json:"confirmed"`
	Proof     string `json:"proof"`
}

// RUN-23: assessment and recovery must not rewrite one volume ledger at once.
func lockManagedFolder(folder string) (*os.File, error) {
	st, err := os.Lstat(folder)
	if err != nil || !st.IsDir() || st.Mode().Perm() != 0700 {
		return nil, errors.New("managed folder unavailable or unsafe")
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Getuid()) {
		return nil, errors.New("managed folder not owned")
	}
	f, err := os.OpenFile(filepath.Join(folder, ".managed-run.lock"), os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, errors.New("managed lock unavailable")
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		f.Close()
		return nil, errors.New("managed lock unsafe")
	}
	owner, ok = info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Getuid()) || owner.Nlink != 1 {
		f.Close()
		return nil, errors.New("managed lock not private")
	}
	if syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		f.Close()
		return nil, errors.New("managed assessment or recovery already active")
	}
	return f, nil
}

func persistentCleanupRecord(folder string, p *host.DaytonaPersistentBox, volume *host.DaytonaVolume, gone map[string]bool) error {
	result := host.DaytonaPersistentCleanup{BoxIDs: p.BoxIDs(), BoxesConfirmed: gone[""], StorageConfirmed: gone[volume.ID()], Confirmed: gone[""] && gone[volume.ID()]}
	if err := save(folder, "persistent-cleanup.json", result); err != nil {
		return err
	}
	return save(folder, "storage-cleanup.json", map[string]any{"volume_id": volume.ID(), "confirmed": result.StorageConfirmed, "proof": "see original-ID volume journal"})
}

type cappedOutput struct{ bytes.Buffer }

func (b *cappedOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 128*1024 {
		return 0, errors.New("output limit")
	}
	return b.Buffer.Write(p)
}
func command(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = bytes.NewReader(stdin)
	cmd.Stderr = io.Discard
	cmd.Env = []string{}
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if name == "SANDPROBE_CF_TOKEN" || name == "AWS_ENDPOINT_URL" || strings.HasPrefix(name, "AWS_ENDPOINT_URL_") || name == "AWS_MAX_ATTEMPTS" || name == "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS" {
			continue
		}
		cmd.Env = append(cmd.Env, entry)
	}
	cmd.Env = append(cmd.Env, "AWS_MAX_ATTEMPTS=1", "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true")
	var out cappedOutput
	cmd.Stdout = &out
	if cmd.Run() != nil {
		return nil, errors.New("managed subprocess failed")
	}
	return out.Bytes(), nil
}
func hash(v any) string {
	b, _ := json.Marshal(v)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
func save(dir, name string, v any) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	return saveBytes(dir, name, append(b, '\n'))
}
func saveBytes(dir, name string, b []byte) error {
	if filepath.Base(name) != name {
		return errors.New("invalid output name")
	}
	f, e := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	d, e := os.Open(dir)
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
func verifySource(ctx context.Context, o options) error {
	raw, e := command(ctx, nil, "git", "-C", o.root, "rev-parse", "HEAD")
	if e != nil || len(sourceCommit) != 40 || strings.TrimSpace(string(raw)) != sourceCommit {
		return errors.New("source binding failed")
	}
	raw, e = command(ctx, nil, "git", "-C", o.root, "status", "--porcelain")
	if e != nil || len(bytes.TrimSpace(raw)) != 0 {
		return errors.New("source is not clean")
	}
	// The operator's own account and profile (SANDPROBE_AWS_ACCOUNT, SANDPROBE_AWS_PROFILE); unset, nothing matches.
	account, profile := os.Getenv("SANDPROBE_AWS_ACCOUNT"), os.Getenv("SANDPROBE_AWS_PROFILE")
	if len(account) != 12 || strings.Trim(account, "0123456789") != "" || profile == "" {
		return errors.New("AWS account binding failed: set SANDPROBE_AWS_ACCOUNT and SANDPROBE_AWS_PROFILE")
	}
	raw, e = command(ctx, nil, "aws", "--profile", profile, "--region", "us-west-2", "sts", "get-caller-identity", "--query", "Account", "--output", "text")
	if e != nil || strings.TrimSpace(string(raw)) != account {
		return errors.New("AWS account binding failed")
	}
	return nil
}
func selectedModel(o options) string {
	if o.model == "" {
		return "mistral.ministral-3-3b-instruct"
	}
	return o.model
}
func validModel(model string) bool {
	return model == "mistral.ministral-3-3b-instruct" || model == "mistral.ministral-3-8b-instruct"
}

func boundModelRequest(o options, raw []byte) bool {
	var request struct {
		Model string `json:"modelId"`
	}
	return json.Unmarshal(raw, &request) == nil && request.Model == selectedModel(o)
}
func controller(ctx context.Context, o options, mode string, input []byte) ([]byte, error) {
	return command(ctx, input, "python3", "-I", filepath.Join(o.root, "experiments/daytona-agent/controller.py"), mode, selectedModel(o))
}
func decodeModelResponse(raw []byte, transport error, result *taskResult) ([]byte, bool) {
	var envelope struct {
		Response  json.RawMessage `json:"response"`
		Attempted *bool           `json:"converse_attempted"`
		Error     string          `json:"error"`
	}
	if transport != nil || json.Unmarshal(raw, &envelope) != nil || envelope.Attempted == nil {
		result.ModelRequestCountUncertain = true
		return nil, false
	}
	if *envelope.Attempted {
		result.ModelRequests++
	}
	if envelope.Error != "" || len(envelope.Response) == 0 {
		return nil, false
	}
	return envelope.Response, true
}

// EVD-8: the workload boundary also permits credential-free preparation fault tests.
type workloadBox interface {
	WorkloadUpload(context.Context, string, []byte) error
	WorkloadCommand(context.Context, string) ([]byte, error)
}

func workload(ctx context.Context, o options, b workloadBox) taskResult {
	result := taskResult{Schema: "sandprobe.agent-task/2", Workload: "synthetic-coding-v1", Model: selectedModel(o), Pattern: "host_controller_no_guest_credentials", Independent: "failed"}
	files := map[string]string{"coding.py": "experiments/eks-agent/coding.py", "project_exec.py": "experiments/eks-agent/project_exec.py", "worker.py": "experiments/eks-agent/worker.py"}
	for name, path := range files {
		result.PreparationArtifact = name // source-fixed basename, never a local path
		result.Stage = "artifact_read"
		data, e := os.ReadFile(filepath.Join(o.root, path))
		if e != nil {
			result.FailureCategory = "local_artifact_read_failed"
			return result
		}
		result.Stage = "artifact_upload"
		if e = b.WorkloadUpload(ctx, name, data); e != nil {
			result.FailureCategory = failureCategory(e)
			return result
		}
	}
	result.PreparationArtifact = ""
	result.Stage = "worker_prepare_execution"
	prepared, e := b.WorkloadCommand(ctx, "python3 -I /opt/sandprobe/worker.py prepare")
	var preparation struct {
		Ready bool `json:"worker_ready"`
	}
	if e != nil {
		result.FailureCategory = failureCategory(e)
		return result
	}
	result.Stage = "worker_prepare_response"
	if json.Unmarshal(prepared, &preparation) != nil || !preparation.Ready {
		result.FailureCategory = "worker_ready_not_reported"
		return result
	}
	result.Stage = "intended_network"
	address := strings.TrimSuffix(strings.Split(o.network, ",")[0], "/32")
	raw, e := b.WorkloadCommand(ctx, "python3 -I /opt/sandprobe/worker.py network "+address)
	var network struct {
		TLS bool `json:"intended_model_tls"`
	}
	if e != nil || json.Unmarshal(raw, &network) != nil || !network.TLS {
		return result
	}
	if save(o.folder, "intended-network.json", network) != nil {
		result.Stage = "record_write"
		return result
	}
	var previous []byte
	for attempt := 1; attempt <= 2; attempt++ {
		result.Stage = "model_request"
		request, e := controller(ctx, o, "request", previous)
		if e != nil || !boundModelRequest(o, request) {
			return result
		}
		mctx, cancel := context.WithTimeout(ctx, 150*time.Second)
		raw, e = command(mctx, request, o.modelPython, "-I", filepath.Join(o.root, "experiments/daytona-agent/model.py"), "request")
		cancel()
		var valid bool
		raw, valid = decodeModelResponse(raw, e, &result)
		if !valid {
			return result
		}

		result.Stage = "response_format"
		parsed, e := controller(ctx, o, "parse", raw)
		if e != nil {
			return result
		}
		var source struct {
			Source   string `json:"source"`
			Previous string `json:"previous"`
		}
		if json.Unmarshal(parsed, &source) != nil || source.Source == "" || len(source.Source) > 16384 {
			return result
		}
		result.Stage = "artifact_write"
		if b.WorkloadUpload(ctx, "solution.py", []byte(source.Source)) != nil {
			return result
		}
		digest := sha256.Sum256([]byte(source.Source))
		result.SHA = hex.EncodeToString(digest[:])
		result.Stage = "functional_checks"
		raw, e = b.WorkloadCommand(ctx, "python3 -I /opt/sandprobe/worker.py verify "+result.SHA)
		var verified struct {
			Tests       int    `json:"functional_tests"`
			Independent string `json:"independent_verification"`
			SHA         string `json:"artifact_sha256"`
		}
		if e != nil || json.Unmarshal(raw, &verified) != nil || verified.Tests != 9 || verified.SHA != result.SHA {
			return result
		}
		diagnostic, diagnosticError := controller(ctx, o, "diagnostic", raw)
		if diagnosticError != nil || save(o.folder, fmt.Sprintf("functional-attempt-%d.json", attempt), map[string]any{
			"schema": "sandprobe.functional-attempt/1", "attempt": attempt, "artifact_sha256": result.SHA, "diagnostic": json.RawMessage(diagnostic),
		}) != nil {
			return result
		}
		result.FunctionalTests = verified.Tests
		if verified.Independent == "passed" {
			result.Independent = "passed"
			result.Stage = ""
			return result
		}
		previous, _ = json.Marshal(map[string]any{"previous": source.Previous, "verification": json.RawMessage(raw)})
	}
	return result
}

// Categories contain only source-fixed labels; never emit SDK/guest error text.
var safeSDKFailure = regexp.MustCompile(`^Daytona (create|lookup|exec|upload|delete|snapshot) (?:HTTP ([1-5][0-9]{2})|refused: (runtime_proxy_guard|runtime_identity_guard|identity_policy_guard|command_failed_or_output_limit|boot_guard|upload_path_guard))$`)

func failureCategory(e error) string {
	if e == nil {
		return "none"
	}
	if m := safeSDKFailure.FindStringSubmatch(e.Error()); m != nil {
		if m[2] != "" {
			return "sdk_http_" + m[2]
		}
		return "bridge_" + m[3]
	}
	switch e.Error() {
	case "Daytona local SDK interpreter unavailable":
		return "local_sdk_unavailable"
	case "Daytona workload configuration changed":
		return "native_configuration_mismatch"
	case "Daytona startup stopped; no implicit resume":
		return "unsupported_startup_state"
	case "Daytona exec failed (SDK, transport, command or deadline)":
		return "guest_command_failed"
	case "Daytona create identity timestamp unavailable":
		return "creation_identity_unavailable"
	}
	return "managed_step_failed"
}
func execute(ctx context.Context, o options) (err error) {
	uploadHosts, e := catalog.ParseUploadHosts(o.uploadHosts)
	if e != nil {
		return e
	}
	st, statErr := os.Lstat(o.folder)
	if statErr != nil || !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return errors.New("private output directory required")
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Getuid()) {
		return errors.New("output directory not owned")
	}
	stage := "preflight"
	if !validModel(selectedModel(o)) {
		return errors.New("unsupported workload model")
	}
	createAttempted := false
	storageCreateAttempted := false
	if o.storageProfile == "" {
		o.storageProfile = "ephemeral"
	}
	if o.storageProfile != "ephemeral" && o.storageProfile != "persistent-workspace" && o.storageProfile != "persistent-artifacts" {
		return errors.New("invalid storage profile")
	}
	if (o.persistenceMarker != "" && o.persistenceMarker != obs.LinkMarkerKind) || (o.persistenceMarker != "" && o.storageProfile == "ephemeral") {
		return errors.New("unsupported persistence marker or profile")
	}
	lock, e := lockManagedFolder(o.folder)
	if e != nil {
		return e
	}
	defer lock.Close()
	defer func() {
		save(o.folder, "execution-status.json", map[string]any{"stage": stage, "create_attempted": createAttempted, "storage_create_attempted": storageCreateAttempted, "completed": err == nil, "failure_category": failureCategory(err)})
	}()
	if !hexRun.MatchString(o.runID) {
		return errors.New("invalid managed run ID")
	}
	if e := verifySource(ctx, o); e != nil {
		return e
	}
	key, e := host.DaytonaKey(o.key)
	if e != nil {
		return e
	}
	client, e := host.NewDaytonaClient(key, o.python)
	if e != nil {
		return e
	}
	if e = client.CheckSDK(ctx); e != nil {
		return e
	}
	if e = client.Available(ctx); e != nil {
		return e
	}
	modelIdentity, modelError := command(ctx, nil, o.modelPython, "-I", filepath.Join(o.root, "experiments/daytona-agent/model.py"), "identity")
	var modelReady struct {
		Ready   bool   `json:"ready"`
		Version string `json:"client_version"`
	}
	if modelError != nil || json.Unmarshal(modelIdentity, &modelReady) != nil || !modelReady.Ready || modelReady.Version != "1.44.6" {
		return errors.New("model client preflight failed")
	}

	snapshot, e := client.WorkloadSnapshot(ctx, o.snapshot)
	if e != nil {
		return e
	}
	canary, e := host.LoadSSMCanary(o.canary)
	if e != nil || canary.Profile == "" || canary.Profile != os.Getenv("SANDPROBE_AWS_PROFILE") || canary.Region != "us-west-2" || canary.Domain() != "daytona-"+o.runID+".probe.ac0.dev" {
		return errors.New("run canary binding failed")
	}
	public, e := host.OpenHostedCanary(ctx) // MEAS-5: the run-owned receiver keeps its independent calibration.
	if e != nil {
		return e
	}
	defer func() {
		if host.CloseHostedCanary(public) != nil {
			err = errors.New("hosted canary release unconfirmed")
		}
	}()
	if !obs.ValidCanaryTCP80Protocol(o.canaryProtocol) {
		return errors.New("invalid canary TCP/80 protocol")
	}
	if o.canaryProtocol != "" {
		stage = "canary-http-preflight"
		if e = host.RequireHTTPMarkerV1(ctx, public); e != nil {
			return e
		}
	}
	for _, arch := range []string{"amd64", "arm64"} {
		if _, _, e := probes.Probe(arch); e != nil {
			return errors.New("probe artifact unavailable")
		}
	}
	if e = save(o.folder, "snapshot.json", snapshot); e != nil {
		return e
	}
	var volume *host.DaytonaVolume
	var persistent *host.DaytonaPersistentBox
	storageCleanupRecorded := false
	if o.storageProfile != "ephemeral" {
		stage = "create-storage"
		storageCreateAttempted = true
		mount := "/workspace"
		if o.storageProfile == "persistent-artifacts" {
			mount = "/persist"
		}
		volume, e = client.CreateDaytonaVolume(ctx, o.folder, mount)
		if volume != nil {
			defer func() {
				if storageCleanupRecorded {
					return
				}
				dctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
				defer cancel()
				de := volume.Destroy(dctx)
				confirmed := de == nil && volume.CleanupConfirmed()
				se := save(o.folder, "storage-cleanup.json", map[string]any{"volume_id": volume.ID(), "confirmed": confirmed, "proof": "see original-ID volume journal"})
				if se != nil || !confirmed {
					err = errors.New("storage cleanup unconfirmed")
				}
			}()
		}
		if e != nil {
			return e
		}
		if e = save(o.folder, "storage-profile.json", map[string]any{"storage_profile": o.storageProfile, "volume_id": volume.ID(), "mount_path": volume.MountPath(), "subpath": "", "uid": 10001, "source_commit": sourceCommit}); e != nil {
			return e
		}
	}
	stage = "create-sandbox"
	createAttempted = true
	var b *host.DaytonaBox
	if volume != nil {
		b, e = client.CreateDaytonaWorkload(ctx, o.folder, o.snapshot, o.network, volume)
	} else {
		b, e = client.CreateDaytonaWorkload(ctx, o.folder, o.snapshot, o.network)
	}
	if b == nil {
		return errors.New("sandbox create failed before intent")
	}
	// Always preserve original ownership, including partial/failed creates.
	if raw, readErr := os.ReadFile(b.StatePath()); readErr == nil {
		if se := saveBytes(o.folder, "owned-sandbox.json", raw); se != nil {
			e = se
		}
	}
	cleanupRecorded := false
	defer func() {
		diagnostic := b.WorkloadDiagnostics()
		diagnostic["host_stage"] = stage
		diagnostic["failure_category"] = failureCategory(err)
		save(o.folder, "preparation-diagnostics.json", diagnostic)
		if cleanupRecorded {
			return
		}
		dctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		cleanup := cleanupResult{ID: b.ID()}
		if persistent != nil {
			gone := persistent.Teardown(dctx, []obs.Volume{{ID: volume.ID(), MountPath: volume.MountPath(), Subpath: ""}})
			cleanup.Confirmed = gone[""]
			cleanup.Proof = "see all recorded original/replacement IDs in persistent-cleanup.json"
			storageCleanupRecorded = true
			if se := persistentCleanupRecord(o.folder, persistent, volume, gone); se != nil || !gone[volume.ID()] {
				err = errors.New("persistent storage cleanup unconfirmed")
			}
		} else if de := b.Destroy(dctx); de == nil {
			cleanup.Proof = b.CleanupProof
			cleanup.Confirmed = b.ConfirmWorkloadGone(dctx) == nil
		}
		if se := save(o.folder, "sandbox-cleanup.json", cleanup); se != nil || !cleanup.Confirmed {
			err = errors.New("sandbox cleanup unconfirmed")
		}
	}()
	if e != nil {
		return e
	}
	stage = "detect-runtime"
	if e = b.DetectArch(ctx); e != nil {
		return e
	}
	stage = "prepare-guest"
	if e = b.PrepareWorkload(ctx); e != nil {
		return e
	}
	if o.storageProfile == "persistent-artifacts" {
		stage = "storage-agent-preflight"
		proof, probeErr := b.VerifyArtifactStorage(ctx, o.runID, "preflight", []byte(`{"purpose":"agent_storage_preflight","synthetic":true}`))
		if e = save(o.folder, "storage-preflight.json", proof); e != nil {
			return e
		}
		if probeErr != nil {
			return probeErr
		}
	}
	bin, sha, e := probes.Probe(b.Arch)
	if e != nil {
		return e
	}
	stage = "upload-probe"
	if e = b.Upload(ctx, bin); e != nil {
		return e
	}
	if e = b.WorkloadProbeReady(ctx); e != nil {
		return e
	}
	stage = "freeze-native-context"
	config, e := b.WorkloadConfiguration(ctx)
	if e != nil {
		return e
	}
	stage = "freeze-fixture"
	fixture, e := b.WorkloadFixture(ctx)
	if e != nil {
		return e
	}
	stage = "receiver-calibration-prepare"
	receiver, e := host.BeginReceiverSession(ctx, canary, o.runID, b.ID(), 443)
	if receiver != nil {
		defer func() {
			closeCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			receiver.Close(closeCtx)
		}()
	}
	if e != nil {
		return e
	}
	receiverBinding := receiver.Binding()
	receiverHash, e := obs.ReceiverBindingHash(receiverBinding)
	if e != nil {
		return e
	}
	if e = save(o.folder, "receiver-binding.json", receiverBinding); e != nil {
		return e
	}
	// Native API lacks image-content/private-process verification; never invent it.
	contract := &obs.WorkloadContract{Schema: "sandprobe.workload-contract/2", Profile: obs.WorkloadProfile, Provider: "daytona", IdentityMode: "host_controller_no_guest_credentials", AgentUID: 10001, AgentGID: 10001, ManagedRunID: o.runID, BoxID: b.ID(), SnapshotID: snapshot.ID, ConfigSHA256: hash(config), IdentityPolicySHA256: hash(map[string]string{"model_identity": "none_in_guest", "controller_model": selectedModel(o)}), ProtectedDevice: fixture.Device, ProtectedInode: fixture.Inode, IdentityConfigurationVerified: true, ProtectedFixtureVerified: true}
	contract.ReceiverBindingSHA256 = receiverHash
	contract.AgentHomeSHA256 = fixture.HomeSHA256
	stage = "validate-contract"
	if e = obs.ValidateWorkloadContract(contract); e != nil {
		return e
	}
	if e = save(o.folder, "declared-contract.json", contract); e != nil {
		return e
	}
	configurationEvidence := obs.UnavailableConfigurationEvidence(o.runID, b.ID(), contract.ConfigSHA256)
	if e = obs.ValidateConfigurationEvidence(configurationEvidence); e != nil {
		return e
	}
	if e = save(o.folder, "configuration-evidence.json", configurationEvidence); e != nil {
		return e
	}
	// EVD-11: optional organization-default readback, never an enforcement verdict.
	organizationPolicy := b.OrganizationNetworkPolicy(ctx, o.runID, contract.ConfigSHA256)
	if e = save(o.folder, "organization-network-policy.json", organizationPolicy); e != nil {
		return e
	}

	stage = "workload"
	task := workload(ctx, o, b)
	if e = save(o.folder, "workload.json", task); e != nil {
		return e
	}
	if o.storageProfile == "persistent-artifacts" {
		stage = "persist-workload-result"
		payload, _ := json.Marshal(map[string]any{"functional_tests": task.FunctionalTests, "independent_verification": task.Independent, "artifact_sha256": task.SHA, "model_requests": task.ModelRequests})
		proof, artifactErr := b.VerifyArtifactStorage(ctx, o.runID, "workload-result", payload)
		if e = save(o.folder, "storage-workload-result.json", proof); e != nil {
			return e
		}
		if artifactErr != nil {
			return artifactErr
		}
	}
	after, e := b.WorkloadConfiguration(ctx)
	if e != nil || after != config {
		return errors.New("frozen native configuration changed")
	}
	fAfter, e := b.WorkloadFixture(ctx)
	if e != nil || fAfter != fixture {
		return errors.New("frozen fixture changed")
	}
	stage = "receiver-calibration-attempt"
	if e = receiver.Attempt(ctx, b); e != nil {
		save(o.folder, "receiver-calibration-restricted.json", receiver.Evidence())
		return e
	}
	stage = "standard-collection"
	collection := collectionOptions(sha, contract)
	collection.CanaryTCP80Protocol = o.canaryProtocol
	collection.PersistenceMarker = o.persistenceMarker
	collection.UploadHosts = uploadHosts
	collection.UploadAddresses, e = workloadUploadAddresses(uploadHosts, config.NetworkAllowList)
	if e != nil {
		return errors.New("frozen workload endpoint binding failed")
	}
	var target host.Box = b
	if volume != nil {
		persistent, e = host.NewDaytonaPersistentBox(ctx, b, bin)
		if e != nil {
			return e
		}
		target = persistent
	}
	r, e := host.Execute(ctx, target, public, collection)
	if e != nil {
		return errors.New("standard configuration collection failed")
	}
	if persistent != nil {
		if e = persistent.VerifyOriginalAfterCollection(ctx); e != nil {
			return e
		}
	} else {
		after, e = b.WorkloadConfiguration(ctx)
		if e != nil || after != config {
			return errors.New("configuration changed during grading")
		}
		fAfter, e = b.WorkloadFixture(ctx)
		if e != nil || fAfter != fixture {
			return errors.New("fixture changed during grading")
		}
	}
	if !r.Report.Valid {
		r.Report.Invalid = "standard observation evidence invalid or incomplete"
	}
	d := report.BuildLegacy(r, report.Meta{Version: "0.1.0", Provider: "daytona", BoxName: b.ID(), CreatedBySandprobe: true, StartedAt: time.Now(), Cleanup: "pending; see sandbox-cleanup.json and managed cleanup record", Residual: "RUN-10 external model controller; native snapshot UUID does not verify image content or private process namespaces. No provider-control endpoints or reset assessment. Standard checks use the shared hosted canary. " + host.PublicCanaryRetention})
	if persistent != nil {
		d.Statement = o.storageProfile + " profile: other checks observed the original workload; PER-5 uses the separately proven recreation. RC exposure and coverage remain separate from the workload configuration assessment."
	}
	if e = save(o.folder, "legacy-standard-report.json", d); e != nil {
		return e
	}
	page, e := report.HTML(d, "auto")
	if e != nil {
		return e
	}
	if e = saveBytes(o.folder, "legacy-standard-report.html", page); e != nil {
		return e
	}
	bundle := struct {
		Report       report.Doc         `json:"report"`
		Observations string             `json:"observations"`
		Evidence     obs.CanaryEvidence `json:"evidence"`
		Input        obs.Input          `json:"input"`
	}{d, string(r.Doc), r.Evidence, r.Input}
	if e = save(o.folder, "standard-evidence.json", bundle); e != nil {
		return e
	}
	stage = "stop-workload-before-final-receiver"
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 3*time.Minute)
	if persistent != nil {
		gone := persistent.Teardown(stopCtx, []obs.Volume{{ID: volume.ID(), MountPath: volume.MountPath(), Subpath: ""}})
		if !gone[""] || !gone[volume.ID()] {
			stopCancel()
			return errors.New("persistent workload cleanup unconfirmed")
		}
		storageCleanupRecorded = true
		if e = persistentCleanupRecord(o.folder, persistent, volume, gone); e != nil {
			stopCancel()
			return e
		}
	}
	stopProof, stopError := receiver.StopWorkload(stopCtx, b)
	stopCancel()
	if stopError != nil {
		return stopError
	}
	if e = save(o.folder, "sandbox-cleanup.json", cleanupResult{ID: b.ID(), Confirmed: true, Proof: b.CleanupProof}); e != nil {
		return e
	}
	cleanupRecorded = true
	stage = "final-receiver-collection"
	receiverEvidence := receiver.Finalize(ctx, stopProof)
	if receiver.DeliveryObserved() {
		save(o.folder, "receiver-calibration-restricted.json", receiverEvidence)
		return host.ErrReceiverDelivery
	}
	if e = save(o.folder, "receiver-calibration.json", receiverEvidence); e != nil {
		return e
	}
	workloadStatus := "reported_failed"
	if task.Independent == "passed" {
		workloadStatus = "reported_passed"
	}
	assessment := grade.WorkloadGrade(r.Manifest, r.Doc, &r.Evidence, workloadStatus)
	assessment = grade.AddReceiverCalibration(assessment, contract, receiverBinding, receiverEvidence)
	coverage := grade.WorkloadEvidenceCoverage(r.Manifest, r.Doc, assessment)
	if e = save(o.folder, "evidence-coverage.json", coverage); e != nil {
		return e
	}
	if e = save(o.folder, "workload-report.json", assessment); e != nil {
		return e
	}
	exposure := report.WorkloadExposureScore(r.Manifest, r.Doc, &r.Evidence)
	if e = save(o.folder, "exposure-scorecard.json", exposure); e != nil {
		return e
	}
	page, e = report.WorkloadExposureHTML(assessment, coverage, exposure)
	if e != nil {
		return e
	}
	if e = saveBytes(o.folder, "workload-report.html", page); e != nil {
		return e
	}
	stage = "record-complete"
	return save(o.folder, "evaluation.json", map[string]any{"schema": "sandprobe.daytona-workload/1", "source_commit": sourceCommit, "managed_run_id": o.runID, "primary_assessment": "rc_exposure_scorecard", "exposure_scorecard": exposure, "configuration_assessment": assessment, "functional_workload": task})
}

// RUN-13: Plan already skips EGR-6; it is not a provider-excludable check.
// MEAS-7: use the first address of the same verified /32 policy as the workload.
func workloadUploadAddresses(hosts []string, network string) (map[string]string, error) {
	var addresses map[string]string
	for _, name := range hosts {
		if name != "bedrock-runtime.us-west-2.amazonaws.com" {
			continue
		}
		first := strings.Split(network, ",")[0]
		prefix, err := netip.ParsePrefix(first)
		if err != nil || !prefix.Addr().Is4() || prefix.Bits() != 32 || prefix.String() != first {
			return nil, errors.New("frozen model endpoint unavailable")
		}
		addresses = map[string]string{name: prefix.Addr().String()}
	}
	if _, err := catalog.BindUploadHosts(hosts, addresses); err != nil {
		return nil, err
	}
	return addresses, nil
}

func collectionOptions(sha string, contract *obs.WorkloadContract) host.Options {
	return host.Options{Mode: "exec", ProbeSHA256: sha, Excluded: host.DaytonaExclusions(), WorkloadContract: contract}
}
func main() {
	var o options
	var cleanupState, cleanupPersistentState string
	flag.StringVar(&cleanupState, "cleanup-state", "", "original private cleanup journal")
	flag.StringVar(&cleanupPersistentState, "cleanup-persistent-state", "", "original private volume/consumer journal")
	flag.StringVar(&o.canaryProtocol, "canary-tcp80-protocol", "", "explicit canary TCP/80 protocol; legacy by default")
	flag.StringVar(&o.persistenceMarker, "persistence-marker", "", "explicit persistent-profile marker mechanism; regular file by default")
	flag.StringVar(&o.key, "key-file", "", "owner-only API key file")
	flag.StringVar(&o.python, "sdk-python", "", "pinned SDK interpreter")
	flag.StringVar(&o.modelPython, "model-python", "", "pinned Nitro Bedrock SDK interpreter")
	flag.StringVar(&o.folder, "out", "", "private managed journal/output folder")
	flag.StringVar(&o.canary, "canary-state", "", "run-owned receiver state")
	flag.StringVar(&o.runID, "run-id", "", "managed run ID")
	flag.StringVar(&o.snapshot, "snapshot", "", "CPU snapshot UUID")
	flag.StringVar(&o.network, "network", "", "fixed regional model IPv4 /32 list")
	flag.StringVar(&o.uploadHosts, "upload-hosts", "", "explicit comma-separated shipped workload names for TLS-only EGR-6")
	flag.StringVar(&o.model, "model", "mistral.ministral-3-3b-instruct", "supported regional Ministral 3B or 8B model")
	flag.StringVar(&o.storageProfile, "storage-profile", "ephemeral", "ephemeral, persistent-workspace or persistent-artifacts")
	flag.StringVar(&o.root, "source-root", ".", "clean exact-source repository")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	budget := 12 * time.Minute
	if o.storageProfile == "persistent-workspace" || o.storageProfile == "persistent-artifacts" {
		budget = 18 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	if cleanupState != "" && cleanupPersistentState != "" {
		os.Exit(5)
	}
	if cleanupState != "" || cleanupPersistentState != "" {
		path := cleanupState
		if cleanupPersistentState != "" {
			path = cleanupPersistentState
		}
		lock, e := lockManagedFolder(filepath.Dir(path))
		if e != nil {
			os.Exit(5)
		}
		defer lock.Close()
		key, e := host.DaytonaKey(o.key)
		if e != nil {
			os.Exit(5)
		}
		client, e := host.NewDaytonaClient(key, o.python)
		if e != nil {
			os.Exit(5)
		}
		if cleanupPersistentState != "" {
			result, e := client.CleanupDaytonaPersistentState(ctx, cleanupPersistentState)
			json.NewEncoder(os.Stdout).Encode(result)
			if e != nil {
				os.Exit(5)
			}
			return
		}
		id, proof, e := client.CleanupDaytonaState(ctx, cleanupState)
		json.NewEncoder(os.Stdout).Encode(cleanupResult{ID: id, Confirmed: e == nil, Proof: proof})
		if e != nil {
			os.Exit(5)
		}
		return
	}
	if e := execute(ctx, o); e != nil {
		fmt.Fprintln(os.Stderr, "daytona workload: execution incomplete; inspect private managed records")
		os.Exit(5)
	}
	fmt.Println("Daytona workload and configuration records collected; cleanup status is recorded separately.")
}
