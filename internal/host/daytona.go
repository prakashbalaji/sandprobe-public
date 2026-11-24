package host

// PRV-12: pinned isolated SDK bridge, exclusive create and original-ID cleanup.
import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sandprobe/internal/obs"
	"strings"
	"syscall"
	"time"
)

//go:embed daytona_runtime.py
var daytonaRuntime string

const DaytonaResidual = "Exec-mode default prebuilt Daytona CPU snapshot, private ephemeral sandbox, no app/model credentials or persistent mounts. Idle-stop is a cost backstop, not hard expiry. Guest boot evidence is self-observed; SDK runtime is pinned US proxy bound to the original ID. Cleanup accepts provider404 or original-ID destroyed/desired destroyed per SDK, and identifies any retained terminal metadata separately."

var errDaytonaLocalSDK = errors.New("Daytona local SDK interpreter unavailable")

var daytonaID = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
var daytonaDir = regexp.MustCompile(`^/tmp/\.sandprobe-[A-Za-z0-9]{12}$`)

type DaytonaClient struct {
	key, python string
	runtime     func(context.Context, map[string]any) ([]byte, error)
}

func NewDaytonaClient(key, python string) (*DaytonaClient, error) {
	if !validVercelKey(key) {
		return nil, errors.New("Daytona key invalid")
	}
	if python == "" {
		python = "python3"
	}
	c := &DaytonaClient{key: key, python: python}
	c.runtime = c.runSDK
	return c, nil
}
func (c *DaytonaClient) runSDK(ctx context.Context, in map[string]any) ([]byte, error) {
	data, e := json.Marshal(in)
	if e != nil {
		return nil, errors.New("Daytona input invalid")
	}
	ctx, cancel := context.WithTimeout(ctx, 110*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.python, "-I", "-c", daytonaRuntime)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "LANG=C.UTF-8"}
	cmd.Stdin = bytes.NewReader(data)
	var out cappedE2BOutput
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		// EVD-7: no SDK process ran; do not attribute a local tool failure to the provider.
		var launch *exec.Error
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) || errors.As(err, &launch) {
			return nil, errDaytonaLocalSDK
		}
		var problem struct {
			Status int    `json:"http_status"`
			Code   string `json:"failure_code"`
		}
		json.Unmarshal(out.Bytes(), &problem)
		if problem.Status >= 100 && problem.Status <= 599 {
			return nil, fmt.Errorf("Daytona %s HTTP %d", in["op"], problem.Status)
		}
		switch problem.Code {
		case "runtime_proxy_guard", "runtime_identity_guard", "identity_policy_guard", "command_failed_or_output_limit", "boot_guard", "upload_path_guard":
			return nil, fmt.Errorf("Daytona %s refused: %s", in["op"], problem.Code)
		}
		return nil, fmt.Errorf("Daytona %s failed (SDK, transport, command or deadline)", in["op"])
	}
	return out.Bytes(), nil
}
func (c *DaytonaClient) call(ctx context.Context, op string, in map[string]any, out any) error {
	if in == nil {
		in = map[string]any{}
	}
	in["key"] = c.key
	in["op"] = op
	raw, e := c.runtime(ctx, in)
	if e != nil {
		return e
	}
	if len(raw) > obs.MaxDoc || json.Unmarshal(raw, out) != nil {
		return errors.New("Daytona SDK response invalid/oversized")
	}
	return nil
}
func (c *DaytonaClient) CheckSDK(ctx context.Context) error {
	var d struct{ Version string }
	if e := c.call(ctx, "check", nil, &d); e != nil {
		return e
	}
	if d.Version != "0.198.0" {
		return errors.New("Daytona requires pinned SDK0.198.0")
	}
	return nil
}
func (c *DaytonaClient) Available(ctx context.Context) error {
	var d struct{ Available bool }
	if e := c.call(ctx, "available", nil, &d); e != nil {
		return e
	}
	if !d.Available {
		return errors.New("Daytona API access unavailable")
	}
	return nil
}

type daytonaInfo struct {
	ID, Name, Organization, Born, State, User, Proxy string
	Desired                                          string `json:"desired_state"`
	Labels                                           map[string]string
	Public                                           *bool
	AutoDelete                                       *int `json:"auto_delete"`
	AutoStop                                         *int `json:"auto_stop"`
	AutoPause                                        *int `json:"auto_pause"`
	Volumes                                          *int
	Absent                                           bool
	SnapshotID                                       string               `json:"snapshot_id"`
	SnapshotRef                                      string               `json:"snapshot_ref"`
	NetworkAllowList                                 string               `json:"network_allow_list"`
	NetworkBlockAll                                  *bool                `json:"network_block_all"`
	DomainAllowList                                  string               `json:"domain_allow_list"`
	VolumeBindings                                   []daytonaVolumeMount `json:"volume_bindings"`
}
type daytonaVolumeMount struct {
	ID        string `json:"id"`
	MountPath string `json:"mount_path"`
	Subpath   string `json:"subpath"`
}
type daytonaJournal struct {
	Nonce, Name, ID, Born, Organization string
	Requested                           time.Time
	SnapshotID, NetworkAllowList        string
	Volume                              *daytonaVolumeMount `json:",omitempty"`
}
type DaytonaBox struct {
	client                                     *DaytonaClient
	journal                                    daytonaJournal
	state, boot, ProbePath, Arch, CleanupProof string
	Calls                                      []obs.ProviderCall
	gone                                       bool
	probePrefix                                string
	workloadStage                              string
	managerPrefix                              string
	managerReadiness                           *DaytonaManagerReadiness
	workloadChecks                             map[string]bool
	volume                                     *DaytonaVolume
	volumeConsumer                             string
}

func (b *DaytonaBox) call(ctx context.Context, op string, in map[string]any, out any) error {
	at := time.Now()
	e := b.client.call(ctx, op, in, out)
	call := obs.ProviderCall{At: at, Call: "Daytona " + op, OK: e == nil, ID: b.ID()}
	if e != nil {
		call.Error = "provider_error"
		if errors.Is(e, errDaytonaLocalSDK) {
			call.Error = "local_sdk_unavailable"
		}
	}
	b.Calls = append(b.Calls, call)
	return e
}
func (b *DaytonaBox) ID() string        { return b.journal.ID }
func (b *DaytonaBox) StatePath() string { return b.state }
func (b *DaytonaBox) save() error {
	data, _ := json.Marshal(b.journal)
	f, e := os.CreateTemp(filepath.Dir(b.state), ".daytona-state-")
	if e != nil {
		return errors.New("Daytona state update failed")
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(data)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil || ce != nil || os.Rename(name, b.state) != nil {
		return errors.New("Daytona state update failed")
	}
	return syncDaytonaDirectory(filepath.Dir(b.state))
}
func syncDaytonaDirectory(dir string) error {
	f, e := os.Open(dir)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func (c *DaytonaClient) CreateDaytona(ctx context.Context, dir string) (*DaytonaBox, error) {
	return c.createDaytona(ctx, dir, "", "")
}
func (c *DaytonaClient) createDaytona(ctx context.Context, dir, snapshot, network string, volumes ...*DaytonaVolume) (*DaytonaBox, error) {
	if len(volumes) > 1 || (len(volumes) == 1 && (volumes[0] == nil || volumes[0].client != c || snapshot == "")) {
		return nil, errors.New("Daytona persistent workspace selection invalid")
	}
	if len(volumes) == 1 {
		if err := volumes[0].Verify(ctx); err != nil {
			return nil, err
		}
		if filepath.Dir(volumes[0].path) != dir {
			return nil, errors.New("Daytona volume belongs to another run directory")
		}
	}
	if os.MkdirAll(dir, 0700) != nil {
		return nil, errors.New("Daytona journal directory unavailable")
	}
	st, e := os.Lstat(dir)
	if e != nil || !st.IsDir() || st.Mode().Perm()&0022 != 0 {
		return nil, errors.New("Daytona journal directory unsafe")
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Getuid()) {
		return nil, errors.New("Daytona journal directory not owned")
	}
	b := &DaytonaBox{client: c, journal: daytonaJournal{Nonce: token("n"), Name: token("sandprobe-"), Requested: time.Now().UTC(), SnapshotID: snapshot, NetworkAllowList: network}}
	if len(volumes) == 1 {
		b.volume = volumes[0]
		b.journal.Volume = &daytonaVolumeMount{ID: b.volume.ID(), MountPath: b.volume.MountPath(), Subpath: ""}
	}
	b.state = filepath.Join(dir, "daytona-"+b.journal.Nonce+".state")
	f, e := os.OpenFile(b.state, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return nil, errors.New("Daytona intent unavailable")
	}
	data, _ := json.Marshal(b.journal)
	_, e = f.Write(data)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil || ce != nil || syncDaytonaDirectory(dir) != nil {
		return b, errors.New("Daytona intent write failed")
	}
	if b.volume != nil {
		if e = b.volume.consumerIntent(b.state); e != nil {
			return b, e
		}
	}
	var raw json.RawMessage
	create := map[string]any{"name": b.journal.Name, "nonce": b.journal.Nonce}
	if snapshot != "" {
		create["workload"] = true
		create["snapshot_id"] = snapshot
		create["network_allow_list"] = network
	}
	if b.journal.Volume != nil {
		create["volume_binding"] = b.journal.Volume
	}
	if e = b.call(ctx, "create", create, &raw); e != nil {
		return b, e
	}
	var minimal struct{ ID string }
	if json.Unmarshal(raw, &minimal) != nil || !daytonaID.MatchString(minimal.ID) {
		return b, errors.New("Daytona create returned no valid ID; retain intent")
	}
	b.journal.ID = minimal.ID
	if e = b.save(); e != nil {
		return b, e
	}
	if b.volume != nil {
		if e = b.volume.consumerCreated(b.state, b.ID()); e != nil {
			return b, e
		}
	}
	var d daytonaInfo
	if json.Unmarshal(raw, &d) != nil {
		return b, errors.New("Daytona create metadata invalid; ID retained")
	}
	d, e = b.lookup(ctx)
	if e != nil {
		return b, e
	}
	born, e := time.Parse(time.RFC3339Nano, d.Born)
	if e != nil || born.Before(b.journal.Requested.Add(-time.Minute)) || born.After(b.journal.Requested.Add(2*time.Minute)) || d.Organization == "" {
		return b, errors.New("Daytona create identity timestamp unavailable")
	}
	b.journal.Born = d.Born
	b.journal.Organization = d.Organization
	if e = b.save(); e != nil {
		return b, e
	}
	for {
		d, e := b.lookup(ctx)
		if e != nil {
			return b, e
		}
		if e = b.match(d); e != nil {
			return b, e
		}
		switch d.State {
		case "started":
			return b, nil
		case "creating", "starting", "pulling_snapshot":
		default:
			return b, errors.New("Daytona startup stopped; no implicit resume")
		}
		select {
		case <-ctx.Done():
			return b, errors.New("Daytona startup deadline")
		case <-time.After(time.Second):
		}
	}
}
func (b *DaytonaBox) params() map[string]any {
	p := map[string]any{"id": b.ID(), "nonce": b.journal.Nonce, "born": b.journal.Born, "organization": b.journal.Organization, "boot": b.boot}
	if b.journal.Volume != nil {
		p["volume_binding"] = b.journal.Volume
	}
	return p
}
func (b *DaytonaBox) lookup(ctx context.Context) (daytonaInfo, error) {
	var d daytonaInfo
	e := b.call(ctx, "lookup", map[string]any{"id": b.ID(), "workload": b.journal.SnapshotID != ""}, &d)
	return d, e
}
func (b *DaytonaBox) match(d daytonaInfo) error {
	if d.Absent || d.ID != b.ID() || d.Name != b.journal.Name || d.Born != b.journal.Born || d.Organization != b.journal.Organization || d.Labels["sandprobe_run"] != b.journal.Nonce {
		return errors.New("Daytona ownership mismatch")
	}
	volumeCount := 0
	if b.journal.Volume != nil {
		volumeCount = 1
		if b.volume == nil || b.journal.Volume.ID != b.volume.ID() || d.Organization != b.volume.journal.Organization || len(d.VolumeBindings) != 1 || d.VolumeBindings[0] != *b.journal.Volume {
			return errors.New("Daytona persistent workspace binding changed")
		}
	}
	if d.Public == nil || *d.Public || d.AutoDelete == nil || *d.AutoDelete != 0 || d.AutoStop == nil || *d.AutoStop != 15 || d.AutoPause == nil || *d.AutoPause != 0 || d.Volumes == nil || *d.Volumes != volumeCount || len(d.VolumeBindings) != volumeCount {
		return errors.New("Daytona lifecycle/private policy mismatch")
	}
	if b.journal.SnapshotID != "" {
		b.workloadChecks = map[string]bool{"snapshot_matches": d.SnapshotID == b.journal.SnapshotID, "allow_list_matches": d.NetworkAllowList == b.journal.NetworkAllowList, "management_user_root": d.User == "root", "block_all_explicit": d.NetworkBlockAll != nil && *d.NetworkBlockAll, "domain_filter_unset": d.DomainAllowList == "", "toolbox_proxy_matches": d.Proxy == "https://proxy.app.daytona.io/toolbox"}
	}
	if b.journal.SnapshotID != "" && (d.SnapshotID != b.journal.SnapshotID || d.NetworkAllowList != b.journal.NetworkAllowList || d.User != "root" || (d.NetworkBlockAll != nil && *d.NetworkBlockAll) || d.DomainAllowList != "") {
		return errors.New("Daytona workload configuration changed")
	}
	return nil
}
func (b *DaytonaBox) command(ctx context.Context, script string) ([]byte, error) {
	in := b.params()
	in["command"] = script
	var d struct {
		ID, Stdout string
		Exit       *int `json:"exit_code"`
	}
	// EVD-7: b.call already records this SDK invocation.
	e := b.call(ctx, "exec", in, &d)
	if e != nil {
		return nil, e
	}
	if d.ID != b.ID() || d.Exit == nil || *d.Exit != 0 {
		return nil, errors.New("Daytona execution proof invalid")
	}
	return []byte(d.Stdout), nil
}
func (b *DaytonaBox) DetectArch(ctx context.Context) error {
	out, e := b.command(ctx, "uname -m")
	if e != nil {
		return e
	}
	switch strings.TrimSpace(string(out)) {
	case "x86_64":
		b.Arch = "amd64"
	case "arm64", "aarch64":
		b.Arch = "arm64"
	default:
		return errors.New("Daytona unsupported architecture")
	}
	out, e = b.command(ctx, "cat /proc/sys/kernel/random/boot_id")
	if e != nil {
		return e
	}
	b.boot = strings.TrimSpace(string(out))
	if !daytonaID.MatchString(b.boot) {
		return errors.New("Daytona boot identity invalid")
	}
	return nil
}
func (b *DaytonaBox) writeFile(ctx context.Context, path string, data []byte) error {
	if !daytonaDir.MatchString(filepath.Dir(path)) || len(data) > 16*1024*1024 {
		return errors.New("Daytona upload path/size invalid")
	}
	in := b.params()
	in["path"] = path
	in["data"] = base64.StdEncoding.EncodeToString(data)
	in["workload"] = b.journal.SnapshotID != ""
	var d struct {
		ID       string
		Uploaded bool
	}
	if e := b.call(ctx, "upload", in, &d); e != nil {
		return e
	}
	if d.ID != b.ID() || !d.Uploaded {
		return errors.New("Daytona upload proof invalid")
	}
	return nil
}
func (b *DaytonaBox) Upload(ctx context.Context, bin []byte) error {
	out, e := b.command(ctx, "umask 077; mktemp -d /tmp/.sandprobe-XXXXXXXXXXXX")
	if e != nil {
		return e
	}
	dir := strings.TrimSpace(string(out))
	if !daytonaDir.MatchString(dir) {
		return errors.New("Daytona private path invalid")
	}
	b.ProbePath = dir + "/probe"
	if e = b.writeFile(ctx, b.ProbePath, bin); e != nil {
		return e
	}
	if b.journal.SnapshotID != "" {
		out, e = b.rootCommand(ctx, "chmod 700 "+b.ProbePath+" && sha256sum "+b.ProbePath)
	} else {
		out, e = b.command(ctx, "chmod 700 "+b.ProbePath+" && sha256sum "+b.ProbePath)
	}
	if e != nil {
		return e
	}
	sum := sha256.Sum256(bin)
	fields := strings.Fields(string(out))
	if len(fields) != 2 || fields[0] != hex.EncodeToString(sum[:]) || fields[1] != b.ProbePath {
		return errors.New("Daytona probe digest mismatch")
	}
	return nil
}
func (b *DaytonaBox) Probe(ctx context.Context, args []string, input []byte) ([]byte, error) {
	if !daytonaDir.MatchString(filepath.Dir(b.ProbePath)) || filepath.Base(b.ProbePath) != "probe" {
		return nil, errors.New("Daytona probe unavailable")
	}
	suffix := ""
	if len(args) == 1 && args[0] == "-survey" {
		suffix = " -survey"
	} else if len(args) == 1 && args[0] == "-receiver" {
		suffix = " -receiver"
	} else if len(args) == 1 && (args[0] == "-mark" || args[0] == "-recheck") && b.journal.Volume != nil {
		suffix = " " + args[0]
	} else if len(args) != 0 {
		return nil, errors.New("Daytona probe mode invalid")
	}
	in := filepath.Dir(b.ProbePath) + "/input-" + token("i")
	if e := b.writeFile(ctx, in, input); e != nil {
		return nil, e
	}
	prefix := b.probePrefix
	if prefix != "" {
		prefix = "cd /workspace && " + prefix
	}
	script := "trap 'rm -f " + in + "' EXIT; " + prefix + b.ProbePath + suffix + " < " + in
	if b.journal.SnapshotID != "" {
		return b.rootCommand(ctx, script)
	}
	return b.command(ctx, script)
}

// Cleanup does not depend on snapshot/network APIs remaining available.
func (b *DaytonaBox) cleanupLookup(ctx context.Context) (daytonaInfo, error) {
	var d daytonaInfo
	e := b.call(ctx, "lookup", map[string]any{"id": b.ID()}, &d)
	return d, e
}
func (b *DaytonaBox) Destroy(ctx context.Context) error {
	if b.gone {
		return nil
	}
	if b.ID() == "" {
		return errors.New("Daytona create unresolved; preserve intent")
	}
	d, e := b.cleanupLookup(ctx)
	if e != nil {
		return e
	}
	if d.Absent {
		b.CleanupProof = "provider lookup404"
		return b.retire()
	}
	if d.ID != b.ID() || d.Labels["sandprobe_run"] != b.journal.Nonce || (b.journal.Born != "" && d.Born != b.journal.Born) {
		return errors.New("Daytona cleanup ownership mismatch")
	}
	if d.State != "destroyed" {
		var result struct {
			ID      string
			Deleted bool `json:"deleted_request"`
		}
		if e = b.call(ctx, "delete", b.params(), &result); e != nil {
			return e
		}
		if result.ID != b.ID() || !result.Deleted {
			return errors.New("Daytona deletion request unconfirmed")
		}
	}
	for {
		d, e = b.cleanupLookup(ctx)
		if e != nil {
			return e
		}
		if d.Absent {
			b.CleanupProof = "provider lookup404"
			return b.retire()
		}
		if d.ID != b.ID() || d.Labels["sandprobe_run"] != b.journal.Nonce {
			return errors.New("Daytona deletion identity changed")
		}
		if d.State == "destroyed" && d.Desired == "destroyed" {
			b.CleanupProof = "provider state=destroyed/desiredState=destroyed; terminal metadata may remain"
			return b.retire()
		}
		select {
		case <-ctx.Done():
			return errors.New("Daytona deletion deadline")
		case <-time.After(time.Second):
		}
	}
}
func (b *DaytonaBox) retire() error {
	if b.volume != nil {
		if err := b.volume.consumerGone(b); err != nil {
			return err
		}
	}
	if os.Remove(b.state) != nil {
		return errors.New("Daytona journal retirement failed")
	}
	b.gone = true
	return nil
}
func DaytonaExclusions() map[string]string {
	return map[string]string{"SEC-4": "Daytona scope excludes metadata (PRV-12)", "EGR-3": "Daytona scope excludes provider proxy requests (PRV-12)", "AMP-6": "Daytona scope excludes vsock requests (PRV-12)", "AMP-7": "Daytona scope excludes Kubernetes API requests (PRV-12)"}
}

func DaytonaKey(file string) (string, error) {
	key := os.Getenv("DAYTONA_API_KEY")
	if file != "" {
		f, err := os.OpenFile(file, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return "", errors.New("Daytona token file unavailable")
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
			return "", errors.New("Daytona token file must be regular and owner-only")
		}
		owner, ok := st.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != uint32(os.Getuid()) {
			return "", errors.New("Daytona token file not owned")
		}
		raw, err := io.ReadAll(io.LimitReader(f, 8193))
		if err != nil || len(raw) > 8192 {
			return "", errors.New("Daytona token file invalid")
		}
		key = strings.TrimSpace(string(raw))
	}
	if !validVercelKey(key) {
		return "", errors.New("Daytona token missing or malformed")
	}
	return key, nil
}
