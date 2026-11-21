package host

// PRV-11: single create, confined no-env VM, permanent deletion-operation proof.
import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sandprobe/internal/obs"
	"strings"
	"syscall"
	"time"
)

const BoatResidual = "Boat small/base CPU VM with noEnv=true, snapshots=false and monitoring=false explicitly requested. No app/model credentials. Guest boot evidence is self-observed. TTL is auto-archive, not verified deletion; permanent deletion requires completed original-target operation plus sandbox404. Provider audit/backup retention is outside run-owned compute cleanup."

var boatID = regexp.MustCompile(`^bx_[23456789abcdefghjkmnpqrstuvwxyz]{8}$`)
var boatOpID = regexp.MustCompile(`^bdop_[a-f0-9]{32}$`)
var boatFile = regexp.MustCompile(`^/tmp/\.sandprobe-[A-Za-z0-9]{12}/(?:probe(?:\.gz)?|input-i[a-f0-9]{24})$`)
var boatDir = regexp.MustCompile(`^/tmp/\.sandprobe-[A-Za-z0-9]{12}$`)

type BoatClient struct {
	key, endpoint string
	http          *http.Client
}
type boatError struct {
	status    int
	operation string
}

func (e *boatError) Error() string { return fmt.Sprintf("Boat %s HTTP %d", e.operation, e.status) }
func NewBoatClient(key string) (*BoatClient, error) {
	if !validVercelKey(key) {
		return nil, errors.New("Boat key invalid")
	}
	return &BoatClient{key: key, endpoint: "https://boat.dev/api/v1", http: &http.Client{Timeout: 115 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (c *BoatClient) request(ctx context.Context, method, path string, body any, out any) error {
	var data []byte
	if body != nil {
		var e error
		data, e = json.Marshal(body)
		if e != nil {
			return errors.New("Boat request invalid")
		}
	}
	req, e := http.NewRequestWithContext(ctx, method, c.endpoint+path, bytes.NewReader(data))
	if e != nil {
		return errors.New("Boat request invalid")
	}
	req.Header.Set("Authorization", "Bearer "+c.key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Boat-Org", "personal")
	if method == "DELETE" && strings.HasPrefix(path, "/sandboxes/") {
		req.Header.Set("X-Ascii-Confirm-Delete", strings.TrimPrefix(path, "/sandboxes/"))
	}
	resp, e := c.http.Do(req)
	if e != nil {
		return errors.New("Boat transport failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &boatError{resp.StatusCode, method}
	}
	raw, e := io.ReadAll(io.LimitReader(resp.Body, 9*1024*1024+1))
	if e != nil || len(raw) > 9*1024*1024 {
		return errors.New("Boat response limit")
	}
	if json.Unmarshal(raw, out) != nil {
		return errors.New("Boat response invalid")
	}
	return nil
}
func (c *BoatClient) Available(ctx context.Context) error {
	var d struct {
		OK   bool `json:"ok"`
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	if e := c.request(ctx, "GET", "/me", nil, &d); e != nil {
		return e
	}
	if !d.OK || d.User.ID == "" {
		return errors.New("Boat account identity unavailable")
	}
	return nil
}

type boatInfo struct {
	Access             string            `json:"access"`
	HoldsCreatorLogins *bool             `json:"holdsCreatorLogins"`
	WipePending        *bool             `json:"wipePendingUntilRestart"`
	Environment        json.RawMessage   `json:"environment"`
	Team               json.RawMessage   `json:"team"`
	ID                 string            `json:"id"`
	State              string            `json:"state"`
	Created            string            `json:"createdAt"`
	Archive            string            `json:"archiveAfter"`
	TTL                *int              `json:"ttlSeconds"`
	Labels             map[string]string `json:"labels"`
	Snapshots          *bool             `json:"snapshots"`
	Monitoring         *bool             `json:"monitoring"`
}
type boatJournal struct {
	Nonce      string    `json:"nonce"`
	Requested  time.Time `json:"requested"`
	Wallet     string    `json:"wallet"`
	ID         string    `json:"id"`
	Born       string    `json:"born"`
	CreateBorn string    `json:"create_born,omitempty"`
	Operation  string    `json:"deletion_operation,omitempty"`
}
type BoatBox struct {
	client                       *BoatClient
	journal                      boatJournal
	state, boot, ProbePath, Arch string
	Calls                        []obs.ProviderCall
	gone                         bool
}

func (b *BoatBox) request(ctx context.Context, method, path string, body, out any) error {
	at := time.Now()
	e := b.client.request(ctx, method, path, body, out)
	call := obs.ProviderCall{At: at, Call: "Boat " + method + " " + path, OK: e == nil, ID: b.ID()}
	if e != nil {
		call.Error = "provider_error"
	}
	b.Calls = append(b.Calls, call)
	return e
}
func (b *BoatBox) ID() string                { return b.journal.ID }
func (b *BoatBox) StatePath() string         { return b.state }
func (b *BoatBox) DeletionOperation() string { return b.journal.Operation }
func (b *BoatBox) save() error {
	data, _ := json.Marshal(b.journal)
	f, e := os.CreateTemp(filepath.Dir(b.state), ".boat-state-")
	if e != nil {
		return errors.New("Boat state update failed")
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
		return errors.New("Boat state update failed")
	}
	return nil
}
func (c *BoatClient) CreateBoat(ctx context.Context, dir string) (*BoatBox, error) {
	if e := os.MkdirAll(dir, 0700); e != nil {
		return nil, errors.New("Boat journal directory unavailable")
	}
	st, e := os.Lstat(dir)
	if e != nil || !st.IsDir() || st.Mode().Perm()&0022 != 0 {
		return nil, errors.New("Boat journal directory unsafe")
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Getuid()) {
		return nil, errors.New("Boat journal directory not owned")
	}
	b := &BoatBox{client: c, journal: boatJournal{Nonce: token("n"), Requested: time.Now().UTC(), Wallet: "personal"}}
	b.state = filepath.Join(dir, "boat-"+b.journal.Nonce+".state")
	f, e := os.OpenFile(b.state, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return nil, errors.New("Boat intent unavailable")
	}
	data, _ := json.Marshal(b.journal)
	_, e = f.Write(data)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil || ce != nil {
		return b, errors.New("Boat intent write failed")
	}
	var raw json.RawMessage
	body := map[string]any{"type": "small", "ttlSeconds": 900, "environment": "base", "noEnv": true, "snapshots": false, "monitoring": false, "org": "personal", "env": map[string]string{"SANDPROBE_TWIN": "1"}, "labels": map[string]string{"sandprobe_run": b.journal.Nonce}}
	if e = b.request(ctx, "POST", "/sandboxes", body, &raw); e != nil {
		return b, e
	}
	var minimal struct {
		Sandbox struct {
			ID string `json:"id"`
		} `json:"sandbox"`
	}
	if json.Unmarshal(raw, &minimal) != nil || !boatID.MatchString(minimal.Sandbox.ID) {
		return b, errors.New("Boat create returned no valid ID; retain intent")
	}
	b.journal.ID = minimal.Sandbox.ID
	if e = b.save(); e != nil {
		return b, e
	}
	var result struct {
		OK      bool     `json:"ok"`
		Sandbox boatInfo `json:"sandbox"`
	}
	if json.Unmarshal(raw, &result) != nil {
		return b, errors.New("Boat create metadata invalid; ID retained")
	}
	if !result.OK {
		return b, errors.New("Boat create rejected")
	}
	born, e := time.Parse(time.RFC3339Nano, result.Sandbox.Created)
	if e != nil || born.Before(b.journal.Requested.Add(-time.Minute)) || born.After(b.journal.Requested.Add(2*time.Minute)) {
		return b, errors.New("Boat creation timestamp invalid")
	}
	b.journal.CreateBorn = result.Sandbox.Created
	if e = b.save(); e != nil {
		return b, e
	}
	for {
		info, e := b.lookup(ctx)
		if e != nil {
			return b, e
		}
		if e = b.bindBirth(info); e != nil {
			return b, e
		}
		if e = b.match(info); e != nil {
			return b, e
		}
		switch info.State {
		case "ready", "idle", "running":
			return b, nil
		case "init", "provisioning", "provisioned", "cloning":
		default:
			return b, errors.New("Boat startup stopped")
		}
		select {
		case <-ctx.Done():
			return b, errors.New("Boat startup deadline")
		case <-time.After(time.Second):
		}
	}
}
func (b *BoatBox) lookup(ctx context.Context) (boatInfo, error) {
	var d struct {
		OK      bool     `json:"ok"`
		Sandbox boatInfo `json:"sandbox"`
	}
	e := b.request(ctx, "GET", "/sandboxes/"+b.ID(), nil, &d)
	if e != nil {
		return d.Sandbox, e
	}
	if !d.OK {
		return d.Sandbox, errors.New("Boat lookup failed")
	}
	return d.Sandbox, nil
}

// PRV-11: create and persistent read may have different serialization timestamps.
// Pin one fresh lookup birth once; never rebind a later identity change.
func (b *BoatBox) bindBirth(info boatInfo) error {
	if info.ID != b.ID() || info.Labels["sandprobe_run"] != b.journal.Nonce || info.Access != "owner" || string(info.Team) != "null" {
		return errors.New("Boat ownership mismatch")
	}
	born, e := time.Parse(time.RFC3339Nano, info.Created)
	if e != nil || born.Before(b.journal.Requested.Add(-time.Minute)) || born.After(b.journal.Requested.Add(2*time.Minute)) {
		return errors.New("Boat lookup birth invalid")
	}
	if b.journal.Born != "" {
		if info.Created != b.journal.Born {
			return errors.New("Boat canonical birth changed")
		}
		return nil
	}
	if b.journal.CreateBorn != "" {
		created, e := time.Parse(time.RFC3339Nano, b.journal.CreateBorn)
		delta := born.Sub(created)
		if e != nil || delta < -time.Second || delta > time.Second {
			return errors.New("Boat create/read birth mismatch")
		}
	}
	b.journal.Born = info.Created
	return b.save()
}
func (b *BoatBox) match(info boatInfo) error {
	if info.ID != b.ID() || info.Labels["sandprobe_run"] != b.journal.Nonce || (b.journal.Born != "" && info.Created != b.journal.Born) {
		return errors.New("Boat ownership mismatch")
	}
	if (string(info.Environment) != "null" && string(info.Environment) != `"base"`) || string(info.Team) != "null" || info.HoldsCreatorLogins == nil || *info.HoldsCreatorLogins || info.WipePending == nil || *info.WipePending || info.Access != "owner" {
		return errors.New("Boat environment/wallet policy mismatch")
	}
	if b.journal.Born == "" {
		return errors.New("Boat creation timestamp unavailable")
	}
	if info.Snapshots == nil || *info.Snapshots || info.Monitoring == nil || *info.Monitoring || info.TTL == nil || *info.TTL != 900 {
		return errors.New("Boat snapshot/monitoring/TTL policy mismatch")
	}
	deadline, e := time.Parse(time.RFC3339Nano, info.Archive)
	if e != nil || deadline.Before(time.Now()) || deadline.After(b.journal.Requested.Add(16*time.Minute)) {
		return errors.New("Boat archive deadline invalid")
	}
	return nil
}
func (b *BoatBox) commandRaw(ctx context.Context, script string) ([]byte, error) {
	var d struct {
		OK              *bool  `json:"ok"`
		Success         *bool  `json:"success"`
		Exit            *int   `json:"exitCode"`
		Out             string `json:"stdout"`
		Truncated       *bool  `json:"stdoutTruncated"`
		StderrTruncated *bool  `json:"stderrTruncated"`
		TimedOut        *bool  `json:"timedOut"`
		OOM             bool   `json:"oomKilled"`
	}
	e := b.request(ctx, "POST", "/sandboxes/"+b.ID()+"/commands", map[string]any{"command": "SANDPROBE_TWIN=1 " + script, "timeoutSeconds": 95, "detached": false, "stream": false}, &d)
	if e != nil {
		return nil, e
	}
	if d.OK == nil || !*d.OK || d.Success == nil || !*d.Success || d.Exit == nil || *d.Exit != 0 || d.Truncated == nil || *d.Truncated || d.TimedOut == nil || *d.TimedOut || d.OOM || d.StderrTruncated == nil || *d.StderrTruncated || len(d.Out) > obs.MaxDoc {
		return nil, errors.New("Boat command incomplete, failed or truncated")
	}
	return []byte(d.Out), nil
}
func (b *BoatBox) command(ctx context.Context, script string) ([]byte, error) {
	info, e := b.lookup(ctx)
	if e != nil {
		return nil, e
	}
	if e = b.match(info); e != nil {
		return nil, e
	}
	if info.State != "ready" && info.State != "idle" && info.State != "running" {
		return nil, errors.New("Boat is not running; no resume")
	}
	if b.boot != "" {
		out, e := b.commandRaw(ctx, "cat /proc/sys/kernel/random/boot_id")
		if e != nil {
			return nil, e
		}
		if strings.TrimSpace(string(out)) != b.boot {
			return nil, errors.New("Boat boot identity changed")
		}
	}
	return b.commandRaw(ctx, script)
}
func (b *BoatBox) DetectArch(ctx context.Context) error {
	out, e := b.command(ctx, "uname -m")
	if e != nil {
		return e
	}
	switch strings.TrimSpace(string(out)) {
	case "x86_64":
		b.Arch = "amd64"
	case "aarch64", "arm64":
		b.Arch = "arm64"
	default:
		return errors.New("Boat architecture unsupported")
	}
	out, e = b.command(ctx, "cat /proc/sys/kernel/random/boot_id")
	if e != nil {
		return e
	}
	b.boot = strings.TrimSpace(string(out))
	if !cfBoot.MatchString(b.boot) {
		return errors.New("Boat boot identity invalid")
	}
	return nil
}
func (b *BoatBox) writeFile(ctx context.Context, path string, data []byte) error {
	if !boatFile.MatchString(path) || len(data) > 5*1024*1024 {
		return errors.New("Boat file path/size invalid")
	}
	info, e := b.lookup(ctx)
	if e != nil {
		return e
	}
	if e = b.match(info); e != nil {
		return e
	}
	if info.State != "ready" && info.State != "idle" && info.State != "running" {
		return errors.New("Boat upload refused; no resume")
	}
	if b.boot != "" {
		out, e := b.commandRaw(ctx, "cat /proc/sys/kernel/random/boot_id")
		if e != nil {
			return e
		}
		if strings.TrimSpace(string(out)) != b.boot {
			return errors.New("Boat boot identity changed before upload")
		}
	}
	var d struct {
		OK      *bool  `json:"ok"`
		Success *bool  `json:"success"`
		Path    string `json:"path"`
		Size    *int   `json:"size"`
	}
	if e = b.request(ctx, "PUT", "/sandboxes/"+b.ID()+"/files", map[string]any{"path": path, "content": base64.StdEncoding.EncodeToString(data), "encoding": "base64"}, &d); e != nil {
		return e
	}
	if d.OK == nil || !*d.OK || d.Success == nil || !*d.Success || d.Size == nil || *d.Size < 0 {
		size := -1
		if d.Size != nil {
			size = *d.Size
		}
		return fmt.Errorf("Boat upload acknowledgment invalid (ok=%t success=%t path_match=%t size=%d decoded_bytes=%d)", d.OK != nil && *d.OK, d.Success != nil && *d.Success, d.Path == path, size, len(data))
	}
	b.Calls = append(b.Calls, obs.ProviderCall{At: time.Now(), Call: fmt.Sprintf("Boat upload acknowledgment path_match=%t declared_size=%d decoded_bytes=%d", d.Path == path, *d.Size, len(data)), OK: true, ID: b.ID()})
	// The API does not define size units or canonical echo spelling. Digest of the requested path, not metadata, proves bytes.
	out, e := b.command(ctx, "sha256sum "+path)
	if e != nil {
		return e
	}
	sum := sha256.Sum256(data)
	fields := strings.Fields(string(out))
	if len(fields) != 2 || fields[0] != hex.EncodeToString(sum[:]) || fields[1] != path {
		return errors.New("Boat uploaded-file digest mismatch")
	}

	return nil
}
func (b *BoatBox) Upload(ctx context.Context, bin []byte) error {
	out, e := b.command(ctx, "umask 077; mktemp -d /tmp/.sandprobe-XXXXXXXXXXXX")
	if e != nil {
		return e
	}
	dir := strings.TrimSpace(string(out))
	if !boatDir.MatchString(dir) {
		return errors.New("Boat private path invalid")
	}
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	if _, e = gz.Write(bin); e != nil {
		return errors.New("Boat compression failed")
	}
	if gz.Close() != nil {
		return errors.New("Boat compression failed")
	}
	if e = b.writeFile(ctx, dir+"/probe.gz", compressed.Bytes()); e != nil {
		return e
	}
	b.ProbePath = dir + "/probe"
	out, e = b.command(ctx, "gzip -d "+dir+"/probe.gz && chmod 700 "+b.ProbePath+" && sha256sum "+b.ProbePath)
	if e != nil {
		return e
	}
	sum := sha256.Sum256(bin)
	fields := strings.Fields(string(out))
	if len(fields) != 2 || fields[0] != hex.EncodeToString(sum[:]) || fields[1] != b.ProbePath {
		return errors.New("Boat probe digest mismatch")
	}
	return nil
}
func (b *BoatBox) Probe(ctx context.Context, args []string, input []byte) ([]byte, error) {
	if !boatFile.MatchString(b.ProbePath) || filepath.Base(b.ProbePath) != "probe" {
		return nil, errors.New("Boat probe unavailable")
	}
	suffix := ""
	if len(args) == 1 && args[0] == "-survey" {
		suffix = " -survey"
	} else if len(args) != 0 {
		return nil, errors.New("Boat probe mode invalid")
	}
	in := filepath.Dir(b.ProbePath) + "/input-" + token("i")
	if e := b.writeFile(ctx, in, input); e != nil {
		return nil, e
	}
	return b.command(ctx, "sh -c 'trap \"rm -f "+in+"\" EXIT; "+b.ProbePath+suffix+" < "+in+"'")
}
func (b *BoatBox) Destroy(ctx context.Context) error {
	if b.gone {
		return nil
	}
	if b.ID() == "" {
		return errors.New("Boat create unresolved; retain intent, no adoption")
	}
	if b.journal.Operation == "" {
		info, e := b.lookup(ctx)
		if e != nil {
			return e
		}
		if e = b.bindBirth(info); e != nil {
			return e
		}
		var d struct {
			OK        bool `json:"ok"`
			Operation struct {
				ID     string `json:"id"`
				Kind   string `json:"kind"`
				Target string `json:"targetId"`
			} `json:"operation"`
		}
		if e = b.request(ctx, "DELETE", "/sandboxes/"+b.ID(), nil, &d); e != nil {
			return e
		}
		if !d.OK || !boatOpID.MatchString(d.Operation.ID) || d.Operation.Kind != "sandbox" || d.Operation.Target != b.ID() {
			return errors.New("Boat deletion operation invalid")
		}
		b.journal.Operation = d.Operation.ID
		if e = b.save(); e != nil {
			return e
		}
	}
	for {
		var d struct {
			OK        bool `json:"ok"`
			Operation struct {
				ID, Kind, Status string
				Target           string `json:"targetId"`
			} `json:"operation"`
		}
		if e := b.request(ctx, "GET", "/deletion-operations/"+b.journal.Operation, nil, &d); e != nil {
			return e
		}
		op := d.Operation
		if !d.OK || op.ID != b.journal.Operation || op.Kind != "sandbox" || op.Target != b.ID() {
			return errors.New("Boat deletion identity mismatch")
		}
		if op.Status == "completed" {
			break
		}
		if op.Status != "pending" && op.Status != "processing" {
			return errors.New("Boat deletion blocked")
		}
		select {
		case <-ctx.Done():
			return errors.New("Boat cleanup deadline")
		case <-time.After(time.Second):
		}
	}
	_, e := b.lookup(ctx)
	var httpErr *boatError
	if !errors.As(e, &httpErr) || httpErr.status != 404 {
		return errors.New("Boat sandbox absence unconfirmed")
	}
	if os.Remove(b.state) != nil {
		return errors.New("Boat journal retirement failed")
	}
	b.gone = true
	return nil
}
func BoatExclusions() map[string]string {
	return map[string]string{"SEC-4": "Boat scope excludes metadata (PRV-11)", "EGR-3": "Boat scope excludes provider proxy requests (PRV-11)", "AMP-6": "Boat scope excludes vsock requests (PRV-11)", "AMP-7": "Boat scope excludes Kubernetes API requests (PRV-11)"}
}

func BoatKey(file string) (string, error) {
	key := os.Getenv("BOAT_API_KEY")
	if file != "" {
		f, err := os.OpenFile(file, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return "", errors.New("Boat token file unavailable")
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
			return "", errors.New("Boat token file must be regular and owner-only")
		}
		owner, ok := st.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != uint32(os.Getuid()) {
			return "", errors.New("Boat token file not owned")
		}
		raw, err := io.ReadAll(io.LimitReader(f, 8193))
		if err != nil || len(raw) > 8192 {
			return "", errors.New("Boat token file invalid")
		}
		key = strings.TrimSpace(string(raw))
	}
	if !validVercelKey(key) {
		return "", errors.New("Boat token missing or malformed")
	}
	return key, nil
}
