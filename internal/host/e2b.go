package host

// PRV-8: E2B management is native HTTP; only runtime transport uses the pinned SDK.
import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"sandprobe/internal/obs"
)

const E2BSDKVersion = "2.63.0"
const E2BResidual = "E2B base template as user, exec mode; no persistent volumes or reset. PER-5 and provider endpoint checks are skipped. An ambiguous create keeps its journal and relies on the requested 900-second expiry; no name-based cleanup."

//go:embed e2b_runtime.py
var e2bRuntime string

var e2bID = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,127}$`)
var e2bVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)

type E2BClient struct {
	key, python, endpoint string
	http                  *http.Client
	runtime               func(context.Context, map[string]any) ([]byte, error)
}
type e2bError struct{ code int }

func (e *e2bError) Error() string { return fmt.Sprintf("E2B HTTP %d", e.code) }
func e2bStatus(err error, code int) bool {
	var e *e2bError
	return errors.As(err, &e) && e.code == code
}

func E2BKey(file string) (string, error) {
	key := os.Getenv("E2B_API_KEY")
	if file != "" {
		f, err := os.OpenFile(file, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return "", errors.New("E2B key file cannot be opened")
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
			return "", errors.New("E2B key file must be regular and owner-only")
		}
		owner, ok := st.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != uint32(os.Getuid()) {
			return "", errors.New("E2B key file belongs to another user")
		}
		raw, err := io.ReadAll(io.LimitReader(f, 8193))
		if err != nil || len(raw) > 8192 {
			return "", errors.New("E2B key file invalid")
		}
		key = strings.TrimSpace(string(raw))
	}
	if key == "" || len(key) > 8192 || strings.IndexFunc(key, func(r rune) bool { return r <= 32 || r >= 127 }) >= 0 {
		return "", errors.New("E2B API key missing or malformed")
	}
	return key, nil
}
func NewE2BClient(key, python string) (*E2BClient, error) {
	if key == "" || len(key) > 8192 || strings.IndexFunc(key, func(r rune) bool { return r <= 32 || r >= 127 }) >= 0 {
		return nil, errors.New("E2B API key missing or malformed")
	}
	if python == "" {
		python = "python3"
	}
	c := &E2BClient{key: key, python: python, endpoint: "https://api.e2b.app", http: &http.Client{Timeout: 120 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	c.runtime = c.runSDK
	return c, nil
}
func (c *E2BClient) request(ctx context.Context, method, path string, body any, out any) error {
	var raw []byte
	if body != nil {
		var err error
		raw, err = json.Marshal(body)
		if err != nil {
			return errors.New("E2B request invalid")
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.endpoint+path, bytes.NewReader(raw))
	if err != nil {
		return errors.New("E2B request invalid")
	}
	req.Header.Set("X-API-Key", c.key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return errors.New("E2B request failed (transport or deadline)")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &e2bError{resp.StatusCode}
	}
	if out == nil {
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, obs.MaxDoc+1))
	if err != nil || len(data) > obs.MaxDoc || json.Unmarshal(data, out) != nil {
		return errors.New("E2B response incomplete, oversized or malformed")
	}
	return nil
}
func (c *E2BClient) Available(ctx context.Context) error {
	return c.request(ctx, "GET", "/sandboxes?limit=1", nil, new(json.RawMessage))
}
func (c *E2BClient) CheckSDK(ctx context.Context) error {
	raw, err := c.runtime(ctx, map[string]any{"op": "check"})
	if err != nil {
		return err
	}
	var r struct {
		Version string `json:"version"`
	}
	if json.Unmarshal(raw, &r) != nil || r.Version != E2BSDKVersion {
		return errors.New("E2B SDK version must be " + E2BSDKVersion)
	}
	return nil
}

type cappedE2BOutput struct{ bytes.Buffer }

func (b *cappedE2BOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > obs.MaxDoc {
		return 0, errors.New("E2B runtime output exceeds limit")
	}
	return b.Buffer.Write(p)
}
func (c *E2BClient) runSDK(ctx context.Context, in map[string]any) ([]byte, error) {
	raw, err := json.Marshal(in)
	if err != nil {
		return nil, errors.New("E2B runtime input invalid")
	}
	ctx, cancel := context.WithTimeout(ctx, 110*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.python, "-I", "-c", e2bRuntime)
	// No host credentials, endpoint overrides, proxies, PYTHONPATH, or SDK logging configuration.
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "LANG=C.UTF-8"}
	cmd.Stdin = bytes.NewReader(raw)
	var out cappedE2BOutput
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	if cmd.Run() != nil {
		return nil, errors.New("E2B runtime helper failed (SDK, command, output limit or deadline)")
	}
	return out.Bytes(), nil
}

type e2bIdentity struct {
	ID       string `json:"sandboxID"`
	Template string `json:"templateID"`
	Domain   string `json:"domain"`
	Version  string `json:"envdVersion"`
}
type e2bSandbox struct {
	e2bIdentity
	Token    string            `json:"envdAccessToken"`
	Metadata map[string]string `json:"metadata"`
	Started  time.Time         `json:"startedAt"`
	End      time.Time         `json:"endAt"`
	State    string            `json:"state"`
}
type e2bJournal struct {
	Marker    string    `json:"marker"`
	ID        string    `json:"sandbox_id,omitempty"`
	CreatedAt time.Time `json:"create_requested_at"`
}
type E2BBox struct {
	client          *E2BClient
	identity        e2bIdentity
	access          string
	journal         e2bJournal
	state           string
	Arch, ProbePath string
	Calls           []obs.ProviderCall
	gone            bool
}

func (b *E2BBox) ID() string        { return b.journal.ID }
func (b *E2BBox) StatePath() string { return b.state }
func (b *E2BBox) record(at time.Time, call string, err error) {
	status := "ok"
	if err != nil {
		status = "error"
	}
	b.Calls = append(b.Calls, obs.ProviderCall{At: at, Call: "E2B " + call, ID: b.ID(), Status: status})
}
func (b *E2BBox) save() error {
	data, _ := json.MarshalIndent(b.journal, "", "  ")
	f, err := os.CreateTemp(filepath.Dir(b.state), ".e2b-state-*")
	if err != nil {
		return errors.New("E2B journal cannot be written")
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(f.Name(), b.state)
	}
	if err != nil {
		return errors.New("E2B journal cannot be persisted")
	}
	return nil
}
func (c *E2BClient) CreateE2B(ctx context.Context, dir string) (*E2BBox, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, errors.New("E2B journal directory unavailable")
	}
	st, err := os.Lstat(dir)
	if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0022 != 0 {
		return nil, errors.New("E2B journal directory unsafe")
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Getuid()) {
		return nil, errors.New("E2B journal directory not owned")
	}
	marker := token("sandprobe-")
	b := &E2BBox{client: c, journal: e2bJournal{Marker: marker, CreatedAt: time.Now().UTC()}, state: filepath.Join(dir, "e2b-"+marker+".state")}
	if err = b.save(); err != nil {
		return nil, err
	}
	var response json.RawMessage
	at := time.Now()
	err = c.request(ctx, "POST", "/v2/sandboxes", map[string]any{"templateID": "base", "timeout": 900, "autoPause": false, "secure": true, "allow_internet_access": true, "envVars": map[string]string{}, "metadata": map[string]string{"sandprobe_run": marker}}, &response)
	// Persist any valid create-returned ID before validating the runtime connection.
	var envelope struct {
		ID string `json:"sandboxID"`
	}
	if err == nil && json.Unmarshal(response, &envelope) == nil && e2bID.MatchString(envelope.ID) {
		b.journal.ID = envelope.ID
		if saveErr := b.save(); saveErr != nil {
			err = errors.Join(err, saveErr)
		}
	}
	var s e2bSandbox
	if err == nil && json.Unmarshal(response, &s) != nil {
		err = errors.New("E2B create response fields malformed")
	}
	b.identity, b.access = s.e2bIdentity, s.Token
	b.record(at, "create sandbox", err)
	if err != nil {
		return b, err
	}
	if b.ID() == "" || s.Template == "" || !validE2BDomain(s.Domain) || !e2bVersion.MatchString(s.Version) || s.Token == "" || len(s.Token) > 8192 || strings.IndexFunc(s.Token, func(r rune) bool { return r <= 32 || r >= 127 }) >= 0 {
		return b, errors.New("E2B create response identity or access token invalid")
	}
	if err = b.ours(ctx); err != nil {
		return b, err
	}
	return b, nil
}
func validE2BDomain(d string) bool { return d == "" || d == "e2b.app" } // PRV-8: managed cloud only.
func (b *E2BBox) lookup(ctx context.Context) (e2bSandbox, error) {
	var s e2bSandbox
	at := time.Now()
	err := b.client.request(ctx, "GET", "/sandboxes/"+b.ID(), nil, &s)
	b.record(at, "get recorded sandbox", err)
	return s, err
}
func (b *E2BBox) ours(ctx context.Context) error {
	if b.gone || !e2bID.MatchString(b.ID()) {
		return errors.New("E2B sandbox absent or creation unresolved")
	}
	s, err := b.lookup(ctx)
	if err != nil {
		return err
	}
	if s.ID != b.ID() || s.Metadata["sandprobe_run"] != b.journal.Marker || s.Template != b.identity.Template || s.Version != b.identity.Version || s.Domain != b.identity.Domain {
		return errors.New("E2B sandbox identity mismatch")
	}
	if s.State != "running" || s.Started.IsZero() || s.End.IsZero() || !s.End.After(time.Now()) || s.End.Sub(s.Started) > 901*time.Second || s.End.After(b.journal.CreatedAt.Add(16*time.Minute)) {
		return errors.New("E2B sandbox not running with bounded expiry")
	}
	return nil
}
func (b *E2BBox) sdk(ctx context.Context, in map[string]any) ([]byte, error) {
	if err := b.ours(ctx); err != nil {
		return nil, err
	}
	in["sandbox_id"] = b.ID()
	in["domain"] = b.identity.Domain
	in["envd_version"] = b.identity.Version
	in["access_token"] = b.access
	at := time.Now()
	out, err := b.client.runtime(ctx, in)
	b.record(at, "runtime "+in["op"].(string), err)
	return out, err
}
func (b *E2BBox) command(ctx context.Context, command string) ([]byte, error) {
	return b.sdk(ctx, map[string]any{"op": "exec", "command": command})
}
func (b *E2BBox) DetectArch(ctx context.Context) error {
	out, err := b.command(ctx, "uname -m")
	if err != nil {
		return err
	}
	switch strings.TrimSpace(string(out)) {
	case "x86_64":
		b.Arch = "amd64"
	case "aarch64", "arm64":
		b.Arch = "arm64"
	default:
		return errors.New("E2B unsupported architecture")
	}
	return nil
}
func (b *E2BBox) Upload(ctx context.Context, bin []byte) error {
	dirOut, err := b.command(ctx, "umask 077; mktemp -d /tmp/sandprobe-XXXXXXXXXXXX")
	if err != nil {
		return err
	}
	dir := strings.TrimSpace(string(dirOut))
	if !regexp.MustCompile(`^/tmp/sandprobe-[A-Za-z0-9]{12}$`).MatchString(dir) {
		return errors.New("E2B upload directory invalid")
	}
	b.ProbePath = dir + "/probe"
	if _, err = b.sdk(ctx, map[string]any{"op": "upload", "path": b.ProbePath, "data": bin}); err != nil {
		return err
	}
	out, err := b.command(ctx, "chmod 700 "+b.ProbePath+" && sha256sum "+b.ProbePath)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(bin)
	fields := strings.Fields(string(out))
	if len(fields) != 2 || fields[0] != hex.EncodeToString(sum[:]) || fields[1] != b.ProbePath {
		return errors.New("E2B uploaded probe digest mismatch")
	}
	return nil
}
func (b *E2BBox) Probe(ctx context.Context, args []string, stdin []byte) ([]byte, error) {
	if b.ProbePath == "" {
		return nil, errors.New("E2B probe not uploaded")
	}
	suffix := ""
	if len(args) == 1 && args[0] == "-survey" {
		suffix = " -survey"
	} else if len(args) != 0 {
		return nil, errors.New("E2B unsupported probe mode")
	}
	// The input is probe configuration only. No host API key is ever uploaded.
	input := strings.TrimSuffix(b.ProbePath, "/probe") + "/input-" + token("i")
	if stdin == nil {
		stdin = []byte{}
	}
	if _, err := b.sdk(ctx, map[string]any{"op": "upload", "path": input, "data": stdin}); err != nil {
		return nil, err
	}
	return b.command(ctx, "trap 'rm -f "+input+"' EXIT; chmod 600 "+input+" && "+b.ProbePath+suffix+" < "+input)
}
func (b *E2BBox) Destroy(ctx context.Context) error {
	if b.gone {
		return nil
	}
	if !e2bID.MatchString(b.ID()) {
		return errors.New("E2B creation unresolved; inspect journal; requested 900-second expiry is not verified deletion")
	}
	s, err := b.lookup(ctx)
	if e2bStatus(err, 404) {
		b.gone = true
		return b.retire()
	}
	if err != nil {
		return err
	}
	if s.ID != b.ID() || s.Metadata["sandprobe_run"] != b.journal.Marker {
		return errors.New("E2B cleanup identity mismatch")
	}
	at := time.Now()
	err = b.client.request(ctx, "DELETE", "/sandboxes/"+b.ID(), nil, nil)
	b.record(at, "delete recorded sandbox", err)
	if err != nil && !e2bStatus(err, 404) {
		return err
	}
	for {
		_, err = b.lookup(ctx)
		if e2bStatus(err, 404) {
			b.gone = true
			return b.retire()
		}
		if err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return errors.New("E2B deletion not confirmed before deadline")
		case <-time.After(time.Second):
		}
	}
}
func (b *E2BBox) retire() error {
	if err := os.Remove(b.state); err != nil && !os.IsNotExist(err) {
		return errors.New("E2B deletion confirmed but journal removal failed")
	}
	return nil
}
func E2BExclusions() map[string]string {
	return map[string]string{"SEC-4": "E2B approved scope excludes metadata requests (PRV-8)", "EGR-3": "E2B approved scope excludes guest/provider proxy requests (PRV-8)", "AMP-6": "E2B approved scope excludes host vsock requests (PRV-8)", "AMP-7": "E2B approved scope excludes Kubernetes API requests (PRV-8)"}
}
