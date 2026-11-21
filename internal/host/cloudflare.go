package host

// PRV-10: a one-run controller capability, never the Cloudflare management token.
import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sandprobe/internal/obs"
	"strings"
	"syscall"
	"time"
)

const CloudflareResidual = "Exec-mode native Durable Object Container API with built-in cloudflare/debian-trixie, durable_object scheduling and Internet enabled. Native exec inherits PATH, not the full image environment. DO ID is immutable; guest boot identity is self-observed. No host escape attestation. Controller Worker/application/namespace must also be removed by deploy/cloudflare/manage.py down; name-based Worker deletion has a guarded check/delete race."

var cfHex = regexp.MustCompile(`^[a-f0-9]{64}$`)
var cfNonce = regexp.MustCompile(`^[a-f0-9]{32}$`)
var cfDir = regexp.MustCompile(`^/tmp/\.sandprobe-[A-Za-z0-9]{12}$`)
var cfBoot = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

type CloudflareSetup struct {
	Origin     string `json:"origin"`
	Capability string `json:"capability"`
	Nonce      string `json:"nonce"`
	Account    string `json:"account"`
}
type CloudflareBox struct {
	setup                      CloudflareSetup
	http                       *http.Client
	state, id, boot, ProbePath string
	Arch                       string
	ownedIntent                bool
	Calls                      []obs.ProviderCall
}

func NewCloudflareBox(file string) (*CloudflareBox, error) {
	parent, e := os.Lstat(filepath.Dir(file))
	if e != nil || !parent.IsDir() || parent.Mode().Perm()&0022 != 0 {
		return nil, errors.New("Cloudflare setup directory unsafe")
	}
	parentOwner, ok := parent.Sys().(*syscall.Stat_t)
	if !ok || parentOwner.Uid != uint32(os.Getuid()) {
		return nil, errors.New("Cloudflare setup directory owner invalid")
	}

	f, e := os.OpenFile(file, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, errors.New("Cloudflare private setup unavailable")
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 {
		return nil, errors.New("Cloudflare setup must be regular mode 0600")
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Getuid()) {
		return nil, errors.New("Cloudflare setup owner invalid")
	}
	data, e := io.ReadAll(io.LimitReader(f, 65537))
	var setup CloudflareSetup
	if e != nil || len(data) > 65536 || json.Unmarshal(data, &setup) != nil {
		return nil, errors.New("Cloudflare setup invalid")
	}
	u, e := url.Parse(setup.Origin)
	if e != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || !strings.HasSuffix(u.Hostname(), ".workers.dev") || u.Hostname() != u.Host || !cfHex.MatchString(setup.Capability) || !cfNonce.MatchString(setup.Nonce) || !regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(setup.Account) {
		return nil, errors.New("Cloudflare setup identity invalid")
	}
	return &CloudflareBox{setup: setup, state: file + ".box.state", http: &http.Client{Timeout: 110 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (b *CloudflareBox) ID() string        { return b.id }
func (b *CloudflareBox) StatePath() string { return b.state }
func (b *CloudflareBox) call(ctx context.Context, path string, body []byte, dir string, out any) (err error) {
	at := time.Now()
	defer func() {
		c := obs.ProviderCall{At: at, Call: "Cloudflare " + path, OK: err == nil, ID: b.id}
		if err != nil {
			c.Error = "provider_error"
		}
		b.Calls = append(b.Calls, c)
	}()
	req, e := http.NewRequestWithContext(ctx, "POST", b.setup.Origin+path, bytes.NewReader(body))
	if e != nil {
		return errors.New("Cloudflare request invalid")
	}
	req.Header.Set("Authorization", "Bearer "+b.setup.Capability)
	req.Header.Set("X-Sandprobe-Run", b.setup.Nonce)
	req.Header.Set("X-Sandprobe-ID", b.id)
	req.Header.Set("X-Sandprobe-Boot", b.boot)
	req.Header.Set("Content-Type", "application/json")
	if dir != "" {
		req.Header.Set("X-Sandprobe-Dir", dir)
		req.Header.Set("Content-Type", "application/octet-stream")
	}
	resp, e := b.http.Do(req)
	if e != nil {
		return errors.New("Cloudflare controller transport failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("Cloudflare controller %s HTTP %d", path, resp.StatusCode)
	}
	data, e := io.ReadAll(io.LimitReader(resp.Body, 9*1024*1024+1))
	if e != nil || len(data) > 9*1024*1024 {
		return errors.New("Cloudflare controller response limit")
	}
	if json.Unmarshal(data, out) != nil {
		return errors.New("Cloudflare controller response invalid")
	}
	return nil
}

type cfStatus struct {
	ID      string `json:"id"`
	Closed  bool   `json:"closed"`
	Running bool   `json:"running"`
	Created bool   `json:"created"`
}

// PRV-10: missing lifecycle fields cannot prove cleanup or freshness.
func (s *cfStatus) UnmarshalJSON(data []byte) error {
	var wire struct {
		ID      string `json:"id"`
		Closed  *bool  `json:"closed"`
		Running *bool  `json:"running"`
		Created *bool  `json:"created"`
	}
	if json.Unmarshal(data, &wire) != nil || wire.Closed == nil || wire.Running == nil || wire.Created == nil || !cfHex.MatchString(wire.ID) {
		return errors.New("Cloudflare status evidence missing")
	}
	s.ID = wire.ID
	s.Closed = *wire.Closed
	s.Running = *wire.Running
	s.Created = *wire.Created
	return nil
}
func (b *CloudflareBox) Create(ctx context.Context) error {
	var before cfStatus
	if e := b.call(ctx, "/status", []byte(`{}`), "", &before); e != nil {
		return e
	}
	if !cfHex.MatchString(before.ID) || before.Running || before.Closed || before.Created {
		return errors.New("Cloudflare controller is not fresh")
	}
	candidate := before.ID
	// Exclusive intent must precede the only create POST. Never resume it.
	data, _ := json.Marshal(map[string]string{"id": candidate, "origin": b.setup.Origin, "nonce": b.setup.Nonce})
	f, e := os.OpenFile(b.state, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return errors.New("Cloudflare create intent already exists or cannot be written")
	}
	_, e = f.Write(data)
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil || closeErr != nil {
		return errors.New("Cloudflare intent write failed")
	}
	b.id = candidate
	b.ownedIntent = true
	payload, _ := json.Marshal(map[string]string{"nonce": b.setup.Nonce})
	var result struct {
		ID, Boot string
		Expires  int64
		Image    string
	}
	if e = b.call(ctx, "/create", payload, "", &result); e != nil {
		return e
	}
	if result.ID != b.id || !cfBoot.MatchString(result.Boot) || result.Image != "cloudflare/debian-trixie" || result.Expires < time.Now().UnixMilli() || result.Expires > time.Now().Add(16*time.Minute).UnixMilli() {
		return errors.New("Cloudflare create identity invalid")
	}
	b.boot = result.Boot
	// Intent already pins immutable DO ID; journal boot identity before runtime.
	data, _ = json.Marshal(map[string]string{"id": b.id, "boot": b.boot, "origin": b.setup.Origin, "nonce": b.setup.Nonce})
	return b.saveIdentity(data)
}
func (b *CloudflareBox) command(ctx context.Context, argv []string, input []byte) ([]byte, error) {
	if b.id == "" || b.boot == "" {
		return nil, errors.New("Cloudflare box identity unavailable")
	}
	payload, _ := json.Marshal(map[string]any{"argv": argv, "stdin": base64.StdEncoding.EncodeToString(input)})
	var result struct {
		ID, Stdout string
		Exit       *int `json:"exit_code"`
	}
	if e := b.call(ctx, "/exec", payload, "", &result); e != nil {
		return nil, e
	}
	if result.ID != b.id || (result.Exit == nil || *result.Exit != 0) {
		return nil, errors.New("Cloudflare command identity or exit invalid")
	}
	return []byte(result.Stdout), nil
}
func (b *CloudflareBox) DetectArch(ctx context.Context) error {
	out, e := b.command(ctx, []string{"/usr/bin/uname", "-m"}, nil)
	if e != nil {
		return e
	}
	if strings.TrimSpace(string(out)) != "x86_64" {
		return errors.New("Cloudflare unsupported architecture")
	}
	b.Arch = "amd64"
	return nil
}
func (b *CloudflareBox) Upload(ctx context.Context, bin []byte) error {
	out, e := b.command(ctx, []string{"/bin/sh", "-c", "umask 077; mktemp -d /tmp/.sandprobe-XXXXXXXXXXXX"}, nil)
	if e != nil {
		return e
	}
	dir := strings.TrimSpace(string(out))
	if !cfDir.MatchString(dir) {
		return errors.New("Cloudflare private directory invalid")
	}
	var result struct {
		ID       string
		Uploaded bool
	}
	if e = b.call(ctx, "/upload", bin, dir, &result); e != nil {
		return e
	}
	if result.ID != b.id || !result.Uploaded {
		return errors.New("Cloudflare upload identity invalid")
	}
	b.ProbePath = dir + "/probe"
	out, e = b.command(ctx, []string{"/usr/bin/sha256sum", b.ProbePath}, nil)
	if e != nil {
		return e
	}
	sum := sha256.Sum256(bin)
	fields := strings.Fields(string(out))
	if len(fields) != 2 || fields[0] != hex.EncodeToString(sum[:]) || fields[1] != b.ProbePath {
		return errors.New("Cloudflare probe digest mismatch")
	}
	return nil
}
func (b *CloudflareBox) Probe(ctx context.Context, args []string, stdin []byte) ([]byte, error) {
	if !cfDir.MatchString(filepath.Dir(b.ProbePath)) || filepath.Base(b.ProbePath) != "probe" {
		return nil, errors.New("Cloudflare probe not uploaded")
	}
	if len(args) > 1 || (len(args) == 1 && args[0] != "-survey") {
		return nil, errors.New("Cloudflare unsupported probe mode")
	}
	return b.command(ctx, append([]string{b.ProbePath}, args...), stdin)
}
func (b *CloudflareBox) Destroy(ctx context.Context) error {
	if !b.ownedIntent || b.id == "" {
		return nil
	}
	payload, _ := json.Marshal(map[string]string{"id": b.id})
	var result cfStatus
	if e := b.call(ctx, "/destroy", payload, "", &result); e != nil {
		return e
	}
	if result.ID != b.id || result.Running || !result.Closed {
		return errors.New("Cloudflare deletion unconfirmed")
	}
	if e := b.call(ctx, "/status", []byte(`{}`), "", &result); e != nil {
		return e
	}
	if result.ID != b.id || result.Running || !result.Closed {
		return errors.New("Cloudflare terminal verification failed")
	}
	return os.Remove(b.state)
}
func CloudflareExclusions() map[string]string {
	return map[string]string{"SEC-4": "Cloudflare scope excludes metadata (PRV-10)", "EGR-3": "Cloudflare scope excludes provider proxy requests (PRV-10)", "AMP-6": "Cloudflare scope excludes vsock requests (PRV-10)", "AMP-7": "Cloudflare scope excludes Kubernetes API requests (PRV-10)"}
}

func (b *CloudflareBox) Available(ctx context.Context) error {
	var status cfStatus
	return b.call(ctx, "/status", []byte(`{}`), "", &status)
}

// PRV-10: identity updates cannot truncate the original cleanup intent.
func (b *CloudflareBox) saveIdentity(data []byte) error {
	f, e := os.CreateTemp(filepath.Dir(b.state), ".cloudflare-box-")
	if e != nil {
		return errors.New("Cloudflare journal update failed")
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(data)
	}
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil || closeErr != nil {
		return errors.New("Cloudflare journal update failed")
	}
	if os.Rename(name, b.state) != nil {
		return errors.New("Cloudflare journal replacement failed")
	}
	return nil
}

func (b *CloudflareBox) OwnedIntent() bool { return b.ownedIntent }
