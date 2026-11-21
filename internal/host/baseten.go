package host

// Baseten's provider adapter implements PRV-6. Credentials and raw HTTP failures
// never leave this file. Only sandboxes created by this client can be mutated.
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
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"sandprobe/internal/obs"
)

const basetenAPI = "https://api.baseten.co"
const BasetenImage = "baseten/base-image:latest"
const BasetenResidual = "Baseten addresses sandboxes by reusable name. The create-returned name, URL, creation time and external ID are checked before each operation, but the check/operation race remains. No persistent volumes or previews are created; suspend/resume is not a reset."

// BasetenExclusions is the initial approved canary-only scope (PRV-5, PRV-6).
func BasetenExclusions() map[string]string {
	return map[string]string{
		"SEC-4": "Baseten scope excludes provider metadata requests (PRV-6)",
		"EGR-3": "Baseten scope excludes provider or guest proxy requests (PRV-6)",
		"AMP-6": "Baseten scope excludes provider vsock requests (PRV-6)",
		"AMP-7": "Baseten scope excludes provider Kubernetes API requests (PRV-6)",
	}
}

// BasetenKey reads a host-side credential; a selected file never falls back to env.
func BasetenKey(file string) (string, error) {
	key := os.Getenv("BASETEN_API_KEY")
	if file != "" {
		fd, err := syscall.Open(file, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return "", errors.New("Baseten key file cannot be opened safely")
		}
		f := os.NewFile(uintptr(fd), "Baseten key")
		defer f.Close()
		st, err := f.Stat()
		if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
			return "", errors.New("Baseten key file must be regular and owner-only")
		}
		owner, ok := st.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != uint32(os.Getuid()) {
			return "", errors.New("Baseten key file must belong to the current user")
		}
		raw, err := io.ReadAll(io.LimitReader(f, 8193))
		if err != nil || len(raw) > 8192 {
			return "", errors.New("Baseten key file cannot be read or is oversized")
		}
		key = string(raw)
	}
	key = strings.TrimSpace(key)
	if key == "" || len(key) > 8192 || strings.IndexFunc(key, func(r rune) bool { return r <= 32 || r >= 127 }) >= 0 {
		return "", errors.New("Baseten API key is missing or malformed")
	}
	return key, nil
}

type BasetenClient struct {
	key, accessToken, team string
	expires                time.Time
	http                   *http.Client
	poll                   time.Duration
}

func NewBasetenClient(key, team string) (*BasetenClient, error) {
	if key == "" || len(key) > 8192 || strings.IndexFunc(key, func(r rune) bool { return r <= 32 || r >= 127 }) >= 0 {
		return nil, errors.New("Baseten API key is missing or malformed")
	}
	if len(team) > 128 || strings.IndexFunc(team, func(r rune) bool { return r <= 32 || r >= 127 }) >= 0 {
		return nil, errors.New("Baseten team selector is malformed")
	}
	return &BasetenClient{key: key, team: team, http: &http.Client{Timeout: 120 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, poll: time.Second}, nil
}

type basetenHTTPError struct{ code int }

func (e *basetenHTTPError) Error() string { return fmt.Sprintf("Baseten HTTP %d", e.code) }
func basetenStatus(err error, code int) bool {
	var e *basetenHTTPError
	return errors.As(err, &e) && e.code == code
}

// request bounds every response and never returns raw body/transport errors.
func (c *BasetenClient) request(ctx context.Context, method, endpoint, credential, contentType string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return errors.New("Baseten request is invalid")
	}
	req.Header.Set("Authorization", "Bearer "+credential)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return errors.New("Baseten request failed (transport or deadline)")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &basetenHTTPError{resp.StatusCode}
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4*obs.MaxDoc+1))
	if err != nil || len(raw) > 4*obs.MaxDoc {
		return errors.New("Baseten response incomplete or oversized")
	}
	if out != nil && json.Unmarshal(raw, out) != nil {
		return errors.New("Baseten response is malformed")
	}
	return nil
}
func (c *BasetenClient) Authenticate(ctx context.Context) error {
	if c.accessToken != "" && time.Until(c.expires) > time.Minute {
		return nil
	}
	var r struct {
		Token   string `json:"token"`
		Expires string `json:"expires_at"`
	}
	if err := c.request(ctx, "POST", basetenAPI+"/v1/token", c.key, "application/json", []byte(`{"scopes":["sandboxes"]}`), &r); err != nil {
		return err
	}
	expiry, err := time.Parse(time.RFC3339, r.Expires)
	if err != nil || time.Until(expiry) < time.Minute || r.Token == "" || strings.IndexFunc(r.Token, func(r rune) bool { return r <= 32 || r >= 127 }) >= 0 {
		return errors.New("Baseten token response is invalid")
	}
	c.accessToken, c.expires = r.Token, expiry
	return nil
}
func (c *BasetenClient) management(ctx context.Context, method, path string, body []byte, out any) error {
	if err := c.Authenticate(ctx); err != nil {
		return err
	}
	if c.team != "" {
		path += "?team_id=" + url.QueryEscape(c.team)
	}
	return c.request(ctx, method, basetenAPI+path, c.accessToken, "application/json", body, out)
}
func (c *BasetenClient) Available(ctx context.Context) error {
	var r struct {
		Items json.RawMessage `json:"items"`
	}
	if err := c.management(ctx, "GET", "/v1/sandboxes/instances", nil, &r); err != nil {
		return err
	}
	var items []json.RawMessage
	if len(r.Items) == 0 || string(r.Items) == "null" || json.Unmarshal(r.Items, &items) != nil {
		return errors.New("Baseten inventory response is malformed")
	}
	return nil
}

type basetenIdentity struct {
	Name     string `json:"name"`
	URL      string `json:"url"`
	Created  string `json:"created_at"`
	External string `json:"external_id"`
}
type basetenSandbox struct {
	basetenIdentity
	Status    string `json:"status"`
	ExpiresIn *int   `json:"expires_in"`
	Lifecycle struct {
		Policies []struct {
			Action string `json:"action"`
			Type   string `json:"type"`
			Value  string `json:"value"`
		} `json:"expiration_policies"`
	} `json:"lifecycle"`
}
type basetenJournal struct {
	Keep      bool             `json:"keep,omitempty"`
	ExpiresAt string           `json:"expires_at,omitempty"`
	Retained  bool             `json:"retained,omitempty"`
	Team      string           `json:"team,omitempty"`
	Requested string           `json:"requested_name"`
	External  string           `json:"external_id"`
	Identity  *basetenIdentity `json:"identity,omitempty"`
}
type BasetenBox struct {
	client                *BasetenClient
	identity              basetenIdentity
	Name, ProbePath, Arch string
	state                 string
	journal               basetenJournal
	gone                  bool
	Calls                 []obs.ProviderCall
}

func (b *BasetenBox) ID() string        { return b.identity.Name }
func (b *BasetenBox) StatePath() string { return b.state }
func (b *BasetenBox) record(at time.Time, call string, err error) {
	s := "ok"
	if err != nil {
		s = "error"
	}
	b.Calls = append(b.Calls, obs.ProviderCall{At: at, Call: call, ID: b.identity.Name, Status: s})
}

var basetenName = regexp.MustCompile(`^sandprobe-[a-f0-9]{24}$`)
var basetenHost = regexp.MustCompile(`^sbx-[a-z0-9-]+\.[a-z0-9-]+\.b10\.(co|run)$`)

func validBasetenURL(raw, name string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.User == nil && u.Port() == "" && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.RawPath == "" && (u.Path == "" || u.Path == "/") && u.Host == u.Hostname() && basetenHost.MatchString(u.Host) && strings.HasPrefix(u.Host, "sbx-"+name+"-")
}
func validBasetenIdentity(i basetenIdentity, name, external string) bool {
	_, err := time.Parse(time.RFC3339Nano, i.Created)
	return i.Name == name && basetenName.MatchString(i.Name) && i.External == external && external != "" && err == nil && validBasetenURL(i.URL, i.Name)
}
func (b *BasetenBox) save() error {
	raw, _ := json.MarshalIndent(b.journal, "", "  ")
	// Replace atomically: a process interruption never truncates the recorded identity.
	f, err := os.CreateTemp(filepath.Dir(b.state), ".baseten-state-*")
	if err != nil {
		return errors.New("Baseten state cannot be written")
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(raw)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(tmp, b.state)
	}
	if err != nil {
		return errors.New("Baseten state cannot be persisted")
	}
	return nil
}

// CreateBaseten journals before the single create. Even failure returns a box so
// the caller can report its unresolved journal (PRV-1, PRV-6).
func (c *BasetenClient) CreateBaseten(ctx context.Context, stateDir, region string) (*BasetenBox, error) {
	return c.createBaseten(ctx, stateDir, region, false)
}

// CreateBasetenForInspection changes only the initial, bounded lifecycle (PRV-7).
func (c *BasetenClient) CreateBasetenForInspection(ctx context.Context, stateDir, region string) (*BasetenBox, error) {
	return c.createBaseten(ctx, stateDir, region, true)
}
func (c *BasetenClient) createBaseten(ctx context.Context, stateDir, region string, keep bool) (*BasetenBox, error) {
	name := token("sandprobe-")
	// token() has 24 random hex characters; it is also used for the run identity.
	b := &BasetenBox{client: c, Name: name}
	external := token("sandprobe-")
	b.journal = basetenJournal{Team: c.team, Requested: name, External: external, Keep: keep}
	maxAge := "15m"
	if keep {
		maxAge = "1h"
	}
	if !basetenName.MatchString(name) {
		return nil, errors.New("Baseten random identity is invalid")
	}
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return nil, errors.New("Baseten state directory cannot be created")
	}
	st, statErr := os.Lstat(stateDir)
	if statErr != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0022 != 0 {
		return nil, errors.New("Baseten state directory is not a safe owned directory")
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Getuid()) {
		return nil, errors.New("Baseten state directory has a different owner")
	}
	b.state = filepath.Join(stateDir, "baseten-"+name+".state")
	f, err := os.OpenFile(b.state, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, errors.New("Baseten state cannot be reserved")
	}
	f.Close()
	if err = b.save(); err != nil {
		return b, err
	}
	payload := map[string]any{"name": name, "external_id": external, "image": BasetenImage, "create_if_not_exists": false,
		"lifecycle": map[string]any{"expiration_policies": []map[string]string{{"action": "DELETE", "type": "TTL_MAX_AGE", "value": maxAge}}},
		"labels":    map[string]string{"sandprobe-run": external}}
	if region != "" {
		payload["region"] = region
	}
	raw, _ := json.Marshal(payload)
	var box basetenSandbox
	at := time.Now()
	err = c.management(ctx, "POST", "/v1/sandboxes/instances", raw, &box)
	b.record(at, "Baseten create sandbox ("+maxAge+" delete expiry)", err)
	if err != nil {
		return b, err
	}
	if !validBasetenIdentity(box.basetenIdentity, name, external) {
		return b, errors.New("Baseten create returned an unverified identity; no adoption or automatic deletion")
	}
	b.identity = box.basetenIdentity
	b.journal.Identity = &b.identity
	if keep {
		created, _ := time.Parse(time.RFC3339Nano, b.identity.Created)
		b.journal.ExpiresAt = created.Add(time.Hour).UTC().Format(time.RFC3339Nano)
	}
	if err = b.save(); err != nil {
		return b, err
	}
	if box.Status != "DEPLOYED" {
		for {
			if !basetenProvisioning(box.Status) {
				return b, errors.New("Baseten sandbox did not deploy")
			}
			if err = b.pause(ctx); err != nil {
				return b, err
			}
			box, err = b.lookup(ctx)
			if err != nil {
				return b, err
			}
			if err = b.match(box); err != nil {
				return b, err
			}
			if box.Status == "DEPLOYED" {
				break
			}
		}
	}
	return b, nil
}
func (b *BasetenBox) pause(ctx context.Context) error {
	t := time.NewTimer(b.client.poll)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return errors.New("Baseten operation deadline reached")
	}
}
func (b *BasetenBox) lookup(ctx context.Context) (basetenSandbox, error) {
	var s basetenSandbox
	at := time.Now()
	err := b.client.management(ctx, "GET", "/v1/sandboxes/instances/"+url.PathEscape(b.Name), nil, &s)
	b.record(at, "Baseten get recorded sandbox", err)
	return s, err
}
func (b *BasetenBox) match(s basetenSandbox) error {
	if b.identity.Name == "" || s.basetenIdentity != b.identity {
		return errors.New("Baseten sandbox identity changed or was never confirmed")
	}
	return nil
}
func (b *BasetenBox) ours(ctx context.Context) error {
	if b.gone || b.identity.Name == "" {
		return errors.New("Baseten sandbox is gone or its creation is unresolved")
	}
	s, err := b.lookup(ctx)
	if err != nil {
		return err
	}
	if err = b.match(s); err != nil {
		return err
	}
	if s.Status != "DEPLOYED" {
		return errors.New("Baseten sandbox is not deployed")
	}
	return nil
}
func (b *BasetenBox) runtime(ctx context.Context, method, path, contentType string, body []byte, out any) error {
	if err := b.ours(ctx); err != nil {
		return err
	}
	if err := b.client.Authenticate(ctx); err != nil {
		return err
	}
	at := time.Now()
	err := b.client.request(ctx, method, strings.TrimSuffix(b.identity.URL, "/")+path, b.client.accessToken, contentType, body, out)
	b.record(at, "Baseten runtime "+method+" "+strings.Split(path, "?")[0], err)
	return err
}
func (b *BasetenBox) exec(ctx context.Context, command string) ([]byte, error) {
	payload, _ := json.Marshal(map[string]any{"command": command, "env": map[string]string{"SANDPROBE_TWIN": "1"}, "waitForCompletion": true, "keepAlive": true, "restartOnFailure": false, "maxRestarts": 0, "timeout": 95})
	var r struct {
		Status string `json:"status"`
		Exit   *int   `json:"exitCode"`
		Stdout string `json:"stdout"`
	}
	if err := b.runtime(ctx, "POST", "/process", "application/json", payload, &r); err != nil {
		return nil, err
	}
	if r.Status != "completed" || r.Exit == nil || *r.Exit != 0 {
		return nil, errors.New("Baseten command did not complete successfully")
	}
	if len(r.Stdout) > obs.MaxDoc {
		return nil, errors.New("Baseten command output is oversized")
	}
	return []byte(r.Stdout), nil
}
func (b *BasetenBox) DetectArch(ctx context.Context) error {
	raw, err := b.exec(ctx, "uname -m")
	if err != nil {
		return err
	}
	switch strings.TrimSpace(string(raw)) {
	case "x86_64":
		b.Arch = "amd64"
	case "aarch64", "arm64":
		b.Arch = "arm64"
	default:
		return errors.New("Baseten sandbox architecture is unsupported")
	}
	return nil
}
func (b *BasetenBox) Upload(ctx context.Context, probe []byte) error {
	dir := "/tmp/" + token("sandprobe-")
	// A fresh private directory is created exclusively; existing guest files are never overwritten.
	if _, err := b.exec(ctx, "umask 077; mkdir "+dir); err != nil {
		return err
	}
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	part, err := w.CreateFormFile("file", "probe")
	if err != nil {
		return errors.New("Baseten upload could not be prepared")
	}
	part.Write(probe)
	w.WriteField("permissions", "0755")
	w.Close()
	path := dir + "/probe"
	if err := b.runtime(ctx, "PUT", "/filesystem/"+url.PathEscape(path), w.FormDataContentType(), body.Bytes(), nil); err != nil {
		return err
	}
	sum := sha256.Sum256(probe)
	out, err := b.exec(ctx, "sha256sum "+path)
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(out)) != hex.EncodeToString(sum[:])+"  "+path {
		return errors.New("Baseten uploaded probe digest did not match")
	}
	b.ProbePath = path
	return nil
}
func (b *BasetenBox) Probe(ctx context.Context, args []string, stdin []byte) ([]byte, error) {
	if b.ProbePath == "" {
		return nil, errors.New("Baseten probe is not uploaded")
	}
	for _, arg := range args {
		if !probeArg.MatchString(arg) {
			return nil, errors.New("Baseten probe argument is invalid")
		}
	}
	if len(stdin) > obs.MaxDoc {
		return nil, errors.New("Baseten probe input is oversized")
	}
	command := "exec " + b.ProbePath
	if len(args) > 0 {
		command += " " + strings.Join(args, " ")
	}
	if len(stdin) > 0 {
		command = "printf %s '" + base64.StdEncoding.EncodeToString(stdin) + "' | base64 -d | " + strings.TrimPrefix(command, "exec ")
	}
	return b.exec(ctx, command)
}
func (b *BasetenBox) Storage(context.Context) (Storage, error) {
	return Storage{Model: "recreate"}, nil
}
func (b *BasetenBox) Reset(context.Context) (Box, *obs.ResetEvidence, error) {
	return nil, nil, errors.New("Baseten reset is unsupported without run-owned volumes")
}
func (b *BasetenBox) Teardown(ctx context.Context, vols []obs.Volume) map[string]bool {
	return map[string]bool{"": len(vols) == 0 && b.Destroy(ctx) == nil}
}
func (b *BasetenBox) Destroy(ctx context.Context) error {
	if b.gone {
		return b.confirmGone()
	}
	if b.identity.Name == "" {
		return errors.New("Baseten create is unresolved; retain journal and reconcile manually")
	}
	s, err := b.lookup(ctx)
	if basetenStatus(err, 404) {
		return b.confirmGone()
	}
	if err != nil {
		return err
	}
	if err = b.match(s); err != nil {
		return err
	}
	if s.Status == "TERMINATED" {
		return b.confirmGone()
	}
	if !knownBasetenStatus(s.Status) {
		return errors.New("Baseten cleanup status is unknown")
	}
	if s.Status != "DELETING" {
		var deleted basetenSandbox
		at := time.Now()
		err = b.client.management(ctx, "DELETE", "/v1/sandboxes/instances/"+url.PathEscape(b.Name), nil, &deleted)
		b.record(at, "Baseten delete recorded sandbox", err)
		if basetenStatus(err, 404) {
			return b.confirmGone()
		}
		if err != nil {
			return err
		}
		if err = b.match(deleted); err != nil {
			return err
		}
	}
	for {
		if err = b.pause(ctx); err != nil {
			return err
		}
		s, err = b.lookup(ctx)
		if basetenStatus(err, 404) {
			return b.confirmGone()
		}
		if err != nil {
			return err
		}
		if err = b.match(s); err != nil {
			return err
		}
		if s.Status == "TERMINATED" {
			return b.confirmGone()
		}
		if s.Status != "DELETING" {
			return errors.New("Baseten deletion was not confirmed")
		}
	}
}
func basetenProvisioning(s string) bool {
	return s == "DEPLOYING" || s == "BUILDING" || s == "UPLOADING"
}

func knownBasetenStatus(s string) bool {
	switch s {
	case "DEPLOYING", "DEPLOYED", "FAILED", "DEACTIVATING", "DEACTIVATED", "DELETING", "TERMINATED", "ARCHIVING", "ARCHIVED", "UNARCHIVING", "BUILDING", "UPLOADING":
		return true
	}
	return false
}
func (b *BasetenBox) confirmGone() error {
	b.gone = true
	if err := os.Remove(b.state); err != nil && !os.IsNotExist(err) {
		return errors.New("Baseten deletion confirmed but lifecycle journal could not be retired")
	}
	return nil
}

// Retain verifies the original deployed incarnation and server deletion deadline.
// It never changes the provider lifecycle and never treats expiry as deletion.
func (b *BasetenBox) Retain(ctx context.Context) (time.Time, error) {
	if !b.journal.Keep || b.gone {
		return time.Time{}, errors.New("Baseten retention was not requested before creation")
	}
	s, err := b.lookup(ctx)
	if err != nil {
		return time.Time{}, err
	}
	if err = b.match(s); err != nil {
		return time.Time{}, err
	}
	created, err := time.Parse(time.RFC3339Nano, b.identity.Created)
	if err != nil {
		return time.Time{}, errors.New("Baseten creation timestamp is invalid")
	}
	expiry, err := time.Parse(time.RFC3339Nano, b.journal.ExpiresAt)
	remaining := time.Until(expiry)
	if err != nil || !expiry.Equal(created.Add(time.Hour)) || created.After(time.Now().Add(5*time.Second)) || remaining <= 0 || s.Status != "DEPLOYED" || s.ExpiresIn == nil || *s.ExpiresIn <= 0 || *s.ExpiresIn > 3600 || time.Duration(*s.ExpiresIn)*time.Second > remaining+5*time.Second {
		return time.Time{}, errors.New("Baseten retention expiry or deployment cannot be verified")
	}
	if len(s.Lifecycle.Policies) != 1 {
		return time.Time{}, errors.New("Baseten retention policy cannot be verified")
	}
	policy := s.Lifecycle.Policies[0]
	age, err := time.ParseDuration(policy.Value)
	if err != nil || policy.Action != "DELETE" || policy.Type != "TTL_MAX_AGE" || age != time.Hour {
		return time.Time{}, errors.New("Baseten retention deletion policy changed")
	}
	if ctx.Err() != nil {
		return time.Time{}, errors.New("Baseten retention was interrupted")
	}
	b.journal.Retained = true
	if err = b.save(); err != nil {
		return time.Time{}, err
	}
	if ctx.Err() != nil {
		return time.Time{}, errors.New("Baseten retention was interrupted")
	}
	return expiry, nil
}

// LoadBasetenJournal recovers only an owned, create-confirmed private journal.
// No provider call occurs here and no name-only resource can be adopted (PRV-7).
func (c *BasetenClient) LoadBasetenJournal(path string) (*BasetenBox, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("Baseten journal cannot be opened safely")
	}
	f := os.NewFile(uintptr(fd), "Baseten journal")
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 {
		return nil, errors.New("Baseten journal must be a regular mode-0600 file")
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Getuid()) {
		return nil, errors.New("Baseten journal has a different owner")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 16385))
	if err != nil || len(raw) > 16384 {
		return nil, errors.New("Baseten journal is oversized or unreadable")
	}
	var j basetenJournal
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&j) != nil || dec.Decode(new(any)) != io.EOF || j.Identity == nil || !validBasetenIdentity(*j.Identity, j.Requested, j.External) || filepath.Base(path) != "baseten-"+j.Requested+".state" {
		return nil, errors.New("Baseten journal has no verified create identity")
	}
	if c.team != "" && c.team != j.Team {
		return nil, errors.New("Baseten selected team conflicts with the journal")
	}
	if len(j.Team) > 128 || strings.IndexFunc(j.Team, func(r rune) bool { return r <= 32 || r >= 127 }) >= 0 {
		return nil, errors.New("Baseten journal team is invalid")
	}
	if j.Keep {
		born, _ := time.Parse(time.RFC3339Nano, j.Identity.Created)
		expiry, e := time.Parse(time.RFC3339Nano, j.ExpiresAt)
		if e != nil || !expiry.Equal(born.Add(time.Hour)) {
			return nil, errors.New("Baseten journal expiry is invalid")
		}
	}
	c.team = j.Team
	return &BasetenBox{client: c, identity: *j.Identity, Name: j.Requested, state: path, journal: j}, nil
}
