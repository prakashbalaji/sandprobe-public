package host

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sandprobe/internal/obs"
	"sandprobe/internal/probes"
)

type basetenTransport func(*http.Request) (*http.Response, error)

func (f basetenTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func basetenResponse(code int, body string) *http.Response {
	return &http.Response{StatusCode: code, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

type basetenFake struct {
	t                         *testing.T
	sandbox                   basetenSandbox
	creates, deletes, runtime int
	ambiguous, redirect       bool
	overrideURL               string
	createStatus              string
	process                   string
	upload                    []byte
	payload                   map[string]any
}

func (f *basetenFake) transport(r *http.Request) (*http.Response, error) {
	raw, _ := io.ReadAll(r.Body)
	if r.URL.Host == "api.baseten.co" {
		if r.URL.Path == "/v1/token" {
			if r.Header.Get("Authorization") != "Bearer test-key" {
				f.t.Error("key missing on token exchange")
			}
			return basetenResponse(200, fmt.Sprintf(`{"token":"test-access-token","expires_at":%q}`, time.Now().Add(time.Hour).Format(time.RFC3339))), nil
		}
		if r.Header.Get("Authorization") != "Bearer test-access-token" {
			f.t.Error("management endpoint did not use access token")
		}
		if r.Method == "POST" && r.URL.Path == "/v1/sandboxes/instances" {
			f.creates++
			json.Unmarshal(raw, &f.payload)
			if f.ambiguous {
				return nil, errors.New("test-key leaked by upstream transport")
			}
			name := f.payload["name"].(string)
			external := f.payload["external_id"].(string)
			f.sandbox = basetenSandbox{basetenIdentity: basetenIdentity{Name: name, URL: "https://sbx-" + name + "-team.us-pdx-1.b10.co", Created: time.Now().Format(time.RFC3339Nano), External: external}, Status: "DEPLOYED"}
			if f.overrideURL != "" {
				f.sandbox.URL = f.overrideURL
			}
			if f.createStatus != "" {
				f.sandbox.Status = f.createStatus
			}
		} else if r.Method == "DELETE" {
			f.deletes++
			f.sandbox.Status = "DELETING"
			out, _ := json.Marshal(f.sandbox)
			return basetenResponse(202, string(out)), nil
		} else if r.Method == "GET" {
			if f.sandbox.Status == "DELETING" {
				f.sandbox.Status = "TERMINATED"
			}
			if f.sandbox.Status == "DEPLOYING" || f.sandbox.Status == "BUILDING" || f.sandbox.Status == "UPLOADING" {
				f.sandbox.Status = "DEPLOYED"
			}
		}
		out, _ := json.Marshal(f.sandbox)
		return basetenResponse(200, string(out)), nil
	}
	f.runtime++
	if r.Header.Get("Authorization") != "Bearer test-access-token" {
		f.t.Error("runtime received management key or missing token")
	}
	if f.redirect {
		resp := basetenResponse(302, "test-key")
		resp.Header.Set("Location", "https://attacker.example/steal")
		return resp, nil
	}
	if r.Method == "PUT" {
		if !strings.HasPrefix(r.URL.Path, "/filesystem//tmp/") {
			f.t.Error("upload lost absolute path")
		}
		mr, err := multipart.NewReader(strings.NewReader(string(raw)), strings.Split(r.Header.Get("Content-Type"), "boundary=")[1]).ReadForm(20 << 20)
		if err != nil {
			f.t.Fatal(err)
		}
		if mr.Value["permissions"][0] != "0755" {
			f.t.Error("upload is not executable")
		}
		file, _ := mr.File["file"][0].Open()
		f.upload, _ = io.ReadAll(file)
		file.Close()
		return basetenResponse(200, `{"message":"created"}`), nil
	}
	var p map[string]any
	json.Unmarshal(raw, &p)
	if p["waitForCompletion"] != true || p["restartOnFailure"] != false || p["timeout"] != float64(95) {
		f.t.Error("unbounded or restarting execution")
	}
	if f.process != "" {
		return basetenResponse(200, f.process), nil
	}
	command, _ := p["command"].(string)
	if strings.HasPrefix(command, "sha256sum ") {
		sum := sha256.Sum256(f.upload)
		out, _ := json.Marshal(map[string]any{"status": "completed", "exitCode": 0, "stdout": fmt.Sprintf("%x  %s\n", sum, strings.TrimPrefix(command, "sha256sum "))})
		return basetenResponse(200, string(out)), nil
	}
	return basetenResponse(200, `{"status":"completed","exitCode":0,"stdout":"x86_64\n"}`), nil
}
func newBasetenFake(t *testing.T) (*BasetenClient, *basetenFake) {
	t.Helper()
	c, _ := NewBasetenClient("test-key", "team-one")
	f := &basetenFake{t: t}
	c.http.Transport = basetenTransport(f.transport)
	c.poll = time.Microsecond
	return c, f
}
func TestBasetenLifecycle(t *testing.T) {
	c, f := newBasetenFake(t)
	dir := t.TempDir()
	b, err := c.CreateBaseten(context.Background(), dir, "us-pdx-1")
	if err != nil {
		t.Fatal(err)
	}
	if f.creates != 1 || b.ID() == "" {
		t.Fatal("create identity missing")
	}
	st, err := os.Stat(b.state)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatal("journal not private")
	}
	raw, _ := os.ReadFile(b.state)
	if strings.Contains(string(raw), "test-key") || strings.Contains(string(raw), "test-access-token") {
		t.Fatal("credential in journal")
	}
	var j basetenJournal
	if json.Unmarshal(raw, &j) != nil || j.Identity == nil || *j.Identity != b.identity {
		t.Fatal("identity not persisted")
	}
	life := f.payload["lifecycle"].(map[string]any)["expiration_policies"].([]any)[0].(map[string]any)
	if life["type"] != "TTL_MAX_AGE" || life["action"] != "DELETE" || life["value"] != "15m" || f.payload["create_if_not_exists"] != false {
		t.Fatal("expiry or create semantics unsafe")
	}
	if _, ok := f.payload["volumes"]; ok {
		t.Fatal("unexpected volumes")
	}
	if err = b.DetectArch(context.Background()); err != nil || b.Arch != "amd64" {
		t.Fatal("architecture", err)
	}
	if err = b.Destroy(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.deletes != 1 || !b.gone {
		t.Fatal("delete was not confirmed")
	}
	if _, err = os.Stat(b.state); !os.IsNotExist(err) {
		t.Fatal("journal not retired")
	}
	if err = b.Destroy(context.Background()); err != nil || f.deletes != 1 {
		t.Fatal("cleanup repeated delete")
	}
}
func TestBasetenAmbiguousCreate(t *testing.T) {
	c, f := newBasetenFake(t)
	f.ambiguous = true
	b, err := c.CreateBaseten(context.Background(), t.TempDir(), "")
	if err == nil || strings.Contains(err.Error(), "test-key") {
		t.Fatal("raw transport error or unexpected success")
	}
	if f.creates != 1 {
		t.Fatal("create retried")
	}
	if b.Destroy(context.Background()) == nil || f.deletes != 0 {
		t.Fatal("adopted ambiguous create")
	}
	if _, err := os.Stat(b.state); err != nil {
		t.Fatal("lost unresolved journal")
	}
}
func TestBasetenURLValidation(t *testing.T) {
	name := "sandprobe-0123456789abcdef01234567"
	good := "https://sbx-" + name + "-team.us-pdx-1.b10.co"
	for _, raw := range []string{good, strings.Replace(good, ".co", ".run", 1)} {
		if !validBasetenURL(raw, name) {
			t.Error("valid URL refused")
		}
	}
	for _, raw := range []string{"http://" + strings.TrimPrefix(good, "https://"), good + ":443", good + "?x=1", good + "#fragment", good + "/process", strings.Replace(good, "https://", "https://user@", 1), good + ".attacker.example", "https://127.0.0.1", "https://sbx-other-team.us-pdx-1.b10.co", good + "?"} {
		if validBasetenURL(raw, name) {
			t.Error("unsafe URL accepted", raw)
		}
	}
	c, f := newBasetenFake(t)
	f.overrideURL = "https://attacker.example"
	b, err := c.CreateBaseten(context.Background(), t.TempDir(), "")
	if err == nil || b.Destroy(context.Background()) == nil || f.runtime != 0 || f.deletes != 0 {
		t.Fatal("hostile create endpoint trusted")
	}
}
func TestBasetenReplacementAndRedirect(t *testing.T) {
	for _, field := range []string{"created", "url", "external"} {
		t.Run(field, func(t *testing.T) {
			c, f := newBasetenFake(t)
			b, err := c.CreateBaseten(context.Background(), t.TempDir(), "")
			if err != nil {
				t.Fatal(err)
			}
			switch field {
			case "created":
				f.sandbox.Created = time.Now().Add(time.Minute).Format(time.RFC3339Nano)
			case "url":
				f.sandbox.URL += "/changed"
			case "external":
				f.sandbox.External = "replacement"
			}
			if b.DetectArch(context.Background()) == nil || b.Destroy(context.Background()) == nil || f.runtime != 0 || f.deletes != 0 {
				t.Fatal("replacement touched")
			}
		})
	}
	c, f := newBasetenFake(t)
	b, _ := c.CreateBaseten(context.Background(), t.TempDir(), "")
	f.redirect = true
	if err := b.DetectArch(context.Background()); err == nil || strings.Contains(err.Error(), "test-key") || f.runtime != 1 {
		t.Fatal("redirect followed or leaked")
	}
}
func TestBasetenExecutionRequiresTerminalSuccess(t *testing.T) {
	for _, body := range []string{`{"status":"running","exitCode":0}`, `{"status":"completed"}`, `{"status":"completed","exitCode":1,"stderr":"test-key"}`, `{broken`} {
		c, f := newBasetenFake(t)
		b, _ := c.CreateBaseten(context.Background(), t.TempDir(), "")
		f.process = body
		if _, err := b.exec(context.Background(), "uname -m"); err == nil || strings.Contains(err.Error(), "test-key") {
			t.Fatal("accepted incomplete process or leaked stderr")
		}
	}
}
func TestBasetenCredentialFile(t *testing.T) {
	t.Setenv("BASETEN_API_KEY", "test-env-key")
	dir := t.TempDir()
	p := filepath.Join(dir, "key")
	os.WriteFile(p, []byte("test-file-key\n"), 0600)
	if key, err := BasetenKey(p); err != nil || key != "test-file-key" {
		t.Fatal("file auth failed")
	}
	if key, err := BasetenKey(""); err != nil || key != "test-env-key" {
		t.Fatal("env auth failed")
	}
	os.Chmod(p, 0644)
	if _, err := BasetenKey(p); err == nil {
		t.Fatal("permissive key accepted")
	}
	os.Chmod(p, 0600)
	link := filepath.Join(dir, "link")
	os.Symlink(p, link)
	if _, err := BasetenKey(link); err == nil {
		t.Fatal("symlink accepted")
	}
	if _, err := BasetenKey(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing file fell back to env")
	}
	if _, err := BasetenKey(dir); err == nil {
		t.Fatal("directory accepted")
	}
	os.WriteFile(p, []byte("KEY=value with spaces"), 0600)
	if _, err := BasetenKey(p); err == nil {
		t.Fatal("malformed key accepted")
	}
}
func TestBasetenCleanupCancellationAndNonDeletion(t *testing.T) {
	c, f := newBasetenFake(t)
	b, _ := c.CreateBaseten(context.Background(), t.TempDir(), "")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// Do not let a fake transport ignore the context as the real transport won't.
	c.http.Transport = basetenTransport(func(r *http.Request) (*http.Response, error) {
		if r.Context().Err() != nil {
			return nil, r.Context().Err()
		}
		return f.transport(r)
	})
	if b.Destroy(ctx) == nil || f.deletes != 0 {
		t.Fatal("cancelled cleanup succeeded")
	}
	if _, err := os.Stat(b.state); err != nil {
		t.Fatal("journal discarded")
	}
	if err := b.Destroy(context.Background()); err != nil {
		t.Fatal("fresh cleanup context failed", err)
	}
	for _, status := range []string{"ARCHIVED", "DEACTIVATED", "MYSTERY"} {
		c, f := newBasetenFake(t)
		b, _ := c.CreateBaseten(context.Background(), t.TempDir(), "")
		f.sandbox.Status = status
		if status == "MYSTERY" {
			if b.Destroy(context.Background()) == nil || f.deletes != 0 {
				t.Fatal("unknown status counted gone")
			}
		} else if err := b.Destroy(context.Background()); err != nil || f.deletes != 1 {
			t.Fatal("nonterminal status counted as deleted", err)
		}
	}
}
func TestBasetenHTTPFailureRedaction(t *testing.T) {
	c, _ := newBasetenFake(t)
	c.http.Transport = basetenTransport(func(r *http.Request) (*http.Response, error) {
		return basetenResponse(403, `{"message":"test-key and test-access-token"}`), nil
	})
	if err := c.Authenticate(context.Background()); err == nil || err.Error() != "Baseten HTTP 403" {
		t.Fatal("HTTP failure not sanitized")
	}
}

func TestBasetenProvisioningStates(t *testing.T) {
	for _, status := range []string{"DEPLOYING", "BUILDING", "UPLOADING"} {
		t.Run(status, func(t *testing.T) {
			c, f := newBasetenFake(t)
			f.createStatus = status
			b, err := c.CreateBaseten(context.Background(), t.TempDir(), "")
			if err != nil {
				t.Fatal("valid provisioning state refused", err)
			}
			if err := b.Destroy(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Opt-in management/runtime smoke test. -survey inventories the guest but runs
// no network checks. The full graded run uses the CLI and the external canary.
func TestLiveBasetenLifecycle(t *testing.T) {
	if os.Getenv("SANDPROBE_LIVE_BASETEN") != "1" {
		t.Skip("set SANDPROBE_LIVE_BASETEN=1 only for the approved disposable test")
	}
	key, err := BasetenKey(os.Getenv("SANDPROBE_BASETEN_KEY_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewBasetenClient(key, os.Getenv("BASETEN_TEAM_ID"))
	if err != nil {
		t.Fatal(err)
	}
	home, _ := os.UserHomeDir()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	b, err := c.CreateBaseten(ctx, filepath.Join(home, ".config", "sandprobe"), os.Getenv("BASETEN_REGION"))
	if b != nil {
		defer func() {
			cleanup, stop := context.WithTimeout(context.Background(), 3*time.Minute)
			defer stop()
			if e := b.Destroy(cleanup); e != nil {
				t.Errorf("cleanup unconfirmed: %s; journal %s", e, b.StatePath())
			} else {
				t.Log("sandbox deletion confirmed")
			}
		}()
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Log("created sandbox", b.Name)
	if err = b.DetectArch(ctx); err != nil {
		t.Fatal(err)
	}
	binary, _, err := probes.Probe(b.Arch)
	if err != nil {
		t.Fatal(err)
	}
	if err = b.Upload(ctx, binary); err != nil {
		t.Fatal(err)
	}
	raw, err := b.Probe(ctx, []string{"-survey"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	survey, err := obs.ParseSurvey(raw)
	if err != nil {
		t.Fatal("survey did not match the host contract")
	}
	t.Log("uploaded digest verified; guest survey parsed; architecture", b.Arch, "survey present", survey != nil)
}

func TestBasetenUploadAndProbe(t *testing.T) {
	c, f := newBasetenFake(t)
	b, err := c.CreateBaseten(context.Background(), t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	if err = b.Upload(context.Background(), []byte("dummy probe bytes")); err != nil {
		t.Fatal(err)
	}
	if string(f.upload) != "dummy probe bytes" || b.ProbePath == "" {
		t.Fatal("upload missing")
	}
	if _, err = b.Probe(context.Background(), []string{"-survey"}, []byte(`{"test":"stdin"}`)); err != nil {
		t.Fatal(err)
	}
	calls := f.runtime
	if _, err = b.Probe(context.Background(), []string{"-survey; echo injected"}, nil); err == nil || f.runtime != calls {
		t.Fatal("unsafe probe argument executed")
	}
}

func inspectionSandbox(t *testing.T) (*BasetenClient, *basetenFake, *BasetenBox) {
	t.Helper()
	c, f := newBasetenFake(t)
	b, err := c.CreateBasetenForInspection(context.Background(), t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	err = json.Unmarshal([]byte(`{"expires_in":3590,"lifecycle":{"expiration_policies":[{"type":"TTL_MAX_AGE","action":"DELETE","value":"1h"}]}}`), &f.sandbox)
	if err != nil {
		t.Fatal(err)
	}
	return c, f, b
}
func TestBasetenRetainAndRecover(t *testing.T) {
	_, f, b := inspectionSandbox(t)
	policies := f.payload["lifecycle"].(map[string]any)["expiration_policies"].([]any)
	if policies[0].(map[string]any)["value"] != "1h" {
		t.Fatal("inspection expiry not set at creation")
	}
	expiry, err := b.Retain(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	born, _ := time.Parse(time.RFC3339Nano, b.identity.Created)
	if !expiry.Equal(born.Add(time.Hour)) || f.deletes != 0 {
		t.Fatal("retention extended deadline or deleted sandbox")
	}
	client, _ := NewBasetenClient("test-key", "")
	client.http.Transport = basetenTransport(f.transport)
	client.poll = time.Microsecond
	recovered, err := client.LoadBasetenJournal(b.state)
	if err != nil {
		t.Fatal(err)
	}
	if !recovered.journal.Retained || client.team != "team-one" {
		t.Fatal("retention/team journal lost")
	}
	if err = recovered.Destroy(context.Background()); err != nil || f.deletes != 1 {
		t.Fatal("recovered cleanup failed", err)
	}
}
func TestBasetenRetentionFailsClosed(t *testing.T) {
	for _, mode := range []string{"missing-expiry", "expired", "extended", "changed-policy", "missing-policy", "replacement", "stopped", "journal-expiry"} {
		t.Run(mode, func(t *testing.T) {
			_, f, b := inspectionSandbox(t)
			switch mode {
			case "missing-expiry":
				f.sandbox.ExpiresIn = nil
			case "expired":
				n := 0
				f.sandbox.ExpiresIn = &n
			case "extended":
				born := time.Now().Add(-30 * time.Minute)
				b.identity.Created = born.Format(time.RFC3339Nano)
				f.sandbox.Created = b.identity.Created
				b.journal.ExpiresAt = born.Add(time.Hour).Format(time.RFC3339Nano)
			case "changed-policy":
				f.sandbox.Lifecycle.Policies[0].Value = "2h"
			case "missing-policy":
				f.sandbox.Lifecycle.Policies = nil
			case "replacement":
				f.sandbox.External = "replacement"
			case "stopped":
				f.sandbox.Status = "DEACTIVATED"
			case "journal-expiry":
				b.journal.ExpiresAt = time.Now().Add(24 * time.Hour).Format(time.RFC3339Nano)
			}
			if _, err := b.Retain(context.Background()); err == nil {
				t.Fatal("unverified sandbox retained")
			}
			if f.deletes != 0 {
				t.Fatal("retention verification performed deletion")
			}
		})
	}
	c, _ := newBasetenFake(t)
	b, err := c.CreateBaseten(context.Background(), t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = b.Retain(context.Background()); err == nil {
		t.Fatal("retention enabled after ordinary creation")
	}
}
func TestBasetenJournalRecoveryRefusesUnsafeFiles(t *testing.T) {
	for _, mode := range []string{"symlink", "permissions", "unknown-field", "trailing-json", "ambiguous", "wrong-team", "wrong-expiry"} {
		t.Run(mode, func(t *testing.T) {
			c, f, b := inspectionSandbox(t)
			path := b.state
			switch mode {
			case "symlink":
				path = filepath.Join(t.TempDir(), filepath.Base(b.state))
				os.Symlink(b.state, path)
			case "permissions":
				os.Chmod(path, 0644)
			case "unknown-field":
				raw, _ := os.ReadFile(path)
				raw = append(raw[:len(raw)-1], []byte(`,"surprise":true}`)...)
				os.WriteFile(path, raw, 0600)
			case "trailing-json":
				raw, _ := os.ReadFile(path)
				os.WriteFile(path, append(raw, []byte(`{}`)...), 0600)
			case "ambiguous":
				b.journal.Identity = nil
				b.save()
			case "wrong-team":
				c.team = "other-team"
			case "wrong-expiry":
				b.journal.ExpiresAt = time.Now().Add(24 * time.Hour).Format(time.RFC3339Nano)
				b.save()
			}
			before := f.deletes
			if _, err := c.LoadBasetenJournal(path); err == nil {
				t.Fatal("unsafe journal accepted")
			}
			if f.deletes != before {
				t.Fatal("journal loading contacted a resource")
			}
		})
	}
}
