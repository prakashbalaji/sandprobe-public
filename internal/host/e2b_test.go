package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"sandprobe/internal/probes"
)

type e2bFake struct {
	t                                             *testing.T
	sandbox                                       e2bSandbox
	creates, deletes, runtime                     int
	ambiguous, deleted, wrongDigest, forbidDelete bool
	patchCreate                                   func(*e2bSandbox)
	payload                                       map[string]any
	upload                                        []byte
}

func (f *e2bFake) transport(r *http.Request) (*http.Response, error) {
	if r.URL.Host != "api.e2b.app" {
		f.t.Fatal("unexpected management host")
	}
	if r.Header.Get("X-API-Key") != "e2b-test-key" {
		f.t.Fatal("management key missing")
	}
	switch {
	case r.Method == "POST":
		f.creates++
		json.NewDecoder(r.Body).Decode(&f.payload)
		if r.URL.Path != "/v2/sandboxes" {
			f.t.Error("wrong create route")
		}
		if f.ambiguous {
			return nil, errors.New("e2b-test-key upstream body")
		}
		marker := f.payload["metadata"].(map[string]any)["sandprobe_run"].(string)
		now := time.Now().UTC()
		f.sandbox = e2bSandbox{e2bIdentity: e2bIdentity{ID: "testbox123", Template: "base-template-id", Version: "0.5.0", Domain: "e2b.app"}, Token: "sandbox-only-token", Metadata: map[string]string{"sandprobe_run": marker}, Started: now, End: now.Add(900 * time.Second), State: "running"}
		response := f.sandbox
		if f.patchCreate != nil {
			f.patchCreate(&response)
		}
		raw, _ := json.Marshal(response)
		return basetenResponse(201, string(raw)), nil
	case r.Method == "DELETE":
		if f.forbidDelete {
			return basetenResponse(403, "e2b-test-key"), nil
		}
		f.deletes++
		f.deleted = true
		return basetenResponse(204, ""), nil
	case r.Method == "GET":
		if strings.Contains(r.URL.RawQuery, "limit") {
			return basetenResponse(200, "[]"), nil
		}
		if f.deleted {
			return basetenResponse(404, "gone"), nil
		}
		raw, _ := json.Marshal(f.sandbox)
		return basetenResponse(200, string(raw)), nil
	}
	return basetenResponse(500, "e2b-test-key"), nil
}
func (f *e2bFake) sdk(ctx context.Context, in map[string]any) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if in["op"] == "check" {
		return []byte(`{"version":"` + E2BSDKVersion + `"}`), nil
	}
	f.runtime++
	if in["access_token"] != "sandbox-only-token" {
		f.t.Fatal("runtime got wrong token")
	}
	raw, _ := json.Marshal(in)
	if strings.Contains(string(raw), "e2b-test-key") {
		f.t.Fatal("management key reached runtime")
	}
	if in["sandbox_id"] != f.sandbox.ID {
		f.t.Fatal("wrong runtime target")
	}
	if in["op"] == "upload" {
		f.upload = in["data"].([]byte)
		return []byte("{}"), nil
	}
	command := in["command"].(string)
	switch {
	case command == "uname -m":
		return []byte("x86_64\n"), nil
	case strings.Contains(command, "mktemp"):
		return []byte("/tmp/sandprobe-Abc123Def456\n"), nil
	case strings.Contains(command, "sha256sum"):
		sum := sha256.Sum256(f.upload)
		digest := hex.EncodeToString(sum[:])
		if f.wrongDigest {
			digest = strings.Repeat("0", 64)
		}
		return []byte(digest + " /tmp/sandprobe-Abc123Def456/probe\n"), nil
	case strings.Contains(command, "/probe"):
		if !strings.Contains(command, "trap 'rm -f ") {
			f.t.Fatal("input not cleaned")
		}
		return []byte("{}"), nil
	}
	return nil, fmt.Errorf("unexpected command")
}
func newE2BFake(t *testing.T) (*E2BClient, *e2bFake) {
	t.Helper()
	f := &e2bFake{t: t}
	c, err := NewE2BClient("e2b-test-key", "python3")
	if err != nil {
		t.Fatal(err)
	}
	c.http.Transport = basetenTransport(f.transport)
	c.runtime = f.sdk
	return c, f
}
func TestE2BVerifiedLifecycle(t *testing.T) {
	c, f := newE2BFake(t)
	ctx := context.Background()
	b, err := c.CreateE2B(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if f.creates != 1 || f.payload["timeout"] != float64(900) || f.payload["autoPause"] != false || f.payload["secure"] != true {
		t.Fatal("unbounded create")
	}
	journal, err := os.ReadFile(b.StatePath())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(journal), "token") || strings.Contains(string(journal), "key") {
		t.Fatal("credential journaled")
	}
	st, _ := os.Stat(b.StatePath())
	if st.Mode().Perm() != 0600 {
		t.Fatal("journal not private")
	}
	if err = b.DetectArch(ctx); err != nil || b.Arch != "amd64" {
		t.Fatal("detect", err)
	}
	if err = b.Upload(ctx, []byte("probe-binary")); err != nil {
		t.Fatal(err)
	}
	if _, err = b.Probe(ctx, []string{"-survey"}, nil); err != nil {
		t.Fatal(err)
	}
	if err = b.Destroy(ctx); err != nil || f.deletes != 1 {
		t.Fatal("delete", err)
	}
	if _, err = os.Stat(b.StatePath()); !os.IsNotExist(err) {
		t.Fatal("journal left after verified delete")
	}
}
func TestE2BAmbiguousCreateNeverRetriesOrGuesses(t *testing.T) {
	c, f := newE2BFake(t)
	f.ambiguous = true
	b, err := c.CreateE2B(context.Background(), t.TempDir())
	if err == nil || strings.Contains(err.Error(), "e2b-test-key") || f.creates != 1 {
		t.Fatal("create retry or leak")
	}
	if b == nil || b.ID() != "" {
		t.Fatal("ambiguous ID adopted")
	}
	if err = b.Destroy(context.Background()); err == nil || f.deletes != 0 {
		t.Fatal("deleted guessed target")
	}
	if _, err = os.Stat(b.StatePath()); err != nil {
		t.Fatal("lost unresolved journal")
	}
}
func TestE2BBadRuntimeIdentityStillJournalsIDForCleanup(t *testing.T) {
	for _, change := range []func(*e2bSandbox){
		func(s *e2bSandbox) { s.Domain = "evil.example" },
		func(s *e2bSandbox) { s.Token = "" },
		func(s *e2bSandbox) { s.Version = "bad" },
	} {
		c, f := newE2BFake(t)
		f.patchCreate = change
		b, err := c.CreateE2B(context.Background(), t.TempDir())
		if err == nil || b == nil || b.ID() != "testbox123" {
			t.Fatal("lost known returned ID")
		}
		raw, _ := os.ReadFile(b.StatePath())
		if !strings.Contains(string(raw), "testbox123") {
			t.Fatal("ID not persisted")
		}
		if err = b.Destroy(context.Background()); err != nil || f.deletes != 1 {
			t.Fatal("known own ID not cleaned", err)
		}
	}
}
func TestE2BOwnershipExpiryAndUploadFailures(t *testing.T) {
	for _, what := range []string{"metadata", "expiry", "digest", "delete403"} {
		t.Run(what, func(t *testing.T) {
			c, f := newE2BFake(t)
			b, err := c.CreateE2B(context.Background(), t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			switch what {
			case "metadata":
				f.sandbox.Metadata["sandprobe_run"] = "another-run"
				if _, err = b.command(context.Background(), "uname -m"); err == nil || f.runtime != 0 {
					t.Fatal("runtime followed foreign sandbox")
				}
				if err = b.Destroy(context.Background()); err == nil || f.deletes != 0 {
					t.Fatal("foreign metadata deleted")
				}
			case "expiry":
				f.sandbox.End = f.sandbox.Started.Add(time.Hour)
				if _, err = b.command(context.Background(), "uname -m"); err == nil || f.runtime != 0 {
					t.Fatal("lifetime not checked")
				}
				if err = b.Destroy(context.Background()); err != nil {
					t.Fatal(err)
				}
			case "digest":
				f.wrongDigest = true
				if err = b.Upload(context.Background(), []byte("binary")); err == nil {
					t.Fatal("bad digest accepted")
				}
				if err = b.Destroy(context.Background()); err != nil {
					t.Fatal(err)
				}
			case "delete403":
				f.forbidDelete = true
				if err = b.Destroy(context.Background()); err == nil || b.gone {
					t.Fatal("403 counted as absence")
				}
				if _, err = os.Stat(b.StatePath()); err != nil {
					t.Fatal("unresolved journal lost")
				}
			}
		})
	}
}
func TestE2BRedirectAndErrorsDoNotLeak(t *testing.T) {
	c, _ := NewE2BClient("e2b-test-key", "python3")
	calls := 0
	c.http.Transport = basetenTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		resp := basetenResponse(302, "e2b-test-key")
		resp.Header.Set("Location", "https://evil.example/")
		return resp, nil
	})
	err := c.Available(context.Background())
	if err == nil || calls != 1 || strings.Contains(err.Error(), "e2b-test-key") {
		t.Fatal("redirect or secret leak")
	}
	c.http.Transport = basetenTransport(func(r *http.Request) (*http.Response, error) {
		return basetenResponse(200, strings.Repeat("x", obsMaxForE2BTest())), nil
	})
	if err = c.Available(context.Background()); err == nil {
		t.Fatal("oversized response accepted")
	}
}
func obsMaxForE2BTest() int { return (1 << 20) + 1 }
func TestE2BKeyBoundaries(t *testing.T) {
	t.Setenv("E2B_API_KEY", "fallback-key")
	dir := t.TempDir()
	file := filepath.Join(dir, "key")
	if _, err := E2BKey(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("explicit file fell back")
	}
	os.WriteFile(file, []byte("private-key\n"), 0600)
	if key, err := E2BKey(file); err != nil || key != "private-key" {
		t.Fatal("private key refused")
	}
	link := filepath.Join(dir, "link")
	os.Symlink(file, link)
	if _, err := E2BKey(link); err == nil {
		t.Fatal("symlink accepted")
	}
	os.Chmod(file, 0644)
	if _, err := E2BKey(file); err == nil {
		t.Fatal("public key accepted")
	}
	os.Chmod(file, 0600)
	os.WriteFile(file, []byte(strings.Repeat("x", 8193)), 0600)
	if _, err := E2BKey(file); err == nil {
		t.Fatal("oversize key accepted")
	}
}
func TestE2BSDKOutputBound(t *testing.T) {
	var b cappedE2BOutput
	if _, err := b.Write(make([]byte, 1<<20)); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Write([]byte("x")); err == nil {
		t.Fatal("output limit not enforced")
	}
}

func TestE2BMalformedOptionalFieldCannotHideReturnedID(t *testing.T) {
	c, f := newE2BFake(t)
	c.http.Transport = basetenTransport(func(r *http.Request) (*http.Response, error) {
		resp, err := f.transport(r)
		if r.Method == "POST" && err == nil {
			resp.Body.Close()
			resp.Body = io.NopCloser(strings.NewReader(`{"startedAt":"invalid-date","sandboxID":"testbox123"}`))
		}
		return resp, err
	})
	b, err := c.CreateE2B(context.Background(), t.TempDir())
	if err == nil || b == nil || b.ID() != "testbox123" {
		t.Fatal("typed decode hid returned ID")
	}
	if err = b.Destroy(context.Background()); err != nil || f.deletes != 1 {
		t.Fatal("known own ID not cleaned", err)
	}
}

func TestE2BKeyFIFORejectedWithoutBlocking(t *testing.T) {
	file := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(file, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := E2BKey(file); err == nil {
		t.Fatal("FIFO accepted as key")
	}
}

func TestE2BHelperDoesNotInheritHostSecretsOrOverrides(t *testing.T) {
	for _, name := range []string{"E2B_API_KEY", "AWS_SECRET_ACCESS_KEY", "E2B_DOMAIN", "E2B_SANDBOX_URL", "PYTHONPATH", "HTTPS_PROXY"} {
		t.Setenv(name, "sentinel-must-not-reach-helper")
	}
	python := filepath.Join(t.TempDir(), "fake-python")
	script := "#!/bin/sh\n" +
		"test -z \"$E2B_API_KEY$AWS_SECRET_ACCESS_KEY$E2B_DOMAIN$E2B_SANDBOX_URL$PYTHONPATH$HTTPS_PROXY\" || exit 99\n" +
		"printf '{\"version\":\"" + E2BSDKVersion + "\"}'\n"
	if err := os.WriteFile(python, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	c, _ := NewE2BClient("e2b-test-key", python)
	if err := c.CheckSDK(context.Background()); err != nil {
		t.Fatal(err)
	}
}

var _ io.Writer = (*cappedE2BOutput)(nil)

// Opt-in lifecycle only: no containment probe or network checks are executed here.
func TestLiveE2BLifecycle(t *testing.T) {
	if os.Getenv("SANDPROBE_LIVE_E2B") != "1" {
		t.Skip("explicit live scope required")
	}
	key, err := E2BKey(os.Getenv("SANDPROBE_E2B_KEY_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewE2BClient(key, os.Getenv("SANDPROBE_E2B_PYTHON"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	if err = c.CheckSDK(ctx); err != nil {
		t.Fatal(err)
	}
	if err = c.Available(ctx); err != nil {
		t.Fatal(err)
	}
	home, _ := os.UserHomeDir()
	b, createErr := c.CreateE2B(ctx, filepath.Join(home, ".config", "sandprobe"))
	if b != nil {
		t.Cleanup(func() {
			cleanupCtx, stop := context.WithTimeout(context.Background(), 3*time.Minute)
			defer stop()
			if e := b.Destroy(cleanupCtx); e != nil {
				t.Errorf("cleanup failed: %s; journal %s", e, b.StatePath())
			} else {
				t.Log("sandbox deletion confirmed")
			}
		})
	}
	if createErr != nil {
		t.Fatal(createErr)
	}
	t.Log("created sandbox", b.ID())
	if err = b.DetectArch(ctx); err != nil {
		t.Fatal(err)
	}
	bin, _, err := probes.Probe(b.Arch)
	if err != nil {
		t.Fatal(err)
	}
	if err = b.Upload(ctx, bin); err != nil {
		t.Fatal(err)
	}
	raw, err := b.Probe(ctx, []string{"-survey"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var survey map[string]any
	if json.Unmarshal(raw, &survey) != nil || survey["schema"] != "sandprobe.survey/1" {
		t.Fatal("survey malformed")
	}
	t.Log("architecture", b.Arch, "upload digest verified; survey parsed; containment checks not executed")
}
