package host

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sandprobe/internal/probes"
	"strings"
	"testing"
	"time"
)

type cfRoundTrip func(*http.Request) (*http.Response, error)

func (f cfRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func cfTestBox(t *testing.T) *CloudflareBox {
	t.Helper()
	p := filepath.Join(t.TempDir(), "setup")
	s := CloudflareSetup{Origin: "https://sandprobe-test.example.workers.dev", Account: strings.Repeat("a", 32), Nonce: strings.Repeat("b", 32), Capability: strings.Repeat("c", 64)}
	data, _ := json.Marshal(s)
	if e := os.WriteFile(p, data, 0600); e != nil {
		t.Fatal(e)
	}
	b, e := NewCloudflareBox(p)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func cfResponse(value any) *http.Response {
	data, _ := json.Marshal(value)
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(data))), Header: http.Header{}}
}
func TestCloudflareUnsafeOriginAndCredentialFileRejected(t *testing.T) {
	b := cfTestBox(t)
	p := strings.TrimSuffix(b.state, ".box.state")
	for _, origin := range []string{"https://attacker.invalid", "http://x.workers.dev", "https://x.workers.dev/path", "https://x.workers.dev?token=x", "https://user:pass@x.workers.dev"} {
		b.setup.Origin = origin
		data, _ := json.Marshal(b.setup)
		os.WriteFile(p, data, 0600)
		if _, e := NewCloudflareBox(p); e == nil {
			t.Fatalf("accepted unsafe origin %q", origin)
		}
	}
	os.Chmod(p, 0644)
	if _, e := NewCloudflareBox(p); e == nil {
		t.Fatal("accepted public credentials")
	}
}
func TestCloudflareCreateFailureNeverRetriedAndCleanupUsesPinnedID(t *testing.T) {
	b := cfTestBox(t)
	id := strings.Repeat("d", 64)
	creates := 0
	closed := false
	b.http.Transport = cfRoundTrip(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Authorization") != "Bearer "+b.setup.Capability {
			t.Fatal("missing scoped capability")
		}
		switch r.URL.Path {
		case "/status":
			return cfResponse(cfStatus{ID: id, Closed: closed}), nil
		case "/create":
			creates++
			if _, e := os.Stat(b.state); e != nil {
				t.Fatal("no intent before create")
			}
			return nil, errors.New("secret-provider-error")
		case "/destroy":
			var v map[string]string
			json.NewDecoder(r.Body).Decode(&v)
			if v["id"] != id {
				t.Fatal("cleanup not pinned")
			}
			closed = true
			return cfResponse(cfStatus{ID: id, Closed: true}), nil
		}
		t.Fatal("unexpected call")
		return nil, nil
	})
	if e := b.Create(context.Background()); e == nil || strings.Contains(e.Error(), "secret-provider-error") {
		t.Fatal("missing failure or raw error escaped")
	}
	if creates != 1 {
		t.Fatal("create retried")
	}
	if e := b.Destroy(context.Background()); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(b.state); !os.IsNotExist(e) {
		t.Fatal("journal not retired")
	}
}
func TestCloudflareCommandRejectsMissingExitAndWrongIdentity(t *testing.T) {
	b := cfTestBox(t)
	b.id = strings.Repeat("d", 64)
	b.boot = "12345678-1234-1234-1234-123456789abc"
	for _, value := range []map[string]any{{"id": b.id, "stdout": "x"}, {"id": "wrong", "exit_code": 0}} {
		b.http.Transport = cfRoundTrip(func(*http.Request) (*http.Response, error) { return cfResponse(value), nil })
		if _, e := b.command(context.Background(), []string{"/bin/true"}, nil); e == nil {
			t.Fatal("invalid execution response accepted")
		}
	}
}
func TestCloudflareRedirectNeverSendsCapability(t *testing.T) {
	b := cfTestBox(t)
	if b.http.CheckRedirect(&http.Request{}, nil) != http.ErrUseLastResponse {
		t.Fatal("redirects enabled")
	}
}
func TestLiveCloudflareLifecycle(t *testing.T) {
	if os.Getenv("SANDPROBE_LIVE_CLOUDFLARE") != "1" {
		t.Skip("live test gated")
	}
	b, e := NewCloudflareBox(os.Getenv("SANDPROBE_CLOUDFLARE_SETUP"))
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	defer func() {
		clean, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		if e := b.Destroy(clean); e != nil {
			t.Errorf("cleanup unconfirmed: %v", e)
		}
	}()
	if e = b.Create(ctx); e != nil {
		t.Fatal(e)
	}
	if e = b.DetectArch(ctx); e != nil {
		t.Fatal(e)
	}
	bin, _, e := probes.Probe(b.Arch)
	if e != nil {
		t.Fatal(e)
	}
	if e = b.Upload(ctx, bin); e != nil {
		t.Fatal(e)
	}
	out, e := b.Probe(ctx, []string{"-survey"}, nil)
	if e != nil {
		t.Fatal(e)
	}
	if !json.Valid(out) {
		t.Fatal("survey invalid")
	}
	t.Log("Cloudflare lifecycle upload/digest/survey passed")
}
func TestCloudflareExistingIntentNeverCreatesOrDestroys(t *testing.T) {
	b := cfTestBox(t)
	os.WriteFile(b.state, []byte("prior-intent"), 0600)
	calls := 0
	b.http.Transport = cfRoundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Path != "/status" {
			t.Fatal("mutated prior-run object")
		}
		return cfResponse(cfStatus{ID: strings.Repeat("d", 64)}), nil
	})
	if b.Create(context.Background()) == nil {
		t.Fatal("existing intent accepted")
	}
	if e := b.Destroy(context.Background()); e != nil {
		t.Fatal(e)
	}
	if calls != 1 {
		t.Fatal("unexpected calls")
	}
	data, _ := os.ReadFile(b.state)
	if string(data) != "prior-intent" {
		t.Fatal("prior journal altered")
	}
}
func TestCloudflareUsedControllerNeverCreated(t *testing.T) {
	b := cfTestBox(t)
	calls := 0
	b.http.Transport = cfRoundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		return cfResponse(cfStatus{ID: strings.Repeat("d", 64), Created: true}), nil
	})
	if b.Create(context.Background()) == nil {
		t.Fatal("used controller accepted")
	}
	b.Destroy(context.Background())
	if calls != 1 {
		t.Fatal("used controller mutated")
	}
}
func TestCloudflareMissingStatusCannotProveAbsence(t *testing.T) {
	var status cfStatus
	if json.Unmarshal([]byte(`{"id":"`+strings.Repeat("d", 64)+`","closed":true}`), &status) == nil {
		t.Fatal("missing running evidence accepted")
	}
}
