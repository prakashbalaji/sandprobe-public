package host

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sandprobe/internal/obs"
	"strings"
	"testing"
	"time"
)

type vercelFake struct {
	t                                                     *testing.T
	reply                                                 vercelReply
	creates, runtime, stops, deletes                      int
	ambiguous, malformed, deleted, replaced, refuseDelete bool
	patch                                                 func(*vercelReply)
	uploaded                                              []byte
}

func (f *vercelFake) transport(r *http.Request) (*http.Response, error) {
	// PRV-9 contract from official SDK3.9.1, not the public REST origin.
	if r.URL.Scheme != "https" || r.URL.Host != "vercel.com" || !strings.HasPrefix(r.URL.Path, "/api/") {
		f.t.Fatal("request must use official SDK HTTPS origin and /api prefix")
	}
	path := strings.TrimPrefix(r.URL.Path, "/api")
	if r.Header.Get("Authorization") != "Bearer test-key" || r.URL.Query().Get("teamId") != "team_test" {
		f.t.Fatal("wrong authorization/scope")
	}
	switch {
	case r.Method == "POST" && path == "/v3/sandboxes":
		f.creates++
		var p map[string]any
		json.NewDecoder(r.Body).Decode(&p)
		if p["persistent"] != false || p["timeout"] != float64(900000) || p["projectId"] != "prj_test" {
			f.t.Fatal("unsafe creation")
		}
		if f.ambiguous {
			return nil, errors.New("test-key upstream failure")
		}
		now := time.Now().UnixMilli()
		no := false
		name := p["name"].(string)
		f.reply = vercelReply{Sandbox: vercelSandbox{Name: name, Persistent: &no, Created: now, SessionID: "session_test", Tags: map[string]string{"sandprobe_run": name}}, Session: vercelSession{Cwd: "/vercel", ID: "session_test", Status: "running", Created: now, Started: now, Timeout: 900000}}
		if f.patch != nil {
			f.patch(&f.reply)
		}
		if f.malformed {
			return basetenResponse(200, `{"session":{"id":"session_test"},"sandbox":{"persistent":"invalid"}}`), nil
		}
		raw, _ := json.Marshal(f.reply)
		return basetenResponse(200, string(raw)), nil
	case r.Method == "GET" && path == "/v9/projects/prj_test":
		return basetenResponse(200, `{"id":"prj_test","accountId":"team_test"}`), nil
	case r.Method == "GET" && strings.HasPrefix(path, "/v2/sandboxes/sessions/"):
		raw, _ := json.Marshal(map[string]any{"session": f.reply.Session})
		return basetenResponse(200, string(raw)), nil
	case strings.HasSuffix(path, "/stop"):
		f.stops++
		f.reply.Session.Status = "stopped"
		f.reply.Sandbox.SessionID = ""
		return basetenResponse(200, `{}`), nil
	case strings.HasSuffix(path, "/cmd"):
		f.runtime++
		var p struct {
			Command string
			Cwd     string
			Args    []string
			Sudo    bool
			Env     map[string]string
		}
		json.NewDecoder(r.Body).Decode(&p)
		if p.Cwd != f.reply.Session.Cwd {
			f.t.Fatal("command uses a working directory other than create response")
		}
		if p.Command != "/bin/bash" || len(p.Args) != 2 || p.Args[0] != "-c" {
			f.t.Fatal("command must use the fixed absolute image shell without fallback")
		}
		if p.Sudo || strings.Contains(strings.Join(p.Args, " "), "test-key") || len(p.Env) != 1 {
			f.t.Fatal("key or privilege reached guest")
		}
		out := ""
		script := p.Args[1]
		switch {
		case script == "uname -m":
			out = "x86_64\n"
		case strings.Contains(script, "mktemp"):
			out = f.reply.Session.Cwd + "/.sandprobe-Abc123Def456\n"
		case strings.Contains(script, "sha256sum"):
			sum := sha256.Sum256(f.uploaded)
			out = hex.EncodeToString(sum[:]) + "  " + strings.TrimPrefix(script, "sha256sum ") + "\n"
		default:
			out = "{}"
		}
		resp := basetenResponse(200, vercelStream(out, 0))
		resp.Header.Set("Content-Type", "application/x-ndjson")
		return resp, nil
	case strings.HasSuffix(path, "/fs/write"):
		f.runtime++
		if r.Header.Get("x-cwd") != f.reply.Session.Cwd+"/.sandprobe-Abc123Def456" || r.Header.Get("Content-Type") != "application/gzip" {
			f.t.Fatal("unsafe archive target")
		}
		gz, e := gzip.NewReader(r.Body)
		if e != nil {
			f.t.Fatal(e)
		}
		defer gz.Close()
		tr := tar.NewReader(gz)
		h, e := tr.Next()
		if e != nil || strings.Contains(h.Name, "/") || h.Typeflag != tar.TypeReg || (h.Mode != 0700 && h.Mode != 0600) {
			f.t.Fatal("unsafe archive")
		}
		f.uploaded, _ = io.ReadAll(tr)
		if _, e = tr.Next(); e != io.EOF {
			f.t.Fatal("extra archive member")
		}
		return basetenResponse(200, `{}`), nil
	case strings.HasPrefix(path, "/v2/sandboxes/"):
		if r.URL.Query().Get("resume") != "false" || r.URL.Query().Get("projectId") != "prj_test" {
			f.t.Fatal("resume or project binding missing")
		}
		if f.deleted {
			return basetenResponse(404, ""), nil
		}
		if r.Method == "DELETE" {
			if f.refuseDelete {
				return basetenResponse(403, "test-key"), nil
			}
			f.deletes++
			f.deleted = true
			return basetenResponse(200, `{}`), nil
		}
		v := f.reply
		if f.replaced {
			v.Sandbox.Created++
		}
		raw, _ := json.Marshal(v)
		return basetenResponse(200, string(raw)), nil
	}
	f.t.Fatalf("unexpected route %s %s", r.Method, path)
	return nil, nil
}
func newVercelFake(t *testing.T) (*VercelClient, *vercelFake) {
	f := &vercelFake{t: t}
	c, e := NewVercelClient("test-key", "team_test", "prj_test")
	if e != nil {
		t.Fatal(e)
	}
	c.http.Transport = vercelTransport(f.transport)
	return c, f
}
func vercelStream(out string, exit int) string {
	initial := `{"command":{"id":"cmd_test","sessionId":"session_test","exitCode":null}}` + "\n"
	log, _ := json.Marshal(map[string]string{"stream": "stdout", "data": out})
	terminal, _ := json.Marshal(map[string]any{"command": map[string]any{"id": "cmd_test", "sessionId": "session_test", "exitCode": exit}})
	return initial + string(log) + "\n" + string(terminal) + "\n"
}
func TestVercelLifecycleUploadAndCleanup(t *testing.T) {
	c, f := newVercelFake(t)
	if e := c.Available(context.Background()); e != nil {
		t.Fatal(e)
	}
	b, e := c.CreateVercel(context.Background(), t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if e = b.DetectArch(context.Background()); e != nil || b.Arch != "amd64" {
		t.Fatal(e)
	}
	if e = b.Upload(context.Background(), []byte("static-probe")); e != nil {
		t.Fatal(e)
	}
	if _, e = b.Probe(context.Background(), []string{"-survey"}, []byte("{}")); e != nil {
		t.Fatal(e)
	}
	if e = b.Destroy(context.Background()); e != nil {
		t.Fatal(e)
	}
	if f.creates != 1 || f.stops != 1 || f.deletes != 1 || !f.deleted {
		t.Fatal("lifecycle incomplete")
	}
	if _, e = os.Stat(b.StatePath()); !os.IsNotExist(e) {
		t.Fatal("journal not retired")
	}
	if e = b.Destroy(context.Background()); e != nil || f.stops != 1 {
		t.Fatal("cleanup not idempotent")
	}
}
func TestVercelCreateFailureRetainsIdentityWithoutRetry(t *testing.T) {
	for _, kind := range []string{"ambiguous", "malformed"} {
		t.Run(kind, func(t *testing.T) {
			c, f := newVercelFake(t)
			f.ambiguous = kind == "ambiguous"
			f.malformed = kind == "malformed"
			b, e := c.CreateVercel(context.Background(), t.TempDir())
			if e == nil || strings.Contains(e.Error(), "test-key") || f.creates != 1 || f.runtime != 0 {
				t.Fatal("unsafe failure")
			}
			raw, e := os.ReadFile(b.StatePath())
			if e != nil || !json.Valid(raw) {
				t.Fatal("journal lost")
			}
			if kind == "malformed" && b.ID() != "session_test" {
				t.Fatal("immutable ID lost")
			}
			if e = b.Destroy(context.Background()); e == nil {
				t.Fatal("ambiguous cleanup falsely succeeded")
			}
			if kind == "malformed" && f.stops != 1 {
				t.Fatal("known compute not stopped")
			}
			if f.deletes != 0 {
				t.Fatal("unverified name deleted")
			}
		})
	}
}
func TestVercelRejectsIdentityPersistenceAndLifetime(t *testing.T) {
	patches := map[string]func(*vercelReply){"persistent": func(r *vercelReply) { yes := true; r.Sandbox.Persistent = &yes }, "missing persistent": func(r *vercelReply) { r.Sandbox.Persistent = nil }, "snapshot": func(r *vercelReply) { r.Sandbox.SnapshotID = "snapshot_other" }, "mount": func(r *vercelReply) { r.Sandbox.Mounts = map[string]json.RawMessage{"x": json.RawMessage(`{}`)} }, "session": func(r *vercelReply) { r.Sandbox.SessionID = "other" }, "ancient session created valid start": func(r *vercelReply) { r.Session.Created = 1 }, "ancient sandbox created": func(r *vercelReply) { r.Sandbox.Created = 1 }, "future start": func(r *vercelReply) { r.Session.Started = time.Now().Add(time.Hour).UnixMilli() }, "timeout": func(r *vercelReply) { r.Session.Timeout = 900001 }}
	for name, patch := range patches {
		t.Run(name, func(t *testing.T) {
			c, f := newVercelFake(t)
			f.patch = patch
			b, e := c.CreateVercel(context.Background(), t.TempDir())
			if e == nil || f.runtime != 0 || b == nil {
				t.Fatal("unsafe response accepted")
			}
		})
	}
}
func TestVercelCleanupRefusesReplacementOrDeletionError(t *testing.T) {
	for _, replacement := range []bool{false, true} {
		c, f := newVercelFake(t)
		b, e := c.CreateVercel(context.Background(), t.TempDir())
		if e != nil {
			t.Fatal(e)
		}
		f.replaced = replacement
		f.refuseDelete = !replacement
		if e = b.Destroy(context.Background()); e == nil || strings.Contains(e.Error(), "test-key") {
			t.Fatal("cleanup falsely succeeded")
		}
		if _, e = os.Stat(b.StatePath()); e != nil {
			t.Fatal("unresolved journal lost")
		}
		if f.stops != 1 || f.deletes != 0 {
			t.Fatal("wrong resources deleted")
		}
	}
}
func TestVercelStreamFailClosed(t *testing.T) {
	good := vercelStream("hello", 0)
	out, e := parseVercelStream(strings.NewReader(good), "session_test")
	if e != nil || string(out) != "hello" {
		t.Fatal(e)
	}
	cases := []string{vercelStream("", 1), strings.Join(strings.Split(good, "\n")[:2], "\n"), good + `{}`, strings.ReplaceAll(good, "session_test", "other"), strings.Replace(good, `"exitCode":null`, `"exitCode":0`, 1), `{"stream":"stdout","data":"early"}`, vercelStream(strings.Repeat("x", obs.MaxDoc+1), 0), strings.Replace(good, `"stdout"`, `"stderr"`, 1) + strings.Repeat(" ", 8*obs.MaxDoc)}
	for i, s := range cases {
		if _, e = parseVercelStream(strings.NewReader(s), "session_test"); e == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	// Decoded stderr counts towards the same cap; it is never returned as evidence.
	stderr := strings.Replace(vercelStream(strings.Repeat("x", obs.MaxDoc+1), 0), `"stdout"`, `"stderr"`, 1)
	if _, e = parseVercelStream(strings.NewReader(stderr), "session_test"); e == nil {
		t.Fatal("stderr unbounded")
	}
}
func TestVercelTokenAndPrivateScratch(t *testing.T) {
	t.Setenv("VERCEL_TOKEN", "env-key")
	dir := t.TempDir()
	p := filepath.Join(dir, "key")
	os.WriteFile(p, []byte("file-key\n"), 0600)
	if key, e := VercelKey(p); e != nil || key != "file-key" {
		t.Fatal(e)
	}
	os.Chmod(p, 0644)
	if _, e := VercelKey(p); e == nil {
		t.Fatal("public key accepted")
	}
	os.Chmod(p, 0600)
	link := filepath.Join(dir, "link")
	os.Symlink(p, link)
	if _, e := VercelKey(link); e == nil {
		t.Fatal("symlink accepted")
	}
	if !vercelScratch.MatchString("/vercel/sandbox/.sandprobe-Abc123Def456") || vercelScratch.MatchString("/vercel/sandbox/xsandprobe-Abc123Def456") {
		t.Fatal("scratch validation invalid")
	}
	if _, e := NewVercelClient("x", "team_test", "other"); e == nil {
		t.Fatal("unbound project")
	}
}

type vercelTransport func(*http.Request) (*http.Response, error)

func (f vercelTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestVercelHTTPErrorsIdentifyOnlyFixedOperation(t *testing.T) {
	routes := map[string]string{
		"POST /v3/sandboxes":                                                     "create sandbox",
		"GET /v9/projects/prj_test":                                              "verify project",
		"POST /v2/sandboxes/sessions/session_test/cmd":                           "execute command",
		"POST /v2/sandboxes/sessions/session_test/fs/write":                      "upload private file",
		"POST /v2/sandboxes/sessions/session_test/stop":                          "stop immutable session",
		"GET /v2/sandboxes/sessions/session_test":                                "get immutable session",
		"GET /v2/sandboxes/sandprobe-private?projectId=prj_test&resume=false":    "get sandbox without resume",
		"DELETE /v2/sandboxes/sandprobe-private?projectId=prj_test&resume=false": "delete guarded sandbox",
	}
	for route, operation := range routes {
		t.Run(operation, func(t *testing.T) {
			c, _ := newVercelFake(t)
			c.http.Transport = vercelTransport(func(*http.Request) (*http.Response, error) {
				return basetenResponse(400, `{"error":{"message":"test-key credential must never escape"}}`), nil
			})
			method, path, _ := strings.Cut(route, " ")
			_, err := c.do(context.Background(), method, path, "application/json", nil, nil)
			want := "Vercel " + operation + " HTTP 400"
			if err == nil || err.Error() != want || !vercelStatus(err, 400) {
				t.Fatalf("wrong fixed error: %v", err)
			}
		})
	}
}

func TestVercelErrorHintsAreBoundedFixedVocabulary(t *testing.T) {
	cases := []struct{ body, want string }{
		{`{"error":{"message":"Invalid request: timeout must be valid; private-credential-value should not escape","code":"private-credential-value"}}`, " (provider wording mentions: request validation, field timeout)"},
		{`{"error":{"message":"No such file in working directory /private/customer-path"}}`, " (provider wording mentions: missing executable or path, working directory)"},
		{`{"error":{"message":"private-credential-value"}}`, ""},
		{`{"error":{"message":"timeout was rejected"}}` + strings.Repeat(" ", 65536), ""},
		{`{"error":{"message":"timeout"`, ""},
		{`{"error":{"message":"timeouts projectIdentity logstash"}}`, ""},
	}
	for _, c := range cases {
		if got := vercelErrorHint(strings.NewReader(c.body)); got != c.want {
			t.Errorf("got %q want %q", got, c.want)
		}
	}
}

func TestVercelUsesAndPinsCreateReturnedWorkingDirectory(t *testing.T) {
	for _, dir := range []string{"/vercel", "/vercel/sandbox"} {
		t.Run(dir, func(t *testing.T) {
			c, f := newVercelFake(t)
			f.patch = func(r *vercelReply) { r.Session.Cwd = dir }
			b, e := c.CreateVercel(context.Background(), t.TempDir())
			if e != nil {
				t.Fatal(e)
			}
			raw, e := os.ReadFile(b.StatePath())
			if e != nil {
				t.Fatal(e)
			}
			var journal vercelJournal
			if json.Unmarshal(raw, &journal) != nil || journal.WorkDir != dir {
				t.Fatal("working directory not journaled before execution")
			}
			other := "/vercel"
			if dir == other {
				other = "/vercel/sandbox"
			}
			if e = b.uploadFile(context.Background(), other+"/.sandprobe-Abc123Def456/probe", []byte("x"), 0700); e == nil || f.runtime != 0 {
				t.Fatal("upload accepted other base directory")
			}
			if e = b.DetectArch(context.Background()); e != nil {
				t.Fatal(e)
			}
			if e = b.Upload(context.Background(), []byte("static-probe")); e != nil || filepath.Dir(filepath.Dir(b.ProbePath)) != dir {
				t.Fatal("private upload not derived from create directory", e)
			}
			before := f.runtime
			f.reply.Session.Cwd = other
			if e = b.DetectArch(context.Background()); e == nil || f.runtime != before {
				t.Fatal("changed working directory accepted")
			}
			if e = b.Destroy(context.Background()); e != nil {
				t.Fatal(e)
			}
		})
	}
}
func TestVercelRejectsMissingUnsafeOrUnsupportedWorkingDirectory(t *testing.T) {
	for _, dir := range []string{"", "relative", "/vercel/../root", "/root", "/vercel;id", "/vercel/"} {
		t.Run(dir, func(t *testing.T) {
			c, f := newVercelFake(t)
			f.patch = func(r *vercelReply) { r.Session.Cwd = dir }
			b, e := c.CreateVercel(context.Background(), t.TempDir())
			if e == nil || b == nil || f.runtime != 0 {
				t.Fatal("unsupported create directory accepted")
			}
			if e = b.Destroy(context.Background()); e != nil {
				t.Fatal("known immutable compute not cleaned", e)
			}
		})
	}
}

func TestVercelInvalidRecordedNameNeverReachesNamedAPI(t *testing.T) {
	c, f := newVercelFake(t)
	b, e := c.CreateVercel(context.Background(), t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	b.journal.Requested = "../other-project?resume=true"
	transport := c.http.Transport
	c.http.Transport = vercelTransport(func(*http.Request) (*http.Response, error) { t.Fatal("invalid name reached provider"); return nil, nil })
	if _, e = b.lookup(context.Background()); e == nil {
		t.Fatal("invalid name accepted")
	}
	if e = b.DetectArch(context.Background()); e == nil {
		t.Fatal("runtime accepted invalid recorded name")
	}
	c.http.Transport = transport
	if e = b.Destroy(context.Background()); e == nil {
		t.Fatal("cleanup falsely claimed named record deleted")
	}
	if f.stops != 1 || f.deletes != 0 || f.runtime != 0 {
		t.Fatal("wrong resource operation after corrupted name")
	}
	if _, e = os.Stat(b.StatePath()); e != nil {
		t.Fatal("unresolved journal lost")
	}
}
