package host

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const exTestKey = "exe1.fixture-token"
const exTestBoot = "12345678-1234-1234-1234-123456789abc"

func exResponse(status int, raw string, stream bool) *http.Response {
	h := http.Header{}
	if stream {
		h.Set("Content-Type", "application/x-ndjson")
	}
	return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader(raw))}
}
func exJSON(v any) string { b, _ := json.Marshal(v); return string(b) }
func exStream(out, stderr []byte, code int) string {
	return exJSON(map[string]string{"stdout": base64.StdEncoding.EncodeToString(out)}) + "\n" + exJSON(map[string]string{"stderr": base64.StdEncoding.EncodeToString(stderr)}) + "\n" + exJSON(map[string]int{"exit_code": code}) + "\n"
}

func TestExedevStreamRequiresUnambiguousTerminalEvidence(t *testing.T) {
	cases := []struct {
		name, raw string
		ok        bool
	}{
		{"success", exStream([]byte("ok"), nil, 0), true},
		{"equal stdout chunks", "{\"stdout\":\"YQ==\"}\n{\"stdout\":\"YQ==\"}\n{\"exit_code\":0}\n", true},
		{"empty stderr chunks", "{\"stderr\":\"\"}\n{\"stderr\":\"\"}\n{\"exit_code\":0}", true},
		{"no exit", "{\"stdout\":\"b2s=\"}\n", false},
		{"nonzero", exStream(nil, nil, 1), false},
		{"stderr", exStream(nil, []byte("private failure"), 0), false},
		{"exit duplicate", "{\"exit_code\":0}\n{\"exit_code\":0}", false},
		{"after exit", "{\"exit_code\":0}\n{\"stdout\":\"\"}", false},
		{"duplicate key", "{\"exit_code\":1,\"exit_code\":0}", false},
		{"case alias", "{\"EXIT_CODE\":0}", false},
		{"float exit", "{\"exit_code\":0.0}", false},
		{"error", "{\"error\":\"never print me\"}", false},
		{"extra field", "{\"stdout\":\"\",\"exit_code\":0}", false},
		{"bad base64", "{\"stdout\":\"!!!!\"}\n{\"exit_code\":0}", false},
		{"truncated", "{\"exit_code\":", false},
		{"empty", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := exOutput([]byte(tc.raw))
			if (err == nil) != tc.ok {
				t.Fatalf("success=%v want=%v", err == nil, tc.ok)
			}
			if err != nil && strings.Contains(err.Error(), "never print me") {
				t.Fatal("leaked error")
			}
		})
	}
	if _, err := exOutput([]byte(exStream(bytes.Repeat([]byte("a"), exLimit+1), nil, 0))); err == nil {
		t.Fatal("oversized decoded output accepted")
	}
}

type exFixture struct {
	t                            *testing.T
	c                            *ExedevClient
	b                            *ExedevBox
	journalDir                   string
	info                         exInfo
	created, deleted, launches   int
	missing, changed, dropCreate bool
	deleteReply                  string
	createReply                  string
	bootFile                     string
}

func newExFixture(t *testing.T) *exFixture {
	t.Helper()
	c, err := NewExedevClient(exTestKey)
	if err != nil {
		t.Fatal(err)
	}
	f := &exFixture{t: t, c: c, journalDir: t.TempDir(), bootFile: filepath.Join(t.TempDir(), "boot")}
	if err = os.Chmod(f.journalDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(f.bootFile, []byte(exTestBoot+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c.http.Transport = boatTransport(f.roundTrip)
	if err = c.Available(context.Background()); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *exFixture) roundTrip(r *http.Request) (*http.Response, error) {
	f.t.Helper()
	if r.Method != "POST" || r.URL.String() != "https://exe.dev/exec" || r.Header.Get("Authorization") != "Bearer "+exTestKey {
		f.t.Fatal("origin/method/auth changed")
	}
	body, _ := io.ReadAll(r.Body)
	cmd := string(body)
	switch {
	case cmd == "whoami":
		return exResponse(200, `{"email":"fixture@example.test","region":""}`, false), nil
	case strings.HasPrefix(cmd, "new "):
		f.created++
		raw, err := os.ReadFile(filepath.Join(f.journalDir, "exedev-active.state"))
		if err != nil {
			f.t.Fatal("create before journal")
		}
		var j exJournal
		if json.Unmarshal(raw, &j) != nil || j.Confirmed || j.Name == "" {
			f.t.Fatal("bad intent")
		}
		for _, want := range []string{"--sandbox", "--cpu=2", "--memory=4GB", "--image=ubuntu:24.04", "--egress=all", "--no-email", "--name=" + j.Name, "--tag=sandprobe,sandprobe-" + j.Nonce, "--env=SANDPROBE_TWIN=1"} {
			if !strings.Contains(cmd, want) {
				f.t.Fatal("missing create policy", want)
			}
		}
		if strings.Contains(cmd, exTestKey) || strings.Contains(cmd, "--prompt") || strings.Contains(cmd, "--integration") {
			f.t.Fatal("credential or integration in create")
		}
		if f.dropCreate {
			return nil, errors.New("private transport error " + exTestKey)
		}
		f.info = exInfo{Name: j.Name, Born: time.Now().UTC().Format(time.RFC3339Nano), Region: "dfw", Status: "running", Egress: "all", Tags: []string{"sandprobe", "sandprobe-" + j.Nonce}}
		if f.createReply != "" {
			return exResponse(200, strings.ReplaceAll(strings.ReplaceAll(f.createReply, "NAME", j.Name), "BORN", f.info.Born), false), nil
		}
		return exResponse(200, exJSON(map[string]any{"vm_name": j.Name, "created_at": f.info.Born, "future_field": "allowed"}), false), nil
	case strings.HasPrefix(cmd, "ls "):
		var list = []exInfo{}
		if !f.missing {
			info := f.info
			if f.changed {
				info.Born = "2001-01-01T00:00:00Z"
			}
			list = append(list, info)
		}
		return exResponse(200, exJSON(map[string]any{"vms": list}), false), nil
	case strings.HasPrefix(cmd, "rm "):
		f.deleted++
		if f.changed {
			f.t.Fatal("deleted changed identity")
		}
		if f.deleteReply != "" {
			return exResponse(200, f.deleteReply, false), nil
		}
		f.missing = true
		return exResponse(200, exJSON(map[string]any{"deleted": []string{f.info.Name}, "failed": []string{}}), false), nil
	case strings.HasPrefix(cmd, "ssh "):
		// Exercise both actual shell parsing layers on harmless fixture scripts.
		// Never reaches the network or executes a real Linux security probe.
		encoded := strings.TrimPrefix(cmd, "ssh "+f.info.Name+" ")
		first := exec.Command("sh", "-c", "set -- "+encoded+"; printf '%s' \"$1\"")
		guest, err := first.Output()
		if err != nil {
			f.t.Fatal("lobby quote decode failed")
		}
		script := strings.ReplaceAll(string(guest), "/proc/sys/kernel/random/boot_id", f.bootFile)
		script = strings.ReplaceAll(script, "sha256sum ", "shasum -a 256 ")
		// macOS fixtures lack GNU timeout; fixture workloads are bounded by test context.
		script = strings.ReplaceAll(script, "timeout -k 2s 95s ", "")
		if strings.Contains(script, "nohup setsid") {
			f.launches++
			script = strings.ReplaceAll(script, "nohup setsid", "nohup")
		}
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		proc := exec.CommandContext(ctx, "sh", "-c", script)
		var stdout, stderr bytes.Buffer
		proc.Stdout = &stdout
		proc.Stderr = &stderr
		err = proc.Run()
		code := 0
		if err != nil {
			code = 1
		}
		return exResponse(200, exStream(stdout.Bytes(), stderr.Bytes(), code), true), nil
	}
	f.t.Fatal("unexpected API command")
	return nil, nil
}

func (f *exFixture) create() *ExedevBox {
	f.t.Helper()
	b, err := f.c.CreateExedev(context.Background(), f.journalDir)
	if err != nil {
		f.t.Fatal(err)
	}
	f.b = b
	return b
}

func TestExedevCreateJournalIdentityAndAcknowledgedScopedCleanup(t *testing.T) {
	f := newExFixture(t)
	b := f.create()
	if f.created != 1 || !b.journal.Confirmed || b.journal.Born != f.info.Born {
		t.Fatal("original identity not bound")
	}
	if _, err := f.c.CreateExedev(context.Background(), f.journalDir); err == nil || f.created != 1 {
		t.Fatal("concurrent or stale journal allowed another create")
	}
	loaded, err := f.c.LoadExedev(b.StatePath())
	if err != nil {
		t.Fatal(err)
	}
	if err = loaded.Destroy(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.deleted != 1 {
		t.Fatal("delete not single")
	}
	if _, err = os.Stat(b.StatePath()); !os.IsNotExist(err) {
		t.Fatal("successful cleanup retained journal")
	}
}

func TestExedevAmbiguousCreateNeverAdoptsOrRetries(t *testing.T) {
	f := newExFixture(t)
	f.dropCreate = true
	b, err := f.c.CreateExedev(context.Background(), f.journalDir)
	if b == nil || err == nil || f.created != 1 || strings.Contains(err.Error(), exTestKey) {
		t.Fatal("ambiguous create not safely retained")
	}
	if err = b.Destroy(context.Background()); err == nil || f.deleted != 0 {
		t.Fatal("unconfirmed create adopted/deleted by name")
	}
	if _, err = os.Stat(b.StatePath()); err != nil {
		t.Fatal("intent lost")
	}
}

func TestExedevChangedIdentityAndUnprovedAbsenceNeverDelete(t *testing.T) {
	for _, kind := range []string{"birth", "tags", "region", "missing"} {
		t.Run(kind, func(t *testing.T) {
			f := newExFixture(t)
			b := f.create()
			switch kind {
			case "birth":
				f.changed = true
			case "tags":
				f.info.Tags = nil
			case "region":
				f.info.Region = "other"
			case "missing":
				f.missing = true
			}
			if _, err := b.command(context.Background(), "printf unsafe"); err == nil {
				t.Fatal("changed/missing VM executed")
			}
			if err := b.Destroy(context.Background()); err == nil || f.deleted != 0 {
				t.Fatal("changed/missing identity treated as cleanup")
			}
			if _, err := os.Stat(b.StatePath()); err != nil {
				t.Fatal("unresolved journal lost")
			}
		})
	}
}

func TestExedevDeleteHTTP200DoesNotProveDeletion(t *testing.T) {
	for _, reply := range []string{`{}`, `{"deleted":[],"failed":[]}`, `{"deleted":["other"],"failed":[]}`, `{"deleted":null,"failed":null}`, `{"deleted":[],"failed":["x"]}`} {
		t.Run(reply, func(t *testing.T) {
			f := newExFixture(t)
			b := f.create()
			f.deleteReply = reply
			if err := b.Destroy(context.Background()); err == nil {
				t.Fatal("bad acknowledgement accepted")
			}
			if _, err := os.Stat(b.StatePath()); err != nil {
				t.Fatal("journal lost")
			}
		})
	}
}

func TestExedevChunkedUploadDigestAndAsyncProbeWithActualShellQuoting(t *testing.T) {
	f := newExFixture(t)
	b := f.create()
	b.boot = exTestBoot
	// Generated /tmp directory grammar is part of the adapter's confinement.
	dir, err := os.MkdirTemp("/tmp", ".sandprobe-")
	if err != nil {
		t.Fatal(err)
	}
	os.Remove(dir)
	dir = "/tmp/.sandprobe-" + strings.TrimPrefix(token("n"), "n")[:12]
	if err = os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	b.dir = dir
	data := bytes.Repeat([]byte("quotes ' $() `; and bytes\n"), 4000)
	if err = b.writeFile(context.Background(), dir+"/probe.gz", data); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(dir + "/probe.gz")
	if !bytes.Equal(got, data) {
		t.Fatal("chunked bytes changed")
	}
	probe := []byte("#!/bin/sh\nif test \"$1\" = -survey; then printf 'survey\\n'; else cat; fi\n")
	if err = os.WriteFile(dir+"/probe", probe, 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	input := []byte("{\"example\":\"' $() ` quoted input\"}\n")
	got, err = b.Probe(ctx, nil, input)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, input) {
		t.Fatal("probe input changed across shell parsers")
	}
	if f.launches != 1 {
		t.Fatal("probe was not launched exactly once")
	}
	got, err = b.Probe(ctx, []string{"-survey"}, nil)
	if err != nil || string(got) != "survey\n" {
		t.Fatal("survey mode failed", err)
	}
	if err = os.WriteFile(f.bootFile, []byte("changed\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = b.command(ctx, "printf unsafe"); err == nil {
		t.Fatal("boot guard did not run in actual shell")
	}
}

func TestExedevTransportCapsRedirectsAndCredentialErrors(t *testing.T) {
	c, _ := NewExedevClient(exTestKey)
	if c.endpoint != "https://exe.dev/exec" || c.http.Timeout > 25*time.Second || c.http.CheckRedirect(nil, nil) == nil {
		t.Fatal("unsafe transport")
	}
	for _, response := range []struct {
		status int
		raw    string
	}{{403, exTestKey}, {200, `{"error":"` + exTestKey + `"}`}, {200, `{"vms":[],"VMS":[]}`}, {200, strings.Repeat("x", 2*exLimit+1)}} {
		c.http.Transport = boatTransport(func(*http.Request) (*http.Response, error) {
			return exResponse(response.status, response.raw, false), nil
		})
		_, err := c.request(context.Background(), "ls", false)
		if err == nil || strings.Contains(err.Error(), exTestKey) {
			t.Fatal("bad response accepted or token leaked")
		}
	}
}

func TestExedevPrivateCredentialFileRejectsSymlinkAndBroadMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	if err := os.WriteFile(path, []byte(exTestKey+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ExedevKey(path); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ExedevKey(link); err == nil {
		t.Fatal("symlink accepted")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ExedevKey(path); err == nil {
		t.Fatal("public token file accepted")
	}
}

func TestExedevCreatePreservesNameBeforeOptionalMetadataAndSetupErrors(t *testing.T) {
	for _, tc := range []struct {
		reply   string
		cleanup bool
	}{
		{`{"vm_name":"NAME","created_at":42}`, false},
		{`{"vm_name":"NAME","created_at":"BORN","error":{"private":"never print me"}}`, true},
		{`{"vm_name":"NAME","created_at":"BORN","Error":"never print me"}`, true},
	} {
		t.Run(tc.reply, func(t *testing.T) {
			f := newExFixture(t)
			f.createReply = tc.reply
			b, err := f.c.CreateExedev(context.Background(), f.journalDir)
			if b == nil || err == nil || !b.journal.Confirmed || strings.Contains(err.Error(), "never print me") {
				t.Fatal("create name not retained before optional error")
			}
			raw, _ := os.ReadFile(b.StatePath())
			var j exJournal
			_ = json.Unmarshal(raw, &j)
			if !j.Confirmed || j.Name != f.info.Name {
				t.Fatal("returned name not persisted")
			}
			err = b.Destroy(context.Background())
			if (err == nil) != tc.cleanup {
				t.Fatalf("cleanup succeeded=%v want=%v", err == nil, tc.cleanup)
			}
		})
	}
}

func TestExedevAmbiguousDeleteIsNotRepeatedAfterJournalReload(t *testing.T) {
	f := newExFixture(t)
	b := f.create()
	f.deleteReply = `{"deleted":[],"failed":[]}`
	if err := b.Destroy(context.Background()); err == nil {
		t.Fatal("bad delete accepted")
	}
	loaded, err := f.c.LoadExedev(b.StatePath())
	if err != nil {
		t.Fatal(err)
	}
	if err = loaded.Destroy(context.Background()); err == nil || f.deleted != 1 {
		t.Fatal("ambiguous delete was repeated")
	}
}

func TestExedevFullDetectAndGzipUpload(t *testing.T) {
	f := newExFixture(t)
	b := f.create()
	if err := b.DetectArch(context.Background()); err != nil {
		t.Fatal(err)
	}
	probe := []byte("#!/bin/sh\nprintf 'fixture-probe\\n'\n" + strings.Repeat("# fixture padding\n", 6000))
	if err := b.Upload(context.Background(), probe); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(b.dir)
	got, err := os.ReadFile(b.dir + "/probe")
	if err != nil || !bytes.Equal(got, probe) {
		t.Fatal("full gzip upload changed executable bytes")
	}
}

func TestExedevContradictoryDeleteResponseRetainsJournal(t *testing.T) {
	for _, extra := range []string{`"not_found":["NAME"]`, `"errors":{"NAME":"private"}`} {
		f := newExFixture(t)
		b := f.create()
		f.deleteReply = strings.ReplaceAll(`{"deleted":["NAME"],"failed":[],`+extra+`}`, "NAME", b.ID())
		if err := b.Destroy(context.Background()); err == nil {
			t.Fatal("contradictory delete accepted")
		}
		if _, err := os.Stat(b.StatePath()); err != nil {
			t.Fatal("lost unresolved journal")
		}
	}
}

func TestExedevBindsCreatedRegionWithoutAccountDefault(t *testing.T) {
	f := newExFixture(t)
	b := f.create()
	if b.journal.Region != "dfw" {
		t.Fatal("actual created VM region not bound")
	}
	raw, err := os.ReadFile(b.StatePath())
	if err != nil {
		t.Fatal(err)
	}
	var j exJournal
	_ = json.Unmarshal(raw, &j)
	if j.Region != "dfw" {
		t.Fatal("actual region not durable")
	}
	// Recover interruption between create identity persistence and region binding.
	b.journal.Region = ""
	if err = b.save(); err != nil {
		t.Fatal(err)
	}
	loaded, err := f.c.LoadExedev(b.StatePath())
	if err != nil {
		t.Fatal(err)
	}
	if err = loaded.Destroy(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestExedevCreateRefusalPreservesSafeCauseWithoutClaimingCreatedVM(t *testing.T) {
	f := newExFixture(t)
	f.createReply = `{"error":"Choose a plan to start creating VMs. private-token-value"}`
	b, err := f.c.CreateExedev(context.Background(), f.journalDir)
	if b == nil || err == nil || b.CreationConfirmed() || !strings.Contains(err.Error(), "billing_or_plan") || strings.Contains(err.Error(), "private-token-value") {
		t.Fatal("refusal cause lost or leaked/creation misrepresented")
	}
	raw, _ := os.ReadFile(b.StatePath())
	if strings.Contains(string(raw), "private-token-value") || !strings.Contains(string(raw), "billing_or_plan") {
		t.Fatal("unsafe or missing journal diagnostic")
	}
	if err = b.Destroy(context.Background()); err == nil || f.deleted != 0 {
		t.Fatal("refused creation adopted")
	}
}

func TestExedevCreateHintNeverReturnsArbitraryProviderText(t *testing.T) {
	for _, tc := range []struct{ text, want string }{
		{"Unknown flag --credential=private", "command_contract"},
		{"Standalone VMs are not enabled", "standalone_access"},
		{"VM name must be less than 32 characters", "name_contract"},
		{"permission denied", "permission"},
		{"image pull failed", "image_contract"},
		{"private-token-value", "unclassified_response"},
	} {
		got := exCreateHint(map[string]json.RawMessage{"error": json.RawMessage(exJSON(tc.text))})
		if got != tc.want {
			t.Fatal("wrong fixed diagnostic", got)
		}
	}
}
