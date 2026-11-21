package host

import (
	"context"
	"crypto/sha256"
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
)

type boatTransport func(*http.Request) (*http.Response, error)

func (f boatTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func boatResponse(status int, value any) *http.Response {
	raw, _ := json.Marshal(value)
	return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(string(raw)))}
}
func TestBoatSingleCreatePolicyIDJournalAndPermanentDelete(t *testing.T) {
	c, _ := NewBoatClient("fixture-key")
	dir := t.TempDir()
	nonce := ""
	id := "bx_23456789"
	operation := "bdop_" + strings.Repeat("a", 32)
	created := 0
	deleted := false
	info := func() map[string]any {
		return map[string]any{"access": "owner", "holdsCreatorLogins": false, "wipePendingUntilRestart": false, "environment": nil, "team": nil, "id": id, "state": "ready", "createdAt": time.Now().UTC().Truncate(time.Second).Format(time.RFC3339), "archiveAfter": time.Now().Add(15 * time.Minute).UTC().Format(time.RFC3339), "ttlSeconds": 900, "snapshots": false, "monitoring": false, "labels": map[string]string{"sandprobe_run": nonce}}
	}
	born := info()["createdAt"]
	c.http.Transport = boatTransport(func(r *http.Request) (*http.Response, error) {
		path := strings.TrimPrefix(r.URL.Path, "/api/v1")
		switch {
		case r.Method == "POST" && path == "/sandboxes":
			created++
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			if body["noEnv"] != true || body["snapshots"] != false || body["monitoring"] != false || body["type"] != "small" || body["ttlSeconds"] != float64(900) {
				t.Fatal("unsafe create policy")
			}
			nonce = body["labels"].(map[string]any)["sandprobe_run"].(string)
			v := info()
			parsed, _ := time.Parse(time.RFC3339, born.(string))
			v["createdAt"] = parsed.Add(136 * time.Millisecond).Format(time.RFC3339Nano)
			return boatResponse(201, map[string]any{"ok": true, "sandbox": v}), nil
		case r.Method == "GET" && path == "/sandboxes/"+id:
			entries, _ := filepath.Glob(filepath.Join(dir, "boat-*.state"))
			if len(entries) != 1 {
				t.Fatal("missing create intent")
			}
			raw, _ := os.ReadFile(entries[0])
			var j boatJournal
			json.Unmarshal(raw, &j)
			if j.ID != id {
				t.Fatal("ID not persisted before lookup")
			}
			if deleted {
				return boatResponse(404, map[string]any{"message": "never log me"}), nil
			}
			v := info()
			v["createdAt"] = born
			return boatResponse(200, map[string]any{"ok": true, "sandbox": v}), nil
		case r.Method == "DELETE":
			if r.Header.Get("X-Ascii-Confirm-Delete") != id {
				t.Fatal("delete confirmation not pinned")
			}
			deleted = true
			return boatResponse(202, map[string]any{"ok": true, "operation": map[string]any{"id": operation, "kind": "sandbox", "targetId": id}}), nil
		case r.Method == "GET" && path == "/deletion-operations/"+operation:
			return boatResponse(200, map[string]any{"ok": true, "operation": map[string]any{"id": operation, "kind": "sandbox", "targetId": id, "status": "completed"}}), nil
		}
		t.Fatal("unexpected request")
		return nil, nil
	})
	b, e := c.CreateBoat(context.Background(), dir)
	if e != nil {
		t.Fatal(e)
	}
	if created != 1 {
		t.Fatal("create retried")
	}
	if e = b.Destroy(context.Background()); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(b.state); !os.IsNotExist(e) {
		t.Fatal("journal not retired")
	}
}
func TestBoatCreateAmbiguityNoRetryOrAdoption(t *testing.T) {
	c, _ := NewBoatClient("fixture-key")
	calls := 0
	c.http.Transport = boatTransport(func(r *http.Request) (*http.Response, error) { calls++; return nil, errors.New("secret detail") })
	b, e := c.CreateBoat(context.Background(), t.TempDir())
	if e == nil || strings.Contains(e.Error(), "secret detail") || calls != 1 {
		t.Fatal("unsafe ambiguous create")
	}
	if b == nil || b.ID() != "" {
		t.Fatal("unexpected adopted ID")
	}
	if b.Destroy(context.Background()) == nil {
		t.Fatal("unresolved create called clean")
	}
	if calls != 1 {
		t.Fatal("cleanup guessed resource")
	}
}
func TestBoatRejectsMissingCommandProofAndRedirects(t *testing.T) {
	c, _ := NewBoatClient("fixture-key")
	b := &BoatBox{client: c, journal: boatJournal{ID: "bx_23456789"}}
	c.http.Transport = boatTransport(func(*http.Request) (*http.Response, error) {
		return boatResponse(200, map[string]any{"ok": true, "success": true, "exitCode": 0, "stdout": "ok"}), nil
	})
	if _, e := b.commandRaw(context.Background(), "true"); e == nil {
		t.Fatal("missing truncation/timeout evidence accepted")
	}
	if c.http.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Fatal("redirects enabled")
	}
}
func TestBoatOwnershipAndSnapshotPolicyFailClosed(t *testing.T) {
	f := false
	ttl := 900
	b := &BoatBox{journal: boatJournal{ID: "bx_23456789", Nonce: "own"}}
	i := boatInfo{ID: b.ID(), Labels: map[string]string{"sandprobe_run": "other"}, Snapshots: &f, Monitoring: &f, TTL: &ttl, Archive: time.Now().Add(time.Minute).Format(time.RFC3339)}
	if b.match(i) == nil {
		t.Fatal("foreign identity accepted")
	}
	i.Labels["sandprobe_run"] = "own"
	v := true
	i.Snapshots = &v
	if b.match(i) == nil {
		t.Fatal("snapshots accepted")
	}
}

func TestBoatOptionalMetadataFailureRetainsID(t *testing.T) {
	c, _ := NewBoatClient("fixture-key")
	c.http.Transport = boatTransport(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("X-Boat-Org") != "personal" {
			t.Fatal("mutable wallet")
		}
		return boatResponse(201, map[string]any{"ok": true, "sandbox": map[string]any{"id": "bx_23456789", "ttlSeconds": "bad"}}), nil
	})
	b, e := c.CreateBoat(context.Background(), t.TempDir())
	if e == nil || b.ID() != "bx_23456789" {
		t.Fatal("lost original ID")
	}
	raw, _ := os.ReadFile(b.state)
	var j boatJournal
	json.Unmarshal(raw, &j)
	if j.ID != b.ID() {
		t.Fatal("ID not durable")
	}
}
func TestBoatTruncatedStderrRejected(t *testing.T) {
	c, _ := NewBoatClient("fixture-key")
	b := &BoatBox{client: c, journal: boatJournal{ID: "bx_23456789"}}
	c.http.Transport = boatTransport(func(*http.Request) (*http.Response, error) {
		return boatResponse(200, map[string]any{"ok": true, "success": true, "exitCode": 0, "stdout": "ok", "stdoutTruncated": false, "stderrTruncated": true, "timedOut": false}), nil
	})
	if _, e := b.commandRaw(context.Background(), "true"); e == nil {
		t.Fatal("truncation accepted")
	}
}

func TestBoatNoEnvReadbackUsesCredentialFlagAndPinsBirth(t *testing.T) {
	f := false
	ttl := 900
	now := time.Now().UTC()
	id := "bx_23456789"
	b := &BoatBox{journal: boatJournal{ID: id, Nonce: "own", Requested: now, CreateBorn: now.Add(136 * time.Millisecond).Format(time.RFC3339Nano)}, state: filepath.Join(t.TempDir(), "fixture.state")}
	info := boatInfo{ID: id, Access: "owner", HoldsCreatorLogins: &f, WipePending: &f, Labels: map[string]string{"sandprobe_run": "own"}, Created: now.Format(time.RFC3339Nano), Archive: now.Add(15 * time.Minute).Format(time.RFC3339Nano), Environment: json.RawMessage(`"base"`), Team: json.RawMessage(`null`), Snapshots: &f, Monitoring: &f, TTL: &ttl}
	if e := b.bindBirth(info); e != nil {
		t.Fatal(e)
	}
	if e := b.match(info); e != nil {
		t.Fatal(e)
	}
	info.Created = now.Add(time.Millisecond).Format(time.RFC3339Nano)
	if b.bindBirth(info) == nil {
		t.Fatal("canonical timestamp changed")
	}
	info.Created = b.journal.Born
	v := true
	info.HoldsCreatorLogins = &v
	if b.match(info) == nil {
		t.Fatal("creator credentials allowed")
	}
	info.HoldsCreatorLogins = nil
	if b.match(info) == nil {
		t.Fatal("missing credential evidence allowed")
	}
}

func TestBoatRuntimePolicyFailureStillPermanentlyDeletes(t *testing.T) {
	c, _ := NewBoatClient("fixture-key")
	dir := t.TempDir()
	nonce := ""
	id := "bx_23456789"
	operation := "bdop_" + strings.Repeat("a", 32)
	created := 0
	deleted := false
	info := func() map[string]any {
		return map[string]any{"access": "owner", "holdsCreatorLogins": true, "wipePendingUntilRestart": false, "environment": "base", "team": nil, "id": id, "state": "ready", "createdAt": time.Now().UTC().Truncate(time.Second).Format(time.RFC3339), "archiveAfter": time.Now().Add(15 * time.Minute).UTC().Format(time.RFC3339), "ttlSeconds": 900, "snapshots": false, "monitoring": false, "labels": map[string]string{"sandprobe_run": nonce}}
	}
	born := info()["createdAt"]
	c.http.Transport = boatTransport(func(r *http.Request) (*http.Response, error) {
		path := strings.TrimPrefix(r.URL.Path, "/api/v1")
		switch {
		case r.Method == "POST" && path == "/sandboxes":
			created++
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			if body["noEnv"] != true || body["snapshots"] != false || body["monitoring"] != false || body["type"] != "small" || body["ttlSeconds"] != float64(900) {
				t.Fatal("unsafe create policy")
			}
			nonce = body["labels"].(map[string]any)["sandprobe_run"].(string)
			v := info()
			parsed, _ := time.Parse(time.RFC3339, born.(string))
			v["createdAt"] = parsed.Add(136 * time.Millisecond).Format(time.RFC3339Nano)
			return boatResponse(201, map[string]any{"ok": true, "sandbox": v}), nil
		case r.Method == "GET" && path == "/sandboxes/"+id:
			entries, _ := filepath.Glob(filepath.Join(dir, "boat-*.state"))
			if len(entries) != 1 {
				t.Fatal("missing create intent")
			}
			raw, _ := os.ReadFile(entries[0])
			var j boatJournal
			json.Unmarshal(raw, &j)
			if j.ID != id {
				t.Fatal("ID not persisted before lookup")
			}
			if deleted {
				return boatResponse(404, map[string]any{"message": "never log me"}), nil
			}
			v := info()
			v["createdAt"] = born
			return boatResponse(200, map[string]any{"ok": true, "sandbox": v}), nil
		case r.Method == "DELETE":
			if r.Header.Get("X-Ascii-Confirm-Delete") != id {
				t.Fatal("delete confirmation not pinned")
			}
			deleted = true
			return boatResponse(202, map[string]any{"ok": true, "operation": map[string]any{"id": operation, "kind": "sandbox", "targetId": id}}), nil
		case r.Method == "GET" && path == "/deletion-operations/"+operation:
			return boatResponse(200, map[string]any{"ok": true, "operation": map[string]any{"id": operation, "kind": "sandbox", "targetId": id, "status": "completed"}}), nil
		}
		t.Fatal("unexpected request")
		return nil, nil
	})
	b, e := c.CreateBoat(context.Background(), dir)
	if e == nil || !strings.Contains(e.Error(), "environment/wallet") {
		t.Fatal("expected runtime credential-policy rejection", e)
	}
	if created != 1 {
		t.Fatal("create retried")
	}
	if e = b.Destroy(context.Background()); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(b.state); !os.IsNotExist(e) {
		t.Fatal("journal not retired")
	}
}

func TestBoatInitialBirthGapCannotExceedOneSecond(t *testing.T) {
	now := time.Now().UTC()
	b := &BoatBox{journal: boatJournal{ID: "bx_23456789", Nonce: "own", Requested: now, CreateBorn: now.Add(2 * time.Second).Format(time.RFC3339Nano)}, state: filepath.Join(t.TempDir(), "fixture.state")}
	i := boatInfo{ID: b.ID(), Access: "owner", Team: json.RawMessage(`null`), Labels: map[string]string{"sandprobe_run": "own"}, Created: now.Format(time.RFC3339Nano)}
	if b.bindBirth(i) == nil || b.journal.Born != "" {
		t.Fatal("large first birth change accepted")
	}
}

func TestBoatUploadProvesBytesInsteadOfAssumingSizeUnits(t *testing.T) {
	for _, badDigest := range []bool{false, true} {
		t.Run(fmt.Sprint(badDigest), func(t *testing.T) {
			c, _ := NewBoatClient("fixture-key")
			now := time.Now().UTC()
			id := "bx_23456789"
			path := "/tmp/.sandprobe-ABCDEFGHIJKL/probe.gz"
			payload := []byte("five!")
			digest := fmt.Sprintf("%x", sha256.Sum256(payload))
			if badDigest {
				digest = strings.Repeat("0", 64)
			}
			execs := 0
			b := &BoatBox{client: c, journal: boatJournal{ID: id, Nonce: "own", Born: now.Format(time.RFC3339Nano), Requested: now}}
			c.http.Transport = boatTransport(func(r *http.Request) (*http.Response, error) {
				switch r.Method {
				case "GET":
					return boatResponse(200, map[string]any{"ok": true, "sandbox": map[string]any{"id": id, "labels": map[string]string{"sandprobe_run": "own"}, "createdAt": b.journal.Born, "state": "idle", "environment": "base", "team": nil, "access": "owner", "holdsCreatorLogins": false, "wipePendingUntilRestart": false, "snapshots": false, "monitoring": false, "ttlSeconds": 900, "archiveAfter": now.Add(15 * time.Minute).Format(time.RFC3339Nano)}}), nil
				case "PUT":
					return boatResponse(200, map[string]any{"ok": true, "success": true, "path": "/provider/canonical/echo", "size": 8}), nil
				case "POST":
					execs++
					return boatResponse(200, map[string]any{"ok": true, "success": true, "exitCode": 0, "stdout": digest + "  " + path + "\n", "stdoutTruncated": false, "stderrTruncated": false, "timedOut": false}), nil
				}
				t.Fatal("unexpected mutation")
				return nil, nil
			})
			e := b.writeFile(context.Background(), path, payload)
			if (e != nil) != badDigest || execs != 1 {
				t.Fatal("digest proof not enforced", e, execs)
			}
		})
	}
}
func TestBoatUploadRejectsUnsafeFilenameBeforeRequests(t *testing.T) {
	c, _ := NewBoatClient("fixture-key")
	c.http.Transport = boatTransport(func(*http.Request) (*http.Response, error) {
		t.Fatal("unsafe filename reached provider")
		return nil, nil
	})
	b := &BoatBox{client: c}
	for _, path := range []string{"/tmp/.sandprobe-ABCDEFGHIJKL/probe;id", "/tmp/$(id)/../.sandprobe-ABCDEFGHIJKL/probe.gz", "/tmp/other/../.sandprobe-ABCDEFGHIJKL/probe.gz", "/tmp/$(id)/../.sandprobe-ABCDEFGHIJKL/probe"} {
		if b.writeFile(context.Background(), path, []byte("x")) == nil {
			t.Fatal("noncanonical shell path accepted")
		}
		b.ProbePath = path
		if _, e := b.Probe(context.Background(), nil, nil); e == nil {
			t.Fatal("noncanonical probe path accepted")
		}
	}
}

func TestBoatKeyRefusesUnsafeFilesAndNoFallback(t *testing.T) {
	t.Setenv("BOAT_API_KEY", "fixture-env-key")
	dir := t.TempDir()
	file := filepath.Join(dir, "key")
	if e := os.WriteFile(file, []byte("fixture-file-key\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if got, e := BoatKey(file); e != nil || got != "fixture-file-key" {
		t.Fatal("safe credential file rejected")
	}
	if e := os.Chmod(file, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e := BoatKey(file); e == nil {
		t.Fatal("world-readable credential accepted")
	}
	os.Chmod(file, 0600)
	link := filepath.Join(dir, "link")
	if e := os.Symlink(file, link); e != nil {
		t.Fatal(e)
	}
	if _, e := BoatKey(link); e == nil {
		t.Fatal("symlink accepted")
	}
	fifo := filepath.Join(dir, "fifo")
	if e := syscall.Mkfifo(fifo, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := BoatKey(fifo); e == nil {
		t.Fatal("FIFO accepted")
	}
	if _, e := BoatKey(dir); e == nil {
		t.Fatal("directory accepted")
	}
	if _, e := BoatKey(filepath.Join(dir, "missing")); e == nil {
		t.Fatal("selected-file failure fell back to env")
	}
	if e := os.WriteFile(file, []byte(strings.Repeat("x", 8193)), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := BoatKey(file); e == nil {
		t.Fatal("oversized credential accepted")
	}
}
