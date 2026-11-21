package host

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestDaytonaCreateJournalAndTerminalCleanup(t *testing.T) {
	c, _ := NewDaytonaClient("fixture-key", "")
	var name, nonce string
	id := "12345678-1234-1234-1234-123456789abc"
	born := time.Now().UTC().Format(time.RFC3339Nano)
	deleted := false
	creates := 0
	info := func() map[string]any {
		state := "started"
		if deleted {
			state = "destroyed"
		}
		return map[string]any{"id": id, "name": name, "organization": "org-fixture", "born": born, "labels": map[string]string{"sandprobe_run": nonce}, "public": false, "auto_delete": 0, "auto_stop": 15, "auto_pause": 0, "volumes": 0, "state": state, "desired_state": state}
	}
	c.runtime = func(_ context.Context, in map[string]any) ([]byte, error) {
		var out any
		switch in["op"] {
		case "create":
			creates++
			name = in["name"].(string)
			nonce = in["nonce"].(string)
			out = info()
		case "lookup":
			out = info()
		case "delete":
			if in["id"] != id || in["nonce"] != nonce {
				t.Fatal("unbound delete")
			}
			deleted = true
			out = map[string]any{"id": id, "deleted_request": true}
		default:
			t.Fatal("unexpected operation")
		}
		return json.Marshal(out)
	}
	b, e := c.CreateDaytona(context.Background(), t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if creates != 1 {
		t.Fatal("create retried")
	}
	raw, _ := os.ReadFile(b.state)
	var j daytonaJournal
	json.Unmarshal(raw, &j)
	if j.ID != id {
		t.Fatal("ID not journaled")
	}
	if e = b.Destroy(context.Background()); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(b.CleanupProof, "terminal metadata") {
		t.Fatal("cleanup residual omitted")
	}
	if _, e = os.Stat(b.state); !os.IsNotExist(e) {
		t.Fatal("journal remains")
	}
}
func TestDaytonaMalformedMetadataRetainsOriginalID(t *testing.T) {
	c, _ := NewDaytonaClient("fixture-key", "")
	c.runtime = func(context.Context, map[string]any) ([]byte, error) {
		return []byte(`{"id":"12345678-1234-1234-1234-123456789abc","auto_stop":"bad"}`), nil
	}
	b, e := c.CreateDaytona(context.Background(), t.TempDir())
	if e == nil || b.ID() == "" {
		t.Fatal("original ID lost")
	}
	raw, _ := os.ReadFile(b.state)
	var j daytonaJournal
	json.Unmarshal(raw, &j)
	if j.ID != b.ID() {
		t.Fatal("ID not durable")
	}
}
func TestDaytonaAmbiguousCreateNeverAdoptsOrRetries(t *testing.T) {
	c, _ := NewDaytonaClient("fixture-key", "")
	calls := 0
	c.runtime = func(context.Context, map[string]any) ([]byte, error) {
		calls++
		return nil, errors.New("fixed failure")
	}
	b, e := c.CreateDaytona(context.Background(), t.TempDir())
	if e == nil || b.ID() != "" || calls != 1 {
		t.Fatal("unsafe create")
	}
	if b.Destroy(context.Background()) == nil || calls != 1 {
		t.Fatal("cleanup guessed ID")
	}
}
