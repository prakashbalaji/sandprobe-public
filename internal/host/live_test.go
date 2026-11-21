package host

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"sandprobe/internal/canary"
)

// TestLiveCanary drives the live canary through SSMCanary: status, arm, health on every port, one nonce, query,
// disarm. It runs only with SANDPROBE_LIVE_CANARY set to deploy/canary.sh's state file.
func TestLiveCanary(t *testing.T) {
	state := os.Getenv("SANDPROBE_LIVE_CANARY")
	if state == "" {
		t.Skip("SANDPROBE_LIVE_CANARY isn't set")
	}
	c, err := LoadSSMCanary(state)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	st, err := c.Ask(ctx, canary.Request{Op: "status"})
	if err != nil || !st.OK || st.Pin == "" {
		t.Fatalf("status: %+v, %v", st, err)
	}
	key, err := canary.KeyOf(st)
	if err != nil {
		t.Fatal(err)
	}
	run, nonce := token("r"), token("c")
	a, err := c.Ask(ctx, canary.Request{Op: "arm", Run: run, TTL: 120, Wants: []canary.Want{{Nonce: nonce, Proto: "tcp", Port: 8080}}})
	if err != nil || !a.OK || a.Pin != st.Pin {
		t.Fatalf("arm: %+v, %v", a, err)
	}
	defer c.Ask(ctx, canary.Request{Op: "disarm", Run: run})
	for _, p := range []int{443, 22, 80, 8080} {
		if !c.Health(ctx, p, key) {
			t.Errorf("no health on %d", p)
		}
	}
	conn, err := net.Dial("tcp", net.JoinHostPort(c.Addr, "8080"))
	if err != nil {
		t.Fatal(err)
	}
	conn.Write([]byte(nonce + "\n"))
	echo, _ := bufio.NewReader(conn).ReadString('\n')
	conn.Close()
	if strings.TrimSpace(echo) != "sandprobe:"+nonce {
		t.Fatalf("echo %q", echo)
	}
	q, err := c.Ask(ctx, canary.Request{Op: "query", Run: run})
	if err != nil || !q.OK || q.Pin != st.Pin || q.Run != run || len(q.Counts) != 1 || q.Counts[0].Count != 1 {
		t.Fatalf("query: %+v, %v", q, err)
	}
	t.Logf("pin %s, overloaded %v, first from %s", q.Pin, q.Overloaded, q.Counts[0].FirstFrom)
}

// TestLiveSprites grades a fresh Sprites default box against the live canary, through the whole host path, and
// destroys the box. It runs only with SANDPROBE_LIVE_SPRITES set to the org and SANDPROBE_LIVE_CANARY to the canary's
// state file; SANDPROBE_LIVE_OUT names where the run's record goes. PER-5 restores a checkpoint taken before the probe.
func TestLiveSprites(t *testing.T) {
	org, state := os.Getenv("SANDPROBE_LIVE_SPRITES"), os.Getenv("SANDPROBE_LIVE_CANARY")
	if org == "" || state == "" {
		t.Skip("SANDPROBE_LIVE_SPRITES or SANDPROBE_LIVE_CANARY isn't set")
	}
	c, err := LoadSSMCanary(state)
	if err != nil {
		t.Fatal(err)
	}
	probe := filepath.Join(t.TempDir(), "sandprobe-probe")
	cmd := exec.Command("go", "build", "-trimpath", "-o", probe, "sandprobe/cmd/sandprobe-probe")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building the probe: %v\n%s", err, b)
	}
	bin, _ := os.ReadFile(probe)
	sum := sha256.Sum256(bin)
	home, _ := os.UserHomeDir()
	ctx := context.Background()
	s, err := CreateSprite(ctx, filepath.Join(home, ".config/sandprobe/sprites"), org)
	record := map[string]any{"box": map[string]string{"provider": "sprites", "name": s.Name, "id": s.SpriteID}}
	var r *Run
	// The run's record is written after teardown, so it carries the cleanup outcome, and states the residual Sprites
	// leaves (PRV-1): it deletes only by name.
	defer func() {
		cleanup := map[string]any{"destroyed": false, "residual": "Sprites reaches a sprite only by name, for exec, " +
			"checkpoint, restore, delete and the checkpoint-list reads. Each is checked against the recorded ID right before " +
			"(and each read on both sides), but a name deleted and recreated between a check and its call can't be told " +
			"apart (PRV-1, open question 12)"}
		var err error
		if r != nil { // the host's own teardown: the box, and every marker's fate with it
			err = Teardown(ctx, r)
			record["markers"] = r.Markers
		} else {
			err = s.Destroy(ctx)
		}
		if err != nil {
			t.Errorf("teardown: %v", err)
			cleanup["error"] = err.Error()
		} else {
			cleanup["destroyed"], cleanup["verified"] = true, "the name answered with the recorded ID just before the "+
				"delete, or was already gone, and was not found after"
			t.Logf("sprite %s (%s) destroyed, the provider's 404 confirmed", s.Name, s.SpriteID)
		}
		record["cleanup"] = cleanup
		if out := os.Getenv("SANDPROBE_LIVE_OUT"); out != "" {
			b, _ := json.MarshalIndent(record, "", "  ")
			os.WriteFile(out, b, 0o600)
		}
	}()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("sprite %s (%s) created", s.Name, s.SpriteID)
	if err := s.Upload(ctx, bin); err != nil {
		t.Fatal(err)
	}
	if err := s.Checkpoint(ctx); err != nil { // the version PER-5's reset restores
		t.Fatal(err)
	}
	t.Logf("checkpoint %s taken", s.Version)
	r, err = Execute(ctx, s, c, Options{Mode: "exec", ProbeSHA256: hex.EncodeToString(sum[:])})
	if err != nil {
		t.Fatal(err)
	}
	record["manifest"], record["report"], record["evidence"], record["doc"] = r.Manifest, r.Report, r.Evidence, json.RawMessage(r.Doc)
	rep, ev := r.Report, r.Evidence
	t.Logf("grade %q valid %v complete %v; canary live %v, receipts read %v, overloaded %v, %d receipts",
		rep.Letter, rep.Valid, rep.Complete, ev.Live, ev.ReceiptsRead, ev.Overloaded, len(ev.Receipts))
	for _, o := range rep.Outcomes {
		t.Logf("  %-11s %-10s %s%s", o.ID, o.Result, o.Evidence, o.Reason)
	}
	if !rep.Valid || !ev.Live || !ev.ReceiptsRead {
		t.Fatalf("want a valid run against a live canary whose query completed: %s", rep.Invalid)
	}
}
