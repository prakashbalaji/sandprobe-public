package host

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sandprobe/internal/canary"
)

// fakeSSM plays the AWS CLI: send-command returns an ID, and each get-command-invocation returns the next scripted
// invocation.
type fakeSSM struct {
	calls [][]string
	sent  string // the command sent to the instance
	invs  []string
}

func (f *fakeSSM) run(_ context.Context, args ...string) ([]byte, error) {
	f.calls = append(f.calls, args)
	switch args[1] {
	case "send-command":
		var p struct{ Commands []string }
		for i, a := range args {
			if a == "--parameters" {
				json.Unmarshal([]byte(args[i+1]), &p)
			}
		}
		f.sent = strings.Join(p.Commands, "\n")
		return []byte("cmd-1\n"), nil
	case "get-command-invocation":
		if len(f.invs) == 0 {
			return nil, errors.New("no more invocations")
		}
		inv := f.invs[0]
		f.invs = f.invs[1:]
		if inv == "missing" {
			return nil, errors.New("InvocationDoesNotExist")
		}
		return []byte(inv), nil
	}
	return nil, errors.New("unexpected call")
}

func inv(status, stdout string) string {
	b, _ := json.Marshal(map[string]string{"Status": status, "StandardOutputContent": stdout, "StandardErrorContent": "boom"})
	return string(b)
}

func TestSSMAsk(t *testing.T) {
	answer := `{"pin":"p1","ok":true,"run":"r-1","counts":[{"nonce":"c-1","proto":"tcp","port":443,"count":1,"elsewhere":0}]}` + "\n"
	f := &fakeSSM{invs: []string{"missing", inv("Pending", ""), inv("InProgress", ""), inv("Success", answer)}}
	c := &SSMCanary{Instance: "i-1", Addr: "203.0.113.5", Dom: "probe.example", run: f.run}
	a, err := c.Ask(context.Background(), canary.Request{Op: "query", Run: "r-1"})
	if err != nil || !a.OK || a.Pin != "p1" || len(a.Counts) != 1 || a.Counts[0].Count != 1 {
		t.Fatalf("want the answer once the command succeeds, got %+v, %v", a, err)
	}
	if want := "/usr/local/bin/sandprobe-canary -control /run/sandprobe-canary/ctl.sock -ctl query -run r-1"; f.sent != want {
		t.Fatalf("sent %q, want %q", f.sent, want)
	}
	if send := f.calls[0]; !strings.Contains(strings.Join(send, " "), "--instance-ids i-1 --document-name AWS-RunShellScript") {
		t.Fatalf("want the command sent to the canary's instance only: %v", send)
	}
}

func TestSSMAskFails(t *testing.T) {
	long := `{"pin":"p1","ok":true,"run":"r-1","counts":[{"nonce":"c-1","proto":"tcp","port":443,"count":1,"elsew`
	for name, tc := range map[string]struct {
		q    canary.Request
		invs []string
	}{
		"the command failed":             {canary.Request{Op: "status"}, []string{inv("Failed", "")}},
		"the command timed out":          {canary.Request{Op: "status"}, []string{inv("TimedOut", "")}},
		"an answer cut short":            {canary.Request{Op: "query", Run: "r-1"}, []string{inv("Success", long)}},
		"an answer with an extra field":  {canary.Request{Op: "status"}, []string{inv("Success", `{"pin":"p1","ok":true,"x":1}`)}},
		"a run that could reach a shell": {canary.Request{Op: "query", Run: "r-1;reboot"}, nil},
		"a nonce with a space":           {canary.Request{Op: "arm", Run: "r", TTL: 60, Wants: []canary.Want{{Nonce: "a b", Proto: "tcp", Port: 1}}}, nil},
	} {
		f := &fakeSSM{invs: tc.invs}
		c := &SSMCanary{Instance: "i-1", run: f.run}
		if _, err := c.Ask(context.Background(), tc.q); err == nil {
			t.Errorf("%s: want an error", name)
		}
		if tc.invs == nil && len(f.calls) > 0 {
			t.Errorf("%s: want nothing sent, got %v", name, f.calls)
		}
	}
}

func TestLoadSSMCanary(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good")
	os.WriteFile(good, []byte("did=d1\nprofile=p\nregion=us-west-2\ninstance=i-old\ninstance=i-1\nip=203.0.113.5\ndomain=probe.example\n"), 0o600)
	c, err := LoadSSMCanary(good)
	if err != nil || c.Instance != "i-1" || c.Addr != "203.0.113.5" || c.Dom != "probe.example" || c.Profile != "p" {
		t.Fatalf("want the last recorded values, got %+v, %v", c, err)
	}
	for name, body := range map[string]string{
		"no instance": "profile=p\nregion=r\nip=203.0.113.5\ndomain=d\n",
		"no IP":       "profile=p\nregion=r\ninstance=i-1\ndomain=d\n",
		"a bad IP":    "profile=p\nregion=r\ninstance=i-1\nip=nope\ndomain=d\n",
		"no domain":   "profile=p\nregion=r\ninstance=i-1\nip=203.0.113.5\n",
	} {
		p := filepath.Join(dir, strings.ReplaceAll(name, " ", "-"))
		os.WriteFile(p, []byte(body), 0o600)
		if _, err := LoadSSMCanary(p); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}
