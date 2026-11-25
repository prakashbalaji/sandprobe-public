package host

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	pb "github.com/modal-labs/modal-client/go/proto/modal_proto"
	"google.golang.org/grpc"

	"sandprobe/internal/obs"
)

// POC-1: no call but the auth exchange reaches Modal until the server names the operator's workspace; another workspace's
// token creates nothing.
func TestWorkspaceGate(t *testing.T) {
	for _, tc := range []struct {
		workspace, username string
		want                bool
	}{{"example-ws", "", true}, {"", "example-ws", true}, {"someone-else", "", false}, {"", "someone-else", false},
		{"team-ws", "example-ws", false}} { // a team workspace is named by its own name, never the member's username
		g := &workspaceGate{want: "example-ws"}
		var calls []string
		invoker := func(_ context.Context, method string, _, reply any, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
			calls = append(calls, method)
			if r, ok := reply.(*pb.WorkspaceNameLookupResponse); ok {
				r.SetWorkspaceName(tc.workspace)
				r.SetUsername(tc.username)
			}
			return nil
		}
		ctx := context.Background()
		g.unary(ctx, pb.ModalClient_AuthTokenGet_FullMethodName, nil, nil, nil, invoker)
		err := g.unary(ctx, pb.ModalClient_AppGetOrCreate_FullMethodName, nil, nil, nil, invoker)
		g.unary(ctx, pb.ModalClient_SandboxCreate_FullMethodName, nil, nil, nil, invoker)
		created := strings.Contains(strings.Join(calls, " "), "Create")
		lookups := strings.Count(strings.Join(calls, " "), "WorkspaceNameLookup")
		switch {
		case tc.want && (err != nil || !created || lookups != 1):
			t.Errorf("%s/%s: want calls through after one lookup, got %v %v", tc.workspace, tc.username, err, calls)
		case !tc.want && (err == nil || created || (tc.workspace != "" && strings.Contains(err.Error(), tc.workspace))):
			t.Errorf("%s/%s: want every creating call refused, got %v %v", tc.workspace, tc.username, err, calls)
		}
		if _, err := (&workspaceGate{want: "example-ws"}).stream(ctx, nil, nil, "x", nil); err == nil {
			t.Error("a stream ran before the workspace was verified")
		}
	}
}

// PRV-18: the 10 Nov default sandbox's own findings clear the gate; any other name or path, or a line or document it
// can't read, trips it.
func TestModalStop(t *testing.T) {
	const names, reads = "secret-shaped names in the agent's environment, values never read: ", "the agent can read "
	for name, c := range map[string]struct {
		obs  obs.Observation
		trip bool
	}{
		"GPG_KEY":            {obs.Observation{ID: "SEC-1", Result: obs.Finding, Evidence: names + "GPG_KEY", ObservedNames: []string{"GPG_KEY"}}, false},
		"the twin":           {obs.Observation{ID: "SEC-1", Result: obs.Finding, Evidence: names + "SANDPROBE_TWIN"}, false},
		"another name":       {obs.Observation{ID: "SEC-1", Result: obs.Finding, Evidence: names + "GPG_KEY, MODAL_TOKEN"}, true},
		"only in the list":   {obs.Observation{ID: "SEC-1", Result: obs.Finding, Evidence: names + "GPG_KEY", ObservedNames: []string{"MODAL_TOKEN"}}, true},
		"unreadable names":   {obs.Observation{ID: "SEC-1", Result: obs.Finding, Evidence: "something else"}, true},
		"shadow":             {obs.Observation{ID: "SEC-3", Result: obs.Finding, Evidence: reads + "/etc/shadow (opened, never read)"}, false},
		"another file":       {obs.Observation{ID: "SEC-3", Result: obs.Finding, Evidence: reads + "/etc/shadow, /root/.netrc (opened, never read)"}, true},
		"leading garbage":    {obs.Observation{ID: "SEC-1", Result: obs.Finding, Evidence: "junk values never read: GPG_KEY"}, true},
		"garbage before":     {obs.Observation{ID: "SEC-1", Result: obs.Finding, Evidence: "x " + names + "GPG_KEY"}, true},
		"no names":           {obs.Observation{ID: "SEC-1", Result: obs.Finding, Evidence: names}, true},
		"an empty name":      {obs.Observation{ID: "SEC-1", Result: obs.Finding, Evidence: names + "GPG_KEY, "}, true},
		"missing prefix":     {obs.Observation{ID: "SEC-3", Result: obs.Finding, Evidence: "/etc/shadow (opened, never read)"}, true},
		"missing suffix":     {obs.Observation{ID: "SEC-3", Result: obs.Finding, Evidence: reads + "/etc/shadow"}, true},
		"garbage before it":  {obs.Observation{ID: "SEC-3", Result: obs.Finding, Evidence: "x " + reads + "/etc/shadow (opened, never read)"}, true},
		"garbage after it":   {obs.Observation{ID: "SEC-3", Result: obs.Finding, Evidence: reads + "/etc/shadow (opened, never read) x"}, true},
		"unreadable paths":   {obs.Observation{ID: "SEC-3", Result: obs.Finding, Evidence: ""}, true},
		"a pass":             {obs.Observation{ID: "SEC-3", Result: obs.Pass}, false},
		"some other finding": {obs.Observation{ID: "SEC-2", Result: obs.Finding, Evidence: "x"}, false},
	} {
		b, _ := json.Marshal(obs.Doc{Observations: []obs.Observation{c.obs}})
		if got := ModalStop(b); (got != "") != c.trip {
			t.Errorf("%s: %q", name, got)
		}
	}
	if ModalStop([]byte("{")) == "" {
		t.Error("a document that doesn't parse cleared the gate")
	}
}
