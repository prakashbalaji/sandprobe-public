package host

import (
	"context"
	"strings"
	"testing"

	pb "github.com/modal-labs/modal-client/go/proto/modal_proto"
	"google.golang.org/grpc"
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
