package host

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"maps"
	"slices"
	"sync"

	modal "github.com/modal-labs/modal-client/go"
	pb "github.com/modal-labs/modal-client/go/proto/modal_proto"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

// ModalSDK is modalAPI over Modal's Go SDK (PRV table). It holds one App and the image the run's sandboxes use, and
// the sandboxes it created, by ID. The token never leaves the SDK, which reads it from ~/.modal.toml; the SDK's own
// logger is discarded, and every error it returns is sanitized (POC-1).
type ModalSDK struct {
	Workspace string // the one workspace the gate lets this client reach (POC-1)
	Client    *modal.Client
	App       *modal.App
	ImageID   string
	image     *modal.Image
	mu        sync.Mutex
	boxes     map[string]*modal.Sandbox
	volumes   map[string]*modal.Volume
}

// workspaceGate holds every call but the auth exchange until the server says the token belongs to workspace want,
// and refuses them all otherwise. The SDK prefers token variables in the environment over ~/.modal.toml's active
// profile, so only the server's own answer binds the run to the operator's workspace (POC-1).
type workspaceGate struct {
	want     string
	mu       sync.Mutex
	verified bool
}

var gateFree = map[string]bool{pb.ModalClient_WorkspaceNameLookup_FullMethodName: true, pb.ModalClient_AuthTokenGet_FullMethodName: true}

func (g *workspaceGate) check(ctx context.Context, lookup func(*pb.WorkspaceNameLookupResponse) error) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.verified {
		return nil
	}
	var r pb.WorkspaceNameLookupResponse
	if err := lookup(&r); err != nil {
		return sanitize("workspace lookup", err)
	}
	name := r.GetWorkspaceName()
	if name == "" { // a personal workspace: the server leaves the name empty and names it by its username, as the CLI shows
		name = r.GetUsername()
	}
	if name != g.want {
		return &ModalError{Op: "workspace", Category: "the token isn't for workspace " + g.want + ": nothing was created", Code: "PermissionDenied"}
	}
	g.verified = true
	return nil
}

func (g *workspaceGate) unary(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn,
	invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	if !gateFree[method] {
		err := g.check(ctx, func(r *pb.WorkspaceNameLookupResponse) error {
			return invoker(ctx, pb.ModalClient_WorkspaceNameLookup_FullMethodName, &emptypb.Empty{}, r, cc, opts...)
		})
		if err != nil {
			return err
		}
	}
	return invoker(ctx, method, req, reply, cc, opts...)
}

func (g *workspaceGate) stream(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string,
	streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	g.mu.Lock()
	ok := g.verified
	g.mu.Unlock()
	if !ok { // every stream follows a create, which a unary call verified first
		return nil, &ModalError{Op: "stream", Category: "the workspace wasn't verified first", Code: "PermissionDenied"}
	}
	return streamer(ctx, desc, cc, method, opts...)
}

// NewModalSDK opens the client bound to workspace, finds or makes the App, and builds the image once in it.
func NewModalSDK(ctx context.Context, workspace, appName, imageTag string) (*ModalSDK, error) {
	if workspace == "" {
		return nil, errors.New("no Modal workspace named: the gate needs one (POC-1)")
	}
	g := &workspaceGate{want: workspace}
	mc, err := modal.NewClientWithOptions(&modal.ClientParams{Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		GRPCUnaryInterceptors: []grpc.UnaryClientInterceptor{g.unary}, GRPCStreamInterceptors: []grpc.StreamClientInterceptor{g.stream}})
	if err != nil {
		return nil, sanitize("client", err)
	}
	m := &ModalSDK{Workspace: workspace, Client: mc, boxes: map[string]*modal.Sandbox{}, volumes: map[string]*modal.Volume{}}
	if imageTag == "" { // a client for cleanup only: it deletes by ID, so it never looks up, or creates, an App (POC-9)
		return m, nil
	}
	app, err := mc.Apps.FromName(ctx, appName, &modal.AppFromNameParams{CreateIfMissing: true})
	if err != nil {
		mc.Close()
		return nil, sanitize("app", err)
	}
	m.App = app
	img, err := mc.Images.FromRegistry(imageTag, nil).Build(ctx, app, nil)
	if err != nil {
		mc.Close()
		return nil, sanitize("image build", err)
	}
	m.ImageID, m.image = img.ImageID, img
	return m, nil
}

// Close ends the client, and with it any ephemeral volume it holds.
func (m *ModalSDK) Close() {
	for _, v := range m.volumes {
		v.CloseEphemeral()
	}
	m.Client.Close()
}

// EphemeralVolume makes a volume that lives as long as this client, under key, for a spec's Volumes.
func (m *ModalSDK) EphemeralVolume(ctx context.Context, key string) error {
	v, err := m.Client.Volumes.Ephemeral(ctx, nil)
	if err != nil {
		return sanitize("volume", err)
	}
	m.mu.Lock()
	m.volumes[key] = v
	m.mu.Unlock()
	return nil
}

// Volume is the volume made under key.
func (m *ModalSDK) Volume(key string) *modal.Volume {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.volumes[key]
}

// Sandbox is the SDK's handle for a sandbox this client created.
func (m *ModalSDK) Sandbox(id string) *modal.Sandbox {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.boxes[id]
}

// modalParams is the create request for a spec (POC-2): unit-tested against the setups' table.
func modalParams(spec ModalSpec, tags map[string]string, vols map[string]*modal.Volume) *modal.SandboxCreateParams {
	p := &modal.SandboxCreateParams{Command: spec.Command, Timeout: modalTimeout, Tags: maps.Clone(tags),
		BlockNetwork: spec.BlockNetwork, Volumes: vols} // Modal's default size: the baseline POC-2 tests
	if spec.DomainMode { // non-nil, even empty: allowlist mode, never open
		p.OutboundDomainAllowlist = &modal.Allowlist{Entries: append([]string{}, spec.DomainAllowlist...)}
	}
	if spec.CIDRMode {
		p.OutboundCIDRAllowlist = &modal.Allowlist{Entries: append([]string{}, spec.CIDRAllowlist...)}
	}
	if spec.Runtime == "vm" {
		p.Runtime = modal.SandboxRuntimeVM
	}
	if spec.ProxyViaSidecar != "" {
		p.ExperimentalOptions = map[string]any{"proxy_traffic_via_sidecar": spec.ProxyViaSidecar}
	}
	return p
}

func (m *ModalSDK) Create(ctx context.Context, spec ModalSpec, tags map[string]string) (string, error) {
	vols := map[string]*modal.Volume{}
	for path, key := range spec.Volumes {
		v := m.Volume(key)
		if v == nil {
			return "", errors.New("no volume " + key)
		}
		vols[path] = v
	}
	sb, err := m.Client.Sandboxes.Create(ctx, m.App, m.image, modalParams(spec, tags, vols))
	if err != nil {
		return "", sanitize("create", err)
	}
	m.mu.Lock()
	m.boxes[sb.SandboxID] = sb
	m.mu.Unlock()
	return sb.SandboxID, nil
}

func (m *ModalSDK) Exec(ctx context.Context, id string, args []string, stdin []byte) ([]byte, []byte, int, error) {
	sb := m.Sandbox(id)
	if sb == nil {
		return nil, nil, -1, errors.New("not a sandbox this run created")
	}
	p, err := sb.Exec(ctx, args, &modal.SandboxExecParams{Stdout: modal.Pipe, Stderr: modal.Pipe})
	if err != nil {
		return nil, nil, -1, sanitize("exec", err)
	}
	return drive(ctx, p, stdin)
}

// drive feeds a process its stdin, keeps its output capped, and waits for its exit.
func drive(ctx context.Context, p *modal.ContainerProcess, stdin []byte) ([]byte, []byte, int, error) {
	go func() {
		io.Copy(p.Stdin, bytes.NewReader(stdin))
		p.Stdin.Close()
	}()
	out, errs := modalOut(), &capped{max: 4 << 10}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { io.Copy(out, p.Stdout); wg.Done() }()
	go func() { io.Copy(errs, p.Stderr); wg.Done() }()
	wg.Wait()
	code, err := p.Wait(ctx, nil)
	if err != nil {
		return out.Bytes(), errs.Bytes(), -1, sanitize("exec wait", err)
	}
	return out.Bytes(), errs.Bytes(), code, nil
}

func (m *ModalSDK) Terminate(ctx context.Context, id string) error {
	sb := m.Sandbox(id)
	if sb == nil {
		return errors.New("not a sandbox this run created")
	}
	_, err := sb.Terminate(ctx, &modal.SandboxTerminateParams{Wait: true})
	return sanitize("terminate", err)
}

func (m *ModalSDK) Finished(ctx context.Context, id string) (bool, error) {
	sb, err := m.Client.Sandboxes.FromID(ctx, id, nil) // a fresh handle: the provider's own answer
	if err != nil {
		return false, sanitize("from id", err)
	}
	code, err := sb.Poll(ctx, nil)
	if err != nil {
		return false, sanitize("poll", err)
	}
	return code != nil, nil
}

func (m *ModalSDK) Running(ctx context.Context, tags map[string]string) ([]string, error) {
	it, err := m.Client.Sandboxes.List(ctx, &modal.SandboxListParams{AppID: m.App.AppID, Tags: tags})
	if err != nil {
		return nil, sanitize("list", err)
	}
	var ids []string
	for sb, err := range it {
		if err != nil {
			return nil, sanitize("list", err)
		}
		ids = append(ids, sb.SandboxID)
	}
	slices.Sort(ids)
	return ids, nil
}

func isNotFound(err error) bool {
	var e modal.NotFoundError
	return errors.As(err, &e)
}

func isInvalid(err error) bool {
	var e modal.InvalidError
	return errors.As(err, &e)
}

func isExhausted(err error) bool {
	var e modal.ResourceExhaustedError
	return errors.As(err, &e)
}
