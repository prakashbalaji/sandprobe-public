package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc/status"

	"sandprobe/internal/obs"
)

// ModalSpec is one Modal setup's sandbox (PRV table, POC-2): the Modal row's sandbox with one change.
type ModalSpec struct {
	Setup           string
	BlockNetwork    bool
	DomainMode      bool     // a domain allowlist is set, even with no entries: the SDK's allowlist mode
	DomainAllowlist []string // its entries
	CIDRMode        bool     // a CIDR allowlist is set, even with no entries
	CIDRAllowlist   []string
	Runtime         string            // "" lets Modal pick; "vm" asks for a VM
	ProxyViaSidecar string            // the sidecar name proxy_traffic_via_sidecar names, or ""
	Command         []string          // the main container's command; it must keep the sandbox up
	Volumes         map[string]string // mount path to a volume the API created for this run
}

// modalTimeout is every sandbox's lifetime, a server-side backstop on spend (POC-1).
const modalTimeout = 15 * time.Minute

// ModalDefaultCPU and ModalDefaultMemoryMiB are Modal's default sandbox request, which every setup keeps, bursting
// above it as Modal allows (modal.com/docs/guide/sandbox-resources, read 10 Nov). Spend is estimated at it (POC-9).
const (
	ModalDefaultCPU       = 0.125
	ModalDefaultMemoryMiB = 128
)

// modalAPI is what a Modal run needs from the SDK; tests fake it.
type modalAPI interface {
	Create(ctx context.Context, spec ModalSpec, tags map[string]string) (string, error)
	Exec(ctx context.Context, id string, args []string, stdin []byte) (stdout, stderr []byte, exit int, err error)
	Terminate(ctx context.Context, id string) error
	Finished(ctx context.Context, id string) (bool, error)                 // an independent read: the sandbox polls finished
	Running(ctx context.Context, tags map[string]string) ([]string, error) // the App's running sandboxes with these tags
}

// ModalError is an SDK error with its text dropped (POC-1): a fixed category and the gRPC code, never the SDK's
// message, which could quote a request.
type ModalError struct{ Op, Category, Code string }

func (e *ModalError) Error() string {
	return fmt.Sprintf("modal %s: %s (%s)", e.Op, e.Category, e.Code)
}

// sanitize turns any SDK error into a ModalError.
func sanitize(op string, err error) error {
	if err == nil {
		return nil
	}
	var me *ModalError
	if errors.As(err, &me) {
		return me
	}
	cat := "failed"
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		cat = "timed out or canceled"
	case isNotFound(err):
		cat = "not found"
	case isInvalid(err):
		cat = "invalid request"
	case isExhausted(err):
		cat = "resource exhausted"
	}
	return &ModalError{Op: op, Category: cat, Code: status.Code(err).String()}
}

// ModalBox is a sandbox Sandprobe created in its own Modal App for this run, reached with the SDK's exec as the
// image's default user (PRV table: Modal). It is addressed only by the ID its create returned (PRV-1).
type ModalBox struct {
	Spec      ModalSpec
	SandboxID string
	Tags      map[string]string // sandprobe-run=<run id>: how the cleanup confirms nothing of the run is left
	ProbePath string
	Calls     []obs.ProviderCall
	api       modalAPI
}

// CreateModal creates the run's sandbox. It always returns the box, so a create that failed still leaves its tag
// for the cleanup to look for.
func CreateModal(ctx context.Context, api modalAPI, spec ModalSpec) (*ModalBox, error) {
	b := &ModalBox{Spec: spec, Tags: map[string]string{"sandprobe-run": token("m")[1:]}, api: api}
	at := time.Now()
	id, err := api.Create(ctx, spec, b.Tags)
	b.record(ctx, at, "create sandbox ("+spec.Setup+")", id, err)
	if err != nil {
		return b, err
	}
	if id == "" {
		return b, errors.New("modal create returned no sandbox ID")
	}
	b.SandboxID = id
	return b, nil
}

func (b *ModalBox) ID() string { return b.SandboxID }

// Exec runs a command in the main container by the sandbox's ID, recorded without its output (PRV-3).
func (b *ModalBox) Exec(ctx context.Context, args []string, stdin []byte) ([]byte, error) {
	if b.SandboxID == "" {
		return nil, errors.New("no sandbox")
	}
	at := time.Now()
	out, errs, code, err := b.api.Exec(ctx, b.SandboxID, args, stdin)
	if err == nil && code != 0 {
		err = fmt.Errorf("exited %d: %s", code, strings.TrimSpace(string(errs))) // the box's own stderr, never the SDK's
	}
	b.record(ctx, at, "exec "+args[0], "", err)
	if len(out) > obs.MaxDoc {
		return nil, errors.New("the command's output is larger than a document")
	}
	return out, err
}

// Upload puts the probe in a fresh directory in the sandbox, as its default user, and checks the bytes arrived whole.
func (b *ModalBox) Upload(ctx context.Context, probe []byte) error {
	dir := "/tmp/sandprobe-" + token("")[1:13]
	sum := sha256.Sum256(probe)
	out, err := b.Exec(ctx, []string{"sh", "-c", fmt.Sprintf(
		"umask 022 && mkdir %s && cat > %s/probe && chmod 0555 %s/probe && sha256sum %s/probe", dir, dir, dir, dir)}, probe)
	if err != nil {
		return fmt.Errorf("uploading the probe: %w", err)
	}
	if got, _, _ := strings.Cut(strings.TrimSpace(string(out)), " "); got != hex.EncodeToString(sum[:]) {
		return fmt.Errorf("the probe arrived as %q, not %x", got, sum)
	}
	b.ProbePath = dir + "/probe"
	return nil
}

// Probe runs the probe as the image's default user. SANDPROBE_TWIN is SEC-1's twin, set on the way in.
func (b *ModalBox) Probe(ctx context.Context, args []string, stdin []byte) ([]byte, error) {
	if b.ProbePath == "" {
		return nil, errors.New("the probe isn't uploaded")
	}
	for _, a := range args {
		if !probeArg.MatchString(a) {
			return nil, fmt.Errorf("not a probe argument: %q", a)
		}
	}
	return b.Exec(ctx, append([]string{"env", "SANDPROBE_TWIN=1", b.ProbePath}, args...), stdin)
}

// Destroy terminates the sandbox by its ID, then confirms it: the sandbox polls finished, and nothing of the run's
// tag is running in the App (POC-9). A create that returned no ID is looked for by its tag, and only reported.
func (b *ModalBox) Destroy(ctx context.Context) error {
	if b.SandboxID != "" {
		at := time.Now()
		err := b.api.Terminate(ctx, b.SandboxID)
		b.record(ctx, at, "terminate", b.SandboxID, err)
		if err != nil {
			return err
		}
		at = time.Now()
		done, err := b.api.Finished(ctx, b.SandboxID)
		b.record(ctx, at, "poll", b.SandboxID, err)
		if err != nil {
			return err
		}
		if !done {
			return fmt.Errorf("sandbox %s still running after its terminate", b.SandboxID)
		}
	}
	at := time.Now()
	left, err := b.api.Running(ctx, b.Tags)
	b.record(ctx, at, "list running by tag", "", err)
	if err != nil {
		return err
	}
	if len(left) > 0 {
		return fmt.Errorf("still running with this run's tag: %s", strings.Join(left, ", "))
	}
	if b.SandboxID == "" { // accepted but unseen can still appear later, as on EKS: never counted clean
		return fmt.Errorf("the create returned no sandbox ID, so it stays unresolved: look for tag sandprobe-run=%s "+
			"in App sandprobe later; Modal ends any such sandbox at its %s timeout", b.Tags["sandprobe-run"], modalTimeout)
	}
	return nil
}

func (b *ModalBox) record(ctx context.Context, at time.Time, call, id string, err error) {
	c := obs.ProviderCall{At: at.UTC(), Call: "modal " + call, ID: id, OK: err == nil}
	if err != nil {
		var me *ModalError
		switch {
		case errors.As(err, &me):
			c.Error = me.Category + " (" + me.Code + ")"
		case ctx.Err() != nil:
			c.Error = "timed out or canceled"
		default:
			c.Error = "failed"
		}
	}
	b.Calls = append(b.Calls, c)
}

// modalOut keeps a command's output, capped like a document.
func modalOut() *capped { return &capped{max: obs.MaxDoc + 1} }

// ModalSetups are POC-2's setups, in order. `sandprobe run modal` takes all but the sidecar, which only the PoC builds.
var ModalSetups = []string{"default", "domain-empty", "domain-one", "block", "block-vm", "sidecar"}

// ModalSetup is POC-2's table row for a setup: the Modal row's sandbox with one change. domain-one's one name is the
// twin's, <twin>.canary.<domain> (POC-3).
func ModalSetup(setup, twin, domain string) (ModalSpec, error) {
	s := ModalSpec{Setup: setup, Command: []string{"sleep", "infinity"}}
	switch setup {
	case "default":
	case "domain-empty":
		s.DomainMode = true
	case "domain-one":
		if twin == "" || domain == "" {
			return s, errors.New("domain-one needs the twin's nonce and our domain")
		}
		s.DomainMode, s.DomainAllowlist = true, []string{twin + ".canary." + domain}
	case "block":
		s.BlockNetwork = true
	case "block-vm":
		s.BlockNetwork, s.Runtime = true, "vm"
	case "sidecar":
		s.CIDRMode, s.ProxyViaSidecar = true, "watch"
	default:
		return s, fmt.Errorf("no setup %q: one of %s", setup, strings.Join(ModalSetups, ", "))
	}
	return s, nil
}

// ModalExcluded is what the project's rules of engagement on Modal exclude (PRV-5): every request to a Modal-owned endpoint.
var ModalExcluded = map[string]string{
	"SEC-4": "Modal's rules of engagement for this run: no requests to Modal's metadata addresses (PRV-5)",
	"AMP-6": "Modal's rules of engagement for this run: no connects to the host over vsock (PRV-5)",
	"AMP-7": "Modal's rules of engagement for this run: no handshake with a Kubernetes API the box names (PRV-5)",
	"EGR-3": "Modal's rules of engagement for this run: no requests through a proxy the box names (PRV-5)",
}

// NewToken is a fresh nonce the canary accepts, for a check the PoC adds (POC-3's twin).
func NewToken(kind string) string { return token(kind) }

// Sanitize is sanitize, for the PoC's own SDK calls.
func Sanitize(op string, err error) error { return sanitize(op, err) }
