// Package obs holds what crosses the box boundary: the host's manifest, the probe's observations, and the canary's
// evidence. Nothing the box returns is trusted (GRD-5); ParseDoc is the only way a document from a box gets in.
package obs

import (
	"errors"
	"time"

	"sandprobe/internal/strictjson"
)

const (
	Schema   = "sandprobe.obs/1"
	MaxDoc   = 1 << 20 // GRD-5: 1 MB per document
	MaxField = 2048    // GRD-5: 2 KB per evidence field
)

// Results. Skipped is the host's to assign, never the probe's (GRD-3). Attempted is how the probe reports a canary
// check: the host decides those from receipts and health (SBX-11).
const (
	Pass      = "pass"
	Finding   = "finding"
	Absent    = "absent"
	ScopedOut = "scoped_out"
	Unknown   = "unknown"
	NotFound  = "not_found"
	Attempted = "attempted"
	Skipped   = "skipped"
)

// Manifest is fixed by the host before the run (GRD-5).
type Manifest struct {
	CanaryTCP80Protocol                    string            `json:"canary_tcp80_protocol,omitempty"` // EVD-10; saved reports require schema4.
	WorkloadContract                       *WorkloadContract `json:"workload_contract,omitempty"`     // WGR-1: frozen host context
	BoundaryContract                       *BoundaryContract `json:"boundary_contract,omitempty"`     // BND-1: host declaration, not a verdict
	RunID, Nonce, BoxID, ProbeSHA256, Mode string
	Selected                               []string            // checks the probe must answer
	Skipped                                map[string]string   // checks not selected, with the reason
	Targets                                map[string][]string // check ID -> planned targets a proof must cover, every one
	Discover                               map[string][]string // check ID -> discovery rules a proof must report
	CheckNonces                            map[string]string   // canary check ID -> the nonce only that check carries (SBX-3)
	Endpoints                              map[string]string   // canary check ID -> the planned destination, "ip:port"
	Proxy                                  string              // EGR-3's proxy, "host:port" as the agent's environment names it (SBX-3)
	AllowLocalProxy                        bool                // the person approved contacting a local proxy (SBX-1 (e))
	ProxyMalformed                         bool                // the agent names a proxy Sandprobe can't parse: EGR-3 contacts nothing and ends unknown
	KubeAPI                                string              // AMP-7's Kubernetes API, "ip:port" as the agent's environment names it (SBX-3)
	Reset                                  string              // PER-5's reset model: "restore" (in place) or "recreate" (TWN-3)
	Marks                                  []PlannedMark       // PER-5's markers, resolved from the plan's rule before any is placed
	Overrides                              []string            // test override names this run allows (Tests)
	// NoCanary is HCN-5's -no-canary: the canary checks stay graded, as unknown, but are never sent to the probe.
	NoCanary bool `json:"NoCanary,omitempty"`
	// SkipKinds is why each provider-endpoint skip was made (GRD-3, SCR-2): SkipProviderTerms or SkipOptIn. Only the
	// host writes it, and it never reaches the probe's input.
	SkipKinds map[string]string `json:"SkipKinds,omitempty"`
	// Attested is the provider-endpoint checks the person attests their provider's terms allow on their own account
	// (PRV-15's -provider-endpoints), sorted. Only the host writes it, and it never reaches the probe's input.
	Attested []string `json:"Attested,omitempty"`
	// DeclaredProvider is PRV-17's -provider on run exec: the provider the operator says the box runs on, a key of this
	// binary's PRV-row table. It is the operator's word, never verified. Only the host writes it, and it never reaches
	// the probe's input.
	DeclaredProvider string `json:"declared_provider,omitempty"`
}

// Skip kinds (SCR-2). Only a provider-terms skip can make a scorecard category not applicable.
const (
	SkipProviderTerms = "provider_terms" // a PRV row: Sandprobe's reviewed scope for the provider excludes its own endpoint (PRV-5, PRV-17)
	SkipOptIn         = "opt_in"         // PRV-15's or RCP-4's default, which the person may lift (-provider-endpoints)
)

// Input is what the host hands the probe on stdin: the manifest, as far as the box needs it.
type Input struct {
	CanaryTCP80Protocol string              `json:"canary_tcp80_protocol,omitempty"`
	RunID               string              `json:"run_id"`
	Nonce               string              `json:"nonce"`
	BoxID               string              `json:"box_id"`
	Mode                string              `json:"mode"`
	Selected            []string            `json:"selected"`
	Targets             map[string][]string `json:"targets"`
	Discover            map[string][]string `json:"discover"`
	CheckNonces         map[string]string   `json:"check_nonces"`
	Endpoints           map[string]string   `json:"endpoints"`
	CanaryDomain        string              `json:"canary_domain"`
	CanaryPin           string              `json:"canary_pin"` // hex SHA-256 of the canary's SubjectPublicKeyInfo
	Proxy               string              `json:"proxy"`      // the proxy the plan named for EGR-3, "host:port"; the only one contacted
	AllowLocal          bool                `json:"allow_local_proxy"`
	KubeAPI             string              `json:"kube_api"` // the Kubernetes API the plan named for AMP-7; the only one contacted
	// OwnInit says PID 1 is Sandprobe's own idle process, as the host read it from Docker's record of the container,
	// never from the box: SEC-2 and SEC-5 skip exactly that PID (DKR-2).
	OwnInit bool `json:"own_init,omitempty"`
	// Scratch is where the probe makes its private scratch directory: a tmpfs the host mounted for it on a read-only
	// root (DKR-4). Empty is the probe's temporary directory.
	Scratch string `json:"scratch,omitempty"`
}

// SurveySchema names the probe's survey: what the host needs from the box before it can plan (SBX-3).
const SurveySchema = "sandprobe.survey/1"

// Survey is the probe's report before the plan, run through the agent's path like the probe itself.
type Survey struct {
	Schema  string        `json:"schema"`
	Proxy   *ProxySetting `json:"proxy"`    // nil when the agent's environment names no proxy for HTTPS
	KubeAPI string        `json:"kube_api"` // the Kubernetes API the agent's environment names, "ip:port"; empty if none
	Vsock   bool          `json:"vsock"`    // /dev/vsock exists (lstat only, never opened)
	Roots   []Root        `json:"roots"`    // storage roots the agent can write, a read-only inventory (TWN-3)
	// RootsIncomplete says why the inventory may be missing roots. The plan marks every root the adapter declares
	// whether or not the survey found it, so an incomplete inventory can't shrink PER-5.
	RootsIncomplete string `json:"roots_incomplete,omitempty"`
}

// ProxySetting is the proxy the agent's environment names for HTTPS, as SBX-5 records it: the variable, the scheme,
// the address and whether the URL carries credentials. Never the credentials.
type ProxySetting struct {
	Var         string `json:"var"`
	Scheme      string `json:"scheme"`
	Addr        string `json:"addr"` // "host:port", the scheme's default port filled in
	Credentials bool   `json:"credentials"`
	Malformed   bool   `json:"malformed,omitempty"`
}

// ParseSurvey reads a survey from a box under the same rules as ParseDoc.
func ParseSurvey(b []byte) (*Survey, error) {
	var s Survey
	if err := strict(b, &s); err != nil {
		return nil, err
	}
	if s.Schema != SurveySchema {
		return nil, errSchema(s.Schema, SurveySchema)
	}
	if len(s.Roots) > 64 {
		return nil, errors.New("more than 64 storage roots")
	}
	if p := s.Proxy; len(s.KubeAPI) > 512 || p != nil && (len(p.Var) > 64 || len(p.Scheme) > 64 || len(p.Addr) > 512) {
		return nil, errors.New("a survey field is over its size limit")
	}
	return &s, nil
}

// Doc is what the probe returns. Its times are offsets on the probe's own monotonic clock: the box's wall clock is
// never compared with the host's.
type Doc struct {
	Schema       string            `json:"schema"`
	RunID        string            `json:"run_id"`
	Nonce        string            `json:"nonce"`
	BoxID        string            `json:"box_id"`
	ProbeSHA256  string            `json:"probe_sha256"`
	DurationMS   int64             `json:"duration_ms"`
	Identity     *Identity         `json:"identity"`
	Overrides    map[string]string `json:"overrides,omitempty"`
	Observations []Observation     `json:"observations"`
}

// Identity is who the probe ran as (SBX-4), read from /proc/self/status, plus the setuid-root files in the system
// binary directories. The host grades AMP-2 and AMP-3 from it.
type Identity struct {
	UID        int         `json:"uid"`
	GID        int         `json:"gid"`
	CapEff     string      `json:"cap_eff"` // hex, as /proc/self/status prints it
	CapInh     string      `json:"cap_inh"`
	CapPrm     string      `json:"cap_prm"`
	CapBnd     string      `json:"cap_bnd"`
	CapAmb     string      `json:"cap_amb"`
	NoNewPrivs *int        `json:"no_new_privs"` // required: 0 or 1
	Seccomp    int         `json:"seccomp"`
	SetuidScan *SetuidScan `json:"setuid_scan"` // needed when NoNewPrivs is 0
}

// SetuidScan is the probe's scan of the system binary directories for setuid-root files. Complete is false when the
// scan failed or was cut short, so an empty list is never mistaken for a clean scan.
type SetuidScan struct {
	Complete bool     `json:"complete"`
	Files    []string `json:"files"`
}

type Observation struct {
	ObservedNames []string  `json:"observed_names,omitempty"` // WGR-2: identifiers only, never values
	ID            string    `json:"id"`
	Result        string    `json:"result"`
	Variant       string    `json:"variant,omitempty"`
	Evidence      string    `json:"evidence,omitempty"`
	Reason        string    `json:"reason,omitempty"`
	Proof         *Proof    `json:"proof,omitempty"`
	Attempts      []Attempt `json:"attempts,omitempty"`
}

// Proof is a check's negative proof (TWN-1), or its verified absence (TWN-2), covering every planned target and every
// target each discovery rule found.
type Proof struct {
	Mechanism   string         `json:"mechanism"`              // must be the catalog's mechanism for the check
	Twin        bool           `json:"twin"`                   // the allowed twin succeeded through the same call
	TwinRefused bool           `json:"twin_refused,omitempty"` // as non-root, the probe's own 0000 file or 0500 directory was refused
	Root        bool           `json:"root,omitempty"`         // the probe ran as uid 0; must match the identity
	Count       int            `json:"count,omitempty"`        // entries a whole-table mechanism read (env_names, net_table)
	Discovered  map[string]int `json:"discovered,omitempty"`   // discovery rule -> how many targets it found
	Targets     []Target       `json:"targets,omitempty"`
}

// Target is one path, socket or process a check tested. Never a value.
type Target struct {
	Device           uint64 `json:"device,omitempty"` // WGR-2: pinned file metadata, no contents
	Inode            uint64 `json:"inode,omitempty"`
	Name             string `json:"name"`
	Rule             string `json:"rule,omitempty"`  // the discovery rule that found it; empty for a planned target
	State            string `json:"state"`           // refused, absent or found
	Errno            string `json:"errno,omitempty"` // EACCES, EPERM, EROFS or ENOENT
	ParentSearchable bool   `json:"parent_searchable,omitempty"`
}

// Attempt is one network try at the canary, with the kernel evidence TWN-1 asks for.
type Attempt struct {
	Dest           string `json:"dest"`          // the destination tried, "ip:port"; must be the manifest's endpoint
	Via            string `json:"via,omitempty"` // the proxy the attempt went through, "ip:port" as connected; EGR-3 only
	StartMS        int64  `json:"start_ms"`      // offsets from the probe's start, on its monotonic clock
	EndMS          int64  `json:"end_ms"`
	Immediate      bool   `json:"immediate"`                // the error came back from connect itself, with no EINPROGRESS
	Outcome        string `json:"outcome"`                  // refused, timeout, netunreach, hostunreach, eperm, connected, error
	ExchangeStage  string `json:"exchange_stage,omitempty"` // EVD-2: diagnostic only, never refusal/delivery proof
	ExchangeResult string `json:"exchange_result,omitempty"`
	SynSent        bool   `json:"syn_sent"`               // TCP_INFO showed SYN_SENT before the final error
	SynRetrans     int    `json:"syn_retrans"`            // TCP_INFO's SYN retransmits, for a timeout
	RouteLookup    string `json:"route_lookup,omitempty"` // the kernel's route for the canary: none, unreachable, prohibit or ok
	LoopbackTwin   bool   `json:"loopback_twin"`          // the same client call reached the probe's own loopback listener
}

// Receipt says a nonce the host issued reached the canary on its check's protocol and port. The nonce names exactly
// one check, so the canary never has to know the route; it shows the nonce got out, not that the box's own
// connection took the check's route (SBX-11). From is the source address of the first matching attempt. It reaches
// the host from the canary, never through the box.
type Receipt struct {
	Nonce, Proto string
	Port         int
	From         string
}

// ProviderCall is one call an adapter made to its provider (PRV-3): what it called, when, how it ended, the
// provider's own status, and the ID it returned. Nothing the call sent on stdin or printed is kept: a report is
// shareable, and output can hold anything.
type ProviderCall struct {
	At     time.Time `json:"at"`
	Call   string    `json:"call"`
	OK     bool      `json:"ok"`               // the CLI exited 0, and the provider's status, if it gave one, was 2xx
	Exit   int       `json:"exit"`             // the CLI's exit code; -1 when it didn't run to an exit
	Status string    `json:"status,omitempty"` // the provider's HTTP status, for API calls
	ID     string    `json:"id,omitempty"`     // the provider ID the call returned
	Error  string    `json:"error,omitempty"`  // a category only, never the CLI's output
}

// CanaryEvidence is what the host gathered for one run, all by the host's own clock. Launched and Returned bracket
// the probe physically: it can't have run, or attempted anything, outside them.
type CanaryEvidence struct {
	Live               bool
	Launched, Returned time.Time
	Health             map[string][]time.Time // "tcp/443": when each of the host's health connects was confirmed
	Receipts           []Receipt
	Elsewhere          map[string]uint64 // armed nonces also counted on another protocol or port (SBX-11), by nonce
	ReceiptsRead       bool              // the host's receipt query completed; a failed or skipped query leaves this false
	ReceiptsQueriedAt  time.Time         // by the host's clock, when that query was sent; the canary answers with all it holds for the run
	Overloaded         bool              // the canary hit a cap, or the kernel dropped traffic, while the run was armed: no negative counts
	Reset              *ResetEvidence    // PER-5's reset, mark and recheck; nil when PER-5 wasn't run
}

// ParseDoc reads one document from a box: at most MaxDoc bytes, one JSON value, no field Sandprobe doesn't know.
func ParseDoc(b []byte) (*Doc, error) {
	var d Doc
	if err := strict(b, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

func errSchema(got, want string) error { return errors.New("unsupported observation schema") }

func strict(b []byte, v any) error {
	// JON-1: reject duplicate/alias keys before decoding untrusted observations.
	return strictjson.Decode(b, MaxDoc, v)
}
