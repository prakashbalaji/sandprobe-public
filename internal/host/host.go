// Package host is the host's half of a run. It surveys the box, fixes the manifest before anything runs (GRD-5),
// keeps the canary's health confirmed around the probe (SBX-11), launches the probe through the agent's path inside
// its own launch-to-return bracket, asks the canary for its receipts, and grades. It trusts nothing from the box.
package host

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"sandprobe/internal/canary"
	"sandprobe/internal/catalog"
	"sandprobe/internal/grade"
	"sandprobe/internal/obs"
)

// Box is a box under test, reached the way the platform reaches the agent (SBX-4).
type Box interface {
	ID() string // original create-returned provider ID (PRV-1), or explicit named exception PRV-13
	// Probe runs the shipped probe as the agent with args and stdin, and returns what it wrote to stdout.
	Probe(ctx context.Context, args []string, stdin []byte) ([]byte, error)
}

// Storage is what an adapter declares about resetting its box (PRV-4, TWN-3): the model, and the storage PER-5 may
// mark. A box that can't be reset declares none, and PER-5 is skipped.
type Storage struct {
	Model   string       // restore (in place) or recreate; empty when the adapter can't reset its box
	Volumes []obs.Volume // recreate: the persistent volumes Sandprobe created for this run
	Mounts  []string     // restore: the mount paths the adapter declares part of the box, deleted with it
}

// Resettable is a box whose adapter can reset it, and tear it down with everything Sandprobe created for it.
type Resettable interface {
	Box
	Storage(ctx context.Context) (Storage, error)
	// Reset performs the reset and returns the box after it, with the provider's evidence (TWN-3).
	Reset(ctx context.Context) (Box, *obs.ResetEvidence, error)
	// Teardown deletes the box and each volume Sandprobe created for it, identified as it was at creation, and
	// reports which deletions the provider definitively confirmed, by volume ID; the box's own under "". A volume
	// whose identity no longer matches is left alone and reported unconfirmed.
	Teardown(ctx context.Context, vols []obs.Volume) map[string]bool
}

// Canary is the host's side of the canary (SBX-11).
type Canary interface {
	IP() string // its address as the box reaches it
	Domain() string
	Health(ctx context.Context, port int, k canary.Key) bool          // one health connect, proven to come from the canary with key k
	Ask(ctx context.Context, q canary.Request) (canary.Answer, error) // the control channel, answered by the canary itself
}

type Options struct {
	BlockDevicePaths    []string              // EVD-13: host-declared metadata-only paths, supplementing discovery.
	CanaryTCP80Protocol string                // EVD-10: explicit opt-in; empty preserves legacy traffic.
	UploadAddresses     map[string]string     // MEAS-7: host-frozen addresses for selected names only
	UploadHosts         []string              // MEAS-6: explicit TLS-only workload destinations; default off
	WorkloadContract    *obs.WorkloadContract // WGR-1: frozen before workload release
	BoundaryContract    *obs.BoundaryContract // BND-1: optional reference-run declaration
	Mode                string                // exec, workload, self or other (SBX-4)
	NoCanary            bool                  // HCN-5: no canary; its checks are unknown and never sent to the probe
	ProbeSHA256         string                // the digest of the probe binary the host shipped (SBX-5)
	AllowLocalProxy     bool                  // the person approved contacting a local proxy (SBX-1 (e), AGT-3)
	// Excluded is what the provider's rules of engagement rule out (PRV-5): check ID to the reason. Only the checks
	// GRD-3 names for it may be excluded; Execute refuses any other.
	Excluded map[string]string
	// ExcludedKind is why Excluded skips them (SCR-2): obs.SkipProviderTerms for a native adapter's PRV row,
	// obs.SkipOptIn for PRV-15's or RCP-4's default. Empty records no kind, and the scorecard reads "Not tested".
	ExcludedKind string
	// Attested is PRV-15's -provider-endpoints: the provider-endpoint checks the person attests their provider's terms
	// allow on their own account. None may also be excluded.
	Attested []string
	// DeclaredProvider is PRV-17's -provider on run exec: a key of TermsExclusions, the operator's word. Each check its
	// entry excludes must be in Excluded with the entry's own reason, and gets kind provider_terms; the rest keep
	// ExcludedKind, which must be opt_in.
	DeclaredProvider string
	// Existing is an existing box (PRV-1): it gets non-mutating checks only, so AMP-6 makes no vsock connect.
	Existing bool
	// OwnInit is DKR-2: the adapter read from the provider's own record of the box, never from the box, that PID 1 is
	// Sandprobe's idle process, so SEC-2 and SEC-5 skip exactly that PID.
	OwnInit bool
	// Scratch is DKR-4: the absolute path of a tmpfs the adapter mounted for the probe's scratch on a read-only root.
	// It is never a storage root PER-5 may mark.
	Scratch string
}

// excludable is every check a provider's rules of engagement may skip (GRD-3, PRV-5): each would send a request to
// an endpoint the provider owns.
var excludable = catalog.ProviderEndpoints

// Run is everything one run produced, for the report.
type Run struct {
	Survey   *obs.Survey
	Manifest obs.Manifest
	Input    obs.Input
	Doc      []byte
	Evidence obs.CanaryEvidence
	Report   grade.Report
	Box      Box           // the box at the end: a recreate replaces it
	Volumes  []obs.Volume  // the volumes Sandprobe created, as identified at the plan, for teardown
	Markers  []obs.Cleanup // every marker the plan named, its identity confirmed or not
}

const (
	probeLimit  = 100 * time.Second // SBX-7's 90 s for the probe, and the adapter's own exec overhead
	healthEvery = time.Second       // SBX-11: each canary port in use, once a second
	receiptWait = 2100 * time.Millisecond
	armTTL      = 600 // seconds: the probe's limit, the receipt wait and PER-5's reset fit well inside it
)

// armWants is every check nonce the plan issued, each with its check's protocol and port (SBX-11). The document
// nonce isn't armed.
func armWants(m obs.Manifest) []canary.Want {
	var ws []canary.Want
	for _, id := range m.Selected {
		if ck, _ := catalog.Get(id); ck.Canary != nil && m.CheckNonces[id] != "" {
			ws = append(ws, canary.Want{Nonce: m.CheckNonces[id], Proto: ck.Canary.Proto, Port: ck.Canary.Port})
		}
	}
	return ws
}

// Execute runs the probe in a box and grades it. An error means no run happened; a run that happened but can't be
// graded comes back with an invalid report.
func Execute(ctx context.Context, b Box, c Canary, o Options) (*Run, error) {
	if err := catalog.ValidateBlockDevicePaths(o.BlockDevicePaths); err != nil {
		return nil, err
	}
	if !obs.ValidCanaryTCP80Protocol(o.CanaryTCP80Protocol) || (o.NoCanary && o.CanaryTCP80Protocol != "") {
		return nil, fmt.Errorf("invalid canary TCP/80 protocol option")
	}

	if _, err := catalog.BindUploadHosts(o.UploadHosts, o.UploadAddresses); err != nil {
		return nil, err
	}
	if o.NoCanary && len(o.UploadHosts) != 0 {
		return nil, fmt.Errorf("upload hosts cannot be selected with no-canary")
	}
	if err := obs.ValidateWorkloadContract(o.WorkloadContract); err != nil {
		return nil, err
	}
	if o.WorkloadContract != nil && o.WorkloadContract.BoxID != b.ID() {
		return nil, fmt.Errorf("workload box mismatch")
	}
	if err := obs.ValidateBoundaryContract(o.BoundaryContract); err != nil {
		return nil, err
	}
	for id := range o.Excluded {
		if !excludable[id] {
			return nil, fmt.Errorf("%s can't be excluded by a provider's rules of engagement (GRD-3)", id)
		}
	}
	if sc := o.Scratch; sc != "" && (!filepath.IsAbs(sc) || filepath.Clean(sc) != sc || sc == "/" || sc == "/tmp") {
		return nil, fmt.Errorf("the probe's scratch must be an absolute path of Sandprobe's own, never / or /tmp (DKR-4)")
	}
	if k := o.ExcludedKind; k != "" && k != obs.SkipProviderTerms && k != obs.SkipOptIn {
		return nil, fmt.Errorf("%q isn't a skip kind (SCR-2)", k)
	}
	for i, id := range o.Attested { // PRV-15: an attestation names a provider endpoint once, and lifts its exclusion
		if _, excluded := o.Excluded[id]; !excludable[id] || excluded || slices.Contains(o.Attested[:i], id) {
			return nil, fmt.Errorf("%s can't be attested (PRV-15)", id)
		}
	}
	if err := checkDeclared(o); err != nil {
		return nil, err
	}
	out, err := b.Probe(ctx, []string{"-survey"}, nil)
	if err != nil {
		return nil, fmt.Errorf("the survey didn't run: %w", err)
	}
	r := &Run{}
	if r.Survey, err = obs.ParseSurvey(out); err != nil {
		return nil, fmt.Errorf("the survey: %w", err)
	}
	var st Storage
	rs, resettable := b.(Resettable)
	if resettable {
		if st, err = rs.Storage(ctx); err != nil {
			return nil, fmt.Errorf("the box's storage: %w", err)
		}
	}
	if o.NoCanary { // HCN-5: nothing is asked of any canary; its checks end unknown
		c = noCanary{}
	}
	status, err := c.Ask(ctx, canary.Request{Op: "status"})
	pin := status.Pin
	key, kerr := canary.KeyOf(status) // health counts only when it proves this key answered (SBX-11)
	live := err == nil && status.OK && pin != "" && kerr == nil
	if o.CanaryTCP80Protocol != "" {
		if !live {
			return nil, fmt.Errorf("HTTP marker canary status unavailable")
		}
		if err := requireHTTPMarkerForPin(ctx, c, pin); err != nil {
			return nil, err
		}
	}

	r.Manifest, r.Input = Plan(o, r.Survey, b.ID(), st, c.IP(), c.Domain(), pin)
	if wants := armWants(r.Manifest); live && len(wants) > 0 { // SBX-11: the canary counts only what the run armed
		a, err := c.Ask(ctx, canary.Request{Op: "arm", Run: r.Manifest.RunID, TTL: armTTL, Wants: wants})
		live = err == nil && a.OK && a.Pin == pin && a.Run == r.Manifest.RunID
	}
	if m, ok := c.(interface{ MustArm() bool }); ok && m.MustArm() && !live {
		// HCN-3: a public canary that didn't arm the run stops it before the probe; the adapter deletes the box
		return nil, errors.New("the public canary didn't arm this run, so the probe didn't run (HCN-3)")
	}
	r.Box, r.Volumes = b, st.Volumes
	in, err := json.Marshal(r.Input)
	if err != nil {
		return nil, err
	}

	h := startHealth(ctx, c, healthPorts(r.Manifest), key)
	h.firstRound(ctx, 5*time.Second)
	ev := &r.Evidence
	ev.Launched = time.Now()
	pctx, cancel := context.WithTimeout(ctx, probeLimit)
	r.Doc, err = b.Probe(pctx, nil, in)
	cancel()
	ev.Returned = time.Now()
	probeErr := err

	// The receipt query goes at least 2 s after the probe returned, by the host's clock, and health keeps being
	// confirmed past the return so it covers the whole bracket.
	if !o.NoCanary { // with no canary there are no receipts to wait for (HCN-5)
		select {
		case <-time.After(time.Until(ev.Returned.Add(receiptWait))):
		case <-ctx.Done():
		}
	}
	h.stop()
	ev.Health = h.times()
	ev.ReceiptsQueriedAt = time.Now()
	q, err := c.Ask(ctx, canary.Request{Op: "query", Run: r.Manifest.RunID})
	ours := err == nil && q.OK && q.Pin == pin && q.Run == r.Manifest.RunID
	ev.Live = live
	ev.ReceiptsRead = live && ours
	ev.Overloaded = ours && q.Overloaded
	for _, n := range q.Counts {
		if ours && n.Count > 0 {
			ev.Receipts = append(ev.Receipts, obs.Receipt{Nonce: n.Nonce, Proto: n.Proto, Port: n.Port, From: n.FirstFrom})
		}
		if ours && n.Elsewhere > 0 { // never a receipt for the check; kept for a provider's stop gate (POC-5)
			if ev.Elsewhere == nil {
				ev.Elsewhere = map[string]uint64{}
			}
			ev.Elsewhere[n.Nonce] = n.Elsewhere
		}
	}
	if live {
		c.Ask(ctx, canary.Request{Op: "disarm", Run: r.Manifest.RunID})
	}
	if probeErr != nil {
		r.Report = grade.Report{Invalid: "the probe didn't run to the end: " + probeErr.Error(), Skipped: r.Manifest.Skipped}
		return r, nil
	}
	if slices.Contains(r.Manifest.Selected, "PER-5") && resettable {
		ev.Reset = persist(ctx, rs, r)
	}
	r.Report = grade.GradeBytes(r.Manifest, r.Doc, ev)
	return r, nil
}

// persist is PER-5 after the main run (TWN-3): the marks the plan named, the provider's reset, and the recheck on the
// box after it. A step that fails leaves the later ones out, and the grader says unknown. Every planned marker is
// listed from the start, its identity unconfirmed until the mark reports it, so a crash still leaves an exact list.
func persist(ctx context.Context, rs Resettable, r *Run) *obs.ResetEvidence {
	m := r.Manifest
	for _, pm := range m.Marks {
		r.Markers = append(r.Markers, obs.Cleanup{Path: pm.Path, How: "on the box, until it is deleted"})
	}
	in, _ := json.Marshal(obs.MarkInput{RunID: m.RunID, Nonce: m.Nonce, BoxID: m.BoxID, Marks: m.Marks})
	markOut, err := rs.Probe(ctx, []string{"-mark"}, in)
	if err != nil {
		return &obs.ResetEvidence{Model: m.Reset, BoxBefore: m.BoxID}
	}
	md, err := obs.ParseMark(markOut)
	if err != nil || !markFits(m, md) {
		// the grader invalidates it; nothing it names is reset or rechecked
		return &obs.ResetEvidence{Model: m.Reset, BoxBefore: m.BoxID, Mark: markOut}
	}
	// The recheck's input comes from the plan, with only each mark's outcome taken from the document.
	placed := make([]obs.Placed, len(m.Marks))
	for i, pm := range m.Marks {
		p := md.Marks[i]
		placed[i] = obs.Placed{Root: pm.Root, Path: pm.Path, Placed: p.Placed, Ino: p.Ino, Size: p.Size}
		r.Markers[i].Confirmed = p.Placed
	}
	after, ev, err := rs.Reset(ctx)
	if after != nil {
		r.Box = after // whatever the reset created is what teardown must delete, even when the reset then failed
	}
	if ev == nil {
		ev = &obs.ResetEvidence{Model: m.Reset, BoxBefore: m.BoxID}
	}
	ev.Mark = markOut
	if err != nil || after == nil {
		return ev
	}
	in, _ = json.Marshal(obs.RecheckInput{RunID: m.RunID, Nonce: m.Nonce, BoxID: after.ID(), Marks: placed, Startup: grade.StartupTargets()})
	if out, err := after.Probe(ctx, []string{"-recheck"}, in); err == nil {
		ev.Recheck = out
	}
	return ev
}

// markFits: the mark document is this run's, on this box, naming exactly the planned markers in order, each outcome
// consistent with itself (grade.PlacedSound).
func markFits(m obs.Manifest, d *obs.MarkDoc) bool {
	if d.RunID != m.RunID || d.Nonce != m.Nonce || d.BoxID != m.BoxID || len(d.Marks) != len(m.Marks) {
		return false
	}
	for i, pm := range m.Marks {
		if d.Marks[i].Root != pm.Root || d.Marks[i].Path != pm.Path || !grade.PlacedSound(d.Marks[i], m.RunID) {
			return false
		}
	}
	return true
}

// Teardown deletes the box and Sandprobe's volumes, and settles each marker's fate: gone only with a deletion the
// provider confirmed, otherwise an unresolved cleanup item. No marker is ever removed by name (SBX-1).
func Teardown(ctx context.Context, r *Run) error {
	rs, ok := r.Box.(Resettable)
	if !ok {
		for i := range r.Markers {
			r.Markers[i].How = "the box can't be torn down by its adapter: the marker may remain"
		}
		if len(r.Markers) == 0 && len(r.Volumes) == 0 {
			return nil // nothing Sandprobe created beyond what the probe removes itself (SBX-1)
		}
		return fmt.Errorf("box %s can't be torn down by its adapter: delete it and Sandprobe's volumes by hand", r.Box.ID())
	}
	gone := rs.Teardown(ctx, r.Volumes)
	var left []string // PRV-3: a failed delete is loud, markers or not
	if !gone[""] {
		left = append(left, "box "+r.Box.ID())
	}
	for _, v := range r.Volumes {
		if !gone[v.ID] {
			left = append(left, "volume "+v.ID)
		}
	}
	for i, pm := range r.Manifest.Marks {
		if i >= len(r.Markers) {
			break
		}
		key, what := "", "the box"
		if pm.Volume != nil {
			key, what = pm.Volume.ID, "volume "+pm.Volume.ID
		}
		if gone[key] {
			r.Markers[i].Gone, r.Markers[i].How = true, what+" deleted, the provider confirming it"
		} else {
			r.Markers[i].How = what + " wasn't confirmed deleted: the marker may remain"
		}
	}
	if len(left) > 0 {
		return fmt.Errorf("not confirmed deleted, so delete by hand: %s", strings.Join(left, ", "))
	}
	return nil
}

// attested is PRV-15's attestations as the manifest keeps them: sorted, or nil when there are none.
func attested(ids []string) []string {
	if len(ids) == 0 {
		return nil
	}
	return slices.Sorted(slices.Values(ids))
}

// Plan fixes the manifest (GRD-5): the checks selected and skipped, each one's planned targets and discovery rules from
// the catalog, fresh nonces for the run and for each canary check, each canary check's endpoint, and EGR-3's proxy from
// the survey. Only GRD-3's gates skip a check, and only the host decides them: EGR-6 until it's approved, AMP-6 with no
// vsock device, and EGR-3 when the agent's environment names no proxy, or a local one nobody approved. One it can't
// parse leaves EGR-3 unknown.
func Plan(o Options, s *obs.Survey, boxID string, st Storage, canaryIP, domain, pin string) (obs.Manifest, obs.Input) {
	skip := map[string]string{"EGR-6": "contacting EGR-6's public upload hosts wasn't approved"}
	uploadTargets, uploadErr := catalog.BindUploadHosts(o.UploadHosts, o.UploadAddresses)
	if !o.NoCanary && len(o.UploadHosts) > 0 && uploadErr == nil {
		delete(skip, "EGR-6") // MEAS-6: only explicit finite workload destinations lift this gate.
	}
	var kinds map[string]string // SCR-2: only the host's own exclusions get a kind, never a survey-driven skip
	declared := DeclaredExclusions(o.DeclaredProvider)
	for id, why := range o.Excluded {
		if excludable[id] {
			skip[id] = why
			kind := o.ExcludedKind
			if _, ok := declared[id]; ok { // PRV-17: the declared provider's PRV row decides this one
				kind = obs.SkipProviderTerms
			}
			if kind != "" {
				if kinds == nil {
					kinds = map[string]string{}
				}
				kinds[id] = kind
			}
		}
	}
	runID := token("r")
	if o.Scratch != "" { // DKR-4: Sandprobe's own scratch mount is never a storage root of the box
		own := *s
		own.Roots = slices.DeleteFunc(slices.Clone(s.Roots), func(r obs.Root) bool { return r.Path == o.Scratch })
		s = &own
	}
	marks := planMarks(s, st, runID)
	switch {
	case st.Model == "":
		skip["PER-5"] = "the provider's reset leaves no storage to test: the adapter can't reset this box"
	case len(marks) == 0:
		skip["PER-5"] = "the provider's reset leaves no storage to test: no root this run may mark"
	}
	switch {
	case skip["AMP-6"] != "": // a provider's exclusion keeps its own reason (PRV-5)
	case o.Existing:
		skip["AMP-6"] = "an existing box gets no vsock connects (PRV-1)"
	case !s.Vsock:
		skip["AMP-6"] = "no vsock device"
	}
	var proxy string
	switch p := s.Proxy; {
	case skip["EGR-3"] != "": // excluded (PRV-5): the box's proxy is never named, so never contacted
	case p == nil:
		skip["EGR-3"] = "the agent's environment names no proxy"
	case p.Malformed: // a proxy the agent names but Sandprobe can't parse: selected, so it ends unknown
	case local(p.Addr) && !o.AllowLocalProxy:
		skip["EGR-3"] = "the agent's proxy is local, and contacting it wasn't approved (-allow-local-proxy)"
	default:
		proxy = p.Addr
	}
	var selected []string
	skipped := map[string]string{}
	for _, id := range catalog.IDs() {
		if why, ok := skip[id]; ok {
			skipped[id] = why
			continue
		}
		selected = append(selected, id)
	}
	// HCN-5: without a canary its checks stay selected, so the grader marks them unknown, but the probe never sees them.
	probeSelected := selected
	if o.NoCanary {
		probeSelected = nil
		for _, id := range selected {
			if ck, _ := catalog.Get(id); !catalog.NeedsCanary(ck) {
				probeSelected = append(probeSelected, id)
			}
		}
	}
	targets, discover := catalog.Plan(probeSelected)
	// EVD-13: copy the host declaration before launching the probe.
	if len(o.BlockDevicePaths) > 0 {
		targets["AMP-8.blk"] = append(targets["AMP-8.blk"], o.BlockDevicePaths...)
	}
	if skip["EGR-6"] == "" {
		targets["EGR-6"] = append([]string(nil), uploadTargets...)
	}
	if o.WorkloadContract != nil {
		targets["SEC-3"] = append(targets["SEC-3"], obs.ProtectedMarker)
	}
	m := obs.Manifest{CanaryTCP80Protocol: o.CanaryTCP80Protocol, RunID: runID, Nonce: token("n"), BoxID: boxID, ProbeSHA256: o.ProbeSHA256, Mode: o.Mode,
		Selected: selected, Skipped: skipped, Targets: targets, Discover: discover,
		CheckNonces: map[string]string{}, Endpoints: map[string]string{}, Proxy: proxy, AllowLocalProxy: o.AllowLocalProxy,
		ProxyMalformed: s.Proxy != nil && s.Proxy.Malformed && skip["EGR-3"] == "", KubeAPI: s.KubeAPI, NoCanary: o.NoCanary,
		SkipKinds: kinds, Attested: attested(o.Attested), DeclaredProvider: o.DeclaredProvider}
	if o.WorkloadContract != nil {
		contract := *o.WorkloadContract
		m.WorkloadContract = &contract
	}
	// BND-2: scalar fields; caller mutation cannot rewrite the manifest.
	if o.BoundaryContract != nil {
		contract := *o.BoundaryContract
		m.BoundaryContract = &contract
	}
	if skip["AMP-7"] != "" {
		m.KubeAPI = "" // excluded (PRV-5): the box's Kubernetes API is never named, so never contacted
	}
	if skip["PER-5"] == "" {
		m.Reset, m.Marks = st.Model, marks
	}
	for _, id := range probeSelected {
		if ck, _ := catalog.Get(id); ck.Canary != nil {
			m.CheckNonces[id] = token("c")
			m.Endpoints[id] = net.JoinHostPort(canaryIP, fmt.Sprint(ck.Canary.Port))
		}
	}
	in := obs.Input{CanaryTCP80Protocol: m.CanaryTCP80Protocol, RunID: m.RunID, Nonce: m.Nonce, BoxID: m.BoxID, Mode: m.Mode, Selected: probeSelected, Targets: m.Targets,
		Discover: m.Discover, CheckNonces: m.CheckNonces, Endpoints: m.Endpoints, CanaryDomain: domain, CanaryPin: pin,
		Proxy: m.Proxy, AllowLocal: m.AllowLocalProxy, KubeAPI: m.KubeAPI, OwnInit: o.OwnInit, Scratch: o.Scratch}
	return m, in
}

// local: a proxy address the host can already see is local. The probe checks again once the name resolves in the box.
func local(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	ip := net.ParseIP(host)
	return err != nil || host == "localhost" || ip != nil && (ip.IsLoopback() || ip.IsUnspecified())
}

// token is a fresh random name the canary accepts as a nonce: lowercase hex behind a one-letter kind.
func token(kind string) string {
	b := make([]byte, 12)
	rand.Read(b)
	return kind + hex.EncodeToString(b)
}

// healthPorts are the TCP ports a two-sided canary check needs covered (SBX-11).
func healthPorts(m obs.Manifest) []int {
	seen := map[int]bool{}
	if m.NoCanary {
		return nil
	}
	for _, id := range m.Selected {
		ck, _ := catalog.Get(id)
		if ck.Canary != nil && ck.Kind == catalog.TwoSided && ck.Canary.Proto == "tcp" {
			seen[ck.Canary.Port] = true
		}
	}
	var ports []int
	for p := range seen {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports
}

// health connects to each port once a second and records, by the host's clock, each connect the canary confirmed.
type health struct {
	mu    sync.Mutex
	at    map[string][]time.Time
	ports []int
	done  chan struct{}
	wg    sync.WaitGroup
}

func startHealth(ctx context.Context, c Canary, ports []int, k canary.Key) *health {
	h := &health{at: map[string][]time.Time{}, ports: ports, done: make(chan struct{})}
	for _, p := range ports {
		key := fmt.Sprintf("tcp/%d", p)
		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
			tick := time.NewTicker(healthEvery)
			defer tick.Stop()
			for {
				if c.Health(ctx, p, k) {
					h.mu.Lock()
					h.at[key] = append(h.at[key], time.Now())
					h.mu.Unlock()
				}
				select {
				case <-h.done:
					return
				case <-ctx.Done():
					return
				case <-tick.C:
				}
			}
		}()
	}
	return h
}

// firstRound waits until every port has one confirmed health connect, so the bracket starts covered. A port the canary
// never confirms leaves its checks unknown: the grader sees the gap.
func (h *health) firstRound(ctx context.Context, limit time.Duration) {
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		h.mu.Lock()
		n := len(h.at)
		h.mu.Unlock()
		if n == len(h.ports) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (h *health) stop() {
	close(h.done)
	h.wg.Wait()
}

func (h *health) times() map[string][]time.Time {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := map[string][]time.Time{}
	for k, v := range h.at {
		out[k] = append([]time.Time(nil), v...)
	}
	return out
}

// planMarks resolves the plan's marker rule (UX-4, TWN-3) against the survey's inventory. Recreate: each volume
// Sandprobe created, at its mount path. Restore: the agent's home and working directory, and every mount the adapter
// declares part of the box. Any other root is never marked. A planned root missing from the inventory (not writable,
// beyond its cap, or unread) keeps no directory identity, so its mark refuses and PER-5 stays unknown rather than
// quietly smaller.
func planMarks(s *obs.Survey, st Storage, runID string) []obs.PlannedMark {
	byPath := map[string]obs.Root{}
	for _, r := range s.Roots {
		byPath[r.Path] = r
	}
	var marks []obs.PlannedMark
	seen := map[string]bool{}
	add := func(root string, v *obs.Volume) {
		if root == "" || seen[root] {
			return
		}
		seen[root] = true
		inv := byPath[root]
		marks = append(marks, obs.PlannedMark{Root: root, Path: filepath.Join(root, obs.MarkerPrefix+runID),
			Dev: inv.Dev, Ino: inv.Ino, Volume: v})
	}
	switch st.Model {
	case "recreate":
		for i := range st.Volumes {
			add(st.Volumes[i].MountPath, &st.Volumes[i])
		}
	case "restore":
		for _, r := range s.Roots {
			if slices.Contains(r.Kinds, "home") || slices.Contains(r.Kinds, "wd") {
				add(r.Path, nil)
			}
		}
		for _, mp := range st.Mounts { // every declared mount, found by the survey or not: never silently fewer
			add(mp, nil)
		}
	}
	return marks
}

// noCanary is HCN-5's absent canary: it answers nothing and connects nowhere, so a run without one sends no traffic
// to any canary and no network negative can rest on it.
type noCanary struct{}

func (noCanary) IP() string                                   { return "" }
func (noCanary) Domain() string                               { return "" }
func (noCanary) Health(context.Context, int, canary.Key) bool { return false }
func (noCanary) Ask(context.Context, canary.Request) (canary.Answer, error) {
	return canary.Answer{}, errors.New("run without a canary (HCN-5)")
}
