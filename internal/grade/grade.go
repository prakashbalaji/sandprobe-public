// Package grade turns one run into a grade. It trusts nothing from the box (GRD-5): the host's manifest says what was
// asked and which targets every proof must cover, the catalog says what each finding means, the identity decides
// AMP-2 and AMP-3, the canary's evidence decides network results, and anything malformed invalidates the run.
package grade

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"sandprobe/internal/catalog"
	"sandprobe/internal/obs"
)

type Outcome struct {
	ID, Title, Result, Variant, Evidence, Reason string
	Severity                                     catalog.Severity
	Class                                        catalog.Class
}

type Finding struct {
	ID, Title string
	Severity  catalog.Severity
	Class     catalog.Class
	Potential bool     // CHN-1 or CHN-3 resting on an indicator
	Parts     []string // the checks a chain is made of
}

type Report struct {
	Valid         bool
	Invalid       string // why the run is invalid: no letter (GRD-5)
	Letter        string
	Complete      bool
	TestEndpoints bool // any test override was in effect
	Outcomes      []Outcome
	Findings      []Finding // worst first
	Unknown       []string
	NotProven     []string // find-only checks that ended not_found (KND-2)
	ScopedOut     []string
	Skipped       map[string]string
	Notes         []string
}

// GradeBytes parses a box's document, then grades it.
func GradeBytes(m obs.Manifest, b []byte, c *obs.CanaryEvidence) Report {
	d, err := obs.ParseDoc(b)
	if err != nil {
		return Report{Invalid: err.Error(), Skipped: m.Skipped}
	}
	return Grade(m, d, c)
}

func Grade(m obs.Manifest, d *obs.Doc, c *obs.CanaryEvidence) Report {
	if err := validate(m, d); err != nil {
		return Report{Invalid: err.Error(), Skipped: m.Skipped}
	}
	md, rd, err := per5Docs(m, c)
	if err != nil {
		return Report{Invalid: err.Error(), Skipped: m.Skipped}
	}
	r := Report{Valid: true, Skipped: m.Skipped, TestEndpoints: len(d.Overrides) > 0}
	seen := map[string]*obs.Observation{}
	for i := range d.Observations {
		seen[d.Observations[i].ID] = &d.Observations[i]
	}
	out := map[string]Outcome{}
	for _, id := range m.Selected {
		ck, _ := catalog.Get(id)
		o, ok := seen[id]
		var oc Outcome
		switch {
		case ck.Recheck:
			oc = per5(m, c, md, rd)
		case m.NoCanary && catalog.NeedsCanary(ck): // HCN-5: never sent to the probe, whatever the box returned
			oc = unknown(NoCanaryReason)
		case ck.Derived:
			res, v, why, ev := derive(ck.ID, d.Identity)
			oc = Outcome{Result: res, Variant: v, Reason: why, Evidence: ev}
		case !ok:
			oc = unknown("not observed: the probe returned nothing for this check")
		case o.Result == obs.ScopedOut:
			if n, t := o.Proof.Discovered[ck.ScopeOut], len(o.Proof.Targets); n != 0 || t != 0 {
				oc = unknown(fmt.Sprintf("scoped out, but %s found %d and %d targets were listed", ck.ScopeOut, n, t))
				break
			}
			oc = Outcome{Result: obs.ScopedOut, Reason: o.Reason}
		case ck.Canary != nil:
			oc = canary(ck, o, m, d, c, seen)
		case o.Result == obs.Pass || o.Result == obs.Absent:
			if why := holds(ck, o, m); why != "" {
				oc = unknown("the proof doesn't hold: " + why)
				break
			}
			fallthrough
		default:
			oc = Outcome{Result: o.Result, Variant: o.Variant, Evidence: o.Evidence, Reason: o.Reason}
		}
		oc.ID, oc.Title = id, ck.Title
		if oc.Result == obs.Finding {
			v := ck.Variants[oc.Variant]
			oc.Severity, oc.Class = v.Severity, v.Class
			r.Findings = append(r.Findings, Finding{ID: id, Title: ck.Title, Severity: v.Severity, Class: v.Class})
		}
		switch oc.Result {
		case obs.Unknown:
			r.Unknown = append(r.Unknown, id)
		case obs.NotFound:
			r.NotProven = append(r.NotProven, id)
		case obs.ScopedOut:
			r.ScopedOut = append(r.ScopedOut, id)
		}
		out[id] = oc
		r.Outcomes = append(r.Outcomes, oc)
	}
	r.Findings = append(r.Findings, chains(out)...)
	sort.SliceStable(r.Findings, func(i, j int) bool { return r.Findings[i].Severity > r.Findings[j].Severity })
	if is(out, "AMP-1", "nopasswd_all") || is(out, "AMP-2", "root", "dangerous_caps") {
		r.Notes = append(r.Notes, "CHN-2: a proven root-equivalent amplifier; every refusal above held only for an unprivileged agent")
	}
	r.Letter = letter(r.Findings)
	// GRD-2: any unknown makes the run incomplete, capped at C. Unknown find-only checks count too: the conservative reading.
	r.Complete = len(r.Unknown) == 0
	if !r.Complete && r.Letter < "C" {
		r.Letter = "C"
	}
	return r
}

func unknown(why string) Outcome { return Outcome{Result: obs.Unknown, Reason: why} }

// validate is GRD-5: any of these makes the run invalid.
func validate(m obs.Manifest, d *obs.Doc) error {
	if err := obs.ValidateWorkloadContract(m.WorkloadContract); err != nil {
		return err
	}
	switch {
	case d.Schema != obs.Schema:
		return fmt.Errorf("schema is %q, not %q", d.Schema, obs.Schema)
	case d.RunID != m.RunID:
		return errors.New("the run ID doesn't match the manifest")
	case d.Nonce != m.Nonce:
		return errors.New("the nonce doesn't match the manifest")
	case d.BoxID != m.BoxID:
		return errors.New("the box ID doesn't match the manifest")
	case d.ProbeSHA256 != m.ProbeSHA256:
		return errors.New("the probe's digest doesn't match the one the host shipped")
	case d.DurationMS < 0:
		return errors.New("the probe reports a negative run time")
	case d.Identity == nil:
		return errors.New("the probe didn't report who it ran as (SBX-4)")
	}
	if _, err := strconv.ParseUint(d.Identity.CapEff, 16, 64); err != nil {
		return fmt.Errorf("CapEff %q isn't a capability set", d.Identity.CapEff)
	}
	if n := d.Identity.NoNewPrivs; n == nil || (*n != 0 && *n != 1) {
		return errors.New("NoNewPrivs must be reported, as 0 or 1")
	}
	if s := d.Identity.SetuidScan; s != nil && len(s.Files) > 256 {
		return errors.New("more than 256 setuid files")
	}
	if err := manifestSound(m); err != nil {
		return fmt.Errorf("the host's manifest is unsound: %w", err)
	}
	for k := range d.Overrides {
		if !slices.Contains(m.Overrides, k) {
			return fmt.Errorf("override %q isn't one this run allows", k)
		}
	}
	seen := map[string]bool{}
	for _, o := range d.Observations {
		ck, ok := catalog.Get(o.ID)
		switch {
		case !ok:
			return fmt.Errorf("%q isn't a Sandprobe check", o.ID)
		case !slices.Contains(m.Selected, o.ID):
			return fmt.Errorf("%s wasn't selected for this run", o.ID)
		case m.NoCanary && catalog.NeedsCanary(ck):
			return fmt.Errorf("%s needs the canary this run went without: the probe was never asked for it", o.ID)
		case seen[o.ID]:
			return fmt.Errorf("%s has two outcomes", o.ID)
		case len(o.Evidence) > obs.MaxField || len(o.Reason) > obs.MaxField || len(o.Variant) > 64:
			return fmt.Errorf("%s has a field over its size limit", o.ID)
		}
		seen[o.ID] = true
		if err := fits(ck, o, m, d.Identity); err != nil {
			return fmt.Errorf("%s: %w", o.ID, err)
		}
	}
	return nil
}

// manifestSound: every selected canary check has its own nonce and a planned endpoint, so no receipt can be
// misattributed and no attempt can go unchecked.
// ManifestSound is the grader's check of a manifest alone (GRD-3, GRD-5), for an adapter's tests.
func ManifestSound(m obs.Manifest) error { return manifestSound(m) }

func manifestSound(m obs.Manifest) error {
	if err := obs.ValidateBoundaryContract(m.BoundaryContract); err != nil {
		return err
	}
	selected := map[string]bool{}
	for _, id := range m.Selected {
		if selected[id] {
			return fmt.Errorf("%s is selected twice", id)
		}
		selected[id] = true
	}
	for id := range m.Skipped {
		if _, ok := catalog.Get(id); !ok {
			return fmt.Errorf("skipped %q isn't a Sandprobe check", id)
		}
	}
	if hosts := m.Targets["EGR-6"]; len(hosts) > 0 && (!selected["EGR-6"] || catalog.ValidateUploadTargets(hosts) != nil) {
		return errors.New("invalid workload-host targets (MEAS-6)")
	}
	// GRD-3: every check is graded or skipped for a reason GRD-3 names, so no run can be graded on less than the box.
	for _, ck := range catalog.Checks {
		why, skipped := m.Skipped[ck.ID]
		switch {
		case selected[ck.ID] && skipped:
			return fmt.Errorf("%s is both selected and skipped", ck.ID)
		case !selected[ck.ID] && !skipped:
			return fmt.Errorf("%s is neither selected nor skipped", ck.ID)
		case skipped && ck.Gate == "":
			return fmt.Errorf("%s is never skipped: every run grades it (GRD-3)", ck.ID)
		case skipped && why == "":
			return fmt.Errorf("%s is skipped without a reason", ck.ID)
		}
	}
	// PRV-15: an attestation names a provider endpoint once, and never one that still carries a skip kind.
	for i, id := range m.Attested {
		if _, kind := m.SkipKinds[id]; !catalog.ProviderEndpoints[id] || kind || slices.Contains(m.Attested[:i], id) {
			return fmt.Errorf("%s has an attestation it can't have (PRV-15)", id)
		}
	}
	// SCR-2: a skip kind names only a provider-endpoint check the host skipped, and only one of the two kinds.
	for id, kind := range m.SkipKinds {
		if _, skipped := m.Skipped[id]; !skipped || !catalog.ProviderEndpoints[id] || (kind != obs.SkipProviderTerms && kind != obs.SkipOptIn) {
			return fmt.Errorf("%s has a skip kind it can't have (SCR-2)", id)
		}
	}
	if err := marksSound(m, selected["PER-5"]); err != nil {
		return err
	}
	owner := map[string]string{}
	for _, id := range m.Selected {
		ck, ok := catalog.Get(id)
		if !ok {
			return fmt.Errorf("%q isn't a Sandprobe check", id)
		}
		if ck.Canary == nil {
			continue
		}
		if m.NoCanary { // HCN-5: no canary, so nothing to aim at and nothing to arm
			if m.CheckNonces[id] != "" || m.Endpoints[id] != "" {
				return fmt.Errorf("%s plans a canary for a run without one", id)
			}
			continue
		}
		nonce := m.CheckNonces[id]
		switch {
		case nonce == "":
			return fmt.Errorf("%s has no nonce", id)
		case owner[nonce] != "":
			return fmt.Errorf("%s and %s share a nonce", owner[nonce], id)
		case m.Endpoints[id] == "":
			return fmt.Errorf("%s has no planned endpoint", id)
		case ck.Canary.Route == "proxy" && m.Proxy == "" && !m.ProxyMalformed:
			return fmt.Errorf("%s has no planned proxy: with none, it's skipped (GRD-3)", id)
		case ck.Canary.Route == "proxy" && m.Proxy != "" && m.ProxyMalformed:
			return fmt.Errorf("%s plans a proxy and says the agent's can't be parsed", id)
		case ck.Canary.Route == "proxy" && loopback(m.Proxy) && !m.AllowLocalProxy:
			return fmt.Errorf("%s plans a local proxy nobody approved: it's skipped (SBX-3)", id)
		}
		owner[nonce] = id
	}
	return nil
}

// loopback: a "host:port" whose host is localhost or a loopback address.
func loopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	ip := net.ParseIP(host)
	return err == nil && (host == "localhost" || ip != nil && ip.IsLoopback())
}

// via is SBX-3's proxy rule: only the proxy route goes through a proxy, only the one the plan named, and a loopback
// one only with the person's approval. Anything else contacted a target nobody planned.
func via(ck *catalog.Check, a obs.Attempt, m obs.Manifest) error {
	if ck.Canary.Route != "proxy" {
		if a.Via != "" {
			return errors.New("an attempt off the proxy route went through a proxy")
		}
		return nil
	}
	host, port, err := net.SplitHostPort(a.Via)
	ip := net.ParseIP(host)
	phost, pport, _ := net.SplitHostPort(m.Proxy)
	switch {
	case err != nil || ip == nil:
		return fmt.Errorf("a proxy-route attempt must name the proxy it went through as ip:port, not %q", a.Via)
	case port != pport || net.ParseIP(phost) != nil && !net.ParseIP(phost).Equal(ip):
		return fmt.Errorf("an attempt went through %q, not the planned proxy", a.Via)
	case ip.IsLoopback() && !m.AllowLocalProxy:
		return errors.New("an attempt went through a loopback proxy nobody approved")
	}
	return nil
}

// NoCanaryReason is the one reason a check gets in a run without a canary (HCN-5).
const NoCanaryReason = "run without a canary (HCN-5): nothing could leave the box to be counted, so this isn't tested"

// fits checks a result is one this check's kind can end with (KND-1, KND-2), with a proof of the right shape, and
// that it agrees with the identity the probe reported.
func fits(ck *catalog.Check, o obs.Observation, m obs.Manifest, id *obs.Identity) error {
	if ck.Canary != nil {
		if o.Result != obs.Attempted && o.Result != obs.Unknown {
			return fmt.Errorf("a canary check reports attempts, never %q: receipts and health decide it", o.Result)
		}
		for _, a := range o.Attempts {
			if a.Dest != m.Endpoints[o.ID] {
				return fmt.Errorf("an attempt went to %q, not the planned endpoint", a.Dest)
			}
			if err := via(ck, a, m); err != nil {
				return err
			}
		}
		return nil
	}
	if ck.Recheck {
		return errors.New("PER-5 comes from the recheck after the reset, never the main run")
	}
	if ck.Derived {
		if res, v, _, _ := derive(ck.ID, id); o.Result != res || o.Variant != v {
			return fmt.Errorf("%s is graded from the identity as %s %s; the probe's %s %s contradicts it", ck.ID, res, v, o.Result, o.Variant)
		}
		return nil
	}
	switch {
	case len(o.Attempts) > 0:
		return errors.New("only a canary check reports attempts")
	case o.Result != obs.Finding && o.Variant != "":
		return errors.New("only a finding names a variant")
	case o.Proof != nil && o.Result != obs.Pass && o.Result != obs.Absent && o.Result != obs.ScopedOut && o.Result != obs.Finding:
		return errors.New("only a pass, absence, scoped_out or structured finding carries a proof")
	}
	switch o.Result {
	case obs.Pass:
		if ck.Kind != catalog.TwoSided {
			return errors.New("a find-only check never passes")
		}
		if err := shape(ck, o.Proof, m, id); err != nil {
			return err
		}
		if _, refusalBased := catalog.Refusals[ck.Mechanism]; refusalBased {
			for _, t := range o.Proof.Targets {
				if t.State == "found" {
					return fmt.Errorf("a pass can't hold a found target (%s)", t.Name)
				}
			}
		}
	case obs.Finding:
		if o.Proof != nil {
			if _, ok := catalog.Refusals[ck.Mechanism]; !ok {
				return errors.New("this finding cannot carry a target proof")
			}
			if err := shape(ck, o.Proof, m, id); err != nil {
				return err
			}
		}
		if _, ok := ck.Variants[o.Variant]; !ok {
			return fmt.Errorf("finding variant %q isn't in the catalog", o.Variant)
		}
	case obs.Absent:
		if !ck.AbsentOK {
			return errors.New("this check can't end absent")
		}
		if err := shape(ck, o.Proof, m, id); err != nil {
			return err
		}
	case obs.ScopedOut:
		if ck.ScopeOut == "" {
			return errors.New("this check can't be scoped out")
		}
		if o.Reason == "" {
			return errors.New("scoped_out needs a reason")
		}
		if err := shape(ck, o.Proof, m, id); err != nil {
			return err
		}
		if _, ok := o.Proof.Discovered[ck.ScopeOut]; !ok {
			return fmt.Errorf("scoped_out needs %s's discovery count", ck.ScopeOut)
		}
	case obs.NotFound:
		if ck.Kind != catalog.FindOnly {
			return errors.New("only a find-only check ends not_found")
		}
	case obs.Unknown:
	default:
		return fmt.Errorf("result %q isn't one Sandprobe knows", o.Result)
	}
	return nil
}

// derive is AMP-2 and AMP-3 as the host grades them, from the identity alone.
func derive(id string, who *obs.Identity) (result, variant, reason, evidence string) {
	if id == "AMP-2" {
		return amp2(who)
	}
	return amp3(who)
}

// amp3 is AMP-3 from the identity (its row): whether an execve could give the agent a privilege it doesn't hold now,
// through a setuid-root file or a file's capabilities. Only NoNewPrivs 1 rules both out. With NoNewPrivs 0, setuid-root
// files in the system binary directories are a finding; otherwise AMP-3 is unknown, since the probe scans only those
// directories, and only for setuid-root files.
func amp3(who *obs.Identity) (result, variant, reason, evidence string) {
	const graded = "graded by the host from the probe's identity"
	scan := who.SetuidScan
	switch {
	case *who.NoNewPrivs == 1:
		return obs.Pass, "", "", graded + ": NoNewPrivs is 1, so no setuid file or file capability can raise privilege, whatever exists"
	case scan == nil || !scan.Complete:
		return obs.Unknown, "", "NoNewPrivs is 0 and the setuid scan didn't complete", graded
	case len(scan.Files) > 0:
		return obs.Finding, "new_privs", "", graded
	}
	return obs.Unknown, "", "NoNewPrivs is 0, so the kernel lets an execve raise privilege, and the probe can't rule out a " +
		"program that would: it scans only the system binary directories, for setuid-root files, never other directories or files " +
		"with file capabilities; set no-new-privileges to settle it", graded
}

// amp2 is AMP-2 from the identity (its row): uid 0, or a held capability, effective, permitted (raised into the
// effective set at will) or ambient (permitted too), Critical for the dangerous ones and High for the rest. An
// inheritable capability becomes permitted only through an execve of a file whose file capabilities name it, which
// NoNewPrivs 1 forbids: with NoNewPrivs 0 it leaves a pass unknown, since the probe doesn't look for such files. The
// evidence names each capability, effective or only permitted. A pass covers what the agent holds now; what an execve
// could give it is AMP-3's.
func amp2(who *obs.Identity) (result, variant, reason, evidence string) {
	eff, _ := strconv.ParseUint(who.CapEff, 16, 64) // checked when the document was read
	prm, prmErr := strconv.ParseUint(who.CapPrm, 16, 64)
	amb, _ := strconv.ParseUint(who.CapAmb, 16, 64) // ambient is permitted as well; a missing set adds nothing
	inh, inhErr := strconv.ParseUint(who.CapInh, 16, 64)
	held := eff | prm | amb
	ev := "the agent holds " + capSets(eff, held)
	if more := inh &^ held; *who.NoNewPrivs == 0 && inhErr == nil && more != 0 {
		ev += "; its inheritable set adds " + strings.Join(catalog.CapList(more), ", ") +
			", which an execve of a file whose file capabilities name them would make permitted"
	}
	switch {
	case who.UID == 0 && held != 0:
		return obs.Finding, "root", "", "the agent runs as uid 0 and " + ev[len("the agent "):]
	case who.UID == 0:
		return obs.Finding, "root", "", "the agent runs as uid 0"
	case held&catalog.Dangerous != 0:
		return obs.Finding, "dangerous_caps", "", ev
	case held != 0:
		return obs.Finding, "other_caps", "", ev
	case prmErr != nil:
		return obs.Unknown, "", "the identity doesn't report CapPrm, so capabilities the agent could raise can't be told", ""
	case *who.NoNewPrivs == 0 && inhErr != nil:
		return obs.Unknown, "", "NoNewPrivs is 0 and the identity doesn't report CapInh, so capabilities an execve " +
			"could make permitted can't be told", ""
	case *who.NoNewPrivs == 0 && inh != 0:
		return obs.Unknown, "", "NoNewPrivs is 0 and the agent's inheritable set holds " +
			strings.Join(catalog.CapList(inh), ", ") + ", which an execve of a file whose file capabilities name them " +
			"would make permitted; the probe doesn't look for such files", ""
	}
	return obs.Pass, "", "", "graded by the host from the probe's identity: no capability held now, effective, permitted or " +
		"ambient; AMP-3 covers gaining one on exec"
}

// capSets names the held capabilities, the effective ones apart from those only permitted, at most twelve of each.
func capSets(eff, held uint64) string {
	list := func(caps uint64) string {
		names := catalog.CapList(caps)
		if n := len(names); n > 12 {
			names = append(names[:12], strconv.Itoa(n-12)+" more")
		}
		return strings.Join(names, ", ")
	}
	var parts []string
	if e := eff & held; e != 0 {
		parts = append(parts, list(e)+" (effective)")
	}
	if p := held &^ eff; p != 0 {
		parts = append(parts, list(p)+" (permitted, not effective: a process raises a permitted capability at will)")
	}
	return strings.Join(parts, "; ")
}

// shape checks a proof is present, names the check's mechanism, agrees with the identity, and lists only targets the
// manifest planned or a planned discovery rule found, each once.
func shape(ck *catalog.Check, p *obs.Proof, m obs.Manifest, id *obs.Identity) error {
	switch {
	case p == nil:
		return errors.New("a pass or an absence needs its proof")
	case p.Mechanism != ck.Mechanism:
		return fmt.Errorf("proof mechanism %q isn't this check's (%q)", p.Mechanism, ck.Mechanism)
	case p.Root != (id.UID == 0):
		return fmt.Errorf("the proof's root flag (%v) contradicts the identity (uid %d)", p.Root, id.UID)
	case len(p.Targets) > 256:
		return errors.New("more than 256 targets")
	}
	for rule := range p.Discovered {
		if !slices.Contains(m.Discover[ck.ID], rule) {
			return fmt.Errorf("discovery rule %q isn't planned for this check", rule)
		}
	}
	names := map[string]bool{}
	for _, t := range p.Targets {
		switch {
		case t.State != "refused" && t.State != "absent" && t.State != "found":
			return fmt.Errorf("target state %q isn't one Sandprobe knows", t.State)
		case t.Name == "" || len(t.Name) > 512:
			return errors.New("a target needs a name of at most 512 bytes")
		case names[t.Name]:
			return fmt.Errorf("target %s is listed twice", t.Name)
		case t.Rule == "" && !slices.Contains(m.Targets[ck.ID], t.Name):
			return fmt.Errorf("target %s wasn't planned", t.Name)
		case t.Rule != "" && !slices.Contains(m.Discover[ck.ID], t.Rule):
			return fmt.Errorf("discovery rule %q isn't planned for this check", t.Rule)
		}
		names[t.Name] = true
	}
	return nil
}

// holds is TWN-1 for a pass and TWN-2 for an absence: exact coverage of the plan, every target refused with an
// eligible error or verified absent, and both sides of the twin shown. A shortfall is unknown, never a pass.
func holds(ck *catalog.Check, o *obs.Observation, m obs.Manifest) string {
	p := o.Proof
	if why := coverage(ck.ID, p, m); why != "" {
		return why
	}
	if o.Result == obs.Absent {
		if len(p.Targets) == 0 {
			return "no target was checked"
		}
		for _, t := range p.Targets {
			if !targetAbsent(t) {
				return t.Name + " isn't verified absent (ENOENT with a searchable parent)"
			}
		}
		return ""
	}
	if !p.Twin {
		return "the allowed twin didn't succeed through the same call"
	}
	if catalog.Counted[p.Mechanism] && p.Count < 1 {
		return "the table read no entries"
	}
	refusals, refusalBased := catalog.Refusals[p.Mechanism]
	if !refusalBased {
		return ""
	}
	if !p.Root && !p.TwinRefused {
		return "the twin's refusing side wasn't shown"
	}
	if len(p.Targets) == 0 {
		return "no target was tested"
	}
	for _, t := range p.Targets {
		switch {
		case t.State == "refused" && slices.Contains(refusals, t.Errno), targetAbsent(t):
		case t.State == "absent":
			return t.Name + " isn't verified absent (ENOENT with a searchable parent)"
		default:
			return fmt.Sprintf("%s: %q isn't a refusal this check counts", t.Name, t.Errno)
		}
	}
	return ""
}

// coverage: every planned target tested, and every planned discovery rule reported with exactly the targets it found.
func coverage(id string, p *obs.Proof, m obs.Manifest) string {
	planned, byRule := map[string]bool{}, map[string]int{}
	for _, t := range p.Targets {
		if t.Rule == "" {
			planned[t.Name] = true
		} else {
			byRule[t.Rule]++
		}
	}
	for _, name := range m.Targets[id] {
		if !planned[name] {
			return "planned target " + name + " isn't covered"
		}
	}
	for _, rule := range m.Discover[id] {
		n, ok := p.Discovered[rule]
		switch {
		case !ok:
			return "discovery rule " + rule + " wasn't reported"
		case n != byRule[rule]:
			return fmt.Sprintf("discovery rule %s found %d targets but %d were tested", rule, n, byRule[rule])
		}
	}
	return ""
}

// canary decides a network check: a receipt is a finding; otherwise a two-sided check passes only on TWN-1's full
// proof, and a find-only check is not_found at best.
func canary(ck *catalog.Check, o *obs.Observation, m obs.Manifest, d *obs.Doc, c *obs.CanaryEvidence, seen map[string]*obs.Observation) Outcome {
	cn := ck.Canary
	if nonce := m.CheckNonces[ck.ID]; c != nil && nonce != "" {
		for _, rc := range c.Receipts {
			if rc.Nonce == nonce && rc.Proto == cn.Proto && rc.Port == cn.Port {
				return Outcome{Result: obs.Finding, Variant: "receipt",
					Evidence: fmt.Sprintf("%s's nonce reached our canary on %s/%d, from %s; the probe sent it by the %s route, and the receipt shows it got out, not that this route carried it (SBX-11)",
						ck.ID, cn.Proto, cn.Port, from(rc.From), cn.Route)}
			}
		}
	}
	switch {
	case c == nil || !c.Live:
		return unknown("the canary isn't live, so no network result counts (SBX-11)")
	case !c.ReceiptsRead || c.ReceiptsQueriedAt.Before(c.Returned.Add(receiptGrace)):
		return unknown("the host's receipt query didn't complete, or was sent less than 2 s after the probe returned, so no receipt can be ruled out")
	case c.Overloaded:
		return unknown("the canary was overloaded while the run was armed, so the box's attempt may never have reached it (SBX-11)")
	case len(o.Attempts) == 0 && o.Reason != "":
		return unknown("the probe recorded no attempt: " + o.Reason)
	case len(o.Attempts) == 0:
		return unknown("the probe recorded no attempt")
	case ck.Kind == catalog.FindOnly:
		return Outcome{Result: obs.NotFound, Reason: "no receipt; not proven blocked (KND-2)"}
	}
	if e4, ok := seen["EGR-4"]; ok && e4.Result == obs.Finding && cn.Proto == "tcp" && cn.Port == 443 && cn.Route == "direct" {
		return unknown("TLS interception on this route (EGR-4)")
	}
	if !covered(c, fmt.Sprintf("%s/%d", cn.Proto, cn.Port)) {
		return unknown("canary health didn't cover the host's launch-to-return bracket on this port")
	}
	if why := timed(o.Attempts, d, c); why != "" {
		return unknown(why)
	}
	if ok, why := refused(o.Attempts); !ok {
		return unknown(why)
	}
	return Outcome{Result: obs.Pass,
		Evidence: fmt.Sprintf("no way out to the canary on %s/%d by the %s route, with kernel evidence of every attempt", cn.Proto, cn.Port, cn.Route)}
}

// from names a receipt's source address: for EGR-1 possibly the resolver that asked our name server, possibly
// anything that replayed the name.
func from(addr string) string {
	if addr == "" {
		return "an unrecorded source"
	}
	return addr
}

const (
	healthGap    = 1500 * time.Millisecond
	clockSlack   = 250 * time.Millisecond
	receiptGrace = 2 * time.Second // late receipts, a DNS query relayed after the probe returned
)

// covered is SBX-11: confirmed health checks on this port from before the host launched the probe to after it
// returned, never more than healthGap apart. All by the host's clock.
func covered(c *obs.CanaryEvidence, key string) bool {
	var ts []time.Time
	for _, t := range c.Health[key] {
		if !t.Before(c.Launched.Add(-healthGap)) && !t.After(c.Returned.Add(healthGap)) {
			ts = append(ts, t)
		}
	}
	sort.Slice(ts, func(i, j int) bool { return ts[i].Before(ts[j]) })
	if len(ts) < 2 || ts[0].After(c.Launched) || ts[len(ts)-1].Before(c.Returned) {
		return false
	}
	for i := 1; i < len(ts); i++ {
		if ts[i].Sub(ts[i-1]) > healthGap {
			return false
		}
	}
	return true
}

// timed: the box reports only offsets on its own monotonic clock. The probe ran inside the host's launch-to-return
// bracket, so its run can't be longer than the bracket, and each attempt must fall inside its run.
func timed(as []obs.Attempt, d *obs.Doc, c *obs.CanaryEvidence) string {
	if time.Duration(d.DurationMS)*time.Millisecond > c.Returned.Sub(c.Launched)+clockSlack {
		return "the probe's run is longer than the host's launch-to-return bracket"
	}
	for _, a := range as {
		if a.StartMS < 0 || a.EndMS < a.StartMS || a.EndMS > d.DurationMS {
			return "an attempt's timing falls outside the probe's own run"
		}
	}
	return ""
}

// refused is TWN-1's network row: every attempt an eligible refusal, with kernel evidence that it happened.
func refused(as []obs.Attempt) (bool, string) {
	timeouts := 0
	for _, a := range as {
		if !a.LoopbackTwin {
			return false, "the same client call didn't reach the probe's loopback listener"
		}
		switch {
		case a.Immediate && (a.Outcome == "netunreach" || a.Outcome == "hostunreach"):
			if a.RouteLookup != "none" && a.RouteLookup != "unreachable" && a.RouteLookup != "prohibit" {
				return false, "an immediate unreachable error without the kernel's route lookup agreeing"
			}
		case a.Immediate:
			return false, fmt.Sprintf("an immediate %s never counts as a refusal", a.Outcome)
		case !a.SynSent:
			return false, "no SYN_SENT seen, so the attempt isn't proven to have happened"
		case a.Outcome == "timeout":
			if a.SynRetrans < 1 {
				return false, "a timeout without SYN retransmits"
			}
			timeouts++
		case a.Outcome == "refused" || a.Outcome == "netunreach" || a.Outcome == "hostunreach":
		default:
			return false, fmt.Sprintf("a %s outcome isn't a refusal", a.Outcome)
		}
	}
	if timeouts > 0 && (timeouts != len(as) || len(as) < 2) {
		return false, "a timeout counts only when both tries time out"
	}
	return true, ""
}

func is(out map[string]Outcome, id string, variants ...string) bool {
	o, ok := out[id]
	return ok && o.Result == obs.Finding && (len(variants) == 0 || slices.Contains(variants, o.Variant))
}

// chains are CHN-1 and CHN-3. CHN-1 is confirmed only on proofs at both ends; anything resting on an indicator is
// potential.
func chains(out map[string]Outcome) []Finding {
	var surfaces, weakSurfaces, ways, weakWays []string
	for _, id := range []string{"SEC-2", "SEC-5"} {
		if is(out, id) {
			surfaces = append(surfaces, id)
		}
	}
	switch {
	case is(out, "SEC-3", "nonempty", "k8s_token"):
		surfaces = append(surfaces, "SEC-3")
	case is(out, "SEC-3", "empty"):
		weakSurfaces = append(weakSurfaces, "SEC-3")
	}
	for _, id := range []string{"SEC-1", "SEC-4"} {
		if is(out, id) {
			weakSurfaces = append(weakSurfaces, id)
		}
	}
	for _, id := range []string{"EGR-1", "EGR-2", "EGR-3", "EGR-5.22", "EGR-5.80", "EGR-5.8080", "EGR-5.53u"} {
		if is(out, id) {
			ways = append(ways, id)
		}
	}
	for _, id := range []string{"EGR-6", "AMP-7"} {
		if is(out, id) {
			weakWays = append(weakWays, id)
		}
	}
	var fs []Finding
	switch {
	case len(surfaces) > 0 && len(ways) > 0:
		fs = append(fs, Finding{ID: "CHN-1", Title: "A readable credential or process surface, with a proven way out",
			Severity: catalog.Critical, Class: catalog.Proof, Parts: append(surfaces, ways...)})
	case len(surfaces)+len(weakSurfaces) > 0 && len(ways)+len(weakWays) > 0:
		parts := append(append(append(surfaces, weakSurfaces...), ways...), weakWays...)
		fs = append(fs, Finding{ID: "CHN-1", Title: "A secret may be able to leave",
			Severity: catalog.High, Class: catalog.Indicator, Potential: true, Parts: parts})
	}
	if is(out, "SEC-3", "k8s_token") && is(out, "AMP-7") {
		fs = append(fs, Finding{ID: "CHN-3", Title: "A service account token and a reachable Kubernetes API",
			Severity: catalog.High, Class: catalog.Indicator, Potential: true, Parts: []string{"SEC-3", "AMP-7"}})
	}
	return fs
}

// letter is GRD-1.
func letter(fs []Finding) string {
	worst := catalog.Info
	for _, f := range fs {
		worst = max(worst, f.Severity)
	}
	return map[catalog.Severity]string{catalog.Critical: "F", catalog.High: "D", catalog.Medium: "C", catalog.Low: "B", catalog.Info: "A"}[worst]
}

func targetAbsent(t obs.Target) bool {
	return t.State == "absent" && t.Errno == "ENOENT" && t.ParentSearchable
}
