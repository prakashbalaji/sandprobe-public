package report

import (
	"maps"
	"slices"
	"strings"

	"sandprobe/internal/catalog"
	"sandprobe/internal/host"
	"sandprobe/internal/obs"
	"sandprobe/recipes"
)

// Category is one of SCR-1's six questions, with a short fixed label for each of its checks and the plain question
// each check asks (SCR-3).
type Category struct {
	Name, Question string
	Checks         []string
	Label          map[string]string
	Ask            map[string]string
}

// Categories is SCR-1, in headline order. Every catalog check is in exactly one (scorecard_test.go).
var Categories = []Category{
	{Name: "Secrets", Question: "Can it read keys and tokens?", Checks: []string{"SEC-1", "SEC-2", "SEC-3", "SEC-5"},
		Label: map[string]string{"SEC-1": "secret-shaped env names", "SEC-2": "other processes' environments",
			"SEC-3": "credential files", "SEC-5": "other processes' memory"},
		Ask: map[string]string{"SEC-1": "Are there secret-looking variables (API keys, tokens, passwords) in the agent's own environment?",
			"SEC-2": "Can the agent open other programs' environment variables, where keys are often passed?",
			"SEC-3": "Can the agent open credential files: .env, cloud and SSH keys, Kubernetes tokens, /etc/shadow?",
			"SEC-5": "Can the agent open other programs' memory?"}},
	{Name: "Exfiltration", Question: "Can data leave the box?",
		Checks: []string{"EGR-1", "EGR-2", "EGR-3", "EGR-4", "EGR-5.22", "EGR-5.80", "EGR-5.8080", "EGR-5.53u", "EGR-6"},
		Label: map[string]string{"EGR-1": "DNS", "EGR-2": "HTTPS", "EGR-3": "HTTPS via proxy", "EGR-4": "TLS interception",
			"EGR-5.22": "TCP 22", "EGR-5.80": "TCP 80", "EGR-5.8080": "TCP 8080", "EGR-5.53u": "UDP 53",
			"EGR-6": "upload-capable hosts"},
		Ask: map[string]string{"EGR-1": "Can a DNS lookup carry data to a server we control?",
			"EGR-2": "Can it send data over HTTPS to a server we control?", "EGR-3": "Can it send data out through the box's web proxy?",
			"EGR-4": "Is its HTTPS traffic intercepted on the way out?", "EGR-5.22": "Can it connect out on port 22 (SSH)?",
			"EGR-5.80": "Can it connect out on port 80 (HTTP)?", "EGR-5.8080": "Can it connect out on port 8080?",
			"EGR-5.53u": "Can it send UDP packets out on port 53?",
			"EGR-6":     "Can it reach upload sites such as GitHub, npm, PyPI or S3?"}},
	{Name: "Containment", Question: "Can it reach past the box to the host?",
		Checks: []string{"AMP-4", "AMP-5", "AMP-6", "AMP-8.sys", "AMP-8.blk"},
		Label: map[string]string{"AMP-4": "control sockets", "AMP-5": "local control daemons", "AMP-6": "vsock to the host",
			"AMP-8.sys": "writable kernel settings", "AMP-8.blk": "readable block devices"},
		Ask: map[string]string{"AMP-4": "Can it use a control socket, such as Docker's, that drives the machine underneath?",
			"AMP-5": "Is a control service (a Docker API or kubelet port) listening where it can reach?",
			"AMP-6": "Can it talk to the host machine over vsock?", "AMP-8.sys": "Can it change the kernel's settings?",
			"AMP-8.blk": "Can it read the machine's disks directly?"}},
	{Name: "Privilege", Question: "Can it become root?", Checks: []string{"AMP-1", "AMP-2", "AMP-3"},
		Label: map[string]string{"AMP-1": "passwordless sudo", "AMP-2": "root or capabilities", "AMP-3": "setuid or file-capability escalation"},
		Ask: map[string]string{"AMP-1": "Can it run sudo without a password?", "AMP-2": "Is it root, or does it hold powerful Linux capabilities now?",
			"AMP-3": "Could running a setuid program, or a file with capabilities, raise its privileges?"}},
	{Name: "Cloud access", Question: "Can it use your cloud identity?", Checks: []string{"SEC-4", "AMP-7"},
		Label: map[string]string{"SEC-4": "cloud metadata credentials", "AMP-7": "Kubernetes API"},
		Ask: map[string]string{"SEC-4": "Can it get cloud credentials from the cloud's metadata service?",
			"AMP-7": "Can it reach the Kubernetes API?"}},
	{Name: "Persistence", Question: "Can it leave something for the next session?",
		Checks: []string{"PER-1", "PER-2", "PER-3", "PER-4", "PER-5"},
		Label: map[string]string{"PER-1": "startup files", "PER-2": "PATH directories", "PER-3": "boot and schedule",
			"PER-4": "package and git config", "PER-5": "storage that survives a reset"},
		Ask: map[string]string{"PER-1": "Can it change startup files such as ~/.bashrc, which run in the next session?",
			"PER-2": "Can it put programs in folders that come first on the PATH?",
			"PER-3": "Can it add cron jobs or services that run at boot or on a schedule?",
			"PER-4": "Can it change package or git settings, git hooks, or SSH authorized keys?",
			"PER-5": "Does anything it writes survive a reset of the box?"}},
}

// CategoryOf finds a check's category.
func CategoryOf(id string) (Category, bool) {
	for _, c := range Categories {
		if c.Ask[id] != "" {
			return c, true
		}
	}
	return Category{}, false
}

// Row is one category's verdict (SCR-2). Why is empty when the row is green; NotProven names the checks a green
// row rests on without a negative proof (KND-2), so a green never reads as more than it is, and GreenNotProven says a
// green row has no conclusive check at all. A not-applicable row is never green and is out of the score.
type Row struct {
	Name           string `json:"name"`
	Question       string `json:"question"`
	Green          bool   `json:"green"`
	GreenNotProven bool   `json:"green_not_proven,omitempty"` // SCR-2: green with Conclusive == 0; still counts toward Score
	NotApplicable  bool   `json:"not_applicable,omitempty"`
	Why            string `json:"why,omitempty"`
	Terms          string `json:"terms,omitempty"` // SCR-2: a not-applicable row's PRV-row reasons, from this binary's own table
	// Scope is the PRV-row key whose reviewed scope made the row not applicable (SCR-2): the run's provider, or the
	// provider a run exec report declares. DeclaredProvider is set only in that second case (PRV-17): the operator's
	// word, never verified.
	Scope            string         `json:"scope,omitempty"`
	DeclaredProvider string         `json:"declared_provider,omitempty"`
	NotProven        string         `json:"not_proven,omitempty"`
	Found            []string       `json:"found,omitempty"`
	Unknown          []string       `json:"unknown,omitempty"`
	Unproven         []string       `json:"unproven,omitempty"`
	Coverage         *CheckCoverage `json:"coverage,omitempty"`
}

// Card is the headline: Score green rows of Of, the categories that apply (SCR-2). An invalid run has no score.
type Card struct {
	Verification string         `json:"verification,omitempty"` // ANL-1: set when the card comes from a saved report
	Valid        bool           `json:"valid"`
	Score        int            `json:"score"`
	Of           int            `json:"of"`
	Rows         []Row          `json:"rows"`
	Coverage     *ScoreCoverage `json:"coverage,omitempty"`
}

// Score is SCR-2. A row is green only when one of its checks was tested, none is unknown, and none has a finding
// above Info. Only the results named below count as clean: anything else, or a check the grade lists as unknown, is
// "couldn't prove". Its reason is built from the fixed labels above, never from a string the box returned. A row is
// not applicable only when the host skipped every one of its checks under a PRV row's reviewed scope, as its manifest
// records and as this binary's own policy for the run's provider derives: a report's word alone never shrinks the
// score. On run exec that provider may be one the operator declared (PRV-17), which the row and the line say.
func Score(d Doc) Card {
	c := Card{Valid: d.Grade.Valid, Of: len(Categories)}
	if !d.Grade.Valid {
		return c
	}
	policy := PolicyFor(d.Run.Provider, d.Manifest.DeclaredProvider)
	scope, declared := scopeOf(d.Run.Provider, d.Manifest.DeclaredProvider)
	got, unknown := map[string]Check{}, map[string]bool{}
	for _, ck := range d.Checks {
		got[ck.ID] = ck
	}
	for _, id := range d.Grade.Unknown {
		unknown[id] = true
	}
	for _, cat := range Categories {
		out := map[string]outcome{}
		for _, id := range cat.Checks {
			ck, ok := got[id]
			switch {
			case unknown[id] || ok && ck.Result == obs.Unknown:
				out[id] = outUnknown
			case !ok: // not in this run at all: says nothing either way
				out[id] = outMissing
			case ck.Result == obs.Skipped: // not run here: says nothing either way, but its kind may explain why
				switch kind := skipKind(d.Manifest, id); {
				case kind == obs.SkipProviderTerms && policy[id] == obs.SkipProviderTerms:
					out[id] = outTerms
				case kind == obs.SkipOptIn:
					out[id] = outOptIn
				default:
					out[id] = outSkipped
				}
			case ck.Result == obs.Pass || ck.Result == obs.Absent || ck.Result == obs.ScopedOut:
				out[id] = outClean
			case ck.Result == obs.NotFound:
				out[id] = outNotFound
			case ck.Result == obs.Finding && ck.Severity == "info":
				out[id] = outInfo
			case ck.Result == obs.Finding:
				out[id] = outFound
			default: // a result the scorecard doesn't know is never clean
				out[id] = outUnknown
			}
		}
		r := buildRow(cat, out, scope, declared, d.Run.NoCanary)
		if r.NotApplicable {
			c.Of--
		}
		if r.Green {
			c.Score++
		}
		c.Rows = append(c.Rows, r)
	}
	attachCoverage(&c, got, unknown)
	return c
}

// skipKind is a skipped check's kind as the host recorded it beside its reason (GRD-3, SCR-2), or "" when it has none.
func skipKind(m obs.Manifest, id string) string {
	if m.Skipped[id] == "" {
		return ""
	}
	return m.SkipKinds[id]
}

// SavedVerification is ANL-1's label on a card computed from a saved report.
const SavedVerification = "structural_only_unauthenticated"

// NotApplicableWhy is SCR-2's fixed reason for a not-applicable row, under SCR-1's narrowed Cloud access contract.
// name is a key of this binary's PRV-row table, never a box string; a declared one (PRV-17) is said to be the
// operator's word.
func NotApplicableWhy(name string, declared bool) string {
	why := "Not applicable: this box holds no cloud identity of yours that Sandprobe checks here; " + ReviewedScope(name)
	if declared {
		why += ". " + DeclaredUnverified(name)
	}
	return why
}

// ReviewedScope is what a provider_terms skip means (SCR-2, PRV-5): Sandprobe's own reviewed scope for that provider,
// never a claim about the provider's published terms. An empty name is a saved card from before the row named it.
func ReviewedScope(name string) string {
	if name == "" {
		return "Sandprobe's reviewed scope for the provider excludes these provider-owned endpoints"
	}
	return "Sandprobe's reviewed scope for " + name + " excludes these provider-owned endpoints"
}

// DeclaredUnverified is PRV-17's statement on every human-readable plan and result that uses a declared provider.
func DeclaredUnverified(name string) string {
	return "The operator declared the provider as " + name + "; Sandprobe did not verify it"
}

// PolicyFor is SCR-2's skip kinds for a report: on a run exec report that declares a provider this binary's table has
// (PRV-17), that entry's checks are provider_terms and the rest of PRV-15's defaults opt_in; on any other report,
// PolicyKinds for its provider. A declared name the table lacks, or one beside another provider, derives nothing new.
func PolicyFor(provider, declared string) map[string]string {
	kinds := PolicyKinds(provider)
	if provider != "exec" {
		return kinds
	}
	for id := range host.DeclaredExclusions(declared) {
		kinds[id] = obs.SkipProviderTerms
	}
	return kinds
}

// scopeOf is the PRV-row key whose reviewed scope a not-applicable row rests on, and whether the operator declared it.
func scopeOf(provider, declared string) (string, bool) {
	if provider == "exec" && host.DeclaredExclusions(declared) != nil {
		return declared, true
	}
	return provider, false
}

// PolicyKinds is SCR-2's skip kinds as this binary's own policy derives them for the provider a run names, never as a
// report states them: a native adapter's PRV-row exclusions are provider_terms (PRV-5); run exec's (PRV-15) and a
// shipped recipe's (RCP-4) default exclusions are opt_in; any other provider has none. PolicyFor adds PRV-17.
func PolicyKinds(provider string) map[string]string {
	kinds := map[string]string{}
	if excluded, ok := host.TermsExclusions[provider]; ok {
		for id := range excluded() {
			kinds[id] = obs.SkipProviderTerms
		}
		return kinds
	}
	var ids []string
	if provider == "exec" {
		ids = slices.Collect(maps.Keys(host.ExecExclusions()))
	} else if text, ok := recipes.Get(provider); ok && recipes.Shipped[provider] != "" {
		if rc, err := host.ParseRecipe(provider, text); err == nil {
			ids = rc.Exclusions
		}
	}
	for _, id := range ids {
		kinds[id] = obs.SkipOptIn
	}
	return kinds
}

// termsReasons is the provider's PRV-row reasons for excluding ids, from this binary's own policy, each said once; ""
// for a name the table lacks, so no caller ever reads a reason the table doesn't hold.
func termsReasons(provider string, ids []string) string {
	excluded := host.DeclaredExclusions(provider)
	if excluded == nil {
		return ""
	}
	var out []string
	for _, id := range ids {
		if why := excluded[id]; !slices.Contains(out, why) {
			out = append(out, why)
		}
	}
	return strings.Join(out, "; ")
}

// NotCounted is SCR-2's line beside the score for each category it leaves out, and why; for a declared provider it
// also says the operator declared it and Sandprobe did not verify it (PRV-17). A name is shown only when it is a key of
// this binary's own PRV-row table, so a card's word never becomes "Sandprobe's reviewed scope".
func (c Card) NotCounted() []string {
	var out []string
	for _, r := range c.Rows {
		if r.NotApplicable {
			scope := r.Scope
			if host.DeclaredExclusions(scope) == nil {
				scope = ""
			}
			line := r.Name + " isn't counted: " + ReviewedScope(scope) + " (" + r.Terms + ")"
			if scope != "" && r.DeclaredProvider == scope {
				line += ". " + DeclaredUnverified(scope) + "."
			}
			out = append(out, line)
		}
	}
	return out
}

// canRed says whether a finding on the check could turn its row red: one with only Info variants never can.
func canRed(id string) bool {
	ck, ok := catalog.Get(id)
	if !ok {
		return true
	}
	for _, v := range ck.Variants {
		if v.Severity > catalog.Info {
			return true
		}
	}
	return false
}

func labels(cat Category, ids []string) string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = cat.Label[id]
	}
	return strings.Join(out, ", ")
}

// allNeedCanary says whether every one of ids is a check a run without a canary can't test (HCN-5).
func allNeedCanary(ids []string) bool {
	for _, id := range ids {
		if ck, ok := catalog.Get(id); !ok || !catalog.NeedsCanary(ck) {
			return false
		}
	}
	return true
}
