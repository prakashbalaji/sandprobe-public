package host

import (
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"

	"sandprobe/internal/obs"
)

// ModalGate is POC-5's gate on the canary's counts for one setup's own nonces: the run's check nonces and, in
// domain-one, the twin's. It returns the rule that tripped, or "" when every count is one the setup allows. The
// canary keeps no other nonces, and host health is never a receipt.
func ModalGate(setup, twin string, receipts []obs.Receipt, elsewhere map[string]uint64) string {
	if setup == "default" {
		return ""
	}
	strays := make([]string, 0, len(elsewhere))
	for n, k := range elsewhere {
		if k > 0 {
			strays = append(strays, n)
		}
	}
	sort.Strings(strays)
	if len(strays) > 0 { // a nonce on a port it wasn't armed for: the canary can't say which, so never allowed
		return fmt.Sprintf("%s: nonce %s counted on a protocol or port it wasn't sent for", setup, strays[0])
	}
	for _, r := range receipts {
		dns := r.Port == 53 && (r.Proto == "dns" || r.Proto == "udp") // "dns": through a resolver (EGR-1); "udp": straight to the canary (EGR-5)
		switch setup {
		case "block", "block-vm":
			return fmt.Sprintf("%s: nonce %s reached the canary on %s/%d with all outbound traffic blocked", setup, r.Nonce, r.Proto, r.Port)
		case "domain-empty":
			if !dns {
				return fmt.Sprintf("%s: nonce %s reached the canary on %s/%d through an empty domain allowlist", setup, r.Nonce, r.Proto, r.Port)
			}
		case "domain-one":
			if !dns && !(r.Nonce == twin && r.Proto == "tcp" && r.Port == 443) {
				return fmt.Sprintf("%s: nonce %s reached the canary on %s/%d, not the allowlist's one name", setup, r.Nonce, r.Proto, r.Port)
			}
		case "sidecar":
			if r.Proto == "tcp" && r.Port != 443 {
				return fmt.Sprintf("%s: nonce %s reached the canary on tcp/%d past an empty CIDR allowlist", setup, r.Nonce, r.Port)
			}
		default:
			return "no gate for setup " + setup
		}
	}
	return ""
}

// RelayLine is one line of the sidecar relay's log (POC-6).
type RelayLine struct {
	T        string `json:"t"`
	Ev       string `json:"ev"`
	Conn     uint64 `json:"conn,omitempty"`
	Nonce    string `json:"nonce,omitempty"`
	Up       int64  `json:"up,omitempty"`
	Down     int64  `json:"down,omitempty"`
	Outcome  string `json:"outcome,omitempty"`
	HelloLen int    `json:"hello_len,omitempty"`
	Listen   string `json:"listen,omitempty"`
}

// RelayLog is the relay's whole log, read after the probe's receipt wait. Complete means it parsed line by line,
// begins with the relay's ready line, and every accepted connection has its end; Relayed is each nonce with an
// accept and an end, bytes both ways and the outcome relayed.
type RelayLog struct {
	Lines    []RelayLine
	Complete bool
	Why      string // why it isn't complete
	Relayed  map[string]bool
	Refused  int
}

// ParseRelayLog reads the relay's log.
func ParseRelayLog(b []byte) RelayLog {
	l := RelayLog{Relayed: map[string]bool{}}
	text := strings.TrimSpace(string(b))
	if text == "" {
		l.Why = "the relay's log is empty"
		return l
	}
	open := map[uint64]string{}
	for i, s := range strings.Split(text, "\n") {
		var x RelayLine
		if err := json.Unmarshal([]byte(s), &x); err != nil {
			l.Why = fmt.Sprintf("line %d doesn't parse: the log may be truncated", i+1)
			return l
		}
		if i == 0 && x.Ev != "ready" {
			l.Why = "the log doesn't begin with the relay's ready line"
			return l
		}
		l.Lines = append(l.Lines, x)
		switch x.Ev {
		case "accept":
			open[x.Conn] = x.Nonce
		case "end":
			if open[x.Conn] != x.Nonce {
				l.Why = fmt.Sprintf("connection %d ended without its accept", x.Conn)
				return l
			}
			delete(open, x.Conn)
			if x.Outcome == "relayed" && x.Up > 0 && x.Down > 0 {
				l.Relayed[x.Nonce] = true
			}
		case "refused":
			l.Refused++
		}
	}
	if len(open) > 0 {
		l.Why = fmt.Sprintf("%d accepted connections have no end line", len(open))
		return l
	}
	l.Complete = true
	return l
}

// RelayGate is POC-5's second sidecar gate, once the relay's log is read in full. A TCP 443 count for a nonce a
// complete log shows no relay of trips it; a log that isn't complete leaves the sidecar's attribution unknown, and
// the setup ends there, before look.
func RelayGate(receipts []obs.Receipt, l RelayLog) (trip, unknown string) {
	if !l.Complete {
		return "", l.Why
	}
	for _, r := range receipts {
		if r.Proto == "tcp" && r.Port == 443 && !l.Relayed[r.Nonce] {
			return fmt.Sprintf("sidecar: nonce %s reached the canary on tcp/443 with no relay of it in the sidecar's complete log", r.Nonce), ""
		}
	}
	return "", ""
}

// ModalUnsound is why a run's canary evidence can't clear POC-5's gate, or "": an empty receipt list means nothing
// unless the run was live, the receipts were read, and the canary wasn't overloaded.
func ModalUnsound(ev obs.CanaryEvidence, valid bool, invalid string) string {
	switch {
	case !ev.Live:
		return "the canary wasn't armed for the run"
	case !ev.ReceiptsRead:
		return "the canary's receipts weren't read"
	case ev.Overloaded:
		return "the canary was overloaded, so its counts prove nothing either way"
	case !valid:
		return "the probe's document isn't valid: " + invalid
	}
	return ""
}

// ModalImageNames are the names ModalImage's own config declares, as Docker showed them on 10 Nov 2026 (POC-7). A name
// a later build of that tag adds stops run modal until a reviewed change lists it.
var ModalImageNames = []string{"PATH", "LANG", "GPG_KEY", "PYTHON_VERSION", "PYTHON_SHA256"}

// ModalStop is POC-5's generic gate for run modal's open sandbox (PRV-18): a credential surface the image and the host
// didn't put there, which may be Modal's own. It returns the rule that tripped, or "". A document it can't read trips.
func ModalStop(doc []byte) string {
	if names := ModalUnplacedNames(doc, ModalImageNames); len(names) > 0 {
		return "SEC-1 names whose source POC-7 can't establish: " + strings.Join(names, ", ")
	}
	if paths := ModalUnexpectedCreds(doc); len(paths) > 0 {
		return "SEC-3 credential files beyond the image's own /etc/shadow: " + strings.Join(paths, ", ")
	}
	return ""
}

// ModalUnplacedNames are SEC-1's names that neither the image declares nor the host set (it sets SANDPROBE_TWIN only).
func ModalUnplacedNames(doc []byte, image []string) []string {
	d, err := obs.ParseDoc(doc)
	if err != nil {
		return []string{"(the document didn't parse)"}
	}
	var out []string
	for _, o := range d.Observations {
		if o.ID != "SEC-1" || o.Result != obs.Finding {
			continue
		}
		_, list, ok := strings.Cut(o.Evidence, "values never read: ")
		if !ok {
			out = append(out, "(the evidence couldn't be read)")
		}
		for n := range strings.SplitSeq(list, ", ") {
			if n != "" && !slices.Contains(image, n) && n != "SANDPROBE_TWIN" {
				out = append(out, n)
			}
		}
		for _, n := range o.ObservedNames {
			if !slices.Contains(image, n) && n != "SANDPROBE_TWIN" && !slices.Contains(out, n) {
				out = append(out, n)
			}
		}
	}
	return out
}

// ModalUnexpectedCreds are SEC-3's readable credential paths other than the image's own /etc/shadow.
func ModalUnexpectedCreds(doc []byte) []string {
	d, err := obs.ParseDoc(doc)
	if err != nil {
		return []string{"(the document didn't parse)"}
	}
	var out []string
	for _, o := range d.Observations {
		if o.ID != "SEC-3" || o.Result != obs.Finding {
			continue
		}
		list := strings.TrimSuffix(strings.TrimPrefix(o.Evidence, "the agent can read "), " (opened, never read)")
		for p := range strings.SplitSeq(list, ", ") {
			if p != "/etc/shadow" {
				out = append(out, p)
			}
		}
	}
	return out
}
