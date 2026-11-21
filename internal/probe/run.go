//go:build linux

// Package probe is the in-box half of Sandprobe: a static binary that runs as the agent, observes, and never grades
// (SBX-9). It changes nothing but its own scratch directory and, for its twins, two short-lived children of its own.
package probe

import (
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"sandprobe/internal/catalog"
	"sandprobe/internal/obs"
)

// Input is what the host hands the probe (obs.Input).
type Input = obs.Input

type env struct {
	in          Input
	start       time.Time // the probe's start, for monotonic offsets (SBX-11)
	intercepted bool      // a TLS session to the canary showed a key other than the pin (EGR-4)
	root        bool
	home        string
	tw          *twins
	ownPort     int // the probe's own loopback listener, AMP-5's twin
}

func (e *env) ms() int64 { return time.Since(e.start).Milliseconds() }

func (e *env) expand(name string) string {
	if strings.HasPrefix(name, "~/") {
		return filepath.Join(e.home, name[2:])
	}
	return name
}

func home() string {
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	if u, err := user.Current(); err == nil {
		return u.HomeDir
	}
	return "/"
}

// Run observes every selected check it implements and returns the document for the host to grade.
func Run(in Input) (*obs.Doc, error) {
	start := time.Now()
	sum, err := selfDigest()
	if err != nil {
		return nil, err
	}
	id, err := readIdentity()
	if err != nil {
		return nil, err
	}
	tw, err := makeTwins()
	if tw != nil {
		defer tw.close()
	}
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	defer ln.Close()
	e := &env{in: in, start: start, root: id.UID == 0, home: home(), tw: tw, ownPort: ln.Addr().(*net.TCPAddr).Port}
	d := &obs.Doc{Schema: obs.Schema, RunID: in.RunID, Nonce: in.Nonce, BoxID: in.BoxID, ProbeSHA256: sum, Identity: id}
	for _, cid := range in.Selected {
		ck, known := catalog.Get(cid)
		fn, implemented := checks[cid]
		if !known || !implemented {
			continue
		}
		o := fn(e, ck)
		o.ID = cid
		o.Evidence, o.Reason = clip(o.Evidence), clip(o.Reason)
		d.Observations = append(d.Observations, o)
	}
	d.DurationMS = time.Since(start).Milliseconds()
	return d, nil
}

func clip(s string) string {
	if len(s) <= obs.MaxField {
		return s
	}
	return s[:obs.MaxField-3] + "..."
}

// Survey is what the host needs from the box before it can plan (SBX-3): the agent's proxy, as SBX-5 records it, the
// Kubernetes API its environment names, and whether a vsock device exists.
func Survey() *obs.Survey {
	s := &obs.Survey{Schema: obs.SurveySchema, Vsock: vsockDevice()}
	if p, ok := agentProxy(); ok {
		s.Proxy = &p
	}
	s.KubeAPI, _ = kubeAPI()
	s.Roots = storageRoots(&s.RootsIncomplete)
	return s
}
