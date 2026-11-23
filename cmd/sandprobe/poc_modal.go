//go:build poc

// The Modal proof of concept (SPEC.md, the Modal section): built only with -tags poc, never shipped.
package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	modal "github.com/modal-labs/modal-client/go"

	"sandprobe/internal/canary"
	"sandprobe/internal/host"
	"sandprobe/internal/obs"
	"sandprobe/internal/probes"
)

//go:embed pocbin/sandprobe-aux-linux-amd64
var auxAmd64 []byte

// pocWorkspace is the one Modal workspace the PoC may use, named by the operator (POC-1); nothing runs without it.
func pocWorkspace() (string, error) {
	w := os.Getenv("SANDPROBE_MODAL_WORKSPACE")
	if !regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`).MatchString(w) {
		return "", fail("not_logged_in", "set SANDPROBE_MODAL_WORKSPACE to the Modal workspace the PoC may use", "modal profile list", exitLogin)
	}
	return w, nil
}

const (
	pocApp          = "sandprobe"
	pocImage        = "python:3.12-slim-bookworm"
	pocSidecarImage = "alpine:3.21"
	exitHeld        = 8 // POC-5: a stop case; only the incident note is kept
)

func init() { pocCmd = pocMain }

func pocMain(o opts, r runFlags, args []string, stderr io.Writer) (int, error) {
	if len(args) != 2 || args[0] != "modal" {
		return 0, fail("usage", "poc modal run|render|summary|cleanup", "sandprobe poc modal run -variant default -out <dir> -y", exitUsage)
	}
	switch args[1] {
	case "run":
		return pocRun(o, r, stderr)
	case "render":
		return pocRender(o, r)
	case "summary":
		return pocSummary(o, r)
	case "cleanup":
		return pocCleanup(o, r, stderr)
	}
	return 0, fail("usage", "no poc command "+args[1], "sandprobe poc modal run -variant default -out <dir> -y", exitUsage)
}

// rawRecord is POC-5's raw record of one setup: our own observations and timestamps, kept before any report exists.
type rawRecord struct {
	Setup      string             `json:"setup"`
	Started    time.Time          `json:"started"`
	Ended      time.Time          `json:"ended"`
	SandboxID  string             `json:"sandbox_id"`
	Arch       string             `json:"arch"`
	Kernel     string             `json:"kernel"`
	Survey     *obs.Survey        `json:"survey"`
	Manifest   obs.Manifest       `json:"manifest"`
	Input      obs.Input          `json:"input"`
	Doc        json.RawMessage    `json:"doc"`
	Evidence   obs.CanaryEvidence `json:"evidence"`
	Calls      []obs.ProviderCall `json:"calls"`
	Cleanup    string             `json:"cleanup"`
	Cleaned    bool               `json:"cleaned"`
	ImageNames []string           `json:"image_env_names"`
	Twin       *twinRecord        `json:"twin,omitempty"`
	Relay      *host.RelayLog     `json:"relay,omitempty"`
	Look       []map[string]any   `json:"look,omitempty"`
	Sidecar    map[string]string  `json:"sidecar,omitempty"`
	Notes      []string           `json:"notes,omitempty"`
	Processes  map[string]string  `json:"processes,omitempty"` // pid to /proc/<pid>/comm, names only, after the probe
	// GatesPassed is set only when every step ran and every gate passed (POC-5); render and summary take nothing else.
	GatesPassed bool `json:"gates_passed"`
}

// twinRecord is POC-3's allowed twin: the probe's own EGR-2, under the allowlist's one name.
type twinRecord struct {
	Nonce     string            `json:"nonce"`
	Attempts  []obs.Attempt     `json:"attempts"`
	Receipts  []obs.Receipt     `json:"receipts"`
	Elsewhere map[string]uint64 `json:"elsewhere,omitempty"`
	Read      bool              `json:"read"`
}

// incident is all that stays of a setup that tripped POC-5: the rule, the times, our own counts.
type incident struct {
	Setup     string            `json:"setup"`
	Rule      string            `json:"rule"`
	At        time.Time         `json:"at"`
	Started   time.Time         `json:"started"`
	Receipts  []obs.Receipt     `json:"receipts"`
	Elsewhere map[string]uint64 `json:"elsewhere,omitempty"`
	Cleanup   string            `json:"cleanup"`
}

type held struct{ rule string }

func (h *held) Error() string { return "held: " + h.rule }

func pocRun(o opts, r runFlags, stderr io.Writer) (int, error) {
	setup := r.variant
	if _, err := host.ModalSetup(setup, "cx", "x"); err != nil {
		return 0, fail("usage", err.Error(), "-variant "+strings.Join(host.ModalSetups, "|"), exitUsage)
	}
	if !o.yes {
		return exitApproval, fail("needs_approval", "nothing was created: the PoC runs only with -y", "sandprobe poc modal run -variant "+setup+" -y", exitApproval)
	}
	workspace, err := pocWorkspace() // before the canary, Docker or Modal is contacted
	if err != nil {
		return 0, err
	}
	// The run's image list must be this workspace's before any image is built, or a new one could never be cleaned up.
	if list, err := readImages(r.outDir, true); err != nil {
		return 0, fail("usage", "the image list can't be read: "+err.Error(), "a new -out directory, or clean the old images first", exitUsage)
	} else if list.Workspace != "" && list.Workspace != workspace {
		return 0, fail("usage", "the image list in "+r.outDir+" is for workspace "+list.Workspace+", not "+workspace, "a new -out directory", exitUsage)
	}
	c, err := r.liveCanary()
	if err != nil {
		return 0, err
	}
	step := func(f string, a ...any) { fmt.Fprintf(stderr, "· "+f+"\n", a...) }
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	status, err := c.Ask(ctx, canary.Request{Op: "status"})
	if err != nil || !status.OK {
		return 0, fail("provider_error", "the canary didn't answer over SSM", "deploy/canary.sh status", exitPartial)
	}
	names, err := imageEnvNames(pocImage)
	if err != nil {
		return 0, fail("provider_error", "the image's declared names (POC-7): "+err.Error(), "docker pull "+pocImage, exitPartial)
	}
	rec := &rawRecord{Setup: setup, Started: time.Now().UTC(), ImageNames: names}
	step("binding the Modal client to workspace %s and building %s in App %s", workspace, pocImage, pocApp)
	sdk, err := host.NewModalSDK(ctx, workspace, pocApp, pocImage)
	if err != nil {
		return 0, fail("provider_error", err.Error(), "modal profile list", exitPartial)
	}
	defer sdk.Close()
	if err := noteImage(r.outDir, workspace, sdk.ImageID); err != nil {
		return 0, fail("provider_error", fmt.Sprintf("image %s was built but its ID couldn't be kept for cleanup: %v", sdk.ImageID, err), "note it, then sandprobe poc modal cleanup", exitPartial)
	}

	twin := ""
	if setup == "domain-one" {
		twin = host.NewToken("c")
	}
	spec, _ := host.ModalSetup(setup, twin, c.Dom)
	mainMark, sideMark := markerToken(), markerToken()
	if setup == "sidecar" {
		if err := sdk.EphemeralVolume(ctx, "shared"); err != nil {
			return 0, fail("provider_error", err.Error(), "retry", exitPartial)
		}
		spec.Volumes = map[string]string{"/mnt/shared": "shared"}
		spec.Command = mainCommand(mainMark)
	}
	step("creating the %s sandbox", setup)
	box, err := host.CreateModal(ctx, sdk, spec)
	rec.SandboxID = box.SandboxID
	teardown := func() {
		tctx, tcancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer tcancel()
		step("terminating sandbox %s", box.SandboxID)
		if terr := box.Destroy(tctx); terr != nil {
			rec.Cleanup, rec.Cleaned = "NOT confirmed deleted: "+terr.Error(), false
			fmt.Fprintf(stderr, "sandprobe: %s\n", rec.Cleanup)
			return
		}
		rec.Cleanup, rec.Cleaned = fmt.Sprintf("sandbox %s terminated, polled finished, and nothing running with tag sandprobe-run=%s", box.SandboxID, box.Tags["sandprobe-run"]), true
		if setup == "sidecar" {
			rec.Cleanup += "; the sidecar went with it; the ephemeral volume closes with the client"
		}
	}
	runErr := func() error {
		if err != nil {
			return err
		}
		if setup == "sidecar" {
			if err := startSidecar(ctx, sdk, box, c, sideMark, rec, r.outDir, step); err != nil {
				return err
			}
		}
		arch, kernel, err := uname(ctx, box)
		if err != nil {
			return err
		}
		rec.Arch, rec.Kernel = arch, kernel
		bin, sum, err := probes.Probe(arch)
		if err != nil {
			return err
		}
		step("sandbox %s (%s, kernel %s); uploading the probe", box.SandboxID, arch, kernel)
		if err := box.Upload(ctx, bin); err != nil {
			return err
		}
		step("running the probe as the image's default user")
		run, err := host.Execute(ctx, box, c, host.Options{Mode: "exec", ProbeSHA256: sum, Excluded: host.ModalExcluded, ExcludedKind: obs.SkipProviderTerms})
		if err != nil {
			return err
		}
		rec.Survey, rec.Manifest, rec.Input, rec.Doc, rec.Evidence = run.Survey, run.Manifest, run.Input, run.Doc, run.Evidence
		if why := evidenceUnsound(run.Evidence, run.Report.Valid, run.Report.Invalid); why != "" {
			return errors.New("the gate can't clear this setup, so nothing more ran: " + why) // never a clear on no evidence
		}
		if rule := host.ModalGate(setup, twin, run.Evidence.Receipts, run.Evidence.Elsewhere); rule != "" {
			return &held{rule}
		}
		if unknownNames := unplacedNames(run.Doc, names); len(unknownNames) > 0 {
			return &held{"SEC-1 names whose source POC-7 can't establish: " + strings.Join(unknownNames, ", ")}
		}
		if creds := unexpectedCreds(run.Doc); len(creds) > 0 { // anything but the image's own shadow file: Modal's? (POC-5)
			return &held{"SEC-3 credential files beyond the image's own /etc/shadow: " + strings.Join(creds, ", ")}
		}
		ps, err := processNames(ctx, box) // names only: which processes SEC-2 and SEC-5 saw (POC-7)
		if err != nil {
			return err
		}
		rec.Processes = ps
		if setup == "domain-one" {
			step("the allowed twin: the probe's EGR-2 under the allowlist's one name")
			t, err := runTwin(ctx, box, c, run.Input, twin)
			rec.Twin = t
			if err != nil {
				return err
			}
			if rule := host.ModalGate(setup, twin, t.Receipts, t.Elsewhere); rule != "" {
				return &held{rule}
			}
		}
		if setup == "sidecar" {
			return lookSidecar(ctx, sdk, box, run.Evidence.Receipts, mainMark, sideMark, rec, step)
		}
		return nil
	}()
	teardown()
	rec.Calls, rec.Ended = box.Calls, time.Now().UTC()
	var h *held
	if errors.As(runErr, &h) {
		inc := incident{Setup: setup, Rule: h.rule, At: time.Now().UTC(), Started: rec.Started, Receipts: rec.Evidence.Receipts,
			Elsewhere: rec.Evidence.Elsewhere, Cleanup: rec.Cleanup}
		if rec.Twin != nil {
			inc.Receipts = append(inc.Receipts, rec.Twin.Receipts...)
		}
		p := filepath.Join(r.outDir, "incident-"+setup+".json")
		os.MkdirAll(r.outDir, 0o700)
		if err := writeJSON(p, inc); err != nil {
			fmt.Fprintf(stderr, "sandprobe: STOPPED under POC-5, held for the project owner: %s\n  the incident note couldn't be written (%v); the rule above is the note\n", h.rule, err)
			return exitHeld, nil
		}
		fmt.Fprintf(stderr, "sandprobe: STOPPED under POC-5, held for the project owner: %s\n  only the incident note was kept: %s\n", h.rule, p)
		if !rec.Cleaned {
			return exitCleanup, nil
		}
		return exitHeld, nil
	}
	dir := filepath.Join(r.outDir, "raw", setup)
	os.MkdirAll(dir, 0o700)
	os.RemoveAll(filepath.Join(r.outDir, "reports", setup)) // a new record never sits beside an older run's report
	if runErr != nil {
		rec.Notes = append(rec.Notes, "ended early: "+runErr.Error())
	}
	rec.GatesPassed = runErr == nil
	if err := writeJSON(filepath.Join(dir, "record.json"), rec); err != nil {
		return exitPartial, fail("provider_error", "the raw record couldn't be written: "+err.Error(), "free space in "+dir+", then run the setup again", exitPartial)
	}
	fmt.Fprintf(stderr, "sandprobe: %s's raw record is in %s; read it against POC-5 before `poc modal render`\n", setup, dir)
	if runErr != nil {
		return failExit(rec.Cleaned), fail("provider_error", runErr.Error(), "see the raw record", failExit(rec.Cleaned))
	}
	if !rec.Cleaned {
		return exitCleanup, nil
	}
	return 0, nil
}

// mainCommand keeps the sidecar setup's main container up, with its marker in its arguments, in /tmp and /root, on
// the shared volume, and answered on TCP 7070 (POC-6).
func mainCommand(m string) []string {
	script := `M=$1
echo "$M" > /tmp/sandprobe-$M
echo "$M" > /root/sandprobe-$M
echo "$M" > /mnt/shared/sandprobe-$M
sync
python3 -c 'import socket,sys
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("0.0.0.0", 7070)); s.listen(4)
while True:
    c, _ = s.accept(); c.sendall((sys.argv[1] + "\n").encode()); c.close()' "$M" &
while :; do sleep 60; done`
	return []string{"sh", "-c", script, "sandprobe-main", m}
}

func markerToken() string { return "m" + host.NewToken("")[:20] }

// startSidecar builds the sidecar image, starts the relay in it with its egress pinned to the canary's /32, and
// waits for its ready mark (POC-6).
func startSidecar(ctx context.Context, sdk *host.ModalSDK, box *host.ModalBox, c *host.SSMCanary, sideMark string, rec *rawRecord, out string, step func(string, ...any)) error {
	step("building the sidecar image %s", pocSidecarImage)
	img, err := sdk.Client.Images.FromRegistry(pocSidecarImage, nil).Build(ctx, sdk.App, nil)
	if err != nil {
		return errors.New("sidecar image build failed")
	}
	if err := noteImage(out, sdk.Workspace, img.ImageID); err != nil {
		return fmt.Errorf("sidecar image %s was built but its ID couldn't be kept for cleanup: %v", img.ImageID, err)
	}
	sb := sdk.Sandbox(box.SandboxID)
	cmd := fmt.Sprintf(`while [ ! -x /tmp/sp-aux ]; do sleep 0.2; done
/tmp/sp-aux relay -suffix canary.%s -to %s:443 -dir /tmp/sp-relay
sleep infinity`, c.Dom, c.Addr)
	side, err := sb.ExperimentalSidecars.Create(ctx, "watch", img, &modal.SidecarCreateParams{
		Command:               []string{"sh", "-c", cmd, "sandprobe-side", sideMark},
		OutboundCIDRAllowlist: &modal.Allowlist{Entries: []string{c.Addr + "/32"}},
		Volumes:               map[string]*modal.Volume{"/mnt/shared": sdk.Volume("shared")},
	})
	if err != nil {
		return errors.New("sidecar create failed")
	}
	rec.Sidecar = map[string]string{"container": side.ContainerID, "image": pocSidecarImage}
	if err := side.Filesystem.WriteBytes(ctx, auxAmd64, "/tmp/sp-aux.tmp", nil); err != nil {
		return errors.New("copying the relay into the sidecar failed")
	}
	if _, err := sideExec(ctx, side, []string{"sh", "-c", "chmod 0555 /tmp/sp-aux.tmp && mv /tmp/sp-aux.tmp /tmp/sp-aux"}, nil); err != nil {
		return err
	}
	for i := 0; i < 60; i++ {
		if out, err := sideExec(ctx, side, []string{"cat", "/tmp/sp-relay/ready"}, nil); err == nil && strings.TrimSpace(string(out)) == "ready" {
			step("the sidecar's relay is ready")
			return nil
		}
		time.Sleep(time.Second)
	}
	return errors.New("the sidecar's relay never wrote ready: the setup ends unknown")
}

func sideContainer(ctx context.Context, sdk *host.ModalSDK, box *host.ModalBox) (*modal.SidecarContainer, error) {
	return sdk.Sandbox(box.SandboxID).ExperimentalSidecars.Get(ctx, "watch", nil)
}

func sideExec(ctx context.Context, side *modal.SidecarContainer, args []string, stdin []byte) ([]byte, error) {
	p, err := side.Exec(ctx, args, &modal.SidecarExecParams{Stdout: modal.Pipe, Stderr: modal.Pipe})
	if err != nil {
		return nil, errors.New("sidecar exec failed")
	}
	go func() {
		p.Stdin.Write(stdin)
		p.Stdin.Close()
	}()
	out, _ := io.ReadAll(io.LimitReader(p.Stdout, obs.MaxDoc+1))
	io.Copy(io.Discard, p.Stdout)
	io.Copy(io.Discard, p.Stderr)
	code, err := p.Wait(ctx, nil)
	if err != nil || code != 0 {
		return out, fmt.Errorf("sidecar exec %s exited %d", args[0], code)
	}
	if len(out) > obs.MaxDoc { // a prefix could parse as a complete log: overflow is unknown
		return nil, fmt.Errorf("sidecar exec %s wrote more than a document", args[0])
	}
	return out, nil
}

// lookSidecar reads the relay's whole log and gates on it, then runs look's rows one at a time, each gated: the first
// unexpected sighting stops everything after it (POC-5, POC-6).
func lookSidecar(ctx context.Context, sdk *host.ModalSDK, box *host.ModalBox, receipts []obs.Receipt, mainMark, sideMark string, rec *rawRecord, step func(string, ...any)) error {
	side, err := sideContainer(ctx, sdk, box)
	if err != nil {
		return errors.New("the sidecar can't be found")
	}
	log, err := sideExec(ctx, side, []string{"cat", "/tmp/sp-relay/relay.jsonl"}, nil)
	l := host.ParseRelayLog(log)
	if err != nil {
		l = host.RelayLog{Why: "the relay's log couldn't be read"}
	}
	rec.Relay = &l
	trip, unknown := host.RelayGate(receipts, l)
	if trip != "" {
		return &held{trip}
	}
	if unknown != "" {
		return errors.New("the sidecar's attribution is unknown, so look didn't run: " + unknown)
	}
	step("the relay's log is complete: %d relayed, %d refused", len(l.Relayed), l.Refused)
	auxMain, err := uploadAux(ctx, box)
	if err != nil {
		return err
	}
	type row struct {
		side     string // "sidecar" or "main"
		args     []string
		mark     string
		expected bool // seeing it is expected (the volume, main's port); otherwise a sighting stops the run
		reload   bool
	}
	rows := []row{
		{"sidecar", []string{"look", "-row", "procs"}, mainMark, false, false},
		{"sidecar", []string{"look", "-row", "files", "-paths", "/tmp/sandprobe-" + mainMark + ",/root/sandprobe-" + mainMark}, mainMark, false, false},
		{"main", []string{"look", "-row", "procs"}, sideMark, false, false},
		{"sidecar", []string{"look", "-row", "volume", "-paths", "/mnt/shared/sandprobe-" + mainMark}, mainMark, true, false},
		{"sidecar", []string{"look", "-row", "volume", "-paths", "/mnt/shared/sandprobe-" + mainMark}, mainMark, true, true},
		{"sidecar", []string{"look", "-row", "net", "-connect", "main:7070"}, mainMark, true, false},
	}
	for _, rw := range rows {
		if rw.reload {
			if err := side.ReloadVolumes(ctx, nil); err != nil {
				rec.Look = append(rec.Look, map[string]any{"from": rw.side, "row": "volume", "after_reload": true, "error": "reload failed"})
				continue
			}
		}
		var out []byte
		var err error
		if rw.side == "sidecar" {
			out, err = sideExec(ctx, side, append([]string{"/tmp/sp-aux"}, rw.args...), []byte(rw.mark+"\n"))
		} else {
			out, err = box.Exec(ctx, append([]string{auxMain}, rw.args...), []byte(rw.mark+"\n"))
		}
		res := map[string]any{"from": rw.side, "after_reload": rw.reload}
		if err != nil {
			res["error"] = "look didn't run to the end"
		} else if json.Unmarshal(out, &res) != nil {
			res["error"] = "look's line didn't parse"
		}
		res["from"], res["after_reload"] = rw.side, rw.reload
		rec.Look = append(rec.Look, res)
		if seen, _ := res["seen"].(bool); seen && !rw.expected {
			return &held{fmt.Sprintf("sidecar: the %s saw the other side's %v", rw.side, res["row"])}
		}
	}
	return nil
}

// uploadAux puts the helper in the main container, for look from that side.
func uploadAux(ctx context.Context, box *host.ModalBox) (string, error) {
	dir := "/tmp/sandprobe-aux-" + host.NewToken("")[:12]
	if _, err := box.Exec(ctx, []string{"sh", "-c", fmt.Sprintf("umask 022 && mkdir %s && cat > %s/aux && chmod 0555 %s/aux", dir, dir, dir)}, auxAmd64); err != nil {
		return "", fmt.Errorf("uploading the helper: %w", err)
	}
	return dir + "/aux", nil
}

// runTwin is POC-3: the probe again, selecting only EGR-2, under nonce t, with the canary armed for t on its own run.
func runTwin(ctx context.Context, box *host.ModalBox, c *host.SSMCanary, in obs.Input, t string) (*twinRecord, error) {
	rec := &twinRecord{Nonce: t}
	run := host.NewToken("r")
	a, err := c.Ask(ctx, canary.Request{Op: "arm", Run: run, TTL: 600, Wants: []canary.Want{{Nonce: t, Proto: "tcp", Port: 443}}})
	if err != nil || !a.OK {
		return rec, errors.New("the canary didn't arm the twin")
	}
	defer c.Ask(context.Background(), canary.Request{Op: "disarm", Run: run})
	tin := in
	tin.RunID, tin.Nonce = run, host.NewToken("n")
	tin.Selected = []string{"EGR-2"}
	tin.CheckNonces = map[string]string{"EGR-2": t}
	tin.Endpoints = map[string]string{"EGR-2": in.Endpoints["EGR-2"]}
	tin.Targets, tin.Discover = nil, nil
	b, _ := json.Marshal(tin)
	pctx, cancel := context.WithTimeout(ctx, 100*time.Second)
	out, err := box.Probe(pctx, nil, b)
	cancel()
	if err != nil {
		return rec, errors.New("the twin's probe didn't run to the end")
	}
	d, err := obs.ParseDoc(out)
	if err != nil {
		return rec, errors.New("the twin's document didn't parse")
	}
	found := false
	for _, o := range d.Observations {
		if o.ID == "EGR-2" {
			rec.Attempts, found = o.Attempts, true
		}
	}
	if !found {
		return rec, errors.New("the twin's document holds no EGR-2 observation")
	}
	time.Sleep(2100 * time.Millisecond)
	q, err := c.Ask(ctx, canary.Request{Op: "query", Run: run})
	if err != nil || !q.OK || q.Run != run || q.Pin != a.Pin {
		return rec, errors.New("the twin's receipts couldn't be read")
	}
	if q.Overloaded {
		return rec, errors.New("the canary was overloaded during the twin, so its receipts prove nothing either way")
	}
	rec.Read = true
	for _, n := range q.Counts {
		if n.Count > 0 {
			rec.Receipts = append(rec.Receipts, obs.Receipt{Nonce: n.Nonce, Proto: n.Proto, Port: n.Port, From: n.FirstFrom})
		}
		if n.Elsewhere > 0 {
			if rec.Elsewhere == nil {
				rec.Elsewhere = map[string]uint64{}
			}
			rec.Elsewhere[n.Nonce] = n.Elsewhere
		}
	}
	return rec, nil
}

func uname(ctx context.Context, box *host.ModalBox) (arch, kernel string, err error) {
	out, err := box.Exec(ctx, []string{"uname", "-m", "-r"}, nil)
	if err != nil {
		return "", "", fmt.Errorf("uname: %w", err)
	}
	f := strings.Fields(string(out))
	if len(f) != 2 {
		return "", "", errors.New("uname answered oddly")
	}
	switch f[1] {
	case "x86_64":
		return "amd64", f[0], nil
	case "aarch64":
		return "arm64", f[0], nil
	}
	return "", "", errors.New("an architecture Sandprobe has no probe for")
}

// imageEnvNames is the names the image's config declares, names only (POC-7), from docker image inspect.
func imageEnvNames(image string) ([]string, error) {
	if exec.Command("docker", "image", "inspect", image).Run() != nil {
		if err := exec.Command("docker", "pull", "-q", image).Run(); err != nil {
			return nil, errors.New("docker couldn't pull it")
		}
	}
	out, err := exec.Command("docker", "image", "inspect", image, "--format", "{{json .Config.Env}}").Output()
	if err != nil {
		return nil, errors.New("docker couldn't inspect it")
	}
	var env []string
	if err := json.Unmarshal(out, &env); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(env))
	for _, kv := range env {
		n, _, _ := strings.Cut(kv, "=")
		names = append(names, n)
	}
	return names, nil
}

// unplacedNames are SEC-1's names that neither the image declares nor the host set (it sets SANDPROBE_TWIN only).
func unplacedNames(doc []byte, image []string) []string {
	d, err := obs.ParseDoc(doc)
	if err != nil {
		return nil
	}
	var out []string
	for _, o := range d.Observations {
		if o.ID != "SEC-1" || o.Result != obs.Finding {
			continue
		}
		_, list, _ := strings.Cut(o.Evidence, "values never read: ")
		for n := range strings.SplitSeq(list, ", ") {
			if n != "" && !contains(image, n) && n != "SANDPROBE_TWIN" {
				out = append(out, n)
			}
		}
	}
	return out
}

// unexpectedCreds are SEC-3's readable credential paths other than the image's own /etc/shadow.
func unexpectedCreds(doc []byte) []string {
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

// processNames is every visible process's name, from /proc/<pid>/comm: metadata, never arguments or environment.
func processNames(ctx context.Context, box *host.ModalBox) (map[string]string, error) {
	out, err := box.Exec(ctx, []string{"sh", "-c", `for p in /proc/[0-9]*; do printf '%s %s\n' "${p#/proc/}" "$(cat "$p/comm" 2>/dev/null)"; done`}, nil)
	if err != nil {
		return nil, fmt.Errorf("listing process names: %w", err)
	}
	ps := map[string]string{}
	for l := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		if pid, name, ok := strings.Cut(l, " "); ok && len(name) <= 16 {
			ps[pid] = name
		}
	}
	return ps, nil
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// noteImage records an image the PoC built, for cleanup at the end (POC-9). A list that exists but doesn't parse is
// an error, never an empty list.
// imageList is the images a run built, bound to the workspace it built them in (POC-1, POC-9).
type imageList struct {
	Workspace string   `json:"workspace"`
	IDs       []string `json:"ids"`
}

func noteImage(dir, workspace, id string) error {
	if id == "" || workspace == "" {
		return errors.New("no image ID, or no workspace")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	list, err := readImages(dir, true)
	if err != nil {
		return err
	}
	if list.Workspace != "" && list.Workspace != workspace {
		return fmt.Errorf("this run's image list is for workspace %s, not %s", list.Workspace, workspace)
	}
	list.Workspace = workspace
	if !contains(list.IDs, id) {
		list.IDs = append(list.IDs, id)
	}
	return writeJSON(filepath.Join(dir, "images.json"), list)
}

// readImages reads the image list; missing is empty only when the caller allows it. A list without its workspace
// (written before the binding) is refused, never cleaned in whatever workspace is named now.
func readImages(dir string, missingOK bool) (imageList, error) {
	b, err := os.ReadFile(filepath.Join(dir, "images.json"))
	if errors.Is(err, os.ErrNotExist) && missingOK {
		return imageList{}, nil
	}
	if err != nil {
		return imageList{}, err
	}
	var list imageList
	if err := json.Unmarshal(b, &list); err != nil {
		return imageList{}, fmt.Errorf("images.json doesn't parse: %w", err)
	}
	if list.Workspace == "" && len(list.IDs) > 0 {
		return imageList{}, errors.New("images.json names no workspace; clean those images by hand in the workspace that built them")
	}
	return list, nil
}

// evidenceUnsound is why a run's canary evidence can't clear POC-5's gate: an empty receipt list means nothing
// unless the run was live, the receipts were read, and the canary wasn't overloaded.
func evidenceUnsound(ev obs.CanaryEvidence, valid bool, invalid string) string {
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
