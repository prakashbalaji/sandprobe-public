package host

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"sandprobe/internal/obs"
)

// SpritesExclusions are the checks that would send something to an endpoint Fly owns: cloud metadata, the host over
// vsock, a proxy or Kubernetes API the box names. Sandprobe checks the customer's own sprite, from inside it, and talks
// only to our canary (the Sprites PRV row, PRV-5).
func SpritesExclusions() map[string]string {
	why := "Sprites scope covers the sprite itself, never a Fly-owned endpoint (PRV-5)"
	return map[string]string{"SEC-4": why, "EGR-3": why, "AMP-6": why, "AMP-7": why}
}

// SpriteBox is a sprite on Sprites, reached with `sprite exec` as its default user, the way an agent's commands reach
// it (SBX-4). Sandprobe creates it for the run and destroys it after. Sprites deletes only by name, so the destroy
// goes only while that name still answers with the immutable ID the create returned, and counts only on a 404 after;
// the race between that check and the delete is residual (PRV-1, open question 12).
type SpriteBox struct {
	Home      string // the sprite CLI's HOME: Sandprobe's own login, never the user's default
	Org       string
	Name      string
	SpriteID  string             // sprite-<uuid>, as the provider reported it at creation
	ProbePath string             // the uploaded probe, once Upload has run
	Launcher  string             // the agent's launch path, when the person's setup left one (SPR-2)
	Version   string             // the checkpoint the reset restores, once Checkpoint has run
	Calls     []obs.ProviderCall // every call to the provider, in order (PRV-3)
	// cli runs the sprite CLI; tests replace it.
	cli func(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, args ...string) error
}

// spriteCLI, when set, stands in for the sprite CLI in boxes CreateSprite makes; tests set it.
var spriteCLI func(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, args ...string) error

// CreateSprite creates a sprite for this run under a fresh name, and records the ID the provider gives it. It always
// returns the box, so a create that failed after the provider made the sprite still leaves its name for Destroy to
// resolve and report.
func CreateSprite(ctx context.Context, home, org string) (*SpriteBox, error) {
	s := &SpriteBox{Home: home, Org: org, Name: "sandprobe-" + token("")[1:13], cli: spriteCLI}
	if _, err := s.run(ctx, nil, "create", "-skip-console", s.Name); err != nil {
		return s, fmt.Errorf("creating sprite %s: %w", s.Name, err)
	}
	id, gone, err := s.lookup(ctx)
	switch {
	case err != nil:
		return s, fmt.Errorf("sprite %s was created, but its ID didn't come back: %w", s.Name, err)
	case gone || !strings.HasPrefix(id, "sprite-"):
		return s, fmt.Errorf("sprite %s was created, but the provider doesn't show it", s.Name)
	}
	s.SpriteID = id
	return s, nil
}

func (s *SpriteBox) ID() string { return s.SpriteID }

// ours checks, immediately before a call that reaches the sprite by name (exec, checkpoint, restore), that the name
// still answers with the ID the create returned (PRV-1). The race between the check and the call is residual (open
// question 12).
func (s *SpriteBox) ours(ctx context.Context) error {
	id, gone, err := s.lookup(ctx)
	switch {
	case err != nil:
		return fmt.Errorf("sprite %s: %w", s.Name, err)
	case gone:
		return fmt.Errorf("sprite %s is gone", s.Name)
	case s.SpriteID == "" || id != s.SpriteID:
		return fmt.Errorf("sprite %s answers with ID %s, not this run's %s: left alone", s.Name, id, s.SpriteID)
	}
	return nil
}

// Upload puts the probe in a fresh directory in the sprite, as its default user, and checks the bytes arrived whole.
func (s *SpriteBox) Upload(ctx context.Context, probe []byte) error {
	if err := s.ours(ctx); err != nil {
		return err
	}
	dir := "/var/tmp/sandprobe-" + token("")[1:13] // SPR-2: outside /tmp, which a launcher may make private
	sum := sha256.Sum256(probe)
	out, err := s.run(ctx, bytes.NewReader(probe), "exec", "sh", "-c",
		fmt.Sprintf("umask 022 && mkdir %s && cat > %s/probe && chmod 0555 %s/probe && sha256sum %s/probe", dir, dir, dir, dir))
	if err != nil {
		return fmt.Errorf("uploading the probe: %w", err)
	}
	if got, _, _ := strings.Cut(strings.TrimSpace(string(out)), " "); got != hex.EncodeToString(sum[:]) {
		return fmt.Errorf("the probe arrived as %q, not %x", got, sum)
	}
	s.ProbePath = dir + "/probe"
	return nil
}

var probeArg = regexp.MustCompile(`^-?[a-z0-9/._-]+$`)

// AgentExec is where a person's setup may leave the agent's launcher (SPR-2).
const AgentExec = "/usr/local/bin/agent-exec"

// Setup runs the person's setup script once, as the sprite's default user, on sh's standard input (SPR-1), then looks
// for the launcher it may leave. Nothing the script prints is kept or shown: a failure carries its exit code only.
func (s *SpriteBox) Setup(ctx context.Context, script []byte) error {
	// PRV-1: each call below reaches the sprite by name, so each is preceded by its own check that the name still
	// answers with the ID the create returned.
	// SPR-2: only a launcher the setup made is the agent's. One already in the new sprite isn't the person's, so the
	// run stops before the setup runs rather than route every probe call through it.
	if err := s.ours(ctx); err != nil {
		return err
	}
	pre, err := s.run(ctx, nil, "exec", "sh", "-c", "if [ -e "+AgentExec+" ] || [ -L "+AgentExec+" ]; then echo present; else echo absent; fi")
	if err != nil { // an answer through a failing call counts for nothing
		return errors.New("couldn't check the new sprite for an existing launcher")
	}
	switch strings.TrimSpace(string(pre)) {
	case "absent":
	case "present":
		return fmt.Errorf("the new sprite already has %s, which your setup didn't make: nothing ran (SPR-2)", AgentExec)
	default:
		return errors.New("couldn't check the new sprite for an existing launcher")
	}
	if err := s.ours(ctx); err != nil {
		return err
	}
	if _, err := s.run(ctx, bytes.NewReader(script), "exec", "sh", "-s"); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return fmt.Errorf("the setup script exited %d (its output isn't kept)", ee.ExitCode())
		}
		return errors.New("the setup script didn't run to an exit")
	}
	if err := s.ours(ctx); err != nil {
		return err
	}
	out, err := s.run(ctx, nil, "exec", "sh", "-c", "test -x "+AgentExec+" && echo launcher || echo none")
	if err != nil {
		return errors.New("couldn't check for the agent's launcher")
	}
	if strings.TrimSpace(string(out)) == "launcher" {
		s.Launcher = AgentExec
	}
	return nil
}

// Probe runs the probe as the sprite's default user. The sprite CLI reads -s and -o anywhere on its command line,
// even after --, so a probe flag such as -survey would be taken for its own -s. The command goes to the sprite's
// shell as one string instead, built only from the probe's path and flags, each checked.
func (s *SpriteBox) Probe(ctx context.Context, args []string, stdin []byte) ([]byte, error) {
	if s.ProbePath == "" {
		return nil, errors.New("the probe isn't uploaded")
	}
	line := append([]string{"exec", s.ProbePath}, args...)
	if s.Launcher != "" { // SPR-2: the way the person's agent's commands run
		line = append([]string{"exec", s.Launcher, s.ProbePath}, args...)
	}
	for _, a := range line[1:] {
		if !probeArg.MatchString(a) {
			return nil, fmt.Errorf("not a probe argument: %q", a)
		}
	}
	if err := s.ours(ctx); err != nil {
		return nil, err
	}
	return s.run(ctx, bytes.NewReader(stdin), "exec", "-env", "SANDPROBE_TWIN=1", "sh", "-c", strings.Join(line, " "))
}

// Destroy deletes the sprite by name while that name answers with the ID the create returned, and confirms the
// provider's 404 after. A sprite already gone counts as destroyed. A sprite whose create never confirmed an ID is
// reported, never deleted.
func (s *SpriteBox) Destroy(ctx context.Context) error {
	id, gone, err := s.lookup(ctx)
	switch {
	case err != nil:
		return fmt.Errorf("sprite %s: %w; destroy it by hand", s.Name, err)
	case gone:
		return nil
	case s.SpriteID == "":
		return fmt.Errorf("sprite %s exists (%s), but this run's create never confirmed it: left alone, unresolved", s.Name, id)
	case id != s.SpriteID:
		return fmt.Errorf("sprite %s now has ID %s, not %s: left alone", s.Name, id, s.SpriteID)
	}
	if _, err := s.run(ctx, nil, "destroy", "-force"); err != nil {
		return fmt.Errorf("destroying sprite %s: %w", s.Name, err)
	}
	if _, gone, err := s.lookup(ctx); err != nil || !gone {
		return fmt.Errorf("sprite %s (%s) still answers after its destroy; destroy it by hand", s.Name, s.SpriteID)
	}
	return nil
}

// lookup asks the provider for the sprite by name: its ID, or gone on a definitive 404.
func (s *SpriteBox) lookup(ctx context.Context) (id string, gone bool, err error) {
	out, err := s.run(ctx, nil, "api", "/sprites/"+s.Name, "-w", "\n%{http_code}")
	if err != nil {
		return "", false, err
	}
	text := strings.TrimSpace(string(out))
	body, code := "", text
	if i := strings.LastIndex(text, "\n"); i >= 0 {
		body, code = text[:i], text[i+1:]
	}
	switch code {
	case "404":
		return "", true, nil
	case "200":
		var r struct{ Data struct{ ID string } }
		if err := json.Unmarshal([]byte(body), &r); err != nil || r.Data.ID == "" {
			return "", false, fmt.Errorf("the provider's answer didn't parse")
		}
		if n := len(s.Calls); n > 0 {
			s.Calls[n-1].ID = r.Data.ID // PRV-3: the ID this call returned
		}
		return r.Data.ID, false, nil
	}
	return "", false, fmt.Errorf("the provider answered %q", code)
}

// callRecord is PRV-3's record of one CLI call: never its stdin or what it printed, only how it ended, and the
// provider's HTTP status when the call asked for one with -w.
func callRecord(ctx context.Context, at time.Time, args []string, out string, err error) obs.ProviderCall {
	c := obs.ProviderCall{At: at.UTC(), Call: "sprite " + strings.Join(args, " ")}
	var ee *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &ee):
		c.Exit, c.Error = ee.ExitCode(), fmt.Sprintf("exited %d", ee.ExitCode())
	case ctx.Err() != nil:
		c.Exit, c.Error = -1, "timed out or canceled"
	default:
		c.Exit, c.Error = -1, "the sprite CLI didn't run to an exit"
	}
	if slices.Contains(args, "-w") {
		text := strings.TrimSpace(out)
		c.Status = text[strings.LastIndex(text, "\n")+1:]
		if n, err := strconv.Atoi(c.Status); err != nil || n < 100 || n > 599 {
			c.Status = "none"
		}
	}
	n, _ := strconv.Atoi(c.Status)
	c.OK = err == nil && (c.Status == "" || (n >= 200 && n <= 299))
	return c
}

// run calls the sprite CLI for this sprite, with stdin, and returns its stdout (capped like a document).
func (s *SpriteBox) run(ctx context.Context, stdin io.Reader, args ...string) ([]byte, error) {
	if stdin == nil {
		stdin = bytes.NewReader(nil)
	}
	full := append([]string{args[0], "-o", s.Org, "-s", s.Name}, args[1:]...)
	if args[0] == "create" || args[0] == "api" { // create names its sprite as an argument; api, by path
		full = append([]string{args[0], "-o", s.Org}, args[1:]...)
	}
	out, errs := &capped{max: obs.MaxDoc + 1}, &capped{max: 4 << 10}
	var err error
	at := time.Now()
	defer func() { s.Calls = append(s.Calls, callRecord(ctx, at, full, out.String(), err)) }()
	if s.cli != nil {
		err = s.cli(ctx, stdin, out, errs, full...)
	} else {
		cmd := exec.CommandContext(ctx, "sprite", full...)
		cmd.Env = append(cmd.Environ(), "HOME="+s.Home)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, out, errs
		err = cmd.Run()
	}
	if err != nil {
		return out.Bytes(), fmt.Errorf("%w: %s", err, strings.TrimSpace(errs.String()))
	}
	return out.Bytes(), nil
}

// spriteRoots are the sprite's own filesystems, the roots PER-5 may mark (TWN-3): the overlay over its user data, and
// /tmp and /var/lib/docker, each its own ext4. Sprites gives none of them an identity of its own.
var spriteRoots = []string{"/", "/tmp", "/var/lib/docker"}

// read is checkpoints with the sprite's ID checked on each side, so the state it reads is this run's sprite's; the
// race between a check and the read is residual (PRV-1).
func (s *SpriteBox) read(ctx context.Context) ([]string, string, error) {
	if err := s.ours(ctx); err != nil {
		return nil, "", err
	}
	versions, current, err := s.checkpoints(ctx)
	if err != nil {
		return nil, "", err
	}
	if err := s.ours(ctx); err != nil {
		return nil, "", err
	}
	return versions, current, nil
}

// checkpoints reads the provider's checkpoint versions for the sprite, and its Current checkpoint's time.
func (s *SpriteBox) checkpoints(ctx context.Context) (versions []string, current string, err error) {
	out, err := s.run(ctx, nil, "api", "/sprites/"+s.Name+"/checkpoints", "-w", "\n%{http_code}")
	if err != nil {
		return nil, "", err
	}
	text := strings.TrimSpace(string(out))
	i := strings.LastIndex(text, "\n")
	if i < 0 || text[i+1:] != "200" {
		return nil, "", fmt.Errorf("the checkpoint list didn't come back")
	}
	var cps []struct {
		ID         string `json:"id"`
		CreateTime string `json:"create_time"`
	}
	if err := json.Unmarshal([]byte(text[:i]), &cps); err != nil {
		return nil, "", fmt.Errorf("the checkpoint list didn't parse: %w", err)
	}
	for _, c := range cps {
		if c.ID == "Current" {
			current = c.CreateTime
		} else if c.ID != "" {
			versions = append(versions, c.ID)
		}
	}
	if current == "" {
		return nil, "", fmt.Errorf("the checkpoint list has no Current")
	}
	return versions, current, nil
}

// Checkpoint takes the checkpoint the reset will restore (TWN-3). The provider's list must gain exactly one version.
func (s *SpriteBox) Checkpoint(ctx context.Context) error {
	before, _, err := s.read(ctx)
	if err != nil {
		return err
	}
	if err := s.ours(ctx); err != nil { // immediately before the create
		return err
	}
	if _, err := s.run(ctx, nil, "checkpoint", "create"); err != nil {
		return fmt.Errorf("taking a checkpoint: %w", err)
	}
	after, _, err := s.read(ctx)
	if err != nil {
		return err
	}
	var added []string
	for _, v := range after {
		if !slices.Contains(before, v) {
			added = append(added, v)
		}
	}
	if len(added) != 1 {
		return fmt.Errorf("the checkpoint list gained %d versions, not exactly one: %v", len(added), added)
	}
	s.Version = added[0]
	return nil
}

// Storage declares the restore model, once a checkpoint exists to restore; without one, the box can't be reset.
func (s *SpriteBox) Storage(context.Context) (Storage, error) {
	if s.Version == "" {
		return Storage{}, nil
	}
	return Storage{Model: "restore", Mounts: spriteRoots}, nil
}

// Reset restores exactly the checkpoint Checkpoint took (TWN-3). The host names the attempt; done is the restore
// call's own stream ending cleanly on the complete event for that version, with the provider's state after it
// agreeing: the same sprite ID by name, and a new Current time. No root gets an identity: Sprites has none per
// filesystem.
func (s *SpriteBox) Reset(ctx context.Context) (Box, *obs.ResetEvidence, error) {
	ev := &obs.ResetEvidence{Model: "restore", OperationID: "restore-" + token("")[1:13], Checkpoint: s.Version}
	if s.Version == "" {
		return s, ev, errors.New("no checkpoint to restore")
	}
	var err error
	if _, ev.RestoreBefore, err = s.read(ctx); err != nil {
		return s, ev, err
	}
	if err := s.ours(ctx); err != nil { // nothing is restored but this run's sprite
		return s, ev, err
	}
	ev.BoxBefore = s.SpriteID
	out, err := s.run(ctx, nil, "api", "/sprites/"+s.Name+"/checkpoints/"+s.Version+"/restore", "-X", "POST", "-w", "\n%{http_code}")
	if err != nil {
		return s, ev, fmt.Errorf("the restore call: %w", err)
	}
	complete, why := restoreComplete(string(out), s.Version)
	// every postcondition failing is an error, so the host never rechecks through a name that may now be another's
	id, gone, err := s.lookup(ctx)
	if err != nil || gone {
		return s, ev, fmt.Errorf("the sprite after the restore: gone %v, %v", gone, err)
	}
	if ev.BoxAfter = id; id != s.SpriteID {
		return s, ev, fmt.Errorf("after the restore, sprite %s answers with ID %s, not %s", s.Name, id, s.SpriteID)
	}
	if _, ev.RestoreAfter, err = s.read(ctx); err != nil {
		return s, ev, err
	}
	switch {
	case !complete:
		return s, ev, errors.New("the restore didn't complete: " + why)
	case ev.RestoreAfter == ev.RestoreBefore:
		return s, ev, errors.New("the provider's Current checkpoint didn't change")
	}
	ev.Done = true
	return s, ev, nil
}

// restoreComplete reads a restore call's response: NDJSON events, then the HTTP status. It completed only when the
// status is 200 and the last event is the complete event for exactly version, after no error event.
func restoreComplete(out, version string) (bool, string) {
	text := strings.TrimSpace(out)
	i := strings.LastIndex(text, "\n")
	if i < 0 || text[i+1:] != "200" {
		return false, "the call didn't answer 200"
	}
	var last struct{ Type, Data string }
	for _, line := range strings.Split(text[:i], "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var e struct{ Type, Data string }
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return false, "an event didn't parse"
		}
		if e.Type == "error" {
			return false, "the provider reported an error: " + e.Data
		}
		last = e
	}
	if last.Type != "complete" || last.Data != "Restore from "+version+" complete" {
		return false, fmt.Sprintf("the last event is %q %q, not the complete event for %s", last.Type, last.Data, version)
	}
	return true, ""
}

// Teardown destroys the sprite (PRV-1); Sandprobe creates no volumes on Sprites.
func (s *SpriteBox) Teardown(ctx context.Context, _ []obs.Volume) map[string]bool {
	return map[string]bool{"": s.Destroy(ctx) == nil}
}
