package host

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"sandprobe/internal/obs"
	"sandprobe/internal/strictjson"
)

// ExecBox is an existing box Sandprobe reaches through the person's own command, which starts a POSIX sh in the box,
// on the agent's path, reading stdin (PRV-15). Sandprobe neither creates nor deletes it. Every probe invocation is one
// script on that command's stdin: a scratch directory at one literal path fixed before the first upload, an exit and
// signal trap that removes it, the probe decoded from base64, and its run framed by fresh markers. After each
// invocation a separate one confirms the scratch path is gone.
type ExecBox struct {
	Command []string // the person's command, run without a shell, arguments as given
	Binary  []byte   // the shipped probe for the box's architecture
	Scratch string   // <dir>/sandprobe-<24 hex>, fixed before the first upload
	Env     []string // the command's environment when set: a recipe's sp_shell gets its box's ID and name here (RCP-2)
	// Guard runs before every invocation when set, and stops it on an error: a name-addressed recipe's sp_whois (RCP-2).
	Guard func(context.Context) error

	uid     int    // the uid every invocation after the preflight is bound to (-expect-uid)
	bound   bool   // set by Bind
	pending bool   // an invocation ended without its removal confirmed
	owner   string // a random mark written into the scratch right after its exclusive mkdir: only a path carrying it is ours
	foreign bool   // the scratch path exists without the mark: never removed, only reported
}

var (
	scratchDir  = regexp.MustCompile(`^/[A-Za-z0-9._/-]{0,200}$`)
	scratchPath = regexp.MustCompile(`^/[A-Za-z0-9._/-]{0,200}/sandprobe-[0-9a-f]{24}$|^/sandprobe-[0-9a-f]{24}$`)
	execArg     = regexp.MustCompile(`^[A-Za-z0-9._:/=,-]{1,128}$`)
	// ExecCommandLimit bounds each invocation of the person's command; tests shorten it.
	ExecCommandLimit = 3 * time.Minute
)

// NewExecBox checks the person's command and scratch directory, and fixes the scratch path (PRV-15).
func NewExecBox(command []string, binary []byte, dir string) (*ExecBox, error) {
	if len(command) == 0 || command[0] == "" {
		return nil, errors.New("run exec needs a command that starts sh in the box, after --")
	}
	if _, err := exec.LookPath(command[0]); err != nil {
		return nil, fmt.Errorf("the command %q isn't on this machine's PATH", command[0])
	}
	if dir == "" {
		dir = "/tmp"
	}
	if !scratchDir.MatchString(dir) || path.Clean(dir) != dir || strings.Contains(dir, "..") {
		return nil, errors.New("-scratch takes an absolute directory: letters, digits and . _ / - only")
	}
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, errors.New("no randomness for the scratch path")
	}
	p := path.Join(dir, "sandprobe-"+hex.EncodeToString(b[:]))
	if !scratchPath.MatchString(p) {
		return nil, errors.New("the scratch path isn't valid")
	}
	owner, err := token24()
	if err != nil {
		return nil, err
	}
	return &ExecBox{Command: command, Binary: binary, Scratch: p, owner: owner}, nil
}

// ID names the box by the person's command, since it has no provider ID: an existing box (PRV-1).
func (b *ExecBox) ID() string {
	sum := sha256.Sum256([]byte(strings.Join(b.Command, "\x00")))
	return "exec-" + hex.EncodeToString(sum[:6])
}

// Preflight is PRV-15's identity-only first invocation: the probe's four uids, as's uid in the box, and the box's
// temporary directory. No check runs. With as given, the run stops unless all four uids are as's.
func (b *ExecBox) Preflight(ctx context.Context, as string) (obs.WhoAmI, error) {
	var w obs.WhoAmI
	args := []string{"-whoami"}
	if as != "" {
		args = append(args, as)
	}
	out, err := b.invoke(ctx, args, nil)
	if err != nil {
		return w, err
	}
	if err := strictjson.Decode(out, obs.MaxDoc, &w); err != nil || w.Schema != obs.WhoAmISchema {
		return w, errors.New("the preflight's answer didn't parse")
	}
	if as != "" && w.NameUID == nil {
		return w, fmt.Errorf("the box has no user %q", as)
	}
	want := w.UIDs[0]
	if w.NameUID != nil {
		want = *w.NameUID
	}
	for _, u := range w.UIDs {
		if u != want {
			return w, fmt.Errorf("the command runs as uids %d/%d/%d/%d, not %s's %d: nothing else runs (PRV-15)",
				w.UIDs[0], w.UIDs[1], w.UIDs[2], w.UIDs[3], as, want)
		}
	}
	b.uid, b.bound = want, true
	return w, nil
}

// Probe runs the shipped probe bound to the preflight's uid, so it refuses at startup as anyone else (PRV-15).
func (b *ExecBox) Probe(ctx context.Context, args []string, stdin []byte) ([]byte, error) {
	if !b.bound {
		return nil, errors.New("no identity preflight: nothing runs before the user is bound (PRV-15)")
	}
	return b.invoke(ctx, append([]string{"-expect-uid", strconv.Itoa(b.uid)}, args...), stdin)
}

// invoke runs one wrapped probe invocation, then a separate one confirming the scratch path is gone.
func (b *ExecBox) invoke(ctx context.Context, args []string, stdin []byte) ([]byte, error) {
	if b.pending {
		return nil, fmt.Errorf("an earlier invocation's scratch %s isn't confirmed gone: %s", b.Scratch, b.RemovalCommand())
	}
	for _, a := range args {
		if !execArg.MatchString(a) {
			return nil, fmt.Errorf("not a probe argument: %q", a)
		}
	}
	tok, err := token24()
	if err != nil {
		return nil, err
	}
	if b.owner == "" {
		if b.owner, err = token24(); err != nil {
			return nil, err
		}
	}
	b.pending = true
	stdout, runErr := b.run(ctx, b.script(tok, args, stdin))
	out, status, framed := unframe(stdout, tok)
	if framed && status == 97 { // the path was there before this invocation: not ours, so nothing to remove
		b.pending = false
	} else if err := b.confirmGone(ctx); err == nil {
		b.pending = false
	}
	switch {
	case framed && status == 97:
		return nil, fmt.Errorf("the scratch path %s already exists in the box: nothing ran", b.Scratch)
	case framed && status == 98:
		return nil, errors.New("the box couldn't decode the probe: it needs a working base64")
	case runErr != nil: // whatever the output framed, a command that failed doesn't count as a probe run
		return nil, fmt.Errorf("the command failed: %w", runErr)
	case !framed:
		return nil, errors.New("the box's shell never framed a probe run: is the command one that starts sh?")
	case status != 0:
		return out, fmt.Errorf("the probe exited %d", status)
	}
	return out, nil
}

// script is one invocation: everything literal but the probe and its input, which travel base64 in heredocs whose
// delimiters carry a fresh token.
func (b *ExecBox) script(tok string, args []string, stdin []byte) []byte {
	var s bytes.Buffer
	q := "'" + b.Scratch + "'" // scratchPath allows no quote
	fmt.Fprintf(&s, "umask 077\nmkdir -m 700 %s 2>/dev/null || { printf '%%s %%d\\n' 'SP-START-%s' 97; exit 0; }\n", q, tok)
	// The mark goes in first, so every removal (the trap included) can check it: one the box swapped in isn't ours.
	fmt.Fprintf(&s, "printf '%%s\\n' '%s' > %s/.sp-owner || { rmdir %s 2>/dev/null; exit 0; }\n%s\ntrap sp_clean EXIT HUP INT TERM\n",
		b.owner, q, q, b.cleanFunc())
	heredoc := func(dst, tag string, data []byte) {
		fmt.Fprintf(&s, "base64 -d > %s/%s <<'SP-%s-%s' || { printf '%%s %%d\\n' 'SP-START-%s' 98; exit 0; }\n", q, dst, tag, tok, tok)
		enc := base64.StdEncoding.EncodeToString(data)
		for len(enc) > 76 {
			s.WriteString(enc[:76] + "\n")
			enc = enc[76:]
		}
		s.WriteString(enc + "\nSP-" + tag + "-" + tok + "\n")
	}
	heredoc("p", "BIN", b.Binary)
	heredoc("in", "IN", stdin)
	fmt.Fprintf(&s, "chmod 700 %s/p\nprintf '%%s\\n' 'SP-START-%s'\nSANDPROBE_TWIN=1 %s/p %s < %s/in\nrc=$?\nprintf '\\n%%s %%d\\n' 'SP-END-%s' \"$rc\"\n",
		q, tok, q, strings.Join(args, " "), q, tok)
	return s.Bytes()
}

// unframe finds this invocation's own markers. Anything outside them (a banner, a motd) is ignored. A start marker
// carrying a status is the wrapper's own refusal.
func unframe(out []byte, tok string) ([]byte, int, bool) {
	start := []byte("SP-START-" + tok)
	i := bytes.Index(out, start)
	if i < 0 {
		return nil, 0, false
	}
	rest := out[i+len(start):]
	if line, _, _ := bytes.Cut(rest, []byte("\n")); len(bytes.TrimSpace(line)) > 0 { // "SP-START-<tok> 97"
		n, err := strconv.Atoi(string(bytes.TrimSpace(line)))
		return nil, n, err == nil
	}
	rest = rest[bytes.IndexByte(rest, '\n')+1:]
	end := []byte("\nSP-END-" + tok + " ")
	j := bytes.LastIndex(rest, end)
	if j < 0 {
		return nil, 0, false
	}
	line, _, _ := bytes.Cut(rest[j+len(end):], []byte("\n"))
	n, err := strconv.Atoi(string(bytes.TrimSpace(line)))
	return rest[:j], n, err == nil
}

// confirmGone is the separate invocation after each one: it removes the scratch path if a killed shell left it, and
// reports it gone only when the removal succeeded, nothing answers at that path, and its parent is a directory the
// shell can search, so "can't tell" is never "gone". A command that fails confirms nothing.
func (b *ExecBox) confirmGone(ctx context.Context) error {
	tok, err := token24()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	q, parent := "'"+b.Scratch+"'", "'"+path.Dir(b.Scratch)+"'"
	// Only a directory carrying this box's mark is ours to remove; anything else at the path is left alone.
	script := fmt.Sprintf("if [ -e %[1]s ] || [ -L %[1]s ]; then\n"+
		"  if %[3]s; then rm -rf %[1]s; rc=$?\n"+
		"  else printf '%%s\\n' 'SP-FOREIGN-%[4]s'; rc=1; fi\n"+
		"else rc=0; fi\n"+
		"if [ \"$rc\" -ne 0 ] || [ -e %[1]s ] || [ -L %[1]s ] || ! [ -d %[2]s ] || ! [ -x %[2]s ]; then printf '%%s\\n' 'SP-STILL-%[4]s'; "+
		"else printf '%%s\\n' 'SP-GONE-%[4]s'; fi\n", q, parent, b.ownedTest(), tok)
	out, runErr := b.run(ctx, []byte(script))
	b.foreign = runErr == nil && bytes.Contains(out, []byte("SP-FOREIGN-"+tok))
	if runErr == nil && bytes.Contains(out, []byte("SP-GONE-"+tok)) && !bytes.Contains(out, []byte("SP-STILL-"+tok)) {
		return nil
	}
	if b.foreign {
		return fmt.Errorf("the scratch path %s exists without this run's mark, so it isn't Sandprobe's: left alone", b.Scratch)
	}
	return fmt.Errorf("the scratch %s isn't confirmed gone", b.Scratch)
}

// Cleanup confirms the last scratch path is gone, or names it and the command that removes it (PRV-1).
func (b *ExecBox) Cleanup(ctx context.Context) error {
	if !b.pending {
		return nil
	}
	if err := b.confirmGone(ctx); err != nil {
		if b.foreign { // never suggest removing what isn't ours
			return fmt.Errorf("%w; check it yourself", err)
		}
		return fmt.Errorf("%w; remove it with: %s", err, b.RemovalCommand())
	}
	b.pending = false
	return nil
}

// ownedTest is true in the box's shell only for a real directory (not a link) at the scratch path carrying this box's
// owner mark: the one test every removal makes first.
func (b *ExecBox) ownedTest() string {
	q := "'" + b.Scratch + "'"
	return fmt.Sprintf("[ -d %[1]s ] && ! [ -L %[1]s ] && [ \"$(cat %[1]s/.sp-owner 2>/dev/null)\" = '%[2]s' ]", q, b.owner)
}

// cleanFunc is the wrapper's exit and signal trap: it removes the scratch path only if it's ours.
func (b *ExecBox) cleanFunc() string {
	return fmt.Sprintf("sp_clean() { if %s; then rm -rf '%s'; fi; }", b.ownedTest(), b.Scratch)
}

// RemovalCommand is what removes the scratch path by hand, through the person's own command, and only if it still
// carries this box's mark.
func (b *ExecBox) RemovalCommand() string {
	quoted := make([]string, len(b.Command))
	for i, a := range b.Command {
		quoted[i] = shellQuote(a)
	}
	return "echo " + shellQuote(b.cleanFunc()+"; sp_clean") + " | " + strings.Join(quoted, " ")
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// run is one invocation of the person's command with script on stdin, bounded, its output capped.
func (b *ExecBox) run(ctx context.Context, script []byte) ([]byte, error) {
	if b.Guard != nil {
		if err := b.Guard(ctx); err != nil {
			return nil, err
		}
	}
	ctx, cancel := context.WithTimeout(ctx, ExecCommandLimit)
	defer cancel()
	cmd := exec.CommandContext(ctx, b.Command[0], b.Command[1:]...)
	cmd.Env, cmd.WaitDelay = b.Env, 5*time.Second
	cmd.Stdin = bytes.NewReader(script)
	out := &capped{max: obs.MaxDoc + 64<<10}
	cmd.Stdout, cmd.Stderr = out, &capped{max: 4 << 10}
	err := cmd.Run()
	return out.Bytes(), err
}

func token24() (string, error) {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", errors.New("no randomness for the invocation's markers")
	}
	return hex.EncodeToString(b[:]), nil
}

// Arch asks the box which of the shipped probes it runs, before the identity preflight (PRV-15): one invocation printing
// uname -m between fresh markers. No probe runs, no check, nothing is written. The answer only chooses a binary; a wrong
// one fails to start, and SBX-5's digest catches a broken upload.
func (b *ExecBox) Arch(ctx context.Context) (string, error) {
	tok, err := token24()
	if err != nil {
		return "", err
	}
	out, runErr := b.run(ctx, []byte(fmt.Sprintf("printf '%%s %%s\\n' 'SP-ARCH-%s' \"$(uname -m)\"\n", tok)))
	if runErr != nil { // like every invocation, an answer through a command that failed counts for nothing
		return "", fmt.Errorf("the command failed: %w", runErr)
	}
	i := bytes.Index(out, []byte("SP-ARCH-"+tok+" "))
	if i < 0 {
		return "", errors.New("the box's shell didn't answer: is the command one that starts sh?")
	}
	m, _, _ := bytes.Cut(out[i+len("SP-ARCH-"+tok+" "):], []byte("\n"))
	switch strings.TrimSpace(string(m)) {
	case "x86_64", "amd64":
		return "amd64", nil
	case "aarch64", "arm64":
		return "arm64", nil
	}
	return "", errors.New("the box runs an architecture sandprobe carries no probe for")
}

// ExecExclusions are PRV-15's default for a box whose provider isn't identified: the checks that would contact a
// provider-owned endpoint, off unless the person turns one on for their own account.
func ExecExclusions() map[string]string {
	why := "run exec doesn't know this box's provider, so checks that contact a provider-owned endpoint are off by default (PRV-15)"
	return map[string]string{"SEC-4": why, "EGR-3": why, "AMP-6": why, "AMP-7": why}
}

// TermsExclusions is each native adapter's PRV-row exclusions by the provider name its reports record (PRV-5): the
// provider's terms exclude its own endpoints, so a report naming that provider may mark them provider_terms (SCR-2).
// It is the binary's own policy, so a scorecard never takes a saved report's word for a kind.
var TermsExclusions = map[string]func() map[string]string{
	"sprites": SpritesExclusions, "e2b": E2BExclusions, "daytona": DaytonaExclusions, "vercel": VercelExclusions,
	"cloudflare": CloudflareExclusions, "boat": BoatExclusions, "baseten": BasetenExclusions, "exe.dev": ExedevExclusions,
	"modal": func() map[string]string { return ModalExcluded },
}

// ExecResidual is what a run exec report says it can't vouch for (PRV-1, PRV-2).
const ExecResidual = "This is an existing box, reached through your own command: the boundary is your word that it's the agent's box and " +
	"not production (PRV-2). Sandprobe didn't create, reset or delete it; it placed only a scratch directory, removed after each " +
	"invocation. Persistence across a reset (PER-5) isn't tested, and the four checks that would contact your provider's own " +
	"endpoints are off by default."
