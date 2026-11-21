package host

// PRV-13: exe.dev is name-addressed. No guest claim is an immutable provider ID.
import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"

	"sandprobe/internal/obs"
	"sandprobe/internal/strictjson"
)

const ExedevResidual = "exe.dev Ubuntu 24.04 standalone CPU VM, egress=all, no integrations or app/model credentials supplied. API operations address a reusable name, not an immutable ID. Birth/region/run-tag checks reduce but cannot eliminate a same-account name-replacement race. Cleanup proves acknowledged named deletion and scoped API absence, not provider-internal erasure. No provider-enforced expiry; after a host crash compute may cost money until journal cleanup. No reset evidence."

const exLimit = 1 << 20

var exName = regexp.MustCompile(`^sandprobe-[a-f0-9]{24}$`)
var exNonce = regexp.MustCompile(`^n[a-f0-9]{24}$`)
var exDir = regexp.MustCompile(`^/tmp/\.sandprobe-[A-Za-z0-9]{12}$`)

type ExedevClient struct {
	key, endpoint, account string
	http                   *http.Client
}

func NewExedevClient(key string) (*ExedevClient, error) {
	if !validVercelKey(key) || !strings.HasPrefix(key, "exe1.") {
		return nil, errors.New("exe.dev token missing or malformed")
	}
	return &ExedevClient{key: key, endpoint: "https://exe.dev/exec", http: &http.Client{Timeout: 25 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

// ExedevKey deliberately has no environment-value fallback or JSON token echo.
func ExedevKey(path string) (string, error) {
	raw, err := exPrivateFile(path, 8192)
	if err != nil {
		return "", err
	}
	key := strings.TrimSpace(string(raw))
	if _, err = NewExedevClient(key); err != nil {
		return "", err
	}
	return key, nil
}

func exPrivateFile(path string, max int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("exe.dev private file unavailable")
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		return nil, errors.New("exe.dev private file must be regular and owner-only")
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Getuid()) {
		return nil, errors.New("exe.dev private file not owned")
	}
	raw, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(raw)) > max {
		return nil, errors.New("exe.dev private file too large or unreadable")
	}
	return raw, nil
}

// request never retries or returns transport/provider text containing commands or keys.
func (c *ExedevClient) request(ctx context.Context, command string, stream bool) ([]byte, error) {
	if len(command) == 0 || len(command) > 60*1024 {
		return nil, errors.New("exe.dev request size invalid")
	}
	req, err := http.NewRequestWithContext(ctx, "POST", c.endpoint, strings.NewReader(command))
	if err != nil {
		return nil, errors.New("exe.dev request invalid")
	}
	req.Header.Set("Authorization", "Bearer "+c.key)
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Accept", "application/json")
	if stream {
		req.Header.Set("Accept", "application/x-ndjson")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, errors.New("exe.dev transport failed; operation outcome may be unknown")
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 2*exLimit+1))
	if err != nil || len(raw) > 2*exLimit {
		return nil, errors.New("exe.dev response incomplete or too large")
	}
	if stream {
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("exe.dev API HTTP %d", resp.StatusCode)
		}
		if strings.ToLower(strings.TrimSpace(strings.Split(resp.Header.Get("Content-Type"), ";")[0])) != "application/x-ndjson" {
			return nil, errors.New("exe.dev command response was not NDJSON")
		}
		return exOutput(raw)
	}
	// Management allows future fields but not duplicate/case-aliased keys or trailing JSON.
	var obj map[string]json.RawMessage
	if strictjson.Decode(raw, 2*exLimit, &obj) != nil || obj == nil {
		return nil, errors.New("exe.dev management response invalid")
	}
	var refusal error
	if resp.StatusCode != http.StatusOK {
		refusal = fmt.Errorf("exe.dev API HTTP %d", resp.StatusCode)
	}
	for key := range obj {
		if strings.EqualFold(key, "error") {
			refusal = errors.New("exe.dev management request refused")
		}
	}
	if refusal != nil {
		if strings.HasPrefix(command, "new ") {
			return raw, refusal
		} // preserve explicit create identity, never error text
		return nil, refusal
	}
	return raw, nil
}

func exOutput(raw []byte) ([]byte, error) {
	s := bufio.NewScanner(bytes.NewReader(raw))
	s.Buffer(make([]byte, 4096), 2*exLimit)
	var out []byte
	terminal := false
	for s.Scan() {
		line := bytes.TrimSpace(s.Bytes())
		if len(line) == 0 {
			continue
		}
		var frame map[string]json.RawMessage
		if terminal || strictjson.Decode(line, 2*exLimit, &frame) != nil || len(frame) != 1 {
			return nil, errors.New("exe.dev command frame invalid")
		}
		for key, value := range frame {
			switch key {
			case "stdout", "stderr":
				var encoded string
				if len(value) == 0 || value[0] != '"' || json.Unmarshal(value, &encoded) != nil {
					return nil, errors.New("exe.dev output encoding invalid")
				}
				b, err := base64.StdEncoding.Strict().DecodeString(encoded)
				if err != nil || len(out)+len(b) > exLimit || (key == "stderr" && len(b) != 0) {
					return nil, errors.New("exe.dev output limit, encoding or stderr failure")
				}
				if key == "stdout" {
					out = append(out, b...)
				}
			case "exit_code":
				if string(value) != "0" {
					return nil, errors.New("exe.dev command did not exit zero")
				}
				terminal = true
			default:
				return nil, errors.New("exe.dev command interrupted or unknown frame")
			}
		}
	}
	if s.Err() != nil || !terminal {
		return nil, errors.New("exe.dev command missing complete exit evidence")
	}
	return out, nil
}

func (c *ExedevClient) Available(ctx context.Context) error {
	raw, err := c.request(ctx, "whoami", false)
	if err != nil {
		return err
	}
	var who struct{ Email, Region string }
	if json.Unmarshal(raw, &who) != nil || who.Email == "" || len(who.Region) > 64 {
		return errors.New("exe.dev account identity unavailable")
	}
	hash := sha256.Sum256([]byte(who.Email))
	c.account = hex.EncodeToString(hash[:])
	return nil
}

type exInfo struct {
	Name   string   `json:"vm_name"`
	Born   string   `json:"created_at"`
	Region string   `json:"region"`
	Status string   `json:"status"`
	Egress string   `json:"egress_policy"`
	Tags   []string `json:"tags"`
}

type exJournal struct {
	Version     int       `json:"version"`
	Nonce       string    `json:"nonce"`
	Requested   time.Time `json:"requested"`
	Name        string    `json:"name"`
	Confirmed   bool      `json:"confirmed"`
	Born        string    `json:"born"`
	Region      string    `json:"region"`
	Account     string    `json:"account"`
	DeleteAck   bool      `json:"delete_ack"`
	DeleteSent  bool      `json:"delete_sent"`
	FailureHint string    `json:"failure_hint,omitempty"`
}

type ExedevBox struct {
	client  *ExedevClient
	journal exJournal
	state   string
	boot    string
	dir     string
	Arch    string
	Calls   []obs.ProviderCall
	removed bool
}

func (b *ExedevBox) ID() string              { return b.journal.Name }
func (b *ExedevBox) CreationConfirmed() bool { return b.journal.Confirmed }
func (b *ExedevBox) StatePath() string       { return b.state }
func (b *ExedevBox) runTag() string          { return "sandprobe-" + b.journal.Nonce }

func (b *ExedevBox) save() error {
	raw, _ := json.Marshal(b.journal)
	f, err := os.CreateTemp(filepath.Dir(b.state), ".exedev-state-")
	if err != nil {
		return errors.New("exe.dev journal update failed")
	}
	defer os.Remove(f.Name())
	_, err = f.Write(raw)
	if err == nil {
		err = f.Sync()
	}
	ce := f.Close()
	if err != nil || ce != nil || os.Rename(f.Name(), b.state) != nil {
		return errors.New("exe.dev journal update failed")
	}
	return exSyncDir(filepath.Dir(b.state))
}

func exSyncDir(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return errors.New("exe.dev journal directory sync failed")
	}
	defer d.Close()
	if d.Sync() != nil {
		return errors.New("exe.dev journal directory sync failed")
	}
	return nil
}

func (c *ExedevClient) CreateExedev(ctx context.Context, dir string) (*ExedevBox, error) {
	if c.account == "" {
		return nil, errors.New("exe.dev account preflight required")
	}
	if os.MkdirAll(dir, 0700) != nil {
		return nil, errors.New("exe.dev journal directory unavailable")
	}
	st, err := os.Lstat(dir)
	if err != nil || !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return nil, errors.New("exe.dev journal directory must be private")
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Getuid()) {
		return nil, errors.New("exe.dev journal directory not owned")
	}
	nonce := token("n")
	b := &ExedevBox{client: c, state: filepath.Join(dir, "exedev-active.state"), journal: exJournal{Version: 1, Nonce: nonce, Requested: time.Now().UTC(), Name: "sandprobe-" + strings.TrimPrefix(nonce, "n"), Account: c.account}}
	f, err := os.OpenFile(b.state, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, errors.New("exe.dev unresolved journal or concurrent run; cleanup before creating")
	}
	raw, _ := json.Marshal(b.journal)
	_, err = f.Write(raw)
	if err == nil {
		err = f.Sync()
	}
	ce := f.Close()
	if err != nil || ce != nil {
		return b, errors.New("exe.dev create intent could not be persisted")
	}
	if err = exSyncDir(dir); err != nil {
		return b, err
	}
	// MkdirAll may have created ancestors; persist every directory entry before billing can start.
	for parent := filepath.Dir(dir); ; parent = filepath.Dir(parent) {
		if err = exSyncDir(parent); err != nil {
			return b, err
		}
		if parent == filepath.Dir(parent) {
			break
		}
	}
	command := "new --sandbox --cpu=2 --memory=4GB --image=ubuntu:24.04 --egress=all --no-email --name=" + b.ID() + " --tag=sandprobe," + b.runTag() + " --env=SANDPROBE_TWIN=1"
	raw, createErr := b.request(ctx, command, false, "create")
	if raw == nil {
		return b, createErr
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	var returned string
	if json.Unmarshal(fields["vm_name"], &returned) != nil || returned != b.ID() {
		b.journal.FailureHint = exCreateHint(fields)
		if err = b.save(); err != nil {
			return b, err
		}
		if createErr != nil {
			return b, fmt.Errorf("exe.dev create refused (%s); name unconfirmed, retain intent: %w", b.journal.FailureHint, createErr)
		}
		return b, fmt.Errorf("exe.dev create name unconfirmed (%s); retain intent, no adoption", b.journal.FailureHint)
	}
	b.journal.Confirmed = true
	if err = b.save(); err != nil {
		return b, err
	}
	var bornText string
	if json.Unmarshal(fields["created_at"], &bornText) != nil {
		return b, errors.New("exe.dev create timestamp malformed; name retained")
	}
	born, e := time.Parse(time.RFC3339Nano, bornText)
	if e != nil || born.Before(b.journal.Requested.Add(-time.Minute)) || born.After(b.journal.Requested.Add(time.Minute)) {
		return b, errors.New("exe.dev create timestamp unconfirmed; name retained")
	}
	b.journal.Born = bornText
	if err = b.save(); err != nil {
		return b, err
	}
	if createErr != nil {
		return b, createErr
	}
	if err = b.check(ctx, true); err != nil {
		return b, err
	}
	return b, nil
}

// Only fixed labels leave the host. Provider text and arbitrary response keys
// can contain credentials and must never enter a journal, error or report.
func exCreateHint(fields map[string]json.RawMessage) string {
	text := ""
	for k, v := range fields {
		if strings.EqualFold(k, "error") || strings.EqualFold(k, "message") || strings.EqualFold(k, "reason") {
			var part string
			if len(v) <= 64*1024 && json.Unmarshal(v, &part) == nil {
				text += " " + strings.ToLower(part)
			}
		}
	}
	switch {
	case strings.Contains(text, "unknown flag") || strings.Contains(text, "unknown command") || strings.Contains(text, "unrecognized option"):
		return "command_contract"
	case strings.Contains(text, "standalone") && (strings.Contains(text, "not enabled") || strings.Contains(text, "not allowed") || strings.Contains(text, "disabled") || strings.Contains(text, "require")):
		return "standalone_access"
	case (strings.Contains(text, "plan") || strings.Contains(text, "subscription") || strings.Contains(text, "billing")) && (strings.Contains(text, "choose") || strings.Contains(text, "upgrade") || strings.Contains(text, "required") || strings.Contains(text, "no active") || strings.Contains(text, "payment")):
		return "billing_or_plan"
	case strings.Contains(text, "name") && (strings.Contains(text, "invalid") || strings.Contains(text, "too long") || strings.Contains(text, "must") || strings.Contains(text, "already")):
		return "name_contract"
	case strings.Contains(text, "permission") || strings.Contains(text, "not allowed") || strings.Contains(text, "forbidden"):
		return "permission"
	case strings.Contains(text, "image") && (strings.Contains(text, "invalid") || strings.Contains(text, "pull") || strings.Contains(text, "not found")):
		return "image_contract"
	default:
		return "unclassified_response"
	}
}

func (b *ExedevBox) request(ctx context.Context, command string, stream bool, operation string) ([]byte, error) {
	at := time.Now()
	raw, err := b.client.request(ctx, command, stream)
	call := obs.ProviderCall{At: at, Call: "exe.dev " + operation, ID: b.ID(), OK: err == nil}
	if err != nil {
		call.Error = "provider_error"
	}
	b.Calls = append(b.Calls, call)
	return raw, err
}

func (b *ExedevBox) lookup(ctx context.Context) (*exInfo, error) {
	if !exName.MatchString(b.ID()) {
		return nil, errors.New("exe.dev recorded name invalid")
	}
	raw, err := b.request(ctx, "ls "+b.ID(), false, "lookup")
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	var list []exInfo
	if fields["vms"] == nil || string(fields["vms"]) == "null" || json.Unmarshal(fields["vms"], &list) != nil {
		return nil, errors.New("exe.dev listing invalid")
	}
	if len(list) == 0 {
		return nil, nil
	}
	if len(list) != 1 || list[0].Name != b.ID() {
		return nil, errors.New("exe.dev lookup returned unexpected VM")
	}
	return &list[0], nil
}

func (b *ExedevBox) match(info *exInfo, running bool) error {
	if !b.journal.Confirmed || b.journal.Born == "" || info == nil || info.Name != b.ID() || info.Born != b.journal.Born || info.Region != b.journal.Region || !slices.Contains(info.Tags, "sandprobe") || !slices.Contains(info.Tags, b.runTag()) {
		return errors.New("exe.dev original name/birth/region/run tags not confirmed")
	}
	if running && (info.Status != "running" || info.Egress != "all") {
		return errors.New("exe.dev VM stopped or policy changed; no resume")
	}
	return nil
}
func (b *ExedevBox) check(ctx context.Context, running bool) error {
	info, err := b.lookup(ctx)
	if err != nil {
		return err
	}
	if err = b.bindRegion(info); err != nil {
		return err
	}
	return b.match(info, running)
}

// An account may have no default region. Bind only the confirmed create's
// first matching provider record; no lookup can adopt an unconfirmed name.
func (b *ExedevBox) bindRegion(info *exInfo) error {
	if b.journal.Region != "" {
		return nil
	}
	if !b.journal.Confirmed || b.journal.Born == "" || info == nil || info.Name != b.ID() || info.Born != b.journal.Born || !slices.Contains(info.Tags, "sandprobe") || !slices.Contains(info.Tags, b.runTag()) || info.Region == "" || len(info.Region) > 64 {
		return errors.New("exe.dev created VM region/identity not confirmed")
	}
	b.journal.Region = info.Region
	return b.save()
}

func exQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }

func (b *ExedevBox) command(ctx context.Context, script string) ([]byte, error) {
	if err := b.check(ctx, true); err != nil {
		return nil, err
	}
	if b.boot != "" {
		script = "test \"$(cat /proc/sys/kernel/random/boot_id)\" = " + exQuote(b.boot) + " || exit 91; " + script
	}
	// The lobby and guest shell each consume one layer of quoting.
	out, err := b.request(ctx, "ssh "+b.ID()+" "+exQuote("sh -c "+exQuote(script)), true, "exec")
	if err != nil {
		return nil, err
	}
	if err = b.check(ctx, true); err != nil {
		return nil, err
	}
	return out, nil
}

func (b *ExedevBox) DetectArch(ctx context.Context) error {
	out, err := b.command(ctx, "uname -m; cat /proc/sys/kernel/random/boot_id")
	if err != nil {
		return err
	}
	parts := strings.Fields(string(out))
	if len(parts) != 2 || !cfBoot.MatchString(parts[1]) {
		return errors.New("exe.dev architecture/boot evidence invalid")
	}
	switch parts[0] {
	case "x86_64":
		b.Arch = "amd64"
	case "aarch64", "arm64":
		b.Arch = "arm64"
	default:
		return errors.New("exe.dev architecture unsupported")
	}
	b.boot = parts[1]
	return nil
}

func exSum(data []byte) string { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }

func (b *ExedevBox) writeFile(ctx context.Context, path string, data []byte) error {
	if !exDir.MatchString(b.dir) || filepath.Dir(path) != b.dir || len(data) > 8*exLimit {
		return errors.New("exe.dev upload path or size invalid")
	}
	if _, err := b.command(ctx, "umask 077; : > "+path); err != nil {
		return err
	}
	for start := 0; start < len(data); start += 40 * 1024 {
		end := min(start+40*1024, len(data))
		chunk := base64.StdEncoding.EncodeToString(data[start:end])
		if _, err := b.command(ctx, "printf %s "+exQuote(chunk)+" | base64 -d >> "+path); err != nil {
			return err
		}
	}
	out, err := b.command(ctx, "sha256sum "+path)
	if err != nil {
		return err
	}
	if string(out) != exSum(data)+"  "+path+"\n" {
		return errors.New("exe.dev uploaded bytes digest mismatch")
	}
	return nil
}

func (b *ExedevBox) Upload(ctx context.Context, binary []byte) error {
	if b.boot == "" {
		return errors.New("exe.dev boot identity required")
	}
	out, err := b.command(ctx, "umask 077; mktemp -d /tmp/.sandprobe-XXXXXXXXXXXX")
	if err != nil {
		return err
	}
	b.dir = strings.TrimSpace(string(out))
	if !exDir.MatchString(b.dir) {
		return errors.New("exe.dev scratch directory invalid")
	}
	var compressed bytes.Buffer
	z := gzip.NewWriter(&compressed)
	if _, err = z.Write(binary); err != nil {
		return errors.New("exe.dev compression failed")
	}
	if err = z.Close(); err != nil {
		return errors.New("exe.dev compression failed")
	}
	if err = b.writeFile(ctx, b.dir+"/probe.gz", compressed.Bytes()); err != nil {
		return err
	}
	out, err = b.command(ctx, "gzip -dc "+b.dir+"/probe.gz > "+b.dir+"/probe && chmod 700 "+b.dir+"/probe && sha256sum "+b.dir+"/probe")
	if err != nil {
		return err
	}
	if string(out) != exSum(binary)+"  "+b.dir+"/probe\n" {
		return errors.New("exe.dev probe digest mismatch")
	}
	return nil
}

// Probe uses one acknowledged launch and short polls; /exec's per-request limit
// never truncates the common 90-second probe into a false success (PRV-13).
func (b *ExedevBox) Probe(ctx context.Context, args []string, input []byte) ([]byte, error) {
	if !exDir.MatchString(b.dir) || b.boot == "" {
		return nil, errors.New("exe.dev probe not uploaded")
	}
	suffix := ""
	if len(args) == 1 && args[0] == "-survey" {
		suffix = " -survey"
	} else if len(args) != 0 {
		return nil, errors.New("exe.dev probe mode invalid")
	}
	base := b.dir + "/" + token("i")
	if err := b.writeFile(ctx, base+".in", input); err != nil {
		return nil, err
	}
	worker := "umask 077; timeout -k 2s 95s " + b.dir + "/probe" + suffix + " < " + base + ".in > " + base + ".out 2> " + base + ".err; code=$?; rm -f " + base + ".in; printf '%s\\n' \"$code\" > " + base + ".tmp; mv " + base + ".tmp " + base + ".done"
	launch := "umask 077; nohup setsid sh -c " + exQuote(worker) + " < /dev/null > /dev/null 2>&1 & printf 'started\\n'"
	out, err := b.command(ctx, launch)
	if err != nil {
		return nil, err
	}
	if string(out) != "started\n" {
		return nil, errors.New("exe.dev launch unconfirmed; not retried")
	}
	for {
		poll := "if test -f " + base + ".done; then test ! -s " + base + ".err || exit 92; test \"$(wc -c < " + base + ".out)\" -le 1048000 || exit 93; printf 'complete\\n'; cat " + base + ".done " + base + ".out; else printf 'pending\\n'; fi"
		out, err = b.command(ctx, poll)
		if err != nil {
			return nil, err
		}
		if bytes.HasPrefix(out, []byte("complete\n0\n")) {
			return out[len("complete\n0\n"):], nil
		}
		if string(out) != "pending\n" {
			return nil, errors.New("exe.dev probe exit/completion evidence invalid")
		}
		select {
		case <-ctx.Done():
			return nil, errors.New("exe.dev probe interrupted or deadline")
		case <-time.After(time.Second):
		}
	}
}

func (b *ExedevBox) Destroy(ctx context.Context) error {
	if b.removed {
		return nil
	}
	if !b.journal.Confirmed || b.journal.Born == "" {
		return errors.New("exe.dev create unresolved; retain intent, no name adoption")
	}
	if b.client.account != b.journal.Account {
		return errors.New("exe.dev cleanup account mismatch")
	}
	info, err := b.lookup(ctx)
	if err != nil {
		return err
	}
	if b.journal.DeleteAck && info == nil {
		return b.retire()
	}
	if err = b.bindRegion(info); err != nil {
		return err
	}
	if err = b.match(info, false); err != nil {
		return err
	}
	if b.journal.DeleteAck {
		return errors.New("exe.dev acknowledged deletion still visible; retain journal")
	}
	if b.journal.DeleteSent {
		return errors.New("exe.dev prior deletion outcome unresolved; no mutation retry")
	}
	b.journal.DeleteSent = true
	if err = b.save(); err != nil {
		return err
	}
	raw, err := b.request(ctx, "rm "+b.ID(), false, "delete")
	if err != nil {
		return err
	}
	var result struct {
		Deleted  []string                   `json:"deleted"`
		Failed   []string                   `json:"failed"`
		NotFound []string                   `json:"not_found"`
		Errors   map[string]json.RawMessage `json:"errors"`
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	if len(fields["deleted"]) == 0 || fields["deleted"][0] != '[' || len(fields["failed"]) == 0 || fields["failed"][0] != '[' || json.Unmarshal(raw, &result) != nil || len(result.Deleted) != 1 || result.Deleted[0] != b.ID() || len(result.Failed) != 0 || len(result.NotFound) != 0 || len(result.Errors) != 0 {
		return errors.New("exe.dev original-name deletion not acknowledged")
	}
	b.journal.DeleteAck = true
	if err = b.save(); err != nil {
		return err
	}
	for {
		info, err = b.lookup(ctx)
		if err != nil {
			return err
		}
		if info == nil {
			return b.retire()
		}
		if err = b.match(info, false); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return errors.New("exe.dev deletion absence unconfirmed")
		case <-time.After(time.Second):
		}
	}
}
func (b *ExedevBox) retire() error {
	if os.Remove(b.state) != nil {
		return errors.New("exe.dev deleted but journal retirement failed")
	}
	if err := exSyncDir(filepath.Dir(b.state)); err != nil {
		return err
	}
	b.removed = true
	return nil
}

func (c *ExedevClient) LoadExedev(path string) (*ExedevBox, error) {
	raw, err := exPrivateFile(path, 16*1024)
	if err != nil {
		return nil, err
	}
	var j exJournal
	if strictjson.Decode(raw, 16*1024, &j) != nil || j.Version != 1 || !exName.MatchString(j.Name) || !exNonce.MatchString(j.Nonce) || j.Name != "sandprobe-"+strings.TrimPrefix(j.Nonce, "n") || j.Requested.IsZero() || j.Account != c.account || !j.Confirmed || (j.DeleteAck && !j.DeleteSent) {
		return nil, errors.New("exe.dev cleanup journal invalid or create unresolved")
	}
	born, e := time.Parse(time.RFC3339Nano, j.Born)
	if e != nil || born.Before(j.Requested.Add(-time.Minute)) || born.After(j.Requested.Add(5*time.Minute)) {
		return nil, errors.New("exe.dev cleanup birth invalid")
	}
	return &ExedevBox{client: c, journal: j, state: path}, nil
}

func ExedevExclusions() map[string]string {
	return map[string]string{"SEC-4": "exe.dev scope excludes metadata (PRV-13)", "EGR-3": "exe.dev scope excludes provider proxy requests (PRV-13)", "AMP-6": "exe.dev scope excludes vsock (PRV-13)", "AMP-7": "exe.dev scope excludes Kubernetes API (PRV-13)"}
}
