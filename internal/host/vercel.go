package host

// PRV-9: native Vercel Sandbox wire contract, verified against official SDK3.9.1.
import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"sandprobe/internal/obs"
)

const VercelResidual = "Vercel runtime and stop target the immutable create-returned session ID. Sandbox record deletion uses a guarded random name; the identity check/delete race remains. No resume, persistence, snapshots or drives. The dedicated project is retained as an explicit setup residual; no deployments."

var vercelID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
var vercelName = regexp.MustCompile(`^sandprobe-[a-f0-9]{24}$`)
var vercelScratch = regexp.MustCompile(`^/vercel(/sandbox)?/\.sandprobe-[A-Za-z0-9]{12}$`)

func VercelKey(file string) (string, error) {
	key := os.Getenv("VERCEL_TOKEN")
	if file != "" {
		f, err := os.OpenFile(file, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return "", errors.New("Vercel token file unavailable")
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
			return "", errors.New("Vercel token file must be regular and owner-only")
		}
		owner, ok := st.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != uint32(os.Getuid()) {
			return "", errors.New("Vercel token file not owned")
		}
		raw, err := io.ReadAll(io.LimitReader(f, 8193))
		if err != nil || len(raw) > 8192 {
			return "", errors.New("Vercel token file invalid")
		}
		key = strings.TrimSpace(string(raw))
	}
	if !validVercelKey(key) {
		return "", errors.New("Vercel token missing or malformed")
	}
	return key, nil
}
func validVercelKey(key string) bool {
	return key != "" && len(key) <= 8192 && strings.IndexFunc(key, func(r rune) bool { return r <= 32 || r >= 127 }) < 0
}

type VercelClient struct {
	key, Team, Project, endpoint string
	http                         *http.Client
}

func NewVercelClient(key, team, project string) (*VercelClient, error) {
	if !validVercelKey(key) || !vercelID.MatchString(team) || !strings.HasPrefix(team, "team_") || !vercelID.MatchString(project) || !strings.HasPrefix(project, "prj_") {
		return nil, errors.New("Vercel token or explicit team/project selector invalid")
	}
	return &VercelClient{key: key, Team: team, Project: project, endpoint: "https://vercel.com/api", http: &http.Client{Timeout: 120 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

type vercelHTTPError struct {
	code      int
	operation string
	hint      string
}

func (e *vercelHTTPError) Error() string {
	return fmt.Sprintf("Vercel %s HTTP %d%s", e.operation, e.code, e.hint)
}

// PRV-9: only fixed operation labels and status escape, never URL/body/token.
func vercelOperation(method, path string) string {
	switch {
	case method == "POST" && path == "/v3/sandboxes":
		return "create sandbox"
	case method == "GET" && strings.HasPrefix(path, "/v9/projects/"):
		return "verify project"
	case strings.HasPrefix(path, "/v2/sandboxes/sessions/"):
		switch {
		case strings.HasSuffix(path, "/cmd"):
			return "execute command"
		case strings.HasSuffix(path, "/fs/write"):
			return "upload private file"
		case strings.HasSuffix(path, "/stop"):
			return "stop immutable session"
		default:
			return "get immutable session"
		}
	case method == "GET" && strings.HasPrefix(path, "/v2/sandboxes/"):
		return "get sandbox without resume"
	case method == "DELETE" && strings.HasPrefix(path, "/v2/sandboxes/"):
		return "delete guarded sandbox"
	default:
		return "request"
	}
}

// PRV-9: inspect only bounded error text in memory; emit fixed vocabulary, never text/code/values.
func vercelErrorHint(reader io.Reader) string {
	const limit = 64 * 1024
	raw, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil || len(raw) > limit {
		return ""
	}
	var body struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(raw, &body) != nil {
		return ""
	}
	message := strings.ToLower(body.Error.Message)
	var hints []string
	categories := []struct {
		label string
		words []string
	}{
		{"request validation", []string{"invalid request", "validation", "additional propert", "schema"}},
		{"session state", []string{"not running", "not ready", "stopped"}},
		{"missing executable or path", []string{"not found", "no such file", "enoent"}},
		{"working directory", []string{"working directory", "cwd"}},
		{"permission", []string{"permission", "access denied"}},
		{"feature eligibility", []string{"feature", "experimental"}},
		{"quota", []string{"quota", "insufficient"}},
		{"credential rejection", []string{"unauthorized", "invalid token", "token expired"}},
	}
	for _, category := range categories {
		for _, word := range category.words {
			if strings.Contains(message, word) {
				hints = append(hints, category.label)
				break
			}
		}
	}
	for _, field := range []string{"command", "args", "cwd", "env", "sudo", "timeout", "wait", "logs", "resume", "projectId", "teamId", "name", "image", "mounts", "persistent", "resources", "networkPolicy"} {
		// Match whole field names only; even a match emits just this fixed label.
		re := regexp.MustCompile(`(?i)(^|[^a-z0-9_])` + regexp.QuoteMeta(field) + `([^a-z0-9_]|$)`)
		if re.MatchString(message) {
			hints = append(hints, "field "+field)
		}
	}
	if len(hints) == 0 {
		return ""
	}
	return " (provider wording mentions: " + strings.Join(hints, ", ") + ")"
}

func vercelStatus(err error, code int) bool {
	var e *vercelHTTPError
	return errors.As(err, &e) && e.code == code
}
func (c *VercelClient) do(ctx context.Context, method, path, contentType string, body []byte, headers map[string]string) (*http.Response, error) {
	u, err := url.Parse(c.endpoint + path)
	if err != nil {
		return nil, errors.New("Vercel request invalid")
	}
	q := u.Query()
	q.Set("teamId", c.Team)
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("Vercel request invalid")
	}
	req.Header.Set("Authorization", "Bearer "+c.key)
	req.Header.Set("Content-Type", contentType)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, errors.New("Vercel request failed (transport or deadline)")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		hint := vercelErrorHint(resp.Body)
		resp.Body.Close()
		return nil, &vercelHTTPError{code: resp.StatusCode, operation: vercelOperation(method, path), hint: hint}
	}
	return resp, nil
}
func (c *VercelClient) request(ctx context.Context, method, path string, body any, out any) error {
	var raw []byte
	var err error
	if body != nil {
		raw, err = json.Marshal(body)
		if err != nil {
			return errors.New("Vercel request invalid")
		}
	}
	resp, err := c.do(ctx, method, path, "application/json", raw, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if out == nil {
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, obs.MaxDoc+1))
	if err != nil || len(data) > obs.MaxDoc || json.Unmarshal(data, out) != nil {
		return errors.New("Vercel response incomplete, oversized or malformed")
	}
	return nil
}
func (c *VercelClient) Available(ctx context.Context) error {
	var p struct {
		ID, AccountID string
		Name          string
	}
	// Project JSON uses accountId rather than Go's underscore conventions.
	var response struct {
		ID      string `json:"id"`
		Account string `json:"accountId"`
		Name    string `json:"name"`
	}
	if err := c.request(ctx, "GET", "/v9/projects/"+c.Project, nil, &response); err != nil {
		return err
	}
	p.ID, p.AccountID = response.ID, response.Account
	if p.ID != c.Project || p.AccountID != c.Team {
		return errors.New("Vercel project does not belong to selected team")
	}
	return nil
}

type vercelSession struct {
	Cwd       string `json:"cwd"`
	ID        string `json:"id"`
	Status    string `json:"status"`
	Created   int64  `json:"createdAt"`
	Requested int64  `json:"requestedAt"`
	Started   int64  `json:"startedAt"`
	Timeout   int64  `json:"timeout"`
}
type vercelSandbox struct {
	Name       string                     `json:"name"`
	Persistent *bool                      `json:"persistent"`
	Created    int64                      `json:"createdAt"`
	SessionID  string                     `json:"currentSessionId"`
	SnapshotID string                     `json:"currentSnapshotId"`
	Mounts     map[string]json.RawMessage `json:"mounts"`
	Tags       map[string]string          `json:"tags"`
}
type vercelReply struct {
	Sandbox vercelSandbox `json:"sandbox"`
	Session vercelSession `json:"session"`
}
type vercelJournal struct {
	WorkDir   string    `json:"working_directory,omitempty"`
	Team      string    `json:"team_id"`
	Project   string    `json:"project_id"`
	Requested string    `json:"requested_name"`
	SessionID string    `json:"session_id,omitempty"`
	Created   int64     `json:"sandbox_created_at,omitempty"`
	At        time.Time `json:"create_requested_at"`
}
type VercelBox struct {
	client          *VercelClient
	journal         vercelJournal
	state           string
	Arch, ProbePath string
	Calls           []obs.ProviderCall
	gone            bool
}

func (b *VercelBox) ID() string        { return b.journal.SessionID }
func (b *VercelBox) Name() string      { return b.journal.Requested }
func (b *VercelBox) StatePath() string { return b.state }
func (b *VercelBox) record(at time.Time, call string, err error) {
	status := "ok"
	if err != nil {
		status = "error"
	}
	b.Calls = append(b.Calls, obs.ProviderCall{At: at, Call: "Vercel " + call, ID: b.ID(), Status: status})
}
func (b *VercelBox) save() error {
	raw, _ := json.MarshalIndent(b.journal, "", "  ")
	f, err := os.CreateTemp(filepath.Dir(b.state), ".vercel-state-*")
	if err != nil {
		return errors.New("Vercel journal unavailable")
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(raw)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(f.Name(), b.state)
	}
	if err != nil {
		return errors.New("Vercel journal cannot be persisted")
	}
	return nil
}
func (c *VercelClient) CreateVercel(ctx context.Context, dir string) (*VercelBox, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, errors.New("Vercel journal directory unavailable")
	}
	st, err := os.Lstat(dir)
	if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0022 != 0 {
		return nil, errors.New("Vercel journal directory unsafe")
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Getuid()) {
		return nil, errors.New("Vercel journal directory not owned")
	}
	name := token("sandprobe-")
	b := &VercelBox{client: c, journal: vercelJournal{Team: c.Team, Project: c.Project, Requested: name, At: time.Now().UTC()}, state: filepath.Join(dir, "vercel-"+name+".state")}
	if err = b.save(); err != nil {
		return nil, err
	}
	var raw json.RawMessage
	at := time.Now()
	err = c.request(ctx, "POST", "/v3/sandboxes", map[string]any{"name": name, "projectId": c.Project, "image": "vercel/sandbox/universal", "persistent": false, "timeout": 900000, "resources": map[string]int{"vcpus": 2}, "env": map[string]string{}, "ports": []int{}, "mounts": map[string]string{}, "tags": map[string]string{"sandprobe_run": name}, "networkPolicy": map[string]string{"mode": "allow-all"}}, &raw)
	var envelope struct {
		Session struct {
			ID string `json:"id"`
		} `json:"session"`
	}
	if err == nil && json.Unmarshal(raw, &envelope) == nil && vercelID.MatchString(envelope.Session.ID) {
		b.journal.SessionID = envelope.Session.ID
		if saveErr := b.save(); saveErr != nil {
			err = errors.Join(err, saveErr)
		}
	}
	var r vercelReply
	if err == nil && json.Unmarshal(raw, &r) != nil {
		err = errors.New("Vercel create response fields malformed")
	}
	if r.Sandbox.Name == name && r.Sandbox.Created > 0 {
		b.journal.Created = r.Sandbox.Created
		if validVercelWorkDir(r.Session.Cwd) {
			b.journal.WorkDir = r.Session.Cwd
		}
		if saveErr := b.save(); saveErr != nil {
			err = errors.Join(err, saveErr)
		}
	}
	b.record(at, "create sandbox", err)
	if err != nil {
		return b, err
	}
	if b.ID() == "" {
		return b, errors.New("Vercel create returned no immutable session ID")
	}
	if err = b.match(r, false); err != nil {
		return b, err
	}
	for r.Session.Status == "pending" {
		if err = b.pause(ctx); err != nil {
			return b, err
		}
		r, err = b.lookup(ctx)
		if err != nil {
			return b, err
		}
		if err = b.match(r, false); err != nil {
			return b, err
		}
	}
	if err = b.ours(ctx); err != nil {
		return b, err
	}
	return b, nil
}
func (b *VercelBox) namedPath() (string, error) {
	if !vercelName.MatchString(b.Name()) {
		return "", errors.New("Vercel recorded sandbox name invalid; preserve journal")
	}
	return "/v2/sandboxes/" + b.Name() + "?projectId=" + url.QueryEscape(b.client.Project) + "&resume=false", nil
}
func (b *VercelBox) lookup(ctx context.Context) (vercelReply, error) {
	var r vercelReply
	at := time.Now()
	path, err := b.namedPath()
	if err == nil {
		err = b.client.request(ctx, "GET", path, nil, &r)
	}
	b.record(at, "get sandbox without resume", err)
	return r, err
}
func (b *VercelBox) match(r vercelReply, terminal bool) error {
	s := r.Sandbox
	if s.Name != b.Name() || s.Created <= 0 || s.Created != b.journal.Created || s.Tags["sandprobe_run"] != b.Name() || s.Persistent == nil || *s.Persistent || s.SnapshotID != "" || len(s.Mounts) != 0 {
		return errors.New("Vercel sandbox identity or non-persistence mismatch")
	}
	if s.SessionID != b.ID() && !(terminal && s.SessionID == "") {
		return errors.New("Vercel sandbox session replaced")
	}
	if !terminal {
		ss := r.Session
		if !validVercelWorkDir(b.journal.WorkDir) || ss.Cwd != b.journal.WorkDir {
			return errors.New("Vercel image working directory missing, unsupported or changed")
		}
		if ss.ID != b.ID() || ss.Timeout <= 0 || ss.Timeout > 900000 || ss.Created <= 0 {
			return errors.New("Vercel session identity or timeout invalid")
		}
		now := time.Now()
		timestamps := []int64{s.Created, ss.Created}
		if ss.Started != 0 {
			timestamps = append(timestamps, ss.Started)
		}
		for _, created := range timestamps {
			t := time.UnixMilli(created)
			if t.Before(b.journal.At.Add(-time.Minute)) || t.After(b.journal.At.Add(2*time.Minute)) || t.After(now.Add(time.Minute)) {
				return errors.New("Vercel creation/start timestamp outside run")
			}
		}
		start := ss.Started
		if start == 0 {
			start = ss.Created
		}
		if !now.Before(time.UnixMilli(start).Add(time.Duration(ss.Timeout) * time.Millisecond)) {
			return errors.New("Vercel session lifetime exhausted")
		}
	}
	return nil
}
func (b *VercelBox) ours(ctx context.Context) error {
	if b.gone || !vercelID.MatchString(b.ID()) {
		return errors.New("Vercel sandbox gone or create unresolved")
	}
	r, err := b.lookup(ctx)
	if err != nil {
		return err
	}
	if err = b.match(r, false); err != nil {
		return err
	}
	if r.Session.Status != "running" {
		return errors.New("Vercel session is not running")
	}
	return nil
}
func (b *VercelBox) pause(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return errors.New("Vercel deadline reached")
	case <-time.After(time.Second):
		return nil
	}
}
func (b *VercelBox) command(ctx context.Context, script string) (out []byte, err error) {
	if err = b.ours(ctx); err != nil {
		return nil, err
	}
	at := time.Now()
	defer func() { b.record(at, "execute command stream", err) }()
	payload, _ := json.Marshal(map[string]any{"command": "/bin/bash", "args": []string{"-c", script}, "cwd": b.journal.WorkDir, "env": map[string]string{"SANDPROBE_TWIN": "1"}, "sudo": false, "timeout": 95000, "wait": true, "logs": true})
	resp, err := b.client.do(ctx, "POST", "/v2/sandboxes/sessions/"+b.ID()+"/cmd", "application/json", payload, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if strings.Split(resp.Header.Get("Content-Type"), ";")[0] != "application/x-ndjson" {
		return nil, errors.New("Vercel command response is not NDJSON")
	}
	return parseVercelStream(io.LimitReader(resp.Body, 8*obs.MaxDoc+1), b.ID())
}

type vercelCommand struct {
	ID        string `json:"id"`
	SessionID string `json:"sessionId"`
	Exit      *int   `json:"exitCode"`
}

func parseVercelStream(reader io.Reader, sessionID string) ([]byte, error) {
	scan := bufio.NewScanner(reader)
	scan.Buffer(make([]byte, 4096), 8*obs.MaxDoc)
	first, finished := false, false
	commandID := ""
	total, wire := 0, 0
	var stdout bytes.Buffer
	for scan.Scan() {
		line := scan.Bytes()
		wire += len(line) + 1
		if wire > 8*obs.MaxDoc {
			return nil, errors.New("Vercel command wire limit exceeded")
		}
		if finished {
			return nil, errors.New("Vercel command data after terminal event")
		}
		var event struct {
			Command *vercelCommand  `json:"command"`
			Stream  string          `json:"stream"`
			Data    json.RawMessage `json:"data"`
		}
		if json.Unmarshal(line, &event) != nil {
			return nil, errors.New("Vercel command stream malformed")
		}
		if event.Command != nil {
			c := event.Command
			if c.SessionID != sessionID || !vercelID.MatchString(c.ID) {
				return nil, errors.New("Vercel command identity invalid")
			}
			if !first {
				first = true
				commandID = c.ID
				// SDK protocol starts with command identity, then streams a terminal command.
				if c.Exit != nil {
					return nil, errors.New("Vercel command initial event already terminal")
				}
			} else {
				if c.ID != commandID || c.Exit == nil || *c.Exit != 0 {
					return nil, errors.New("Vercel command missing zero exit or changed identity")
				}
				finished = true
			}
			continue
		}
		if !first || event.Stream != "stdout" && event.Stream != "stderr" {
			return nil, errors.New("Vercel unexpected command event")
		}
		var data string
		if json.Unmarshal(event.Data, &data) != nil {
			return nil, errors.New("Vercel command log invalid")
		}
		total += len(data)
		if total > obs.MaxDoc {
			return nil, errors.New("Vercel command output limit exceeded")
		}
		if event.Stream == "stdout" {
			stdout.WriteString(data)
		}
	}
	if scan.Err() != nil || !first || !finished {
		return nil, errors.New("Vercel command stream incomplete")
	}
	return stdout.Bytes(), nil
}
func (b *VercelBox) DetectArch(ctx context.Context) error {
	out, err := b.command(ctx, "uname -m")
	if err != nil {
		return err
	}
	switch strings.TrimSpace(string(out)) {
	case "x86_64":
		b.Arch = "amd64"
	case "aarch64", "arm64":
		b.Arch = "arm64"
	default:
		return errors.New("Vercel unsupported architecture")
	}
	return nil
}
func (b *VercelBox) uploadFile(ctx context.Context, path string, data []byte, mode int64) (err error) {
	if err = b.ours(ctx); err != nil {
		return err
	}
	if !b.privateDir(filepath.Dir(path)) || filepath.Base(path) == "." || filepath.Base(path) == ".." {
		return errors.New("Vercel upload outside private directory")
	}
	var packed bytes.Buffer
	gz := gzip.NewWriter(&packed)
	tw := tar.NewWriter(gz)
	if err = tw.WriteHeader(&tar.Header{Name: filepath.Base(path), Size: int64(len(data)), Mode: mode, Typeflag: tar.TypeReg}); err == nil {
		_, err = tw.Write(data)
	}
	closeTar := tw.Close()
	closeGzip := gz.Close()
	if err != nil || closeTar != nil || closeGzip != nil {
		return errors.New("Vercel upload archive failed")
	}
	at := time.Now()
	defer func() { b.record(at, "upload private file", err) }()
	resp, err := b.client.do(ctx, "POST", "/v2/sandboxes/sessions/"+b.ID()+"/fs/write", "application/gzip", packed.Bytes(), map[string]string{"x-cwd": filepath.Dir(path)})
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}
func validVercelWorkDir(dir string) bool { return dir == "/vercel" || dir == "/vercel/sandbox" }

func (b *VercelBox) privateDir(dir string) bool {
	return validVercelWorkDir(b.journal.WorkDir) && vercelScratch.MatchString(dir) && filepath.Dir(dir) == b.journal.WorkDir
}

func (b *VercelBox) Upload(ctx context.Context, bin []byte) error {
	out, err := b.command(ctx, "umask 077; mktemp -d "+b.journal.WorkDir+"/.sandprobe-XXXXXXXXXXXX")
	if err != nil {
		return err
	}
	dir := strings.TrimSpace(string(out))
	if !b.privateDir(dir) {
		return errors.New("Vercel private directory invalid")
	}
	b.ProbePath = dir + "/probe"
	if err = b.uploadFile(ctx, b.ProbePath, bin, 0700); err != nil {
		return err
	}
	out, err = b.command(ctx, "sha256sum "+b.ProbePath)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(bin)
	fields := strings.Fields(string(out))
	if len(fields) != 2 || fields[0] != hex.EncodeToString(sum[:]) || fields[1] != b.ProbePath {
		return errors.New("Vercel probe digest mismatch")
	}
	return nil
}
func (b *VercelBox) Probe(ctx context.Context, args []string, stdin []byte) ([]byte, error) {
	if b.ProbePath == "" {
		return nil, errors.New("Vercel probe not uploaded")
	}
	suffix := ""
	if len(args) == 1 && args[0] == "-survey" {
		suffix = " -survey"
	} else if len(args) != 0 {
		return nil, errors.New("Vercel unsupported probe mode")
	}
	input := filepath.Dir(b.ProbePath) + "/input-" + token("i")
	if err := b.uploadFile(ctx, input, stdin, 0600); err != nil {
		return nil, err
	}
	return b.command(ctx, "trap 'rm -f "+input+"' EXIT; "+b.ProbePath+suffix+" < "+input)
}
func vercelTerminal(s string) bool { return s == "stopped" || s == "failed" || s == "aborted" }
func (b *VercelBox) session(ctx context.Context) (vercelSession, error) {
	var r struct {
		Session vercelSession `json:"session"`
	}
	at := time.Now()
	err := b.client.request(ctx, "GET", "/v2/sandboxes/sessions/"+b.ID(), nil, &r)
	b.record(at, "get immutable session", err)
	if err == nil && r.Session.ID != b.ID() {
		err = errors.New("Vercel cleanup session identity mismatch")
	}
	return r.Session, err
}
func (b *VercelBox) Destroy(ctx context.Context) error {
	if b.gone {
		return nil
	}
	if !vercelID.MatchString(b.ID()) {
		return errors.New("Vercel create unresolved; preserve journal; never delete guessed name")
	}
	s, err := b.session(ctx)
	if err != nil && !vercelStatus(err, 404) {
		return err
	}
	if err == nil && !vercelTerminal(s.Status) {
		at := time.Now()
		err = b.client.request(ctx, "POST", "/v2/sandboxes/sessions/"+b.ID()+"/stop", nil, nil)
		b.record(at, "stop immutable session", err)
		if err != nil && !vercelStatus(err, 404) {
			return err
		}
		for {
			s, err = b.session(ctx)
			if vercelStatus(err, 404) || err == nil && vercelTerminal(s.Status) {
				break
			}
			if err != nil {
				return err
			}
			if err = b.pause(ctx); err != nil {
				return err
			}
		}
	}
	r, err := b.lookup(ctx)
	if vercelStatus(err, 404) {
		return b.retire()
	}
	if err != nil {
		return err
	}
	if err = b.match(r, true); err != nil {
		return err
	}
	at := time.Now()
	path, err := b.namedPath()
	if err != nil {
		return err
	}
	err = b.client.request(ctx, "DELETE", path, nil, nil)
	b.record(at, "delete guarded sandbox record", err)
	if err != nil && !vercelStatus(err, 404) {
		return err
	}
	for {
		_, err = b.lookup(ctx)
		if vercelStatus(err, 404) {
			return b.retire()
		}
		if err != nil {
			return err
		}
		if err = b.pause(ctx); err != nil {
			return err
		}
	}
}
func (b *VercelBox) retire() error {
	if err := os.Remove(b.state); err != nil && !os.IsNotExist(err) {
		return errors.New("Vercel resources gone but journal removal failed")
	}
	b.gone = true
	return nil
}
func VercelExclusions() map[string]string {
	return map[string]string{"SEC-4": "Vercel scope excludes metadata requests (PRV-9)", "EGR-3": "Vercel scope excludes guest/provider proxy requests (PRV-9)", "AMP-6": "Vercel scope excludes host vsock requests (PRV-9)", "AMP-7": "Vercel scope excludes Kubernetes API requests (PRV-9)"}
}
