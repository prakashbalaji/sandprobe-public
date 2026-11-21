package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"

	"sandprobe/internal/obs"
)

// fakeSprite plays the sprite CLI: lookups answer from codes in turn, and every call is recorded.
type fakeSprite struct {
	calls   [][]string
	lookups []string // "200 <id>", "404", or "500"
	upload  string   // what the upload's sha256sum prints
	agent   bool     // the setup left the agent's launcher (SPR-2)
	already bool     // a launcher was in the sprite before the setup ran
	preErr  bool     // the launcher pre-check prints "absent" but its call fails
	stdin   []byte
}

func (f *fakeSprite) cli(_ context.Context, stdin io.Reader, stdout, _ io.Writer, args ...string) error {
	f.calls = append(f.calls, args)
	f.stdin, _ = io.ReadAll(stdin)
	switch args[0] {
	case "api":
		if len(f.lookups) == 0 {
			return errors.New("no lookup scripted")
		}
		l := f.lookups[0]
		f.lookups = f.lookups[1:]
		code, id, _ := strings.Cut(l, " ")
		body := `{"error":"sprite not found"}`
		if code == "200" {
			body = fmt.Sprintf(`{"data":{"id":%q,"name":"x"}}`, id)
		}
		fmt.Fprintf(stdout, "%s\n%s", body, code)
	case "exec":
		if last := args[len(args)-1]; strings.HasPrefix(last, "if [ -e ") {
			if f.preErr {
				io.WriteString(stdout, "absent\n")
				return errors.New("the call failed")
			}
			if f.already {
				io.WriteString(stdout, "present\n")
			} else {
				io.WriteString(stdout, "absent\n")
			}
		} else if strings.HasPrefix(last, "test -x ") {
			if f.agent {
				io.WriteString(stdout, "launcher\n")
			} else {
				io.WriteString(stdout, "none\n")
			}
		} else if slices.Contains(args, "sh") {
			fmt.Fprintf(stdout, "%s  /tmp/x/probe\n", f.upload)
		} else {
			io.WriteString(stdout, `{"schema":"x"}`)
		}
	}
	return nil
}

func box(f *fakeSprite) *SpriteBox {
	return &SpriteBox{Home: "/h", Org: "org", Name: "sandprobe-abc", SpriteID: "sprite-1", cli: f.cli}
}

func TestCreateSprite(t *testing.T) {
	f := &fakeSprite{lookups: []string{"200 sprite-9"}}
	orig := spriteCLI
	defer func() { spriteCLI = orig }()
	spriteCLI = f.cli
	s, err := CreateSprite(context.Background(), "/h", "org")
	if err != nil || s.SpriteID != "sprite-9" || !strings.HasPrefix(s.Name, "sandprobe-") {
		t.Fatalf("want the provider's ID recorded, got %+v, %v", s, err)
	}
	if c := f.calls[0]; c[0] != "create" || !slices.Contains(c, s.Name) || !slices.Contains(c, "org") {
		t.Fatalf("create: %v", c)
	}
	if c := f.calls[1]; c[0] != "api" || slices.Contains(c, "-s") && c[slices.Index(c, "-s")+1] == s.Name {
		t.Fatalf("the lookup must go by path, not under the sprite: %v", c)
	}
}

// A create that fails still hands back the name, and Destroy then reports a sprite by that name, never deleting it.
func TestCreateSpriteFails(t *testing.T) {
	f := &fakeSprite{lookups: []string{"200 sprite-7"}}
	orig := spriteCLI
	defer func() { spriteCLI = orig }()
	spriteCLI = func(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, args ...string) error {
		if args[0] == "create" {
			f.calls = append(f.calls, args)
			return errors.New("the reply was lost")
		}
		return f.cli(ctx, stdin, stdout, stderr, args...)
	}
	s, err := CreateSprite(context.Background(), "/h", "org")
	if err == nil || s == nil || s.Name == "" || s.SpriteID != "" {
		t.Fatalf("want the name handed back with the error, got %+v, %v", s, err)
	}
	if err := s.Destroy(context.Background()); err == nil || !strings.Contains(err.Error(), "sprite-7") {
		t.Fatalf("want the unconfirmed sprite reported with its ID, got %v", err)
	}
	if slices.ContainsFunc(f.calls, func(c []string) bool { return c[0] == "destroy" }) {
		t.Fatal("an unconfirmed sprite must never be deleted")
	}
	f.lookups = []string{"404"}
	if err := s.Destroy(context.Background()); err != nil {
		t.Fatalf("nothing by that name: nothing to resolve, got %v", err)
	}
}

func TestSpriteUploadAndProbe(t *testing.T) {
	probe := []byte("the probe")
	sum := sha256.Sum256(probe)
	f := &fakeSprite{upload: hex.EncodeToString(sum[:]), lookups: []string{"200 sprite-1", "200 sprite-1", "200 sprite-1"}}
	s := box(f)
	if err := s.Upload(context.Background(), probe); err != nil || !strings.HasSuffix(s.ProbePath, "/probe") || string(f.stdin) != "the probe" {
		t.Fatalf("upload: %v, %q", err, s.ProbePath)
	}
	if _, err := s.Probe(context.Background(), []string{"-survey"}, nil); err != nil {
		t.Fatal(err)
	}
	c := f.calls[len(f.calls)-1]
	if want := []string{"exec", "-o", "org", "-s", "sandprobe-abc", "-env", "SANDPROBE_TWIN=1", "sh", "-c", "exec " + s.ProbePath + " -survey"}; !slices.Equal(c, want) {
		t.Fatalf("probe ran as %v, want %v", c, want)
	}
	// the sprite CLI takes -s and -o from anywhere: no argument past its own options may start with either
	for _, call := range f.calls {
		for _, a := range call[5:] {
			if strings.HasPrefix(a, "-s") || strings.HasPrefix(a, "-o") || strings.HasPrefix(a, "-h") {
				t.Errorf("an argument the sprite CLI would take for its own: %q in %v", a, call)
			}
		}
	}
	if _, err := s.Probe(context.Background(), []string{"-survey; reboot"}, nil); err == nil {
		t.Error("want an argument that isn't a plain flag refused")
	}
	f.upload = "0000"
	if err := box(f).Upload(context.Background(), probe); err == nil {
		t.Fatal("want an upload that arrived different refused")
	}
	// the name now answers with another sprite: nothing is uploaded or run there
	f = &fakeSprite{upload: hex.EncodeToString(sum[:]), lookups: []string{"200 sprite-9", "200 sprite-9"}}
	s = box(f)
	s.ProbePath = "/tmp/x/probe"
	_, perr := s.Probe(context.Background(), []string{"-survey"}, nil)
	if s.Upload(context.Background(), probe) == nil || perr == nil {
		t.Fatal("want upload and probe refused on another sprite by that name")
	}
	if slices.ContainsFunc(f.calls, func(c []string) bool { return c[0] == "exec" }) {
		t.Fatal("nothing may be run on another sprite")
	}
}

func TestSpriteDestroy(t *testing.T) {
	for name, tc := range map[string]struct {
		lookups []string
		ok      bool
		destroy bool
	}{
		"destroyed, then a 404":            {[]string{"200 sprite-1", "404"}, true, true},
		"already gone":                     {[]string{"404"}, true, false},
		"the name now has another ID":      {[]string{"200 sprite-2"}, false, false},
		"still there after the destroy":    {[]string{"200 sprite-1", "200 sprite-1"}, false, true},
		"the provider answers neither way": {[]string{"500"}, false, false},
	} {
		f := &fakeSprite{lookups: tc.lookups}
		err := box(f).Destroy(context.Background())
		destroyed := slices.ContainsFunc(f.calls, func(c []string) bool { return c[0] == "destroy" })
		if (err == nil) != tc.ok || destroyed != tc.destroy {
			t.Errorf("%s: err %v, destroy called %v", name, err, destroyed)
		}
	}
}

// fakeRestore plays the sprite CLI for checkpoints and restores: each call to a path takes the next scripted answer.
type fakeRestore struct {
	answers map[string][]string // "lookup", "list", "restore" -> answers in turn (body, then "\n" and the code)
	calls   [][]string
}

func (f *fakeRestore) cli(_ context.Context, _ io.Reader, stdout, _ io.Writer, args ...string) error {
	f.calls = append(f.calls, args)
	key := "other"
	switch {
	case args[0] == "checkpoint":
		return nil
	case args[0] == "exec":
		key = "exec"
	case args[0] != "api":
	case strings.HasSuffix(args[3], "/restore"):
		key = "restore"
	case strings.HasSuffix(args[3], "/checkpoints"):
		key = "list"
	default:
		key = "lookup"
	}
	if len(f.answers[key]) == 0 {
		return errors.New("nothing scripted for " + key)
	}
	io.WriteString(stdout, f.answers[key][0])
	f.answers[key] = f.answers[key][1:]
	return nil
}

func list(current string, versions ...string) string {
	b := `[{"id":"Current","create_time":"` + current + `"}`
	for _, v := range versions {
		b += `,{"id":"` + v + `","create_time":"t"}`
	}
	return b + "]\n200"
}

const (
	live  = `{"data":{"id":"sprite-1"}}` + "\n200"
	other = `{"data":{"id":"sprite-9"}}` + "\n200"
)

func TestSpriteCheckpoint(t *testing.T) {
	five := []string{live, live, live, live, live} // a check on each side of each list read, and one before the create
	for name, tc := range map[string]struct {
		lookups, lists []string
		want           string
		create         bool
	}{
		"exactly one new version":                {five, []string{list("t1", "v1"), list("t2", "v1", "v2")}, "v2", true},
		"none":                                   {five, []string{list("t1", "v1"), list("t1", "v1")}, "", true},
		"two at once":                            {five, []string{list("t1", "v1"), list("t2", "v1", "v2", "v3")}, "", true},
		"no Current":                             {five, []string{`[{"id":"v1","create_time":"t"}]` + "\n200", list("t2", "v1", "v2")}, "", false},
		"another sprite before the list read":    {[]string{other}, []string{list("t1", "v1")}, "", false},
		"the name moves during the list read":    {[]string{live, other}, []string{list("t1", "v1")}, "", false},
		"the name moves right before the create": {[]string{live, live, other}, []string{list("t1", "v1")}, "", false},
		"the name moves during the list after":   {[]string{live, live, live, live, other}, []string{list("t1", "v1"), list("t2", "v1", "v2")}, "", true},
	} {
		f := &fakeRestore{answers: map[string][]string{"lookup": tc.lookups, "list": tc.lists}}
		s := &SpriteBox{Name: "n", Org: "o", SpriteID: "sprite-1", cli: f.cli}
		err := s.Checkpoint(context.Background())
		if s.Version != tc.want || (err == nil) != (tc.want != "") {
			t.Errorf("%s: version %q, err %v", name, s.Version, err)
		}
		st, _ := s.Storage(context.Background())
		if (st.Model == "restore") != (tc.want != "") {
			t.Errorf("%s: storage %+v", name, st)
		}
		i := slices.IndexFunc(f.calls, func(c []string) bool { return c[0] == "checkpoint" })
		if (i >= 0) != tc.create {
			t.Errorf("%s: checkpoint create called %v, want %v", name, i >= 0, tc.create)
		}
		if tc.lookups[0] == other && slices.ContainsFunc(f.calls, func(c []string) bool { return len(c) > 3 && strings.HasSuffix(c[3], "/checkpoints") }) {
			t.Errorf("%s: the checkpoint list was read on another sprite", name)
		}
		// the ID check is the call right before the create, with nothing between (PRV-1)
		if i >= 0 && (i == 0 || f.calls[i-1][0] != "api" || strings.HasSuffix(f.calls[i-1][3], "/checkpoints")) {
			t.Errorf("%s: the call before the create isn't the ID check: %v", name, f.calls)
		}
	}
}

func TestSpriteReset(t *testing.T) {
	stream := func(lines ...string) string { return strings.Join(lines, "\n") + "\n200" }
	ok := stream(`{"type":"info","data":"Restoring from checkpoint v2...","time":"a"}`, `{"type":"complete","data":"Restore from v2 complete","time":"b"}`)
	// a check on each side of the Current read, one before the restore, the ID after it, a check on each side of the
	// Current read after
	six := []string{live, live, live, live, live, live}
	both := []string{list("t1"), list("t2")}
	for name, tc := range map[string]struct {
		lookups, lists     []string
		restore            string
		restored, done, ok bool
	}{
		"restored":                                     {six, both, ok, true, true, true},
		"the complete event for another version":       {six, both, stream(`{"type":"complete","data":"Restore from v1 complete"}`), true, false, false},
		"an error event before the end":                {six, both, stream(`{"type":"error","data":"no"}`, `{"type":"complete","data":"Restore from v2 complete"}`), true, false, false},
		"the stream ended early":                       {six, both, stream(`{"type":"info","data":"Restoring from checkpoint v2..."}`), true, false, false},
		"the call didn't answer 200":                   {six, both, strings.Replace(ok, "\n200", "\n500", 1), true, false, false},
		"Current didn't change":                        {six, []string{list("t1"), list("t1")}, ok, true, false, false},
		"another sprite before the Current read":       {[]string{other}, both, ok, false, false, false},
		"the name moves during the Current read":       {[]string{live, other}, both, ok, false, false, false},
		"the name moves right before the restore":      {[]string{live, live, other}, both, ok, false, false, false},
		"another sprite by that name after":            {[]string{live, live, live, other}, both, ok, true, false, false},
		"the name moves during the Current read after": {[]string{live, live, live, live, live, other}, both, ok, true, false, false},
	} {
		f := &fakeRestore{answers: map[string][]string{"lookup": tc.lookups, "list": tc.lists, "restore": {tc.restore}}}
		s := &SpriteBox{Name: "n", Org: "o", SpriteID: "sprite-1", Version: "v2", cli: f.cli}
		after, ev, err := s.Reset(context.Background())
		if after != s || ev.Done != tc.done || (err == nil) != tc.ok || ev.Model != "restore" || ev.Checkpoint != "v2" ||
			!strings.HasPrefix(ev.OperationID, "restore-") || ev.RootIdentity != nil {
			t.Errorf("%s: done %v, err %v, evidence %+v", name, ev.Done, err, ev)
		}
		if tc.done && (ev.RestoreBefore != "t1" || ev.RestoreAfter != "t2" || ev.BoxBefore != "sprite-1" || ev.BoxAfter != "sprite-1") {
			t.Errorf("%s: evidence %+v", name, ev)
		}
		if tc.lookups[0] == other && slices.ContainsFunc(f.calls, func(c []string) bool { return len(c) > 3 && strings.HasSuffix(c[3], "/checkpoints") }) {
			t.Errorf("%s: the checkpoint list was read on another sprite", name)
		}
		restored := slices.ContainsFunc(f.calls, func(c []string) bool { return len(c) > 3 && strings.HasSuffix(c[3], "/restore") })
		if restored != tc.restored {
			t.Errorf("%s: restore called %v, want %v", name, restored, tc.restored)
		}
	}
	s := &SpriteBox{Version: "v2", cli: (&fakeRestore{}).cli}
	_, e1, _ := s.Reset(context.Background())
	_, e2, _ := s.Reset(context.Background())
	if e1.OperationID == e2.OperationID {
		t.Error("want every restore attempt its own ID")
	}
}

// A restore after which the name answers with another sprite ends PER-5 there: the host never rechecks through it.
func TestSpriteRestoreMismatchSkipsRecheck(t *testing.T) {
	m := obs.Manifest{RunID: "r1", Nonce: "n1", BoxID: "sprite-1", Reset: "restore",
		Marks: []obs.PlannedMark{{Root: "/tmp", Path: "/tmp/.sandprobe-r1", Dev: 1, Ino: 5}}}
	mark, _ := json.Marshal(obs.MarkDoc{Schema: obs.MarkSchema, RunID: "r1", Nonce: "n1", BoxID: "sprite-1", BootID: "b",
		Marks: []obs.Placed{{Root: "/tmp", Path: "/tmp/.sandprobe-r1", Placed: true, Ino: 100, Size: 2}}})
	ok := `{"type":"complete","data":"Restore from v2 complete"}` + "\n200"
	f := &fakeRestore{answers: map[string][]string{
		"exec":    {string(mark), "{}"},
		"lookup":  {live, live, live, live, other}, // the mark's check; the Current read's two; before the restore; after it
		"list":    {list("t1"), list("t2")},
		"restore": {ok},
	}}
	s := &SpriteBox{Name: "n", Org: "o", SpriteID: "sprite-1", Version: "v2", ProbePath: "/tmp/x/probe", cli: f.cli}
	ev := persist(context.Background(), s, &Run{Box: s, Manifest: m})
	if ev.Done || ev.Recheck != nil || ev.Mark == nil || ev.BoxAfter != "sprite-9" {
		t.Fatalf("want the mark kept, the reset not done and no recheck: %+v", ev)
	}
	for _, c := range f.calls {
		if c[0] == "exec" && strings.Contains(c[len(c)-1], "-recheck") {
			t.Fatalf("the host rechecked through a name that answers for another sprite: %v", c)
		}
	}
}

// PRV-3's call log keeps how each call ended, the provider's status and the ID it returned, and never what the CLI
// printed: a report is shareable, and output can hold anything.
func TestSpriteCallLog(t *testing.T) {
	leak := func(_ context.Context, _ io.Reader, stdout, stderr io.Writer, args ...string) error {
		io.WriteString(stderr, "token=secret-token-xyz")
		switch {
		case args[0] == "api" && strings.HasSuffix(args[3], "/checkpoints"):
			io.WriteString(stdout, "{\"error\":\"secret-token-xyz\"}\n500")
		case args[0] == "api":
			io.WriteString(stdout, live)
		default:
			return errors.New("secret-token-xyz")
		}
		return nil
	}
	s := &SpriteBox{Name: "n", Org: "o", SpriteID: "sprite-1", Version: "v2", cli: leak}
	s.Reset(context.Background())                            // a checkpoint list that answers 500
	s.ours(context.Background())                             // a lookup that returns an ID
	s.run(context.Background(), nil, "checkpoint", "create") // a call that fails
	b, _ := json.Marshal(s.Calls)
	if strings.Contains(string(b), "secret-token") {
		t.Fatalf("CLI output reached the call log: %s", b)
	}
	var list, lookup, failed obs.ProviderCall
	for _, c := range s.Calls {
		switch {
		case strings.Contains(c.Call, "/checkpoints"):
			list = c
		case strings.Contains(c.Call, "api"):
			lookup = c
		case strings.Contains(c.Call, "checkpoint"):
			failed = c
		}
	}
	if list.OK || list.Status != "500" || list.Exit != 0 {
		t.Errorf("a 500 must not read ok: %+v", list)
	}
	if !lookup.OK || lookup.Status != "200" || lookup.ID != "sprite-1" {
		t.Errorf("want the lookup's status and the ID it returned: %+v", lookup)
	}
	if failed.OK || failed.Error == "" || failed.Exit != -1 {
		t.Errorf("want a failed call recorded as a category: %+v", failed)
	}
}

// The Sprites PRV row: Sandprobe checks the sprite itself, so every check that would contact a
// Fly-owned endpoint is excluded, and Execute accepts each exclusion (GRD-3).
func TestSpritesExclusions(t *testing.T) {
	ex := SpritesExclusions()
	for _, id := range []string{"SEC-4", "EGR-3", "AMP-6", "AMP-7"} {
		if ex[id] == "" || !excludable[id] {
			t.Errorf("%s isn't an accepted Sprites exclusion", id)
		}
	}
	if len(ex) != 4 {
		t.Errorf("Sprites excludes %d checks, want 4", len(ex))
	}
}

// SPR-1 and SPR-2: the setup goes in on standard input, the launcher it leaves is found, and every probe call runs
// through it; the probe sits outside /tmp, which the launcher may make private.
func TestSpriteSetupAndLauncher(t *testing.T) {
	probe := []byte("the probe")
	sum := sha256.Sum256(probe)
	f := &fakeSprite{upload: hex.EncodeToString(sum[:]), agent: true, lookups: []string{"200 sprite-1", "200 sprite-1", "200 sprite-1", "200 sprite-1", "200 sprite-1"}}
	s := box(f)
	if err := s.Upload(context.Background(), probe); err != nil || !strings.HasPrefix(s.ProbePath, "/var/tmp/sandprobe-") {
		t.Fatalf("upload: %v, %q", err, s.ProbePath)
	}
	if err := s.Setup(context.Background(), []byte("useradd agent\n")); err != nil {
		t.Fatal(err)
	}
	ran := slices.ContainsFunc(f.calls, func(c []string) bool { return slices.Equal(c[len(c)-2:], []string{"sh", "-s"}) })
	if !ran || s.Launcher != AgentExec {
		t.Fatalf("want the setup on sh -s and the launcher found; calls %v, launcher %q", f.calls, s.Launcher)
	}
	if _, err := s.Probe(context.Background(), []string{"-survey"}, nil); err != nil {
		t.Fatal(err)
	}
	if c := f.calls[len(f.calls)-1]; c[len(c)-1] != "exec "+AgentExec+" "+s.ProbePath+" -survey" {
		t.Fatalf("the probe didn't run through the launcher: %v", c)
	}
	f = &fakeSprite{upload: hex.EncodeToString(sum[:]), lookups: []string{"200 sprite-1", "200 sprite-1", "200 sprite-1"}}
	s = box(f)
	if err := s.Setup(context.Background(), []byte("true\n")); err != nil || s.Launcher != "" {
		t.Fatalf("no launcher left: want none used, got %q (%v)", s.Launcher, err)
	}
}

// SPR-2: a launcher already in the new sprite isn't the person's, so the setup never runs and nothing is routed
// through it.
func TestSpriteSetupRefusesAPreexistingLauncher(t *testing.T) {
	f := &fakeSprite{agent: true, already: true, lookups: []string{"200 sprite-1"}}
	s := box(f)
	err := s.Setup(context.Background(), []byte("useradd agent\n"))
	if err == nil || !strings.Contains(err.Error(), "already has") || s.Launcher != "" {
		t.Fatalf("want a refusal and no launcher, got %v, %q", err, s.Launcher)
	}
	if slices.ContainsFunc(f.calls, func(c []string) bool { return slices.Equal(c[len(c)-2:], []string{"sh", "-s"}) }) {
		t.Fatal("the setup ran with a launcher already there")
	}
}

// PRV-1 inside the setup: the ID is checked before each of its calls, so a name that changes hands mid-setup stops it.
// SPR-2: an "absent" from a pre-check whose call failed counts for nothing.
func TestSpriteSetupFailureCases(t *testing.T) {
	ran := func(f *fakeSprite) bool {
		return slices.ContainsFunc(f.calls, func(c []string) bool { return slices.Equal(c[len(c)-2:], []string{"sh", "-s"}) })
	}
	f := &fakeSprite{lookups: []string{"200 sprite-1", "200 sprite-2"}}
	s := box(f)
	if err := s.Setup(context.Background(), []byte("true\n")); err == nil || !strings.Contains(err.Error(), "left alone") || ran(f) {
		t.Fatalf("a name that changed hands before the script: %v, ran %v", err, ran(f))
	}
	f = &fakeSprite{agent: true, lookups: []string{"200 sprite-1", "200 sprite-1", "200 sprite-2"}}
	s = box(f)
	if err := s.Setup(context.Background(), []byte("true\n")); err == nil || s.Launcher != "" {
		t.Fatalf("a name that changed hands before the launcher check: %v, launcher %q", err, s.Launcher)
	}
	f = &fakeSprite{preErr: true, lookups: []string{"200 sprite-1", "200 sprite-1"}}
	s = box(f)
	if err := s.Setup(context.Background(), []byte("true\n")); err == nil || ran(f) {
		t.Fatalf("a failed pre-check was read as absent: %v, ran %v", err, ran(f))
	}
}
