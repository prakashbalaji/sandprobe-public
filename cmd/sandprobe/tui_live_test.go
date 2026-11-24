package main

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// UX-5: every runner with live phases feeds the tracker from its own plan: newLive with its provider's
// livePhasesFor, the canary's steps through lv.stepFunc("canary"), every phase its plan lists started, the probe
// marked finished only on success, and the cleanup outcome passed to close. No step line bypasses the tracker.
// (sandprobe-codex's review of #50, finding 1: seven native runners never fed it.)
func TestEveryRunnerFeedsTheLiveTracker(t *testing.T) {
	runners := []struct {
		file, fn, provider string
		keep               bool
	}{
		{"docker.go", "runDocker", "docker", false},
		{"exec.go", "runExec", "exec", false},
		{"nitro.go", "runNitro", "aws-nitro", false},
		{"recipe.go", "runRecipe", "kubernetes", false},
		{"sprites.go", "runCmd", "sprites", false},
		{"e2b.go", "runE2B", "e2b", false},
		{"vercel.go", "runVercel", "vercel", false},
		{"daytona.go", "runDaytona", "daytona", false},
		{"cloudflare.go", "runCloudflare", "cloudflare", false},
		{"boat.go", "runBoat", "boat", false},
		{"exedev.go", "runExedev", "exe.dev", false},
		{"baseten.go", "runBaseten", "baseten", false},
		{"baseten.go", "runBaseten", "baseten", true},
	}
	str := func(e ast.Expr) string {
		if lit, ok := e.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			s, _ := strconv.Unquote(lit.Value)
			return s
		}
		return ""
	}
	isLv := func(e ast.Expr, method string) (*ast.CallExpr, bool) {
		call, ok := e.(*ast.CallExpr)
		if !ok {
			return nil, false
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return nil, false
		}
		x, ok := sel.X.(*ast.Ident)
		return call, ok && x.Name == "lv" && sel.Sel.Name == method
	}
	fset := token.NewFileSet()
	for _, rn := range runners {
		f, err := parser.ParseFile(fset, rn.file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		var body *ast.BlockStmt
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == rn.fn {
				body = fd.Body
			}
		}
		if body == nil {
			t.Fatalf("%s: no %s", rn.file, rn.fn)
		}
		started := map[string]bool{}
		var tracked, canary, finished, closed bool
		ast.Inspect(body, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.BasicLit:
				if strings.Contains(str(n), "· ") {
					t.Errorf("%s: a step line bypasses the live tracker: %s", rn.fn, n.Value)
				}
			case *ast.CallExpr:
				switch fun := n.Fun.(type) {
				case *ast.Ident:
					switch fun.Name {
					case "progress":
						t.Errorf("%s: canary steps bypass the live tracker", rn.fn)
					case "newLive":
						phases, ok := n.Args[3].(*ast.CallExpr)
						if p := str(n.Args[2]); ok && (p == rn.provider || rn.provider == "kubernetes" && p == "") &&
							phases.Fun.(*ast.Ident).Name == "livePhasesFor" && str(phases.Args[0]) == str(n.Args[2]) {
							tracked = true
						}
					}
				case *ast.SelectorExpr:
					if fun.Sel.Name == "openCanary" {
						if call, ok := isLv(n.Args[2], "stepFunc"); ok && str(call.Args[0]) == "canary" {
							canary = true
						}
					}
					for _, m := range []string{"phase", "quiet", "done", "stepFunc"} {
						if call, ok := isLv(n, m); ok {
							id := str(call.Args[0])
							started[id] = true
							finished = finished || m == "done" && (id == "probe" || id == "reset")
						}
					}
					if call, ok := isLv(n, "close"); ok {
						if id, isIdent := call.Args[0].(*ast.Ident); !isIdent || id.Name != "false" {
							closed = true
						}
					}
				}
			}
			return true
		})
		canary = canary || rn.provider == "docker" // run docker starts its own local canary, as a quiet phase
		if !tracked || !canary || !finished || !closed {
			t.Errorf("%s (%s): newLive from its plan %v, canary through the tracker %v, probe finished %v, cleanup outcome to close %v",
				rn.fn, rn.provider, tracked, canary, finished, closed)
		}
		for _, p := range livePhasesFor(rn.provider, false, rn.keep) {
			if !started[p.ID] {
				t.Errorf("%s (%s, keep %v): never starts its plan's %q phase", rn.fn, rn.provider, rn.keep, p.ID)
			}
		}
	}
}

// liveScript drives a tracker the way an adapter does: "p:id" phase, "q:id" quiet, "d:id" done, "close:true|false".
func liveScript(t *testing.T, lv *liveTracker, steps ...string) {
	t.Helper()
	for _, s := range steps {
		verb, arg, _ := strings.Cut(s, ":")
		switch verb {
		case "p":
			lv.phase(arg, "doing %s", arg)
		case "q":
			lv.quiet(arg, "doing %s", arg)
		case "d":
			lv.done(arg, "")
		case "close":
			lv.close(arg == "true")
		default:
			t.Fatalf("bad step %q", s)
		}
	}
}

// UX-5, AGENTS rule 1: a live phase is ticked only when it finished. A cleanup that succeeds completes only the
// cleanup phase; a phase cut short reads "did not finish", one never started "not run", an unconfirmed cleanup
// "not confirmed", never ✓. Each case is an adapter's own call sequence on a failure path (finding 2).
func TestLivePhaseNeverTicksSkippedOrFailed(t *testing.T) {
	const (
		P = phasePending
		D = phaseDone
		F = phaseFailed
	)
	cases := []struct {
		name, provider string
		keep           bool
		steps          []string
		want           []phaseState
	}{
		{"exec success", "exec", false, []string{"p:canary", "p:preflight", "p:probe", "d:probe", "q:cleanup", "close:true"}, []phaseState{D, D, D, D}},
		{"exec preflight fails, cleanup confirmed", "exec", false, []string{"p:canary", "p:preflight", "q:cleanup", "close:true"}, []phaseState{D, F, P, D}},
		{"exec canary fails", "exec", false, []string{"p:canary", "close:false"}, []phaseState{F, P, P, P}},
		{"docker success", "docker", false, []string{"p:network", "q:canary", "p:box", "p:probe", "d:reset", "p:delete", "close:true"}, []phaseState{D, D, D, D, D, D}},
		{"docker box hangs, cleanup confirmed", "docker", false, []string{"p:network", "q:canary", "p:box", "p:delete", "close:true"}, []phaseState{D, D, F, P, P, D}},
		{"docker probe fails, cleanup unconfirmed", "docker", false, []string{"p:network", "q:canary", "p:box", "p:probe", "p:delete", "close:false"}, []phaseState{D, D, D, F, P, F}},
		{"sprites success", "sprites", false, []string{"p:canary", "p:box", "p:probe", "d:reset", "p:delete", "close:true"}, []phaseState{D, D, D, D, D}},
		{"nitro probe fails, cleanup confirmed", "aws-nitro", false, []string{"p:canary", "p:box", "p:probe", "p:delete", "close:true"}, []phaseState{D, D, F, D}},
		{"recipe create fails with no ID", "kubernetes", false, []string{"p:canary", "q:box", "close:false"}, []phaseState{D, F, P, P}},
		{"e2b canary fails", "e2b", false, []string{"p:canary", "close:false"}, []phaseState{F, P, P, P}},
		{"e2b create errs, cleanup confirmed", "e2b", false, []string{"p:canary", "p:box", "p:delete", "close:true"}, []phaseState{D, F, P, D}},
		{"daytona success", "daytona", false, []string{"p:canary", "p:box", "p:box", "p:probe", "d:probe", "p:delete", "close:true"}, []phaseState{D, D, D, D}},
		{"cloudflare with nothing created", "cloudflare", false, []string{"p:canary", "p:box", "close:true"}, []phaseState{D, F, P, P}},
		{"boat cleanup unconfirmed", "boat", false, []string{"p:canary", "p:box", "p:probe", "d:probe", "p:delete", "close:false"}, []phaseState{D, D, D, F}},
		{"baseten keep, run failed so deleted", "baseten", true, []string{"p:canary", "p:box", "p:probe", "q:retain", "close:false"}, []phaseState{D, D, F, F}},
		{"baseten keep, retained", "baseten", true, []string{"p:canary", "p:box", "p:probe", "d:probe", "q:retain", "close:true"}, []phaseState{D, D, D, D}},
	}
	for _, tc := range cases {
		phases := livePhasesFor(tc.provider, false, tc.keep)
		var buf bytes.Buffer
		lv := newLive(opts{out: "text"}, &buf, tc.provider, phases)
		lv.inPlace, lv.caps = true, termCaps{width: 80} // the in-place view, without a terminal or its timer
		liveScript(t, lv, tc.steps...)
		for i, p := range phases {
			if lv.states[i] != tc.want[i] {
				t.Errorf("%s: %s is %d, want %d", tc.name, p.ID, lv.states[i], tc.want[i])
			}
		}
		frames := strings.Split(buf.String(), "\x1b[2K")
		last := frames[len(frames)-len(phases):]
		for i, p := range phases {
			line := ansiSGR.ReplaceAllString(last[i], "")
			ticked := strings.HasPrefix(strings.TrimSpace(line), "✓ "+p.Label)
			if ticked != (tc.want[i] == D) {
				t.Errorf("%s: final frame line for %s is %q", tc.name, p.ID, line)
			}
			word := map[phaseState]string{P: "not run", F: "did not finish"}[tc.want[i]]
			if tc.want[i] == F && isCleanupPhase(p.ID) {
				word = "not confirmed"
			}
			if word != "" && !strings.Contains(line, word) {
				t.Errorf("%s: %s should read %q: %q", tc.name, p.ID, word, line)
			}
		}
	}
}

// UX-5 end to end. On Docker a hung box start fails the run: box did not finish, probe and reset never ran, and
// delete is ticked exactly when the run confirmed its cleanup (any exit but 7). A failing run exec command fails
// preflight; its confirmed cleanup completes only the cleanup phase.
func TestRunnersLiveOutcomeOnFailure(t *testing.T) {
	var got *liveTracker
	onNewLive = func(lv *liveTracker) { got = lv }
	defer func() { onNewLive = nil }()

	dir := t.TempDir()
	fake := `#!/bin/sh
case "$*" in
  "info --format {{.Architecture}}") echo aarch64 ;;
  "image inspect"*) echo sha256:fake ;;
  "network create"*) echo net0123456789abcdef ;;
  "run -d"*/sandprobe-canary:ro*) echo canary0123456789abcdef ;;
  "run -d"*) exec sleep 60 ;;
  "port "*) echo 127.0.0.1:40001 ;;
  "exec "*) echo '{"ok":true}' ;;
  "inspect --type container"*) echo "Error: No such container" >&2; exit 1 ;;
  "network inspect"*) echo "Error: network not found" >&2; exit 1 ;;
  *) ;;
esac
`
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(fake), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	defer func(d time.Duration) { dockerRunTimeout = d }(dockerRunTimeout)
	dockerRunTimeout = 3 * time.Second
	var out, errb bytes.Buffer
	code := run([]string{"run", "docker", "some-image", "-y", "-out", t.TempDir()}, &out, &errb)
	if code == exitGraded || got == nil {
		t.Fatalf("want a failed docker run with a tracker; exit %d\n%s", code, errb.String())
	}
	deleted := phaseDone
	if code == exitCleanup {
		deleted = phaseFailed
	}
	want := map[string]phaseState{"network": phaseDone, "box": phaseFailed, "probe": phasePending, "reset": phasePending, "delete": deleted}
	for i, p := range got.phases {
		if w, ok := want[p.ID]; ok && got.states[i] != w {
			t.Errorf("docker %s: %d, want %d", p.ID, got.states[i], w)
		}
	}

	got = nil
	out.Reset()
	errb.Reset()
	if code := run([]string{"run", "exec", "-no-canary", "-y", "-out", t.TempDir(), "--", "false"}, &out, &errb); code != exitPartial || got == nil {
		t.Fatalf("want exec to fail preflight with its cleanup confirmed; exit %d\n%s", code, errb.String())
	}
	for i, w := range []phaseState{phaseFailed, phasePending, phaseDone} { // preflight, probe, cleanup
		if got.states[i] != w {
			t.Errorf("exec %s: %d, want %d", got.phases[i].ID, got.states[i], w)
		}
	}
}
