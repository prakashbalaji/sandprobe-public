package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"

	"sandprobe/internal/analysis"
	"sandprobe/internal/catalog"
)

// FBK-1 to FBK-7. Every test pins PATH to a directory of its own, holding a fake gh or none, so no test can reach
// GitHub through a real gh. Token-shaped values are built at run time, so this file holds none.

// ghScript is a fake gh. It logs each call's first two arguments, and records each call's full arguments
// (NUL-separated), the GH_HOST and GH_REPO it saw, and issue create's standard input.
const ghScript = `#!/bin/sh
d=%q
/bin/echo "$1 $2" >> "$d/calls"
case "$1 $2" in
"api graphql") f=graphql ;;
"issue create") f=create ;;
*) exit 64 ;;
esac
for a in "$@"; do printf '%s\0' "$a"; done > "$d/$f.args"
printf 'GH_HOST=%s GH_REPO=%s\n' "$GH_HOST" "$GH_REPO" > "$d/$f.env"
if [ "$f" = graphql ]; then
	[ -f "$d/unauth" ] && exit 4
	/bin/cat "$d/perm"
	exit 0
fi
/bin/cat > "$d/stdin"
/bin/cat "$d/out"
exit "$(/bin/cat "$d/exit")"
`

type fakeGH struct{ dir string }

// pinGH sets PATH to a new directory. mode is "absent", "unauth", or the account's viewerPermission.
func pinGH(t *testing.T, mode string) fakeGH {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	f := fakeGH{dir}
	if mode == "absent" {
		return f
	}
	if err := os.WriteFile(filepath.Join(dir, "gh"), []byte(strings.Replace(ghScript, "%q", "'"+dir+"'", 1)), 0o755); err != nil {
		t.Fatal(err)
	}
	if mode == "unauth" {
		f.set("unauth", "")
	}
	f.login("octo-agent", mode)
	f.set("out", "https://github.com/summationai/sandprobe/issues/42\n")
	f.set("exit", "0")
	return f
}

func (f fakeGH) set(name, s string) { os.WriteFile(filepath.Join(f.dir, name), []byte(s), 0o644) }

func (f fakeGH) login(login, perm string) {
	f.set("perm", `{"data":{"viewer":{"login":"`+login+`"},"repository":{"viewerPermission":"`+perm+`"}}}`)
}

func (f fakeGH) read(name string) string {
	b, _ := os.ReadFile(filepath.Join(f.dir, name))
	return string(b)
}

// args are a call's full arguments: "graphql" or "create".
func (f fakeGH) args(call string) []string {
	s := f.read(call + ".args")
	if s == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(s, "\x00"), "\x00")
}

func (f fakeGH) created() bool { return strings.Contains(f.read("calls"), "issue create") }

type fbRun struct {
	code           int
	stdout, stderr string
}

func writeBody(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "body.md")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// fb runs feedback once, outside a terminal, with the body on a file: a preview, unless args hold -confirm.
func fb(t *testing.T, body string, args ...string) fbRun {
	t.Helper()
	return fbIn(t, "", nil, append(slices.Clone(args), "-body-file", writeBody(t, body))...)
}

func fbIn(t *testing.T, stdin string, tty func() (io.ReadCloser, error), args ...string) fbRun {
	t.Helper()
	var out, errb bytes.Buffer
	code := feedback(args, strings.NewReader(stdin), tty, &out, &errb)
	return fbRun{code, out.String(), errb.String()}
}

// fbFile previews, takes the code, and runs again with it: what an agent does after its person's clear yes.
func fbFile(t *testing.T, body string, args ...string) fbRun {
	t.Helper()
	path := writeBody(t, body)
	pre := fbIn(t, "", nil, append(slices.Clone(args), "-body-file", path, "-o", "json")...)
	var p feedbackResult
	if pre.code != exitApproval || json.Unmarshal([]byte(pre.stdout), &p) != nil || p.Confirm == "" {
		return pre
	}
	return fbIn(t, "", nil, append(slices.Clone(args), "-body-file", path, "-confirm", p.Confirm)...)
}

func answer(s string) func() (io.ReadCloser, error) {
	return func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(s)), nil }
}

const plainBody = "sandprobe run docker hangs before the plan.\nExpected a clear error.\n"

func linkOf(t *testing.T, stdout string) url.Values {
	t.Helper()
	for _, line := range strings.Split(stdout, "\n") {
		if strings.HasPrefix(line, feedbackIssue+"/new?") {
			u, err := url.Parse(line)
			if err != nil {
				t.Fatal(err)
			}
			return u.Query()
		}
	}
	t.Fatalf("no link in:\n%s", stdout)
	return nil
}

func TestFeedbackKinds(t *testing.T) {
	for kind, want := range map[string]struct{ title, label, form, field string }{
		"bug":     {"Bug: it hangs", "bug", "bug-report.yml", "actual"},
		"feature": {"Feature: it hangs", "enhancement", "feature-request.yml", "details"},
		"idea":    {"Idea: it hangs", "enhancement", "feature-request.yml", "details"},
	} {
		gh := pinGH(t, "WRITE")
		r := fbFile(t, plainBody, kind, "-title", "it hangs")
		args := gh.args("create")
		if r.code != exitGraded || !strings.Contains(r.stdout, "Filed: https://github.com/summationai/sandprobe/issues/42") {
			t.Errorf("%s via gh: exit %d\n%s%s", kind, r.code, r.stdout, r.stderr)
		}
		if !slices.Contains(args, "--title="+want.title) || !slices.Contains(args, "--label="+want.label) {
			t.Errorf("%s via gh: args %q", kind, args)
		}
		pinGH(t, "absent")
		r = fbFile(t, plainBody, kind, "-title", "it hangs")
		q := linkOf(t, r.stdout)
		if r.code != exitGraded || q.Get("template") != want.form || q.Get("title") != want.title || !strings.HasPrefix(q.Get(want.field), plainBody) {
			t.Errorf("%s via link: exit %d, query %v", kind, r.code, q)
		}
		if !strings.Contains(r.stdout, "Label: "+want.label+" (the form adds it)") {
			t.Errorf("%s via link: preview doesn't name the form's label:\n%s", kind, r.stdout)
		}
	}
}

// refusal is FBK-7's error document for FBK-4.
type refusal struct {
	Error   string          `json:"error"`
	Matches []feedbackMatch `json:"matches"`
}

// FBK-4: one refusal per pattern, never printing the match, and nothing sent.
func TestFeedbackRefusesCredentials(t *testing.T) {
	t.Setenv("HOME", "/var/lib/agentx")
	b64 := func(n int) string { return strings.Repeat("Ab3d", n) }
	for name, tc := range map[string]struct {
		secret, pattern string
		start           bool // the pattern holds only at the start of a line
	}{
		"private key":      {"-----BEGIN OPENSSH " + "PRIVATE KEY-----", "a private key", false},
		"PuTTY key":        {"PuTTY-User-" + "Key-File-3: ssh-ed25519", "a private key", false},
		"AWS key ID":       {"AKIA" + "Q7XZ3MPLEKEYHOST", "an AWS access key ID", false},
		"AWS role ID":      {"AROA" + "Q7XZ3MPLEKEYHOST", "an AWS access key ID", false},
		"JWT":              {"eyJ" + "hbGciOiJI.eyJ" + "zdWIiOiIx.c2lnbmF0dXJl", "a JSON Web Token", false},
		"GitHub token":     {"gh" + "p_" + b64(9), "a GitHub token", false},
		"GitHub PAT":       {"github" + "_pat_" + b64(9), "a GitHub token", false},
		"Anthropic key":    {"sk-" + "ant-api03-" + b64(5), "an Anthropic API key", false},
		"OpenAI key":       {"sk-" + "proj-" + b64(6), "an OpenAI API key", false},
		"Slack token":      {"xo" + "xb-1234-5678-abcdefgh", "a Slack token or webhook", false},
		"Slack webhook":    {"https://hooks.slack" + ".com/services/T000/B000/xyz", "a Slack token or webhook", false},
		"bearer token":     {"Bearer " + "abcdefghijklmnopqrstu", "a bearer token", false},
		"Authorization":    {"Authorization: token " + "abc", "an Authorization header", false},
		"kubeconfig field": {"client-key-" + "data: LS0tLS1", "a credential field", false},
		"kubeconfig token": {"token: " + "k8s-sa-token-value", "a credential field", true},
		"macOS home":       {"/Users/" + "alice/proj", "a home-directory path", false},
		"Linux home":       {"/home/" + "alice/.env", "a home-directory path", false},
		"Windows home":     {`C:\Users\` + `alice\proj`, "a home-directory path", false},
		"this home":        {"/var/lib/agentx" + "/notes.txt", "a home-directory path", false},
		"long hex":         {strings.Repeat("deadbeef", 5), "a long hex string", false},
		"prefixed hex":     {"dop" + "_v1_" + strings.Repeat("0a1b2c3d", 8), "a long hex string", false},
		"long base64":      {"wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY", "a long base64 string", false},
	} {
		for _, out := range []string{"text", "json"} {
			gh := pinGH(t, "WRITE")
			prefix := "the value is "
			if tc.start {
				prefix = ""
			}
			r := fb(t, "first line\n"+prefix+tc.secret+" here\n", "bug", "-title", "a refusal", "-o", out)
			column := len(prefix) + 1
			if name == "prefixed hex" {
				column += len("dop_v1_") // the match starts after the prefix
			}
			all := r.stdout + r.stderr
			if r.code != exitUsage || strings.Contains(all, tc.secret) || gh.read("calls") != "" {
				t.Errorf("%s (%s): exit %d, gh calls %q, output:\n%s", name, out, r.code, gh.read("calls"), all)
				continue
			}
			if out == "text" {
				if !strings.Contains(r.stderr, fmt.Sprintf("body line 2, column %d: %s [REDACTED]", column, tc.pattern)) {
					t.Errorf("%s: the refusal doesn't name the place and pattern:\n%s", name, r.stderr)
				}
				continue
			}
			var doc refusal
			if json.Unmarshal([]byte(r.stdout), &doc) != nil || doc.Error != "feedback.refused" || len(doc.Matches) != 1 ||
				doc.Matches[0] != (feedbackMatch{Where: "body", Line: 2, Column: column, Pattern: tc.pattern, Text: "[REDACTED]"}) {
				t.Errorf("%s: -o json refusal %+v from\n%s", name, doc, r.stdout)
			}
		}
	}
	pinGH(t, "absent")
	if r := fb(t, plainBody, "bug", "-title", "key AKIA"+"Q7XZ3MPLEKEYHOST"); r.code != exitUsage || !strings.Contains(r.stderr, "title, column 5: an AWS access key ID [REDACTED]") {
		t.Errorf("a title with a key: exit %d\n%s", r.code, r.stderr)
	}
	for _, ordinary := range []string{
		"SEC-3 found ~/.aws/credentials readable, and /root/.ssh too",
		"commit a7868b9, issue https://github.com/summationai/sandprobe/issues/new?template=false-pass.yml",
		"Bearer authentication failed; token: none; the Authorization header was missing",
		"TestPrintableEscapesUnicodeFormatControls and internal/report/scorecard_test.go",
		"sandprobe run exec -provider-endpoints SEC-4,AMP-7 -- docker exec -i box sh",
		"the bearer of bad news; basic HTTP auth; Basic usage; Author: Prakash",
		"password: <redacted>, api_key=$OPENAI_API_KEY, token: ***, client-secret: [REDACTED], \"refresh_token\": null",
		"ssh://git@github.com/summationai/sandprobe.git and https://user@example.com/path",
		"```yaml\ntoken: <redacted>\npassword: null\nauth: ~\n```",
		"```json\n{\"refresh_token\": \"$REFRESH_TOKEN\", \"cookie\": \"\"}\n```",
	} {
		if r := fb(t, ordinary+"\n", "bug", "-title", "ordinary text"); r.code != exitApproval {
			t.Errorf("ordinary text refused: %q\n%s", ordinary, r.stderr)
		}
	}
}

// FBK-4: Sandprobe's own offline output, which an agent may paste into a bug, isn't refused: every check's explain,
// and scorecard, profile and assess of every saved report in text and JSON, and compare.
func TestFeedbackPassesOwnOutput(t *testing.T) {
	reports, _ := filepath.Glob("../../demo/reports/*.json")
	more, _ := filepath.Glob("../../test/reports/*.json")
	reports = append(reports, more...)
	cmds := [][]string{{"compare", reports[0], reports[1]}, {"compare", reports[0], reports[1], "-o", "json"}, {"help"}}
	for _, c := range catalog.Checks {
		cmds = append(cmds, []string{"explain", c.ID})
	}
	for _, r := range reports {
		for _, o := range []string{"text", "json"} {
			cmds = append(cmds, []string{"scorecard", r, "-o", o}, []string{"profile", r, "-o", o}, []string{"assess", r, "canary-egress-deny-v1", "-o", o})
		}
	}
	for _, args := range cmds {
		var out, errb bytes.Buffer
		run(args, &out, &errb)
		o := out.String() + errb.String()
		if m := scanFeedback("", o, o, "/nonexistent-home"); len(m) > 0 {
			t.Errorf("%q is refused: %+v", args, m)
		}
	}
	for _, refused := range []string{"SECRETS=abc123", "secrets_key: abc123", "app-secrets: abc123", "secrets: abc123", "Secrets: abc123",
		"secrets: map[pass:1]; finding IDs [\"SEC-3\"] abc123", "  ● Secrets: Can it read abc123"} {
		if m := scanFeedback("", refused, refused, "/nonexistent-home"); len(m) == 0 {
			t.Errorf("%q passed: only secrets and Secrets alone are Sandprobe's own", refused)
		}
	}
}

// FBK-4, the security reviews of #65: a credential in context is refused at any length and on any line, through gh
// and through the link, in text and in -o json, with and without a -confirm code. The value appears in no output, gh
// never runs, and no link or file is made.
func TestFeedbackRefusesShortCredentials(t *testing.T) {
	const v = "shortsecret"
	const own, doc = "a credential value on its own line", "a credential in a YAML or JSON document"
	cases := map[string]struct {
		text, pattern string
		line          int // the refused line, counting the "first line" before the text
	}{
		"bare Bearer":          {"curl -H 'Bearer " + v + "'", "a bearer token", 2},
		"Authorization Bearer": {"Authorization: Bearer " + v, "an Authorization header", 2},
		"Authorization Basic":  {"Proxy-Authorization: Basic " + v, "an Authorization header", 2},
		"Authorization raw":    {"authorization=" + v, "an Authorization header", 2},
		"Basic credential":     {"sent Basic dXNlcjpw" + "YXNz", "a Basic credential", 2},
		"URL password":         {"git clone https://bob:" + v + "@example.com/repo", "a URL with a password", 2},
		"URL empty user":       {"git clone https://:" + v + "@example.com/repo", "a URL with a password", 2},
		"kubeconfig token":     {"    token: " + v, "a credential field", 2},
		"access-token":         {"access-token: " + v, "a credential field", 2},
		"id-token":             {"  id-token: " + v, "a credential field", 2},
		"refresh-token":        {"refresh-token: " + v, "a credential field", 2},
		"client-key-data":      {"client-key-data: " + v, "a credential field", 2},
		"client-cert-data":     {"client-certificate-data: " + v, "a credential field", 2},
		"client-secret":        {"client-secret: " + v, "a credential field", 2},
		"password YAML":        {"- password: " + v, "a credential field", 2},
		"INI secret key":       {"aws_secret_access_key = " + v, "a credential field", 2},
		"INI session token":    {"aws_session_token=" + v, "a credential field", 2},
		"JSON field":           {`{"refresh_token": "` + v + `"}`, "a credential field", 2},
		"JSON auth":            {`"auth": "` + v + `"`, "a credential field", 2},
		"env variable":         {"export GITHUB_TOKEN=" + v, "a credential field", 2},
		"header":               {"X-Auth-Token: " + v, "a credential field", 2},
		"cookie":               {"Cookie: sid=" + v, "a credential field", 2},
		"api key":              {"x-api-key: " + v, "a credential field", 2},
		"Go assignment":        {`password := "` + v + `"`, "a credential field", 2},
		"flag":                 {"mycli --token " + v, "a credential flag", 2},
		"short GitHub":         {"gh" + "p_" + v, "a GitHub token", 2},
		"short Anthropic":      {"sk-" + "ant-" + v, "an Anthropic API key", 2},
		"short OpenAI":         {"sk-" + v, "an OpenAI API key", 2},
		"short JWT":            {"eyJ" + "a.eyJ" + "b." + v, "a JSON Web Token", 2},
		// the re-reviews: a value on another line, and documents
		"YAML next line":       {"token:\n  " + v, own, 3},
		"YAML after comments":  {"token:\n  # still\n\n  " + v, own, 5},
		"comment after key":    {"token: # the CI one\n  " + v, "a credential field", 2},
		"block scalar":         {"token: |\n  " + v, "a credential field", 2},
		"folded block scalar":  {"client-secret: >-\n  " + v, "a credential field", 2},
		"JSON next line":       {"\"password\":\n  \"" + v + "\",", own, 3},
		"explicit YAML key":    {"? token\n: " + v, own, 3},
		"folded Authorization": {"Authorization:\n  " + v, own, 3},
		"Authorization scheme": {"Authorization: Bearer\n  " + v, own, 3},
		"flag continued":       {"mycli --token \\\n  " + v, "a credential flag", 2},
		"Bearer at line end":   {"the header was Bearer\n  " + v, own, 3},
		"fenced JSON":          {"```json\n{\"user\": {\"password\"\n  :\n  \"" + v + "\"}}\n```", doc, 3},
		"fenced escaped key":   {"```json\n{\"pass\\u0077ord\": \"" + v + "\"}\n```", "a credential field", 3},
		"fenced YAML alias":    {"```yaml\nx: &a [1]\ntoken: *a\n```", "a credential field", 4},
		// the advisor's probes and Codex's exact forms
		"Codex JSON token":            {"\"token\":\n  \"" + v + "\"", own, 3},
		"secrets as a key":            {"secrets: " + v, "a credential field", 2},
		"compare-shaped, changed":     {"  ● Secrets: " + v, "a credential field", 2},
		"DB_PASS":                     {"DB_PASS=" + v, "a credential field", 2},
		"MYSQL_PWD":                   {"export MYSQL_PWD=" + v, "a credential field", 2},
		"second continuation line":    {"token:\n  <redacted>\n  " + v, own, 4},
		"continued after placeholder": {"token: <redacted>\n  " + v, own, 3},
		"folded after placeholder":    {"Authorization: Bearer <token>\n  " + v, own, 3},
		// round 3: a placeholder part never excuses the rest, fences nest by length, and walks read to the end
		"shell concatenation":  {"export TOKEN=\"<redacted>\"" + v, "a credential field", 2},
		"single-quoted concat": {"TOKEN='<redacted>'" + v, "a credential field", 2},
		"YAML words":           {"password: <redacted> " + v, "a credential field", 2},
		"header concat":        {"Authorization: Bearer <token>" + v, "an Authorization header", 2},
		"flag concat":          {"mycli --token \"<x>\"" + v, "a credential flag", 2},
		"Bearer concat":        {"curl -H 'Bearer <x>'" + v, "a bearer token", 2},
		"continuation concat":  {"token:\n  \"<redacted>\"" + v, own, 3},
		"nested fences":        {"````md\n```yaml\nx: &k password\n*k : " + v + "\n```\n````", doc, 5},
		"17th YAML document":   {strings.Repeat("---\nsafe: 1\n", 15) + "---\nx: &k password\n*k : " + v, doc, 34},
		"Codex duplicate key":  {"```json\n{\n  \"pass\\u0077ord\"\n  :\n  \"" + v + "\",\n  \"password\": null\n}\n```", doc, 4},
		"escaped key in prose": {"the config had \"pass\\u0077ord\": \"" + v + "\" in it", "a credential field", 2},
		"HTML entity key":      {"&#112;assword: " + v, "a credential field", 2},
	}
	for _, prefix := range []string{"xoxb", "xoxp", "xoxa", "xoxr", "xoxs", "xoxe", "xoxc", "xoxd", "xoxo", "xapp", "xwfp", "xoxe.xoxp", "xoxe.xapp"} {
		cases["Slack "+prefix] = struct {
			text, pattern string
			line          int
		}{"token " + prefix[:2] + prefix[2:] + "-" + v, "a Slack token or webhook", 2}
	}
	for name, tc := range cases {
		for _, mode := range []string{"absent", "WRITE"} {
			for _, out := range []string{"text", "json"} {
				for _, confirm := range [][]string{nil, {"-confirm", "0123456789ab"}} {
					gh := pinGH(t, mode)
					tmp := t.TempDir()
					t.Setenv("TMPDIR", tmp)
					args := append([]string{"bug", "-title", "a short credential", "-o", out}, confirm...)
					r := fb(t, "first line\n"+tc.text+"\n", args...)
					all := r.stdout + r.stderr
					if r.code != exitUsage || strings.Contains(all, v) || strings.Contains(all, feedbackIssue) || gh.read("calls") != "" {
						t.Errorf("%s (%s, %s, %q): exit %d, gh calls %q, output:\n%s", name, mode, out, confirm, r.code, gh.read("calls"), all)
						continue
					}
					if left, _ := os.ReadDir(tmp); len(left) != 0 {
						t.Errorf("%s (%s, %s): a file was made: %v", name, mode, out, left)
					}
					if out == "text" && !strings.Contains(r.stderr, fmt.Sprintf("body line %d, column ", tc.line)) {
						t.Errorf("%s: the refusal doesn't name line %d:\n%s", name, tc.line, r.stderr)
					}
					var d refusal
					if out == "json" && (json.Unmarshal([]byte(r.stdout), &d) != nil || d.Error != "feedback.refused" || len(d.Matches) == 0 ||
						d.Matches[0].Pattern != tc.pattern || d.Matches[0].Line != tc.line || d.Matches[0].Text != "[REDACTED]") {
						t.Errorf("%s: -o json refusal %+v, want %q on line %d", name, d, tc.pattern, tc.line)
					}
				}
			}
		}
	}
	// A whole body that is one JSON document, read only by the walk.
	gh := pinGH(t, "absent")
	r := fb(t, "{\"user\": {\"password\"\n:\n\""+v+"\"}}\n", "bug", "-title", "whole", "-o", "json")
	var d refusal
	if json.Unmarshal([]byte(r.stdout), &d) != nil || r.code != exitUsage || strings.Contains(r.stdout, v) || gh.read("calls") != "" ||
		len(d.Matches) == 0 || d.Matches[0].Pattern != doc || d.Matches[0].Line != 1 {
		t.Errorf("a whole JSON body: exit %d, %+v", r.code, d)
	}
}

// FBK-4: a walk that reaches a limit refuses and names it; it never passes what it didn't read.
func TestFeedbackWalkLimits(t *testing.T) {
	pinGH(t, "absent")
	deepJSON := strings.Repeat("[", maxJSONDepth+1) + strings.Repeat("]", maxJSONDepth+1)
	var fences []string
	for n := maxFenceDepth + 5; n >= 3; n-- {
		fences = append(fences, strings.Repeat("`", n))
	}
	closers := slices.Clone(fences)
	slices.Reverse(closers)
	deepFences := strings.Join(fences, "\n") + "\nx\n" + strings.Join(closers, "\n")
	for name, tc := range map[string]struct{ body, limit string }{
		"JSON depth":   {deepJSON + "\n", "deeper"},
		"fence depth":  {deepFences + "\n", fmt.Sprintf("fenced blocks nested more than %d deep", maxFenceDepth)},
		"YAML aliases": {"a: &a [x, x, x, x, x, x, x, x, x]\nb: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a]\n", ""},
	} {
		r := fb(t, tc.body, "bug", "-title", "limits", "-o", "json")
		var d refusal
		json.Unmarshal([]byte(r.stdout), &d)
		if tc.limit == "" { // aliases aren't expanded in a node walk, so they reach no limit and aren't a credential
			if r.code != exitApproval {
				t.Errorf("%s: exit %d, %+v", name, r.code, d)
			}
			continue
		}
		if r.code != exitUsage || len(d.Matches) == 0 || !strings.Contains(d.Matches[0].Pattern, tc.limit) {
			t.Errorf("%s: exit %d, %+v", name, r.code, d)
		}
	}
	// The JSON walk reads tokens: a key repeated later, as null, doesn't hide the first one's value.
	var out []feedbackMatch
	walkJSON(`{"password": "abc", "password": null}`, 0, &out)
	if len(out) != 1 {
		t.Errorf("a repeated key: %+v", out)
	}
}

// FBK-3: a hostile saved report still passes ANL-1, and nothing from it but fixed vocabularies leaves.
func TestFeedbackReportSummary(t *testing.T) {
	aws, ghTok := "AKIA"+"Q7XZ3MPLEKEYHOST", "gh"+"p_"+strings.Repeat("Zx9", 12)
	// The first set is credential-shaped, which FBK-4 would refuse anyway; the second isn't, so only FBK-3's
	// allowlist keeps it out.
	for name, planted := range map[string][]string{
		"credential-shaped": {"/home/alice/.aws/credentials", "/Users/alice/work/.env", "STRIPE_SECRET_KEY", "OPENAI_API_KEY", aws, ghTok, "alice-prod-box-7"},
		"plain names":       {"alice-prod-box-7", "STRIPE_SECRET_KEY", "notes/plan.txt", "agent@devbox"},
	} {
		t.Run(name, func(t *testing.T) { hostileSummary(t, planted) })
	}
}

func hostileSummary(t *testing.T, planted []string) {
	t.Helper()
	h := strings.Join(planted, " ")
	planted = append(planted, "alice")
	base, err := os.ReadFile("../../demo/reports/vibe.json")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(base, &m); err != nil {
		t.Fatal(err)
	}
	obj := func(v any, keys ...string) map[string]any {
		for _, k := range keys {
			v = v.(map[string]any)[k]
		}
		return v.(map[string]any)
	}
	obj(m, "run")["provider"] = h
	obj(m, "run", "box")["name"] = h
	obj(m, "run", "box")["provider_id"], obj(m, "manifest")["BoxID"] = h, h
	m["statement"], m["lead"], m["boundary"] = h, h, h
	obj(m, "probe")["version"] = h
	obj(m, "cleanup")["outcome"], obj(m, "cleanup")["residual"] = h, h
	obj(m, "identity", "setuid_scan")["files"] = []any{h}
	obj(m, "limits")["not_tested"] = []any{h}
	obj(m, "limits", "skipped")["AMP-6"], obj(m, "manifest", "Skipped")["AMP-6"] = h, h
	obj(m, "manifest", "Targets")["SEC-3"] = []any{h}
	for _, list := range []string{"checks", "findings", "receipts", "contacted"} {
		for _, v := range m[list].([]any) {
			for _, k := range []string{"evidence", "reason", "gets", "title", "From", "host"} {
				if _, ok := v.(map[string]any)[k]; ok {
					v.(map[string]any)[k] = h
				}
			}
		}
	}
	hostile, _ := json.Marshal(m)
	path := filepath.Join(t.TempDir(), "hostile.json")
	if err := os.WriteFile(path, hostile, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := analysis.Load(path); err != nil {
		t.Fatalf("the hostile report must pass ANL-1, or this test proves nothing: %v", err)
	}
	for _, mode := range []string{"WRITE", "absent"} {
		gh := pinGH(t, mode)
		r := fbFile(t, plainBody, "bug", "-title", "a summary", "-report", path)
		u, _ := url.QueryUnescape(r.stdout)
		sent := r.stdout + r.stderr + u + strings.Join(gh.args("create"), "\n") + gh.read("stdin")
		if r.code != exitGraded {
			t.Fatalf("%s: exit %d\n%s", mode, r.code, r.stderr)
		}
		for _, p := range planted {
			if strings.Contains(sent, p) {
				t.Errorf("%s: %q left the machine", mode, p)
			}
		}
		for _, want := range []string{"### Report summary", "- Provider: other", "- Valid: yes. Complete: yes.", "- Score: 1/6", "SEC-1 finding", "AMP-8.blk scoped_out", "not re-verified (ANL-1)"} {
			if !strings.Contains(sent, want) {
				t.Errorf("%s: the summary lacks %q", mode, want)
			}
		}
	}
	gh := pinGH(t, "WRITE")
	r := fbFile(t, plainBody, "bug", "-title", "a summary", "-report", "../../demo/reports/vibe.json")
	if !strings.Contains(gh.read("stdin"), "- Provider: docker") || !strings.Contains(gh.read("stdin"), "### Where you ran it\n\n"+runtime.GOOS+"/"+runtime.GOARCH+", docker\n") {
		t.Errorf("a known provider is named: exit %d\n%s", r.code, gh.read("stdin"))
	}
	edited := bytes.Replace(base, []byte(`"result": "finding"`), []byte(`"result": "`+h+`"`), 1)
	if bytes.Equal(edited, base) {
		t.Fatal("the edit didn't apply")
	}
	os.WriteFile(path, edited, 0o600)
	gh = pinGH(t, "WRITE")
	r = fb(t, plainBody, "bug", "-title", "a summary", "-report", path)
	if r.code != exitUsage || !strings.Contains(r.stderr, "unsupported, inconsistent or unsafe report input") || strings.Contains(r.stderr, "alice") || gh.read("calls") != "" {
		t.Errorf("an edited report: exit %d\n%s", r.code, r.stderr)
	}
}

// FBK-6: gh's exact arguments for both calls, whatever GH_HOST and GH_REPO say; its standard input; failures; and the
// link when gh is absent or signed out.
func TestFeedbackTransport(t *testing.T) {
	t.Setenv("GH_HOST", "evil.example")
	t.Setenv("GH_REPO", "evil/repo")
	title := `$(touch /tmp/x); "quoted" & -flag`
	gh := pinGH(t, "TRIAGE")
	pre := fb(t, plainBody, "bug", "-title", title, "-o", "json")
	var p feedbackResult
	json.Unmarshal([]byte(pre.stdout), &p)
	r := fbFile(t, plainBody, "bug", "-title", title)
	query := `query=query{viewer{login} repository(owner:"summationai",name:"sandprobe"){viewerPermission}}`
	if got, want := gh.args("graphql"), []string{"api", "graphql", "--hostname", "github.com", "-f", query}; !slices.Equal(got, want) {
		t.Errorf("graphql args %q, want %q", got, want)
	}
	want := []string{"issue", "create", "--repo", "github.com/summationai/sandprobe", "--title=Bug: " + title, "--body-file", "-", "--label=bug"}
	if got := gh.args("create"); r.code != exitGraded || !slices.Equal(got, want) {
		t.Errorf("create args %q, want %q (exit %d)", got, want, r.code)
	}
	if env := gh.read("create.env"); env != "GH_HOST=evil.example GH_REPO=evil/repo\n" {
		t.Errorf("the fake didn't see the environment this test sets, so it proves nothing: %q", env)
	}
	if gh.read("stdin") != p.Body || !strings.Contains(p.Body, "### Sandprobe version\n\nsandprobe "+Version) {
		t.Errorf("gh's standard input isn't the previewed body:\n%s", gh.read("stdin"))
	}
	if calls := gh.read("calls"); calls != "api graphql\napi graphql\napi graphql\nissue create\n" {
		t.Errorf("gh calls: %q", calls)
	}

	gh = pinGH(t, "READ")
	r = fbFile(t, plainBody, "feature", "-title", "x")
	if r.code != exitGraded || slices.Contains(gh.args("create"), "--label=enhancement") || !strings.Contains(r.stdout, "Label: none") {
		t.Errorf("an account that can't triage gets no label: %q\n%s", gh.args("create"), r.stdout)
	}

	for _, mode := range []string{"absent", "unauth"} {
		gh = pinGH(t, mode)
		r = fbFile(t, plainBody, "bug", "-title", "x")
		if r.code != exitGraded || gh.created() || linkOf(t, r.stdout).Get("template") != "bug-report.yml" {
			t.Errorf("gh %s: exit %d, created %v\n%s", mode, r.code, gh.created(), r.stdout)
		}
	}

	for name, f := range map[string]func(fakeGH){
		"gh fails":         func(g fakeGH) { g.set("exit", "1"); g.set("out", "") },
		"no URL":           func(g fakeGH) { g.set("out", "done\n") },
		"another repo URL": func(g fakeGH) { g.set("out", "https://github.com/evil/sandprobe/issues/1\n") },
	} {
		gh = pinGH(t, "WRITE")
		f(gh)
		r = fbFile(t, plainBody, "bug", "-title", "x")
		if r.code != exitPartial || !strings.Contains(r.stdout, "nothing is confirmed filed") || strings.Contains(r.stdout, "Filed:") || linkOf(t, r.stdout).Get("title") != "Bug: x" {
			t.Errorf("%s: exit %d\n%s", name, r.code, r.stdout)
		}
	}
}

// FBK-6: the link's encoding and its length limit.
func TestFeedbackLink(t *testing.T) {
	pinGH(t, "absent")
	title := "a & b = c? #1 + 50% ünïcode"
	body := "line one & two\nline 2: a+b=c #x ?y\n"
	r := fbFile(t, body, "idea", "-title", title, "-provider", "exec")
	q := linkOf(t, r.stdout)
	if q.Get("title") != "Idea: "+title || !strings.HasPrefix(q.Get("details"), body) || q.Get("version") != "sandprobe "+Version+" ("+runtime.Version()+")" ||
		!strings.HasSuffix(q.Get("platform"), ", exec") || len(q) != 5 {
		t.Errorf("the link doesn't decode to the issue: %v", q)
	}
	link := strings.TrimSpace(r.stdout[strings.LastIndex(r.stdout, "\n"+feedbackIssue):])
	if strings.ContainsAny(link, " \n+") || len(link) > maxLink {
		t.Errorf("the link isn't percent-encoded within %d characters: %s", maxLink, link)
	}

	long := strings.Repeat("this line is long enough to push the link past its limit.\n", 200)
	r = fbFile(t, long, "bug", "-title", "long", "-o", "json")
	var res feedbackResult
	if err := json.Unmarshal([]byte(r.stdout), &res); err != nil || r.code != exitGraded {
		t.Fatalf("exit %d: %v\n%s", r.code, err, r.stdout)
	}
	u, _ := url.Parse(res.URL)
	if len(res.URL) > maxLink || u.Query().Has("actual") || res.BodyFile == "" {
		t.Errorf("a long body: link %d characters, file %q", len(res.URL), res.BodyFile)
	}
	defer os.Remove(res.BodyFile)
	st, err := os.Stat(res.BodyFile)
	saved, _ := os.ReadFile(res.BodyFile)
	if err != nil || st.Mode().Perm() != 0o600 || string(saved) != long {
		t.Errorf("the body file: %v, mode %v, same %v", err, st.Mode(), string(saved) == long)
	}
}

// FBK-7: one JSON document.
func TestFeedbackJSON(t *testing.T) {
	gh := pinGH(t, "MAINTAIN")
	r := fbFile(t, plainBody, "feature", "-title", "json", "-o", "json")
	var res map[string]any
	if err := json.Unmarshal([]byte(r.stdout), &res); err != nil || r.code != exitGraded {
		t.Fatalf("exit %d: %v\n%s", r.code, err, r.stdout)
	}
	for k, v := range map[string]any{"repo": "github.com/summationai/sandprobe", "public": true, "account": "octo-agent", "kind": "feature",
		"title": "Feature: json", "via": "gh", "filed": true, "url": "https://github.com/summationai/sandprobe/issues/42"} {
		if res[k] != v {
			t.Errorf("%s: %v, want %v", k, res[k], v)
		}
	}
	if labels, _ := res["labels"].([]any); len(labels) != 1 || labels[0] != "enhancement" || !strings.HasPrefix(res["body"].(string), plainBody) {
		t.Errorf("labels %v, body %q", res["labels"], res["body"])
	}
	for _, k := range []string{"needs_approval", "confirm"} {
		if _, ok := res[k]; ok {
			t.Errorf("a filed issue carries %s", k)
		}
	}

	for _, login := range []string{"evil\u001b[31m", "-lead", "a--b", strings.Repeat("a", 40), ""} {
		gh.login(login, "WRITE")
		gh.set("calls", "")
		r = fb(t, plainBody, "bug", "-title", "login", "-o", "json")
		var p feedbackResult
		json.Unmarshal([]byte(r.stdout), &p)
		if p.Via != "link" || p.Account != "" || gh.created() {
			t.Errorf("login %q: via %s, account %q, created %v", login, p.Via, p.Account, gh.created())
		}
	}
}

var codeLine = regexp.MustCompile(`-confirm ([0-9a-f]{12})\n`)

// FBK-5: consent is bound to exactly what is posted.
func TestFeedbackConsent(t *testing.T) {
	gh := pinGH(t, "WRITE")
	path := writeBody(t, plainBody)
	args := func(extra ...string) []string {
		return append([]string{"bug", "-title", "consent", "-body-file", path}, extra...)
	}

	// A preview: the code, nothing sent, no link.
	r := fbIn(t, "", nil, args("-o", "json")...)
	var p feedbackResult
	if json.Unmarshal([]byte(r.stdout), &p) != nil || r.code != exitApproval || !p.NeedsApproval || !p.Public || p.Account != "octo-agent" ||
		!confirmForm.MatchString(p.Confirm) || p.URL != "" || p.Filed || gh.created() {
		t.Fatalf("the -o json preview: exit %d, %+v", r.code, p)
	}
	r = fbIn(t, "", nil, args()...)
	m := codeLine.FindStringSubmatch(r.stdout)
	if r.code != exitApproval || m == nil || m[1] != p.Confirm || strings.Contains(r.stdout, feedbackIssue) || gh.created() ||
		!strings.Contains(r.stdout, "A PUBLIC issue on github.com/summationai/sandprobe, filed through gh as GitHub user @octo-agent.") {
		t.Errorf("the text preview: exit %d, code %v (json %s)\n%s", r.code, m, p.Confirm, r.stdout)
	}

	// The matching code files exactly what was previewed.
	r = fbIn(t, "", nil, args("-confirm", p.Confirm)...)
	if r.code != exitGraded || !slices.Contains(gh.args("create"), "--title="+p.Title) || !slices.Contains(gh.args("create"), "--label=bug") || gh.read("stdin") != p.Body {
		t.Errorf("the matching code: exit %d, args %q\n%s", r.code, gh.args("create"), r.stderr)
	}

	// A code for anything else files nothing and makes no link.
	changed := func(name string, setup func() string, want string) {
		t.Helper()
		gh = pinGH(t, "WRITE")
		code := setup()
		for _, out := range []string{"text", "json"} {
			r := fbIn(t, "", nil, args("-confirm", code, "-o", out)...)
			if r.code != exitApproval || gh.created() || strings.Contains(r.stdout+r.stderr, feedbackIssue+"/new") ||
				!strings.Contains(r.stdout+r.stderr, want) || codeLine.MatchString(r.stdout+r.stderr) {
				t.Errorf("%s (%s): exit %d, created %v\n%s%s", name, out, r.code, gh.created(), r.stdout, r.stderr)
			}
		}
	}
	previewCode := func() string {
		r := fbIn(t, "", nil, args("-o", "json")...)
		var p feedbackResult
		json.Unmarshal([]byte(r.stdout), &p)
		return p.Confirm
	}
	changed("an edited body", func() string {
		code := previewCode()
		os.WriteFile(path, []byte(plainBody+"one more line\n"), 0o600)
		return code
	}, "the code doesn't match")
	os.WriteFile(path, []byte(plainBody), 0o600)
	changed("another account", func() string {
		code := previewCode()
		gh.login("someone-else", "WRITE")
		return code
	}, "the code doesn't match")
	changed("another label", func() string {
		gh.login("octo-agent", "READ")
		code := previewCode()
		gh.login("octo-agent", "WRITE")
		return code
	}, "the code doesn't match")
	changed("gh signed in after a link preview", func() string {
		gh.set("unauth", "")
		code := previewCode()
		os.Remove(filepath.Join(gh.dir, "unauth"))
		return code
	}, "the preview was for a link, but gh is now signed in as @octo-agent")
	changed("a wrong code", func() string { return "0123456789ab" }, "the code doesn't match")

	// -y is refused, and so is a code in the wrong form; neither reaches gh.
	for _, bad := range [][]string{{"-y"}, {"-confirm", "XYZ"}, {"-confirm", p.Confirm + "0"}} {
		gh = pinGH(t, "WRITE")
		r = fbIn(t, "", nil, args(bad...)...)
		if r.code != exitUsage || gh.read("calls") != "" || !strings.Contains(r.stderr, "-confirm") {
			t.Errorf("%q: exit %d\n%s", bad, r.code, r.stderr)
		}
	}

	// In a terminal the person may type yes instead, and only "yes" counts.
	for typed, filed := range map[string]bool{"yes\n": true, " yes \n": true, "y\n": false, "YES\n": false, "\n": false, "yes please\n": false, "": false} {
		gh = pinGH(t, "WRITE")
		r = fbIn(t, "", answer(typed), args()...)
		if gh.created() != filed || (filed && r.code != exitGraded) || (!filed && r.code != exitApproval) ||
			!strings.Contains(r.stdout, "File this public issue as @octo-agent? Type yes: ") {
			t.Errorf("typed %q: exit %d, created %v\n%s", typed, r.code, gh.created(), r.stdout)
		}
	}
	gh = pinGH(t, "WRITE")
	noTTY := func() (io.ReadCloser, error) { return nil, errors.New("no /dev/tty") }
	if r = fbIn(t, "", noTTY, args()...); r.code != exitApproval || gh.created() {
		t.Errorf("no /dev/tty: exit %d", r.code)
	}
	if r = fbIn(t, "", answer("yes\n"), args("-o", "json")...); r.code != exitApproval || gh.created() || strings.Contains(r.stdout, "Type yes") {
		t.Errorf("-o json never prompts: exit %d\n%s", r.code, r.stdout)
	}
	pinGH(t, "absent")
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	r = fbIn(t, "", nil, args()...)
	if r.code != exitApproval || strings.Contains(r.stdout, feedbackIssue) || !strings.Contains(r.stdout, "no link was made") {
		t.Errorf("a link preview makes no link:\n%s", r.stdout)
	}
	r = fbIn(t, "", answer("yes\n"), args()...)
	if r.code != exitGraded || !strings.Contains(r.stdout, "Print the link to file this public issue yourself? Type yes: ") || linkOf(t, r.stdout).Get("title") != "Bug: consent" {
		t.Errorf("a typed yes prints the link: exit %d\n%s", r.code, r.stdout)
	}
	if left, _ := os.ReadDir(tmp); len(left) != 0 {
		t.Errorf("a file was made: %v", left)
	}

	// A body on standard input previews, then files with its code.
	gh = pinGH(t, "WRITE")
	r = fbIn(t, plainBody, nil, "bug", "-title", "stdin", "-body-file", "-", "-o", "json")
	json.Unmarshal([]byte(r.stdout), &p)
	if r = fbIn(t, plainBody, nil, "bug", "-title", "stdin", "-body-file", "-", "-confirm", p.Confirm); r.code != exitGraded || !strings.HasPrefix(gh.read("stdin"), plainBody) {
		t.Errorf("a body on standard input: exit %d\n%s", r.code, r.stderr)
	}
}

func TestFeedbackUsage(t *testing.T) {
	pinGH(t, "absent")
	for name, tc := range map[string]struct {
		body string
		args []string
		want string
	}{
		"no kind":        {plainBody, []string{"-title", "x"}, "name one kind"},
		"bad kind":       {plainBody, []string{"praise", "-title", "x"}, "name one kind"},
		"no title":       {plainBody, []string{"bug"}, "-title is required"},
		"two-line title": {plainBody, []string{"bug", "-title", "a\nb"}, "control or format character"},
		"long title":     {plainBody, []string{"bug", "-title", strings.Repeat("x", 201)}, "longer than 200"},
		"empty body":     {" \n\n", []string{"bug", "-title", "x"}, "the body is empty"},
		"big body":       {strings.Repeat("x", maxBody+1), []string{"bug", "-title", "x"}, "longer than 48 KiB"},
		"escape":         {"ok\nred \x1b[31m text\n", []string{"bug", "-title", "x"}, "body line 2, column 5: a control or format character (U+001B)"},
		"bidi":           {"a \u202e b\n", []string{"bug", "-title", "x"}, "U+202E"},
		"not UTF-8":      {"\xff\xfe", []string{"bug", "-title", "x"}, "isn't UTF-8"},
		"bad provider":   {plainBody, []string{"bug", "-title", "x", "-provider", "/home/alice"}, "-provider takes one of"},
		"bad -o":         {plainBody, []string{"bug", "-title", "x", "-o", "yaml"}, "-o takes text or json"},
		"-y":             {plainBody, []string{"bug", "-title", "x", "-y"}, "takes no -y"},
		"bad -confirm":   {plainBody, []string{"bug", "-title", "x", "-confirm", "yes"}, "12-character code"},
	} {
		r := fb(t, tc.body, tc.args...)
		if r.code != exitUsage || !strings.Contains(r.stderr, tc.want) {
			t.Errorf("%s: exit %d\n%s", name, r.code, r.stderr)
		}
	}
	if r := fbIn(t, "", nil, "bug", "-title", "x"); r.code != exitUsage || !strings.Contains(r.stderr, "-body-file is required") {
		t.Errorf("no body file: exit %d\n%s", r.code, r.stderr)
	}
	r := fbFile(t, "\ufeffwindows\r\nline\r\n", "bug", "-title", "x")
	if q := linkOf(t, r.stdout); !strings.HasPrefix(q.Get("actual"), "windows\nline\n") {
		t.Errorf("CRLF and a byte order mark: %q", q.Get("actual"))
	}
	var out, errb bytes.Buffer
	if code := run([]string{"feedback", "praise"}, &out, &errb); code != exitUsage || !strings.Contains(errb.String(), "name one kind") {
		t.Errorf("run feedback: exit %d\n%s", code, errb.String())
	}
}
