package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"sandprobe/internal/analysis"
	"sandprobe/internal/catalog"
	"sandprobe/internal/host"
	"sandprobe/internal/obs"
	"sandprobe/internal/report"
	"sandprobe/recipes"

	"go.yaml.in/yaml/v3"
)

// FBK-1: one repository, on one host.
const (
	feedbackRepo  = "summationai/sandprobe"
	feedbackHost  = "github.com"
	feedbackIssue = "https://github.com/" + feedbackRepo + "/issues"
	maxTitle      = 200      // characters, before the kind's prefix (FBK-2)
	maxBody       = 48 << 10 // bytes (FBK-2)
	maxLink       = 8000     // characters (FBK-6)
	redacted      = "[REDACTED]"
)

// feedbackKind is FBK-1's title prefix and label, and FBK-6's form and its main field.
type feedbackKind struct{ prefix, label, form, formName, field string }

var feedbackKinds = map[string]feedbackKind{
	"bug":     {"Bug: ", "bug", "bug-report.yml", "bug report", "actual"},
	"feature": {"Feature: ", "enhancement", "feature-request.yml", "feature request", "details"},
	"idea":    {"Idea: ", "enhancement", "feature-request.yml", "feature request", "details"},
}

// feedbackProviders is FBK-1's fixed list, for -provider and a summary's provider (FBK-3).
func feedbackProviders() map[string]bool {
	known := map[string]bool{"aws-nitro": true, "docker": true, "exec": true}
	for name := range host.TermsExclusions {
		known[name] = true
	}
	for name := range recipes.Shipped {
		known[name] = true
	}
	return known
}

// feedbackResult is FBK-7's document, and what the preview shows.
type feedbackResult struct {
	Repo          string   `json:"repo"`
	Public        bool     `json:"public"`            // always: the issue is public (FBK-5)
	Account       string   `json:"account,omitempty"` // the gh login it is or would be filed as (FBK-7)
	Kind          string   `json:"kind"`
	Title         string   `json:"title"`
	Labels        []string `json:"labels"`
	Body          string   `json:"body"`
	Via           string   `json:"via"` // gh or link
	Filed         bool     `json:"filed"`
	URL           string   `json:"url,omitempty"`
	BodyFile      string   `json:"body_file,omitempty"`
	NeedsApproval bool     `json:"needs_approval,omitempty"`
	Confirm       string   `json:"confirm,omitempty"` // a preview's code (FBK-5)
	Note          string   `json:"note,omitempty"`
}

// feedbackMatch is one FBK-4 refusal; text is always [REDACTED].
type feedbackMatch struct {
	Where   string `json:"where"`
	Line    int    `json:"line,omitempty"`
	Column  int    `json:"column,omitempty"`
	Pattern string `json:"pattern"`
	Text    string `json:"text"`
}

// feedback is FBK-1 to FBK-7. It has its own flags. stdin and tty are the caller's, so tests choose them: tty is nil
// unless standard input and output are both terminals, and it opens /dev/tty for FBK-5's typed yes.
func feedback(args []string, stdin io.Reader, tty func() (io.ReadCloser, error), stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("feedback", flag.ContinueOnError)
	fs.SetOutput(stderr)
	o := opts{stdout: stdout}
	var title, bodyFile, reportPath, provider, confirm string
	var yes bool
	fs.StringVar(&o.out, "o", "text", "output: text or json")
	fs.BoolVar(&yes, "y", false, "not taken here: FBK-5's -confirm <code> replaces it")
	fs.StringVar(&confirm, "confirm", "", "the code a preview printed: files exactly that issue, only if nothing changed (FBK-5)")
	fs.StringVar(&title, "title", "", "the issue's title, one line")
	fs.StringVar(&bodyFile, "body-file", "", "a file holding the issue's body, or - for standard input")
	fs.StringVar(&reportPath, "report", "", "a saved report.json: adds a short summary of it, never the report (FBK-3)")
	fs.StringVar(&provider, "provider", "", "the provider or run mode it's about, such as docker, exec or sprites")
	positional, err := parse(fs, args)
	if err != nil {
		return reportErr(o, stderr, fail("usage", err.Error(), feedbackUsage, exitUsage))
	}
	if o.out != "text" && o.out != "json" {
		return reportErr(o, stderr, fail("usage", "-o takes text or json", feedbackUsage+" -o json", exitUsage))
	}
	if yes { // FBK-1, FBK-5
		return reportErr(o, stderr, fail("usage", "feedback takes no -y: consent is bound to the exact issue",
			"run it without -y to preview; show your person the exact issue; only with their yes, run it again with -confirm <code>", exitUsage))
	}
	if confirm != "" && !confirmForm.MatchString(confirm) {
		return reportErr(o, stderr, fail("usage", "-confirm takes the 12-character code a preview printed", "run it without -confirm to preview and get the code", exitUsage))
	}
	if o.json() {
		tty = nil // never prompt under -o json (AGT-1)
	}
	res, fields, err := composeFeedback(positional, title, bodyFile, reportPath, provider, stdin)
	if err != nil {
		return reportErr(o, stderr, err)
	}
	k := feedbackKinds[res.Kind]
	home, _ := os.UserHomeDir()
	// FBK-4 first, whatever -confirm holds. The title's columns count from what was typed, after the fixed prefix.
	if matches := scanFeedback(strings.TrimPrefix(res.Title, k.prefix), res.Body, fields.body, home); len(matches) > 0 {
		return refuseFeedback(o, stderr, matches)
	}
	gh, login, triage := ghReady() // FBK-6
	res.Via, res.Labels = "link", []string{k.label}
	if gh != "" {
		res.Via, res.Labels, res.Account = "gh", []string{}, login
		if triage {
			res.Labels = []string{k.label}
		}
	}
	code := confirmCode(res)
	switch {
	case confirm != "": // FBK-5: only the exact issue the person approved
		if confirm != code {
			return reportErr(o, stderr, changedError(confirm, res, k))
		}
		printPreview(o, res, k)
	case tty != nil:
		printPreview(o, res, k)
		prompt := "\nPrint the link to file this public issue yourself? Type yes: "
		if res.Via == "gh" {
			prompt = "\nFile this public issue as @" + res.Account + "? Type yes: "
		}
		if !askYes(tty, o.stdout, prompt) {
			return reportErr(o, stderr, fail("needs_approval", "nothing was sent: only yes files it", "run it again and type yes, or preview it and use -confirm <code>", exitApproval))
		}
	default:
		res.NeedsApproval, res.Confirm = true, code
		if o.json() {
			o.emit(res)
		} else {
			printPreview(o, res, k)
			printConsent(o.stdout, res)
		}
		return exitApproval
	}
	exit := exitGraded
	if res.Via == "gh" {
		if res.URL, err = ghCreate(gh, res); err == nil {
			res.Filed = true
		} else {
			res.Note = err.Error() + ", so nothing is confirmed filed. Check " + feedbackIssue + " before you open this link."
			res.Via, res.Labels, res.Account, exit = "link", []string{k.label}, "", exitPartial
		}
	}
	if !res.Filed {
		if res.URL, res.BodyFile, err = feedbackLink(k, res, fields); err != nil {
			return reportErr(o, stderr, err)
		}
	}
	printSent(o, res, k)
	return exit
}

const feedbackUsage = "sandprobe feedback bug|feature|idea -title <one line> -body-file <file or -> [-report <report.json>] [-provider <name>] [-confirm <code>]"

// feedbackTTY is FBK-5's terminal: /dev/tty, only through the gate UX-7's keys use (AGT-1): standard input and
// output both terminals, stdout this process's own, in the foreground process group, and not CI, SANDPROBE_NO_KEYS
// or TERM=dumb.
func feedbackTTY(stdout io.Writer) func() (io.ReadCloser, error) {
	if !shouldInteract(opts{out: "text", stdout: stdout}) {
		return nil
	}
	return func() (io.ReadCloser, error) { return os.Open("/dev/tty") }
}

var confirmForm = regexp.MustCompile(`^[0-9a-f]{12}$`)

// confirmCode is FBK-5's code: the first 12 hex digits of SHA-256 over exactly what would be posted, as it would
// reach gh's arguments and standard input.
func confirmCode(res feedbackResult) string {
	b, _ := json.Marshal(struct {
		Scheme, Repo, Via, Account string
		Labels                     []string
		Title, Body                string
	}{"sandprobe-feedback/1", res.Repo, res.Via, res.Account, res.Labels, res.Title, res.Body})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])[:12]
}

// changedError is FBK-5's refusal of a code that doesn't match: it says what changed when it can, never the new code.
func changedError(confirm string, res feedbackResult, k feedbackKind) error {
	asLink := res
	asLink.Via, asLink.Account, asLink.Labels = "link", "", []string{k.label}
	msg := "nothing was sent: the code doesn't match what would be filed now. The title, body, labels, account or the way it goes changed since the preview, or the code is wrong"
	if res.Via == "gh" && confirm == confirmCode(asLink) {
		msg = "nothing was sent: the preview was for a link, but gh is now signed in as @" + res.Account + ", so the issue would be filed under that account"
	}
	return fail("feedback.changed", msg, "run it again without -confirm, show your person the new preview, and only with their yes use its code", exitApproval)
}

// askYes is FBK-5's typed consent: the prompt, then one line from the terminal, and only "yes" counts.
func askYes(tty func() (io.ReadCloser, error), w io.Writer, prompt string) bool {
	f, err := tty()
	if err != nil {
		return false
	}
	defer f.Close()
	fmt.Fprint(w, prompt)
	answer, _ := bufio.NewReader(f).ReadString('\n')
	return strings.TrimSpace(answer) == "yes"
}

// printConsent is a preview's last word: nothing was sent, and how the person's yes files exactly this.
func printConsent(w io.Writer, res feedbackResult) {
	if res.Via == "gh" {
		fmt.Fprintf(w, "\nNothing was sent. Show your person this exact title and body, tell them it is PUBLIC and filed as\n"+
			"GitHub user @%s, and ask them. Only after their yes, run the same command again with:\n  -confirm %s\n", res.Account, res.Confirm)
		return
	}
	fmt.Fprintf(w, "\nNothing was sent and no link was made. Show your person this exact title and body and tell them it is\n"+
		"PUBLIC. Only after their yes, run the same command again with this, to print the link:\n  -confirm %s\n", res.Confirm)
}

// feedbackFields are what FBK-6's link puts in the form: the main field, version and platform.
type feedbackFields struct{ main, version, platform, body string } // body: the person's own text (FBK-4's walk)

// composeFeedback is FBK-1 to FBK-3: it checks the input and builds exactly what would be sent.
func composeFeedback(positional []string, title, bodyFile, reportPath, provider string, stdin io.Reader) (feedbackResult, feedbackFields, error) {
	var res feedbackResult
	var f feedbackFields
	if len(positional) != 1 || feedbackKinds[positional[0]].label == "" {
		return res, f, fail("usage", "name one kind: bug, feature or idea", feedbackUsage, exitUsage)
	}
	kind := positional[0]
	title = strings.TrimSpace(title)
	if title == "" {
		return res, f, fail("usage", "-title is required: one line saying what it's about", feedbackUsage, exitUsage)
	}
	if utf8.RuneCountInString(title) > maxTitle {
		return res, f, fail("usage", fmt.Sprintf("-title is longer than %d characters", maxTitle), "shorten the title; details go in the body", exitUsage)
	}
	if where := unsafeText("title", title, false); where != "" {
		return res, f, fail("usage", where, "the title is one plain line", exitUsage)
	}
	if bodyFile == "" {
		return res, f, fail("usage", "-body-file is required: a file holding the issue's body, or - for standard input", feedbackUsage, exitUsage)
	}
	body, err := readBody(bodyFile, stdin)
	if err != nil {
		return res, f, err
	}
	known := feedbackProviders()
	if provider != "" && !known[provider] {
		names := make([]string, 0, len(known))
		for n := range known {
			names = append(names, n)
		}
		sort.Strings(names)
		return res, f, fail("usage", "-provider takes one of: "+strings.Join(names, ", "), "leave -provider out, or name it in the body", exitUsage)
	}
	summary, reported := "", ""
	if reportPath != "" {
		d, err := analysis.Load(reportPath)
		if err != nil { // ANL-1's fixed error: nothing from the file is shown
			return res, f, fail("report.input", "unsupported, inconsistent or unsafe report input", reportInputFix, exitUsage)
		}
		summary, reported = reportSummary(d, known)
	}
	if provider == "" && reported != "other" {
		provider = reported
	}
	f.main, f.body = body, body
	if summary != "" {
		f.main = strings.TrimRight(body, "\n") + "\n\n" + summary
	}
	f.version = "sandprobe " + Version + " (" + runtime.Version() + ")"
	f.platform = runtime.GOOS + "/" + runtime.GOARCH
	if provider != "" {
		f.platform += ", " + provider
	}
	k := feedbackKinds[kind]
	res = feedbackResult{Repo: feedbackHost + "/" + feedbackRepo, Public: true, Kind: kind, Title: k.prefix + title,
		Body: strings.TrimRight(f.main, "\n") + "\n\n### Sandprobe version\n\n" + f.version + "\n\n### Where you ran it\n\n" +
			f.platform + "\n\n_Filed with `sandprobe feedback`._\n"}
	return res, f, nil
}

// readBody is FBK-2: bounded, UTF-8, CRLF read as LF, no leading byte order mark, and nothing that hides text.
func readBody(name string, stdin io.Reader) (string, error) {
	var r io.Reader = stdin
	if name != "-" {
		file, err := os.Open(name)
		if err != nil {
			return "", fail("usage", "can't open -body-file", "name a file you can read, or - for standard input", exitUsage)
		}
		defer file.Close()
		r = file
	}
	b, err := io.ReadAll(io.LimitReader(r, maxBody+1))
	if err != nil {
		return "", fail("usage", "can't read the body", "name a file you can read, or - for standard input", exitUsage)
	}
	if len(b) > maxBody {
		return "", fail("usage", fmt.Sprintf("the body is longer than %d KiB", maxBody>>10), "shorten it: link to a gist or a repository for anything long", exitUsage)
	}
	body := strings.TrimPrefix(strings.ReplaceAll(string(b), "\r\n", "\n"), "\ufeff")
	if !utf8.ValidString(body) {
		return "", fail("usage", "the body isn't UTF-8 text", "save it as UTF-8", exitUsage)
	}
	if strings.TrimSpace(body) == "" {
		return "", fail("usage", "the body is empty", "say what happened, or what you'd like, in the body", exitUsage)
	}
	for i, line := range strings.Split(body, "\n") {
		if where := unsafeText(fmt.Sprintf("body line %d", i+1), line, true); where != "" {
			return "", fail("usage", where, "remove it: the body is plain text", exitUsage)
		}
	}
	return body, nil
}

// unsafeText names the first control or format character in s (FBK-2), or returns "".
func unsafeText(where, s string, tabs bool) string {
	for i, r := range s {
		if (r == '\t' && tabs) || !(unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == 0x2028 || r == 0x2029) {
			continue
		}
		return fmt.Sprintf("%s, column %d: a control or format character (U+%04X)", where, utf8.RuneCountInString(s[:i])+1, r)
	}
	return ""
}

// reportSummary is FBK-3: values from fixed vocabularies only, never a string from the report. It returns the
// summary and the provider it names.
func reportSummary(d *report.Doc, known map[string]bool) (string, string) {
	provider := "other"
	if known[d.Run.Provider] {
		provider = d.Run.Provider
	}
	yes := map[bool]string{true: "yes", false: "no"}
	var b strings.Builder
	b.WriteString("### Report summary\n\n")
	b.WriteString("From a saved report, checked for structure only and not re-verified (ANL-1).\n\n")
	fmt.Fprintf(&b, "- Provider: %s\n- Valid: %s. Complete: %s.\n", provider, yes[d.Grade.Valid], yes[d.Grade.Complete])
	if card := report.Score(*d); card.Valid {
		fmt.Fprintf(&b, "- Score: %d/%d\n", card.Score, card.Of)
	}
	results := map[string]bool{obs.Pass: true, obs.Finding: true, obs.Absent: true, obs.ScopedOut: true, obs.Unknown: true, obs.NotFound: true, obs.Skipped: true}
	var checks []string
	for _, c := range d.Checks {
		if _, ok := catalog.Get(c.ID); !ok {
			continue
		}
		result := "other"
		if results[c.Result] {
			result = c.Result
		}
		checks = append(checks, c.ID+" "+result)
	}
	fmt.Fprintf(&b, "- Checks: %s\n", strings.Join(checks, ", "))
	return b.String(), provider
}

// credentialPattern is one FBK-4 pattern. With words set, the regexp ends where a value begins, and the value is
// read as shell words (shellWords): one word, or every word to the value's end. The match is refused when any word
// isn't ok. Otherwise, when its regexp has a group, the group is the value, and flag, when set, says whether the match
// is refused.
type credentialPattern struct {
	name  string
	re    *regexp.Regexp
	flag  func(match, value string) bool
	words int // 0: none; oneWord or allWords
	ok    func(word string) bool
}

// The ways shellWords reads a value.
const (
	oneWord  = 1 // a flag's or a Bearer's value: one shell word, commas and all
	allWords = 2 // a field's, a header's or a continuation line's value: every word, split at , and ;, to a comment
	//              or the line's end
)

// credKey is a key whose name says it holds a credential (FBK-4): YAML, INI, JSON, environment and header names.
const credKey = `[A-Za-z0-9_.-]*(?:token|secret|passw(?:or)?d|passphrase|api[_-]?key|apikey|access[_-]?key|private[_-]?key|` +
	`client[_-]?key|signing[_-]?key|encryption[_-]?key|master[_-]?key|key[_-]?data|certificate[_-]?data|authority[_-]?data|` +
	`credentials?|cookie|session[_-]?id|sessionid)[A-Za-z0-9_.-]*|(?:[A-Za-z0-9_.-]*[_.-])?auth(?:[_.-][A-Za-z0-9_.-]*)?|` +
	`[A-Za-z0-9_.-]*[_.-](?:pass|pwd)(?:[_.-][A-Za-z0-9_.-]*)?|(?:pass|pwd)[_.-][A-Za-z0-9_.-]*` // DB_PASS, MYSQL_PWD; not a bare pass

// placeholder is FBK-4's short list of values that carry nothing.
var placeholder = regexp.MustCompile(`^(?:<[^>]*>|\[[^\]]*\]|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|[*xX•.…_-]+|` +
	`(?i:redacted|none|null|nil|empty|unset|hidden|masked|true|false|~|n/a))$`)

func notPlaceholder(_, v string) bool { return !placeholder.MatchString(v) }

func emptyOrPlaceholder(w string) bool { return w == "" || placeholder.MatchString(w) }

// ownLine is one of Sandprobe's own lines that prints its Secrets area or category as a key, exactly: profile's
// count line and compare's question line. No other line that names secrets as a key is exempt.
var ownLine = func() *regexp.Regexp {
	var asks []string
	for _, c := range report.Categories {
		if c.Name == "Secrets" {
			for _, a := range c.Ask {
				asks = append(asks, regexp.QuoteMeta(a))
			}
		}
	}
	sort.Strings(asks)
	id := `"[A-Z]+-[0-9A-Za-z.]+"`
	return regexp.MustCompile(`^secrets: map\[(?:[a-z_]+:[0-9]+(?: [a-z_]+:[0-9]+)*)?\]; finding IDs \[(?:` + id + `(?: ` + id + `)*)?\]$` +
		`|^  ● Secrets: (?:` + strings.Join(asks, "|") + `)$`)
}()

// bearerWords are the ordinary words a "Bearer" may precede in prose.
var bearerWords = map[string]bool{"token": true, "tokens": true, "auth": true, "authentication": true, "authorization": true,
	"header": true, "headers": true, "scheme": true, "credential": true, "credentials": true, "value": true, "of": true,
	"and": true, "or": true, "the": true, "a": true, "an": true, "is": true, "in": true, "for": true, "with": true, "to": true}

var authScheme = regexp.MustCompile(`(?i)^(?:bearer|basic|token|bot|digest|negotiate|aws4-hmac-sha256)(?:\s+|$)`)

// credentialPatterns are FBK-4's, most specific first: where two overlap, the first names the match.
var credentialPatterns = []credentialPattern{
	{name: "a private key", re: regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|PuTTY-User-Key-File-[0-9]+:`)},
	{name: "an AWS access key ID", re: regexp.MustCompile(`\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|APKA|AROA|ASCA)[A-Z0-9]{16,}`)},
	{name: "a JSON Web Token", re: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`)},
	{name: "a GitHub token", re: regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]+|github_pat_[A-Za-z0-9_]+)`)},
	{name: "an Anthropic API key", re: regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]+`)},
	{name: "an OpenAI API key", re: regexp.MustCompile(`\bsk-[A-Za-z0-9][A-Za-z0-9_-]*`)},
	// Slack: xox and any letter (xoxb, xoxp, xoxa, xoxr, xoxs, xoxe, ...), xapp, xwfp, and the rotating xoxe.xoxp, xoxe.xapp.
	{name: "a Slack token or webhook", re: regexp.MustCompile(`\b(?:xox[a-z]|xapp|xwfp)(?:\.(?:xox[a-z]|xapp))?-[A-Za-z0-9._-]+|https://hooks\.slack\.com/[A-Za-z0-9/_-]+`)},
	{name: "a URL with a password", re: regexp.MustCompile(`\b[A-Za-z][A-Za-z0-9+.-]*://[^/\s:@]*:([^/\s@]*)@`), flag: notPlaceholder},
	{name: "an Authorization header", re: regexp.MustCompile(`(?i)\b(?:proxy-)?authorization["']?\s*(?::=|[:=])\s*(?:(?:bearer|basic|token|bot|digest|negotiate|aws4-hmac-sha256)\s+)?`),
		words: allWords, ok: func(w string) bool {
			return emptyOrPlaceholder(w) || (authScheme.MatchString(w) && emptyOrPlaceholder(authScheme.ReplaceAllString(w, "")))
		}},
	{name: "a bearer token", re: regexp.MustCompile(`(?i)\bbearer\s+`), words: oneWord,
		ok: func(w string) bool { return emptyOrPlaceholder(w) || bearerWords[strings.ToLower(w)] }},
	{name: "a Basic credential", re: regexp.MustCompile(`(?i)\bbasic\s+`), words: oneWord, ok: func(w string) bool {
		if w == "" || placeholder.MatchString(w) || strings.ContainsAny(w, " \t") {
			return true
		}
		rest := w[1:] // a capital first letter is prose; base64 mixes cases inside
		return !strings.ContainsAny(w, "0123456789+/=") && (strings.ToLower(rest) == rest || strings.ToUpper(rest) == rest)
	}},
	{name: "a credential field", re: regexp.MustCompile(`(?i)(?:` + credKey + `)["']?\s*(?::=|[:=])\s*`), words: allWords, ok: emptyOrPlaceholder},
	{name: "a credential flag", re: regexp.MustCompile(`(?i)(?:^|\s)--?(?:` + credKey + `)\s+`), words: oneWord, ok: emptyOrPlaceholder},
	{name: "a home-directory path", re: regexp.MustCompile(`(?:/Users/|/home/)[^/\s]+|(?i:\b[a-z]:\\users\\[^\\\s]+)`)},
	{name: "a long hex string", re: regexp.MustCompile(`[0-9A-Fa-f]{32,}`)}, // no \b: a prefix such as dop_v1_ is a word character
	{name: "a long base64 string", re: regexp.MustCompile(`[A-Za-z0-9+/_-]{32,}={0,2}`), flag: func(m, _ string) bool {
		return strings.ContainsAny(m, "0123456789") && strings.ContainsAny(m, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") && strings.ContainsAny(m, "abcdefghijklmnopqrstuvwxyz")
	}},
}

// shellWords reads the value at line[start:] the way a shell joins one: quoted parts ("..." and '...') and unquoted
// parts next to each other make one word, so a placeholder part never excuses the rest. Whitespace separates words,
// and in allWords so do an unquoted , and ;, which never end a value (fail closed: TOKEN=<x>,y is refused). Only a #
// after whitespace, or the line's end, ends the value. A backtick is always data: it neither quotes nor ends
// anything, so no Markdown code span, escaped or not, can cut a value short. An unclosed " or ' runs to the line's
// end. Inside "...", a backslash goes only before $ ` " or \, as a shell's does, and stays before anything else; a
// word that an escape changed is also returned raw, every backslash kept, so both forms must pass and no escape can
// turn a value into a placeholder. Each word is checked exactly as read, nothing stripped, so `true)` is not `true`:
// when in doubt, refuse. It returns the words and where the value ends.
func shellWords(line string, start, mode int) ([]string, int) {
	var words []string
	var w, raw strings.Builder
	in := false
	end := func() {
		if in {
			words = append(words, w.String())
			if raw.String() != w.String() {
				words = append(words, raw.String())
			}
			w.Reset()
			raw.Reset()
			in = false
		}
	}
	for i := start; i < len(line); {
		c := line[i]
		switch {
		case c == ' ' || c == '\t':
			end()
			if mode == oneWord && len(words) > 0 {
				return words, i
			}
			j := i
			for j < len(line) && (line[j] == ' ' || line[j] == '\t') {
				j++
			}
			if j < len(line) && line[j] == '#' {
				return words, i
			}
			i = j
		case (c == ',' || c == ';') && mode == allWords: // a separator, never an end: each part must pass
			end()
			i++
		case c == '"' || c == '\'':
			j := i + 1
			for j < len(line) && line[j] != c {
				if c == '"' && line[j] == '\\' && j+1 < len(line) && strings.IndexByte("$`\"\\", line[j+1]) >= 0 {
					raw.WriteByte('\\')
					j++
				}
				w.WriteByte(line[j])
				raw.WriteByte(line[j])
				j++
			}
			in, i = true, j+1
		default:
			w.WriteByte(c)
			raw.WriteByte(c)
			in, i = true, i+1
		}
	}
	end()
	return words, len(line)
}

// escape is a character written as an escape a reader decodes: JSON's and YAML's \u and \U, \x, and HTML's numeric
// references, which GitHub renders.
var escape = regexp.MustCompile(`\\u[0-9A-Fa-f]{4}|\\U[0-9A-Fa-f]{8}|\\x[0-9A-Fa-f]{2}|&#[0-9]{1,7};|&#[xX][0-9A-Fa-f]{1,6};`)

// decodeEscapes is a line as its reader sees it, so `"pass\u0077ord": x` is scanned as `"password": x`.
func decodeEscapes(s string) string {
	return escape.ReplaceAllStringFunc(s, func(e string) string {
		var n uint64
		switch {
		case strings.HasPrefix(e, "&#x"), strings.HasPrefix(e, "&#X"):
			n, _ = strconv.ParseUint(e[3:len(e)-1], 16, 32)
		case strings.HasPrefix(e, "&#"):
			n, _ = strconv.ParseUint(e[2:len(e)-1], 10, 32)
		default:
			n, _ = strconv.ParseUint(e[2:], 16, 32)
		}
		if r := rune(n); utf8.ValidRune(r) && !unicode.IsControl(r) && !unicode.Is(unicode.Cf, r) {
			return string(r)
		}
		return " "
	})
}

// scanFeedback is FBK-4 on the title and every line of the body, each as written and as decoded, and its walk of
// doc, the person's own text, which begins the body, so their lines agree. It records where and why, never the text.
func scanFeedback(title, body, doc, home string) []feedbackMatch {
	patterns := credentialPatterns
	if home != "" && home != "/" && home != "/root" {
		patterns = append(patterns[:len(patterns):len(patterns)], credentialPattern{name: "a home-directory path", re: regexp.MustCompile(regexp.QuoteMeta(home) + `\b`)})
	}
	out := scanLine(patterns, "title", 0, title)
	if d := decodeEscapes(title); d != title && len(out) == 0 {
		out = scanLine(patterns, "title", 0, d)
	}
	lines := strings.Split(body, "\n")
	decoded := make([]string, len(lines))
	seen := map[int]bool{}
	for i, line := range lines {
		m := scanLine(patterns, "body", i+1, line)
		if decoded[i] = decodeEscapes(line); len(m) == 0 && decoded[i] != line {
			m = scanLine(patterns, "body", i+1, decoded[i])
		}
		for _, x := range m {
			seen[x.Line] = true
		}
		out = append(out, m...)
	}
	var docs []feedbackMatch
	scanDocuments(doc, 0, 0, &docs)
	for _, m := range append(scanContinued(decoded), docs...) { // they only add: one finding per line
		if !seen[m.Line] {
			seen[m.Line] = true
			out = append(out, m)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Where != out[j].Where {
			return out[i].Where == "title"
		}
		return out[i].Line < out[j].Line || (out[i].Line == out[j].Line && out[i].Column < out[j].Column)
	})
	return out
}

// danglingKey is a line whose credential field, flag, Authorization header, explicit YAML key or Bearer ends before
// its value: at the key, its separator, its scheme or a comment (FBK-4). Its value is on a later line.
var danglingKey = regexp.MustCompile("(?i)(?:" +
	"(?:^|\\s)--?(?:" + credKey + ")" +
	"|(?:" + credKey + ")[\"']?\\s*(?::=|[:=])" +
	"|\\b(?:proxy-)?authorization[\"']?\\s*(?::=|[:=])(?:\\s*(?:bearer|basic|token|bot|digest|negotiate|aws4-hmac-sha256))?" +
	"|^\\s*\\?\\s*[\"']?(?:" + credKey + "|(?:proxy-)?authorization)[\"']?" +
	"|\\b(bearer)" +
	")\\s*\\\\?\\s*(?:(?:#|//).*)?$")

// keyOnly is a line that ends with a credential key and no separator: JSON or YAML whose colon is on a later line.
var keyOnly = regexp.MustCompile(`(?i)(?:^|[\s{,\[])["']?(?:` + credKey + `|(?:proxy-)?authorization)["']?\s*$`)

// contextKey is a line that names a credential: a field, a flag or an Authorization header, with or without a value.
var contextKey = regexp.MustCompile("(?i)(?:(?:^|\\s)--?(?:" + credKey + ")(?:\\s|$)|(?:" + credKey + ")[\"']?\\s*(?::=|[:=])" +
	"|\\b(?:proxy-)?authorization[\"']?\\s*(?::=|[:=]))")

// scanContinued is FBK-4's value on other lines, on the decoded lines. A dangling key's value is the next line that
// isn't blank or a comment (a YAML value, JSON's next token, a folded header); a key whose colon is on a later line
// takes what follows that colon. After any line naming a credential, each later line indented deeper than it
// continues the value (a YAML continuation, an obs-folded header). Each must be empty or a placeholder.
func scanContinued(lines []string) []feedbackMatch {
	var out []feedbackMatch
	for i, line := range lines {
		if ownLine.MatchString(line) {
			continue
		}
		d := danglingKey.FindStringSubmatch(line)
		j := nextValue(lines, i)
		if d == nil && keyOnly.MatchString(line) && j >= 0 {
			if t := strings.TrimSpace(lines[j]); strings.HasPrefix(t, ":") || strings.HasPrefix(t, "=") {
				if rest := strings.TrimSpace(t[1:]); rest != "" {
					if !valueOK(rest, false) {
						out = append(out, valueMatch(lines, j))
					}
				} else if k := nextValue(lines, j); k >= 0 && !valueOK(lines[k], false) {
					out = append(out, valueMatch(lines, k))
				}
			}
			continue
		}
		if d == nil && !contextKey.MatchString(line) {
			continue
		}
		if d != nil && j >= 0 {
			if !valueOK(lines[j], d[1] != "") {
				out = append(out, valueMatch(lines, j))
				continue
			}
			j = nextValue(lines, j)
		}
		for key := indent(line); j >= 0 && indent(lines[j]) > key; j = nextValue(lines, j) {
			if !valueOK(lines[j], false) {
				out = append(out, valueMatch(lines, j))
				break
			}
		}
	}
	return out
}

// nextValue is the index of the next line after i that isn't blank or a comment, or -1.
func nextValue(lines []string, i int) int {
	for j := i + 1; j < len(lines); j++ {
		if t := strings.TrimSpace(lines[j]); t != "" && !strings.HasPrefix(t, "#") && !strings.HasPrefix(t, "//") {
			return j
		}
	}
	return -1
}

func indent(line string) int { return len(line) - len(strings.TrimLeft(line, " \t")) }

// valueOK says a value line carries nothing: every shell word on it, after its list dash and explicit-key colon, is
// empty or a placeholder; for a Bearer, only its first word counts, and it may also be an ordinary one.
func valueOK(line string, bearer bool) bool {
	v := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(line), "- "), ":"))
	mode := allWords
	if bearer {
		mode = oneWord
	}
	words, _ := shellWords(v, 0, mode)
	ok := func(w string) bool { return emptyOrPlaceholder(w) || (bearer && bearerWords[strings.ToLower(w)]) }
	for _, w := range words {
		if !ok(w) {
			return false
		}
	}
	return true
}

func valueMatch(lines []string, j int) feedbackMatch {
	return feedbackMatch{Where: "body", Line: j + 1, Column: utf8.RuneCountInString(lines[j][:indent(lines[j])]) + 1, Pattern: "a credential value on its own line", Text: redacted}
}

// limitMatch is FBK-4's refusal when a walk can't finish: it names the limit, never passing what it didn't read.
func limitMatch(line int, limit string) feedbackMatch {
	return feedbackMatch{Where: "body", Line: line, Column: 1, Pattern: limit, Text: redacted}
}

var (
	credKeyWhole = regexp.MustCompile("(?i)^(?:" + credKey + "|(?:proxy-)?authorization)$")
	// fenceOpen is a CommonMark code fence's opening line, after any blockquote and list markers: three or more
	// backticks or tildes, then an info string.
	fenceOpen  = regexp.MustCompile("^((?:\\s*>)*\\s*(?:(?:[-*+]|[0-9]{1,9}[.)])\\s+)?\\s*)(`{3,}|~{3,})(.*)$")
	blockquote = regexp.MustCompile(`^(?:\s*>)+ ?`)
)

// The walks' limits (FBK-4). Reaching one refuses the issue and names it.
const (
	maxFenceDepth = 16    // fenced blocks inside fenced blocks
	maxJSONDepth  = 10000 // containers, the root included, as encoding/json's own decoder allows
)

// scanDocuments is FBK-4's walk: text, and each fenced block in it, parsed as YAML and as JSON (YAML reads most JSON,
// but not a key whose colon is on the next line). Fences follow CommonMark: a block closes only at a fence of the same
// character at least as long as its opener, so a longer fence holds shorter ones, and each block's content is itself
// walked, fences and all. A parse that fails adds nothing and its error is never shown; a limit reached refuses.
func scanDocuments(text string, offset, depth int, out *[]feedbackMatch) {
	if depth > maxFenceDepth {
		*out = append(*out, limitMatch(offset+1, fmt.Sprintf("fenced blocks nested more than %d deep, which the checker doesn't read", maxFenceDepth)))
		return
	}
	walkYAML(text, offset, out)
	walkJSON(text, offset, out)
	lines := strings.Split(text, "\n")
	for i := 0; i < len(lines); i++ {
		m := fenceOpen.FindStringSubmatch(lines[i])
		if m == nil || (m[2][0] == '`' && strings.Contains(m[3], "`")) {
			continue
		}
		quoted, char, n := strings.Contains(m[1], ">"), m[2][0], len(m[2])
		var block []string
		j := i + 1
		for ; j < len(lines); j++ {
			l := lines[j]
			if quoted {
				l = blockquote.ReplaceAllString(l, "")
			}
			if t := strings.TrimSpace(l); len(t) >= n && t[0] == char && strings.Trim(t, string(char)) == "" {
				break
			}
			block = append(block, l)
		}
		scanDocuments(strings.Join(block, "\n"), offset+i+1, depth+1, out)
		i = j
	}
}

// walkYAML decodes every document to the end and walks each; offset is the line before the text's first. A parse
// that fails stops it and adds nothing, but the parser's own depth and alias limits, and a parser panic, refuse.
func walkYAML(text string, offset int, out *[]feedbackMatch) {
	defer func() {
		if recover() != nil {
			*out = append(*out, limitMatch(offset+1, "a YAML document the checker failed on"))
		}
	}()
	dec := yaml.NewDecoder(strings.NewReader(text))
	for {
		var doc yaml.Node
		err := dec.Decode(&doc)
		if err == io.EOF {
			return
		}
		if err != nil {
			if strings.Contains(err.Error(), "exceeded max depth") || strings.Contains(err.Error(), "excessive aliasing") {
				*out = append(*out, limitMatch(offset+1, "a YAML document deeper or more aliased than the checker reads"))
			}
			return
		}
		walkNode(&doc, offset, out)
	}
}

// walkNode refuses a mapping key named as a credential, or Authorization, written or through an alias, unless its
// value is empty or a placeholder. An alias, a tag, or a non-empty mapping or list as its value is refused too.
func walkNode(n *yaml.Node, offset int, out *[]feedbackMatch) {
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			name := k
			if k.Kind == yaml.AliasNode && k.Alias != nil { // an alias as a key names what it points to
				name = k.Alias
			}
			if name.Kind == yaml.ScalarNode && credKeyWhole.MatchString(name.Value) && credentialNode(v) {
				*out = append(*out, feedbackMatch{Where: "body", Line: offset + k.Line, Column: k.Column, Pattern: "a credential in a YAML or JSON document", Text: redacted})
			}
		}
	}
	for _, c := range n.Content {
		walkNode(c, offset, out)
	}
}

func credentialNode(v *yaml.Node) bool {
	switch v.Kind {
	case yaml.ScalarNode:
		if v.Style&yaml.TaggedStyle != 0 {
			return true
		}
		return v.Tag != "!!null" && v.Value != "" && !placeholder.MatchString(v.Value)
	case yaml.MappingNode, yaml.SequenceNode:
		return len(v.Content) > 0
	}
	return true // an alias, or anything else
}

// walkJSON reads text as JSON values through the token stream, never into a map, so every key is seen, a repeated
// one included, and refuses what walkNode would; a key is placed at the line where it ends. A stream that breaks stops
// it, keeping what it found before; nesting deeper than maxJSONDepth refuses.
func walkJSON(text string, offset int, out *[]feedbackMatch) {
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	lineAt := func() int { return offset + strings.Count(text[:dec.InputOffset()], "\n") + 1 }
	refuse := func(line int) {
		*out = append(*out, feedbackMatch{Where: "body", Line: line, Column: 1, Pattern: "a credential in a YAML or JSON document", Text: redacted})
	}
	errDeep := errors.New("too deep")
	// value reads one value; cred is the line of the credential key that holds it, or 0. depth is the number of
	// containers this value opens or sits in: the root container is 1.
	var value func(cred, depth int) error
	value = func(cred, depth int) error {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case json.Delim:
			if depth > maxJSONDepth {
				return errDeep
			}
			n := 0
			for dec.More() {
				inner := 0
				if t == '{' {
					k, err := dec.Token()
					if err != nil {
						return err
					}
					if key, _ := k.(string); credKeyWhole.MatchString(key) {
						inner = lineAt()
					}
				}
				if err := value(inner, depth+1); err != nil {
					return err
				}
				n++
			}
			if _, err := dec.Token(); err != nil {
				return err
			}
			if cred > 0 && n > 0 {
				refuse(cred)
			}
		case string:
			if cred > 0 && !emptyOrPlaceholder(t) {
				refuse(cred)
			}
		case json.Number:
			if cred > 0 {
				refuse(cred)
			}
		}
		return nil
	}
	for {
		err := value(0, 1)
		var syntax *json.SyntaxError
		switch {
		case err == nil:
			continue
		case err == io.EOF, err == io.ErrUnexpectedEOF:
			// the end, or a document cut short: every token before it was walked
		case err == errDeep || strings.Contains(err.Error(), "exceeded max depth"):
			*out = append(*out, limitMatch(offset+1, fmt.Sprintf("a JSON document nested more than %d deep, which the checker doesn't read", maxJSONDepth)))
		case errors.As(err, &syntax):
			// not JSON from here on; the line rules read it
		default: // anything else stopped the walk: refuse rather than pass what it didn't read
			*out = append(*out, limitMatch(offset+1, "a JSON document the checker couldn't finish"))
		}
		return
	}
}

func scanLine(patterns []credentialPattern, where string, n int, line string) []feedbackMatch {
	var taken [][2]int
	var out []feedbackMatch
	own := ownLine.MatchString(line)
	for _, p := range patterns {
		if own && p.name == "a credential field" {
			continue
		}
		for _, loc := range p.re.FindAllStringSubmatchIndex(line, -1) {
			span := [2]int{loc[0], loc[1]}
			if p.words != 0 {
				words, end := shellWords(line, loc[1], p.words)
				refused := false
				for _, w := range words {
					refused = refused || !p.ok(w)
				}
				if !refused {
					continue
				}
				span[1] = max(end, loc[1])
			} else {
				value := line[loc[0]:loc[1]]
				if len(loc) > 2 && loc[2] >= 0 {
					value = line[loc[2]:loc[3]]
				}
				if p.flag != nil && !p.flag(line[loc[0]:loc[1]], value) {
					continue
				}
			}
			overlap := false
			for _, t := range taken {
				overlap = overlap || (span[0] < t[1] && t[0] < span[1])
			}
			if overlap {
				continue
			}
			start := loc[1] - len(strings.TrimLeft(line[loc[0]:loc[1]], " \t")) // a flag's match starts at the space before it
			taken = append(taken, span)
			out = append(out, feedbackMatch{Where: where, Line: n, Column: utf8.RuneCountInString(line[:start]) + 1, Pattern: p.name, Text: redacted})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Column < out[j].Column })
	return out
}

// refuseFeedback is FBK-4's refusal and FBK-7's error document: where and why, with [REDACTED], and exit 2.
func refuseFeedback(o opts, stderr io.Writer, matches []feedbackMatch) int {
	msg := "nothing was sent: the issue holds text that looks like a credential or a home-directory path"
	fix := "remove or replace each one, then run this again"
	if o.json() {
		o.emit(struct {
			Code    string          `json:"error"`
			Message string          `json:"message"`
			Fix     string          `json:"fix"`
			Matches []feedbackMatch `json:"matches"`
		}{"feedback.refused", msg, fix, matches})
		return exitUsage
	}
	fmt.Fprintf(stderr, "sandprobe: %s\n", msg)
	for _, m := range matches {
		where := "title"
		if m.Where == "body" {
			where = fmt.Sprintf("body line %d", m.Line)
		}
		fmt.Fprintf(stderr, "  %s, column %d: %s %s\n", where, m.Column, m.Pattern, m.Text)
	}
	fmt.Fprintf(stderr, "  fix: %s\n", fix)
	return exitUsage
}

// printPreview is FBK-5: exactly what would be sent, that it's public, and the account, before anything is.
func printPreview(o opts, res feedbackResult, k feedbackKind) {
	if o.json() {
		return // the one -o json document carries the preview (FBK-7)
	}
	w := o.stdout
	label := strings.Join(res.Labels, ", ")
	if res.Via == "link" {
		fmt.Fprintf(w, "A PUBLIC issue on %s. gh isn't signed in here, so once confirmed this prints a link to\n", res.Repo)
		fmt.Fprintf(w, "GitHub's %s form, filled in with what's below, for you to submit yourself.\n", k.formName)
		label += " (the form adds it)"
	} else {
		fmt.Fprintf(w, "A PUBLIC issue on %s, filed through gh as GitHub user @%s.\n", res.Repo, res.Account)
		if label == "" {
			label = "none: only the maintainers can label it, and they will"
		}
	}
	rule := strings.Repeat("─", 60)
	fmt.Fprintf(w, "\nTitle: %s\nLabel: %s\nBody:\n%s\n%s%s\n", shown(res.Title), label, rule, shown(strings.TrimRight(res.Body, "\n"))+"\n", rule)
}

// shown is text for the terminal through printable (ANL-2), line by line, keeping tabs: FBK-2 already refuses what
// it would escape, so the preview is exactly what is sent.
func shown(s string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		parts := strings.Split(line, "\t")
		for j := range parts {
			parts[j] = printable(parts[j])
		}
		lines[i] = strings.Join(parts, "\t")
	}
	return strings.Join(lines, "\n")
}

// printSent is FBK-7's last word: the issue's URL, or the link.
func printSent(o opts, res feedbackResult, k feedbackKind) {
	if o.json() {
		o.emit(res)
		return
	}
	w := o.stdout
	if res.Filed {
		fmt.Fprintf(w, "\nFiled: %s\n", res.URL)
		return
	}
	if res.Note != "" {
		fmt.Fprintf(w, "\n%s\n", res.Note)
	}
	if res.BodyFile != "" {
		fmt.Fprintf(w, "\nThe body is too long for a link, so it's in %s. Paste it into the form's first box.\n", printable(res.BodyFile))
	}
	if res.Kind == "bug" {
		fmt.Fprintln(w, "\nThe form also asks what you ran and what you expected.")
	}
	fmt.Fprintf(w, "\nOpen this link to file it:\n%s\n", res.URL)
}

// ghEnv is gh's own environment, never prompting: gh signs in its own way, and Sandprobe reads no token.
func ghEnv() []string {
	return append(os.Environ(), "GH_PROMPT_DISABLED=1", "GH_NO_UPDATE_NOTIFIER=1", "NO_COLOR=1")
}

// ghReady is FBK-6: gh's path when it's on PATH and signed in to github.com, the account's login, and whether that
// account may triage. One read-only query; a login not in GitHub's own form means no gh.
func ghReady() (string, string, bool) {
	path, err := exec.LookPath("gh")
	if err != nil {
		return "", "", false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	query := `query{viewer{login} repository(owner:"summationai",name:"sandprobe"){viewerPermission}}`
	cmd := exec.CommandContext(ctx, path, "api", "graphql", "--hostname", feedbackHost, "-f", "query="+query)
	cmd.Env, cmd.Stdin, cmd.Stderr = ghEnv(), nil, io.Discard
	out, err := cmd.Output()
	var v struct {
		Data struct {
			Viewer     struct{ Login string }
			Repository struct{ ViewerPermission string }
		}
	}
	if err != nil || json.Unmarshal(out, &v) != nil || len(v.Data.Viewer.Login) > 39 || !ghLogin.MatchString(v.Data.Viewer.Login) || v.Data.Repository.ViewerPermission == "" {
		return "", "", false
	}
	switch v.Data.Repository.ViewerPermission {
	case "ADMIN", "MAINTAIN", "WRITE", "TRIAGE":
		return path, v.Data.Viewer.Login, true
	}
	return path, v.Data.Viewer.Login, false
}

// ghLogin is GitHub's login form: letters, digits and single hyphens, neither first nor last, at most 39.
var ghLogin = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9]|-[A-Za-z0-9]){0,38}$`)

var issueURL = regexp.MustCompile(`^https://github\.com/summationai/sandprobe/issues/[1-9][0-9]*$`)

// ghCreate is FBK-6: each value one argument, the body on standard input, gh's errors never shown.
func ghCreate(path string, res feedbackResult) (string, error) {
	args := []string{"issue", "create", "--repo", feedbackHost + "/" + feedbackRepo, "--title=" + res.Title, "--body-file", "-"}
	for _, l := range res.Labels {
		args = append(args, "--label="+l)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env, cmd.Stdin, cmd.Stderr = ghEnv(), strings.NewReader(res.Body), io.Discard
	out, err := cmd.Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return "", fmt.Errorf("gh issue create exited with status %d", exit.ExitCode())
		}
		return "", errors.New("gh issue create didn't run")
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if u := strings.TrimSpace(lines[len(lines)-1]); issueURL.MatchString(u) {
		return u, nil
	}
	return "", errors.New("gh issue create printed no issue URL")
}

// feedbackLink is FBK-6's link: the form, the title and its fields, percent-encoded, at most maxLink characters.
// A longer one leaves the main field out, and the main field goes to a new file only the person can read.
func feedbackLink(k feedbackKind, res feedbackResult, f feedbackFields) (string, string, error) {
	enc := func(s string) string { return strings.ReplaceAll(url.QueryEscape(s), "+", "%20") }
	link := func(main bool) string {
		q := []string{"template=" + enc(k.form), "title=" + enc(res.Title)}
		if main {
			q = append(q, k.field+"="+enc(f.main))
		}
		q = append(q, "version="+enc(f.version), "platform="+enc(f.platform))
		return feedbackIssue + "/new?" + strings.Join(q, "&")
	}
	if l := link(true); len(l) <= maxLink {
		return l, "", nil
	}
	file, err := os.CreateTemp("", "sandprobe-feedback-*.md")
	if err != nil {
		return "", "", fail("usage", "the body is too long for a link, and it couldn't be written to a file", "shorten the body", exitUsage)
	}
	_, werr := file.WriteString(f.main)
	if cerr := file.Close(); werr != nil || cerr != nil {
		os.Remove(file.Name())
		return "", "", fail("usage", "the body is too long for a link, and it couldn't be written to a file", "shorten the body", exitUsage)
	}
	return link(false), file.Name(), nil
}
