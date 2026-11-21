//go:build poc

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"sandprobe/internal/host"
	"sandprobe/internal/report"
)

// bucketRule is one row of POC-7's reviewed table. A finding gets the first rule whose checks and setups match it;
// a finding no rule matches stops the summary.
type bucketRule struct {
	Checks  []string // check IDs; "EGR-5" matches every EGR-5 port, "EGR-5.53u" only UDP 53
	Setups  []string // nil: every setup
	Bucket  string
	Saw     string // what we saw, one line
	Control string
	Words   string // Modal's own words, when Modal documents it
	Link    string
	Still   bool           // a careful customer would still hit it (POC-8's "gaps that apply")
	Procs   bool           // holds only when every PID the finding opened is PID1 or one of the setup's own commands
	PID1    string         // the name PID 1 must have for this row
	Targets *regexp.Regexp // when set, every path the check's evidence names must match it, or the row doesn't hold
}

// vmOwn is the guest's own surfaces the live block-vm run showed: three kernel settings and its
// virtual disks. Anything else stays unplaced until a reviewed change names it.
var vmOwn = regexp.MustCompile(`^(/proc/sys/kernel/core_pattern|/proc/sys/kernel/sysrq|/proc/sys/net/ipv4/ip_forward|/dev/vda[0-9]*|/dev/loop[0-9]+|/dev/ram[0-9]+|/dev/zram[0-9]+|/dev/nullb[0-9]+)$`)

var evidencePath = regexp.MustCompile(`/(proc|dev)/[^ ,()]+`)

// targetsFit says every path a check's evidence names matches the row's targets.
func targetsFit(d report.Doc, id string, re *regexp.Regexp) error {
	var ev string
	for _, c := range d.Checks {
		if c.ID == id {
			ev = c.Evidence
		}
	}
	paths := evidencePath.FindAllString(ev, -1)
	if len(paths) == 0 {
		return errors.New("its evidence names no path")
	}
	for _, p := range paths {
		if !re.MatchString(p) {
			return fmt.Errorf("%s isn't one of the guest's own surfaces the row names", p)
		}
	}
	return nil
}

// ownProcs are the process names POC-7 counts as the sandbox's own: Modal's init and the setups' commands.
var ownProcs = []string{"dumb-init", "sleep", "sh", "python3"}

var procPID = regexp.MustCompile(`/proc/([0-9]+)/`)

// ownProcesses binds every PID a SEC-2 or SEC-5 finding opened to a name the raw record holds for that PID: PID 1 is
// Modal's init, every other one of the setup's own names. A PID with no recorded name, such as one that exited before
// the names were listed, can't be placed.
func ownProcesses(d report.Doc, id string, rec *rawRecord, pid1 string) error {
	if rec == nil || len(rec.Processes) == 0 {
		return errors.New("the raw record names no processes")
	}
	var ev string
	for _, c := range d.Checks {
		if c.ID == id {
			ev = c.Evidence
		}
	}
	pids := procPID.FindAllStringSubmatch(ev, -1)
	if len(pids) == 0 {
		return errors.New("its evidence names no process")
	}
	for _, m := range pids {
		name, ok := rec.Processes[m[1]]
		switch {
		case !ok:
			return fmt.Errorf("process %s has no recorded name", m[1])
		case m[1] == "1" && name != pid1:
			return fmt.Errorf("PID 1 is %s, not %s", name, pid1)
		case m[1] == "1":
		case !slices.Contains(ownProcs, name):
			return fmt.Errorf("process %s (%s) isn't the sandbox's own", m[1], name)
		}
	}
	return nil
}

const (
	docNet     = "https://modal.com/docs/guide/sandbox-networking"
	docSidecar = "https://modal.com/docs/guide/sandbox-sidecars"
)

var (
	allowlists = []string{"domain-empty", "domain-one", "sidecar"}
	gvisor     = []string{"default", "domain-empty", "domain-one", "block", "sidecar"} // every setup but block-vm
)

var bucketTable = []bucketRule{
	// The VM runtime: the guest's kernel and disks are its own. SEC-2 and SEC-5 inside the VM have no row: a finding
	// there stops the summary until a reviewed change adds one (POC-7).
	{Checks: []string{"AMP-8"}, Setups: []string{"block-vm"}, Bucket: "by design", Targets: vmOwn,
		Saw:     "inside the VM, root can read the guest's own disks and write its kernel settings, as a VM with its own kernel allows",
		Control: "nothing needed: it's the sandbox's own kernel", Words: "the Sandbox runs in its own virtual machine with its own Linux kernel.", Link: docNet},
	{Checks: []string{"EGR-1", "EGR-2", "EGR-5"}, Setups: []string{"default"}, Bucket: "A",
		Saw: "the sandbox reached our test server over DNS, HTTPS and other ports", Control: "block_network, or the domain and CIDR allowlists for all but DNS",
		Words: "By default, Sandboxes can make outbound connections to any public IP address.", Link: docNet},
	{Checks: []string{"EGR-1", "EGR-5.53u"}, Setups: allowlists, Bucket: "C",
		Saw: "a name looked up inside the sandbox reached our name server despite the allowlist", Control: "only block_network",
		Words: "DNS traffic is allowed without restriction except when all outbound traffic is blocked.", Link: docNet},
	{Checks: []string{"EGR-2"}, Setups: []string{"sidecar"}, Bucket: "A",
		Saw: "HTTPS from the main container reached our test server through the sidecar, which logged it", Control: "the sidecar's own allowlists",
		Words: "Each Sidecar has its own outbound network policy, independent of the main container's and open by default.", Link: docSidecar},
	{Checks: []string{"AMP-2"}, Bucket: "B", Saw: "the agent ran as root, with root's capabilities", Control: "a non-root USER in the image"},
	{Checks: []string{"AMP-3"}, Bucket: "B", Saw: "no_new_privs was off and setuid-root files were present", Control: "an image with no setuid-root files"},
	{Checks: []string{"PER-1", "PER-2", "PER-3", "PER-4"}, Bucket: "B", Saw: "the agent could replace startup, PATH, schedule or access files",
		Control: "a non-root user that owns neither its home nor the PATH, schedule and startup directories"},
	{Checks: []string{"SEC-2", "SEC-5"}, Setups: gvisor, Bucket: "B", Saw: "the agent could open other processes' environment or memory: the sandbox's init and its own command",
		Control: "the agent under a UID of its own, apart from every other process", Procs: true, PID1: "dumb-init"},
	{Checks: []string{"SEC-3"}, Bucket: "B", Saw: "root could read the image's own /etc/shadow", Control: "a non-root USER in the image"},
	{Checks: []string{"SEC-1"}, Bucket: "B", Saw: "secret-shaped variable names the image itself declares", Control: "the customer's own image and environment"},
	{Checks: []string{"AMP-8"}, Setups: gvisor, Bucket: "D", Saw: "root could change a setting of gVisor's own kernel (ip_forward)",
		Control: "Modal's to say: what that setting reaches"},
	{Checks: []string{"AMP-4"}, Bucket: "D", Saw: "a control socket of Modal's was visible in the sandbox; it was never connected to",
		Control: "Modal's to say: who may use it"},
}

func (b bucketRule) matches(id, setup string) bool {
	if b.Setups != nil && !slices.Contains(b.Setups, setup) {
		return false
	}
	for _, c := range b.Checks {
		if id == c || strings.HasPrefix(id, c+".") {
			return true
		}
	}
	return false
}

// bucketOf is POC-7's table, never a judgment.
func bucketOf(id, setup string) (int, error) {
	for i, b := range bucketTable {
		if b.matches(id, setup) {
			return i, nil
		}
	}
	return -1, fmt.Errorf("finding %s in %s isn't in POC-7's table: the summary waits for a reviewed change", id, setup)
}

type setupRow struct {
	Setup, Runtime  string
	A, B, C, D      int
	Complete, Valid bool
	Unknown         int    // checks the run couldn't decide: shown beside the row, never hidden as nothing found
	Design          int    // findings that are the setup's design, not a gap (POC-7)
	Out             string // what reached our test server, from the canary's receipts
}

type bucketLine struct {
	Bucket, Saw, Control, Words, Link string
	Setups                            []string
	Checks                            []string
	Still                             bool
}

type summaryView struct {
	Nonce, When, Spend string
	Rows               []setupRow
	Lines              []bucketLine
	Gaps               []bucketLine
	Sidecar            [][3]string
	Twin               string
	NotTested          []string
}

var setupOrder = map[string]int{"default": 0, "domain-empty": 1, "domain-one": 2, "block": 3, "block-vm": 4, "sidecar": 5}

func pocSummary(o opts, r runFlags) (int, error) {
	docs := map[string]report.Doc{}
	recs := map[string]*rawRecord{}
	for setup := range setupOrder {
		found, _ := filepath.Glob(filepath.Join(r.outDir, "reports", setup, "sandprobe-modal-*.json"))
		if len(found) == 0 {
			continue
		}
		if len(found) > 1 {
			return 0, fail("usage", setup+" has more than one rendered report", "keep one", exitUsage)
		}
		b, err := os.ReadFile(found[0])
		if err != nil {
			return 0, err
		}
		var d report.Doc
		if err := json.Unmarshal(b, &d); err != nil {
			return 0, err
		}
		rec, err := readRecord(r.outDir, setup) // every report needs its own sound raw record
		if err != nil {
			return 0, err
		}
		if err := recordSound(rec, setup); err != nil {
			return 0, fail("usage", err.Error(), "render only setups that passed every gate", exitPartial)
		}
		if d.Run.ID != rec.Manifest.RunID || d.Run.Nonce != rec.Manifest.Nonce || d.Run.Box.ProviderID != rec.SandboxID {
			return 0, fail("usage", setup+"'s report isn't from the run its raw record holds", "sandprobe poc modal render -variant "+setup, exitPartial)
		}
		docs[setup], recs[setup] = d, rec
	}
	if len(docs) == 0 {
		return 0, fail("usage", "no rendered setups", "sandprobe poc modal render -variant default -out "+r.outDir, exitUsage)
	}
	v, err := buildSummary(docs, recs)
	if err != nil {
		return 0, fail("usage", err.Error(), "a reviewed change to POC-7's table", exitPartial)
	}
	page, err := summaryHTML(v)
	if err != nil {
		return 0, err
	}
	if err := os.WriteFile(filepath.Join(r.outDir, "summary.html"), page, 0o600); err != nil {
		return 0, err
	}
	if err := os.WriteFile(filepath.Join(r.outDir, "summary.md"), summaryMD(v), 0o600); err != nil {
		return 0, err
	}
	fmt.Fprintln(o.stdout, filepath.Join(r.outDir, "summary.html"))
	return 0, nil
}

func buildSummary(docs map[string]report.Doc, recs map[string]*rawRecord) (summaryView, error) {
	v := summaryView{Nonce: randNonce(), When: time.Now().Format("2 Jan 2006")}
	setups := make([]string, 0, len(docs))
	for s := range docs {
		setups = append(setups, s)
	}
	sort.Slice(setups, func(i, j int) bool { return setupOrder[setups[i]] < setupOrder[setups[j]] })
	lines := map[int]*bucketLine{}
	var secs float64
	unconfirmed := 0
	for _, s := range setups {
		d := docs[s]
		if !d.Grade.Valid {
			return v, fmt.Errorf("%s's report isn't valid (%s): it can't be summarised", s, d.Grade.Invalid)
		}
		row := setupRow{Setup: s, Complete: d.Grade.Complete, Valid: d.Grade.Valid, Runtime: "left to Modal", Unknown: len(d.Grade.Unknown)}
		counted := map[int]bool{}
		if rec := recs[s]; rec != nil {
			row.Out = gotOut(rec)
		}
		if s == "block-vm" {
			row.Runtime = "vm"
		}
		if rec := recs[s]; rec != nil {
			if rec.Kernel != "" {
				row.Runtime += ", kernel " + rec.Kernel
			}
			secs += sandboxSeconds(rec)
			if !rec.Cleaned {
				unconfirmed++
			}
		}
		for _, f := range d.Findings {
			if strings.HasPrefix(f.ID, "CHN-") {
				for _, c := range f.Checks { // a chain is reported through the checks it joins
					if _, err := bucketOf(c, s); err != nil {
						return v, err
					}
				}
				continue
			}
			i, err := bucketOf(f.ID, s)
			if err != nil {
				return v, err
			}
			b := bucketTable[i]
			if b.Procs {
				if err := ownProcesses(d, f.ID, recs[s], b.PID1); err != nil {
					return v, fmt.Errorf("%s in %s: %v: the summary waits for a reviewed change", f.ID, s, err)
				}
			}
			if b.Targets != nil {
				if err := targetsFit(d, f.ID, b.Targets); err != nil {
					return v, fmt.Errorf("%s in %s: %v: the summary waits for a reviewed change", f.ID, s, err)
				}
			}
			if !counted[i] { // one line of the table counts once per setup, however many checks it holds
				counted[i] = true
				switch b.Bucket {
				case "A":
					row.A++
				case "B":
					row.B++
				case "C":
					row.C++
				case "D":
					row.D++
				case "by design":
					row.Design++
				}
			}
			l := lines[i]
			if l == nil {
				l = &bucketLine{Bucket: b.Bucket, Saw: b.Saw, Control: b.Control, Words: b.Words, Link: b.Link, Still: b.Still}
				lines[i] = l
			}
			if !slices.Contains(l.Setups, s) {
				l.Setups = append(l.Setups, s)
			}
			if !slices.Contains(l.Checks, f.ID) {
				l.Checks = append(l.Checks, f.ID)
			}
		}
		v.Rows = append(v.Rows, row)
	}
	idx := make([]int, 0, len(lines))
	for i := range lines {
		idx = append(idx, i)
	}
	sort.Slice(idx, func(a, b int) bool {
		if lines[idx[a]].Bucket != lines[idx[b]].Bucket {
			return lines[idx[a]].Bucket < lines[idx[b]].Bucket
		}
		return idx[a] < idx[b]
	})
	for _, i := range idx {
		v.Lines = append(v.Lines, *lines[i])
		if lines[i].Bucket == "C" || (lines[i].Bucket == "B" && lines[i].Still) {
			v.Gaps = append(v.Gaps, *lines[i])
		}
	}
	if rec := recs["sidecar"]; rec != nil {
		v.Sidecar = sidecarRows(rec)
	}
	if rec := recs["domain-one"]; rec != nil && rec.Twin != nil {
		switch {
		case !rec.Twin.Read:
			v.Twin = "The allowlist's twin couldn't be read, so the allowlist wasn't shown to admit anything."
		case len(rec.Twin.Receipts) > 0 && !egr2Reached(rec):
			v.Twin = "Under the one-name allowlist, that name reached our test server, and the probe's own name, sent the same way to the same address and port, didn't: the allowlist matched on the name."
		default:
			v.Twin = "Under the one-name allowlist, the allowed name didn't reach our test server either, so the allowlist wasn't shown to admit anything."
		}
	}
	v.NotTested = notTested(docs)
	v.Spend = spend(secs, unconfirmed)
	return v, nil
}

func sidecarRows(rec *rawRecord) [][3]string {
	var rows [][3]string
	if rec.Relay != nil {
		got := "the log was incomplete, so which route carried it is unknown"
		if rec.Relay.Complete {
			got = fmt.Sprintf("%d connection(s) relayed and logged by name; %d refused", len(rec.Relay.Relayed), rec.Relay.Refused)
		}
		rows = append(rows, [3]string{"the main container's HTTPS", "saw it, by name only (TLS stays encrypted)", got})
	}
	dns := "not seen"
	for _, r := range rec.Evidence.Receipts {
		if r.Port == 53 && (r.Proto == "dns" || r.Proto == "udp") {
			dns = "not seen, yet a lookup reached our name server: DNS bypasses the sidecar"
		}
	}
	rows = append(rows, [3]string{"the main container's DNS", "can't see it", dns})
	names := map[string]string{"procs": "the main container's processes", "files": "the main container's files",
		"volume": "a shared Volume", "net": "a port the main container opened"}
	for _, l := range rec.Look {
		row, _ := l["row"].(string)
		from, _ := l["from"].(string)
		what := names[row]
		if from == "main" {
			what = "the sidecar's processes, from the main container"
		}
		if r, _ := l["after_reload"].(bool); r {
			what += ", after a volume reload"
		}
		expect := map[string]string{"procs": "not seen", "files": "not seen", "volume": "seen", "net": "seen"}[row]
		if r, _ := l["after_reload"].(bool); r && row == "volume" {
			expect = "seen"
		}
		res := "not seen"
		switch {
		case l["error"] != nil:
			res = fmt.Sprint("couldn't check: ", l["error"])
		case l["unknown"] != nil:
			res = fmt.Sprint("couldn't check: ", l["unknown"])
		case l["seen"] == true:
			res = "seen"
		}
		rows = append(rows, [3]string{what, expect, res})
	}
	return rows
}

func notTested(docs map[string]report.Doc) []string {
	out := []string{
		"Cloud metadata, vsock to the host, a Kubernetes API, and a proxy the sandbox names (SEC-4, AMP-6, AMP-7, EGR-3): each would send a request to an endpoint Modal owns.",
		"Persistence across a reset: a terminate and recreate would test only a Volume, and the probe's sandbox mounted none.",
		"Domain fronting through a shared CDN: it needs a third party's server. The one-name allowlist shows only how the allowlist matches.",
		"Inbound connections through unencrypted tunnels: that would open ports to the internet.",
		"GPU sandboxes, the Datadog integration and the outbound secret policy.",
		"Anything that tries to leave the sandbox or reach other tenants, and any load.",
	}
	if _, ok := docs["block-vm"]; !ok {
		out = append(out, "The VM runtime: not run in this workspace.")
	}
	return out
}

func randNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "n"
	}
	return fmt.Sprintf("%x", b)
}

var summaryTmpl = template.Must(template.New("s").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Modal sandboxes, from inside</title>
<style>
:root{--bg:#fbfaf7;--fg:#1d1d1b;--mute:#6b6a64;--line:#e4e1d8;--a:#2f6f4f;--b:#8a6d1f;--c:#a3402b;--d:#4b5a8a}
@media (prefers-color-scheme:dark){:root{--bg:#161614;--fg:#ecebe6;--mute:#a19f97;--line:#33322e;--a:#7fc29b;--b:#e0c069;--c:#f08a72;--d:#9fb0e6}}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:860px;margin:0 auto;padding:32px 16px 64px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:17px;margin:32px 0 8px}
.sub{color:var(--mute);margin:0 0 20px}
table{border-collapse:collapse;width:100%;font-size:14px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mute);font-weight:600}
.tag{display:inline-block;min-width:18px;text-align:center;font-weight:700;border-radius:4px;padding:0 5px;color:var(--bg)}
.A{background:var(--a)}.B{background:var(--b)}.C{background:var(--c)}.D{background:var(--d)}.design{background:var(--mute)}
ul{padding-left:20px}li{margin:4px 0}.mute{color:var(--mute)}q{font-style:italic}
.wrap{overflow-x:auto}
</style></head><body><main>
<h1>Modal Sandboxes, from inside</h1>
<p class="sub">A small probe ran as the agent inside sandboxes in our own workspace, {{.When}}. Every connection went only to our own test server. Time: {{.Spend}}.</p>
<p class="mute"><span class="tag A">A</span> documented, with a Modal control &nbsp; <span class="tag B">B</span> a default you can change &nbsp; <span class="tag C">C</span> no control today &nbsp; <span class="tag D">D</span> only Modal can tell &nbsp; <span class="tag design">by design</span> expected, not a gap</p>
<h2>1. The setups</h2>
<div class="wrap"><table><tr><th>Setup, and what reached our server</th><th>Runtime</th><th>A</th><th>B</th><th>C</th><th>D</th><th>By design</th><th>Undecided</th></tr>
{{range .Rows}}<tr><td>{{.Setup}}<br><span class="mute">{{.Out}}</span></td><td>{{.Runtime}}</td><td>{{.A}}</td><td>{{.B}}</td><td>{{.C}}</td><td>{{.D}}</td><td>{{.Design}}</td><td>{{if .Unknown}}{{.Unknown}} checks{{else}}none{{end}}</td></tr>{{end}}
</table></div>
<h2>2. What we saw, by bucket</h2>
<ul>{{range .Lines}}<li><span class="tag {{if eq .Bucket "by design"}}design{{else}}{{.Bucket}}{{end}}">{{.Bucket}}</span> {{.Saw}}. <span class="mute">In: {{range $i, $s := .Setups}}{{if $i}}, {{end}}{{$s}}{{end}}. Closed by: {{.Control}}.</span>{{if .Words}} Modal's docs: <q>{{.Words}}</q>{{if .Link}} (<a href="{{.Link}}">source</a>){{end}}{{end}}</li>{{end}}</ul>
{{if .Twin}}<p>{{.Twin}}</p>{{end}}
<h2>3. The gaps that apply</h2>
{{if .Gaps}}<ul>{{range .Gaps}}<li><span class="tag {{.Bucket}}">{{.Bucket}}</span> {{.Saw}}. <span class="mute">Closed by: {{.Control}}.</span></li>{{end}}</ul>{{else}}<p>None beyond what Modal documents and ships a control for.</p>{{end}}
<h2>4. What the sidecar saw, and what it couldn't</h2>
{{if .Sidecar}}<div class="wrap"><table><tr><th>From the sidecar</th><th>Expected</th><th>Measured</th></tr>
{{range .Sidecar}}<tr><td>{{index . 0}}</td><td>{{index . 1}}</td><td>{{index . 2}}</td></tr>{{end}}</table></div>{{else}}<p class="mute">The sidecar setup wasn't run.</p>{{end}}
<h2>5. Not tested, and why</h2>
<ul>{{range .NotTested}}<li>{{.}}</li>{{end}}</ul>
</main></body></html>
`))

func summaryHTML(v summaryView) ([]byte, error) {
	var b bytes.Buffer
	if err := summaryTmpl.Execute(&b, v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func summaryMD(v summaryView) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "# Modal Sandboxes, from inside\n\nA small probe ran as the agent inside sandboxes in our own workspace, %s. Every connection went only to our own test server. Time: %s.\n\n", md(v.When), md(v.Spend))
	b.WriteString("Buckets: A documented, with a Modal control; B a default you can change; C no control today; D only Modal can tell.\n\n## 1. The setups\n\n| Setup | What reached our server | Runtime | A | B | C | D | By design | Undecided |\n|-|-|-|-|-|-|-|-|-|\n")
	for _, r := range v.Rows {
		fmt.Fprintf(&b, "| %s | %s | %s | %d | %d | %d | %d | %d | %d |\n", md(r.Setup), md(r.Out), md(r.Runtime), r.A, r.B, r.C, r.D, r.Design, r.Unknown)
	}
	b.WriteString("\n## 2. What we saw, by bucket\n\n")
	for _, l := range v.Lines {
		fmt.Fprintf(&b, "- **%s** %s. In: %s. Closed by: %s.", l.Bucket, md(l.Saw), md(strings.Join(l.Setups, ", ")), md(l.Control))
		if l.Words != "" {
			fmt.Fprintf(&b, " Modal's docs: \"%s\" (%s)", md(l.Words), md(l.Link))
		}
		b.WriteString("\n")
	}
	if v.Twin != "" {
		b.WriteString("\n" + md(v.Twin) + "\n")
	}
	b.WriteString("\n## 3. The gaps that apply\n\n")
	if len(v.Gaps) == 0 {
		b.WriteString("None beyond what Modal documents and ships a control for.\n")
	}
	for _, l := range v.Gaps {
		fmt.Fprintf(&b, "- **%s** %s. Closed by: %s.\n", l.Bucket, md(l.Saw), md(l.Control))
	}
	b.WriteString("\n## 4. What the sidecar saw, and what it couldn't\n\n")
	if len(v.Sidecar) == 0 {
		b.WriteString("The sidecar setup wasn't run.\n")
	} else {
		b.WriteString("| From the sidecar | Expected | Measured |\n|-|-|-|\n")
		for _, r := range v.Sidecar {
			fmt.Fprintf(&b, "| %s | %s | %s |\n", md(r[0]), md(r[1]), md(r[2]))
		}
	}
	b.WriteString("\n## 5. Not tested, and why\n\n")
	for _, n := range v.NotTested {
		b.WriteString("- " + md(n) + "\n")
	}
	return []byte(b.String())
}

// md makes text safe in Markdown, table cells included: no row or column breaks, links, emphasis or HTML.
func md(s string) string {
	s = strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
	var b strings.Builder
	for _, r := range s {
		if strings.ContainsRune("\\`*_[]<>#|", r) {
			b.WriteRune('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// Modal's published non-preemptible sandbox rates (modal.com/pricing, read 10 Nov 2026), per second.
const (
	ratePerCoreSecond = 0.00003942
	ratePerGiBSecond  = 0.00000667
)

// sandboxSeconds is a sandbox's lifetime: from its create call to the end of its teardown (rec.Ended, taken after the
// last call returned). A sandbox not confirmed deleted may run to its server-side timeout, so that is its lifetime.
func sandboxSeconds(rec *rawRecord) float64 {
	start := rec.Started
	for _, c := range rec.Calls {
		if strings.HasPrefix(c.Call, "modal create sandbox") {
			start = c.At
			break
		}
	}
	if !rec.Cleaned {
		return (15 * time.Minute).Seconds() // the timeout every sandbox carries (POC-1)
	}
	return rec.Ended.Sub(start).Seconds()
}

// spend is POC-9's estimate: each sandbox's lifetime at Modal's default request and published rates. Bursting above
// the request bills more, so it's a floor, never a bound; the workspace's usage page has the real figure.
func spend(secs float64, unconfirmed int) string {
	perSec := host.ModalDefaultCPU*ratePerCoreSecond + float64(host.ModalDefaultMemoryMiB)/1024*ratePerGiBSecond
	// An estimate in no particular direction: the lifetime counts create and teardown time Modal may not bill, and
	// bursting above the request bills more.
	kind := "an estimate, not a bound either way"
	if unconfirmed > 0 {
		kind += fmt.Sprintf(", with %d sandbox(es) not confirmed deleted counted at their 15-minute timeout", unconfirmed)
	}
	return fmt.Sprintf("%d sandbox-minutes; estimated at Modal's default request and published rates, about $%.3f, %s (Modal's usage page has the real figure); image builds not included",
		int(secs/60)+1, secs*perSec, kind)
}

// egr2Reached says whether EGR-2's own nonce reached the canary in the main run.
func egr2Reached(rec *rawRecord) bool {
	n := rec.Manifest.CheckNonces["EGR-2"]
	for _, r := range rec.Evidence.Receipts {
		if r.Nonce == n {
			return true
		}
	}
	return false
}

// gotOut is what reached our test server in a setup, from the canary's receipts only: never a refusal claim.
func gotOut(rec *rawRecord) string {
	check := map[string]string{}
	for id, n := range rec.Manifest.CheckNonces {
		check[n] = id
	}
	var dns, https, udp bool
	var ports []int
	for _, r := range rec.Evidence.Receipts {
		switch id := check[r.Nonce]; {
		case id == "EGR-1":
			dns = true
		case id == "EGR-2":
			https = true
		case id == "EGR-5.53u":
			udp = true
		case strings.HasPrefix(id, "EGR-5.") && r.Proto == "tcp":
			ports = append(ports, r.Port) // the ports that actually reached it
		}
	}
	sort.Ints(ports)
	var out []string
	if dns {
		out = append(out, "DNS")
	}
	if https {
		if rec.Setup == "sidecar" {
			out = append(out, "HTTPS through the sidecar")
		} else {
			out = append(out, "HTTPS")
		}
	}
	if len(ports) > 0 {
		ps := make([]string, len(ports))
		for i, p := range ports {
			ps[i] = fmt.Sprint(p)
		}
		out = append(out, "TCP "+strings.Join(ps, ", "))
	}
	if udp {
		out = append(out, "UDP 53")
	}
	if rec.Twin != nil && len(rec.Twin.Receipts) > 0 {
		out = append(out, "the allowlist's one name")
	}
	if len(out) == 0 {
		return "nothing"
	}
	return strings.Join(out, ", ")
}
