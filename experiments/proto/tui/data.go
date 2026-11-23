package main

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
	"time"
)

type Cat int

const (
	SEC Cat = iota
	EGR
	PER
	AMP
)

var catName = []string{"SEC", "EGR", "PER", "AMP"}
var catLong = []string{"Secrets", "Ways out", "Persistence", "Amplifiers"}

type Result int

const (
	Pass Result = iota + 1
	Find
	Unknown
)

// Check is one demo result. A finding with no Sev is part of a chain and reported through it.
type Check struct {
	ID, Title string
	Cat       Cat
	Result    Result
	Sev       string // CRIT, HIGH, MED
	Ticker    string // one-line result for the live ticker
	Breach    string // what escapes through the wall on the map
	Gets      string // what a hijacked agent gets
	Evidence  string
	How       string // how we checked, with its twin
	Fix       string
}

var checks = []Check{
	{ID: "SEC-1", Title: "Secret-shaped names in the agent's environment", Cat: SEC, Result: Find, Ticker: "1 name found, value unread", Breach: "ANTHROPIC_API_KEY",
		Gets: "An API key it can use, or send anywhere it can reach.", Evidence: "ANTHROPIC_API_KEY is set in the agent's environment. Recorded: the name and its length (108). The value was never read.",
		How: "Listed the probe's own environment names. Twin: SANDPROBE_TWIN, set by the probe, shows up through the same read.", Fix: "Inject the key at a proxy outside the box so it never enters the agent's environment."},
	{ID: "SEC-2", Title: "Other processes' environments", Cat: SEC, Result: Pass, Ticker: "refused (EACCES), twin ok",
		Evidence: "open() on /proc/<pid>/environ of 3 root processes was refused with EACCES.", How: "Twin: the probe's own /proc/self/environ opens through the same call."},
	{ID: "SEC-3", Title: "Cloud and tool credential files", Cat: SEC, Result: Pass, Ticker: "absent, 14 paths checked",
		Evidence: "None of ~/.aws/credentials, ~/.config/gcloud, ~/.kube/config, ~/.docker/config.json, ~/.netrc, ~/.git-credentials, ~/.ssh/id_* and 7 more exist.", How: "stat() on each path. A missing file needs no twin: its absence is the observation."},
	{ID: "SEC-4", Title: "Cloud metadata credentials", Cat: SEC, Result: Pass, Ticker: "no metadata service, twin ok",
		Evidence: "169.254.169.254, 169.254.170.2 and 169.254.170.23 refused the connection.", How: "One request to each address, asking only for role names, never credentials. Twin: the probe's own loopback listener answers the same client."},
	{ID: "SEC-5", Title: "Kubernetes service account token", Cat: SEC, Result: Pass, Ticker: "absent",
		Evidence: "/var/run/secrets/kubernetes.io/serviceaccount does not exist and KUBERNETES_SERVICE_HOST is unset.", How: "stat() and the environment."},
	{ID: "SEC-6", Title: "Other processes' memory", Cat: SEC, Result: Pass, Ticker: "refused (EACCES), twin ok",
		Evidence: "open() on /proc/<pid>/mem of root processes was refused. ptrace_scope is 1.", How: "Open only, no bytes read. Twin: the mem file of a child the probe starts opens through the same call."},

	{ID: "EGR-1", Title: "HTTPS straight out", Cat: EGR, Result: Find, Ticker: "OPEN, pinned key matched", Breach: ":443 OPEN",
		Gets: "A way to send anything in the box to the internet.", Evidence: "TLS to probe.sandprobe.dev:443 completed directly. The server's key matched the pinned key and it echoed this run's nonce.",
		How: "Direct connect with no proxy. The pinned key rules out an intercepting proxy faking success.", Fix: "Default-deny egress and allow only the hosts the agent needs."},
	{ID: "EGR-2", Title: "SSH straight out", Cat: EGR, Result: Pass, Ticker: "reset by network, twin ok",
		Evidence: "TCP to probe.sandprobe.dev:22 was reset before the handshake.", How: "Twin: the probe's loopback listener accepted the same client on the same port."},
	{ID: "EGR-3", Title: "Data out through DNS", Cat: EGR, Result: Pass, Ticker: "no upstream lookup seen",
		Evidence: "A unique name under probe.sandprobe.dev was looked up. Our name server saw no query within 5 s.", How: "Twin: a name the box's own resolver serves resolved through the same call."},
	{ID: "EGR-4", Title: "Through the configured proxy", Cat: EGR, Result: Pass, Ticker: "no proxy configured",
		Evidence: "HTTP_PROXY, HTTPS_PROXY and ALL_PROXY are unset, and no agent tool config names a proxy.", How: "Read the environment and the agent's tool configs."},
	{ID: "EGR-5", Title: "TLS interception", Cat: EGR, Result: Pass, Ticker: "none, pinned key matched",
		Evidence: "Every TLS session to probe.sandprobe.dev presented the pinned key.", How: "A mismatch would mean a proxy in the path and would make the egress checks unknown, never passed."},

	{ID: "PER-1", Title: "Home directory survives a reset", Cat: PER, Result: Find, Sev: "MED", Ticker: "marker survived the reset", Breach: "~/.bashrc",
		Gets: "Code it adds to ~/.bashrc runs in the next agent session, after the reset.", Evidence: "The marker /home/agent/.sandprobe-7f3a, holding only the run id, was still there after the checkpoint restore. It has been removed.",
		How: "Planted a marker, reset through the provider, looked again. Twin: a file written after the reset is found by the same lookup, and boot_id changed, so the reset happened.", Fix: "Restore home from a clean image on every reset, or keep it read-only to the agent."},
	{ID: "PER-2", Title: "/etc/profile.d", Cat: PER, Result: Pass, Ticker: "not writable, twin ok",
		Evidence: "Creating a file in /etc/profile.d was refused with EACCES.", How: "Twin: the same create in the probe's own scratch directory works."},
	{ID: "PER-3", Title: "Cron and systemd units", Cat: PER, Result: Pass, Ticker: "not writable, twin ok",
		Evidence: "crontab is refused, and /etc/systemd/system and ~/.config/systemd are not writable.", How: "Twin: the same create in the probe's scratch directory works."},
	{ID: "PER-4", Title: "Directories early in PATH", Cat: PER, Result: Pass, Ticker: "not writable, twin ok",
		Evidence: "None of the 6 PATH directories ahead of /usr/bin is writable by the agent.", How: "Create and remove a probe-named file in each. Twin: the scratch directory."},
	{ID: "PER-5", Title: "/tmp and /var/tmp", Cat: PER, Result: Pass, Ticker: "marker gone after reset",
		Evidence: "Markers in /tmp and /var/tmp were gone after the reset.", How: "Twin: a file written after the reset is found by the same lookup."},

	{ID: "AMP-1", Title: "Root through sudo", Cat: AMP, Result: Find, Sev: "CRIT", Ticker: "sudo: root, no password", Breach: "sudo → root",
		Gets: "Root on the box: every file, every socket, every other process.", Evidence: "sudo -n true exited 0 as agent (uid 1001).",
		How: "Twin: sudo -n -l lists NOPASSWD: ALL for agent, so sudo answered and the result is not a misread.", Fix: "Remove agent from sudoers and set NoNewPrivs on the agent's process."},
	{ID: "AMP-2", Title: "Effective capabilities", Cat: AMP, Result: Pass, Ticker: "CapEff 0",
		Evidence: "CapEff is 0000000000000000 for the agent's process.", How: "Read /proc/self/status through the agent's own exec path."},
	{ID: "AMP-3", Title: "Setuid programs", Cat: AMP, Result: Pass, Ticker: "standard set only",
		Evidence: "Only sudo, su, passwd and mount carry the setuid bit.", How: "Listed setuid files under /usr and /bin. sudo is covered by AMP-1."},
	{ID: "AMP-4", Title: "The sprite's control socket", Cat: AMP, Result: Find, Sev: "CRIT", Ticker: "world-writable, connect ok", Breach: "api.sock",
		Gets: "Control of the box from inside it: restore checkpoints and add boot services.", Evidence: "/.sprite/api.sock is srwxrwxrwx root:root. connect() succeeded; nothing was sent.",
		How: "connect() only. Twin: a socket the probe makes accepts the same call.", Fix: "Mask the socket in the agent's mount namespace by binding /dev/null over it."},
	{ID: "AMP-5", Title: "Container runtime sockets", Cat: AMP, Result: Pass, Ticker: "absent",
		Evidence: "No docker, containerd or podman socket exists.", How: "stat() on the known paths and every socket listed in /proc/net/unix."},
	{ID: "AMP-6", Title: "Local control APIs", Cat: AMP, Result: Find, Sev: "MED", Ticker: ":8080 answers, no auth", Breach: ":8080 open",
		Gets: "A root-owned local API it can call without credentials.", Evidence: "127.0.0.1:8080, owned by uid 0, accepted the agent's connection.",
		How: "Listeners read from /proc/net/tcp, no port scan. Twin: the probe's own listener accepts the same client.", Fix: "Serve it on a socket only its owner can open, or require a token."},
	{ID: "AMP-7", Title: "vsock to the host", Cat: AMP, Result: Unknown, Ticker: "no tool to test it",
		Evidence: "Testing AF_VSOCK needs python3 or socat, and neither is in the box.", How: "An unknown is never a pass. It makes the run incomplete and caps the grade at C.",
		Fix: "Add python3 to the image, or let the probe use its static helper."},
	{ID: "AMP-8", Title: "Kernel settings", Cat: AMP, Result: Pass, Ticker: "read-only, twin ok",
		Evidence: "/proc/sys is mounted read-only to the agent.", How: "Asked for write access without writing. Twin: write access to the scratch directory is granted through the same call."},
}

var chain = Check{ID: "CHN-1", Title: "A secret can leave the box", Cat: SEC, Result: Find, Sev: "HIGH",
	Gets:     "ANTHROPIC_API_KEY can be sent to any host on the internet.",
	Evidence: "SEC-1 found ANTHROPIC_API_KEY in the agent's environment. EGR-1 reached probe.sandprobe.dev:443 directly.",
	How:      "A readable secret plus a proven way out is one finding, ranked above either part.",
	Fix:      "Inject the key at a proxy outside the box, and default-deny egress."}

const lead = "A hijacked agent in this box can become root, drive the sprite's control socket, and send ANTHROPIC_API_KEY to any host on the internet."

type provider struct {
	Name, Short, Desc, Box, Reset string
	Access, Steps, Existing       []string
}

var providers = []provider{
	{Name: "Sprites (Fly)", Short: "sprites", Desc: "a fresh sprite, default settings", Box: "sandprobe-7f3a", Reset: "restore the sprite from a checkpoint",
		Access: []string{"sprite CLI found, logged in (demo)", "this account can create sprites"},
		Steps:  []string{"create sprite sandprobe-7f3a with default settings", "run a read-only probe in it as the agent user, through sprite exec", "restore the sprite from a checkpoint, then look for what survived", "delete sandprobe-7f3a"}},
	{Name: "AWS Nitro Sandboxes (EKS)", Short: "aws-nitro", Desc: "an isolated pod on a Nitro node", Box: "sandprobe-7f3a", Reset: "delete the pod and start it again",
		Access: []string{"aws CLI found, profile default (demo)", "kubectl reaches the sandprobe cluster (demo)"},
		Steps:  []string{"start pod sandprobe-7f3a with runtimeClassName isolated-sandbox", "run a read-only probe in it as the pod's user, through kubectl exec", "restart the pod, then look for what survived", "delete pod sandprobe-7f3a"}},
	{Name: "Modal Sandboxes", Short: "modal", Desc: "modal.Sandbox, no network flags", Box: "sandprobe-7f3a", Reset: "start a fresh sandbox from the same image",
		Access: []string{"modal CLI found, logged in (demo)", "this workspace can create sandboxes"},
		Steps:  []string{"create sandbox sandprobe-7f3a with default settings", "run a read-only probe inside it, through sandbox exec", "start a fresh sandbox from the image, then look for what survived", "terminate both sandboxes"}},
	{Name: "Baseten Sandbox", Short: "baseten", Desc: "a fresh sandbox, default settings", Box: "sandprobe-7f3a", Reset: "start a fresh sandbox from the base image",
		Access: []string{"Baseten API key found (demo)", "this account can create sandboxes"},
		Steps:  []string{"create sandbox sandprobe-7f3a with default settings", "run a read-only probe in it, through the sandbox's exec API", "start a fresh sandbox from the base image, then look for what survived", "delete both sandboxes"}},
	{Name: "exe.dev", Short: "exe.dev", Desc: "a fresh exe.dev VM", Box: "sandprobe-7f3a", Reset: "reboot the VM",
		Access: []string{"ssh key for exe.dev found (demo)", "this account can create VMs"},
		Steps:  []string{"create VM sandprobe-7f3a from the default image", "run a read-only probe inside it as the default user, over ssh", "reboot the VM, then look for anything that survived", "delete VM sandprobe-7f3a"}},
	{Name: "Somewhere else", Short: "self", Desc: "you run the probe, we read the results", Box: "your box", Reset: "your platform's own reset",
		Access: []string{"sandprobe ready"},
		Steps:  []string{"run the probe inside your box, as the agent:", "  curl -fsSL https://get.sandprobe.dev | sh > results.json", "then: sandprobe report results.json", "demo: we load sample results now"}},
}

func init() {
	for i := range providers {
		if providers[i].Existing == nil && providers[i].Short != "self" {
			s := providers[i].Steps
			providers[i].Existing = []string{"attach to a " + strings.Fields(s[0])[1] + " you pick; nothing is created", s[1], "skip the reset: it would disrupt your box", "detach; nothing is changed or deleted"}
		} else if providers[i].Existing == nil {
			providers[i].Existing = providers[i].Steps
		}
	}
}

func counts() (crit, high, med, pass, unk int) {
	for _, c := range append([]Check{chain}, checks...) {
		switch {
		case c.Result == Pass:
			pass++
		case c.Result == Unknown:
			unk++
		case c.Sev == "CRIT":
			crit++
		case c.Sev == "HIGH":
			high++
		case c.Sev == "MED":
			med++
		}
	}
	return
}

func gradeLetter() string {
	cr, hi, md, _, un := counts()
	switch {
	case cr > 0:
		return "F"
	case hi > 0:
		return "D"
	case md > 0 || un > 0:
		return "C"
	}
	return "A"
}

func sevRank(s string) int { return strings.Index("CRIT HIGH MED  LOW", s) }

func resultName(r Result) string {
	return map[Result]string{Pass: "pass", Find: "finding", Unknown: "unknown"}[r]
}

func idxOf(id string) int {
	for i, c := range checks {
		if c.ID == id {
			return i
		}
	}
	return -1
}

// findings lists what the report leads with: chains and standalone findings, worst first.
func findings() []Check {
	var f []Check
	for _, c := range append([]Check{chain}, checks...) {
		if c.Result == Find && c.Sev != "" {
			f = append(f, c)
		}
	}
	sort.SliceStable(f, func(i, j int) bool { return sevRank(f[i].Sev) < sevRank(f[j].Sev) })
	return f
}

func nowPT() string {
	loc, err := time.LoadLocation("America/Los_Angeles")
	if err != nil {
		return time.Now().Format("2 Jan 2006, 3:04 PM")
	}
	return time.Now().In(loc).Format("2 Jan 2006, 3:04 PM") + " PT"
}

func checkJSON(c Check) map[string]any {
	return map[string]any{"id": c.ID, "title": c.Title, "category": catName[c.Cat], "result": resultName(c.Result),
		"severity": c.Sev, "evidence": c.Evidence, "how": c.How, "fix": c.Fix}
}

func reportJSON() map[string]any {
	cr, hi, md, ps, un := counts()
	fs, cs := []map[string]any{}, []map[string]any{}
	for _, c := range findings() {
		fs = append(fs, checkJSON(c))
	}
	for _, c := range checks {
		cs = append(cs, checkJSON(c))
	}
	return map[string]any{
		"schema": "sandprobe.report/v0", "demo": true, "note": "prototype: demo data, no box was probed",
		"provider": "sprites", "box": "sandprobe-7f3a", "summary": lead,
		"identity": map[string]any{"user": "agent", "uid": 1001, "launch": "sprite exec", "cap_eff": "0000000000000000", "no_new_privs": 0},
		"grade":    map[string]any{"letter": gradeLetter(), "complete": un == 0, "critical": cr, "high": hi, "medium": md, "passed": ps, "unknown": un},
		"findings": fs, "checks": cs,
	}
}

// agentOutput is the no-TUI path: JSON for agents and pipes, with exit codes that mean one thing each.
func agentOutput(format, minGrade string) int {
	enc := json.NewEncoder(os.Stdout)
	rep := reportJSON()
	switch format {
	case "json":
		enc.SetIndent("", "  ")
		enc.Encode(rep)
	case "ndjson":
		for _, c := range checks {
			enc.Encode(map[string]any{"event": "check", "id": c.ID, "result": resultName(c.Result)})
		}
		enc.Encode(map[string]any{"event": "report", "report": rep})
	default:
		json.NewEncoder(os.Stderr).Encode(map[string]any{"error": "unknown_format", "fix": "use -o json or -o ndjson"})
		return 2
	}
	if g := strings.ToUpper(minGrade); g != "" && strings.Index("ABCDF", gradeLetter()) > strings.Index("ABCDF", g) {
		return 6
	}
	return 0
}
