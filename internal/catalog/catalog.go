// Package catalog is the one list of Sandprobe's checks (SPEC.md, "Checks"): each check's kind, its negative proof,
// its planned targets and discovery rules, and what each kind of finding means for severity and evidence class. The
// host plans from here and the grader judges from here; severity never comes from the box.
package catalog

// Kind is KND-1 or KND-2.
type Kind int

const (
	TwoSided Kind = iota // ends pass, finding, absent, scoped_out or unknown
	FindOnly             // ends finding, not_found or unknown; never a pass
)

// Class is KND-3: a proof shows the capability, an indicator shows exposure.
type Class string

const (
	Proof     Class = "proof"
	Indicator Class = "indicator"
)

type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

func (s Severity) String() string { return [...]string{"info", "low", "medium", "high", "critical"}[s] }

// Variant is one kind of finding a check can report.
type Variant struct {
	Severity Severity
	Class    Class
}

// NeedsCanary is HCN-5's set for a run without a canary: every check the canary decides, and EGR-4, which reads the
// TLS handshake EGR-2 makes to it.
func NeedsCanary(c *Check) bool { return c.Canary != nil || c.ID == "EGR-4" }

// Canary marks a network check the host decides from the canary's receipts and health (SBX-11), not from the box.
type Canary struct {
	Proto string // tcp, udp or dns
	Port  int
	Route string // direct, proxy or resolver
}

type Check struct {
	ID, Category, Title string
	Kind                Kind
	Mechanism           string   // the negative proof a pass, or an absence, must carry (TWN-1)
	AbsentOK            bool     // may end absent, every planned and discovered target verified absent (TWN-2)
	ScopeOut            string   // the discovery rule that must find nothing for the check to be scoped out (KND-1)
	Derived             bool     // graded by the host from the probe's identity, whatever the probe says (GRD-5)
	Gate                string   // when the host may skip it (GRD-3); empty: every run grades it
	Recheck             bool     // graded by the host from the marks, the reset and the recheck (TWN-3), never the main run
	Targets             []string // planned targets a proof must cover, every one
	Discover            []string // discovery rules a proof must report, with every target each one found
	Canary              *Canary
	Variants            map[string]Variant
}

// Refusals are the errors that count as a refusal for each refusal-based mechanism (TWN-1's table).
var Refusals = map[string][]string{
	"file_read":  {"EACCES", "EPERM"},
	"proc_open":  {"EACCES", "EPERM"},
	"write_perm": {"EACCES", "EROFS"},
	"read_perm":  {"EACCES", "EPERM"},
}

// Counted mechanisms read a whole table; a pass must say how many entries it read, and show its twin in it.
var Counted = map[string]bool{"env_names": true, "net_table": true}

func v(s Severity, c Class) Variant { return Variant{s, c} }

var receipt = map[string]Variant{"receipt": v(Medium, Proof)}

// Checks are in report order. EGR-5 is one check per port, and AMP-8 one per surface, because each is proven by its
// own mechanism and scoped to itself (TWN-1).
var Checks = []Check{
	{ID: "SEC-1", Category: "SEC", Title: "Secret-shaped names in the agent's environment", Kind: TwoSided, Mechanism: "env_names",
		Variants: map[string]Variant{"names": v(High, Indicator)}},
	{ID: "SEC-2", Category: "SEC", Title: "Other processes' environments", Kind: TwoSided, Mechanism: "proc_open", ScopeOut: "proc_pids",
		Discover: []string{"proc_pids"}, Variants: map[string]Variant{"readable": v(High, Proof)}},
	{ID: "SEC-3", Category: "SEC", Title: "Credential files", Kind: TwoSided, Mechanism: "file_read", AbsentOK: true,
		Targets: []string{"~/.aws/credentials", "~/.config/gcloud/application_default_credentials.json", "~/.config/gcloud/credentials.db",
			"~/.kube/config", "~/.docker/config.json", "~/.netrc", "~/.git-credentials", "~/.config/gh/hosts.yml", "~/.npmrc", "~/.pypirc",
			"/etc/shadow", "/var/run/secrets/kubernetes.io/serviceaccount/token"},
		Discover: []string{"ssh_keys", "run_secrets", "dotenv"},
		Variants: map[string]Variant{"nonempty": v(High, Proof), "k8s_token": v(High, Proof), "empty": v(Info, Indicator)}},
	{ID: "SEC-4", Category: "SEC", Title: "Cloud metadata credentials", Kind: FindOnly, Variants: map[string]Variant{"role_listed": v(High, Indicator)},
		Gate: "the provider's rules of engagement exclude its metadata addresses (PRV-5), or run exec's default for an unidentified provider (PRV-15)"},
	{ID: "SEC-5", Category: "SEC", Title: "Other processes' memory", Kind: TwoSided, Mechanism: "proc_open", ScopeOut: "proc_pids",
		Discover: []string{"proc_pids"}, Variants: map[string]Variant{"readable": v(High, Proof)}},

	{ID: "EGR-1", Category: "EGR", Title: "A looked-up name reaches our name server", Kind: FindOnly, Canary: &Canary{"dns", 53, "resolver"}, Variants: receipt},
	{ID: "EGR-2", Category: "EGR", Title: "A nonce sent by HTTPS straight out reaches our canary", Kind: TwoSided, Canary: &Canary{"tcp", 443, "direct"}, Variants: receipt},
	{ID: "EGR-3", Category: "EGR", Title: "HTTPS through the box's proxy", Kind: FindOnly, Canary: &Canary{"tcp", 443, "proxy"}, Variants: receipt,
		Gate: "the agent's environment names no proxy, or a local one nobody approved, or the provider's rules of engagement exclude it (PRV-5), or run exec's default for an unidentified provider (PRV-15)"},
	{ID: "EGR-4", Category: "EGR", Title: "TLS interception", Kind: FindOnly, Variants: map[string]Variant{"intercepted": v(Info, Indicator)}},
	{ID: "EGR-5.22", Category: "EGR", Title: "TCP 22 out", Kind: TwoSided, Canary: &Canary{"tcp", 22, "direct"}, Variants: receipt},
	{ID: "EGR-5.80", Category: "EGR", Title: "TCP 80 out", Kind: TwoSided, Canary: &Canary{"tcp", 80, "direct"}, Variants: receipt},
	{ID: "EGR-5.8080", Category: "EGR", Title: "TCP 8080 out", Kind: TwoSided, Canary: &Canary{"tcp", 8080, "direct"}, Variants: receipt},
	{ID: "EGR-5.53u", Category: "EGR", Title: "UDP 53 out", Kind: FindOnly, Canary: &Canary{"udp", 53, "direct"}, Variants: receipt},
	{ID: "EGR-6", Category: "EGR", Title: "Upload-capable hosts on an allowlist", Kind: FindOnly, Variants: map[string]Variant{"handshake": v(Medium, Indicator)},
		Gate: "contacting its public hosts wasn't approved"},

	{ID: "PER-1", Category: "PER", Title: "Startup files", Kind: TwoSided, Mechanism: "write_perm",
		Targets:  []string{"~/.bashrc", "~/.profile", "~/.bash_profile", "~/.zshrc", "/etc/profile.d", "/etc/bash.bashrc"},
		Variants: map[string]Variant{"writable": v(Low, Indicator)}},
	{ID: "PER-2", Category: "PER", Title: "PATH directories ahead of the system's", Kind: TwoSided, Mechanism: "write_perm",
		Targets: []string{"/usr/local/bin"}, Discover: []string{"path_dirs"}, Variants: map[string]Variant{"writable": v(Low, Indicator)}},
	{ID: "PER-3", Category: "PER", Title: "Boot and schedule", Kind: TwoSided, Mechanism: "write_perm",
		Targets:  []string{"/etc/systemd/system", "~/.config/systemd/user", "/etc/cron.d", "/var/spool/cron/crontabs", "/etc/rc.local", "/etc/init.d"},
		Variants: map[string]Variant{"writable": v(Low, Indicator)}},
	{ID: "PER-4", Category: "PER", Title: "Supply chain and access config", Kind: TwoSided, Mechanism: "write_perm",
		Targets:  []string{"~/.npmrc", "~/.config/pip/pip.conf", "~/.pip/pip.conf", "~/.gitconfig", "~/.git-templates/hooks", "~/.ssh/authorized_keys"},
		Variants: map[string]Variant{"writable": v(Low, Indicator)}},
	{ID: "PER-5", Category: "PER", Title: "Storage that survives the provider's reset", Kind: FindOnly,
		Variants: map[string]Variant{"survived": v(Medium, Proof), "survived_startup": v(High, Proof)},
		Gate:     "an existing box gets no markers, or the provider's reset leaves no storage to test", Recheck: true},

	{ID: "AMP-1", Category: "AMP", Title: "sudo without a password", Kind: FindOnly, Mechanism: "sudo_paths", AbsentOK: true,
		Targets: []string{"/usr/bin/sudo", "/bin/sudo", "/usr/local/bin/sudo"}, Discover: []string{"path_sudo"},
		Variants: map[string]Variant{"nopasswd_all": v(Critical, Proof), "nopasswd_named": v(High, Proof)}},
	{ID: "AMP-2", Category: "AMP", Title: "Root or capabilities", Kind: TwoSided, Mechanism: "self_status", Derived: true,
		Variants: map[string]Variant{"root": v(Critical, Proof), "dangerous_caps": v(Critical, Proof), "other_caps": v(High, Proof)}},
	{ID: "AMP-3", Category: "AMP", Title: "New privileges", Kind: TwoSided, Mechanism: "self_status", Derived: true,
		Variants: map[string]Variant{"new_privs": v(Medium, Proof)}},
	{ID: "AMP-4", Category: "AMP", Title: "Control sockets", Kind: TwoSided, Mechanism: "write_perm", AbsentOK: true,
		Targets: []string{"/.sprite/api.sock", "/var/run/docker.sock", "/run/docker.sock", "/run/containerd/containerd.sock",
			"/run/podman/podman.sock", "/run/dbus/system_bus_socket"},
		Variants: map[string]Variant{"control_socket": v(High, Indicator), "system_bus": v(Medium, Indicator)}},
	{ID: "AMP-5", Category: "AMP", Title: "Local daemons", Kind: TwoSided, Mechanism: "net_table",
		Variants: map[string]Variant{"control_port": v(High, Indicator)}},
	{ID: "AMP-6", Category: "AMP", Title: "vsock to the host", Kind: FindOnly, Variants: map[string]Variant{"vsock_connected": v(Medium, Proof)},
		Gate: "no vsock device, or an existing box, or the provider's rules of engagement exclude it (PRV-5), or run exec's default for an unidentified provider (PRV-15)"},
	{ID: "AMP-7", Category: "AMP", Title: "The Kubernetes API", Kind: FindOnly, Variants: map[string]Variant{"k8s_api": v(Medium, Indicator)},
		Gate: "the provider's rules of engagement exclude the API the box names (PRV-5), or run exec's default for an unidentified provider (PRV-15)"},
	{ID: "AMP-8.sys", Category: "AMP", Title: "Kernel settings", Kind: TwoSided, Mechanism: "write_perm",
		Targets:  []string{"/proc/sys/kernel/core_pattern", "/proc/sys/kernel/modprobe", "/proc/sys/kernel/sysrq", "/proc/sys/net/ipv4/ip_forward"},
		Variants: map[string]Variant{"writable_sysctl": v(High, Proof)}},
	{ID: "AMP-8.blk", Category: "AMP", Title: "Block devices", Kind: TwoSided, Mechanism: "read_perm", ScopeOut: "block_devices",
		Discover: []string{"block_devices"}, Variants: map[string]Variant{"readable_block_device": v(High, Proof)}},
}

var byID = func() map[string]*Check {
	m := make(map[string]*Check, len(Checks))
	for i := range Checks {
		m[Checks[i].ID] = &Checks[i]
	}
	return m
}()

// Get returns the check with this ID.
func Get(id string) (*Check, bool) {
	c, ok := byID[id]
	return c, ok
}

// IDs lists every check, in report order.
func IDs() []string {
	ids := make([]string, len(Checks))
	for i, c := range Checks {
		ids[i] = c.ID
	}
	return ids
}

// Plan returns each selected check's planned targets and discovery rules, for the host's manifest.
func Plan(ids []string) (targets, discover map[string][]string) {
	targets, discover = map[string][]string{}, map[string][]string{}
	for _, id := range ids {
		if c, ok := byID[id]; ok {
			targets[id] = append([]string(nil), c.Targets...)
			discover[id] = append([]string(nil), c.Discover...)
		}
	}
	return targets, discover
}

// Dangerous are the capabilities that make AMP-2 Critical: SYS_ADMIN, SYS_PTRACE, SYS_MODULE, DAC_OVERRIDE and
// DAC_READ_SEARCH, as bits of CapEff.
const Dangerous uint64 = 1<<21 | 1<<19 | 1<<16 | 1<<1 | 1<<2
