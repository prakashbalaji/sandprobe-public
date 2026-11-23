//go:build linux

package probe

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"sandprobe/internal/catalog"
	"sandprobe/internal/obs"
)

type check func(e *env, ck *catalog.Check) obs.Observation

// checks implemented so far. Anything selected but missing here is left out of the document, and the host grades it
// unknown: never a pass.
var checks = map[string]check{
	"SEC-1":      sec1,
	"SEC-2":      func(e *env, ck *catalog.Check) obs.Observation { return secProc(e, ck, "environ") },
	"SEC-3":      sec3,
	"SEC-4":      sec4,
	"SEC-5":      func(e *env, ck *catalog.Check) obs.Observation { return secProc(e, ck, "mem") },
	"PER-1":      writable,
	"PER-2":      writable,
	"PER-3":      writable,
	"PER-4":      writable,
	"AMP-1":      amp1,
	"AMP-4":      sockets,
	"AMP-5":      amp5,
	"AMP-6":      amp6,
	"AMP-7":      amp7,
	"AMP-8.sys":  writable,
	"AMP-8.blk":  amp8blk,
	"EGR-1":      egrDNS,
	"EGR-2":      egrDirect,
	"EGR-3":      egrProxy,
	"EGR-4":      egrIntercept,
	"EGR-5.22":   egrDirect,
	"EGR-5.80":   egrDirect,
	"EGR-5.8080": egrDirect,
	"EGR-5.53u":  egrUDP,
}

func unknownObs(why string) obs.Observation { return obs.Observation{Result: obs.Unknown, Reason: why} }

// sweep tests the check's planned targets, then every target each planned discovery rule found, with test.
func (e *env) sweep(id string, found map[string][]string, test func(name, path string) (obs.Target, error)) ([]obs.Target, map[string]int, error) {
	var ts []obs.Target
	counts := map[string]int{}
	for _, name := range e.in.Targets[id] {
		t, err := test(name, e.expand(name))
		if err != nil {
			return nil, nil, err
		}
		ts = append(ts, t)
	}
	for _, rule := range e.in.Discover[id] {
		counts[rule] = len(found[rule])
		for _, p := range found[rule] {
			t, err := test(p, p)
			if err != nil {
				return nil, nil, err
			}
			t.Rule = rule
			ts = append(ts, t)
		}
	}
	if len(ts) > 256 {
		return nil, nil, errors.New("more than 256 targets")
	}
	return ts, counts, nil
}

// judge turns a sweep into an observation: a finding if any target is found; an absence if every target is verified
// absent and the check allows it; otherwise a pass carrying its proof, both twin sides and every target.
func (e *env) judge(ck *catalog.Check, ts []obs.Target, counts map[string]int, twinOK, twinRefused bool,
	pick func(found []obs.Target) (variant, evidence string)) obs.Observation {
	var found []obs.Target
	allAbsent := len(ts) > 0
	for _, t := range ts {
		if t.State == "found" {
			found = append(found, t)
		}
		if t.State != "absent" {
			allAbsent = false
		}
	}
	if len(found) > 0 {
		v, ev := pick(found)
		return obs.Observation{Result: obs.Finding, Variant: v, Evidence: ev,
			Proof: &obs.Proof{Mechanism: ck.Mechanism, Root: e.root, Discovered: counts, Targets: ts, Twin: twinOK, TwinRefused: twinRefused && !e.root}}
	}
	if why := reachPast(); why != "" {
		return unknownObs(why)
	}
	p := &obs.Proof{Mechanism: ck.Mechanism, Root: e.root, Discovered: counts, Targets: ts}
	if allAbsent && ck.AbsentOK {
		return obs.Observation{Result: obs.Absent, Proof: p}
	}
	if why := e.refusalsHold(ck, ts); why != "" {
		return unknownObs(why)
	}
	p.Twin, p.TwinRefused = twinOK, twinRefused && !e.root
	return obs.Observation{Result: obs.Pass, Proof: p}
}

// reachPast says why no negative stands for this agent, or "" (TWN-4): it holds a capability that reaches past file
// permissions and the mount table altogether, so a refusal, an absence or an empty listing alike shows nothing (a
// mount can hide a path or stand in for one, and hidepid can be remounted). Every early negative return of a file
// check asks it first.
func reachPast() string {
	if held := agentCaps() & pastPermissions; held != 0 {
		return "nothing was found, but the agent holds " + capList(held) + ", which reaches past file permissions and " +
			"mounts altogether, so no refusal, absence or empty listing shows anything (TWN-4)"
	}
	return ""
}

// refusalsHold says why a pass's refusals can't count, or "" (TWN-4): the agent could get past them whatever a path's
// mode is now, by a capability it holds, permitted or effective, or a path it owns. Nothing is opened to find out.
func (e *env) refusalsHold(ck *catalog.Check, ts []obs.Target) string {
	caps := agentCaps()
	var refused []obs.Target
	for _, t := range ts {
		if t.State == "refused" {
			refused = append(refused, t)
		}
	}
	if len(refused) == 0 {
		return ""
	}
	switch ck.Mechanism {
	case "file_read", "read_perm":
		if caps&readPowers != 0 {
			return "the agent was refused " + names(refused) + ", but it holds " + capList(caps&readPowers) +
				", with which it can read a file whatever its mode now, so no refusal shows anything (TWN-4)"
		}
		for _, t := range refused {
			why, err := gain(e.expand(t.Name), 4, true)
			switch {
			case err != nil:
				return "the agent was refused " + t.Name + ", and whether a change could get it in can't be told: " +
					err.Error() + " (TWN-4)"
			case why != "":
				return "the agent was refused " + t.Name + ", but could read it " + why + " (TWN-4)"
			}
		}
	case "proc_open":
		if caps&procPowers != 0 {
			return "the agent was refused " + names(refused) + ", but it holds " + capList(caps&procPowers) +
				", with which it can get past ptrace's rules for another process, so no refusal shows anything (TWN-4)"
		}
	}
	return ""
}

func names(ts []obs.Target) string {
	var n []string
	for _, t := range ts {
		n = append(n, t.Name)
	}
	return strings.Join(n, ", ")
}

func sweepErr(err error) obs.Observation {
	if errors.Is(err, errUnknowable) {
		return unknownObs(err.Error())
	}
	return unknownObs("the probe couldn't test a target: " + err.Error())
}

// SEC-1: names only (SBX-2). SANDPROBE_TWIN, set by the adapter, must show up through the same read.
var secretName = regexp.MustCompile(`(?i)(KEY|TOKEN|SECRET|PASS|CREDENTIAL|AUTH|PRIVATE|DSN|_PAT$|DATABASE_URL)`)

func sec1(e *env, ck *catalog.Check) obs.Observation {
	var found []string
	count, twin := 0, false
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		count++
		switch {
		case name == "SANDPROBE_TWIN":
			twin = true
		case secretName.MatchString(name):
			found = append(found, name)
		}
	}
	if len(found) > 0 {
		sort.Strings(found)
		return obs.Observation{Result: obs.Finding, Variant: "names", ObservedNames: found,
			Evidence: "secret-shaped names in the agent's environment, values never read: " + strings.Join(found, ", ")}
	}
	return obs.Observation{Result: obs.Pass, Proof: &obs.Proof{Mechanism: ck.Mechanism, Twin: twin, Count: count, Root: e.root}}
}

// SEC-2 and SEC-5: every other process's environ or mem, opened and never read.
func secProc(e *env, ck *catalog.Check, file string) obs.Observation {
	var paths []string
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return unknownObs("can't list /proc: " + err.Error())
	}
	self := os.Getpid()
	for _, d := range entries {
		pid, err := strconv.Atoi(d.Name())
		if err != nil || pid == self || e.tw.children[pid] {
			continue
		}
		paths = append(paths, "/proc/"+d.Name()+"/"+file)
	}
	if len(paths) == 0 {
		if why := reachPast(); why != "" {
			return unknownObs(why)
		}
		return obs.Observation{Result: obs.ScopedOut, Reason: "no other process is visible to the probe (a PID namespace, or hidepid)",
			Proof: &obs.Proof{Mechanism: ck.Mechanism, Root: e.root, Discovered: map[string]int{"proc_pids": 0}}}
	}
	ts, counts, err := e.sweep(ck.ID, map[string][]string{"proc_pids": paths}, procCheck)
	if err != nil {
		return sweepErr(err)
	}
	return e.judge(ck, ts, counts, e.tw.procOK[file], e.tw.procRefused[file], func(found []obs.Target) (string, string) {
		return "readable", "the agent can open " + names(found) + " (nothing was read)"
	})
}

// SEC-3: credential files, each read-checked on a pinned inode.
func sec3(e *env, ck *catalog.Check) obs.Observation {
	keys, err := sshKeys(e.home)
	if err != nil {
		return unknownObs("ssh key discovery failed: " + err.Error())
	}
	secrets, err := secretFiles("/run/secrets")
	if err != nil {
		return unknownObs("/run/secrets discovery failed: " + err.Error())
	}
	wd, err := os.Getwd()
	if err != nil {
		return unknownObs("can't tell the working directory: " + err.Error())
	}
	envs, err := dotenvs(e.home, wd)
	if err != nil {
		return unknownObs(".env discovery failed: " + err.Error())
	}
	found := map[string][]string{"ssh_keys": keys, "run_secrets": secrets, "dotenv": envs}
	nonEmpty := map[string]bool{}
	ts, counts, err := e.sweep(ck.ID, found, func(name, path string) (obs.Target, error) {
		t, ne, err := readCheck(name, path)
		nonEmpty[name] = ne
		return t, err
	})
	if err != nil {
		return sweepErr(err)
	}
	return e.judge(ck, ts, counts, e.tw.readOK, e.tw.readRefused, func(fs []obs.Target) (string, string) {
		variant := "empty"
		for _, t := range fs {
			switch {
			case nonEmpty[t.Name] && strings.HasSuffix(t.Name, "serviceaccount/token"):
				variant = "k8s_token"
			case nonEmpty[t.Name] && variant == "empty":
				variant = "nonempty"
			}
		}
		return variant, "the agent can read " + names(fs) + " (opened, never read)"
	})
}

// writable is PER-1 to PER-4, AMP-4 and AMP-8's kernel settings: write or replace, never opened for writing.
func writable(e *env, ck *catalog.Check) obs.Observation {
	found := map[string][]string{}
	if ck.ID == "PER-2" {
		wd, _ := os.Getwd()
		dirs, err := pathDirs(os.Getenv("PATH"), wd)
		if err != nil {
			return unknownObs(err.Error())
		}
		found["path_dirs"] = dirs
	}
	how := map[string]string{}
	ts, counts, err := e.sweep(ck.ID, found, func(name, path string) (obs.Target, error) {
		t, h, err := writeHow(name, path)
		how[name] = h
		return t, err
	})
	if err != nil {
		return sweepErr(err)
	}
	return e.judgeWrite(ck, ts, counts, how, func(now []obs.Target, made []string) (string, string) {
		variant := "writable"
		if ck.ID == "AMP-8.sys" {
			variant = "writable_sysctl"
		}
		var ev []string
		if len(now) > 0 {
			ev = append(ev, "the agent can write or replace "+names(now))
		}
		if len(made) > 0 {
			ev = append(ev, "the agent could write or replace "+strings.Join(made, ", "))
		}
		return variant, strings.Join(ev, "; ")
	})
}

// AMP-4: the known control sockets, each an existing socket the agent may connect to, never connected.
func sockets(e *env, ck *catalog.Check) obs.Observation {
	how := map[string]string{}
	ts, counts, err := e.sweep(ck.ID, nil, func(name, path string) (obs.Target, error) {
		t, h, err := socketCheck(name, path)
		how[name] = h
		return t, err
	})
	if err != nil {
		return sweepErr(err)
	}
	return e.judgeWrite(ck, ts, counts, how, func(now []obs.Target, made []string) (string, string) {
		variant := "system_bus"
		for _, t := range ts {
			if t.State == "found" && t.Name != "/run/dbus/system_bus_socket" {
				variant = "control_socket"
			}
		}
		var ev []string
		if len(now) > 0 {
			ev = append(ev, "the agent has connect permission on "+names(now))
		}
		if len(made) > 0 {
			ev = append(ev, "the agent could give itself connect permission on "+strings.Join(made, ", "))
		}
		return variant, strings.Join(ev, "; ") + " (never connected)"
	})
}

// judgeWrite is judge for the write_perm mechanism, shared by every check that uses it (TWN-4). A target found only
// because the agent can make it writable (how names it) counts as found where the check's findings are indicators, and
// pick lists it apart, with how; where they are proofs, it leaves the check unknown unless another target is found
// outright. judge then holds any pass to refusalsHold.
func (e *env) judgeWrite(ck *catalog.Check, ts []obs.Target, counts map[string]int, how map[string]string,
	pick func(now []obs.Target, made []string) (variant, evidence string)) obs.Observation {
	var now []obs.Target
	var made []string
	for _, t := range ts {
		switch {
		case t.State != "found":
		case how[t.Name] != "":
			made = append(made, t.Name+" ("+how[t.Name]+")")
		default:
			now = append(now, t)
		}
	}
	proofs := false
	for _, v := range ck.Variants {
		proofs = proofs || v.Class == catalog.Proof
	}
	if proofs && len(made) > 0 && len(now) == 0 {
		return unknownObs("nothing is writable now, and the agent could write " + strings.Join(made, ", ") +
			" only by a change of identity or mode, which is no proof (TWN-4)")
	}
	if proofs {
		made = nil
	}
	return e.judge(ck, ts, counts, e.tw.writeOK, e.tw.writeRefused, func([]obs.Target) (string, string) { return pick(now, made) })
}

// AMP-5: listening sockets from /proc/net/tcp and tcp6, never connected. The twin is the probe's own loopback
// listener, which must show up in the same table.
var controlPorts = map[int]bool{2375: true, 2376: true, 10250: true}

type netRow struct {
	port   int
	listen bool
	uid    string
}

// parseNetTable reads a whole /proc/net/tcp table. A read error or a malformed row fails it: a partial table is
// never taken for a complete one.
func parseNetTable(r io.Reader) ([]netRow, error) {
	sc := bufio.NewScanner(r)
	if !sc.Scan() {
		return nil, errors.New("the table has no header")
	}
	var rows []netRow
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 10 {
			return nil, fmt.Errorf("malformed row %q", sc.Text())
		}
		_, portHex, ok := strings.Cut(f[1], ":")
		port, err := strconv.ParseUint(portHex, 16, 16)
		if !ok || err != nil || len(f[3]) != 2 {
			return nil, fmt.Errorf("malformed row %q", sc.Text())
		}
		rows = append(rows, netRow{port: int(port), listen: f[3] == "0A", uid: f[7]})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return rows, nil
}

func amp5(e *env, ck *catalog.Check) obs.Observation {
	rows, twin := 0, false
	var control []string
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		fh, err := os.Open(f)
		if err != nil {
			if f == "/proc/net/tcp6" && os.IsNotExist(err) {
				continue
			}
			return unknownObs("can't read " + f + ": " + err.Error())
		}
		table, err := parseNetTable(fh)
		fh.Close()
		if err != nil {
			return unknownObs(f + ": " + err.Error())
		}
		for _, r := range table {
			rows++
			if !r.listen {
				continue
			}
			if r.port == e.ownPort {
				twin = true
			}
			if controlPorts[r.port] {
				control = append(control, fmt.Sprintf("port %d (uid %s)", r.port, r.uid))
			}
		}
	}
	if len(control) > 0 {
		return obs.Observation{Result: obs.Finding, Variant: "control_port",
			Evidence: "a control API listens in the agent's network namespace: " + strings.Join(control, ", ")}
	}
	return obs.Observation{Result: obs.Pass, Proof: &obs.Proof{Mechanism: ck.Mechanism, Twin: twin, Count: rows, Root: e.root}}
}

// AMP-8 block devices: read permission on each, never opened. With none visible, scoped out.
func amp8blk(e *env, ck *catalog.Check) obs.Observation {
	var devs []string
	entries, err := os.ReadDir("/sys/class/block")
	if err != nil && !os.IsNotExist(err) {
		return unknownObs("can't list /sys/class/block: " + err.Error())
	}
	for _, d := range entries {
		p := "/dev/" + d.Name()
		if _, err := os.Lstat(p); err == nil {
			devs = append(devs, p)
		}
	}
	if len(devs) == 0 {
		if why := reachPast(); why != "" {
			return unknownObs(why)
		}
		return obs.Observation{Result: obs.ScopedOut, Reason: "no block device is visible to the probe",
			Proof: &obs.Proof{Mechanism: ck.Mechanism, Root: e.root, Discovered: map[string]int{"block_devices": 0}}}
	}
	ts, counts, err := e.sweep(ck.ID, map[string][]string{"block_devices": devs}, permCheck)
	if err != nil {
		return sweepErr(err)
	}
	return e.judge(ck, ts, counts, e.tw.permOK, e.tw.permRefused, func(fs []obs.Target) (string, string) {
		return "readable_block_device", "the agent can read " + names(fs) + " (never opened)"
	})
}

// Discovery rules.

// Discovery rules ask what the agent can reach. A missing directory, or one the agent can't search, holds nothing it
// could read, so it's empty. One the agent can search but not list may hold files reachable by name: errHidden, and
// the check is unknown unless the rule can test the names it cares about directly. Any other error fails discovery.
var errHidden = errors.New("can be searched but not listed, so files reachable by name can't be ruled out")

func listDir(dir string) ([]os.DirEntry, error) {
	entries, err := os.ReadDir(dir)
	switch {
	case err == nil:
		return entries, nil
	case os.IsNotExist(err):
		return nil, nil
	case errnoOf(err) == syscall.EACCES:
		if syscall.Faccessat(unixAtFDCWD, dir, 1 /* X_OK */, atEAccess) != nil {
			return nil, nil // nothing inside is reachable by the agent
		}
		return nil, fmt.Errorf("%s %w", dir, errHidden)
	}
	return nil, err
}

func sshKeys(home string) ([]string, error) {
	dir := filepath.Join(home, ".ssh")
	entries, err := listDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, d := range entries {
		if strings.HasPrefix(d.Name(), "id_") && !strings.HasSuffix(d.Name(), ".pub") {
			out = append(out, filepath.Join(dir, d.Name()))
		}
	}
	return out, nil
}

// secretDepth is how far below /run/secrets the walk goes. Kubernetes mounts service account tokens there as
// directories of symlinks two levels down (kubernetes.io/serviceaccount/token, and EKS's eks.amazonaws.com and
// pods.eks.amazonaws.com), with the real files one level further, behind ..data.
const secretDepth = 4

// secretFiles is /run/secrets as the agent can reach it: every entry that isn't a directory is a target, for readCheck
// to judge, and directories, symlinked ones too (within SBX-2's 8 hops), are walked to secretDepth. A directory is
// walked again only with more depth left than before. One past secretDepth can't be covered, and fails discovery.
func secretFiles(root string) ([]string, error) {
	type dirKey struct{ dev, ino uint64 }
	budget := map[dirKey]int{}
	var out []string
	var walk func(dir string, depth int) error
	walk = func(dir string, depth int) error {
		var st syscall.Stat_t
		if syscall.Stat(dir, &st) == nil {
			k, left := dirKey{uint64(st.Dev), st.Ino}, secretDepth-depth
			if b, ok := budget[k]; ok && b >= left {
				return nil
			}
			budget[k] = left
		}
		entries, err := listDir(dir)
		if err != nil {
			return err
		}
		for _, d := range entries {
			p := filepath.Join(dir, d.Name())
			isDir := d.IsDir()
			if d.Type()&os.ModeSymlink != 0 {
				n, err := resolve(p)
				isDir = err == nil && n.errno == 0 && n.st.Mode&syscall.S_IFMT == syscall.S_IFDIR
			}
			switch {
			case !isDir:
				out = append(out, p) // a file, or a link that leads anywhere but a directory
			case depth == secretDepth:
				return fmt.Errorf("%s is deeper than the walk covers", p)
			default:
				if err := walk(p, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(root, 0); err != nil {
		return nil, err
	}
	return out, nil
}

// dotenvs finds .env files in the agent's home and working directory, two levels deep, "/" included, following
// symlinked directories as the agent would (each chain bounded by SBX-2's 8 hops). A directory is walked again only
// when a later path reaches it with more depth left than any earlier one, so neither a cycle nor the order of the two
// roots can cut coverage short. procfs
// and sysfs hold none and are skipped. A directory at the last level that can be searched but not listed gets its
// .env checked by name; above that level, it makes discovery fail.
func dotenvs(home, wd string) ([]string, error) {
	type dirKey struct{ dev, ino uint64 }
	seen, budget := map[string]bool{}, map[dirKey]int{} // the most depth left any walk of a directory has had
	var out []string
	add := func(p string) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	var walk func(dir string, depth int) error
	walk = func(dir string, depth int) error {
		if pseudo(dir) {
			return nil
		}
		var st syscall.Stat_t
		if syscall.Stat(dir, &st) == nil {
			k, left := dirKey{uint64(st.Dev), st.Ino}, 2-depth
			if b, ok := budget[k]; ok && b >= left {
				return nil // walked already with at least this much depth left: a cycle, or a shallower path first
			}
			budget[k] = left
		}
		entries, err := listDir(dir)
		if errors.Is(err, errHidden) && depth == 2 {
			p := filepath.Join(dir, ".env")
			switch e := errnoOf(lstat(p, new(syscall.Stat_t))); {
			case e == 0:
				add(p)
			case e == syscall.ENOENT:
			default:
				return fmt.Errorf("checking %s by name: %w", p, e)
			}
			return nil
		}
		if err != nil {
			return err
		}
		for _, d := range entries {
			p := filepath.Join(dir, d.Name())
			switch {
			case d.Name() == ".env":
				add(p)
			case depth >= 2:
			case d.IsDir():
				if err := walk(p, depth+1); err != nil {
					return err
				}
			case d.Type()&os.ModeSymlink != 0:
				n, err := resolve(p)
				switch {
				case errors.Is(err, errDangling):
					continue // leads nowhere the agent could read
				case err != nil:
					return err // a loop, or too many hops: coverage can't be established
				case n.errno == 0 && n.st.Mode&syscall.S_IFMT == syscall.S_IFDIR:
					if err := walk(p, depth+1); err != nil {
						return err
					}
				}
			}
		}
		return nil
	}
	for _, root := range []string{home, wd} {
		if root == "" {
			continue
		}
		if err := walk(root, 0); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// pathDirs are the PATH entries ahead of the first system directory, other than the planned /usr/local/bin. An empty
// or relative entry is searched relative to the working directory, so it resolves against wd; without one, it can't
// be judged.
func pathDirs(path, wd string) ([]string, error) {
	system := map[string]bool{"/usr/sbin": true, "/usr/bin": true, "/sbin": true, "/bin": true}
	seen := map[string]bool{}
	var out []string
	for _, d := range filepath.SplitList(path) {
		if system[d] {
			break
		}
		if !filepath.IsAbs(d) {
			if wd == "" {
				return nil, fmt.Errorf("PATH entry %q is relative to a working directory the probe can't tell", d)
			}
			d = filepath.Join(wd, d)
		}
		d = filepath.Clean(d)
		if d == "/usr/local/bin" || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out, nil
}
