//go:build linux

package probe

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// The property test for TWN-4: the model's verdict against a brute-force model of the kernel's permission rules,
// written apart from reach.go. kernel searches every sequence of setuid, setgroups, chmod and chown the agent's
// capabilities allow, resolving the path before each one, until the target is written or read, or no new state is
// left. Any disagreement fails: a pass where the brute force gets in, or a finding where it can't.

type kNode struct {
	uid, gid, mode                          uint32
	dir, exists, ro, procfs, noEntries, mnt bool
	link                                    bool // a symlink entry: looked up in its directory, then followed
	in                                      int  // 1 + the index of the directory it is looked up in; 0: the node before it
}

// up is the index of the directory node i is looked up in.
func up(ns []kNode, i int) int {
	if ns[i].in == 0 {
		return i - 1
	}
	return ns[i].in - 1
}

type kState struct {
	uid    uint32
	groups uint32 // a bit per candidate gid
	opened uint32 // a bit per node made 0777
	owners [8]uint32
}

// kPerm is generic_permission, without ACLs: the owner's, the group's or the others' bits, CAP_DAC_OVERRIDE and
// CAP_DAC_READ_SEARCH; proc's own check for a file in procfs, which no DAC capability passes.
func kPerm(n kNode, mode, owner, uid uint32, inGroup bool, caps uint64, want uint32) bool {
	if !(n.procfs && !n.dir) {
		if caps&capDacOverride != 0 {
			if n.dir || want&1 == 0 || mode&0o111 != 0 {
				return true
			}
		}
		if caps&capDacReadSearch != 0 {
			if n.dir && want&2 == 0 || !n.dir && want == 4 {
				return true
			}
		}
	}
	bits := mode
	switch {
	case uid == owner:
		bits >>= 6
	case inGroup:
		bits >>= 3
	}
	return bits&7&want == want
}

func kernelCan(ns []kNode, agentUID uint32, agentGids []uint32, caps uint64, want uint32) bool {
	uids := []uint32{agentUID}
	var gids []uint32 // each candidate gid once: a duplicate adds states, never an identity
	addGid := func(g uint32) {
		for _, c := range gids {
			if c == g {
				return
			}
		}
		gids = append(gids, g)
	}
	for _, g := range agentGids {
		addGid(g)
	}
	for _, n := range ns {
		uids = append(uids, n.uid)
		addGid(n.gid)
	}
	uids = append(uids, 0, 0xfff0)
	var start kState
	start.uid = agentUID
	for i, g := range gids {
		for _, a := range agentGids {
			if g == a {
				start.groups |= 1 << i
			}
		}
	}
	for i, n := range ns {
		start.owners[i] = n.uid
	}
	inGroup := func(s kState, g uint32) bool {
		for i, c := range gids {
			if c == g && s.groups&(1<<i) != 0 {
				return true
			}
		}
		return false
	}
	mode := func(s kState, i int) uint32 {
		if s.opened&(1<<i) != 0 {
			return 0o777
		}
		return ns[i].mode
	}
	perm := func(s kState, i int, want uint32) bool {
		return kPerm(ns[i], mode(s, i), s.owners[i], s.uid, inGroup(s, ns[i].gid), caps, want)
	}
	resolves := func(s kState, i int) bool { // every lookup up to node i: its directory exists and is searchable
		for k := 1; k <= i; k++ {
			d := up(ns, k)
			if !ns[d].exists || !perm(s, d, 1) || k < i && !ns[k].exists {
				return false
			}
		}
		return true
	}
	last := len(ns) - 1
	done := func(s kState) bool {
		t := ns[last]
		if !(want == 2 && t.link) && resolves(s, last) && t.exists && !(want == 2 && t.ro) && perm(s, last, want) {
			return true
		}
		if want != 2 {
			return false
		}
		for k := last; k >= 1; k-- { // replace any entry, a link's included, in the directory it is looked up in
			d := up(ns, k)
			p, c := ns[d], ns[k]
			if !p.exists || !p.dir || p.ro || p.noEntries || !resolves(s, k) || !perm(s, d, 3) { // one mask, as the kernel asks
				continue
			}
			if !c.exists {
				return true
			}
			if c.mnt {
				continue
			}
			if mode(s, d)&0o1000 != 0 && s.uid != s.owners[d] && s.uid != s.owners[k] && caps&capFowner == 0 {
				continue
			}
			return true
		}
		return false
	}
	seen := map[kState]bool{start: true}
	queue := []kState{start}
	for len(queue) > 0 {
		s := queue[0]
		queue = queue[1:]
		if done(s) {
			return true
		}
		var next []kState
		if caps&capSetuid != 0 {
			for _, u := range uids {
				t := s
				t.uid = u
				next = append(next, t)
			}
		}
		if caps&capSetgid != 0 {
			for m := uint32(0); m < 1<<len(gids); m++ {
				t := s
				t.groups = m
				next = append(next, t)
			}
		}
		for i, n := range ns {
			if !n.exists || n.ro || n.procfs || !resolves(s, i) {
				continue
			}
			if !n.link && (s.uid == s.owners[i] || caps&capFowner != 0) { // a link's own mode never changes
				t := s
				t.opened |= 1 << i
				next = append(next, t)
			}
			if caps&capChown != 0 {
				t := s
				t.owners[i] = s.uid
				next = append(next, t)
			}
		}
		for _, t := range next {
			if !seen[t] {
				seen[t] = true
				queue = append(queue, t)
			}
		}
	}
	return false
}

// toInodes turns a case into the model's inodes, in lookup order, each named under the directory it is looked up in,
// all seen.
func toInodes(ns []kNode) []inode {
	out := make([]inode, len(ns))
	for i, n := range ns {
		p, parent := "/", -1
		if i > 0 {
			parent = up(ns, i)
			p = filepath.Join(out[parent].path, fmt.Sprintf("n%d", i))
		}
		out[i] = inode{path: p, parent: parent, seen: true, exists: n.exists, dir: n.dir, link: n.link, uid: n.uid,
			gid: n.gid, mode: n.mode, ro: n.ro, procfs: n.procfs, noEntries: n.noEntries, mountPoint: n.mnt}
	}
	return out
}

type kCase struct {
	name string
	ns   []kNode
	uid  uint32
	gids []uint32
	caps uint64
}

func checkCase(t *testing.T, c kCase) {
	t.Helper()
	for _, want := range []uint32{2, 4} {
		a := agentID{uid: c.uid, gids: c.gids, caps: c.caps}
		v, how := gains(a, toInodes(c.ns), want, false, true)
		k := kernelCan(c.ns, c.uid, c.gids, c.caps, want)
		switch {
		case k && v != can:
			t.Errorf("%s, want %d: the brute force gets in, the model says %d (a false pass)", c.name, want, v)
		case !k && v == can:
			t.Errorf("%s, want %d: the brute force can't, the model says it can, %s (a false finding)", c.name, want, how)
		}
	}
}

func dir(uid, gid, mode uint32) kNode {
	return kNode{uid: uid, gid: gid, mode: mode, dir: true, exists: true}
}
func file(uid, gid, mode uint32) kNode {
	return kNode{uid: uid, gid: gid, mode: mode, exists: true}
}

func TestModelAgainstKernel(t *testing.T) {
	const me, other = 1000, 2000
	root := dir(0, 0, 0o755)
	curated := []kCase{
		// the code review's: a group-search directory over a group-write file, CAP_SETGID alone
		{"setgid composes search and write", []kNode{root, dir(0, 1234, 0o010), file(0, 1234, 0o020)}, me, []uint32{me}, capSetgid},
		// permitted CAP_DAC_READ_SEARCH over a root 0000 directory and a 0666 file
		{"read-search over a closed directory", []kNode{root, dir(0, 0, 0), file(0, 0, 0o666)}, me, []uint32{me}, capDacReadSearch},
		// the security review's: CAP_SETUID alone and a procfs sysctl root may write
		{"setuid to a sysctl", []kNode{root, {uid: 0, gid: 0, mode: 0o555, dir: true, exists: true, procfs: true, noEntries: true},
			{uid: 0, gid: 0, mode: 0o644, exists: true, procfs: true}}, me, []uint32{me}, capSetuid},
		// an agent-owned 0555 directory above a root-owned 0444 file
		{"owned read-only directory", []kNode{root, dir(me, me, 0o555), file(0, 0, 0o444)}, me, []uint32{me}, 0},
		// a sticky directory under CAP_FOWNER
		{"sticky under fowner", []kNode{root, dir(0, 0, 0o1777), file(0, 0, 0o444)}, me, []uint32{me}, capFowner},
		{"sticky, no power", []kNode{root, dir(0, 0, 0o1777), file(0, 0, 0o444)}, me, []uint32{me}, 0},
		// a read-only mount stops even an owner
		{"read-only owned", []kNode{root, {uid: me, gid: me, mode: 0o555, dir: true, exists: true, ro: true},
			{uid: me, gid: me, mode: 0o444, exists: true, ro: true}}, me, []uint32{me}, capFowner | capSetuid},
		// an owner bits of 0 under group-writable: being the owner can lock one out
		{"owner locked out", []kNode{root, dir(0, 0, 0o755), file(me, 4000, 0o070)}, me, []uint32{me, 4000}, 0},
		// the post-merge review's: root's sticky directory holding my link to root's 0555 directory and its 0444 file
		{"my link in a sticky directory", []kNode{root, dir(0, 0, 0o1777), {uid: me, gid: me, mode: 0o777, exists: true, link: true},
			{uid: 0, gid: 0, mode: 0o555, dir: true, exists: true, in: 1}, file(0, 0, 0o444)}, me, []uint32{me}, 0},
		{"root's link in a sticky directory", []kNode{root, dir(0, 0, 0o1777), {uid: 0, gid: 0, mode: 0o777, exists: true, link: true},
			{uid: 0, gid: 0, mode: 0o555, dir: true, exists: true, in: 1}, file(0, 0, 0o444)}, me, []uint32{me}, 0},
	}
	for _, c := range curated {
		checkCase(t, c)
	}
	// a seeded table: two or three components below "/", a directory holding a link (absolute, to a directory in "/",
	// or relative, in its own directory), or a link followed by ".." (the target looked up in the real parent), each
	// owned by me, root or another, in my group, root's or another's, with modes drawn from the ones that matter,
	// sometimes read-only, missing or a mount point, and every combination of the capabilities the model weighs
	rng := rand.New(rand.NewSource(24))
	modes := []uint32{0, 0o010, 0o020, 0o030, 0o040, 0o070, 0o100, 0o200, 0o300, 0o400, 0o444, 0o500, 0o555, 0o600,
		0o644, 0o666, 0o700, 0o701, 0o705, 0o711, 0o750, 0o755, 0o770, 0o777, 0o1777, 0o1770, 0o1733}
	owners := []uint32{me, 0, other}
	groups := []uint32{me, 0, 4000}
	powers := []uint64{capSetuid, capSetgid, capChown, capFowner, capDacOverride, capDacReadSearch}
	pick := func(dirNode bool) kNode {
		n := kNode{uid: owners[rng.Intn(3)], gid: groups[rng.Intn(3)], mode: modes[rng.Intn(len(modes))], dir: dirNode,
			exists: rng.Intn(12) != 0, ro: rng.Intn(10) == 0, mnt: rng.Intn(15) == 0}
		if !dirNode && rng.Intn(10) == 0 {
			n.procfs = true
		}
		return n
	}
	for i := 0; i < 12000; i++ {
		ns := []kNode{dir(0, 0, modes[rng.Intn(len(modes))])}
		switch rng.Intn(4) {
		case 0: // two or three components, each in the one before
			for d := 1 + rng.Intn(2); d > 0; d-- {
				ns = append(ns, pick(true))
			}
		case 1: // a directory holding an absolute link to a directory in "/": /a/link -> /b
			l := pick(false)
			l.link, l.mode, l.ro, l.procfs, l.mnt = true, 0o777, false, false, false
			b := pick(true)
			b.in = 1
			ns = append(ns, pick(true), l, b)
		case 2: // a relative link, resolved in its own directory: /a/link -> b, that is /a/b
			l := pick(false)
			l.link, l.mode, l.ro, l.procfs, l.mnt = true, 0o777, false, false, false
			b := pick(true)
			b.in = 2
			ns = append(ns, pick(true), l, b)
		case 3: // ".." after a directory link: /link -> /x/y, then .. lands in /x, where the target is looked up
			l := pick(false)
			l.link, l.mode, l.ro, l.procfs, l.mnt = true, 0o777, false, false, false
			x := pick(true)
			x.in = 1 // in "/"
			ns = append(ns, l, x, pick(true))
		}
		target := pick(rng.Intn(4) == 0)
		if len(ns) == 4 && ns[1].link {
			target.in = 3 // after .., in /x, never in /x/y nor beside the link
		}
		ns = append(ns, target)
		for j := 1; j < len(ns); j++ { // nothing exists below what doesn't, nor past a missing link
			if !ns[up(ns, j)].exists || ns[j-1].link && !ns[j-1].exists {
				ns[j].exists = false
			}
		}
		var caps uint64
		for _, p := range powers {
			if rng.Intn(4) == 0 {
				caps |= p
			}
		}
		gids := []uint32{me}
		if rng.Intn(3) == 0 {
			gids = append(gids, 4000)
		}
		checkCase(t, kCase{fmt.Sprintf("case %d %+v caps %#x gids %v", i, ns, caps, gids), ns, me, gids, caps})
	}
}

// walkPath keeps every lookup the kernel makes: a link on the way stays an entry of its own directory, then is
// followed to the real directories it leads to; past a directory the probe can't search, nothing is seen.
func TestWalkPathNodes(t *testing.T) {
	d := t.TempDir()
	os.MkdirAll(filepath.Join(d, "real", "sub"), 0o755)
	os.WriteFile(filepath.Join(d, "real", "sub", "f"), nil, 0o644)
	os.Symlink(filepath.Join(d, "real"), filepath.Join(d, "link")) // a directory link
	w, err := walkPath(filepath.Join(d, "link", "sub", "f"), false)
	if err != nil {
		t.Fatal(err)
	}
	defer w.close()
	var paths []string
	link := -1
	for i, n := range w.nodes {
		paths = append(paths, n.path)
		if n.path == filepath.Join(d, "link") && n.link {
			link = i
		}
	}
	switch got := strings.Join(paths, " "); {
	case !strings.Contains(got, filepath.Join(d, "real", "sub")):
		t.Errorf("want the real directories the link leads to: %s", got)
	case link < 0 || w.nodes[w.nodes[link].parent].path != d:
		t.Errorf("want the link kept as an entry of its own directory, %s: %s", d, got)
	}
	if !root {
		closed := filepath.Join(d, "closed")
		os.Mkdir(closed, 0)
		t.Cleanup(func() { os.Chmod(closed, 0o700) })
		w, _ := walkPath(filepath.Join(closed, "x", "f"), false)
		if last := w.nodes[w.last()]; last.seen || w.errno != syscall.EACCES || !w.nodes[w.last()-2].seen {
			t.Errorf("past a directory the probe can't search, nothing is seen: %+v", w.nodes)
		}
		w.close()
	}
}

// The code review of #37's cases, against the kernel: after a directory link, a final link to ../target resolves from
// the real directory holding it, not the lexical one, so the walk, and the read check's pin, land on the inode the
// kernel's own stat reaches; and eight directory links plus a final link spend one budget of eight, so the walk refuses.
func TestWalkAgreesWithKernel(t *testing.T) {
	d := t.TempDir()
	os.MkdirAll(filepath.Join(d, "real", "dir"), 0o755)
	os.Mkdir(filepath.Join(d, "base"), 0o755)
	os.WriteFile(filepath.Join(d, "real", "target"), []byte("real"), 0o644)
	os.WriteFile(filepath.Join(d, "base", "target"), []byte("lexical"), 0o644)
	os.Symlink(filepath.Join(d, "real", "dir"), filepath.Join(d, "base", "linkdir"))
	os.Symlink("../target", filepath.Join(d, "real", "dir", "final"))
	p := filepath.Join(d, "base", "linkdir", "final")
	var kst syscall.Stat_t
	if err := syscall.Stat(p, &kst); err != nil {
		t.Fatal(err)
	}
	w, err := walkPath(p, true)
	if err != nil {
		t.Fatal(err)
	}
	if n := w.nodes[w.last()]; n.ino != kst.Ino || n.dev != uint64(kst.Dev) || n.path != filepath.Join(d, "real", "target") {
		t.Errorf("want the kernel's inode, %s, got %s", filepath.Join(d, "real", "target"), n.path)
	}
	w.close()
	if tg, _, err := readCheck(p, p); err != nil || tg.Inode != kst.Ino {
		t.Errorf("the read check pinned another inode than the kernel reaches: %+v %v", tg, err)
	}
	// eight directory links, then a final link: nine in all
	for i := 1; i <= 8; i++ {
		os.Symlink(fmt.Sprintf("h%d", i+1), filepath.Join(d, fmt.Sprintf("h%d", i)))
	}
	os.Mkdir(filepath.Join(d, "h9"), 0o755)
	os.Symlink("../real/target", filepath.Join(d, "h9", "last"))
	nine := filepath.Join(d, "h1", "last")
	if _, err := walkPath(nine, true); err == nil || !strings.Contains(err.Error(), "more than 8") {
		t.Errorf("eight directory links and a final link: want refused, got %v", err)
	}
	if _, _, err := readCheck(nine, nine); err == nil || !strings.Contains(err.Error(), "more than 8") {
		t.Errorf("the read check followed nine links: %v", err)
	}
	if _, _, err := writeHow(nine, nine); err == nil || !strings.Contains(err.Error(), "more than 8") {
		t.Errorf("the write check followed nine links: %v", err)
	}
}

// A mount point is never told by a change of device: a Btrfs subvolume has its own device ID yet stays an entry its
// directory can rename. Only the mount-root attribute makes an entry immovable (TWN-4).
func TestDeviceChangeIsNoMountPoint(t *testing.T) {
	const me = 1000
	ns := toInodes([]kNode{dir(0, 0, 0o755), dir(me, me, 0o755), {uid: 0, gid: 0, mode: 0o555, dir: true, exists: true},
		file(0, 0, 0o444)})
	ns[2].dev = ns[1].dev + 1 // a subvolume's own device, without the mount-root attribute
	a := agentID{uid: me, gids: []uint32{me}}
	if v, _ := gains(a, ns, 2, false, false); v != can {
		t.Error("a subvolume in the agent's own directory: want it replaceable")
	}
	ns[2].mountPoint = true // statx's STATX_ATTR_MOUNT_ROOT
	if v, _ := gains(a, ns, 2, false, false); v == can {
		t.Error("a mount root: want it immovable")
	}
}

// readOnly says whether p's mount is read-only, for the tests.
func readOnly(p string) bool {
	var fs syscall.Statfs_t
	return syscall.Statfs(p, &fs) == nil && fs.Flags&1 != 0
}

// TWN-4: bounded search is not an exhaustive negative proof.
func TestIdentitySearchCompleteness(t *testing.T) {
	a := agentID{uid: 10001, caps: capSetgid}
	for i := uint32(5000); i < 5020; i++ {
		a.gids = append(a.gids, i)
	}
	ns := toInodes([]kNode{
		{uid: 0, gid: 0, mode: 0o755, dir: true, exists: true},
		{uid: 0, gid: 1234, mode: 0o010, dir: true, exists: true},
		{uid: 0, gid: 1234, mode: 0o020, exists: true},
	})
	if got, _ := gains(a, ns, 2, false, true); got != can {
		t.Fatal("irrelevant existing groups hid a path identity")
	}

	nodes := []kNode{{uid: 0, gid: 0, mode: 0o755, dir: true, exists: true}}
	for i := uint32(1); i <= 11; i++ {
		nodes = append(nodes, kNode{uid: 0, gid: i, mode: 0o755, dir: true, exists: true})
	}
	nodes = append(nodes, kNode{uid: 0, gid: 99, mode: 0o020, exists: true})
	ns = toInodes(nodes)
	if got, why := gains(a, ns, 2, false, true); got != cantTell || !strings.Contains(why, "bound") {
		t.Fatal("unexplored group authority became a negative proof", got, why)
	}
	// A witnessed access is valid even when other identities remain unexplored.
	ns[len(ns)-1].gid = 0
	if got, _ := gains(a, ns, 2, false, true); got != can {
		t.Fatal("bounded search discarded a witnessed access")
	}
}

// The post-merge review's case, at the end observation: the agent's own link in root's sticky /tmp, leading to root's
// directories. The agent can replace the link (the kernel lets an entry's owner rename it in a sticky directory), so
// a write check through it finds the path; then the test makes that rename itself, which the kernel must allow.
func TestStickyLinkReplaceable(t *testing.T) {
	link := filepath.Join("/tmp", fmt.Sprintf("sp-stickylink-%d", os.Getpid()))
	os.Remove(link)
	if err := os.Symlink("/usr/bin", link); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(link); os.Remove(link + ".moved") })
	tg, _, err := writeHow("ls", filepath.Join(link, "ls"))
	if err != nil || tg.State != "found" {
		t.Fatalf("a path through the agent's own link in a sticky directory: want found, got %+v %v", tg, err)
	}
	if err := os.Rename(link, link+".moved"); err != nil {
		t.Errorf("the kernel refused the rename the finding rests on: %v", err)
	}
}
