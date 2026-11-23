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
}

type kState struct {
	uid    uint32
	groups uint32 // a bit per candidate gid
	opened uint32 // a bit per node made 0777
	owners [4]uint32
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
	gids := append([]uint32{}, agentGids...)
	for _, n := range ns {
		uids = append(uids, n.uid)
		gids = append(gids, n.gid)
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
	resolves := func(s kState, i int) bool { // every directory before node i exists and is searchable
		for j := 0; j < i; j++ {
			if !ns[j].exists || !perm(s, j, 1) {
				return false
			}
		}
		return true
	}
	last := len(ns) - 1
	done := func(s kState) bool {
		if resolves(s, last) && ns[last].exists && !(want == 2 && ns[last].ro) && perm(s, last, want) {
			return true
		}
		if want != 2 {
			return false
		}
		for j := last - 1; j >= 0; j-- {
			p, c := ns[j], ns[j+1]
			if !p.exists || !p.dir || p.ro || p.noEntries || !resolves(s, j) || !perm(s, j, 3) { // one mask, as the kernel asks
				continue
			}
			if !c.exists {
				return true
			}
			if c.mnt {
				continue
			}
			if mode(s, j)&0o1000 != 0 && s.uid != s.owners[j] && s.uid != s.owners[j+1] && caps&capFowner == 0 {
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
			if s.uid == s.owners[i] || caps&capFowner != 0 {
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

// toInodes turns a case into the model's inodes: "/", "/a", ... and the target last, all seen.
func toInodes(ns []kNode) []inode {
	out := make([]inode, len(ns))
	p := "/"
	for i, n := range ns {
		if i > 0 {
			p = filepath.Join(p, fmt.Sprintf("n%d", i))
		}
		out[i] = inode{path: p, seen: true, exists: n.exists, dir: n.dir, uid: n.uid, gid: n.gid, mode: n.mode, ro: n.ro,
			procfs: n.procfs, noEntries: n.noEntries, mountPoint: n.mnt}
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
	}
	for _, c := range curated {
		checkCase(t, c)
	}
	// a seeded table: two or three components below "/", each owned by me, root or another, in my group, root's or
	// another's, with modes drawn from the ones that matter, sometimes read-only, missing or a mount point, and every
	// combination of the capabilities the model weighs
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
	for i := 0; i < 6000; i++ {
		depth := 2 + rng.Intn(2)
		ns := []kNode{dir(0, 0, modes[rng.Intn(len(modes))])}
		for d := 1; d < depth; d++ {
			ns = append(ns, pick(true))
		}
		ns = append(ns, pick(rng.Intn(4) == 0))
		for j := 1; j < len(ns); j++ { // nothing exists below what doesn't
			if !ns[j-1].exists {
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

// pathNodes judges the directories the kernel traverses: every link on the way is followed, a directory's link
// included, and counted against SBX-2's eight; past a directory the probe can't search, nothing is seen.
func TestPathNodes(t *testing.T) {
	d := t.TempDir()
	os.MkdirAll(filepath.Join(d, "real", "sub"), 0o755)
	os.WriteFile(filepath.Join(d, "real", "sub", "f"), nil, 0o644)
	os.Symlink(filepath.Join(d, "real"), filepath.Join(d, "link")) // a directory link
	ns, err := pathNodes(filepath.Join(d, "link", "sub", "f"), false)
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, n := range ns {
		paths = append(paths, n.path)
	}
	if got := strings.Join(paths, " "); !strings.Contains(got, filepath.Join(d, "real", "sub")) || strings.Contains(got, filepath.Join(d, "link")) {
		t.Errorf("want the real directories, not the link: %s", got)
	}
	for i := 1; i <= 9; i++ {
		os.Symlink(fmt.Sprintf("h%d", i+1), filepath.Join(d, fmt.Sprintf("h%d", i)))
	}
	os.Mkdir(filepath.Join(d, "h10"), 0o755)
	if _, err := pathNodes(filepath.Join(d, "h1", "f"), false); err == nil || !strings.Contains(err.Error(), "more than 8") {
		t.Errorf("nine directory links: want refused after eight, got %v", err)
	}
	if !root {
		closed := filepath.Join(d, "closed")
		os.Mkdir(closed, 0)
		t.Cleanup(func() { os.Chmod(closed, 0o700) })
		ns, _ := pathNodes(filepath.Join(closed, "x", "f"), false)
		if last := ns[len(ns)-1]; last.seen || !ns[len(ns)-3].seen {
			t.Errorf("past a directory the probe can't search, nothing is seen: %+v", ns)
		}
	}
}

// readOnly says whether p's mount is read-only, for the tests.
func readOnly(p string) bool {
	var fs syscall.Statfs_t
	return syscall.Statfs(p, &fs) == nil && fs.Flags&1 != 0
}
