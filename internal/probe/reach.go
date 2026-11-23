//go:build linux

package probe

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// TWN-4's model of the kernel's permission rules: could the agent write or read a path by an identity it can assume
// or a mode it can change, judged along the inodes the kernel traverses for it. The kernel itself answers for the
// agent as it is (faccessat, the open); the model answers only for what a change could gain. It reads stat
// information alone: nothing is opened, read or changed.

// inode is one inode on a path as the kernel traverses it: a real directory, or the target.
type inode struct {
	path       string
	seen       bool // stat could see it; past a directory the agent can't search, nothing can be
	exists     bool
	dir        bool
	link       bool // the target is a symlink: replacing it counts, writing it doesn't (its target is the next hop)
	uid, gid   uint32
	mode       uint32 // the permission bits and the sticky bit
	ro         bool   // on a read-only mount: nothing writes here, and no mode or owner changes
	procfs     bool   // in procfs: no mode or owner changes, and no DAC capability opens its files
	noEntries  bool   // procfs or sysfs: no entry is created, renamed or removed in it
	mountPoint bool   // a mount point: it can't be renamed or removed
	acl        bool   // carries a POSIX ACL, which the model doesn't evaluate
	dev        uint64 // its device, for telling a mount point below it
}

// agentID is the agent as it is: its uid and groups, its effective capabilities, and every capability it holds or
// can raise (permitted or effective).
type agentID struct {
	uid       uint32
	gids      []uint32
	eff, caps uint64
}

// identity is one the agent can assume, with the capabilities it keeps.
type identity struct {
	uid  uint32
	gids map[uint32]bool
	caps uint64
}

type verdict int

const (
	cannot   verdict = iota
	can              // a change of identity or mode gets the access
	cantTell         // the path passes through what the probe can't see, or an ACL or a security module decides
)

// errModel means the model can't judge a path at all; the check is unknown.
var errModel = errors.New("the path can't be modelled")

// theAgent reads the agent as it is, with capget(2) and the id calls, never /proc. A failed capability read counts
// every capability.
func theAgent() agentID {
	a := agentID{uid: uint32(os.Geteuid()), gids: []uint32{uint32(os.Getegid())}}
	if gs, err := os.Getgroups(); err == nil {
		for _, g := range gs {
			a.gids = append(a.gids, uint32(g))
		}
	}
	a.caps = agentCaps()
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if unix.Capget(&hdr, &data[0]) == nil {
		a.eff = uint64(data[0].Effective) | uint64(data[1].Effective)<<32
	}
	a.eff &= a.caps
	return a
}

// pathNodes are the inodes the kernel traverses for p: "/", every real directory below it, each symlink on the way
// followed (a directory's as well as the last name's when follow is set) within SBX-2's eight hops, and the target
// last. A missing component, and everything after it, doesn't exist; past a directory the agent can't search,
// nothing is seen.
func pathNodes(p string, follow bool) ([]inode, error) {
	ns := []inode{stat("/")}
	rest := strings.Split(p, "/")
	cur, hops := "/", 0
	for len(rest) > 0 {
		c := rest[0]
		rest = rest[1:]
		switch c {
		case "", ".":
			continue
		case "..":
			if cur != "/" {
				cur, ns = filepath.Dir(cur), ns[:len(ns)-1]
			}
			continue
		}
		next := filepath.Join(cur, c)
		last := true
		for _, r := range rest {
			last = last && (r == "" || r == ".")
		}
		var st syscall.Stat_t
		err := syscall.Lstat(next, &st)
		switch e := errnoOf(err); {
		case e == syscall.ENOENT || e == syscall.ENOTDIR:
			ns = append(ns, inode{path: next, seen: true})
			for _, r := range rest {
				if r != "" && r != "." {
					next = filepath.Join(next, r)
					ns = append(ns, inode{path: next, seen: true})
				}
			}
			return ns, nil
		case e == syscall.EACCES:
			ns = append(ns, inode{path: next})
			for _, r := range rest {
				if r != "" && r != "." {
					next = filepath.Join(next, r)
					ns = append(ns, inode{path: next})
				}
			}
			return ns, nil
		case err != nil:
			return nil, fmt.Errorf("%w: %s: %v", errModel, next, err)
		}
		if st.Mode&syscall.S_IFMT == syscall.S_IFLNK && (!last || follow) {
			if hops++; hops > maxHops {
				return nil, fmt.Errorf("%w: more than %d links on the way to %s", errModel, maxHops, p)
			}
			t, err := os.Readlink(next)
			if err != nil {
				return nil, fmt.Errorf("%w: %s: %v", errModel, next, err)
			}
			if filepath.IsAbs(t) {
				cur, ns = "/", ns[:1]
			}
			rest = append(strings.Split(t, "/"), rest...)
			continue
		}
		n := stat(next)
		n.mountPoint = uint64(st.Dev) != ns[len(ns)-1].dev
		ns = append(ns, n)
		cur = next
	}
	return ns, nil
}

// stat is one inode's attributes, by lstat, statfs and the ACL's extended attribute's size; nothing is opened.
func stat(p string) inode {
	n := inode{path: p, seen: true}
	var st syscall.Stat_t
	if syscall.Lstat(p, &st) != nil {
		n.seen = false
		return n
	}
	n.dev = uint64(st.Dev)
	n.exists = true
	n.dir = st.Mode&syscall.S_IFMT == syscall.S_IFDIR
	n.link = st.Mode&syscall.S_IFMT == syscall.S_IFLNK
	n.uid, n.gid, n.mode = st.Uid, st.Gid, st.Mode&0o1777
	var fs syscall.Statfs_t
	if syscall.Statfs(p, &fs) == nil {
		n.ro = fs.Flags&1 /* ST_RDONLY */ != 0
		n.procfs = fs.Type == 0x9fa0                    /* PROC_SUPER_MAGIC */
		n.noEntries = n.procfs || fs.Type == 0x62656572 /* SYSFS_MAGIC */
	}
	if !n.link {
		size, err := unix.Lgetxattr(p, "system.posix_acl_access", nil)
		n.acl = err == nil && size > 0
	}
	return n
}

// allows is the kernel's permission check of one inode for an identity: the owner's, the group's or the others' bits;
// CAP_DAC_OVERRIDE passing every directory check and any file read or write; CAP_DAC_READ_SEARCH any read, and a
// directory's search. A file in procfs gets its class bits only. opened: the agent made the mode 0777.
func allows(n *inode, id identity, want uint32, opened bool) bool {
	mode := n.mode
	if opened {
		mode = 0o777
	}
	if !(n.procfs && !n.dir) {
		if id.caps&capDacOverride != 0 && (n.dir || want&1 == 0 || mode&0o111 != 0) {
			return true
		}
		if id.caps&capDacReadSearch != 0 && want&2 == 0 && (n.dir || want&1 == 0) {
			return true
		}
	}
	bits := mode & 7
	switch {
	case id.uid == n.uid:
		bits = mode >> 6 & 7
	case id.gids[n.gid]:
		bits = mode >> 3 & 7
	}
	return bits&want == want
}

// identities are the ones the agent can assume: with CAP_SETUID any uid (the ones that own something here, uid 0, and
// one that owns nothing), with CAP_SETGID any set of inode-owner groups here. Other groups do not affect DAC.
// The bool says whether every relevant combination was considered. Capabilities stay across a change of uid.
func identities(a agentID, ns []inode) ([]identity, bool) {
	complete := true
	uids := []uint32{a.uid}
	if a.caps&capSetuid != 0 {
		have := map[uint32]bool{a.uid: true}
		add := func(u uint32) {
			if !have[u] {
				have[u] = true
				uids = append(uids, u)
			}
		}
		add(0)
		for _, n := range ns {
			if n.exists {
				add(n.uid)
			}
		}
		fresh := uint32(0xfffe)
		for have[fresh] {
			fresh--
		}
		add(fresh)
	}
	sets := []map[uint32]bool{{}}
	for _, g := range a.gids {
		sets[0][g] = true
	}
	if a.caps&capSetgid != 0 {
		have := map[uint32]bool{}
		var rel []uint32
		// TWN-4: only inode-owner groups affect the DAC group-class choice.
		// Existing unrelated groups have no effect and must not exhaust the bound.
		for _, n := range ns {
			if n.exists && !have[n.gid] {
				have[n.gid] = true
				rel = append(rel, n.gid)
			}
		}
		if len(rel) > 10 {
			rel = rel[:10]
			complete = false // Unexplored identities cannot justify a refusal.
		}
		sets = sets[:0]
		for mask := 0; mask < 1<<len(rel); mask++ {
			s := map[uint32]bool{}
			for i, g := range rel {
				if mask&(1<<i) != 0 {
					s[g] = true
				}
			}
			sets = append(sets, s)
		}
	}
	var ids []identity
	for _, u := range uids {
		for _, s := range sets {
			ids = append(ids, identity{uid: u, gids: s, caps: a.caps})
		}
	}
	return ids, complete
}

// reach: can identity id resolve the path to ns[i], every directory before it searchable (as it is, or opened)?
func reach(ns []inode, i int, id identity, opened []bool) verdict {
	for j := 0; j < i; j++ {
		switch {
		case !ns[j].seen:
			return cantTell
		case !ns[j].exists:
			return cannot
		case !allows(&ns[j], id, 1, opened[j]):
			return cannot
		}
	}
	return can
}

// opens is the fixpoint of the modes the agent can change: an inode it can reach as an identity that owns it, or
// holds CAP_FOWNER, or CAP_CHOWN (taking it over first), off read-only mounts and procfs. The reason says how.
func opens(ns []inode, ids []identity, a agentID) ([]bool, []string) {
	opened, why := make([]bool, len(ns)), make([]string, len(ns))
	for changed := true; changed; {
		changed = false
		for i, n := range ns {
			if opened[i] || !n.seen || !n.exists || n.link || n.ro || n.procfs {
				continue
			}
			for _, id := range ids {
				power := ""
				switch {
				case id.uid == n.uid && id.uid == a.uid:
					power = "which it owns"
				case id.uid == n.uid:
					power = fmt.Sprintf("as its owner, uid %d (CAP_SETUID)", n.uid)
				case id.caps&capFowner != 0:
					power = "with CAP_FOWNER"
				case id.caps&capChown != 0:
					power = "taking it over with CAP_CHOWN"
				default:
					continue
				}
				if reach(ns, i, id, opened) == can {
					opened[i], why[i], changed = true, power, true
					break
				}
			}
		}
	}
	return opened, why
}

// gains: could the agent get want (2 write, 4 read) on the path's target, under any identity it can assume and any
// mode it can change (change), or as it is, changing nothing (!change)? For a write, creating, renaming or removing an entry on the way counts too, unless onlyOpen
// (a socket, whose path anyone can rebind is no way to its server). It returns how, when it can.
func gains(a agentID, ns []inode, want uint32, onlyOpen, change bool) (verdict, string) {
	ids := []identity{{uid: a.uid, gids: map[uint32]bool{}, caps: a.eff}}
	for _, g := range a.gids {
		ids[0].gids[g] = true
	}
	opened, why := make([]bool, len(ns)), make([]string, len(ns))
	complete := true
	if change {
		ids, complete = identities(a, ns)
		opened, why = opens(ns, ids, a)
	}
	result, how := cannot, ""
	last := len(ns) - 1
	for _, id := range ids {
		v, at := goal(ns, id, opened, want, onlyOpen)
		if v == can {
			return can, describe(a, ns, id, opened, why, at, want)
		}
		if v == cantTell {
			via := "a change of mode"
			if held := a.caps & (capSetuid | capSetgid | capChown | capFowner | capDacOverride | capDacReadSearch); held != 0 {
				via = capList(held)
			}
			result, how = cantTell, "the agent might reach "+ns[last].path+" by "+via+", past a directory the probe can't see into"
		}
	}
	if !complete {
		return cantTell, "the identity search exceeded its relevant-group bound; access through unexplored identities is unproven"
	}
	return result, how
}

// goal is one identity's answer, and the inode whose access gives it: the target, or the directory whose entry it
// can create or replace.
func goal(ns []inode, id identity, opened []bool, want uint32, onlyOpen bool) (verdict, int) {
	last := len(ns) - 1
	t := ns[last]
	result := cannot
	if !(want == 2 && t.link) {
		r := reach(ns, last, id, opened)
		switch {
		case r == can && t.seen && t.exists && !(want == 2 && t.ro) && allows(&t, id, want, opened[last]):
			return can, last
		case r == cantTell || r == can && !t.seen:
			result = cantTell
		}
	}
	if want != 2 || onlyOpen {
		return result, -1
	}
	for j := last - 1; j >= 0; j-- {
		p, c := ns[j], ns[j+1]
		if !p.seen || !p.exists || !p.dir || p.ro || p.noEntries || !allows(&p, id, 3, opened[j]) {
			continue
		}
		r := reach(ns, j, id, opened)
		if r == cannot {
			continue
		}
		child := can
		switch {
		case !c.seen:
			child = cantTell
		case !c.exists:
		case c.mountPoint:
			child = cannot
		case p.mode&syscall.S_ISVTX != 0 && !opened[j] && id.uid != p.uid && id.uid != c.uid &&
			id.caps&capFowner == 0 && !(id.caps&capChown != 0 && !c.ro && !c.procfs):
			child = cannot
		}
		switch {
		case r == can && child == can:
			return can, j
		case child != cannot:
			result = cantTell
		}
	}
	return result, -1
}

// describe says how an identity gets the access: the change of uid or groups, the capabilities it raises, and the
// modes it changes on the way.
func describe(a agentID, ns []inode, id identity, opened []bool, why []string, at int, want uint32) string {
	var parts []string
	if id.uid != a.uid {
		parts = append(parts, fmt.Sprintf("as uid %d (CAP_SETUID)", id.uid))
	}
	own := map[uint32]bool{}
	for _, g := range a.gids {
		own[g] = true
	}
	var gs []string
	differ := len(id.gids) != len(own)
	for g := range id.gids {
		gs = append(gs, fmt.Sprint(g))
		differ = differ || !own[g]
	}
	if differ {
		sort.Strings(gs)
		parts = append(parts, "in groups "+strings.Join(gs, ", ")+" (CAP_SETGID)")
	}
	if raise := a.caps &^ a.eff & (capDacOverride | capDacReadSearch); raise != 0 {
		parts = append(parts, "raising "+capList(raise))
	} else if dac := id.caps & (capDacOverride | capDacReadSearch); dac != 0 {
		parts = append(parts, "with "+capList(dac))
	}
	for i := 0; i <= at && i < len(ns); i++ {
		need := uint32(1) // search, on the way
		switch {
		case i == at && at == len(ns)-1:
			need = want
		case i == at:
			need = 3 // write and search the directory whose entry changes
		}
		if opened[i] && !allows(&ns[i], id, need, false) {
			parts = append(parts, "changing the mode of "+ns[i].path+", "+why[i])
		}
	}
	if len(parts) == 0 {
		return "by a change of identity or mode"
	}
	return strings.Join(parts, ", ")
}

// modelGain is TWN-4's question for a path the kernel refused the agent as it is: could a change get it want? A
// path whose modes alone already let the agent in, though the kernel refused, is decided by an ACL or a security
// module, which the model doesn't follow: it can't tell. So too where an ACL lies on the way and the agent has any
// power to change identity or mode.
func modelGain(p string, follow bool, want uint32, onlyOpen bool) (verdict, string, error) {
	ns, err := pathNodes(p, follow)
	if err != nil {
		return cannot, "", err
	}
	a := theAgent()
	if v, _ := gains(a, ns, want, onlyOpen, false); v == can {
		return cantTell, "its modes let the agent in, yet the kernel refused it: an ACL or a security module decides " + p, nil
	}
	for _, n := range ns {
		if n.acl && (a.caps&(capSetuid|capSetgid|capChown|capFowner|capDacOverride|capDacReadSearch) != 0 || n.uid == a.uid) {
			return cantTell, "an ACL on " + n.path + " decides, which the model doesn't follow", nil
		}
	}
	v, how := gains(a, ns, want, onlyOpen, true)
	return v, how, nil
}
