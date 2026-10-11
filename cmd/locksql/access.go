package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// repair is a change `locksql doctor --fix` (and `locksql setup`) can make
// to fix a check: small, idempotent and never a loosening beyond what the
// separated setup itself needs.
type repair struct {
	// what says what it changes, for the report.
	what string
	// root are shell commands run as root (sudo), or "".
	root string
	// apply is a change made by this account, or nil.
	apply func() error
}

// svcAccount is the console account, as file permissions see it.
type svcAccount struct {
	name string
	uid  int
	gids []int
}

// ACL entry tags (linux/posix_acl_xattr.h).
const (
	aclUserObj  = 0x01
	aclUser     = 0x02
	aclGroupObj = 0x04
	aclGroup    = 0x08
	aclMask     = 0x10
	aclOther    = 0x20
)

type aclEntry struct {
	tag, perm uint16
	id        uint32
}

// parseACL decodes a system.posix_acl_access value; nil when there is none
// or it cannot be read.
func parseACL(b []byte) []aclEntry {
	if len(b) < 4 || binary.LittleEndian.Uint32(b) != 2 || (len(b)-4)%8 != 0 {
		return nil
	}
	var out []aclEntry
	for p := b[4:]; len(p) >= 8; p = p[8:] {
		out = append(out, aclEntry{binary.LittleEndian.Uint16(p), binary.LittleEndian.Uint16(p[2:]), binary.LittleEndian.Uint32(p[4:])})
	}
	return out
}

// permsFor is the rwx bits (4, 2, 1) account a has on a file of mode perm,
// owner uid and group gid, under its POSIX ACL entries (nil: none).
func permsFor(perm os.FileMode, uid, gid int, acl []aclEntry, a svcAccount) uint16 {
	mode := uint16(perm.Perm())
	if a.uid == uid {
		return mode >> 6 & 7
	}
	if len(acl) == 0 {
		if slices.Contains(a.gids, gid) {
			return mode >> 3 & 7
		}
		return mode & 7
	}
	mask := uint16(7)
	for _, e := range acl {
		if e.tag == aclMask {
			mask = e.perm
		}
	}
	for _, e := range acl {
		if e.tag == aclUser && int(e.id) == a.uid {
			return e.perm & mask
		}
	}
	var groups uint16
	matched := false
	for _, e := range acl {
		switch {
		case e.tag == aclGroupObj && slices.Contains(a.gids, gid),
			e.tag == aclGroup && slices.Contains(a.gids, int(e.id)):
			groups |= e.perm & mask
			matched = true
		}
	}
	if matched {
		return groups
	}
	for _, e := range acl {
		if e.tag == aclOther {
			return e.perm
		}
	}
	return 0
}

// projectChecks are what the console account needs to serve the project
// at root: enter every directory down to it, read its config and own its
// .locksql directory, where it writes pii.toml. me is this account's uid.
func projectChecks(d doctorEnv, root string, svc svcAccount, me int) []check {
	var out []check
	add := func(state, title, detail, fix string, r *repair) {
		out = append(out, check{state: state, title: title, detail: detail, fix: fix, repair: r})
	}
	perms := func(path string) (uint16, int, bool) {
		fi, err := d.stat(path)
		if err != nil {
			return 0, 0, false
		}
		uid, gid, ok := d.ownerOf(fi)
		if !ok {
			return 0, 0, false
		}
		var acl []aclEntry
		if d.acl != nil {
			acl = parseACL(d.acl(path))
		}
		return permsFor(fi.Mode(), uid, gid, acl, svc), uid, true
	}

	// 1. Every directory down to the project, and the project itself.
	var blocked []string
	var mine, others []string
	for dir := root; ; dir = filepath.Dir(dir) {
		want := uint16(1) // search
		if dir == root {
			want = 5 // read and search
		}
		if p, uid, ok := perms(dir); ok && p&want != want {
			blocked = append(blocked, dir)
			if uid == me {
				mine = append(mine, dir)
			} else {
				others = append(others, dir)
			}
		}
		if filepath.Dir(dir) == dir {
			break
		}
	}
	if len(blocked) == 0 {
		add(checkOK, "project access", svc.name+" can enter "+root, "", nil)
	} else {
		acl := func(dir string) string {
			p := "x"
			if dir == root {
				p = "rx"
			}
			if d.goos == "darwin" {
				search := "search"
				if dir == root {
					search = "list,search"
				}
				return fmt.Sprintf("chmod +a %s %s", shellQuote(svc.name+" allow "+search), shellQuote(dir))
			}
			return fmt.Sprintf("setfacl -m u:%s:%s %s", svc.name, p, shellQuote(dir))
		}
		var cmds []string
		for _, dir := range blocked {
			cmds = append(cmds, acl(dir))
		}
		var r *repair
		// On macOS the ACL is not read back: the check would stay failed.
		if d.goos == "linux" && d.lookPath != nil {
			if _, err := d.lookPath("setfacl"); err == nil {
				r = &repair{what: "let " + svc.name + " enter " + strings.Join(blocked, ", ") + " (an ACL entry for that account only)"}
				var rootCmds []string
				for _, dir := range others {
					rootCmds = append(rootCmds, acl(dir))
				}
				r.root = strings.Join(rootCmds, "\n")
				if len(mine) > 0 {
					dirs := mine
					r.apply = func() error {
						for _, dir := range dirs {
							p := "x"
							if dir == root {
								p = "rx"
							}
							if out, err := d.run("setfacl", "-m", "u:"+svc.name+":"+p, dir); err != nil {
								return fmt.Errorf("setfacl %s: %v: %s", dir, err, strings.TrimSpace(string(out)))
							}
						}
						return nil
					}
				}
			}
		}
		add(checkFail, "project access", svc.name+" cannot enter "+strings.Join(blocked, ", ")+": the console cannot read the project's config",
			strings.Join(cmds, "; ")+" (or move the project where every account may enter)", r)
	}

	// 2. The .locksql directory: the console writes pii.toml there.
	dir := filepath.Join(root, ".locksql")
	if fi, err := d.stat(dir); err == nil {
		uid, _, ok := d.ownerOf(fi)
		perm := fi.Mode().Perm()
		fixCmd := fmt.Sprintf("chown %s %s && chmod 0755 %s", svc.name, shellQuote(dir), shellQuote(dir))
		switch {
		case !ok:
		case uid != svc.uid || perm&0o022 != 0 || perm&0o005 != 0o005:
			add(checkFail, "project .locksql", fmt.Sprintf("%s: %04o, owner uid %d; the console account must own it (it writes pii.toml there) and every account read it", dir, perm, uid),
				fmt.Sprintf("sudo chown %s %s && sudo chmod 0755 %s", svc.name, shellQuote(dir), shellQuote(dir)),
				&repair{what: "give " + dir + " to " + svc.name + ", mode 0755", root: fixCmd})
		default:
			add(checkOK, "project .locksql", fmt.Sprintf("%s %04o, owned by %s", dir, perm, svc.name), "", nil)
		}
	}

	// 3. The files both accounts read.
	for _, name := range []string{"config.toml", "pii.toml"} {
		path := filepath.Join(dir, name)
		p, uid, ok := perms(path)
		if !ok || p&4 != 0 {
			continue
		}
		r := &repair{what: "make " + path + " readable (0644)"}
		if uid == me {
			r.apply = func() error { return os.Chmod(path, 0o644) }
		} else {
			r.root = "chmod 0644 " + shellQuote(path)
		}
		add(checkFail, "project "+name, path+" is not readable by "+svc.name, "chmod 0644 "+shellQuote(path), r)
	}
	return out
}
