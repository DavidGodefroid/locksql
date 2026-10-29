package main

import (
	"encoding/binary"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/pii"
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
// .locksql directory and its pii directory, where it writes the PII rule
// sets. me is this account's uid.
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

	// 2. The .locksql directory, and pii in it: the console writes the PII
	// rule sets there.
	dir := filepath.Join(root, ".locksql")
	sets := filepath.Join(dir, pii.SetsDir)
	ownDir := func(title, path string) bool {
		if d.lstat != nil {
			if fi, err := d.lstat(path); err == nil && fi.Mode()&fs.ModeSymlink != 0 {
				add(checkFail, title, path+" is a symbolic link: the console account must own a directory of the project itself",
					"replace it with a directory holding "+filepath.Base(path)+"'s files", nil)
				return false
			}
		}
		if fi, err := d.stat(path); err == nil {
			uid, _, ok := d.ownerOf(fi)
			perm := fi.Mode().Perm()
			switch {
			case !ok:
			case uid != svc.uid || perm&0o022 != 0 || perm&0o005 != 0o005:
				// The uid, not the name: in Docker the console account exists
				// only in the image.
				add(checkFail, title, fmt.Sprintf("%s: %04o, owner uid %d; the console account (%s, uid %d) must own it (it writes the PII rule sets there) and every account read it", path, perm, uid, svc.name, svc.uid),
					fmt.Sprintf("sudo chown %d %s && sudo chmod 0755 %s", svc.uid, shellQuote(path), shellQuote(path)),
					&repair{what: "give " + path + " to " + svc.name + ", mode 0755", root: giveDirScript(path, svc.uid)})
			default:
				add(checkOK, title, fmt.Sprintf("%s %04o, owned by %s", path, perm, svc.name), "", nil)
			}
		}
		return true
	}
	if !ownDir("project .locksql", dir) {
		return out
	}
	setsOK := ownDir("project .locksql/pii", sets)

	// 3. The files both accounts read: the config, a legacy pii.toml, and
	// the rule set of every project profile.
	readable := func(title, in, name string) {
		path := filepath.Join(in, name)
		p, uid, ok := perms(path)
		if !ok || p&4 != 0 {
			return
		}
		r := &repair{what: "make " + path + " readable (0644)"}
		if uid == me {
			r.apply = func() error { return os.Chmod(path, 0o644) }
		} else {
			r.root = inDirScript(in, readableScript(name))
		}
		add(checkFail, title, path+" is not readable by "+svc.name, "chmod 0644 "+shellQuote(path), r)
	}
	for _, name := range []string{"config.toml", pii.LegacyFile} {
		readable("project "+name, dir, name)
	}
	if setsOK {
		for _, set := range projectRuleSets(d, root) {
			readable("project "+pii.SetsDir+"/"+set+".toml", sets, set+".toml")
		}
	}
	return out
}

// projectRuleSets are the PII rule sets the project's profiles use, and
// the default set a legacy pii.toml became; none when the config cannot be
// read (the config checks report it).
func projectRuleSets(d doctorEnv, root string) []string {
	if d.readFile == nil {
		return nil
	}
	path := filepath.Join(root, ".locksql", "config.toml")
	data, err := d.readFile(path)
	if err != nil {
		return nil
	}
	profiles, err := config.ParseProfiles(data, path, root)
	if err != nil {
		return nil
	}
	sets := []string{pii.DefaultSet}
	for _, p := range profiles {
		sets = append(sets, config.RuleSetOf(p))
	}
	slices.Sort(sets)
	return slices.Compact(sets)
}

// giveDirScript is the root script that gives dir to uid, mode 0755.
func giveDirScript(dir string, uid int) string {
	return inDirScript(dir, fmt.Sprintf("chown %d . && chmod 0755 .", uid))
}

// readableScript is the root script that makes name, in the current
// directory, mode 0644. chmod follows a symbolic link, and a hard link is
// the same file as its other names: on either it would make readable a file
// the agent's account linked there, /etc/shadow say. The script refuses
// both, with a message, and changes nothing. find -links is POSIX, where
// stat -c %h is GNU only.
func readableScript(name string) string {
	q := shellQuote(name)
	return fmt.Sprintf("if test -L %[1]s || test \"$(find %[1]s -prune -links 1)\" != %[1]s; then echo %[2]s >&2; false; else chmod 0644 %[1]s; fi",
		q, shellQuote("locksql: "+name+" is a symbolic or hard link: not changed, replace it with a plain file"))
}

// inDirScript runs cmds as root inside dir, in a subshell. The agent's
// account may own dir and the directories above it, and swap any of them
// for a symbolic link between the check and the script: a chown or chmod
// by path would then change whatever the link names. The script enters dir
// once and checks that it is the directory at that path, symbolic links
// resolved, before it changes ".", which no rename can redirect.
func inDirScript(dir, cmds string) string {
	real := dir
	if parent, err := filepath.EvalSymlinks(filepath.Dir(dir)); err == nil {
		real = filepath.Join(parent, filepath.Base(dir))
	}
	return fmt.Sprintf("(cd -P -- %s && test \"$(pwd -P)\" = %s && %s)", shellQuote(dir), shellQuote(real), cmds)
}
