package main

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// repair is a change `locksql doctor --fix` can make
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
}

// doctorForEnv names the account, "UID:GID", whose project directory
// doctor checks: the launcher passes yours (`id -u`:`id -g`), since it
// runs doctor in the image as another account (the image's agent account,
// or root for the one repair that needs it). Unset, it is the account
// doctor runs as.
const doctorForEnv = "LOCKSQL_DOCTOR_FOR"

// projectOwner is the account the project's .locksql must belong to: the
// human who runs `lox up`.
type projectOwner struct{ uid, gid int }

// ownerFor is the account the project's .locksql must belong to:
// doctorForEnv when set, else me.
func ownerFor(d doctorEnv, me *user.User) (projectOwner, error) {
	if d.getenv != nil {
		if v := d.getenv(doctorForEnv); v != "" {
			u, g, ok := strings.Cut(v, ":")
			uid, err1 := strconv.Atoi(u)
			gid, err2 := strconv.Atoi(g)
			if !ok || err1 != nil || err2 != nil || uid < 0 || gid < 0 {
				return projectOwner{}, errors.New(doctorForEnv + " is not UID:GID")
			}
			return projectOwner{uid, gid}, nil
		}
	}
	uid, err := strconv.Atoi(me.Uid)
	if err != nil {
		return projectOwner{}, fmt.Errorf("uid %q is not a number", me.Uid)
	}
	gid, err := strconv.Atoi(me.Gid)
	if err != nil {
		gid = -1
	}
	return projectOwner{uid, gid}, nil
}

// projectChecks are what `lox up` needs of the project's .locksql at root
// (lockhub docs/lox-up.md): it reads it as you, following no link, and
// copies it to the console, which never reads the project itself. So
// .locksql is a directory, not a link, and each of its entries a directory
// or a regular file that o owns, can read, and no one else can write. o is
// that account, cur the account doctor runs as, svcUID the console
// account's uid (-1: none).
//
// Entries the console account owns are the leftover of doctor --fix up to
// v0.13.0, which gave .locksql to it: only root can give them back, which
// the launcher's doctor --fix does in a root container of its own (the
// repair is offered when cur is root). Modes are repaired by o itself.
func projectChecks(d doctorEnv, root string, o projectOwner, cur, svcUID int) []check {
	if d.lstat == nil || d.readDir == nil {
		return nil
	}
	const title = "project .locksql"
	dir := filepath.Join(root, ".locksql")
	top, err := d.lstat(dir)
	if err != nil {
		return nil
	}
	if !top.IsDir() {
		return []check{{state: checkFail, title: title, detail: dir + " is not a directory (a symbolic link?): lox up copies only a directory of yours",
			fix: "replace it with a directory holding its files"}}
	}
	var links, console, foreign, modes []string
	type change struct {
		path string
		mode fs.FileMode
	}
	var changes []change
	others := map[int]bool{}
	var walk func(path string, fi os.FileInfo)
	walk = func(path string, fi os.FileInfo) {
		if !fi.IsDir() && !fi.Mode().IsRegular() {
			links = append(links, path)
			return
		}
		if uid, _, ok := d.ownerOf(fi); ok {
			perm := fi.Mode().Perm()
			want := perm &^ 0o022
			if fi.IsDir() {
				want |= 0o500
			} else {
				want |= 0o400
			}
			switch {
			case uid == svcUID:
				console = append(console, path)
			case uid != o.uid:
				foreign = append(foreign, path)
				others[uid] = true
			case want != perm:
				modes = append(modes, fmt.Sprintf("%s %04o", path, perm))
				changes = append(changes, change{path, fi.Mode()&(fs.ModeSetgid|fs.ModeSticky) | want})
			}
		}
		if !fi.IsDir() {
			return
		}
		ents, err := d.readDir(path)
		if err != nil {
			return // not readable from this account: lox up reads it as o
		}
		for _, e := range ents {
			p := filepath.Join(path, e.Name())
			if cfi, err := d.lstat(p); err == nil {
				walk(p, cfi)
			}
		}
	}
	walk(dir, top)

	var out []check
	if len(links) > 0 {
		out = append(out, check{state: checkFail, title: title, detail: listPaths(links) + ": not a regular file or a directory (a symbolic link?): lox up copies none",
			fix: "replace each with a regular file or a directory"})
	}
	chown := fmt.Sprintf("sudo chown -R %d:%d %s", o.uid, o.gid, shellQuote(dir))
	if o.gid < 0 {
		chown = fmt.Sprintf("sudo chown -R %d %s", o.uid, shellQuote(dir))
	}
	if len(console) > 0 {
		c := check{state: checkFail, title: title + " owner",
			detail: fmt.Sprintf("%s: owned by the console account (uid %d), not by you (uid %d): lox up copies only your own files (doctor --fix up to v0.13.0 gave them to the console account)", listPaths(console), svcUID, o.uid),
			fix:    "locksql doctor --fix (it gives them back to you as root), or " + chown}
		if cur == 0 && o.uid > 0 {
			c.repair = &repair{what: fmt.Sprintf("give back to uid %d what the console account owns in %s", o.uid, dir),
				apply: func() error { return giveBack(dir, svcUID, o.uid, o.gid) }}
		}
		out = append(out, c)
	}
	if len(foreign) > 0 {
		var uids []string
		for _, u := range slices.Sorted(maps.Keys(others)) {
			uids = append(uids, strconv.Itoa(u))
		}
		out = append(out, check{state: checkFail, title: title + " owner",
			detail: fmt.Sprintf("%s: owned by uid %s, not by you (uid %d): lox up copies only your own files", listPaths(foreign), strings.Join(uids, ", "), o.uid),
			fix:    "check that they are yours, then " + chown})
	}
	if len(modes) > 0 {
		c := check{state: checkFail, title: title + " mode",
			detail: listPaths(modes) + ": writable by group or others, or not readable by you: lox up copies only files no one else can write",
			fix:    "chmod -R go-w,u+rX " + shellQuote(dir)}
		if cur == o.uid {
			c.repair = &repair{what: "make " + dir + " writable by you only, and readable by you (chmod go-w,u+rX)", apply: func() error {
				var errs []error
				for _, ch := range changes {
					errs = append(errs, os.Chmod(ch.path, ch.mode))
				}
				return errors.Join(errs...)
			}}
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		out = append(out, check{state: checkOK, title: title, detail: fmt.Sprintf("%s: yours (uid %d), writable by you only, as lox up copies it", dir, o.uid)})
	}
	return out
}

// listPaths shows the first paths of a list, and how many more there are.
func listPaths(p []string) string {
	const shown = 3
	if len(p) <= shown {
		return strings.Join(p, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(p[:shown], ", "), len(p)-shown)
}
