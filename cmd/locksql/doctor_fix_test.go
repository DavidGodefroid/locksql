//go:build unix

package main

import (
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"testing"
)

// ownedInfo is a fake file with an owner and group, for the access checks.
type ownedInfo struct {
	fakeInfo
	uid, gid int
}

func TestParseACLAndPerms(t *testing.T) {
	// getfacl: user::rwx user:nobody:--x group::r-x mask::r-x other::---
	raw, _ := hex.DecodeString("0200000001000700ffffffff02000100feff000004000500ffffffff10000500ffffffff20000000ffffffff")
	acl := parseACL(raw)
	if len(acl) != 5 || acl[1].tag != aclUser || acl[1].id != 65534 || acl[1].perm != 1 {
		t.Fatalf("parseACL = %+v", acl)
	}
	nobody := svcAccount{name: "nobody", uid: 65534, gids: []int{65534}}
	if got := permsFor(0o750, 1000, 1000, acl, nobody); got != 1 {
		t.Errorf("ACL user entry: %o, want 1", got)
	}
	if got := permsFor(0o750, 1000, 1000, nil, nobody); got != 0 {
		t.Errorf("no ACL, other: %o, want 0", got)
	}
	member := svcAccount{uid: 900, gids: []int{1000}}
	if got := permsFor(0o750, 1000, 1000, nil, member); got != 5 {
		t.Errorf("group member: %o, want 5", got)
	}
	if got := permsFor(0o700, 900, 1000, acl, member); got != 7 {
		t.Errorf("owner: %o, want 7", got)
	}
	// The mask limits a named user entry.
	masked := []aclEntry{{aclUserObj, 7, 0}, {aclUser, 7, 900}, {aclGroupObj, 0, 0}, {aclMask, 1, 0}, {aclOther, 0, 0}}
	if got := permsFor(0o710, 1000, 1000, masked, svcAccount{uid: 900}); got != 1 {
		t.Errorf("masked entry: %o, want 1", got)
	}
	if parseACL([]byte{1, 0, 0, 0}) != nil || parseACL(nil) != nil {
		t.Error("bad ACL parsed")
	}
}

// accessDoctor fakes a project at /home/alice/proj whose home directory
// the console account (uid 900) cannot enter.
func accessDoctor(files map[string]ownedInfo, ran *[][]string) doctorEnv {
	d := fakeDoctor(separatedSys())
	d.stat = func(p string) (os.FileInfo, error) {
		if fi, ok := files[p]; ok {
			return fi, nil
		}
		return nil, fs.ErrNotExist
	}
	d.ownerOf = func(fi os.FileInfo) (int, int, bool) {
		o := fi.(ownedInfo)
		return o.uid, o.gid, true
	}
	d.lookPath = func(n string) (string, error) { return "/usr/bin/" + n, nil }
	d.run = func(name string, args ...string) ([]byte, error) {
		*ran = append(*ran, append([]string{name}, args...))
		return nil, nil
	}
	return d
}

func TestProjectChecks(t *testing.T) {
	dir := func(mode fs.FileMode, uid int) ownedInfo {
		return ownedInfo{fakeInfo{"d", fs.ModeDir | mode}, uid, uid}
	}
	files := map[string]ownedInfo{
		"/":                                     dir(0o755, 0),
		"/home":                                 dir(0o755, 0),
		"/home/alice":                           dir(0o750, 1000),
		"/home/alice/proj":                      dir(0o755, 1000),
		"/home/alice/proj/.locksql":             dir(0o755, 1000),
		"/home/alice/proj/.locksql/config.toml": {fakeInfo{"config.toml", 0o600}, 1000, 1000},
	}
	var ran [][]string
	d := accessDoctor(files, &ran)
	svc := svcAccount{name: "locksql", uid: 900, gids: []int{900}}
	checks := projectChecks(d, "/home/alice/proj", svc, 1000)
	byTitle := map[string]check{}
	for _, c := range checks {
		byTitle[c.title] = c
	}
	acc := byTitle["project access"]
	if acc.state != checkFail || !strings.Contains(acc.detail, "/home/alice") || acc.repair == nil || acc.repair.apply == nil || acc.repair.root != "" {
		t.Fatalf("project access: %+v", acc)
	}
	if err := acc.repair.apply(); err != nil {
		t.Fatal(err)
	}
	if len(ran) != 1 || strings.Join(ran[0], " ") != "setfacl -m u:locksql:x /home/alice" {
		t.Errorf("setfacl runs %q", ran)
	}
	dot := byTitle["project .locksql"]
	if dot.state != checkFail || dot.repair == nil || dot.repair.root != giveDirScript("/home/alice/proj/.locksql", 900) ||
		!strings.Contains(dot.fix, "sudo chown 900 '/home/alice/proj/.locksql'") {
		t.Errorf("project .locksql: %+v", dot)
	}
	cfg := byTitle["project config.toml"]
	if cfg.state != checkFail || cfg.repair == nil || cfg.repair.apply == nil {
		t.Errorf("project config.toml: %+v", cfg)
	}

	// Once repaired, every check passes.
	files["/home/alice"] = dir(0o755, 1000)
	files["/home/alice/proj/.locksql"] = dir(0o755, 900)
	files["/home/alice/proj/.locksql/config.toml"] = ownedInfo{fakeInfo{"config.toml", 0o644}, 1000, 1000}
	for _, c := range projectChecks(d, "/home/alice/proj", svc, 1000) {
		if c.state != checkOK {
			t.Errorf("after repair: %+v", c)
		}
	}

	// Without setfacl there is nothing to run, only the steps.
	d.lookPath = func(string) (string, error) { return "", exec.ErrNotFound }
	files["/home/alice"] = dir(0o750, 1000)
	for _, c := range projectChecks(d, "/home/alice/proj", svc, 1000) {
		if c.title == "project access" && (c.repair != nil || !strings.Contains(c.fix, "setfacl -m u:locksql:x '/home/alice'")) {
			t.Errorf("without setfacl: %+v", c)
		}
	}
}

func TestSocketDirRepair(t *testing.T) {
	d := fakeDoctor(separatedSys())
	stat := d.stat
	d.stat = func(p string) (os.FileInfo, error) {
		if p == "/run/locksql" {
			return nil, fs.ErrNotExist
		}
		return stat(p)
	}
	me := &user.User{Uid: "1000", Username: "agent"}
	var sock check
	for _, c := range separationChecks(d, separatedSys(), me, 1000) {
		if c.title == "socket directory" {
			sock = c
		}
	}
	if sock.state != checkFail || sock.repair == nil {
		t.Fatalf("socket directory: %+v", sock)
	}
	for _, want := range []string{"mkdir -p '/run/locksql'", "chown 'locksql':'locksql-clients' '/run/locksql'", "chmod 2710 '/run/locksql'", "/etc/tmpfiles.d/locksql.conf"} {
		if !strings.Contains(sock.repair.root, want) {
			t.Errorf("repair lacks %q:\n%s", want, sock.repair.root)
		}
	}
}

// doctor --fix wires the agents in this account, runs the root repairs
// in one script and checks again.
func TestDoctorFix(t *testing.T) {
	e, out, _ := onboardEnv(t, "codex")
	d := fakeDoctor(separatedSys())
	member := false // the agent's account is not in the group yet
	d.inGroup = func(uid int, _ string) bool { return member && uid == 1000 }
	d.agents = e.agentEnv
	e.doc = &d
	var scripts []string
	e.root = func(s string) error {
		scripts = append(scripts, s)
		member = true
		return nil
	}
	e.tty = false
	if code := runEnv(e, []string{"doctor", "--fix"}); code != exitUsage || len(scripts) != 0 {
		t.Fatalf("no terminal, no --yes: code %d, scripts %q\n%s", code, scripts, out)
	}
	out.Reset()
	if code := runEnv(e, []string{"doctor", "--fix", "--yes"}); code != exitOK {
		t.Fatalf("code %d\n%s", code, out)
	}
	if len(scripts) != 1 || !strings.Contains(scripts[0], "usermod -aG 'locksql-clients' 'agent'") {
		t.Fatalf("root scripts %q", scripts)
	}
	for _, want := range []string{"repaired: wire codex for this account", "repaired: add agent to locksql-clients", "After the repairs:", "wired: codex"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}

	// Again: nothing left to repair.
	out.Reset()
	if code := runEnv(e, []string{"doctor", "--fix", "--yes"}); code != exitOK || len(scripts) != 1 {
		t.Fatalf("second run: code %d, scripts %d\n%s", code, len(scripts), out)
	}
	if !strings.Contains(out.String(), "Nothing doctor --fix can repair") {
		t.Errorf("second run:\n%s", out)
	}

	// A failed root script is reported.
	member = false
	e.root = func(string) error { return errors.New("sudo: a password is required") }
	out.Reset()
	if code := runEnv(e, []string{"doctor", "--fix", "--yes"}); code != exitFail || !strings.Contains(out.String(), "a password is required") {
		t.Fatalf("failed sudo: code %d\n%s", code, out)
	}
	if code := runEnv(e, []string{"doctor", "--yes"}); code != exitUsage {
		t.Errorf("--yes without --fix: code %d", code)
	}

}

// A .locksql that is a symbolic link gets no repair: a chown by root would
// change whatever it names.
func TestProjectChecksSymlinkedDotDir(t *testing.T) {
	dir := func(mode fs.FileMode, uid int) ownedInfo {
		return ownedInfo{fakeInfo{"d", fs.ModeDir | mode}, uid, uid}
	}
	files := map[string]ownedInfo{
		"/":                         dir(0o755, 0),
		"/home":                     dir(0o755, 0),
		"/home/alice":               dir(0o755, 1000),
		"/home/alice/proj":          dir(0o755, 1000),
		"/home/alice/proj/.locksql": dir(0o755, 1000),
	}
	var ran [][]string
	d := accessDoctor(files, &ran)
	d.lstat = func(p string) (os.FileInfo, error) {
		if p == "/home/alice/proj/.locksql" {
			return ownedInfo{fakeInfo{".locksql", fs.ModeSymlink | 0o777}, 1000, 1000}, nil
		}
		return d.stat(p)
	}
	svc := svcAccount{name: "locksql", uid: 900, gids: []int{900}}
	for _, c := range projectChecks(d, "/home/alice/proj", svc, 1000) {
		if c.title != "project .locksql" {
			continue
		}
		if c.state != checkFail || c.repair != nil || !strings.Contains(c.detail, "symbolic link") {
			t.Errorf("symlinked .locksql: %+v", c)
		}
		return
	}
	t.Error("no project .locksql check")
}

// The root scripts change the directory they entered, never what a
// symbolic link swapped in at its path names.
func TestInDirScript(t *testing.T) {
	sh := func(script string) error {
		return exec.Command("sh", "-c", "set -eu\n"+script).Run()
	}
	mode := func(p string) fs.FileMode {
		fi, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		return fi.Mode().Perm()
	}
	root := t.TempDir()
	dot := root + "/.locksql"
	if err := os.Mkdir(dot, 0o775); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dot, 0o775); err != nil {
		t.Fatal(err)
	}
	if err := sh(giveDirScript(dot, os.Getuid())); err != nil {
		t.Fatal(err)
	}
	if got := mode(dot); got != 0o755 {
		t.Errorf("mode %04o, want 0755", got)
	}
	cfg := dot + "/config.toml"
	if err := os.WriteFile(cfg, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := sh(inDirScript(dot, "test ! -L 'config.toml' && chmod 0644 'config.toml'")); err != nil {
		t.Fatal(err)
	}
	if got := mode(cfg); got != 0o644 {
		t.Errorf("config.toml %04o, want 0644", got)
	}

	// .locksql swapped for a link to another directory.
	other := t.TempDir()
	if err := os.Chmod(other, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(dot); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, dot); err != nil {
		t.Fatal(err)
	}
	if err := sh(giveDirScript(dot, os.Getuid())); err == nil {
		t.Error("script ran through a symbolic link")
	}
	if got := mode(other); got != 0o700 {
		t.Errorf("link target changed to %04o", got)
	}

	// A file swapped for a link.
	if err := os.Remove(dot); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dot, 0o755); err != nil {
		t.Fatal(err)
	}
	secret := other + "/secret"
	if err := os.WriteFile(secret, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, dot+"/pii.toml"); err != nil {
		t.Fatal(err)
	}
	if err := sh(inDirScript(dot, "test ! -L 'pii.toml' && chmod 0644 'pii.toml'")); err == nil {
		t.Error("chmod ran through a symbolic link")
	}
	if got := mode(secret); got != 0o600 {
		t.Errorf("link target changed to %04o", got)
	}
}
