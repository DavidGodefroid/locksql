//go:build unix

package main

import (
	"bytes"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// loxUpProject is a project whose .locksql is as lox up copies it: yours,
// writable by you only. It returns the project and its .locksql.
func loxUpProject(t *testing.T) (string, string) {
	t.Helper()
	proj := t.TempDir()
	dot := filepath.Join(proj, ".locksql")
	for _, d := range []string{dot, filepath.Join(dot, "pii")} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, mode := range map[string]fs.FileMode{"config.toml": 0o644, "pii/shop.toml": 0o600} {
		p := filepath.Join(dot, name)
		if err := os.WriteFile(p, []byte("# x\n"), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
	}
	return proj, dot
}

// fsDoctor reads the real file system for the project checks.
func fsDoctor() doctorEnv {
	d := fakeDoctor(separatedSys())
	d.lstat, d.readDir, d.ownerOf = os.Lstat, os.ReadDir, fileOwner
	return d
}

func titles(checks []check) map[string]check {
	out := map[string]check{}
	for _, c := range checks {
		out[c.title] = c
	}
	return out
}

func modeOf(t *testing.T, p string) fs.FileMode {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

// A fresh .locksql, as profile add writes it, passes; the umask's group
// write fails, and doctor --fix repairs it as you.
func TestProjectChecksLoxUp(t *testing.T) {
	proj, dot := loxUpProject(t)
	d := fsDoctor()
	me := projectOwner{os.Getuid(), os.Getgid()}
	got := projectChecks(d, proj, me, me.uid, 10001)
	if len(got) != 1 || got[0].title != "project .locksql" || got[0].state != checkOK {
		t.Fatalf("fresh .locksql: %+v", got)
	}

	for p, m := range map[string]fs.FileMode{dot: 0o775, filepath.Join(dot, "config.toml"): 0o664, filepath.Join(dot, "pii/shop.toml"): 0o200} {
		if err := os.Chmod(p, m); err != nil {
			t.Fatal(err)
		}
	}
	c := titles(projectChecks(d, proj, me, me.uid, 10001))["project .locksql mode"]
	if c.state != checkFail || c.repair == nil || c.repair.apply == nil || c.repair.root != "" || !strings.Contains(c.fix, "go-w") {
		t.Fatalf("group-writable .locksql: %+v", c)
	}
	// From another account (the image's agent account, for you): reported,
	// not repaired.
	if o := titles(projectChecks(d, proj, me, 10002, 10001))["project .locksql mode"]; o.state != checkFail || o.repair != nil {
		t.Errorf("from another account: %+v", o)
	}
	if err := c.repair.apply(); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]fs.FileMode{dot: 0o755, filepath.Join(dot, "config.toml"): 0o644, filepath.Join(dot, "pii/shop.toml"): 0o600} {
		if got := modeOf(t, p); got != want {
			t.Errorf("%s: %04o, want %04o", p, got, want)
		}
	}
	if got := projectChecks(d, proj, me, me.uid, 10001); len(got) != 1 || got[0].state != checkOK {
		t.Errorf("after the repair: %+v", got)
	}

	// A link inside, which lox up refuses: no repair.
	if err := os.Symlink("/etc/passwd", filepath.Join(dot, "pii", "linked.toml")); err != nil {
		t.Fatal(err)
	}
	if c := titles(projectChecks(d, proj, me, me.uid, 10001))["project .locksql"]; c.state != checkFail || c.repair != nil || !strings.Contains(c.detail, "linked.toml") {
		t.Errorf("a link inside: %+v", c)
	}

	// .locksql itself a link.
	other, _ := loxUpProject(t)
	if err := os.RemoveAll(dot); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(other, ".locksql"), dot); err != nil {
		t.Fatal(err)
	}
	if got := projectChecks(d, proj, me, me.uid, 10001); len(got) != 1 || got[0].state != checkFail || got[0].repair != nil || !strings.Contains(got[0].detail, "not a directory") {
		t.Errorf(".locksql a link: %+v", got)
	}
}

// The old failure (lockhub#92): doctor --fix up to v0.13.0 gave .locksql
// to the console account, and lox up then refused it ("owned by uid 10001,
// not by you"). Doctor now reports it as a failure for you, repaired only
// as root (the launcher's root container); never the other way round.
func TestProjectChecksConsoleOwned(t *testing.T) {
	proj, dot := loxUpProject(t)
	d := fsDoctor()
	// The files are the test's: make the console account the test's uid,
	// and you another one.
	svc := os.Getuid()
	you := projectOwner{svc + 1000, svc + 1000}
	c := titles(projectChecks(d, proj, you, you.uid, svc))["project .locksql owner"]
	if c.state != checkFail || c.repair != nil || !strings.Contains(c.detail, "console account") || !strings.Contains(c.detail, "v0.13.0") ||
		!strings.Contains(c.fix, "sudo chown -R "+strconv.Itoa(you.uid)+":"+strconv.Itoa(you.gid)+" '"+dot+"'") {
		t.Fatalf("console-owned, as you: %+v", c)
	}
	if r := titles(projectChecks(d, proj, you, 0, svc))["project .locksql owner"].repair; r == nil || r.apply == nil || r.root != "" || !strings.Contains(r.what, "give back to uid "+strconv.Itoa(you.uid)) {
		t.Fatalf("console-owned, as root: %+v", r)
	}
	// Never a repair that hands .locksql to the console account.
	for _, cur := range []int{0, you.uid} {
		for _, c := range projectChecks(d, proj, you, cur, svc) {
			if c.repair != nil && (strings.Contains(c.repair.what, "to locksql") || strings.Contains(c.repair.root, "chown "+strconv.Itoa(svc))) {
				t.Errorf("a repair for the console account: %+v", c.repair)
			}
		}
	}

	// Another owner than the console account: the steps only.
	c = titles(projectChecks(d, proj, you, you.uid, -1))["project .locksql owner"]
	if c.state != checkFail || c.repair != nil || !strings.Contains(c.detail, "owned by uid "+strconv.Itoa(svc)) {
		t.Errorf("foreign owner: %+v", c)
	}
}

// giveBack changes only what it opened inside .locksql: a hard link to a
// file elsewhere is refused, a symbolic link left alone, a .locksql that is
// a link refused.
func TestGiveBack(t *testing.T) {
	proj, dot := loxUpProject(t)
	uid, gid := os.Getuid(), os.Getgid()
	if err := giveBack(dot, uid, uid, gid); err != nil {
		t.Fatal(err)
	}
	if uid == 0 {
		// As root (a container): the files really change hands.
		if err := giveBack(dot, 0, 4242, 4242); err != nil {
			t.Fatal(err)
		}
		for _, p := range []string{dot, filepath.Join(dot, "pii"), filepath.Join(dot, "pii/shop.toml")} {
			fi, _ := os.Lstat(p)
			if u, _, _ := fileOwner(fi); u != 4242 {
				t.Errorf("%s: uid %d", p, u)
			}
		}
		return
	}

	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dot, "linked.toml")); err != nil {
		t.Fatal(err)
	}
	if err := giveBack(dot, uid, uid, gid); err != nil {
		t.Errorf("a symbolic link inside: %v", err)
	}
	if err := os.Link(outside, filepath.Join(dot, "pii", "hard.toml")); err != nil {
		t.Fatal(err)
	}
	if err := giveBack(dot, uid, uid, gid); err == nil || !strings.Contains(err.Error(), "hard.toml: a hard link") {
		t.Errorf("a hard link inside: %v", err)
	}
	// Not the console account's: left alone, even a hard link.
	if err := giveBack(dot, uid+1, uid, gid); err != nil {
		t.Errorf("another owner: %v", err)
	}

	link := filepath.Join(proj, "link")
	if err := os.Symlink(dot, link); err != nil {
		t.Fatal(err)
	}
	if err := giveBack(link, uid, uid, gid); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Errorf(".locksql a link: %v", err)
	}
}

// The root part of the launcher's doctor --fix: only the give-back repair,
// its text on stderr, nothing on stdout (the JSON is the next run's).
func TestDoctorAsRoot(t *testing.T) {
	proj, _ := loxUpProject(t)
	e, _, _ := onboardEnv(t)
	d := fsDoctor()
	me := strconv.Itoa(os.Getuid())
	// The console account is the test's uid, so the files are its.
	d.lookupUser = func(n string) (*user.User, error) { return &user.User{Uid: me, Username: n}, nil }
	d.getenv = func(k string) string {
		if k == doctorForEnv {
			return me + ":" + strconv.Itoa(os.Getgid())
		}
		return ""
	}
	e.doc, e.cwd, e.tty = &d, proj, false
	e.euid = func() int { return 0 }
	var stdout, stderr bytes.Buffer
	e.stdout, e.stderr = &stdout, &stderr
	e.root = func(s string) error { t.Errorf("a root script: %s", s); return nil }
	if code := runEnv(e, []string{"doctor", "--fix", "--yes", "--json"}); code != exitOK {
		t.Fatalf("code %d\n%s", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "repaired: give back to uid "+me) || strings.Contains(stderr.String(), "client access") {
		t.Errorf("stderr:\n%s", stderr.String())
	}

	// A bad LOCKSQL_DOCTOR_FOR, or root, is refused.
	for _, v := range []string{"0:0", "x:1", "1000"} {
		d.getenv = func(string) string { return v }
		stderr.Reset()
		if code := runEnv(e, []string{"doctor", "--fix", "--yes"}); code != exitUsage {
			t.Errorf("%s=%s: code %d\n%s", doctorForEnv, v, code, stderr.String())
		}
	}
}

// Plain doctor, as the launcher runs it (the image's agent account), checks
// .locksql for you: LOCKSQL_DOCTOR_FOR.
func TestDoctorChecksTheProjectForYou(t *testing.T) {
	proj, _ := loxUpProject(t)
	d := fsDoctor()
	d.getenv = func(k string) string {
		if k == doctorForEnv {
			return strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid())
		}
		return ""
	}
	checks := doctor(d, proj, "")
	if c := findCheck(checks, "project .locksql"); c == nil || c.state != checkOK {
		t.Errorf("for you: %+v", c)
	}
	// Without it, for the account doctor runs as (uid 1000 here).
	d.getenv = nil
	if os.Getuid() != 1000 {
		if c := findCheck(doctor(d, proj, ""), "project .locksql"); c == nil || c.state != checkFail {
			t.Errorf("for uid 1000: %+v", c)
		}
	}
}
