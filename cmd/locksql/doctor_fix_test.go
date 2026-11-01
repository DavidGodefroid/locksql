//go:build unix

package main

import (
	"errors"
	"io/fs"
	"os"
	"os/user"
	"strings"
	"testing"
)

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

// The launcher's doctor --fix runs as your uid, which has no account in
// the image: client access is not a failure there (no group to add it to),
// where it used to fail the run as root on every fresh setup.
func TestDoctorClientAccessUnknownUID(t *testing.T) {
	d := fakeDoctor(separatedSys())
	d.inGroup = func(int, string) bool { return false }
	d.knownUID = func(string) bool { return false }
	c := findCheck(separationChecks(d, separatedSys(), &user.User{Uid: "1000", Username: "david"}, 1000), "client access")
	if c == nil || c.state != checkOK || c.repair != nil || !strings.Contains(c.detail, "no account here") || !strings.Contains(c.detail, "allowed_uids") {
		t.Errorf("unknown uid: %+v", c)
	}
	// A known account outside the group still fails, with its repair.
	d.knownUID = func(string) bool { return true }
	c = findCheck(separationChecks(d, separatedSys(), &user.User{Uid: "1000", Username: "david"}, 1000), "client access")
	if c == nil || c.state != checkFail || c.repair == nil {
		t.Errorf("known uid outside the group: %+v", c)
	}
}

func TestPasswdHas(t *testing.T) {
	if _, err := os.Stat("/etc/passwd"); err != nil {
		t.Skip("no /etc/passwd")
	}
	if !passwdHas("0") || passwdHas("987654321") {
		t.Errorf("passwdHas: root %v, 987654321 %v", passwdHas("0"), passwdHas("987654321"))
	}
}
