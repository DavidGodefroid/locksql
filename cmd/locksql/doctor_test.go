package main

import (
	"errors"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/locksql/internal/client"
	"github.com/DavidGodefroid/locksql/internal/ipc"
	"github.com/DavidGodefroid/locksql/internal/secrets"
	"github.com/DavidGodefroid/locksql/internal/sysconf"
)

type fakeInfo struct {
	name string
	mode fs.FileMode
}

func (f fakeInfo) Name() string       { return f.name }
func (f fakeInfo) Size() int64        { return 0 }
func (f fakeInfo) Mode() fs.FileMode  { return f.mode }
func (f fakeInfo) ModTime() time.Time { return time.Time{} }
func (f fakeInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeInfo) Sys() any           { return nil }

func fakeDoctor(sys *sysconf.Config) doctorEnv {
	return doctorEnv{
		goos:    "linux",
		loadSys: func() (*sysconf.Config, error) { return sys, nil },
		display: func() sysconf.Display { return sysconf.Display{Kind: sysconf.DisplayWayland} },
		current: func() (*user.User, error) { return &user.User{Uid: "1000", Username: "agent"}, nil },
		lookupUser: func(n string) (*user.User, error) {
			if n == "locksql" {
				return &user.User{Uid: "900", Username: "locksql"}, nil
			}
			return nil, errors.New("no such user")
		},
		inGroup:    func(uid int, _ string) bool { return uid == 1000 },
		sudoNoPass: func() bool { return false },
		executable: func() (string, error) { return "/usr/local/bin/locksql", nil },
		stat: func(p string) (os.FileInfo, error) {
			switch p {
			case "/usr/local/bin/locksql":
				return fakeInfo{"locksql", 0o755}, nil
			case "/run/locksql":
				return fakeInfo{"locksql", fs.ModeDir | 0o710}, nil
			case "/run/user/900":
				return fakeInfo{"900", fs.ModeDir | 0o700}, nil
			}
			return nil, fs.ErrNotExist
		},
		ownerOf: func(fi os.FileInfo) (int, int, bool) {
			if fi.Name() == "locksql" && fi.IsDir() {
				return 900, -1, true
			}
			return 0, 0, true
		},
		tiocsti:  func() (bool, bool) { return false, true },
		ptrace:   func() (int, bool) { return 1, true },
		keychain: func(string, string) error { return secrets.ErrNotFound },
		status: func(string, string) (*ipc.StatusResult, error) {
			return &ipc.StatusResult{Tier: "read", Health: &ipc.Health{Separated: true, Display: "wayland", ExplainOK: true}}, nil
		},
	}
}

func doctorProject(t *testing.T, credentials string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".locksql"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := "[profiles.uat]\nengine = \"mariadb\"\nhost = \"db\"\ncredentials = \"" + credentials + "\"\n"
	if err := os.WriteFile(filepath.Join(dir, ".locksql", "config.toml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func stateOf(checks []check, title string) string {
	for _, c := range checks {
		if strings.Contains(c.title, title) {
			return c.state
		}
	}
	return ""
}

func separatedSys() *sysconf.Config {
	return &sysconf.Config{ServiceUser: "locksql", ClientGroup: "locksql-clients", SocketDir: "/run/locksql", X11: "refuse"}
}

func TestDoctorSeparatedHealthy(t *testing.T) {
	checks := doctor(fakeDoctor(separatedSys()), doctorProject(t, "ask"), "")
	for _, c := range checks {
		if c.state == checkFail {
			t.Errorf("unexpected failure: %+v", c)
		}
	}
	for _, title := range []string{"console account isolated", "client access", "privilege escalation", "separate session", "binary", "uat: console", "uat: EXPLAIN"} {
		if stateOf(checks, title) != checkOK {
			t.Errorf("%s: %q, want OK\n%+v", title, stateOf(checks, title), checks)
		}
	}
}

func TestDoctorFindsProblems(t *testing.T) {
	cases := map[string]struct {
		mutate func(*doctorEnv)
		cred   string
		title  string
		want   string
	}{
		"password-less sudo": {func(d *doctorEnv) { d.sudoNoPass = func() bool { return true } }, "ask", "privilege escalation", checkFail},
		"agent not in group": {func(d *doctorEnv) { d.inGroup = func(int, string) bool { return false } }, "ask", "client access", checkFail},
		"console in group":   {func(d *doctorEnv) { d.inGroup = func(int, string) bool { return true } }, "ask", "console account isolated", checkFail},
		"x11": {func(d *doctorEnv) {
			d.display = func() sysconf.Display { return sysconf.Display{Kind: sysconf.DisplayX11} }
		}, "ask", "graphical session", checkWarn},
		"binary writable": {func(d *doctorEnv) {
			d.ownerOf = func(os.FileInfo) (int, int, bool) { return 1000, 1000, true }
		}, "ask", "binary", checkFail},
		"secret in agent keychain": {func(d *doctorEnv) { d.keychain = func(string, string) error { return nil } }, "keychain", "secret store", checkFail},
		"no console": {func(d *doctorEnv) {
			d.status = func(string, string) (*ipc.StatusResult, error) { return nil, &client.NoConsoleError{Profile: "uat"} }
		}, "ask", "uat: console", checkWarn},
		"privileged account": {func(d *doctorEnv) {
			d.status = func(string, string) (*ipc.StatusResult, error) {
				return &ipc.StatusResult{Tier: "read", Health: &ipc.Health{Separated: true, ExplainOK: true, Privileges: []string{"INSERT"}}}, nil
			}
		}, "ask", "database privileges", checkWarn},
		"console not separated": {func(d *doctorEnv) {
			d.status = func(string, string) (*ipc.StatusResult, error) {
				return &ipc.StatusResult{Tier: "read", Health: &ipc.Health{ExplainOK: true}}, nil
			}
		}, "ask", "console separation", checkFail},
	}
	for name, c := range cases {
		d := fakeDoctor(separatedSys())
		c.mutate(&d)
		checks := doctor(d, doctorProject(t, c.cred), "")
		if got := stateOf(checks, c.title); got != c.want {
			t.Errorf("%s: %s = %q, want %q", name, c.title, got, c.want)
		}
	}
}

func TestDoctorSameUserMode(t *testing.T) {
	d := fakeDoctor(nil)
	d.tiocsti = func() (bool, bool) { return true, true }
	d.status = func(string, string) (*ipc.StatusResult, error) { return nil, &client.NoConsoleError{Profile: "uat"} }
	checks := doctor(d, doctorProject(t, "ask"), "")
	if stateOf(checks, "separation") != checkWarn || stateOf(checks, "terminal injection") != checkWarn {
		t.Errorf("same-user checks: %+v", checks)
	}
}

func TestInstallPrint(t *testing.T) {
	o := cli(t, t.TempDir(), "", "install", "--client", "agent", "--print")
	if o.code != 0 {
		t.Fatalf("exit %d: %s", o.code, o.stderr)
	}
	adduser := "useradd"
	if runtime.GOOS == "darwin" {
		adduser = "sysadminctl"
	}
	for _, want := range []string{adduser, "locksql-clients", "/etc/locksql/system.toml", "x11          = \"refuse\"", "0710"} {
		if !strings.Contains(o.stdout, want) {
			t.Errorf("install script lacks %q", want)
		}
	}
	if o := cli(t, t.TempDir(), "", "install", "--client", "locksql", "--print"); o.code != exitUsage {
		t.Error("same agent and console account accepted")
	}
	if o := cli(t, t.TempDir(), "", "install", "--client", "a;id", "--print"); o.code != exitUsage {
		t.Error("shell metacharacters accepted in an account name")
	}
}
