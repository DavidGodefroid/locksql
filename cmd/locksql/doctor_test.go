//go:build unix

package main

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/secrets"
	"github.com/DavidGodefroid/lockkit/sysconf"
	"github.com/DavidGodefroid/locksql/internal/client"
	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/ipc"
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
				return fakeInfo{"locksql", fs.ModeDir | fs.ModeSetgid | 0o710}, nil
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
		keychain: func(string, string, int) error { return secrets.ErrNotFound },
		readFile: os.ReadFile,
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

func hasCheck(checks []check, state, titlePart string) bool {
	for _, c := range checks {
		if c.state == state && strings.Contains(c.title, titlePart) {
			return true
		}
	}
	return false
}

func TestDoctorTLSMode(t *testing.T) {
	d := fakeDoctor(nil)
	weak := config.Profile{Name: "p", Engine: config.EnginePostgres, Host: "db.example", TLS: config.TLSRequire, Credentials: config.CredentialsAsk}
	if !hasCheck(profileChecks(d, weak, nil, t.TempDir()), checkWarn, "tls") {
		t.Error("require on a remote host is not reported")
	}
	strong := weak
	strong.TLS = config.TLSVerifyFull
	if !hasCheck(profileChecks(d, strong, nil, t.TempDir()), checkOK, "tls") {
		t.Error("verify-full not reported ok")
	}
	withCA := weak
	withCA.TLSCA = "/ca.pem"
	if !hasCheck(profileChecks(d, withCA, nil, t.TempDir()), checkOK, "tls") {
		t.Error("require with tls_ca, which verifies the chain, not reported ok")
	}
}

func TestDoctorSSHKeyFile(t *testing.T) {
	d := fakeDoctor(nil)
	d.stat = os.Stat // fakeDoctor's stat knows only the install paths
	dir := t.TempDir()
	key := filepath.Join(dir, "id")
	if err := os.WriteFile(key, []byte("k"), 0o644); err != nil {
		t.Fatal(err)
	}
	p := config.Profile{Name: "p", Engine: config.EnginePostgres, Host: "127.0.0.1", TLS: config.TLSPrefer, Credentials: config.CredentialsAsk,
		SSH: &config.SSHProfile{Host: "b", Port: 22, User: "u", Auth: config.SSHAuthKey, Key: key, Credentials: config.CredentialsAsk}}
	checks := profileChecks(d, p, nil, dir)
	if !hasCheck(checks, checkFail, "ssh key") {
		t.Error("group/world-readable key not reported")
	}
	if !hasCheck(checks, checkOK, "ssh") {
		t.Error("the bastion is not reported")
	}
	if c := findCheck(checks, ": tls"); c == nil || c.state != checkOK || !strings.Contains(c.detail, "bastion") {
		t.Errorf("tls check of a database on the bastion = %+v, want ok naming the bastion", c)
	}
	if err := os.Chmod(key, 0o600); err != nil {
		t.Fatal(err)
	}
	if !hasCheck(profileChecks(d, p, nil, dir), checkOK, "ssh key") {
		t.Error("0600 key not reported ok")
	}
	p.SSH.Key = filepath.Join(dir, "missing")
	if !hasCheck(profileChecks(d, p, nil, dir), checkFail, "ssh key") {
		t.Error("missing key not reported")
	}
	if hasCheck(profileChecks(d, p, separatedSys(), dir), checkFail, "ssh key") {
		t.Error("an unreadable key in the console account's home reported as failing in a separated setup")
	}
}

func findCheck(checks []check, titlePart string) *check {
	for i := range checks {
		if strings.Contains(checks[i].title, titlePart) {
			return &checks[i]
		}
	}
	return nil
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
		"socket dir without setgid": {func(d *doctorEnv) {
			stat := d.stat
			d.stat = func(p string) (os.FileInfo, error) {
				if p == "/run/locksql" {
					return fakeInfo{"locksql", fs.ModeDir | 0o710}, nil
				}
				return stat(p)
			}
		}, "ask", "socket directory", checkFail},
		"secret in agent keychain": {func(d *doctorEnv) { d.keychain = func(string, string, int) error { return nil } }, "keychain", "secret store", checkFail},
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
	if stateOf(checks, "separation") != checkFail {
		t.Errorf("same-user mode is not a failure: %+v", checks)
	}
	if stateOf(checks, "terminal injection") != checkWarn {
		t.Errorf("terminal injection check: %+v", checks)
	}
}

// The image refuses locksql install: no fix may send the human there.
func TestDoctorFixesNameNoHostInstall(t *testing.T) {
	missing := func(d *doctorEnv) {
		d.lookupUser = func(string) (*user.User, error) { return nil, errors.New("no such user") }
	}
	noSocketDir := func(d *doctorEnv) {
		stat := d.stat
		d.stat = func(p string) (os.FileInfo, error) {
			if p == "/run/locksql" {
				return nil, fs.ErrNotExist
			}
			return stat(p)
		}
	}
	noSetgid := func(d *doctorEnv) {
		stat := d.stat
		d.stat = func(p string) (os.FileInfo, error) {
			if p == "/run/locksql" {
				return fakeInfo{"locksql", fs.ModeDir | 0o710}, nil
			}
			return stat(p)
		}
	}
	writable := func(d *doctorEnv) { d.ownerOf = func(os.FileInfo) (int, int, bool) { return 1000, 1000, true } }
	badSys := func(d *doctorEnv) {
		d.loadSys = func() (*sysconf.Config, error) { return nil, errors.New("bad system.toml") }
	}
	for name, c := range map[string]struct {
		sys    *sysconf.Config
		mutate func(*doctorEnv)
		title  string
	}{
		"same-user":            {nil, func(*doctorEnv) {}, "separation"},
		"same-user binary":     {nil, writable, "binary"},
		"bad system config":    {separatedSys(), badSys, "system setup"},
		"no console account":   {separatedSys(), missing, "console account"},
		"writable binary":      {separatedSys(), writable, "binary"},
		"no socket directory":  {separatedSys(), noSocketDir, "socket directory"},
		"socket dir no setgid": {separatedSys(), noSetgid, "socket directory"},
	} {
		d := fakeDoctor(c.sys)
		c.mutate(&d)
		found := false
		for _, ch := range doctor(d, doctorProject(t, "ask"), "") {
			if strings.Contains(ch.fix, "locksql install") || strings.Contains(ch.detail, "locksql install") {
				t.Errorf("%s: %s: %q", name, ch.title, ch.fix)
			}
			found = found || ch.title == c.title && ch.fix != ""
		}
		if !found {
			t.Errorf("%s: no %q check with a fix", name, c.title)
		}
	}
}

func TestDoctorShowsSetgidMode(t *testing.T) {
	checks := doctor(fakeDoctor(separatedSys()), doctorProject(t, "ask"), "")
	if stateOf(checks, "socket directory") != checkOK {
		t.Fatalf("socket directory check: %+v", checks)
	}
	for _, c := range checks {
		if c.title == "socket directory" && !strings.Contains(c.detail, "/run/locksql 2710") {
			t.Errorf("socket directory shown as %q, want mode 2710", c.detail)
		}
	}
}

func TestDoctorReportsShowResults(t *testing.T) {
	d := fakeDoctor(separatedSys())
	d.status = func(string, string) (*ipc.StatusResult, error) {
		return &ipc.StatusResult{Tier: "read", ShowResults: true, Health: &ipc.Health{Separated: true, Display: "wayland", ExplainOK: true}}, nil
	}
	for _, c := range doctor(d, doctorProject(t, "ask"), "") {
		if strings.HasSuffix(c.title, ": console") {
			if !strings.Contains(c.detail, "--show-results") {
				t.Errorf("console check does not report --show-results: %q", c.detail)
			}
			return
		}
	}
	t.Fatal("no console check")
}

func TestDoctorVault(t *testing.T) {
	p := config.Profile{Name: "p", Engine: config.EnginePostgres, Host: "127.0.0.1", TLS: config.TLSPrefer,
		Credentials: config.CredentialsVault, VaultPath: "database/creds/app-ro"}
	d := fakeDoctor(nil)
	d.lookPath = func(string) (string, error) { return "", exec.ErrNotFound }
	if !hasCheck(profileChecks(d, p, nil, t.TempDir()), checkFail, "vault CLI") {
		t.Error("a missing vault CLI is not reported")
	}
	d.lookPath = func(string) (string, error) { return "/usr/bin/vault", nil }
	if c := findCheck(profileChecks(d, p, nil, t.TempDir()), "credentials"); c == nil || c.state != checkOK || !strings.Contains(c.detail, "database/creds/app-ro") {
		t.Errorf("credentials check = %+v", c)
	}

	// Separated: the console account reads Vault; a token held by the
	// agent's account lets the agent read the login itself.
	d = fakeDoctor(separatedSys())
	if c := findCheck(profileChecks(d, p, separatedSys(), t.TempDir()), "credentials"); c == nil || c.state != checkOK || !strings.Contains(c.detail, "locksql") {
		t.Errorf("separated credentials check = %+v", c)
	}
	d.getenv = func(k string) string {
		if k == "VAULT_TOKEN" {
			return "hvs.x"
		}
		return ""
	}
	c := findCheck(profileChecks(d, p, separatedSys(), t.TempDir()), "vault token")
	if c == nil || c.state != checkFail || !strings.Contains(c.detail, "VAULT_TOKEN") || strings.Contains(c.detail+c.fix, "hvs.x") {
		t.Errorf("VAULT_TOKEN check = %+v", c)
	}
	d.getenv = nil
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".vault-token"), []byte("hvs.y"), 0o600); err != nil {
		t.Fatal(err)
	}
	d.current = func() (*user.User, error) { return &user.User{Uid: "1000", Username: "agent", HomeDir: home}, nil }
	d.stat = os.Stat
	if c := findCheck(profileChecks(d, p, separatedSys(), t.TempDir()), "vault token"); c == nil || c.state != checkFail || !strings.Contains(c.detail, ".vault-token") {
		t.Errorf("~/.vault-token check = %+v", c)
	}
}

func TestDoctorProxyCommand(t *testing.T) {
	p := config.Profile{Name: "p", Engine: config.EngineMariaDB, Host: "127.0.0.1", TLS: config.TLSPrefer, Credentials: config.CredentialsAsk,
		ProxyCommand: []string{"docker", "exec", "-i", "db", "nc", "127.0.0.1", "3306"}}
	d := fakeDoctor(nil)
	d.lookPath = func(string) (string, error) { return "", exec.ErrNotFound }
	if c := findCheck(profileChecks(d, p, nil, t.TempDir()), "proxy_command"); c == nil || c.state != checkFail || !strings.Contains(c.detail, "docker") {
		t.Errorf("missing program check = %+v", c)
	}
	d.lookPath = func(string) (string, error) { return "/usr/bin/docker", nil }
	checks := profileChecks(d, p, nil, t.TempDir())
	if c := findCheck(checks, "proxy_command"); c == nil || c.state != checkOK || !strings.Contains(c.detail, `"docker" "exec"`) {
		t.Errorf("proxy_command check = %+v", c)
	}
	if c := findCheck(checks, ": tls"); c == nil || c.state != checkOK {
		t.Errorf("tls check of a loopback database behind a proxy = %+v", c)
	}

	// A program inside the project can be rewritten by the agent after the
	// approval.
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".locksql"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".locksql", "config.toml"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	p.ProxyCommand = []string{filepath.Join(root, "bin", "proxy")}
	d.stat = os.Stat
	if c := findCheck(profileChecks(d, p, nil, filepath.Join(root, "sub")), "proxy_command"); c == nil || c.state != checkFail || !strings.Contains(c.detail, "project") {
		t.Errorf("program in the project check = %+v", c)
	}

	remote := p
	remote.Host, remote.ProxyCommand = "db.internal", []string{"kubectl", "exec", "-i", "pod", "--", "nc", "db.internal", "3306"}
	if c := findCheck(profileChecks(d, remote, nil, t.TempDir()), ": tls"); c == nil || c.state != checkWarn || !strings.Contains(c.detail, "proxy_command") {
		t.Errorf("tls check of a remote database behind a proxy = %+v", c)
	}
}
