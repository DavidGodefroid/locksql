//go:build unix

package main

import (
	"bytes"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/sysconf"
	"github.com/DavidGodefroid/locksql/internal/config"
)

// setupFixture is a setup run in a temporary project, with a fake install
// that creates the separated setup, a fake console account (uid 900) and
// the root scripts recorded instead of run.
type setupFixture struct {
	e        env
	out      *bytes.Buffer
	root     string
	home     string
	scripts  []string
	installs []installOpts
	chowned  bool // the root script gave .locksql to the console account
}

func newSetupFixture(t *testing.T, separatedAlready bool, onPath ...string) *setupFixture {
	t.Helper()
	e, out, home := onboardEnv(t, onPath...)
	f := &setupFixture{e: e, out: out, home: home, root: e.cwd}
	// t.TempDir makes 0700 directories: let the console account enter.
	for _, dir := range []string{f.root, filepath.Dir(f.root)} {
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	separated := separatedAlready
	f.e.sys = func() (*sysconf.Config, error) {
		if !separated {
			return nil, nil
		}
		return separatedSys(), nil
	}
	f.e.installer = func(o installOpts) (int, bool) {
		f.installs = append(f.installs, o)
		separated = true
		return exitOK, true
	}
	f.e.root = func(s string) error {
		f.scripts = append(f.scripts, s)
		if strings.Contains(s, "chown 900 .") {
			f.chowned = true
		}
		return nil
	}
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	d := fakeDoctor(separatedSys())
	d.current = func() (*user.User, error) { return me, nil }
	// The directories above the test's own (macOS: /var/folders/.../T, mode
	// 0700) are outside the fixture: show them as enterable by everyone.
	outside := filepath.Dir(f.root)
	d.stat = func(p string) (os.FileInfo, error) {
		fi, err := os.Stat(p)
		if err == nil && fi.IsDir() && p != outside && !strings.HasPrefix(p, outside+string(filepath.Separator)) {
			return enterable{fi}, nil
		}
		return fi, err
	}
	d.ownerOf = func(fi os.FileInfo) (int, int, bool) {
		uid, gid, ok := fileOwner(fi)
		if f.chowned && fi.Name() == ".locksql" && fi.IsDir() {
			uid = 900
		}
		return uid, gid, ok
	}
	d.acl = func(string) []byte { return nil }
	f.e.doc = &d
	return f
}

// enterable is a directory any account may enter.
type enterable struct{ os.FileInfo }

func (e enterable) Mode() os.FileMode { return e.FileInfo.Mode() | 0o055 }

func (f *setupFixture) run(args ...string) int {
	return runSetup(f.e, args)
}

func TestSetupInteractive(t *testing.T) {
	f := newSetupFixture(t, false, "codex")
	// The password question is declined, then the wizard: name, engine
	// (an invalid one first, which asks again), file; then the root step
	// for the project is confirmed.
	answers := "n\ndemo\noracle\ndemo\nsqlite\ndata/app.db\ny\n"
	if runtime.GOOS != "linux" {
		answers = strings.TrimPrefix(answers, "n\n") // the password question is Linux only
	}
	f.e.stdin = strings.NewReader(answers)
	if code := f.run(); code != exitOK {
		t.Fatalf("code %d\n%s", code, f.out)
	}
	if len(f.installs) != 1 || f.installs[0].yes {
		t.Fatalf("installs %+v", f.installs)
	}
	cfg, err := config.LoadFrom(f.root, "")
	if err != nil {
		t.Fatal(err)
	}
	p, ok := cfg.Profiles["demo"]
	if !ok || p.Engine != config.EngineSQLite || p.Path != filepath.Join(f.root, "data", "app.db") {
		t.Fatalf("profiles %+v", cfg.Profiles)
	}
	if _, err := os.Stat(filepath.Join(f.home, ".codex", "config.toml")); err != nil {
		t.Errorf("codex not wired: %v", err)
	}
	if len(f.scripts) != 1 || !strings.Contains(f.scripts[0], giveDirScript(filepath.Join(f.root, ".locksql"), 900)) {
		t.Errorf("root scripts %q", f.scripts)
	}
	for _, want := range []string{"invalid:", "Wired for your account: codex", "does not exist yet",
		"log out and in again", "locksql console --project " + f.root, "Ready."} {
		if !strings.Contains(f.out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, f.out)
		}
	}
	if strings.Contains(f.out.String(), "Password") {
		t.Errorf("the wizard asked for a password:\n%s", f.out)
	}

	// Again: nothing to install, the profile is kept, no root step.
	f.out.Reset()
	f.e.stdin = strings.NewReader("")
	if code := f.run(); code != exitOK {
		t.Fatalf("second run: code %d\n%s", code, f.out)
	}
	if len(f.installs) != 1 || len(f.scripts) != 1 {
		t.Errorf("second run installed or ran root steps: %d, %d", len(f.installs), len(f.scripts))
	}
	for _, want := range []string{"Already set up", "Kept the profiles", "demo"} {
		if !strings.Contains(f.out.String(), want) {
			t.Errorf("second run lacks %q:\n%s", want, f.out)
		}
	}
	if strings.Contains(f.out.String(), "log out and in again") {
		t.Errorf("second run asks to log in again:\n%s", f.out)
	}
}

// In CI: no terminal, every answer as a flag.
func TestSetupNonInteractive(t *testing.T) {
	f := newSetupFixture(t, false)
	f.e.tty = false
	if code := f.run("--engine", "sqlite", "--path", "app.db"); code != exitUsage {
		t.Fatalf("without --yes: code %d\n%s", code, f.out)
	}
	if len(f.installs) != 0 {
		t.Fatal("installed without confirmation")
	}
	if code := f.run(); code != exitUsage {
		t.Fatalf("without a profile: code %d\n%s", code, f.out)
	}
	f.out.Reset()
	if code := f.run("--yes", "--engine", "postgres", "--host", "db.internal", "--user", "reporting", "--profile", "uat", "--credentials", "keychain"); code != exitOK {
		t.Fatalf("code %d\n%s", code, f.out)
	}
	if len(f.installs) != 1 || !f.installs[0].yes {
		t.Fatalf("installs %+v", f.installs)
	}
	cfg, err := config.LoadFrom(f.root, "")
	if err != nil {
		t.Fatal(err)
	}
	p := cfg.Profiles["uat"]
	if p.Host != "db.internal" || p.Port != 5432 || p.User != "reporting" || p.Credentials != config.CredentialsKeychain || p.TLS != config.TLSVerifyFull {
		t.Errorf("profile %+v", p)
	}
	if code := f.run("--yes", "--engine", "sqlite", "--path", "x.db", "--profile", "uat"); code != exitUsage || !strings.Contains(f.out.String(), "already in") {
		t.Errorf("duplicate profile: code %d\n%s", code, f.out)
	}
}

// A profile added to the commented example of locksql init keeps it.
func TestSetupAppendsToInitConfig(t *testing.T) {
	f := newSetupFixture(t, true)
	f.e.tty = false
	if err := os.MkdirAll(filepath.Join(f.root, ".locksql"), 0o755); err != nil {
		t.Fatal(err)
	}
	example := "# example\n# [profiles.dev]\n# engine = \"postgres\"\n"
	if err := os.WriteFile(configPath(f.root), []byte(example), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := f.run("--yes", "--engine", "sqlite", "--path", "a.db"); code != exitOK {
		t.Fatalf("code %d\n%s", code, f.out)
	}
	if len(f.installs) != 0 {
		t.Error("installed again")
	}
	b, _ := os.ReadFile(configPath(f.root))
	if !strings.HasPrefix(string(b), example) || !strings.Contains(string(b), "[profiles.dev]\nengine = \"sqlite\"\npath = \"a.db\"\n") {
		t.Errorf("config:\n%s", b)
	}
}

func TestSetupRefusals(t *testing.T) {
	f := newSetupFixture(t, true)
	f.e.euid = func() int { return 0 }
	if code := f.run(); code != exitUsage || !strings.Contains(f.out.String(), "not as root") {
		t.Errorf("as root: code %d\n%s", code, f.out)
	}
	f = newSetupFixture(t, true)
	if code := f.run("--host", "x"); code != exitUsage || !strings.Contains(f.out.String(), "need --engine") {
		t.Errorf("flags without engine: code %d\n%s", code, f.out)
	}
	f = newSetupFixture(t, false)
	f.e.installer = func(installOpts) (int, bool) { return exitOK, false } // declined
	f.e.stdin = strings.NewReader("")
	if code := f.run(); code != exitOK || !strings.Contains(f.out.String(), "Run locksql setup again") {
		t.Errorf("declined install: code %d\n%s", code, f.out)
	}
	if _, err := os.Stat(configPath(f.root)); err == nil {
		t.Error("profile written after a declined install")
	}
}

func TestCompleteSpec(t *testing.T) {
	bad := []profileSpec{
		{engine: "oracle"},
		{engine: "sqlite"},
		{engine: "sqlite", path: "a.db", host: "h"},
		{engine: "postgres", path: "a.db"},
		{engine: "postgres", port: 70000},
		{engine: "postgres", credentials: "env"},
		{engine: "postgres", name: "a.b"},
		{engine: "postgres", host: "h\nx"},
	}
	for _, s := range bad {
		if _, err := completeSpec(s); err == nil {
			t.Errorf("%+v accepted", s)
		}
	}
	s, err := completeSpec(profileSpec{engine: "mariadb", user: `we"ird\`})
	if err != nil {
		t.Fatal(err)
	}
	if s.name != "dev" || s.host != "127.0.0.1" || s.port != 3306 || s.credentials != "ask" {
		t.Errorf("defaults %+v", s)
	}
	profiles, err := config.ParseProfiles([]byte(s.toml()), "t", t.TempDir())
	if err != nil {
		t.Fatalf("%v\n%s", err, s.toml())
	}
	if profiles["dev"].User != `we"ird\` {
		t.Errorf("user %q", profiles["dev"].User)
	}
}
