//go:build unix

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/pii"
)

const teamConfig = `[profiles.uat]
engine = "mariadb"
host = "db.uat.example.com"
user = "alice"
database = "app"
tls = "verify-full"
tls_ca = "/etc/ssl/corp.pem"
pii_rules = "shop"

[profiles.uat.ssh]
host = "bastion.example.com"
user = "deploy"
auth = "key"
key = "~/.ssh/id_ed25519"

[profiles.reporting]
engine = "postgres"
host = "db.internal"
credentials = "vault"
vault_path = "database/creds/reporting-ro"

[profiles.local]
engine = "sqlite"
path = "dev.db"
`

// machine is one account's config and state directories, for the user
// scope.
type machine struct{ home, cfg, dir, state string }

func newMachine(t *testing.T) machine {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(home, ".state"))
	cfg, err := config.UserConfigPath()
	if err != nil {
		t.Fatal(err)
	}
	state, err := config.StateDir()
	if err != nil {
		t.Fatal(err)
	}
	return machine{home: home, cfg: cfg, dir: filepath.Dir(cfg), state: state}
}

func (m machine) write(t *testing.T, cfg string, sets map[string][]string) {
	t.Helper()
	if err := os.MkdirAll(m.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.cfg, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	for set, cols := range sets {
		var r pii.Rules
		for _, c := range cols {
			if strings.HasPrefix(c, "allow:") {
				_ = r.AddAllow(strings.TrimPrefix(c, "allow:"))
			} else if col, mode, ok := strings.Cut(c, "="); ok {
				_ = r.AddMode(col, mode)
			} else {
				_ = r.Add(c)
			}
		}
		p, _ := pii.SetPath(m.dir, set)
		if err := pii.SaveRulesFile(p, r); err != nil {
			t.Fatal(err)
		}
	}
}

func (m machine) rules(t *testing.T, set string) pii.Rules {
	t.Helper()
	p, _ := pii.SetPath(m.dir, set)
	r, err := pii.LoadRulesFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func runIn(t *testing.T, stdin string, tty bool, args ...string) outcome {
	t.Helper()
	var out, errb bytes.Buffer
	code := runEnv(env{stdin: strings.NewReader(stdin), stdout: &out, stderr: &errb, cwd: t.TempDir(), tty: tty}, args)
	return outcome{code, out.String(), errb.String()}
}

func exportFrom(t *testing.T, args ...string) string {
	t.Helper()
	a := newMachine(t)
	a.write(t, teamConfig, map[string][]string{"shop": {"app.users.email=email", "app.users.phone", "allow:app.templates.name"}, "other": {"x.y.z"}})
	o := runIn(t, "", false, append([]string{"config", "export"}, args...)...)
	o.want(t, exitOK)
	if len(args) == 0 && !strings.Contains(o.stderr, `skipped: profile "local"`) {
		t.Errorf("no warning for the sqlite profile: %q", o.stderr)
	}
	return o.stdout
}

func TestConfigExport(t *testing.T) {
	out := exportFrom(t)
	var s config.Share
	if err := json.Unmarshal([]byte(out), &s); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if s.Format != config.ShareFormat || len(s.Profiles) != 2 {
		t.Fatalf("share = %+v", s)
	}
	for _, leak := range []string{"alice", "corp.pem", "id_ed25519", "dev.db"} {
		if strings.Contains(out, leak) {
			t.Errorf("export holds %q:\n%s", leak, out)
		}
	}
	if got := strings.Join(s.Profiles["uat"].NeedsLocal, ","); got != "tls_ca,ssh.key" {
		t.Errorf("needs_local = %s", got)
	}
	// Only the sets of the exported profiles.
	if _, ok := s.PII["shop"]; !ok || len(s.PII) != 1 {
		t.Errorf("sets = %v", s.PII)
	}
	if out := exportFrom(t, "--include-user"); !strings.Contains(out, `"user": "alice"`) {
		t.Errorf("--include-user:\n%s", out)
	}
	if out := exportFrom(t, "--no-pii"); strings.Contains(out, `"pii": {`) {
		t.Errorf("--no-pii:\n%s", out)
	}
	if out := exportFrom(t, "--profile", "reporting"); strings.Contains(out, `"uat"`) {
		t.Errorf("--profile:\n%s", out)
	}
}

func TestConfigExportOutputFile(t *testing.T) {
	a := newMachine(t)
	a.write(t, teamConfig, nil)
	path := filepath.Join(t.TempDir(), "team.json")
	runIn(t, "", false, "config", "export", "--output", path).want(t, exitOK, "private repository")
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("output: %v %v", st, err)
	}
}

func teamFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "team.json")
	if err := os.WriteFile(p, []byte(exportFrom(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

var localArgs = []string{"--local", "uat.tls_ca=/b/ca.pem", "--local", "uat.ssh.key=~/.ssh/b"}

// A fresh machine gets the same profiles and rules as the source on the
// shared keys; a second import changes nothing.
func TestConfigImportFreshMachine(t *testing.T) {
	team := teamFile(t)
	b := newMachine(t)
	runIn(t, "", false, append([]string{"config", "import", team, "--yes", "--allow-loosen"}, localArgs...)...).
		want(t, exitOK, "profile uat:", "new profile", "approve each loosened profile")
	got, err := config.LoadFrom(t.TempDir(), b.cfg)
	if err != nil {
		t.Fatal(err)
	}
	src, _ := config.ParseProfiles([]byte(teamConfig), "config.toml", "/x")
	u := got.Profiles["uat"]
	if u.Host != src["uat"].Host || u.TLSCA != "/b/ca.pem" || u.SSH == nil || u.SSH.Key != "~/.ssh/b" || u.User != "" || u.PIIRules != "shop" {
		t.Errorf("uat = %+v", u)
	}
	if r := b.rules(t, "shop"); len(r.Mask) != 2 || r.Modes["app.users.email"] != pii.ModeEmail || len(r.Allow) != 1 {
		t.Errorf("shop rules = %+v", r)
	}
	if st, _ := os.Stat(b.cfg); st.Mode().Perm() != 0o644 {
		t.Errorf("config mode %v", st.Mode())
	}
	before, _ := os.ReadFile(b.cfg)
	runIn(t, "", false, append([]string{"config", "import", team, "--yes"}, localArgs...)...).want(t, exitOK, "nothing to change")
	if after, _ := os.ReadFile(b.cfg); !bytes.Equal(before, after) {
		t.Error("second import changed the file")
	}
	// Audited, without values.
	log, err := os.ReadFile(filepath.Join(b.state, "locksql", "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(log), `"event":"config_import"`) || !strings.Contains(string(log), `"scope":"user"`) ||
		strings.Contains(string(log), "db.uat.example.com") || strings.Contains(string(log), "/b/ca.pem") {
		t.Errorf("audit log:\n%s", log)
	}
	// The import never approves: no approved policy written.
	if _, err := os.Stat(filepath.Join(b.state, "locksql", "approved")); err == nil {
		t.Error("approved policies written")
	}
}

func TestConfigImportNeedsLocal(t *testing.T) {
	team := teamFile(t)
	b := newMachine(t)
	o := runIn(t, "", false, "config", "import", team, "--yes", "--allow-loosen")
	o.want(t, exitOK, "not imported: profile uat", "--local uat.tls_ca")
	got, _ := config.LoadFrom(t.TempDir(), b.cfg)
	if _, ok := got.Profiles["uat"]; ok {
		t.Error("uat imported without its local values")
	}
	runIn(t, "", false, "config", "import", team, "--local", "uat.host=x").want(t, exitUsage, "only tls_ca")
}

// Merging keeps local-only profiles, the local user and local files; a
// mode conflict keeps redact.
func TestConfigImportMerge(t *testing.T) {
	team := teamFile(t)
	b := newMachine(t)
	b.write(t, `[profiles.mine]
engine = "postgres"
host = "db.mine"

[profiles.uat]
engine = "mariadb"
host = "db.uat.example.com"
user = "bob"
database = "app"
tls = "verify-full"
tls_ca = "/b/ca.pem"
pii_rules = "shop"

[profiles.uat.ssh]
host = "bastion.example.com"
user = "deploy"
auth = "key"
key = "~/.ssh/b"
`, map[string][]string{"shop": {"app.users.email=partial", "app.users.iban"}})
	o := runIn(t, "", false, "config", "import", team, "--yes", "--allow-loosen")
	o.want(t, exitOK, "PII mode conflict: shop: app.users.email")
	got, _ := config.LoadFrom(t.TempDir(), b.cfg)
	if _, ok := got.Profiles["mine"]; !ok {
		t.Error("local-only profile dropped")
	}
	if u := got.Profiles["uat"]; u.User != "bob" || u.TLSCA != "/b/ca.pem" || u.SSH.Key != "~/.ssh/b" {
		t.Errorf("local values lost: %+v", u)
	}
	r := b.rules(t, "shop")
	if len(r.Mask) != 3 || r.Modes["app.users.email"] != "" {
		t.Errorf("merged rules: %+v", r)
	}
	if _, err := os.Stat(b.cfg + ".bak"); err != nil {
		t.Error("no config backup")
	}
	if p, _ := pii.SetPath(b.dir, "shop"); func() bool { _, err := os.Stat(p + ".bak"); return err != nil }() {
		t.Error("no rule set backup")
	}

	// --replace drops mine, keeps uat's local values.
	// It drops a mask rule and a mode: a loosening.
	runIn(t, "", false, "config", "import", team, "--yes", "--replace").want(t, exitFail, "pii.mask: app.users.iban")
	runIn(t, "", false, "config", "import", team, "--yes", "--replace", "--allow-loosen").want(t, exitOK)
	got, _ = config.LoadFrom(t.TempDir(), b.cfg)
	if _, ok := got.Profiles["mine"]; ok {
		t.Error("--replace kept mine")
	}
	if u := got.Profiles["uat"]; u.User != "bob" || u.TLSCA != "/b/ca.pem" {
		t.Errorf("--replace lost local values: %+v", u)
	}
}

// A tampered team file that loosens anything is refused without
// --allow-loosen, and nothing is written.
func TestConfigImportLooseningRefused(t *testing.T) {
	team := teamFile(t)
	b := newMachine(t)
	runIn(t, "", false, append([]string{"config", "import", team, "--yes", "--allow-loosen"}, localArgs...)...).want(t, exitOK)
	clean, _ := os.ReadFile(team)
	tamper := func(t *testing.T, from, to string) string {
		t.Helper()
		if !strings.Contains(string(clean), from) {
			t.Fatalf("no %q in the export", from)
		}
		p := filepath.Join(t.TempDir(), "tampered.json")
		_ = os.WriteFile(p, []byte(strings.Replace(string(clean), from, to, 1)), 0o600)
		return p
	}
	cases := map[string][2]string{
		"tier":        {`"tier": "read"`, `"tier": "admin"`},
		"tls":         {`"tls": "verify-full"`, `"tls": "disable"`},
		"host":        {`"host": "db.internal"`, `"host": "db.evil.example.com"`},
		"max_rows":    {`"max_rows": 200`, `"max_rows": 100000`},
		"k":           {`"k_anonymity": 5`, `"k_anonymity": 1`},
		"detector":    {`"email",`, ``},
		"allow rule":  {`"allow": [`, `"allow": [{"column": "app.users.phone"},`},
		"mask mode":   {`"column": "app.users.phone"`, `"column": "app.users.phone", "mode": "partial"`},
		"pii_rules":   {`"pii_rules": "shop"`, `"pii_rules": "other"`},
		"credentials": {`"credentials": "ask"`, `"credentials": "keychain"`},
	}
	before, _ := os.ReadFile(b.cfg)
	shop := b.rules(t, "shop")
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			p := tamper(t, c[0], c[1])
			o := runIn(t, "", false, append([]string{"config", "import", p, "--yes", "--replace"}, localArgs...)...)
			o.want(t, exitFail, "loosens", "--allow-loosen", "nothing written")
			if after, _ := os.ReadFile(b.cfg); !bytes.Equal(before, after) {
				t.Error("config written")
			}
			if r := b.rules(t, "shop"); len(r.Mask) != len(shop.Mask) || len(r.Allow) != len(shop.Allow) {
				t.Error("rules written")
			}
		})
	}
	// A removed mask rule loosens under --replace.
	var sh config.Share
	if err := json.Unmarshal(clean, &sh); err != nil {
		t.Fatal(err)
	}
	r := sh.PII["shop"]
	r.Mask = r.Mask[1:]
	sh.PII["shop"] = r
	var buf bytes.Buffer
	_ = config.EncodeShare(&buf, sh)
	p := filepath.Join(t.TempDir(), "removed.json")
	_ = os.WriteFile(p, buf.Bytes(), 0o600)
	runIn(t, "", false, append([]string{"config", "import", p, "--yes", "--replace"}, localArgs...)...).want(t, exitFail, "pii.mask:", "loosens")
	// Without --replace the rule stays: the union tightens only.
	runIn(t, "", false, append([]string{"config", "import", p, "--yes"}, localArgs...)...).want(t, exitOK)
	if len(b.rules(t, "shop").Mask) != len(shop.Mask) {
		t.Error("merge removed a rule")
	}
}

func TestConfigImportDryRunTTYAndSymlink(t *testing.T) {
	team := teamFile(t)
	b := newMachine(t)
	args := append([]string{"config", "import", team, "--allow-loosen"}, localArgs...)
	runIn(t, "", false, append(args, "--dry-run")...).want(t, exitOK, "--dry-run: nothing written")
	if _, err := os.Stat(b.cfg); err == nil {
		t.Fatal("dry run wrote the config")
	}
	runIn(t, "", false, args...).want(t, exitFail, "pass --yes")
	runIn(t, "n\n", true, args...).want(t, exitFail, "not confirmed")
	if _, err := os.Stat(b.cfg); err == nil {
		t.Fatal("written without confirmation")
	}
	runIn(t, "y\n", true, args...).want(t, exitOK, "written")

	// A config file that is a symbolic link is refused.
	real := filepath.Join(t.TempDir(), "real.toml")
	data, _ := os.ReadFile(b.cfg)
	_ = os.WriteFile(real, data, 0o644)
	_ = os.Remove(b.cfg)
	if err := os.Symlink(real, b.cfg); err != nil {
		t.Fatal(err)
	}
	runIn(t, "", false, append(args, "--yes")...).want(t, exitFail, "symbolic link")
}

func TestConfigImportRefusesBadFiles(t *testing.T) {
	newMachine(t)
	for name, data := range map[string]string{
		"newer":   `{"locksql_config_format":99,"profiles":{}}`,
		"unknown": `{"locksql_config_format":1,"profiles":{"a":{"engine":"mariadb","host":"h","detectors":[],"x":1}}}`,
		"engine":  `{"locksql_config_format":1,"profiles":{"a":{"engine":"oracle","host":"h","detectors":[]}}}`,
		"tier":    `{"locksql_config_format":1,"profiles":{"a":{"engine":"mariadb","host":"h","tier":"root","detectors":[]}}}`,
		"port":    `{"locksql_config_format":1,"profiles":{"a":{"engine":"mariadb","host":"h","port":70000,"detectors":[]}}}`,
		"limits":  `{"locksql_config_format":1,"profiles":{"a":{"engine":"mariadb","host":"h","limits":{"max_session":"48h"},"detectors":[]}}}`,
		"dur":     `{"locksql_config_format":1,"profiles":{"a":{"engine":"mariadb","host":"h","limits":{"statement_timeout":"soon"},"detectors":[]}}}`,
		"rule":    `{"locksql_config_format":1,"pii":{"s":{"mask":[{"column":"a.b"}],"allow":[]}}}`,
		"inject":  `{"locksql_config_format":1,"profiles":{"a":{"engine":"mariadb","host":"h\n[profiles.x]","detectors":[]}}}`,
	} {
		p := filepath.Join(t.TempDir(), name+".json")
		_ = os.WriteFile(p, []byte(data), 0o600)
		o := runIn(t, "", false, "config", "import", p, "--yes", "--allow-loosen")
		if o.code != exitFail || !strings.Contains(o.stderr, "nothing written") {
			t.Errorf("%s: exit %d\n%s%s", name, o.code, o.stdout, o.stderr)
		}
	}
	cfg, _ := config.UserConfigPath()
	if _, err := os.Stat(cfg); err == nil {
		t.Error("a refused import wrote the config")
	}
}
