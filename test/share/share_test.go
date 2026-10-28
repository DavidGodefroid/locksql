//go:build integration && unix

// Package share runs locksql config export and import end to end, with the
// real binary, between two machines simulated by two sets of
// XDG_CONFIG_HOME / XDG_STATE_HOME directories.
package share

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/pii"
)

var bin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "locksql-share-")
	if err != nil {
		panic(err)
	}
	bin = filepath.Join(dir, "locksql")
	if out, err := exec.Command("go", "build", "-o", bin, "../../cmd/locksql").CombinedOutput(); err != nil {
		panic(string(out))
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

type machine struct{ home string }

func (m machine) env() []string {
	return append(os.Environ(), "HOME="+m.home, "XDG_CONFIG_HOME="+filepath.Join(m.home, ".config"), "XDG_STATE_HOME="+filepath.Join(m.home, ".state"))
}

func (m machine) dir() string { return filepath.Join(m.home, ".config", "locksql") }

func (m machine) run(t *testing.T, stdin string, args ...string) (int, string) {
	t.Helper()
	c := exec.Command(bin, args...)
	c.Env, c.Dir = m.env(), m.home
	c.Stdin = strings.NewReader(stdin)
	var out bytes.Buffer
	c.Stdout, c.Stderr = &out, &out
	err := c.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return code, out.String()
}

func (m machine) profiles(t *testing.T) map[string]config.Profile {
	t.Helper()
	c, err := config.LoadFrom(m.home, filepath.Join(m.dir(), "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	return c.Profiles
}

func TestExportImportBetweenMachines(t *testing.T) {
	a, b := machine{t.TempDir()}, machine{t.TempDir()}
	if err := os.MkdirAll(a.dir(), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(a.dir(), "config.toml"), []byte(`[profiles.uat]
engine = "mariadb"
host = "db.uat.example.com"
user = "alice"
tls = "verify-full"
tls_ca = "/etc/ssl/corp.pem"
pii_rules = "shop"

[profiles.uat.limits]
max_rows = 300
`), 0o644); err != nil {
		t.Fatal(err)
	}
	var r pii.Rules
	_ = r.AddMode("app.users.email", pii.ModeEmail)
	_ = r.Add("*.*.recipient_reference")
	p, _ := pii.SetPath(a.dir(), "shop")
	if err := pii.SaveRulesFile(p, r); err != nil {
		t.Fatal(err)
	}

	code, team := a.run(t, "", "config", "export")
	if code != 0 {
		t.Fatalf("export: %d\n%s", code, team)
	}
	// B keeps a profile of its own.
	if err := os.MkdirAll(b.dir(), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(b.dir(), "config.toml"), []byte("[profiles.mine]\nengine = \"postgres\"\nhost = \"db.mine\"\nuser = \"bob\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, out := b.run(t, team, "config", "import", "-", "--yes", "--allow-loosen", "--local", "uat.tls_ca=/b/ca.pem"); code != 0 {
		t.Fatalf("import: %d\n%s", code, out)
	}
	pa, pb := a.profiles(t), b.profiles(t)
	ua, ub := pa["uat"], pb["uat"]
	ua.User, ua.TLSCA, ub.TLSCA, ua.PIIRules, ub.PIIRules = "", "", "", "", ""
	if !reflect.DeepEqual(ua, ub) {
		t.Errorf("shared keys differ:\nA %+v\nB %+v", ua, ub)
	}
	if pb["uat"].TLSCA != "/b/ca.pem" || pb["mine"].User != "bob" {
		t.Errorf("local values: %+v / %+v", pb["uat"], pb["mine"])
	}
	pbShop, _ := pii.SetPath(b.dir(), "shop")
	rb, err := pii.LoadRulesFile(pbShop)
	if err != nil || !reflect.DeepEqual(pii.ToShared(r), pii.ToShared(rb)) {
		t.Errorf("rules: %+v, %v", rb, err)
	}

	// A second import is a no-op.
	if code, out := b.run(t, team, "config", "import", "-", "--yes", "--local", "uat.tls_ca=/b/ca.pem"); code != 0 || !strings.Contains(out, "nothing to change") {
		t.Fatalf("second import: %d\n%s", code, out)
	}

	// A tampered file is refused without --allow-loosen.
	for _, tamper := range [][2]string{{`"tier": "read"`, `"tier": "admin"`}, {`"column": "app.users.email",`, `"column": "app.users.emailx",`}} {
		bad := strings.Replace(team, tamper[0], tamper[1], 1)
		if bad == team {
			t.Fatalf("no %q in the export", tamper[0])
		}
		before, _ := os.ReadFile(filepath.Join(b.dir(), "config.toml"))
		code, out := b.run(t, bad, "config", "import", "-", "--yes", "--replace", "--local", "uat.tls_ca=/b/ca.pem")
		if code != 1 || !strings.Contains(out, "--allow-loosen") {
			t.Errorf("tampered %s: %d\n%s", tamper[1], code, out)
		}
		if after, _ := os.ReadFile(filepath.Join(b.dir(), "config.toml")); !bytes.Equal(before, after) {
			t.Error("tampered import wrote the config")
		}
	}
}
