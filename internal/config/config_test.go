package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// installProject copies a fixture into <dir>/.locksql/config.toml and returns dir.
func installProject(t *testing.T, fixture string) string {
	t.Helper()
	dir := t.TempDir()
	writeFixture(t, fixture, filepath.Join(dir, ".locksql", "config.toml"))
	return dir
}

func writeFixture(t *testing.T, fixture, dst string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", fixture))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadFillsDefaults(t *testing.T) {
	root := installProject(t, "basic.toml")
	cfg, err := LoadFrom(root, "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ProjectRoot != root {
		t.Errorf("ProjectRoot = %q, want %q", cfg.ProjectRoot, root)
	}

	uat, ok := cfg.Profiles["uat"]
	if !ok {
		t.Fatal("profile uat missing")
	}
	if uat.Name != "uat" || uat.Engine != EngineMariaDB || uat.Port != 3306 || uat.Database != "app" {
		t.Errorf("uat = %+v", uat)
	}
	if uat.Tier != TierRead || uat.Credentials != CredentialsAsk || uat.Production {
		t.Errorf("uat defaults: tier=%v credentials=%q production=%v", uat.Tier, uat.Credentials, uat.Production)
	}
	if uat.Limits != DefaultLimits(false) {
		t.Errorf("uat limits = %+v, want %+v", uat.Limits, DefaultLimits(false))
	}
	want := Limits{StatementTimeout: 30 * time.Second, ExplainRowsWarn: 100_000, ExplainRowsRefuse: 1_000_000, MaxRows: 200, MaxCellChars: 200, MaxOutputBytes: 65_536, KAnonymity: 5}
	if uat.Limits != want {
		t.Errorf("non-production defaults = %+v, want %+v", uat.Limits, want)
	}
	if strings.Join(uat.Detectors, ",") != strings.Join(DefaultDetectors(), ",") {
		t.Errorf("uat detectors = %v", uat.Detectors)
	}

	prod := cfg.Profiles["prod"]
	if !prod.Production || prod.Port != 5432 {
		t.Errorf("prod = %+v", prod)
	}
	if prod.Limits.StatementTimeout != 10*time.Second || prod.Limits.ExplainRowsWarn != 20_000 ||
		prod.Limits.ExplainRowsRefuse != 200_000 || prod.Limits.MaxRows != 200 {
		t.Errorf("production defaults = %+v", prod.Limits)
	}

	local := cfg.Profiles["local"]
	if local.Tier != TierWrite || local.Limits.MaxRows != 50 || local.Limits.StatementTimeout != 5*time.Second {
		t.Errorf("local explicit values lost: %+v", local)
	}
	if local.Limits.MaxCellChars != 200 {
		t.Errorf("local partial limits not defaulted: %+v", local.Limits)
	}
	if local.Path != filepath.Join(root, "app.db") {
		t.Errorf("sqlite path = %q, want resolved against project root", local.Path)
	}
	if strings.Join(local.Detectors, ",") != "email,be_niss" {
		t.Errorf("local detectors = %v", local.Detectors)
	}
}

func TestLoadWalksUp(t *testing.T) {
	root := installProject(t, "basic.toml")
	sub := filepath.Join(root, "a", "b", "c")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	got, ok := FindProjectRoot(sub)
	if !ok || got != root {
		t.Fatalf("FindProjectRoot = %q, %v; want %q", got, ok, root)
	}
	cfg, err := LoadFrom(sub, "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ProjectRoot != root || len(cfg.Profiles) != 3 {
		t.Errorf("cfg = %+v", cfg)
	}
}

func TestFindProjectRootNone(t *testing.T) {
	if _, ok := FindProjectRoot(t.TempDir()); ok {
		t.Error("found a project root in an empty temp dir")
	}
}

func TestLoadUserConfigProjectWins(t *testing.T) {
	root := installProject(t, "basic.toml")
	userPath := filepath.Join(t.TempDir(), "locksql", "config.toml")
	writeFixture(t, "user.toml", userPath)
	cfg, err := LoadFrom(root, userPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Profiles["uat"].Host != "db.uat.example.com" {
		t.Errorf("project profile should win, got host %q", cfg.Profiles["uat"].Host)
	}
	mine, ok := cfg.Profiles["mine"]
	if !ok || mine.Port != 5433 {
		t.Errorf("user profile mine = %+v, %v", mine, ok)
	}
}

func TestLoadUserOnly(t *testing.T) {
	userPath := filepath.Join(t.TempDir(), "config.toml")
	writeFixture(t, "user.toml", userPath)
	cfg, err := LoadFrom(t.TempDir(), userPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ProjectRoot != "" || len(cfg.Profiles) != 2 {
		t.Errorf("cfg = %+v", cfg)
	}
}

func TestLoadErrors(t *testing.T) {
	cases := []struct {
		name, fixture, want string
	}{
		{"secret nested", "secret_nested.toml", "secret"},
		{"secret top", "secret_top.toml", "secret"},
		{"dsn password", "dsn_password.toml", "password"},
		{"unknown engine", "unknown_engine.toml", "engine"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := installProject(t, c.fixture)
			_, err := LoadFrom(root, "")
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q does not mention %q", err, c.want)
			}
			if strings.Contains(err.Error(), "pw@") || strings.Contains(err.Error(), `"x"`) {
				t.Errorf("error leaks the secret value: %q", err)
			}
		})
	}
}

func TestLoadInlineErrors(t *testing.T) {
	cases := []struct {
		name, body, want string
	}{
		{"secret in limits", "[profiles.a]\nengine=\"mysql\"\nhost=\"h\"\n[profiles.a.limits]\ntoken=\"t\"\n", "secret"},
		{"secret suffix", "[profiles.a]\nengine=\"mysql\"\nhost=\"h\"\ndb_passwd=\"t\"\n", "secret"},
		{"secret table", "[profiles.a]\nengine=\"mysql\"\nhost=\"h\"\n[profiles.a.secret]\nv=1\n", "secret"},
		{"pwd", "pwd=\"t\"\n", "secret"},
		{"url dsn", "[profiles.a]\nengine=\"postgres\"\nhost=\"postgres://u:p@h/db\"\n", "password"},
		{"user dsn", "[profiles.a]\nengine=\"postgres\"\nhost=\"h\"\nuser=\"u:p@h\"\n", "password"},
		{"bad tier", "[profiles.a]\nengine=\"mysql\"\nhost=\"h\"\ntier=\"root\"\n", "tier"},
		{"bad credentials", "[profiles.a]\nengine=\"mysql\"\nhost=\"h\"\ncredentials=\"env\"\n", "credentials"},
		{"bad detector", "[profiles.a]\nengine=\"mysql\"\nhost=\"h\"\ndetectors=[\"dna\"]\n", "detector"},
		{"negative limit", "[profiles.a]\nengine=\"mysql\"\nhost=\"h\"\n[profiles.a.limits]\nmax_rows=-1\n", "max_rows"},
		{"warn above refuse", "[profiles.a]\nengine=\"mysql\"\nhost=\"h\"\n[profiles.a.limits]\nexplain_rows_warn=10\nexplain_rows_refuse=5\n", "explain_rows_warn"},
		{"sqlite no path", "[profiles.a]\nengine=\"sqlite\"\n", "path"},
		{"mysql no host", "[profiles.a]\nengine=\"mysql\"\n", "host"},
		{"bad name", "[profiles.\"a/b\"]\nengine=\"mysql\"\nhost=\"h\"\n", "name"},
		{"unknown key", "[profiles.a]\nengine=\"mysql\"\nhost=\"h\"\nmax_row=5\n", "max_row"},
		{"bad toml", "[profiles.a\n", "invalid TOML at line "},
		{"control in host", "[profiles.a]\nengine=\"mysql\"\nhost=\"db\\u001b[2K\"\n", "control"},
		{"bidi in database", "[profiles.a]\nengine=\"mysql\"\nhost=\"h\"\ndatabase=\"a\\u202eb\"\n", "control"},
		{"control in sqlite path", "[profiles.a]\nengine=\"sqlite\"\npath=\"a\\u0007.db\"\n", "control"},
		{"production named y", "[profiles.y]\nengine=\"mysql\"\nhost=\"h\"\nproduction=true\n", "production"},
		{"production named yes", "[profiles.YES]\nengine=\"mysql\"\nhost=\"h\"\nproduction=true\n", "production"},
		{"type mismatch", "[profiles.a]\nengine=\"mysql\"\nhost=\"h\"\nport=\"x\"\n", "line 4 (last key \"profiles.a.port\")"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			p := filepath.Join(root, ".locksql", "config.toml")
			if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(c.body), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := LoadFrom(root, "")
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q does not mention %q", err, c.want)
			}
		})
	}
}

func TestEmptyDetectorsKept(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, ".locksql", "config.toml")
	_ = os.MkdirAll(filepath.Dir(p), 0o700)
	_ = os.WriteFile(p, []byte("[profiles.a]\nengine=\"mysql\"\nhost=\"h\"\ndetectors=[]\n"), 0o600)
	cfg, err := LoadFrom(root, "")
	if err != nil {
		t.Fatal(err)
	}
	if d := cfg.Profiles["a"].Detectors; len(d) != 0 {
		t.Errorf("explicit empty detectors replaced by %v", d)
	}
}

func TestTier(t *testing.T) {
	for _, s := range []string{"read", "write", "ddl", "admin"} {
		tier, err := ParseTier(s)
		if err != nil || tier.String() != s {
			t.Errorf("ParseTier(%q) = %v, %v", s, tier, err)
		}
	}
	if !(TierRead < TierWrite && TierWrite < TierDDL && TierDDL < TierAdmin) {
		t.Error("tier order broken")
	}
	if _, err := ParseTier("root"); err == nil {
		t.Error("ParseTier(root) should fail")
	}
}

func TestProjectHash(t *testing.T) {
	h := ProjectHash("/some/root")
	if len(h) != 8 || strings.Trim(h, "0123456789abcdef") != "" {
		t.Errorf("ProjectHash = %q", h)
	}
	if h != ProjectHash("/some/root/") || h == ProjectHash("/other/root") {
		t.Error("ProjectHash must be stable on the cleaned path and differ between roots")
	}
}

func TestProjectKey(t *testing.T) {
	root := installProject(t, "basic.toml")
	sub := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := ProjectKey(sub); got != ProjectHash(root) {
		t.Errorf("ProjectKey(sub) = %q, want %q", got, ProjectHash(root))
	}
	if got := ProjectKey(t.TempDir()); got != "user" {
		t.Errorf("ProjectKey outside a project = %q, want user", got)
	}
}
