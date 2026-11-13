package config

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/managed"
)

// parseManaged parses a managed file's bytes and locksql's part of it.
func parseManaged(t *testing.T, body string) (*Managed, error) {
	t.Helper()
	f, err := managed.Parse([]byte("version = 1\norganisation = \"Acme\"\n" + body))
	if err != nil {
		t.Fatalf("managed.Parse: %v", err)
	}
	return ParseManaged(f)
}

func mustManaged(t *testing.T, body string) *Managed {
	t.Helper()
	m, err := parseManaged(t, body)
	if err != nil {
		t.Fatalf("ParseManaged: %v", err)
	}
	return m
}

// devProfile is a profile of a config file, built as Load builds it.
func devProfile(t *testing.T, body string) Profile {
	t.Helper()
	ps, err := ParseProfiles([]byte("[profiles.dev]\n"+body), "config.toml", t.TempDir())
	if err != nil {
		t.Fatalf("ParseProfiles: %v", err)
	}
	return ps["dev"]
}

const devBase = "engine = \"postgres\"\nhost = \"db.example.internal\"\n"

// violations checks p (with no PII rules) against the bounds of body.
func violations(t *testing.T, body string, p Profile) []string {
	t.Helper()
	m := mustManaged(t, body)
	lines, err := m.Bounds.Violations(NewPolicy(p, nil, nil))
	if err != nil {
		t.Fatalf("Violations: %v", err)
	}
	return lines
}

// One row of the bounds table each: a profile beyond the bound is refused
// citing the managed key, the bound and the profile's value.
func TestManagedBoundsEveryRow(t *testing.T) {
	for _, tc := range []struct {
		name, bounds, profile, want string
	}{
		{"production", "production = true", "", "locksql.bounds.production = true (profile dev: production = false)"},
		{"tier", `tier = "write"`, `tier = "ddl"`, "locksql.bounds.tier = write (profile dev: tier = ddl)"},
		{"tls", `tls = "verify-full"`, `tls = "require"`, "locksql.bounds.tls = verify-full (profile dev: tls = require)"},
		{"write_functions", `write_functions = "allowlist"`, "", "locksql.bounds.write_functions = allowlist (profile dev: write_functions = denylist)"},
		{"credentials_ttl", `credentials_ttl = "1h"`, `credentials_ttl = "2h"`, "locksql.bounds.credentials_ttl = 1h0m0s (profile dev: credentials_ttl = 2h0m0s)"},
		{"credentials_ttl unset", `credentials_ttl = "1h"`, "", "locksql.bounds.credentials_ttl = 1h0m0s (profile dev: credentials_ttl = 0s)"},
		{"auto.connect", "auto.connect = \"ask\"", `auto = "full-auto"`, "locksql.bounds.auto.connect = ask (profile dev: auto.connect = auto)"},
		{"auto.read", "auto.read = \"ask\"", "", "locksql.bounds.auto.read = ask (profile dev: auto.read = auto)"},
		{"auto.write", "auto.write = \"deny\"", "", "locksql.bounds.auto.write = deny (profile dev: auto.write = ask)"},
		{"auto.ddl", "auto.ddl = \"deny\"", "", "locksql.bounds.auto.ddl = deny (profile dev: auto.ddl = ask)"},
		{"auto.unmask", "auto.unmask = \"deny\"", "", "locksql.bounds.auto.unmask = deny (profile dev: auto.unmask = ask)"},
		{"statement_timeout", "limits.statement_timeout = \"10s\"", "", "locksql.bounds.limits.statement_timeout = 10s (profile dev: limits.statement_timeout = 30s)"},
		{"max_rows", "limits.max_rows = 100", "", "locksql.bounds.limits.max_rows = 100 (profile dev: limits.max_rows = 200)"},
		{"max_cell_chars", "limits.max_cell_chars = 100", "", "locksql.bounds.limits.max_cell_chars = 100 (profile dev: limits.max_cell_chars = 200)"},
		{"max_output_bytes", "limits.max_output_bytes = 1000", "", "locksql.bounds.limits.max_output_bytes = 1000 (profile dev: limits.max_output_bytes = 65536)"},
		{"explain_rows_refuse", "limits.explain_rows_refuse = 1000", "", "locksql.bounds.limits.explain_rows_refuse = 1000 (profile dev: limits.explain_rows_refuse = 1000000)"},
		{"k_anonymity", "limits.k_anonymity = 20", "", "locksql.bounds.limits.k_anonymity = 20 (profile dev: limits.k_anonymity = 5)"},
		{"idle_timeout", "limits.idle_timeout = \"5m\"", "", "locksql.bounds.limits.idle_timeout = 5m0s (profile dev: limits.idle_timeout = 20m0s)"},
		{"max_session", "limits.max_session = \"1h\"", "", "locksql.bounds.limits.max_session = 1h0m0s (profile dev: limits.max_session = 4h0m0s)"},
		{"grant_max_duration", "limits.grant_max_duration = \"10m\"", "", "locksql.bounds.limits.grant_max_duration = 10m0s (profile dev: limits.grant_max_duration = 1h0m0s)"},
		{"grants off", "limits.grant_max_duration = 0", "", "locksql.bounds.limits.grant_max_duration = 0 (grants off) (profile dev: limits.grant_max_duration = 1h0m0s)"},
		{"grant_max_statements", "limits.grant_max_statements = 10", "", "locksql.bounds.limits.grant_max_statements = 10 (profile dev: limits.grant_max_statements = 200)"},
		{"grant_max_rows", "limits.grant_max_rows = 10", "", "locksql.bounds.limits.grant_max_rows = 10 (profile dev: limits.grant_max_rows = 10000)"},
		{"grant_max_bytes", "limits.grant_max_bytes = 10", "", "locksql.bounds.limits.grant_max_bytes = 10 (profile dev: limits.grant_max_bytes = 1048576)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := devProfile(t, devBase+tc.profile+"\n")
			got := violations(t, "[locksql.bounds]\n"+tc.bounds+"\n", p)
			want := "blocked by company policy: " + tc.want
			if len(got) != 1 || got[0] != want {
				t.Fatalf("violations = %q\nwant [%q]", got, want)
			}
		})
	}
}

// A profile stricter than, or equal to, every bound has no violation.
func TestManagedBoundsStricterProfile(t *testing.T) {
	bounds := `[locksql.bounds]
production = true
tier = "write"
tls = "verify-ca"
credentials = ["vault", "ask"]
engine = ["postgres"]
hosts = ["*.example.internal"]
write_functions = "allowlist"
credentials_ttl = "1h"
auto = { connect = "ask", read = "auto", write = "ask", ddl = "deny", unmask = "ask" }
detectors = ["fr_nir"]

[locksql.bounds.limits]
statement_timeout = "10s"
max_rows = 100
max_cell_chars = 100
max_output_bytes = 10000
explain_rows_refuse = 100000
k_anonymity = 10
idle_timeout = "10m"
max_session = "2h"
grant_max_duration = "30m"
grant_max_statements = 100
grant_max_rows = 1000
grant_max_bytes = 1000
`
	p := devProfile(t, devBase+`production = true
tier = "read"
write_functions = "allowlist"
credentials_ttl = "30m"
auto = { ddl = "deny", read = "ask" }
detectors = ["email", "fr_nir"]

[profiles.dev.limits]
statement_timeout = "5s"
max_rows = 50
max_cell_chars = 100
max_output_bytes = 5000
explain_rows_refuse = 1000
explain_rows_warn = 100
k_anonymity = 20
idle_timeout = "5m"
max_session = "1h"
grant_max_duration = "0"
grant_max_statements = 10
grant_max_rows = 10
grant_max_bytes = 10
`)
	p.TLS = TLSVerifyFull
	if got := violations(t, bounds, p); len(got) != 0 {
		t.Fatalf("violations = %q, want none", got)
	}
}

// The allowlists Diff cannot express refuse a value outside the list,
// naming the managed key, and accept one inside it.
func TestManagedBoundsAllowlists(t *testing.T) {
	ssh := "\n[profiles.dev.ssh]\nhost = \"bastion.example.internal\"\nuser = \"u\"\nauth = \"agent\"\n"
	for _, tc := range []struct {
		name, bounds, profile, want string
	}{
		{"credentials in", `credentials = ["vault", "ask"]`, "", ""},
		{"credentials out", `credentials = ["vault"]`, "", "locksql.bounds.credentials does not allow ask (profile dev: credentials + ask)"},
		{"engine in", `engine = ["postgres", "mysql"]`, "", ""},
		{"engine out", `engine = ["mysql"]`, "", "locksql.bounds.engine does not allow postgres (profile dev: engine + postgres)"},
		{"hosts in", `hosts = ["*.example.internal"]`, ssh, ""},
		{"hosts out", `hosts = ["*.db.other.com"]`, "", "locksql.bounds.hosts does not allow db.example.internal (profile dev: host + db.example.internal)"},
		{"ssh host out", `hosts = ["db.example.internal"]`, ssh, "locksql.bounds.hosts does not allow bastion.example.internal (profile dev: ssh.host + bastion.example.internal)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := devProfile(t, devBase+tc.profile)
			got := violations(t, "[locksql.bounds]\n"+tc.bounds+"\n", p)
			if tc.want == "" {
				if len(got) != 0 {
					t.Fatalf("violations = %q, want none", got)
				}
				return
			}
			want := "blocked by company policy: " + tc.want
			if len(got) != 1 || got[0] != want {
				t.Fatalf("violations = %q\nwant [%q]", got, want)
			}
			// The console gets them as an error naming the key, without the
			// lead it adds itself.
			m := mustManaged(t, "[locksql.bounds]\n"+tc.bounds+"\n")
			_, _, err := m.Bounds.Ceiling(NewPolicy(p, nil, nil))
			if err == nil || err.Error() != tc.want {
				t.Fatalf("Ceiling err = %v, want %q", err, tc.want)
			}
		})
	}
}

// [family] vault.required acts as credentials = ["vault"], cited as
// family.vault.required.
func TestManagedVaultRequired(t *testing.T) {
	body := "[family.vault]\naddress = \"https://vault.example.internal\"\nrequired = true\n"
	got := violations(t, body, devProfile(t, devBase))
	want := "blocked by company policy: family.vault.required = true (profile dev: credentials = ask)"
	if len(got) != 1 || got[0] != want {
		t.Fatalf("violations = %q, want [%q]", got, want)
	}
	vault := devProfile(t, devBase+"credentials = \"vault\"\nvault_path = \"database/creds/ro\"\n")
	if got := violations(t, body, vault); len(got) != 0 {
		t.Fatalf("vault profile: violations = %q", got)
	}
}

func TestManagedBoundsInvalid(t *testing.T) {
	for name, body := range map[string]string{
		"tier":        `tier = "root"`,
		"tls":         `tls = "maybe"`,
		"credentials": `credentials = ["plain"]`,
		"engine":      `engine = ["oracle"]`,
		"hosts":       `hosts = ["["]`,
		"auto":        `auto.fly = "ask"`,
		"detectors":   `detectors = ["dna"]`,
		"mask mode":   "[[locksql.bounds.pii_mask]]\ncolumn = \"db.t.c\"\nmode = \"blur\"",
		"mask column": "[[locksql.bounds.pii_mask]]\ncolumn = \"db.t\"",
		"unknown key": `color = "red"`,
		"max_rows":    `limits.max_rows = 0`,
	} {
		if !strings.HasPrefix(body, "[[") {
			body = "[locksql.bounds]\n" + body
		}
		if _, err := parseManaged(t, body+"\n"); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

// A managed profile is served as written; a user or project profile of its
// name is refused; a managed profile beyond the bounds is a load error.
func TestManagedProfiles(t *testing.T) {
	body := `[locksql.bounds]
tier = "write"

[locksql.profiles.prod-erp]
engine = "postgres"
host = "erp.example.internal"
database = "erp"
tier = "read"
production = true
`
	m := mustManaged(t, body)
	p, ok := m.Profiles["prod-erp"]
	if !ok || p.Host != "erp.example.internal" || p.Tier != TierRead || !p.Production || p.Limits.MaxRows != 200 {
		t.Fatalf("managed profile = %+v", p)
	}

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".locksql"), 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(path, s string) {
		if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(dir, ".locksql", "config.toml"), "[profiles.dev]\n"+devBase)
	user := filepath.Join(t.TempDir(), "config.toml")
	write(user, "[profiles.mine]\n"+devBase)
	cfg, err := LoadWith(dir, user, m)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Profiles) != 3 || cfg.Profiles["prod-erp"].Host != "erp.example.internal" || cfg.Managed != m {
		t.Fatalf("profiles = %v", cfg.Profiles)
	}
	for _, where := range []string{"project", "user"} {
		path := user
		if where == "project" {
			path = filepath.Join(dir, ".locksql", "config.toml")
		}
		write(path, "[profiles.prod-erp]\n"+devBase)
		_, err := LoadWith(dir, user, m)
		if err == nil || !strings.Contains(err.Error(), `profile "prod-erp" is provided by the company's managed configuration`) || !strings.Contains(err.Error(), where) {
			t.Fatalf("%s profile prod-erp: err = %v", where, err)
		}
		write(path, "[profiles.dev]\n"+devBase)
	}

	_, err = parseManaged(t, strings.Replace(body, `tier = "read"`, `tier = "ddl"`, 1))
	if err == nil || !strings.Contains(err.Error(), "[locksql.profiles.prod-erp]") || !strings.Contains(err.Error(), "locksql.bounds.tier = write (profile prod-erp: tier = ddl)") {
		t.Fatalf("profile beyond the bounds: err = %v", err)
	}
	if _, err := parseManaged(t, "[locksql.profiles.x]\nengine = \"postgres\"\nhost = \"h\"\ncolour = 1\n"); err == nil {
		t.Fatal("unknown key in a managed profile: no error")
	}
}

// A managed default applies when the profile omits the key; a value of the
// config file within the bounds wins; a default beyond the bounds is a
// load error.
func TestManagedDefaults(t *testing.T) {
	m := mustManaged(t, `[locksql.bounds]
limits.max_rows = 500

[locksql.defaults]
tier = "write"
detectors = ["email", "be_niss"]

[locksql.defaults.limits]
max_rows = 100
statement_timeout = "5s"
`)
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".locksql"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfgFile := "[profiles.a]\n" + devBase + "\n[profiles.b]\n" + devBase + "tier = \"read\"\n[profiles.b.limits]\nmax_rows = 300\n"
	if err := os.WriteFile(filepath.Join(dir, ".locksql", "config.toml"), []byte(cfgFile), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadWith(dir, "", m)
	if err != nil {
		t.Fatal(err)
	}
	a, b := cfg.Profiles["a"], cfg.Profiles["b"]
	if a.Tier != TierWrite || a.Limits.MaxRows != 100 || a.Limits.StatementTimeout.String() != "5s" || strings.Join(a.Detectors, ",") != "email,be_niss" {
		t.Fatalf("a = %+v", a)
	}
	if b.Tier != TierRead || b.Limits.MaxRows != 300 || b.Limits.StatementTimeout.String() != "5s" {
		t.Fatalf("b = %+v", b)
	}
	if got := m.DescribeDefaults(); strings.Join(got, "|") != `locksql.defaults.detectors = ["email", "be_niss"]|locksql.defaults.limits.max_rows = 100|locksql.defaults.limits.statement_timeout = "5s"|locksql.defaults.tier = "write"` {
		t.Fatalf("DescribeDefaults = %q", got)
	}

	_, err = parseManaged(t, "[locksql.bounds]\ntier = \"read\"\n[locksql.defaults]\ntier = \"write\"\n")
	if err == nil || !strings.Contains(err.Error(), "[locksql.defaults]") || !strings.Contains(err.Error(), "locksql.bounds.tier = read (defaults: tier = write)") {
		t.Fatalf("default beyond the bounds: err = %v", err)
	}
	// A bound the defaults do not set is no error of theirs.
	if _, err := parseManaged(t, "[locksql.bounds]\ntier = \"read\"\n[locksql.defaults]\nlimits.max_rows = 10\n"); err != nil {
		t.Fatalf("defaults within the bounds: %v", err)
	}
}

// A managed pii_mask masks its column under every profile; a user allow
// rule on it is refused, a user mask of another column is accepted.
func TestManagedPIIMask(t *testing.T) {
	m := mustManaged(t, "[[locksql.bounds.pii_mask]]\ncolumn = \"db.users.email\"\n\n[[locksql.bounds.pii_mask]]\ncolumn = \"db.users.phone\"\nmode = \"partial\"\n")
	b := m.Bounds
	mask, allow, modes, err := b.ApplyPII([]string{"db.orders.note"}, []string{"db.orders.id"}, map[string]string{"db.users.phone": "email"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(mask, ",") != "db.orders.note,db.users.email,db.users.phone" || strings.Join(allow, ",") != "db.orders.id" || modes["db.users.phone"] != "partial" {
		t.Fatalf("mask %v allow %v modes %v", mask, allow, modes)
	}
	for _, a := range []string{"db.users.email", "*.*.email", "db.users.*", "*.*.*mail"} {
		_, _, _, err := b.ApplyPII(nil, []string{a}, nil)
		if err == nil || !strings.Contains(err.Error(), "locksql.bounds.pii_mask db.users.email") {
			t.Errorf("allow %s: err = %v", a, err)
		}
	}
	if _, _, _, err := b.ApplyPII(nil, []string{"db.users.name", "*.*.email_verified"}, nil); err != nil {
		t.Fatalf("allow on other columns: %v", err)
	}
	// Bounds check: a policy without the managed mask, or whose mode of it
	// is weaker, is beyond them.
	p := devProfile(t, devBase)
	lines, err := b.Violations(NewPolicy(p, []string{"db.users.phone"}, nil).WithModes(map[string]string{"db.users.phone": "partial"}))
	if err != nil || len(lines) != 1 || lines[0] != "blocked by company policy: locksql.bounds.pii_mask requires db.users.email (profile dev: pii.mask - db.users.email)" {
		t.Fatalf("missing mask: %q %v", lines, err)
	}
	full, allow, modes, _ := b.ApplyPII(nil, nil, nil)
	if lines, _ := b.Violations(NewPolicy(p, full, allow).WithModes(modes)); len(lines) != 0 {
		t.Fatalf("managed rules applied: %q", lines)
	}
}

// Load reads the managed file: nil means none, and the behaviour is the
// one without managed configuration.
func TestLoadReadsManaged(t *testing.T) {
	defer func(f func(context.Context) (*managed.File, error)) { loadManaged = f }(loadManaged)
	loadManaged = func(context.Context) (*managed.File, error) { return nil, nil }
	dir := installProject(t, "basic.toml")
	cfg, err := LoadFrom(dir, "")
	if err != nil || cfg.Managed != nil {
		t.Fatalf("no managed file: cfg %+v err %v", cfg, err)
	}
	loadManaged = func(context.Context) (*managed.File, error) {
		return managed.Parse([]byte("version = 1\n[locksql.bounds]\ndetectors = [\"fr_nir\"]\n"))
	}
	cfg, err = LoadFrom(dir, "")
	if err != nil || cfg.Managed == nil {
		t.Fatalf("managed file: err %v", err)
	}
	for n, p := range cfg.Profiles {
		if !strings.Contains(strings.Join(p.Detectors, ","), "fr_nir") {
			t.Errorf("profile %s: detectors %v lack the required fr_nir", n, p.Detectors)
		}
	}
}

func TestPIIPatternsOverlap(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"a.b.c", "a.b.c", true}, {"a.b.c", "A.B.C", true}, {"a.b.c", "a.b.d", false},
		{"*.*.*", "a.b.c", true}, {"a.b.em*", "a.b.email", true}, {"a.b.em*", "a.b.phone", false},
		{"a.b.*il", "a.b.email", true}, {"a.b.*il", "a.b.*ail", true}, {"a.b.*il", "a.b.*ix", false},
		{"a.b.em*", "a.b.e*", true}, {"a.b.em*", "a.b.x*", false}, {"a.b.x*", "a.b.*y", true},
		{"a.b.*m*", "a.b.x*", true},
	} {
		if got := PIIPatternsOverlap(tc.a, tc.b); got != tc.want {
			t.Errorf("Overlap(%s, %s) = %v", tc.a, tc.b, got)
		}
		if got := PIIPatternsOverlap(tc.b, tc.a); got != tc.want {
			t.Errorf("Overlap(%s, %s) = %v", tc.b, tc.a, got)
		}
	}
}
