package console

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/ipc"
	"github.com/DavidGodefroid/locksql/internal/pii"
)

// setsConfig is a project with two profiles on the shop set, one on the
// billing set and one without pii_rules.
const setsConfig = `[profiles.shop-dev]
engine = "mariadb"
host = "db.dev.example.com"
user = "alice"
pii_rules = "shop"

[profiles.shop-uat]
engine = "mariadb"
host = "db.uat.example.com"
user = "alice"
pii_rules = "shop"

[profiles.billing]
engine = "mariadb"
host = "db.billing.example.com"
user = "alice"
pii_rules = "billing"

[profiles.Reports]
engine = "mariadb"
host = "db.reports.example.com"
user = "alice"
`

func setsProject(t *testing.T) (root, dir string) {
	t.Helper()
	root = t.TempDir()
	dir = filepath.Join(root, ".locksql")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(setsConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	return root, dir
}

// resolved is the rule set and policy a console of profile would load.
func resolved(t *testing.T, root, dir, profile string, approved *config.Policy) (string, string, config.Policy) {
	t.Helper()
	cfg, err := config.LoadFrom(root, "")
	if err != nil {
		t.Fatal(err)
	}
	set, path, err := resolveRuleSet(dir, cfg.Profiles[profile], approved)
	if err != nil {
		t.Fatal(err)
	}
	pol, err := policyFromFiles(root, profile, path, set)
	if err != nil {
		t.Fatal(err)
	}
	return set, path, pol
}

func TestRulesDirFor(t *testing.T) {
	if got := rulesDirFor("/work/proj", "/home/u/.config/locksql/config.toml"); got != filepath.Join("/work/proj", ".locksql") {
		t.Errorf("project: %q", got)
	}
	if got := rulesDirFor("", "/home/u/.config/locksql/config.toml"); got != filepath.FromSlash("/home/u/.config/locksql") {
		t.Errorf("user: %q", got)
	}
}

// Profiles on different sets never see each other's rules, wildcard rules
// and allow rules included.
func TestRuleSetsIsolated(t *testing.T) {
	root, dir := setsProject(t)
	shop, _ := pii.SetPath(dir, "shop")
	var r pii.Rules
	for _, pat := range []string{"*.*.recipient_reference", "app.users.email"} {
		if err := r.Add(pat); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.AddAllow("*.*.nickname"); err != nil {
		t.Fatal(err)
	}
	if err := pii.SaveRulesFile(shop, r); err != nil {
		t.Fatal(err)
	}

	set, path, pol := resolved(t, root, dir, "shop-dev", nil)
	if set != "shop" || path != shop || len(pol.PIIMask) != 2 || len(pol.PIIAllow) != 1 || pol.Profile.PIIRules != "shop" {
		t.Fatalf("shop-dev: set %q path %q policy %+v", set, path, pol)
	}
	for _, p := range []string{"billing", "Reports"} {
		set, path, pol := resolved(t, root, dir, p, nil)
		if path == shop || len(pol.PIIMask) != 0 || len(pol.PIIAllow) != 0 {
			t.Errorf("%s (set %q, %s) sees the shop rules: %+v", p, set, path, pol)
		}
	}
	if set, _, _ := resolved(t, root, dir, "Reports", nil); set != "reports" {
		t.Errorf("default set of Reports = %q, want its name", set)
	}
}

// Profiles on the same set share what either console adds.
func TestRuleSetsShared(t *testing.T) {
	root, dir := setsProject(t)
	add := func(profile, pattern string) {
		t.Helper()
		_, path, pol := resolved(t, root, dir, profile, nil)
		h := newHarness(t, pol.Profile, func(c *ServerConfig) {
			c.Policy = pol
			c.RulesPath = path
			c.ApprovedKey = config.ApprovedKey(root, profile)
		})
		h.ok(t, ipc.MethodPIIAdd, ipc.PIIAddParams{Pattern: pattern}, nil)
	}
	add("shop-dev", "app.users.phone")
	add("shop-uat", "app.users.iban")
	for _, p := range []string{"shop-dev", "shop-uat"} {
		_, _, pol := resolved(t, root, dir, p, nil)
		if !slices.Contains(pol.PIIMask, "app.users.phone") || !slices.Contains(pol.PIIMask, "app.users.iban") {
			t.Errorf("%s: mask = %v", p, pol.PIIMask)
		}
	}
	if _, _, pol := resolved(t, root, dir, "billing", nil); len(pol.PIIMask) != 0 {
		t.Errorf("billing sees the shop additions: %v", pol.PIIMask)
	}
}

// The legacy pii.toml becomes the default set, kept by the profiles
// approved before named sets until they name a set.
func TestRuleSetMigration(t *testing.T) {
	root, dir := setsProject(t)
	legacy := filepath.Join(dir, "pii.toml")
	if err := os.WriteFile(legacy, []byte("[[mask]]\ncolumn = \"app.users.email\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	n, err := migrateRules(dir)
	if err != nil {
		t.Fatal(err)
	}
	def, _ := pii.SetPath(dir, pii.DefaultSet)
	if !strings.Contains(n, legacy) || !strings.Contains(n, def) || !strings.Contains(n, "pii_rules") {
		t.Fatalf("notice = %q", n)
	}
	if n, err := migrateRules(dir); err != nil || n != "" {
		t.Fatalf("second start: %q, %v", n, err)
	}

	// Approved before named sets, no pii_rules: the default set.
	cfg, _ := config.LoadFrom(root, "")
	old := config.NewPolicy(cfg.Profiles["Reports"], []string{"app.users.email"}, nil)
	set, path, pol := resolved(t, root, dir, "Reports", &old)
	if set != pii.DefaultSet || path != def || !slices.Contains(pol.PIIMask, "app.users.email") {
		t.Fatalf("legacy profile: set %q path %q mask %v", set, path, pol.PIIMask)
	}
	if ch := config.Diff(old, pol); len(ch) != 0 {
		t.Fatalf("migration asks for approval: %+v", ch)
	}
	// Approved on the default set since: still the default set.
	if set, _, _ := resolved(t, root, dir, "Reports", &pol); set != pii.DefaultSet {
		t.Fatalf("approved on default: set %q", set)
	}
	// An explicit pii_rules wins over the migration.
	shopOld := config.NewPolicy(cfg.Profiles["shop-dev"], nil, nil)
	shopOld.Profile.PIIRules = ""
	if set, _, _ := resolved(t, root, dir, "shop-dev", &shopOld); set != "shop" {
		t.Fatalf("explicit set: %q", set)
	}
	// A profile never approved gets its own set.
	if set, _, _ := resolved(t, root, dir, "Reports", nil); set != "reports" {
		t.Fatalf("new profile: set %q", set)
	}
	// Approved on its own set: the default set is not taken back.
	own := pol
	own.Profile.PIIRules = "reports"
	if set, _, _ := resolved(t, root, dir, "Reports", &own); set != "reports" {
		t.Fatalf("own set: %q", set)
	}
}

// Without a legacy file there is no default set to keep.
func TestRuleSetNoLegacy(t *testing.T) {
	root, dir := setsProject(t)
	cfg, _ := config.LoadFrom(root, "")
	old := config.NewPolicy(cfg.Profiles["Reports"], nil, nil)
	if set, _, _ := resolved(t, root, dir, "Reports", &old); set != "reports" {
		t.Fatalf("set %q", set)
	}
}

// Switching set is a loosening that waits for the human.
func TestRuleSetSwitchLoosens(t *testing.T) {
	root, dir := setsProject(t)
	_, _, before := resolved(t, root, dir, "shop-dev", nil)
	body := strings.Replace(setsConfig, "pii_rules = \"shop\"\n\n[profiles.shop-uat]", "pii_rules = \"billing\"\n\n[profiles.shop-uat]", 1)
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, after := resolved(t, root, dir, "shop-dev", &before)
	ch := config.Diff(before, after)
	if len(ch) != 1 || ch[0].Field != "pii_rules" || !ch[0].Loosens {
		t.Fatalf("changes = %+v", ch)
	}
	if !slices.ContainsFunc(describePolicy(after), func(l string) bool { return strings.Contains(l, `"billing"`) }) {
		t.Errorf("approval screen does not name the set:\n%s", strings.Join(describePolicy(after), "\n"))
	}
}

func TestResolveRuleSetRefusesLinkedDir(t *testing.T) {
	root, dir := setsProject(t)
	if err := os.Symlink(t.TempDir(), filepath.Join(dir, pii.SetsDir)); err != nil {
		t.Skip("no symbolic links:", err)
	}
	cfg, _ := config.LoadFrom(root, "")
	if _, _, err := resolveRuleSet(dir, cfg.Profiles["billing"], nil); err == nil {
		t.Fatal("linked pii directory accepted")
	}
}
