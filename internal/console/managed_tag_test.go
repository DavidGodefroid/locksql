//go:build lockfamily_managed_test

package console

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/managed"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/pii"
)

// placeManaged makes body the machine's managed file for the test.
func placeManaged(t *testing.T, body string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), managed.FileName)
	if err := os.WriteFile(path, []byte("version = 1\norganisation = \"Acme\"\n"+body), 0o644); err != nil {
		t.Fatal(err)
	}
	managed.SetTestPath(path)
	t.Cleanup(func() { managed.SetTestPath("") })
}

// A managed pii_mask masks its column under every profile, whatever its
// rule set; a user allow rule on it is refused at load, a user mask of
// another column is kept.
func TestManagedPIIMaskEveryProfile(t *testing.T) {
	placeManaged(t, "[[locksql.bounds.pii_mask]]\ncolumn = \"app.users.email\"\nmode = \"email\"\n")
	root, dir := setsProject(t)
	for _, profile := range []string{"shop-dev", "billing", "Reports"} {
		_, path, pol := resolved(t, root, dir, profile, nil)
		if !slices.Contains(pol.PIIMask, "app.users.email") || pol.PIIModes["app.users.email"] != "email" {
			t.Fatalf("%s: mask %v modes %v", profile, pol.PIIMask, pol.PIIModes)
		}
		var r pii.Rules
		_ = r.Add("app.orders.note")
		if err := pii.SaveRulesFile(path, r); err != nil {
			t.Fatal(err)
		}
		if _, _, pol = resolved(t, root, dir, profile, nil); !slices.Contains(pol.PIIMask, "app.orders.note") || !slices.Contains(pol.PIIMask, "app.users.email") {
			t.Fatalf("%s with its own mask: %v", profile, pol.PIIMask)
		}
		_ = r.AddAllow("*.users.email")
		if err := pii.SaveRulesFile(path, r); err != nil {
			t.Fatal(err)
		}
		cfg, err := config.LoadFrom(root, "")
		if err != nil {
			t.Fatal(err)
		}
		set, path, err := resolveRuleSet(dir, cfg.Profiles[profile], nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = policyFromFiles(root, profile, path, set)
		if err == nil || !strings.Contains(err.Error(), "locksql.bounds.pii_mask app.users.email") {
			t.Fatalf("%s: allow over the managed mask: %v", profile, err)
		}
	}
}

// managed check reads the profiles' policies as the console does: the
// managed mask in, an allow over it refused.
func TestManagedCheckPolicies(t *testing.T) {
	placeManaged(t, "[locksql.bounds]\ntier = \"read\"\n[[locksql.bounds.pii_mask]]\ncolumn = \"app.users.email\"\n")
	root, _ := setsProject(t)
	cfg, err := config.LoadFrom(root, "")
	if err != nil {
		t.Fatal(err)
	}
	lines, err := ManagedCheck(cfg, []string{"billing", "shop-dev"})
	if err != nil || len(lines) != 0 {
		t.Fatalf("lines %q err %v", lines, err)
	}
}
