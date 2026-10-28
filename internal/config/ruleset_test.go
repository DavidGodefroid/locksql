package config

import (
	"strings"
	"testing"
)

func parseOne(t *testing.T, name, extra string) (Profile, error) {
	t.Helper()
	body := "[profiles.\"" + name + "\"]\nengine=\"mysql\"\nhost=\"/run/db.sock\"\n" + extra
	ps, err := ParseProfiles([]byte(body), "config.toml", t.TempDir())
	if err != nil {
		return Profile{}, err
	}
	return ps[name], nil
}

func TestPIIRulesKey(t *testing.T) {
	p, err := parseOne(t, "shop-dev", "pii_rules = \"shop\"\n")
	if err != nil {
		t.Fatal(err)
	}
	if p.PIIRules != "shop" || RuleSetOf(p) != "shop" {
		t.Fatalf("PIIRules = %q, RuleSetOf = %q", p.PIIRules, RuleSetOf(p))
	}
	// Without the key the set is the profile's name, lower-cased so that
	// it names the same file on every file system.
	p, err = parseOne(t, "Billing.EU", "")
	if err != nil {
		t.Fatal(err)
	}
	if p.PIIRules != "" || RuleSetOf(p) != "billing.eu" {
		t.Fatalf("PIIRules = %q, RuleSetOf = %q", p.PIIRules, RuleSetOf(p))
	}
}

func TestPIIRulesKeyValidated(t *testing.T) {
	for _, bad := range []string{"../etc", "a/b", `a\b`, ".hidden", "-x", "Shop", "a b", "", strings.Repeat("a", 65)} {
		if _, err := parseOne(t, "app", "pii_rules = \""+strings.ReplaceAll(bad, `\`, `\\`)+"\"\n"); err == nil {
			t.Errorf("pii_rules %q accepted", bad)
		} else if !strings.Contains(err.Error(), "pii_rules") {
			t.Errorf("pii_rules %q: error does not name the key: %v", bad, err)
		}
	}
	for _, good := range []string{"shop", "default", "a", "shop_eu-2", "v1.2", strings.Repeat("a", 64)} {
		if _, err := parseOne(t, "app", "pii_rules = \""+good+"\"\n"); err != nil {
			t.Errorf("pii_rules %q refused: %v", good, err)
		}
	}
}

func TestDiffPIIRules(t *testing.T) {
	a := fullPolicy()
	a.Profile.PIIRules = "shop"
	c := clonePolicy(a)
	if ch := Diff(a, c); len(ch) != 0 {
		t.Fatalf("same set: %+v", ch)
	}
	// Another set can drop masks, now or later: always a loosening, even
	// when both sets hold the same rules today.
	c.Profile.PIIRules = "billing"
	ch := Diff(a, c)
	if len(ch) != 1 || ch[0].Field != "pii_rules" || ch[0].Old != "shop" || ch[0].New != "billing" || !ch[0].Loosens {
		t.Fatalf("changes = %+v", ch)
	}
	// Approved before named sets: the rules came from the shared pii.toml,
	// and the rule lists show what differs.
	a.Profile.PIIRules = ""
	if ch := Diff(a, c); len(ch) != 0 {
		t.Fatalf("legacy approval: %+v", ch)
	}
}

// A policy approved before named sets keeps its fingerprint.
func TestFingerprintWithoutPIIRules(t *testing.T) {
	p := fullPolicy()
	before := Fingerprint(p)
	p.Profile.PIIRules = ""
	if Fingerprint(p) != before {
		t.Fatal("empty pii_rules changed the fingerprint")
	}
	p.Profile.PIIRules = "shop"
	if Fingerprint(p) == before {
		t.Fatal("pii_rules not in the fingerprint")
	}
}
