package pii

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A '*' at the start or the end of a segment matches any run of characters,
// so one rule covers every column that looks like an e-mail.
func TestWildcardInSegment(t *testing.T) {
	cases := []struct {
		pat, name string
		want      bool
	}{
		{"*email*", "email_backup", true},
		{"*email*", "contact_email", true},
		{"*email*", "Email", true},
		{"*email*", "email2", true},
		{"*email*", "mail", false},
		{"email*", "email_backup", true},
		{"email*", "contact_email", false},
		{"*email", "contact_email", true},
		{"*email", "email_backup", false},
		{"*email", "EMAIL", true},
		{"email", "email_backup", false},
		{"*", "anything", true},
		{"*ü*", "MÜLLER_ü", true},
	}
	for _, c := range cases {
		if got := segMatch(c.pat, c.name); got != c.want {
			t.Errorf("segMatch(%q, %q) = %v, want %v", c.pat, c.name, got, c.want)
		}
	}
}

func TestWildcardRules(t *testing.T) {
	var r Rules
	for _, ok := range []string{"*.*.*email*", "app.user*.phone", "*.*.email*", "*.*_log.*"} {
		if err := r.Add(ok); err != nil {
			t.Errorf("Add(%q) = %v", ok, err)
		}
	}
	if err := r.AddAllow("*.*.*name*"); err != nil {
		t.Errorf("AddAllow = %v", err)
	}
	for _, c := range []struct {
		db, table, col string
		mask, cover    bool
	}{
		{"app", "users", "email_backup", true, true},
		{"app", "users", "contact_email", true, true},
		{"app", "users", "Email", true, true},
		{"app", "users_old", "phone", true, true},
		{"app", "orders", "phone", false, false},
		{"app", "audit_log", "id", true, true},
		{"app", "users", "email_name", false, true}, // the allow beats the mask
		{"app", "users", "username", false, true},
		{"app", "users", "status", false, false},
	} {
		if got := r.Matches(c.db, c.table, c.col); got != c.mask {
			t.Errorf("Matches(%s.%s.%s) = %v, want %v", c.db, c.table, c.col, got, c.mask)
		}
		if got := r.Covered(c.db, c.table, c.col); got != c.cover {
			t.Errorf("Covered(%s.%s.%s) = %v, want %v", c.db, c.table, c.col, got, c.cover)
		}
	}
	if !r.MatchesName("contact_email") {
		t.Error("MatchesName(contact_email) = false")
	}
	if r.MatchesName("display_name") {
		t.Error("MatchesName(display_name) = true, want false (no mask matches it)")
	}
	if r.MatchesName("email_name") {
		t.Error("MatchesName(email_name) = true; the *.*.*name* allow exempts it everywhere")
	}
}

// A non-ASCII column name or pattern character keeps the loose match of
// MatchesName (servers fold identifiers by collation) with a wildcard too.
func TestWildcardLooseName(t *testing.T) {
	r := Rules{Mask: []string{"*.*.*courriél*"}}
	if !r.MatchesName("old_courriel_2") {
		t.Error("MatchesName(old_courriel_2) = false; a non-ASCII pattern character matches any character")
	}
	if r.MatchesName("old_courrier") {
		t.Error("MatchesName(old_courrier) = true")
	}
}

func TestWildcardRoundTrip(t *testing.T) {
	root := t.TempDir()
	r := Rules{Mask: []string{"*.*.*email*"}, Allow: []string{"app.*.*_name"}}
	if err := SaveRules(root, r); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, RulesFile))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "*email*") || !strings.Contains(string(raw), "prefix") {
		t.Errorf("file does not document in-segment wildcards:\n%s", raw)
	}
	got, err := LoadRules(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Mask) != 1 || got.Mask[0] != "*.*.*email*" || len(got.Allow) != 1 || got.Allow[0] != "app.*.*_name" {
		t.Errorf("round trip = %+v", got)
	}
}
