package pii

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestMatches(t *testing.T) {
	r := Rules{Mask: []string{"*.*.email", "*.*.name"}, Allow: []string{"app.t.name"}}
	cases := []struct {
		db, table, col string
		want           bool
	}{
		{"app", "users", "email", true},
		{"other", "x", "EMAIL", true}, // case-insensitive
		{"app", "users", "name", true},
		{"app", "t", "name", false}, // allow beats mask
		{"APP", "T", "Name", false},
		{"app", "users", "status", false},
	}
	for _, c := range cases {
		if got := r.Matches(c.db, c.table, c.col); got != c.want {
			t.Errorf("Matches(%s.%s.%s) = %v, want %v", c.db, c.table, c.col, got, c.want)
		}
	}
}

func TestAddValidates(t *testing.T) {
	var r Rules
	for _, ok := range []string{"app.users.email", "*.*.recipient_reference", "public.*.iban"} {
		if err := r.Add(ok); err != nil {
			t.Errorf("Add(%q) = %v", ok, err)
		}
	}
	if err := r.Add("app.users.email"); err != nil {
		t.Errorf("duplicate Add = %v", err)
	}
	if len(r.Mask) != 3 {
		t.Errorf("Mask = %v, want 3 distinct rules", r.Mask)
	}
	for _, bad := range []string{"", "email", "users.email", "a.b.c.d", "a..c", "a.b*.c", "a.b. c"} {
		if err := r.Add(bad); err == nil {
			t.Errorf("Add(%q) accepted", bad)
		}
	}
}

func TestLoadSaveRules(t *testing.T) {
	root := t.TempDir()
	r, err := LoadRules(root)
	if err != nil || len(r.Mask)+len(r.Allow) != 0 {
		t.Fatalf("LoadRules(no file) = %v, %v", r, err)
	}
	r = Rules{Mask: []string{"app.users.email", "*.*.recipient_reference"}, Allow: []string{"app.templates.name"}}
	if err := SaveRules(root, r); err != nil {
		t.Fatal(err)
	}
	got, err := LoadRules(root)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got.Mask, ",") != "*.*.recipient_reference,app.users.email" || strings.Join(got.Allow, ",") != "app.templates.name" {
		t.Errorf("round trip = %+v", got)
	}
	raw, _ := os.ReadFile(filepath.Join(root, ".locksql", "pii.toml"))
	if !strings.Contains(string(raw), "[[mask]]") || !strings.Contains(string(raw), `column = "app.users.email"`) {
		t.Errorf("file = %s", raw)
	}
}

func TestLoadRulesRefusesBadFiles(t *testing.T) {
	for name, body := range map[string]string{
		"bad pattern": "[[mask]]\ncolumn = \"users.email\"\n",
		"unknown key": "[[mask]]\ncolumn = \"a.b.c\"\nextra = 1\n",
		"bad toml":    "[[mask]\n",
	} {
		root := t.TempDir()
		_ = os.MkdirAll(filepath.Join(root, ".locksql"), 0o755)
		_ = os.WriteFile(filepath.Join(root, ".locksql", "pii.toml"), []byte(body), 0o644)
		if _, err := LoadRules(root); err == nil {
			t.Errorf("%s: LoadRules accepted", name)
		}
	}
}

func TestRulesFileRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "locksql", "pii.toml")
	r := Rules{Mask: []string{"app.users.email"}}
	if err := SaveRulesFile(path, r); err != nil {
		t.Fatal(err)
	}
	got, err := LoadRulesFile(path)
	if err != nil || !slices.Equal(got.Mask, r.Mask) {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestDefaultModeIsRedact(t *testing.T) {
	var r Rules
	if err := r.Add("app.users.email"); err != nil {
		t.Fatal(err)
	}
	if m, ok := r.Mode("app", "users", "email"); !ok || m != ModeRedact {
		t.Fatalf("Mode = %q %v, want redact", m, ok)
	}
	if err := r.AddMode("app.users.name", ModePartial); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "pii.toml")
	if err := SaveRulesFile(path, r); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), "column = \"app.users.name\"\nmode = \"partial\"") {
		t.Errorf("partial not written explicitly:\n%s", b)
	}
	if strings.Contains(string(b), "\nmode = \"redact\"") {
		t.Errorf("the default is written:\n%s", b)
	}
	back, err := LoadRulesFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if m, _ := back.Mode("app", "users", "name"); m != ModePartial {
		t.Errorf("partial lost on reload: %q", m)
	}
}
