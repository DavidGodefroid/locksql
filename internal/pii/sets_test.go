package pii

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetPath(t *testing.T) {
	dir := filepath.FromSlash("/home/u/.config/locksql")
	got, err := SetPath(dir, "shop")
	if err != nil || got != filepath.Join(dir, "pii", "shop.toml") {
		t.Fatalf("SetPath = %q, %v", got, err)
	}
	for _, bad := range []string{"", "../x", "a/b", `a\b`, ".x", "Shop"} {
		if p, err := SetPath(dir, bad); err == nil {
			t.Errorf("set %q gave %q", bad, p)
		}
	}
}

func TestMigrateLegacy(t *testing.T) {
	dir := t.TempDir()
	// Nothing to migrate.
	if from, to, err := MigrateLegacy(dir); err != nil || from != "" || to != "" {
		t.Fatalf("empty dir: %q %q %v", from, to, err)
	}
	legacy := filepath.Join(dir, "pii.toml")
	body := "[[mask]]\ncolumn = \"app.users.email\"\n"
	if err := os.WriteFile(legacy, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	from, to, err := MigrateLegacy(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(dir, "pii", DefaultSet+".toml")
	if from != legacy || to != want {
		t.Fatalf("from %q to %q, want %q to %q", from, to, legacy, want)
	}
	if b, err := os.ReadFile(want); err != nil || string(b) != body {
		t.Fatalf("default set = %q, %v", b, err)
	}
	if _, err := os.Stat(legacy); err == nil {
		t.Fatal("legacy file still there: it would be migrated again")
	}
	// Once only: a later pii.toml never replaces the default set.
	if err := os.WriteFile(legacy, []byte("mask = []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if from, _, err := MigrateLegacy(dir); err != nil || from != "" {
		t.Fatalf("second migration: %q %v", from, err)
	}
	if b, _ := os.ReadFile(want); string(b) != body {
		t.Fatalf("default set overwritten: %q", b)
	}
}

// A symbolic link in place of pii.toml is not moved into the sets: the
// console would then read a file another account controls.
func TestMigrateLegacyRefusesLink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "x.toml")
	if err := os.WriteFile(target, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "pii.toml")); err != nil {
		t.Skip("no symbolic links:", err)
	}
	if _, _, err := MigrateLegacy(dir); err == nil || !strings.Contains(err.Error(), "pii.toml") {
		t.Fatalf("err = %v", err)
	}
}

func TestSetExists(t *testing.T) {
	dir := t.TempDir()
	if SetExists(dir, "shop") {
		t.Fatal("missing set exists")
	}
	p, _ := SetPath(dir, "shop")
	if err := SaveRulesFile(p, Rules{}); err != nil {
		t.Fatal(err)
	}
	if !SetExists(dir, "shop") {
		t.Fatal("saved set does not exist")
	}
}
