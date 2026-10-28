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

// A pii directory that is a symbolic link is refused: set files would be
// read and written where it points.
func TestSetsDirLinkRefused(t *testing.T) {
	dir := t.TempDir()
	if err := CheckSetsDir(dir); err != nil {
		t.Fatalf("missing dir: %v", err)
	}
	elsewhere := t.TempDir()
	if err := os.Symlink(elsewhere, filepath.Join(dir, SetsDir)); err != nil {
		t.Skip("no symbolic links:", err)
	}
	if err := CheckSetsDir(dir); err == nil {
		t.Fatal("linked pii directory accepted")
	}
	if err := os.WriteFile(filepath.Join(dir, LegacyFile), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := MigrateLegacy(dir); err == nil {
		t.Fatal("migrated through a linked pii directory")
	}
	if entries, _ := os.ReadDir(elsewhere); len(entries) != 0 {
		t.Fatalf("written through the link: %v", entries)
	}
}

// Two consoles starting together both see pii.toml; the one that renames
// second finds it gone. That is no error: the other one moved it.
func TestMigrateLegacyRace(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, LegacyFile), []byte("[[mask]]\ncolumn = \"a.b.c\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := rename
	t.Cleanup(func() { rename = old })
	rename = func(from, to string) error {
		if err := os.Rename(from, to); err != nil { // the other console
			return err
		}
		return os.Rename(from, to)
	}
	from, to, err := MigrateLegacy(dir)
	if err != nil || from != "" || to != "" {
		t.Fatalf("lost race: %q %q %v", from, to, err)
	}
	if r := mustLoad(t, filepath.Join(dir, SetsDir, DefaultSet+".toml")); len(r.Mask) != 1 {
		t.Fatalf("default set = %+v", r)
	}
}

func mustLoad(t *testing.T, path string) Rules {
	t.Helper()
	r, err := LoadRulesFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// ENOENT is only the other console's move when the default set is there
// afterwards; otherwise the error stands.
func TestMigrateLegacyVanished(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, LegacyFile), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	old := rename
	t.Cleanup(func() { rename = old })
	rename = func(from, to string) error {
		if err := os.Remove(from); err != nil { // deleted, not moved
			return err
		}
		return os.Rename(from, to)
	}
	if _, _, err := MigrateLegacy(dir); err == nil {
		t.Fatal("vanished pii.toml without a default set: no error")
	}
}
