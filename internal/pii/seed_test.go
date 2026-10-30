package pii

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The profile's sets reach the console's directory once; a set the
// console holds is never replaced; links, odd names and other files are
// not copied.
func TestSeedSets(t *testing.T) {
	from, to := t.TempDir(), t.TempDir()
	write(t, filepath.Join(from, SetsDir, "shop.toml"), "[[mask]]\ncolumn = \"app.users.email\"\n")
	write(t, filepath.Join(from, SetsDir, "billing.toml"), "# theirs\n")
	write(t, filepath.Join(to, SetsDir, "billing.toml"), "# mine\n")
	write(t, filepath.Join(from, SetsDir, "Bad.toml"), "x")
	write(t, filepath.Join(from, SetsDir, "notes.txt"), "x")
	secret := filepath.Join(t.TempDir(), "secret.toml")
	write(t, secret, "secret")
	if err := os.Symlink(secret, filepath.Join(from, SetsDir, "linked.toml")); err != nil {
		t.Logf("no symbolic link here (%v): the link case is not checked", err)
	}
	got, err := SeedSets(from, to)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{filepath.Join(to, SetsDir, "shop.toml")}; len(got) != 1 || got[0] != want[0] {
		t.Fatalf("seeded %v, want %v", got, want)
	}
	if s := read(t, filepath.Join(to, SetsDir, "shop.toml")); s != "[[mask]]\ncolumn = \"app.users.email\"\n" {
		t.Errorf("shop = %q", s)
	}
	if s := read(t, filepath.Join(to, SetsDir, "billing.toml")); s != "# mine\n" {
		t.Errorf("the console's billing set was replaced: %q", s)
	}
	for _, n := range []string{"Bad.toml", "notes.txt", "linked.toml"} {
		if _, err := os.Lstat(filepath.Join(to, SetsDir, n)); err == nil {
			t.Errorf("%s copied", n)
		}
	}
	// Once: nothing more to copy, even when the profile's set changes.
	write(t, filepath.Join(from, SetsDir, "shop.toml"), "# changed\n")
	if got, err := SeedSets(from, to); err != nil || len(got) != 0 {
		t.Fatalf("second seed: %v, %v", got, err)
	}
}

// The legacy pii.toml of the profile becomes the console's default set
// (the profile's directory is read-only: it is not moved), unless the
// profile has a default set of its own.
func TestSeedSetsLegacy(t *testing.T) {
	from, to := t.TempDir(), t.TempDir()
	write(t, filepath.Join(from, LegacyFile), "# legacy\n")
	if _, err := SeedSets(from, to); err != nil {
		t.Fatal(err)
	}
	if s := read(t, filepath.Join(to, SetsDir, DefaultSet+".toml")); s != "# legacy\n" {
		t.Fatalf("default = %q", s)
	}
	if _, err := os.Stat(filepath.Join(from, LegacyFile)); err != nil {
		t.Fatalf("the legacy file moved: %v", err)
	}

	from, to = t.TempDir(), t.TempDir()
	write(t, filepath.Join(from, LegacyFile), "# legacy\n")
	write(t, filepath.Join(from, SetsDir, DefaultSet+".toml"), "# default\n")
	if _, err := SeedSets(from, to); err != nil {
		t.Fatal(err)
	}
	if s := read(t, filepath.Join(to, SetsDir, DefaultSet+".toml")); s != "# default\n" {
		t.Fatalf("default = %q", s)
	}
}

// A pii that is a link, on either side, is refused.
func TestSeedSetsRefusesLinkedDir(t *testing.T) {
	from, to, other := t.TempDir(), t.TempDir(), t.TempDir()
	if err := os.Symlink(other, filepath.Join(to, SetsDir)); err != nil {
		t.Skipf("no symbolic link here: %v", err)
	}
	if _, err := SeedSets(from, to); err == nil {
		t.Fatal("a linked pii in the console's directory was followed")
	}
	if _, err := SeedSets(to, from); err == nil {
		t.Fatal("a linked pii in the profile's directory was followed")
	}
}

// Missing directories are no error: nothing to seed.
func TestSeedSetsNothing(t *testing.T) {
	got, err := SeedSets(filepath.Join(t.TempDir(), "none"), filepath.Join(t.TempDir(), "none"))
	if err != nil || len(got) != 0 {
		t.Fatalf("%v, %v", got, err)
	}
}

func TestSameRules(t *testing.T) {
	var a, b Rules
	_ = a.Add("app.users.email")
	_ = a.Add("app.users.phone")
	_ = b.Add("app.users.phone")
	_ = b.Add("app.users.email")
	if !SameRules(a, b) {
		t.Fatal("order matters")
	}
	_ = b.AddAllow("app.users.nick")
	if SameRules(a, b) {
		t.Fatal("an allow rule is no difference")
	}
	var c Rules
	_ = c.AddMode("app.users.email", ModeEmail)
	_ = c.Add("app.users.phone")
	if SameRules(a, c) {
		t.Fatal("a mode is no difference")
	}
}
