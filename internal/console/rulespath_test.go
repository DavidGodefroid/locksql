package console

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/pii"
)

func TestRulesPathFor(t *testing.T) {
	cases := []struct {
		name, root, ucp, want string
	}{
		{"project", "/work/proj", "/home/u/.config/locksql/config.toml", filepath.Join("/work/proj", pii.RulesFile)},
		{"no project", "", "/home/u/.config/locksql/config.toml", filepath.FromSlash("/home/u/.config/locksql/pii.toml")},
	}
	for _, c := range cases {
		if got := rulesPathFor(c.root, c.ucp); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestRulesPathOutsideProjectIsInUserConfigDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	ucp, err := config.UserConfigPath()
	if err != nil {
		t.Fatal(err)
	}
	got := rulesPathFor("", ucp)
	if !strings.HasPrefix(got, home) || !strings.HasSuffix(got, filepath.Join("locksql", "pii.toml")) {
		t.Fatalf("rules path %q not under %q or not locksql/pii.toml", got, home)
	}
}

func TestLegacyRulesNotice(t *testing.T) {
	cwd := t.TempDir()
	rules := filepath.Join(t.TempDir(), "locksql", "pii.toml")
	if got := legacyRulesNotice(cwd, "", rules); got != "" {
		t.Fatalf("no old file: %q", got)
	}
	os.MkdirAll(filepath.Join(cwd, ".locksql"), 0o755)
	os.WriteFile(filepath.Join(cwd, ".locksql", "pii.toml"), []byte("mask = []\n"), 0o600)
	got := legacyRulesNotice(cwd, "", rules)
	if !strings.Contains(got, filepath.Join(cwd, ".locksql", "pii.toml")) || !strings.Contains(got, rules) || !strings.Contains(got, "no longer read") {
		t.Fatalf("notice = %q", got)
	}
	if _, err := os.Stat(rules); err == nil {
		t.Fatal("the old file was copied")
	}
	if got := legacyRulesNotice(cwd, cwd, rules); got != "" {
		t.Fatalf("in a project: %q", got)
	}
	os.MkdirAll(filepath.Dir(rules), 0o700)
	os.WriteFile(rules, nil, 0o600)
	if got := legacyRulesNotice(cwd, "", rules); got != "" {
		t.Fatalf("new file exists: %q", got)
	}
}
