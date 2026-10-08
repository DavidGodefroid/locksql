package console

import (
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
