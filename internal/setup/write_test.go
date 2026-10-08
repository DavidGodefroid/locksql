package setup

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/config"
)

func TestAppendProfileCreatesPrivateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "locksql", "config.toml")
	a := Answers{Target: Target{Engine: "postgres", Host: "127.0.0.1", Port: 5432, User: "app", Database: "shop"}, Name: "dev", Tier: "read", Keychain: true}
	if err := AppendProfile(path, a); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(path)
	dst, _ := os.Stat(filepath.Dir(path))
	if st.Mode().Perm() != 0o600 || dst.Mode().Perm() != 0o700 {
		t.Fatalf("modes %v %v", st.Mode().Perm(), dst.Mode().Perm())
	}
	cfg, err := config.LoadFrom(t.TempDir(), path)
	if err != nil || cfg.Profiles["dev"].Credentials != "keychain" || cfg.Profiles["dev"].User != "app" {
		t.Fatalf("load: %+v %v", cfg, err)
	}
}

func TestAppendProfileKeepsExistingContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	orig := "# mine\n[profiles.prod]  # keep me\nengine = \"mysql\"\nhost = \"db\"\nproduction = true\n"
	os.WriteFile(path, []byte(orig), 0o600)
	a := Answers{Target: Target{Engine: "sqlite", Path: "/tmp/x.db"}, Name: "my.db", Tier: "read"}
	if err := AppendProfile(path, a); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if !strings.HasPrefix(string(b), orig) {
		t.Fatalf("existing content changed:\n%s", b)
	}
	cfg, err := config.LoadFrom(t.TempDir(), path)
	if err != nil || len(cfg.Profiles) != 2 || cfg.Profiles["my.db"].Path != "/tmp/x.db" {
		t.Fatalf("load: %+v %v", cfg, err)
	}
}

func TestAppendProfileRefusesInvalidAndDuplicate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	good := Answers{Target: Target{Engine: "postgres", Host: "h", Port: 5432}, Name: "dev", Tier: "read"}
	if err := AppendProfile(path, good); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	for _, a := range []Answers{good, {Target: Target{Engine: "postgres"}, Name: "x", Tier: "read"}} {
		if err := AppendProfile(path, a); err == nil {
			t.Errorf("accepted %+v", a)
		}
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("file changed after a refused append")
	}
}

func TestAppendProfileKeepsSymlink(t *testing.T) {
	target := filepath.Join(t.TempDir(), "dotfiles", "config.toml")
	os.MkdirAll(filepath.Dir(target), 0o700)
	os.WriteFile(target, []byte("[profiles.prod]\nengine = \"mysql\"\nhost = \"db\"\n"), 0o600)
	link := filepath.Join(t.TempDir(), "config.toml")
	if err := os.Symlink(target, link); err != nil {
		t.Skip(err)
	}
	a := Answers{Target: Target{Engine: "sqlite", Path: "/tmp/x.db"}, Name: "dev", Tier: "read"}
	if err := AppendProfile(link, a); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Lstat(link); err != nil || st.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("link replaced: %v %v", st, err)
	}
	cfg, err := config.LoadFrom(t.TempDir(), target)
	if err != nil || len(cfg.Profiles) != 2 {
		t.Fatalf("target: %+v %v", cfg, err)
	}
}
