//go:build !windows

package console

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	kconsole "github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/sysconf"
)

func writeKey(t *testing.T, dir string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, "hub.pub")
	if err := os.WriteFile(p, []byte("a2V5\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func subdir(t *testing.T, mode os.FileMode) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "d")
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(d, mode); err != nil {
		t.Fatal(err)
	}
	return d
}

// The pinned hub key file must not be replaceable by another account,
// and is read through one descriptor that follows no link.
func TestReadHubKeyFile(t *testing.T) {
	for _, c := range []struct {
		name    string
		dir     os.FileMode
		file    os.FileMode
		ok      bool
		symlink bool
	}{
		{"0644 in 0700", 0o700, 0o644, true, false},
		{"0600 in 0755", 0o755, 0o600, true, false},
		{"group-writable file", 0o700, 0o664, false, false},
		{"world-writable file", 0o700, 0o646, false, false},
		{"world-writable directory", 0o777, 0o644, false, false},
		{"sticky directory of the console", os.ModeSticky | 0o777, 0o644, true, false},
		{"symbolic link", 0o700, 0o644, false, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := subdir(t, 0o700)
			p := writeKey(t, d, c.file)
			if c.symlink {
				l := filepath.Join(d, "link.pub")
				if err := os.Symlink(p, l); err != nil {
					t.Fatal(err)
				}
				p = l
			}
			if err := os.Chmod(d, c.dir); err != nil {
				t.Fatal(err)
			}
			b, err := readHubKeyFile(p)
			if (err == nil) != c.ok || err != nil && !errors.Is(err, ErrConfig) {
				t.Fatalf("err = %v, want ok %v", err, c.ok)
			}
			if c.ok && string(b) != "a2V5\n" {
				t.Fatalf("read %q", b)
			}
		})
	}
	if _, err := readHubKeyFile(subdir(t, 0o700)); err == nil {
		t.Error("a directory was accepted")
	}
}

// The console reads its own 0600 copy of the key.
func TestPinHubKeyCopies(t *testing.T) {
	src := writeKey(t, subdir(t, 0o700), 0o644)
	state := t.TempDir()
	dst, err := pinHubKey(state, "sql-uat", src)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(dst)
	if err != nil || fi.Mode().Perm() != 0o600 || !strings.HasPrefix(dst, state) {
		t.Fatalf("copy %s: %v %v", dst, fi.Mode(), err)
	}
	if b, _ := os.ReadFile(dst); string(b) != "a2V5\n" {
		t.Fatalf("copy holds %q", b)
	}
}

// Run refuses a replaceable hub key file before any prompt.
func TestRunRefusesAReplaceableHubKey(t *testing.T) {
	root := t.TempDir()
	writeProjectConfig(t, root, 200)
	old := newIsolationEnv
	newIsolationEnv = func(*os.File) isolationEnv { return fakeIsolation(separated(), sysconf.DisplayWayland) }
	t.Cleanup(func() { newIsolationEnv = old })
	io := &fakeIO{answers: []string{"y", "y", "y"}}
	key := writeKey(t, subdir(t, 0o700), 0o666)
	err := Run(context.Background(), Options{Profile: "uat", IO: io, StateDir: t.TempDir(), Cwd: root,
		Hub: kconsole.HubOptions{URL: "http://lockhub:8443", KeyFile: key, Instance: "sql-uat", Home: t.TempDir()}})
	if !errors.Is(err, ErrConfig) || !strings.Contains(err.Error(), "--hub-key-file") {
		t.Fatalf("err = %v, want the hub key file refused", err)
	}
	if len(io.prompts) != 0 {
		t.Fatalf("prompted before refusing: %q", io.prompts)
	}
}
