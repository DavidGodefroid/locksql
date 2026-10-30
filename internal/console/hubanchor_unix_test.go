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

// The facade keys and devices files are trust anchors like the hub key:
// a link, a group- or world-writable file or directory is refused, and
// the console reads its own 0600 copy in its state directory.
func TestPinAnchors(t *testing.T) {
	write := func(t *testing.T, dir, name string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("[]\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	t.Run("pinned copies", func(t *testing.T) {
		d := subdir(t, 0o700)
		state := t.TempDir()
		o := kconsole.HubOptions{Instance: "sql-uat", FacadeKeysFile: write(t, d, "facades.json", 0o644), DevicesFile: write(t, d, "devices.json", 0o644)}
		if err := pinAnchors(state, &o); err != nil {
			t.Fatal(err)
		}
		for _, p := range []string{o.FacadeKeysFile, o.DevicesFile} {
			fi, err := os.Stat(p)
			if err != nil || !strings.HasPrefix(p, state) || fi.Mode().Perm() != 0o600 {
				t.Fatalf("copy %s: %v", p, err)
			}
		}
	})
	for _, c := range []struct {
		name, flag string
		dir, file  os.FileMode
		link       bool
		set        func(*kconsole.HubOptions, string)
	}{
		{"group-writable facade keys", "--facade-keys-file", 0o700, 0o664, false, func(o *kconsole.HubOptions, p string) { o.FacadeKeysFile = p }},
		{"world-writable devices", "--devices-file", 0o700, 0o646, false, func(o *kconsole.HubOptions, p string) { o.DevicesFile = p }},
		{"devices in a world-writable directory", "--devices-file", 0o777, 0o644, false, func(o *kconsole.HubOptions, p string) { o.DevicesFile = p }},
		{"facade keys through a link", "--facade-keys-file", 0o700, 0o644, true, func(o *kconsole.HubOptions, p string) { o.FacadeKeysFile = p }},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := subdir(t, 0o700)
			p := write(t, d, "anchor.json", c.file)
			if c.link {
				l := filepath.Join(d, "link.json")
				if err := os.Symlink(p, l); err != nil {
					t.Fatal(err)
				}
				p = l
			}
			if err := os.Chmod(d, c.dir); err != nil {
				t.Fatal(err)
			}
			o := kconsole.HubOptions{Instance: "sql-uat"}
			c.set(&o, p)
			err := pinAnchors(t.TempDir(), &o)
			if !errors.Is(err, ErrConfig) || !strings.Contains(err.Error(), c.flag) {
				t.Fatalf("err = %v, want %s refused", err, c.flag)
			}
		})
	}
}

// Run refuses a replaceable facade keys file before any prompt, as it
// refuses a replaceable hub key.
func TestRunRefusesAReplaceableFacadeKeys(t *testing.T) {
	root := t.TempDir()
	writeProjectConfig(t, root, 200)
	old := newIsolationEnv
	newIsolationEnv = func(*os.File) isolationEnv { return fakeIsolation(separated(), sysconf.DisplayWayland) }
	t.Cleanup(func() { newIsolationEnv = old })
	io := &fakeIO{answers: []string{"y", "y", "y"}}
	d := subdir(t, 0o700)
	key := writeKey(t, d, 0o644)
	facades := filepath.Join(d, "facades.json")
	if err := os.WriteFile(facades, []byte("[]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(facades, 0o666); err != nil {
		t.Fatal(err)
	}
	err := Run(context.Background(), Options{Profile: "uat", IO: io, StateDir: t.TempDir(), Cwd: root,
		Hub: kconsole.HubOptions{URL: "http://lockhub:8443", KeyFile: key, Instance: "sql-uat", FacadeKeysFile: facades, Home: t.TempDir()}})
	if !errors.Is(err, ErrConfig) || !strings.Contains(err.Error(), "--facade-keys-file") {
		t.Fatalf("err = %v, want the facade keys file refused", err)
	}
	if len(io.prompts) != 0 {
		t.Fatalf("prompted before refusing: %q", io.prompts)
	}
}
