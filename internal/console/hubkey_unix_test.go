//go:build !windows

package console

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The pinned hub key file must not be replaceable by another account.
func TestCheckHubKeyFile(t *testing.T) {
	dir := t.TempDir()
	for _, c := range []struct {
		mode os.FileMode
		ok   bool
	}{{0o644, true}, {0o600, true}, {0o664, false}, {0o646, false}} {
		p := filepath.Join(dir, "hub-"+c.mode.String()+".pub")
		if err := os.WriteFile(p, []byte("k\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, c.mode); err != nil {
			t.Fatal(err)
		}
		if err := checkHubKeyFile(p); (err == nil) != c.ok || err != nil && !errors.Is(err, ErrConfig) {
			t.Errorf("mode %v: %v", c.mode, err)
		}
	}
	if err := checkHubKeyFile(dir); err == nil {
		t.Error("a directory was accepted")
	}
}
