//go:build !windows

package ipc

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// privateDir creates the socket's parent directory with mode 0700 and
// checks that it is a real directory (not a symlink) owned by the user.
func privateDir(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("ipc: %w", err)
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("ipc: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("ipc: socket dir %s is not a directory (symlink?)", dir)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("ipc: cannot read the owner of %s", dir)
	}
	if int(st.Uid) != os.Getuid() {
		return fmt.Errorf("ipc: socket dir %s is owned by uid %d, not by you", dir, st.Uid)
	}
	if fi.Mode().Perm() != 0o700 {
		if err := os.Chmod(dir, 0o700); err != nil {
			return fmt.Errorf("ipc: %w", err)
		}
	}
	return nil
}

func restrictSocket(path string) error {
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("ipc: %w", err)
	}
	return nil
}
