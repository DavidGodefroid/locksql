//go:build windows

package ipc

import (
	"fmt"
	"os"
	"path/filepath"
)

// privateDir creates the socket's parent directory. Under %LOCALAPPDATA% it
// inherits the user's ACL, which is the only protection on Windows (no peer
// credentials on AF_UNIX); this is a documented limitation.
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
		return fmt.Errorf("ipc: socket dir %s is not a directory", dir)
	}
	return nil
}

func restrictSocket(string) error { return nil }
