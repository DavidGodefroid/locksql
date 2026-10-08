//go:build !windows

package sysconf

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// checkRootOwned refuses a file (and its directory) that someone other
// than root could change.
func checkRootOwned(path string, fi fs.FileInfo) error {
	if SkipOwnerCheck {
		return nil
	}
	for _, p := range []string{path, filepath.Dir(path)} {
		info := fi
		if p != path {
			var err error
			if info, err = os.Stat(p); err != nil {
				return fmt.Errorf("sysconf: %w", err)
			}
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("sysconf: cannot read the owner of %s", p)
		}
		if st.Uid != 0 {
			return fmt.Errorf("sysconf: %s must be owned by root (it is owned by uid %d)", p, st.Uid)
		}
		if info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("sysconf: %s must be writable by root only (mode %04o)", p, info.Mode().Perm())
		}
	}
	return nil
}
