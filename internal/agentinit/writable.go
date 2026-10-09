package agentinit

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// writable checks, before a user-scope write, that target is this
// account's to change: an existing file must be owned by the current user
// and writable by it; a new file needs a writable directory (its nearest
// existing ancestor, when directories are to be created). shown is the
// path as the human sees it.
func writable(target, shown string) error {
	st, err := os.Stat(target)
	switch {
	case err == nil:
		if s, ok := st.Sys().(*syscall.Stat_t); ok && int(s.Uid) != os.Getuid() {
			return fmt.Errorf("%s: owned by another account (uid %d); fix its owner or add the locksql entry by hand", shown, s.Uid)
		}
		if unix.Access(target, unix.W_OK) != nil {
			return fmt.Errorf("%s: not writable by this account; fix its owner or mode, or add the locksql entry by hand", shown)
		}
		return nil
	case !errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("%s: %w", shown, err)
	}
	dir := filepath.Dir(target)
	for {
		if _, err := os.Stat(dir); err == nil {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	if unix.Access(dir, unix.W_OK|unix.X_OK) != nil {
		return fmt.Errorf("%s: directory %s is not writable by this account; fix its owner or add the locksql entry by hand", shown, dir)
	}
	return nil
}
