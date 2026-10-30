//go:build !windows

package console

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// readPinnedFile reads a trust anchor named by flag (the hub key, the
// facade keys, the devices), refusing one another
// account could replace: a symbolic link, not a regular file, writable by
// its group or others, owned by neither root nor the console's account,
// or in a directory writable by group or others that is neither root's
// nor the console's. The checks and the read go through one descriptor,
// opened without following a link.
func readPinnedFile(flag, path string, max int64) ([]byte, error) {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s %s: %s", ErrConfig, flag, path, fmt.Sprintf(format, a...))
	}
	trusted := func(fi os.FileInfo) bool {
		st, ok := fi.Sys().(*syscall.Stat_t)
		return !ok || st.Uid == 0 || int(st.Uid) == os.Getuid()
	}
	if di, err := os.Stat(filepath.Dir(path)); err != nil {
		return nil, bad("%v", err)
	} else if di.Mode().Perm()&0o022 != 0 && !(di.Mode()&os.ModeSticky != 0 && trusted(di)) {
		return nil, bad("its directory is writable by its group or by others (mode %#o)", di.Mode().Perm())
	} else if !trusted(di) {
		return nil, bad("its directory belongs to neither root nor the console's account")
	}
	// O_NONBLOCK: a FIFO named instead of the file does not block the
	// console; it is refused as not regular.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, bad("%v (a symbolic link is refused)", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, bad("%v", err)
	}
	switch {
	case !fi.Mode().IsRegular():
		return nil, bad("not a regular file")
	case fi.Mode().Perm()&0o022 != 0:
		return nil, bad("writable by its group or by others (mode %#o): chmod go-w it", fi.Mode().Perm())
	case !trusted(fi):
		return nil, bad("belongs to neither root nor the console's account")
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, bad("%v", err)
	}
	if int64(len(b)) > max {
		return nil, bad("larger than %d bytes", max)
	}
	return b, nil
}
