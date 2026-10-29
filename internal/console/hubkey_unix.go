//go:build !windows

package console

import (
	"fmt"
	"os"
	"syscall"
)

// checkHubKeyFile refuses a pinned hub key file another account could
// replace: it must belong to root or to the console's account and be
// writable by its owner only (the key decides whose decisions run).
func checkHubKeyFile(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%w: --hub-key-file: %v", ErrConfig, err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%w: --hub-key-file %s is not a regular file", ErrConfig, path)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%w: --hub-key-file %s is writable by its group or by others (mode %#o): chmod go-w it", ErrConfig, path, fi.Mode().Perm())
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Uid != 0 && int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%w: --hub-key-file %s belongs to uid %d, neither root nor the console's account", ErrConfig, path, st.Uid)
	}
	return nil
}
