package agentinit

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// writable checks, before a user-scope write, that target is not a
// directory and that its stat succeeds or the file does not exist yet. On
// Windows ownership and access are left to the write itself, which fails
// with the OS error when the account may not change the file.
func writable(target, shown string) error {
	st, err := os.Stat(target)
	switch {
	case err == nil && st.IsDir():
		return fmt.Errorf("%s: is a directory", shown)
	case err == nil, errors.Is(err, fs.ErrNotExist):
		return nil
	}
	return fmt.Errorf("%s: %w", shown, err)
}
