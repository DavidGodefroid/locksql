package console

import (
	"fmt"
	"os"
)

// checkHubKeyFile checks that the pinned hub key file is a regular file;
// locksql runs its console in its Linux image, where the owner and mode
// are checked too.
func checkHubKeyFile(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%w: --hub-key-file: %v", ErrConfig, err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%w: --hub-key-file %s is not a regular file", ErrConfig, path)
	}
	return nil
}
