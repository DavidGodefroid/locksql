package console

import (
	"fmt"
	"io"
	"os"
)

// maxHubKeyFile bounds the pinned hub key file (one base64 line).
const maxHubKeyFile = 4096

// readHubKeyFile reads the pinned hub key file; locksql runs its console
// in its Linux image, where its owner, mode and directory are checked too.
func readHubKeyFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%w: --hub-key-file: %v", ErrConfig, err)
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: --hub-key-file %s is not a regular file", ErrConfig, path)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxHubKeyFile+1))
	if err != nil || len(b) > maxHubKeyFile {
		return nil, fmt.Errorf("%w: --hub-key-file %s: unreadable or larger than %d bytes", ErrConfig, path, maxHubKeyFile)
	}
	return b, nil
}
