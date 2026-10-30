package console

import (
	"fmt"
	"io"
	"os"
)

// readPinnedFile reads a trust anchor named by flag; locksql runs its console
// in its Linux image, where its owner, mode and directory are checked too.
func readPinnedFile(flag, path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrConfig, flag, err)
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s %s is not a regular file", ErrConfig, flag, path)
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(b)) > max {
		return nil, fmt.Errorf("%w: %s %s: unreadable or larger than %d bytes", ErrConfig, flag, path, max)
	}
	return b, nil
}
