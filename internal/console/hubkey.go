package console

import (
	"os"
	"path/filepath"
)

// pinHubKey reads the hub key file the human named (readHubKeyFile) and
// copies it into the console's own state directory, 0600: lockkit then
// reads the copy, which no other account can swap between the checks and
// the read.
func pinHubKey(stateDir, instance, path string) (string, error) {
	b, err := readHubKeyFile(path)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(stateDir, "locksql", "hub")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	f, err := os.CreateTemp(dir, ".hub-key-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(b); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	dst := filepath.Join(dir, instance+".pub")
	return dst, os.Rename(f.Name(), dst)
}
