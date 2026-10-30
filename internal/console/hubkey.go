package console

import (
	"os"
	"path/filepath"

	kconsole "github.com/DavidGodefroid/lockkit/console"
)

// maxHubKeyFile bounds the pinned hub key file (one base64 line), and
// maxAnchorFile the facade keys and devices files (JSON).
const (
	maxHubKeyFile = 4096
	maxAnchorFile = 1 << 20
)

// readHubKeyFile reads the hub key file the human named (readPinnedFile).
func readHubKeyFile(path string) ([]byte, error) {
	return readPinnedFile("--hub-key-file", path, maxHubKeyFile)
}

// pinHubKey reads the hub key file the human named (readHubKeyFile) and
// copies it into the console's own state directory, 0600: lockkit then
// reads the copy, which no other account can swap between the checks and
// the read.
func pinHubKey(stateDir, instance, path string) (string, error) {
	b, err := readHubKeyFile(path)
	if err != nil {
		return "", err
	}
	return pinCopy(stateDir, instance+".pub", b)
}

// pinAnchors gives the facade keys and devices files of o the hub key's
// treatment (readPinnedFile, then a 0600 copy in the state directory): in
// a separated setup the handoff brings them from the agent's account, and
// they decide which keys a reveal is sealed to and which devices an
// approval needs.
func pinAnchors(stateDir string, o *kconsole.HubOptions) error {
	for _, a := range []struct {
		flag, ext string
		path      *string
	}{{"--facade-keys-file", ".facades.json", &o.FacadeKeysFile}, {"--devices-file", ".devices.json", &o.DevicesFile}} {
		if *a.path == "" {
			continue
		}
		b, err := readPinnedFile(a.flag, *a.path, maxAnchorFile)
		if err != nil {
			return err
		}
		if *a.path, err = pinCopy(stateDir, o.Instance+a.ext, b); err != nil {
			return err
		}
	}
	return nil
}

// pinCopy writes b as name in the console's hub directory, 0600, replacing
// it at once.
func pinCopy(stateDir, name string, b []byte) (string, error) {
	dir := filepath.Join(stateDir, "locksql", "hub")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	f, err := os.CreateTemp(dir, ".pin-*")
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
	dst := filepath.Join(dir, name)
	return dst, os.Rename(f.Name(), dst)
}
