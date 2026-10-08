package setup

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"

	"github.com/BurntSushi/toml"

	"github.com/DavidGodefroid/locksql/internal/config"
)

// Answers is a complete profile as asked by Prompt.
type Answers struct {
	Target
	Name, Tier           string
	Production, Keychain bool
}

type outProfile struct {
	Engine      string `toml:"engine"`
	Host        string `toml:"host,omitempty"`
	Port        int    `toml:"port,omitempty"`
	Path        string `toml:"path,omitempty"`
	User        string `toml:"user,omitempty"`
	Database    string `toml:"database,omitempty"`
	Credentials string `toml:"credentials"`
	Tier        string `toml:"tier"`
	Production  bool   `toml:"production"`
}

// Render returns the profile as a TOML table. The name is quoted, so a
// name holding '.' stays one key.
func Render(a Answers) []byte {
	creds := config.CredentialsAsk
	if a.Keychain {
		creds = config.CredentialsKeychain
	}
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "[profiles.%s]\n", strconv.Quote(a.Name))
	_ = toml.NewEncoder(&buf).Encode(outProfile{
		Engine: a.Engine, Host: a.Host, Port: a.Port, Path: a.Path, User: a.User,
		Database: a.Database, Credentials: creds, Tier: a.Tier, Production: a.Production,
	})
	return buf.Bytes()
}

// AppendProfile appends a to the config at path, creating it (0600, in a
// 0700 directory) when absent. The result is validated as a whole before
// anything is written; existing content is kept byte for byte.
func AppendProfile(path string, a Answers) error {
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved // keep a symlinked config a symlink
	}
	old, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	exists := err == nil
	if exists {
		ps, err := config.ParseProfiles(old, path, filepath.Dir(path))
		if err != nil {
			return err
		}
		if _, dup := ps[a.Name]; dup {
			return fmt.Errorf("profile %q already exists in %s", a.Name, path)
		}
	}
	next := append([]byte{}, old...)
	if len(next) > 0 && !bytes.HasSuffix(next, []byte("\n")) {
		next = append(next, '\n')
	}
	if len(next) > 0 {
		next = append(next, '\n')
	}
	next = append(next, Render(a)...)
	if _, err := config.ParseProfiles(next, path, filepath.Dir(path)); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	mode := fs.FileMode(0o600)
	if exists {
		if st, err := os.Stat(path); err == nil {
			mode = st.Mode().Perm()
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".config-*.toml")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(next); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
