package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// FileKey is a profile key that names a file the console reads: Path as
// written in the config, "~/" included.
type FileKey struct {
	Key  string
	Path string
}

// FileKeys are the file keys p sets: tls_ca, tls_cert, tls_key and, with
// ssh auth = "key", ssh.key.
func (p Profile) FileKeys() []FileKey {
	var out []FileKey
	for _, f := range []FileKey{{"tls_ca", p.TLSCA}, {"tls_cert", p.TLSCert}, {"tls_key", p.TLSKey}} {
		if f.Path != "" {
			out = append(out, f)
		}
	}
	if s := p.SSH; s != nil && s.Auth == SSHAuthKey && s.Key != "" {
		out = append(out, FileKey{"ssh.key", s.Key})
	}
	return out
}

// ExpandHome resolves a leading "~/" (or a lone "~") of a file key's path
// to home, the console account's home, as ssh.key always did; any other
// path is returned as is.
func ExpandHome(path, home string) string {
	if path == "~" {
		return home
	}
	if rest, ok := strings.CutPrefix(path, "~/"); ok {
		return filepath.Join(home, rest)
	}
	return path
}

// HomePath is ExpandHome with this account's home; path as is when the
// home is unknown.
func HomePath(path string) string {
	if path != "~" && !strings.HasPrefix(path, "~/") {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	return ExpandHome(path, home)
}

// CheckFiles opens every file key of p, resolved in home, so that a missing
// or unreadable file stops the console before any question that needs the
// network or a secret. Errors name the key and the path, never the content.
func CheckFiles(p Profile, home string) error {
	for _, f := range p.FileKeys() {
		path := ExpandHome(f.Path, home)
		fh, err := os.Open(path)
		if err == nil {
			fh.Close()
			continue
		}
		where := ""
		if path != f.Path {
			where = " in the console's home (" + home + ")"
		}
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return fmt.Errorf("%s: %s not found%s", f.Key, path, where)
		case errors.Is(err, fs.ErrPermission):
			return fmt.Errorf("%s: %s is not readable by the console account%s", f.Key, path, where)
		default:
			var pe *fs.PathError
			if errors.As(err, &pe) {
				err = pe.Err
			}
			return fmt.Errorf("%s: %s: %v", f.Key, path, err)
		}
	}
	return nil
}
