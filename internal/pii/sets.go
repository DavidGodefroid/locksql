package pii

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/DavidGodefroid/locksql/internal/config"
)

// SetsDir holds the named rule sets, pii/<set>.toml, next to the config.
const SetsDir = "pii"

// LegacyFile is the single rules file of the releases before named sets,
// next to the config. MigrateLegacy moves it to the DefaultSet.
const LegacyFile = "pii.toml"

// DefaultSet is the set the legacy pii.toml becomes.
const DefaultSet = "default"

// SetPath is the file of the rule set named set in dir, the directory of
// the config (.locksql in a project, the user config directory otherwise).
// A name that is not a valid set name is refused: it becomes a file name.
func SetPath(dir, set string) (string, error) {
	if !config.ValidRuleSet(set) {
		return "", fmt.Errorf("pii: invalid rule set name %q", set)
	}
	return filepath.Join(dir, SetsDir, set+".toml"), nil
}

// CheckSetsDir refuses a pii directory in dir that is not a directory of
// its own (a symbolic link, a file): set files would be read and written
// wherever it points. A missing directory is fine.
func CheckSetsDir(dir string) error {
	p := filepath.Join(dir, SetsDir)
	st, err := os.Lstat(p)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return fmt.Errorf("pii: %w", err)
	case !st.IsDir():
		return fmt.Errorf("pii: %s is not a directory (a symbolic link?): replace it with a directory holding the rule sets", p)
	}
	return nil
}

// SetExists reports whether the rule set named set has a file in dir.
func SetExists(dir, set string) bool {
	p, err := SetPath(dir, set)
	if err != nil {
		return false
	}
	st, err := os.Lstat(p)
	return err == nil && st.Mode().IsRegular()
}

// MigrateLegacy moves dir/pii.toml to the default set, once: when the
// default set exists already, nothing moves. It returns the paths moved
// from and to, both "" when nothing moved. A pii.toml that is not a
// regular file is refused rather than followed.
func MigrateLegacy(dir string) (from, to string, err error) {
	if err := CheckSetsDir(dir); err != nil {
		return "", "", err
	}
	legacy := filepath.Join(dir, LegacyFile)
	st, err := os.Lstat(legacy)
	if errors.Is(err, fs.ErrNotExist) {
		return "", "", nil
	}
	if err != nil {
		return "", "", fmt.Errorf("pii: %w", err)
	}
	def, _ := SetPath(dir, DefaultSet)
	if _, err := os.Lstat(def); err == nil {
		return "", "", nil
	}
	if !st.Mode().IsRegular() {
		return "", "", fmt.Errorf("pii: %s is not a regular file: move its rules to %s by hand", legacy, def)
	}
	if err := os.MkdirAll(filepath.Dir(def), 0o755); err != nil {
		return "", "", dirError(filepath.Dir(def), err)
	}
	if err := os.Rename(legacy, def); err != nil {
		return "", "", fmt.Errorf("pii: moving %s to %s: %w", legacy, def, err)
	}
	return legacy, def, nil
}
