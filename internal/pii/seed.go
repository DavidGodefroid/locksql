package pii

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/DavidGodefroid/locksql/internal/config"
)

// maxSeed bounds a rule set file SeedSets copies.
const maxSeed = 1 << 20

// SeedSets copies into the directory to (the console's own rule sets
// directory, LOCKSQL_PII_DIR) each rule set of from (the profile's
// directory, read-only under lock up) that to does not hold yet:
// from/pii/<set>.toml, and the legacy from/pii.toml as the default set.
// A set to holds already is never replaced: from those on, the console's
// copy is the one it reads and edits. Links, files that are not regular
// and invalid set names are skipped. It returns the paths written.
func SeedSets(from, to string) ([]string, error) {
	if err := CheckSetsDir(from); err != nil {
		return nil, err
	}
	if err := CheckSetsDir(to); err != nil {
		return nil, err
	}
	src := map[string]string{} // set -> file in from
	entries, err := os.ReadDir(filepath.Join(from, SetsDir))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("pii: %w", err)
	}
	for _, e := range entries {
		set, ok := strings.CutSuffix(e.Name(), ".toml")
		if !ok || !config.ValidRuleSet(set) || !e.Type().IsRegular() {
			continue
		}
		src[set] = filepath.Join(from, SetsDir, e.Name())
	}
	if _, ok := src[DefaultSet]; !ok {
		legacy := filepath.Join(from, LegacyFile)
		if st, err := os.Lstat(legacy); err == nil && st.Mode().IsRegular() {
			src[DefaultSet] = legacy
		}
	}
	sets := make([]string, 0, len(src))
	for s := range src {
		sets = append(sets, s)
	}
	sort.Strings(sets)
	var wrote []string
	for _, set := range sets {
		dst, _ := SetPath(to, set)
		if _, err := os.Lstat(dst); err == nil {
			continue
		} else if !errors.Is(err, fs.ErrNotExist) {
			return wrote, fmt.Errorf("pii: %w", err)
		}
		raw, err := readRegular(src[set])
		if err != nil {
			return wrote, err
		}
		if err := writeAtomic(dst, raw); err != nil {
			return wrote, err
		}
		wrote = append(wrote, dst)
	}
	return wrote, nil
}

// SameSet reports whether the files a and b hold the same bytes; false
// when either is missing or unreadable.
func SameSet(a, b string) bool {
	ra, err := readRegular(a)
	if err != nil {
		return false
	}
	rb, err := readRegular(b)
	return err == nil && bytes.Equal(ra, rb)
}

// readRegular reads path, a regular file (not a link) of at most maxSeed
// bytes: the file opened is the one checked, not a link swapped in since.
func readRegular(path string) ([]byte, error) {
	lst, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("pii: %w", err)
	}
	if !lst.Mode().IsRegular() {
		return nil, fmt.Errorf("pii: %s is not a regular file", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("pii: %w", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("pii: %w", err)
	}
	if !os.SameFile(lst, st) {
		return nil, fmt.Errorf("pii: %s changed while it was read", path)
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxSeed+1))
	if err != nil {
		return nil, fmt.Errorf("pii: %w", err)
	}
	if len(raw) > maxSeed {
		return nil, fmt.Errorf("pii: %s: more than %d bytes", path, maxSeed)
	}
	return raw, nil
}

// writeAtomic writes raw to path (0644) through a temporary file of its
// directory.
func writeAtomic(path string, raw []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return dirError(dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".pii-*.toml")
	if err != nil {
		return dirError(dir, err)
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return fmt.Errorf("pii: %w", err)
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return fmt.Errorf("pii: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("pii: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return dirError(dir, err)
	}
	return nil
}
