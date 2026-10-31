package pii

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/DavidGodefroid/locksql/internal/config"
)

// ToShared is r in the shared configuration format, sorted.
func ToShared(r Rules) config.SharedRules {
	s := config.SharedRules{Mask: []config.SharedRule{}, Allow: []config.SharedRule{}}
	for _, p := range canonical(r.Mask) {
		m := r.Modes[p]
		if m == ModeRedact {
			m = ""
		}
		s.Mask = append(s.Mask, config.SharedRule{Column: p, Mode: m})
	}
	for _, p := range canonical(r.Allow) {
		s.Allow = append(s.Allow, config.SharedRule{Column: p})
	}
	return s
}

// FromShared checks the rules of a shared configuration like a rules file:
// patterns, modes, and no mode on an allow rule.
func FromShared(s config.SharedRules) (Rules, error) {
	var r Rules
	for i, e := range s.Mask {
		if err := r.AddMode(e.Column, e.Mode); err != nil {
			return Rules{}, fmt.Errorf("mask entry %d: %w", i+1, err)
		}
	}
	for i, e := range s.Allow {
		if e.Mode != "" {
			return Rules{}, fmt.Errorf("allow entry %d: pii rule: an allow rule has no mode", i+1)
		}
		if err := r.AddAllow(e.Column); err != nil {
			return Rules{}, fmt.Errorf("allow entry %d: %w", i+1, err)
		}
	}
	return r, nil
}

// MergeRules is the union of local and imported, without duplicates. A
// mask rule with a different mode on each side gets redact, the stricter,
// and is listed in conflicts.
func MergeRules(local, imported Rules) (Rules, []string) {
	var out Rules
	var conflicts []string
	mode := func(r Rules, p string) string {
		if m := r.Modes[p]; m != "" {
			return m
		}
		return ModeRedact
	}
	for _, p := range canonical(append(slices.Clone(local.Mask), imported.Mask...)) {
		lm, im := slices.Contains(local.Mask, p), slices.Contains(imported.Mask, p)
		m := ModeRedact
		switch {
		case lm && im:
			if a, b := mode(local, p), mode(imported, p); a == b {
				m = a
			} else {
				conflicts = append(conflicts, fmt.Sprintf("%s: mode %s here, %s in the import: kept redact", p, a, b))
			}
		case lm:
			m = mode(local, p)
		default:
			m = mode(imported, p)
		}
		_ = out.AddMode(p, m)
	}
	for _, p := range canonical(append(slices.Clone(local.Allow), imported.Allow...)) {
		_ = out.AddAllow(p)
	}
	return out, conflicts
}

// LoadSets reads every rule set of dir: pii/<set>.toml for each valid set
// name, and a legacy pii.toml as the default set while that set has no
// file of its own. Other files of pii/ are ignored.
func LoadSets(dir string) (map[string]Rules, error) {
	if err := CheckSetsDir(dir); err != nil {
		return nil, err
	}
	out := map[string]Rules{}
	entries, err := os.ReadDir(filepath.Join(dir, SetsDir))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("pii: %w", err)
	}
	for _, e := range entries {
		set, ok := strings.CutSuffix(e.Name(), ".toml")
		if !ok || !config.ValidRuleSet(set) || !e.Type().IsRegular() {
			continue
		}
		r, err := LoadRulesFile(filepath.Join(dir, SetsDir, e.Name()))
		if err != nil {
			return nil, err
		}
		out[set] = r
	}
	if _, ok := out[DefaultSet]; !ok {
		legacy := filepath.Join(dir, LegacyFile)
		if st, err := os.Lstat(legacy); err == nil && st.Mode().IsRegular() {
			r, err := LoadRulesFile(legacy)
			if err != nil {
				return nil, err
			}
			out[DefaultSet] = r
		}
	}
	return out, nil
}

// FileSet is the rule set of p as the files show it, without the
// console's approval state: pii_rules, else its own set when it has a
// file, else the default set when there is one (the migrated pii.toml),
// else its own, new set. has reports whether a set exists.
func FileSet(p config.Profile, has func(set string) bool) string {
	set := config.RuleSetOf(p)
	if p.PIIRules == "" && !has(set) && has(DefaultSet) {
		return DefaultSet
	}
	return set
}
