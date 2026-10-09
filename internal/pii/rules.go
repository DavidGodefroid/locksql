// Package pii decides which result cells must be masked: column rules kept
// in .locksql/pii.toml, rules proposed from the schema, value detectors
// (email, phone, IBAN, card, national ids) and the masking itself.
package pii

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/BurntSushi/toml"
)

// RulesFile is the rules file, relative to the project root.
const RulesFile = ".locksql/pii.toml"

// Rules are the column rules. Each pattern is "db.table.column", where any
// segment may be '*'. For PostgreSQL the db segment is the schema. Matching
// ignores case. An Allow pattern beats every Mask pattern.
type Rules struct {
	Mask  []string
	Allow []string
	// Modes maps a Mask pattern to its mode when it is not ModeRedact.
	Modes map[string]string
}

// Mask modes.
const (
	// ModeRedact replaces the whole value: "<redacted>" (the default).
	ModeRedact = "redact"
	// ModePartial keeps the first character and the length: "j***(12)".
	ModePartial = "partial"
	// ModeEmail keeps the first character and the domain of an address:
	// "j***@example.com" (other values are masked as partial).
	ModeEmail = "email"
)

// ValidMode reports whether m is a mask mode.
func ValidMode(m string) bool {
	return m == ModeRedact || m == ModePartial || m == ModeEmail
}

type ruleEntry struct {
	Column string `toml:"column"`
	Mode   string `toml:"mode,omitempty"`
}

type rulesFile struct {
	Mask  []ruleEntry `toml:"mask"`
	Allow []ruleEntry `toml:"allow"`
}

// LoadRules reads <projectRoot>/.locksql/pii.toml. A missing file gives
// empty rules and no error.
func LoadRules(projectRoot string) (Rules, error) {
	return LoadRulesFile(filepath.Join(projectRoot, RulesFile))
}

// LoadRulesFile reads the rules file at path. A missing file gives empty
// rules and no error.
func LoadRulesFile(path string) (Rules, error) {
	name := filepath.Base(path)
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return Rules{}, nil
	}
	if err != nil {
		return Rules{}, fmt.Errorf("pii: %w", err)
	}
	var f rulesFile
	md, err := toml.Decode(string(raw), &f)
	if err != nil {
		var perr toml.ParseError
		if errors.As(err, &perr) {
			return Rules{}, fmt.Errorf("pii: %s: syntax error at line %d", name, perr.Position.Line)
		}
		return Rules{}, fmt.Errorf("pii: %s: %w", name, err)
	}
	if und := md.Undecoded(); len(und) > 0 {
		return Rules{}, fmt.Errorf("pii: %s: unknown key %q", name, und[0].String())
	}
	var r Rules
	for _, e := range f.Mask {
		if err := r.AddMode(e.Column, e.Mode); err != nil {
			return Rules{}, fmt.Errorf("pii: %s: %w", name, err)
		}
	}
	for _, e := range f.Allow {
		if err := r.AddAllow(e.Column); err != nil {
			return Rules{}, fmt.Errorf("pii: %s: %w", name, err)
		}
	}
	return r, nil
}

// SaveRules writes the rules to <root>/.locksql/pii.toml, sorted and
// de-duplicated, replacing the file atomically.
func SaveRules(root string, r Rules) error {
	return SaveRulesFile(filepath.Join(root, RulesFile), r)
}

// SaveRulesFile writes the rules to path, sorted and de-duplicated,
// replacing the file atomically. Missing directories are created.
func SaveRulesFile(path string, r Rules) error {
	var b bytes.Buffer
	b.WriteString("# locksql PII column rules: \"db.table.column\", '*' matches any segment.\n")
	b.WriteString("# [[mask]] masks whole cells; [[allow]] is an exception that is never masked.\n")
	b.WriteString("# mode = \"redact\" (default: <redacted>), \"partial\" (j***(12)) or \"email\" (j***@example.com).\n")
	write := func(kind string, patterns []string) {
		for _, p := range canonical(patterns) {
			fmt.Fprintf(&b, "\n[[%s]]\ncolumn = %q\n", kind, p)
			if m := r.Modes[p]; kind == "mask" && m != "" && m != ModeRedact {
				fmt.Fprintf(&b, "mode = %q\n", m)
			}
		}
	}
	write("mask", r.Mask)
	write("allow", r.Allow)

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("pii: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".pii-*.toml")
	if err != nil {
		return fmt.Errorf("pii: %w", err)
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if _, err := tmp.Write(b.Bytes()); err != nil {
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
		return fmt.Errorf("pii: %w", err)
	}
	return nil
}

// Add adds a mask pattern after validating it. Adding an existing pattern
// is a no-op.
func (r *Rules) Add(pattern string) error {
	p, err := parsePattern(pattern)
	if err != nil {
		return err
	}
	if !slices.Contains(r.Mask, p) {
		r.Mask = append(r.Mask, p)
	}
	return nil
}

// AddMode adds a mask pattern with a mode ("" for the default). Adding an
// existing pattern sets its mode.
func (r *Rules) AddMode(pattern, mode string) error {
	if mode == "" {
		mode = ModeRedact
	}
	if !ValidMode(mode) {
		return fmt.Errorf("pii rule %q: unknown mode %q (want redact, partial or email)", pattern, mode)
	}
	if err := r.Add(pattern); err != nil {
		return err
	}
	p, _ := parsePattern(pattern)
	if mode == ModeRedact {
		delete(r.Modes, p)
		return nil
	}
	if r.Modes == nil {
		r.Modes = map[string]string{}
	}
	r.Modes[p] = mode
	return nil
}

// Mode returns the mask mode of the column db.table.column and whether a
// rule masks it. Several matching rules with different modes give
// ModeRedact.
func (r Rules) Mode(db, table, column string) (string, bool) {
	if !r.Matches(db, table, column) {
		return "", false
	}
	seg := [3]string{db, table, column}
	return r.combine(func(p string) bool { return anyMatch([]string{p}, seg) }), true
}

// ModeByName is Mode for a column known by its name only (MatchesName).
func (r Rules) ModeByName(column string) (string, bool) {
	if !r.MatchesName(column) {
		return "", false
	}
	return r.combine(func(p string) bool { return !isASCII(column) || looseSegMatch(lastSeg(p), column) }), true
}

func (r Rules) combine(match func(string) bool) string {
	mode := ""
	for _, p := range r.Mask {
		if !match(p) {
			continue
		}
		m := r.Modes[p]
		if m == "" {
			m = ModeRedact
		}
		switch {
		case mode == "":
			mode = m
		case mode != m:
			return ModeRedact
		}
	}
	if mode == "" {
		return ModeRedact
	}
	return mode
}

// AddAllow adds an allow pattern after validating it. Adding an existing pattern is a no-op.
func (r *Rules) AddAllow(pattern string) error {
	p, err := parsePattern(pattern)
	if err != nil {
		return err
	}
	if !slices.Contains(r.Allow, p) {
		r.Allow = append(r.Allow, p)
	}
	return nil
}

// Matches reports whether the column db.table.column is masked: some Mask
// pattern matches it and no Allow pattern does.
func (r Rules) Matches(db, table, column string) bool {
	seg := [3]string{db, table, column}
	return anyMatch(r.Mask, seg) && !anyMatch(r.Allow, seg)
}

// MatchesName reports whether a column known only by its name may be under
// a rule: some Mask pattern has that column segment (whatever its db and
// table) and no Allow pattern exempts the name everywhere ("*.*.name"). It
// is the conservative test used when a result column has no origin.
//
// Servers resolve identifiers with their own collation (MySQL compares
// column names by collation weight, so "fírstname" and "fİrstname" name the
// column firstname), which no Go case folding reproduces. A name with a
// non-ASCII character therefore matches as soon as any Mask pattern exists,
// and a non-ASCII character of a pattern matches any character.
func (r Rules) MatchesName(column string) bool {
	if len(r.Mask) == 0 {
		return false
	}
	masked := !isASCII(column)
	for _, p := range r.Mask {
		if masked {
			break
		}
		masked = looseSegMatch(lastSeg(p), column)
	}
	if !masked {
		return false
	}
	for _, p := range r.Allow {
		s := strings.Split(p, ".")
		if s[0] == "*" && s[1] == "*" && segMatch(s[2], column) {
			return false
		}
	}
	return true
}

// Covered reports whether a mask or an allow pattern names the column: the
// human already decided about it.
func (r Rules) Covered(db, table, column string) bool {
	seg := [3]string{db, table, column}
	return anyMatch(r.Mask, seg) || anyMatch(r.Allow, seg)
}

func anyMatch(patterns []string, seg [3]string) bool {
	for _, p := range patterns {
		s := strings.Split(p, ".")
		if len(s) == 3 && segMatch(s[0], seg[0]) && segMatch(s[1], seg[1]) && segMatch(s[2], seg[2]) {
			return true
		}
	}
	return false
}

func lastSeg(p string) string { return p[strings.LastIndexByte(p, '.')+1:] }

// segMatch compares a pattern segment with a name the way the SQL lexer
// folds identifiers (see fold), so that the alias check and the masking
// agree on which names are equal.
func segMatch(pat, name string) bool { return pat == "*" || fold(pat) == fold(name) }

// looseSegMatch is segMatch where a non-ASCII character of the pattern
// matches any one character of the name.
func looseSegMatch(pat, name string) bool {
	if segMatch(pat, name) {
		return true
	}
	pr, nr := []rune(fold(pat)), []rune(fold(name))
	if len(pr) != len(nr) {
		return false
	}
	for i := range pr {
		if pr[i] != nr[i] && pr[i] < utf8.RuneSelf {
			return false
		}
	}
	return true
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// parsePattern validates "db.table.column": three non-empty segments, each
// '*' or a name without '*', '.', quotes, blanks, control characters or
// format characters (bidi controls, zero-width marks). Patterns are shown to
// the human in review diffs, where such characters could hide text.
func parsePattern(p string) (string, error) {
	segs := strings.Split(p, ".")
	if len(segs) != 3 {
		return "", fmt.Errorf("pii rule %q: want db.table.column ('*' allowed per segment)", p)
	}
	for _, s := range segs {
		if s == "" || (s != "*" && strings.ContainsAny(s, "*\"'`")) || strings.IndexFunc(s, unsafeRune) >= 0 {
			return "", fmt.Errorf("pii rule %q: each segment is '*' or a plain name", p)
		}
	}
	return p, nil
}

// unsafeRune reports a character that a plain name never holds and that
// could alter or hide text on a terminal: controls, spaces of any kind and
// format characters.
func unsafeRune(r rune) bool {
	return r == utf8.RuneError || unicode.IsControl(r) || unicode.IsSpace(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp)
}

func canonical(patterns []string) []string {
	out := slices.Clone(patterns)
	slices.Sort(out)
	return slices.Compact(out)
}
