package config

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ParsePIIPattern validates a PII rule pattern "db.table.column": three
// non-empty segments, each '*' or a name without '.', quotes, blanks,
// control characters or format characters (bidi controls, zero-width
// marks), with at most one leading and one trailing '*'. Patterns are shown
// to the human in review diffs, where such characters could hide text.
// Errors never quote the pattern, which may be a secret pasted in the wrong
// place. Package pii validates its rules with it; the managed bounds'
// pii_mask too.
func ParsePIIPattern(p string) (string, error) {
	segs := strings.Split(p, ".")
	if len(segs) != 3 {
		return "", errors.New("pii rule: want db.table.column ('*' allowed per segment)")
	}
	for _, s := range segs {
		lit, _, _ := splitPIISeg(s)
		if s == "" || (s != "*" && (lit == "" || strings.ContainsAny(lit, "*\"'`"))) || strings.IndexFunc(s, unsafePIIRune) >= 0 {
			return "", errors.New("pii rule: each segment is '*' or a plain name, optionally with a leading or trailing '*'")
		}
	}
	return p, nil
}

// splitPIISeg cuts a pattern segment into its literal part and whether a
// '*' precedes or follows it. A lone '*' is an empty literal with both.
func splitPIISeg(pat string) (lit string, pre, suf bool) {
	lit, pre = strings.CutPrefix(pat, "*")
	lit, suf = strings.CutSuffix(lit, "*")
	return lit, pre, suf || pat == "*"
}

// unsafePIIRune reports a character that a plain name never holds and that
// could alter or hide text on a terminal: controls, spaces of any kind and
// format characters.
func unsafePIIRune(r rune) bool {
	return r == utf8.RuneError || unicode.IsControl(r) || unicode.IsSpace(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp)
}

// PIIPatternsOverlap reports whether some column db.table.column could
// match both patterns a and b (valid patterns): segment by segment, the
// way package pii folds names. It errs toward true: an allow rule that
// overlaps a managed mask is refused.
func PIIPatternsOverlap(a, b string) bool {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	if len(as) != 3 || len(bs) != 3 {
		return true
	}
	for i := range as {
		if !piiSegsOverlap(as[i], bs[i]) {
			return false
		}
	}
	return true
}

// piiSegsOverlap reports whether one name could match both segments.
func piiSegsOverlap(a, b string) bool {
	fold := func(s string) string { return strings.ToUpper(strings.ToLower(s)) }
	al, apre, asuf := splitPIISeg(a)
	bl, bpre, bsuf := splitPIISeg(b)
	al, bl = fold(al), fold(bl)
	match := func(lit string, pre, suf bool, name string) bool {
		switch {
		case pre && suf:
			return strings.Contains(name, lit)
		case pre:
			return strings.HasSuffix(name, lit)
		case suf:
			return strings.HasPrefix(name, lit)
		}
		return name == lit
	}
	switch {
	case !apre && !asuf:
		return match(bl, bpre, bsuf, al)
	case !bpre && !bsuf:
		return match(al, apre, asuf, bl)
	case apre && asuf, bpre && bsuf:
		// *x* and any other wildcard: a long enough name holds both.
		return true
	case asuf && bsuf: // x* and y*
		return strings.HasPrefix(al, bl) || strings.HasPrefix(bl, al)
	case apre && bpre: // *x and *y
		return strings.HasSuffix(al, bl) || strings.HasSuffix(bl, al)
	}
	// x* and *y: "xy" matches both.
	return true
}
