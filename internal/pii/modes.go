package pii

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/sqlast"
)

// Redacted is the cell of a column masked in mode redact.
const Redacted = "<redacted>"

// MaskValue masks one non-NULL cell in mode.
func MaskValue(v any, mode string) any {
	switch mode {
	case ModeRedact:
		return Redacted
	case ModeEmail:
		if s, ok := v.(string); ok {
			if at := strings.LastIndexByte(s, '@'); at > 0 && at < len(s)-1 && utf8.ValidString(s) {
				first, _ := utf8.DecodeRuneInString(s)
				return string(first) + "***@" + s[at+1:]
			}
		}
	}
	return maskCell(v)
}

// CellText is the text of a cell value, as compared and substituted.
func CellText(v any) string {
	switch x := v.(type) {
	case []byte:
		return string(x)
	case string:
		return x
	case time.Time:
		return x.Format(time.RFC3339Nano)
	}
	return fmt.Sprint(v)
}

// RedactedRef is a redacted cell that carries a reference to its value,
// which the console alone keeps.
func RedactedRef(name string) string { return "<redacted:" + name + ">" }

// MaskOutputs masks res in place following the analysed outputs of its
// statement: each column whose resolved sources are under a rule is masked
// in the output's mode. As a second line of defence a column whose engine-
// reported origin matches a rule is masked too. The other text and integer
// cells go through the detectors.
//
// cell, when not nil, stores the value of a cell masked in mode redact and
// returns its reference name, or "" for none. It is called only for a plain
// column the analysis masks in mode redact, whose values cannot be literals
// of the statement and all of whose sources are under a mask rule
// (referenceable): anywhere else the agent may know the value behind the
// reference (a constant, an unmasked UNION arm, an aggregate) and could
// look up one row on it without the k-anonymity check. A column masked by
// its engine-reported origin alone gets plain <redacted> too.
//
// The result must have exactly the analysed columns, and the columns the
// analysis expects by name (plain references, aliases, star expansions)
// must carry that label: otherwise masking by position could hit the wrong
// column, and the result is refused.
func MaskOutputs(res *engine.Result, outs []sqlast.Output, r Rules, ds []Detector, cell func(row, col int, v any) string, origin bool) error {
	if len(res.Columns) != len(outs) {
		return fmt.Errorf("the result has %d columns where the statement was analysed with %d", len(res.Columns), len(outs))
	}
	modes := make([]string, len(outs))
	refs := make([]bool, len(outs))
	for i, c := range res.Columns {
		o := outs[i]
		if o.Label != "" && fold(o.Label) != fold(c.Label) {
			return fmt.Errorf("result column %d is labelled %q where %q was expected", i+1, c.Label, strings.ToLower(o.Label))
		}
		modes[i] = o.Mask
		refs[i] = o.Mask == ModeRedact && referenceable(o.Prov, r)
		if modes[i] == "" && origin && c.HasOrigin() {
			if m, ok := r.Mode(c.OriginDB, c.OriginTable, c.OriginColumn); ok {
				modes[i] = m
			}
		}
	}
	for ri, row := range res.Rows {
		for i, v := range row {
			if v == nil || i >= len(modes) {
				continue
			}
			if modes[i] != "" {
				if refs[i] && cell != nil {
					if name := cell(ri, i, v); name != "" {
						row[i] = RedactedRef(name)
						continue
					}
				}
				row[i] = MaskValue(v, modes[i])
				continue
			}
			row[i] = detect(v, ds)
		}
	}
	return nil
}

// referenceable reports a plain, literal-free column whose every source is
// under a mask rule: its cells hold only values the agent never saw. A view
// source counts only when a rule matches it by name (fail closed).
func referenceable(p sqlast.Prov, r Rules) bool {
	if p.Kind != sqlast.KindIdentity || p.Lit || len(p.Sources) == 0 {
		return false
	}
	for _, s := range p.Sources {
		var ok bool
		if s.View {
			_, ok = r.ModeByName(s.Column)
		} else {
			_, ok = r.Mode(s.DB, s.Table, s.Column)
		}
		if !ok {
			return false
		}
	}
	return true
}
