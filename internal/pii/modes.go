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
// returns its reference name, or "" for none.
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
	for i, c := range res.Columns {
		o := outs[i]
		if o.Label != "" && fold(o.Label) != fold(c.Label) {
			return fmt.Errorf("result column %d is labelled %q where %q was expected", i+1, c.Label, strings.ToLower(o.Label))
		}
		modes[i] = o.Mask
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
				if modes[i] == ModeRedact && cell != nil {
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
