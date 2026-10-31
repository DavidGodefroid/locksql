package pii

import (
	"fmt"
	"strings"

	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/sqlast"
)

// MaskOutputs masks res in place following the analysed outputs of its
// statement: each column whose resolved sources are under a rule is masked
// in the output's mode. As a second line of defence a column whose engine-
// reported origin matches a rule is masked too. The other text and integer
// cells go through the detectors.
//
// The result must have exactly the analysed columns, and the columns the
// analysis expects by name (plain references, aliases, star expansions)
// must carry that label: otherwise masking by position could hit the wrong
// column, and the result is refused.
func MaskOutputs(res *engine.Result, outs []sqlast.Output, r Rules, ds []Detector, origin bool) error {
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
	for _, row := range res.Rows {
		for i, v := range row {
			if v == nil || i >= len(modes) {
				continue
			}
			if modes[i] != "" {
				row[i] = MaskValue(v, modes[i])
				continue
			}
			row[i] = detect(v, ds)
		}
	}
	return nil
}
