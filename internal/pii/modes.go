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
	cut := res.CutSet()
	for ri, row := range res.Rows {
		for i, v := range row {
			if v == nil || i >= len(modes) {
				continue
			}
			if modes[i] != "" {
				// A cut cell holds the start of its value only: a reference
				// would stand for a value that does not exist.
				if refs[i] && cell != nil && !cut[[2]int{ri, i}] {
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
