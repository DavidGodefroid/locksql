// Package weight turns a normalised engine plan into a verdict: OK, WARN or
// REFUSE. One cost model serves every engine:
//
//   - the tables of a group form one nested-loop pipeline, so the rows
//     examined by the group are the product of their estimates;
//   - the child groups of a group (subqueries, derived tables, compound
//     arms, the inner side of a hash join) add their cost, multiplied by the
//     rows of the group's pipeline when they are correlated;
//   - REFUSE when the estimate exceeds explain_rows_refuse, when one full
//     scan reads more than that, or on a cartesian join whose estimate is
//     above explain_rows_warn;
//   - WARN when the estimate exceeds explain_rows_warn, on a full scan above
//     it, on a sort or a temporary table above it, on a smaller cartesian
//     join, and, on a production profile, on a full scan of a table whose
//     size the engine does not know.
package weight

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
)

// Level is the outcome of the weight check, ordered by severity.
type Level int

const (
	// OK runs after the usual approval.
	OK Level = iota
	// Warn shows the reasons to the human before the approval.
	Warn
	// Refuse is final: the human loosens the limits to get past it.
	Refuse
)

var levelNames = [...]string{"OK", "WARN", "REFUSE"}

func (l Level) String() string {
	if l < OK || l > Refuse {
		return "Level(" + strconv.Itoa(int(l)) + ")"
	}
	return levelNames[l]
}

// MarshalText makes a Level show as "OK", "WARN" or "REFUSE" in JSON.
func (l Level) MarshalText() ([]byte, error) {
	if l < OK || l > Refuse {
		return nil, fmt.Errorf("weight: invalid level %d", int(l))
	}
	return []byte(levelNames[l]), nil
}

// UnmarshalText parses the names written by MarshalText.
func (l *Level) UnmarshalText(b []byte) error {
	for i, n := range levelNames {
		if string(b) == n {
			*l = Level(i)
			return nil
		}
	}
	return errors.New("weight: unknown level")
}

// Verdict is the result of Assess.
type Verdict struct {
	Level Level `json:"level"`
	// Reasons explains every finding that raised the level, most severe
	// threshold first in the order found. It is empty for a plain OK.
	Reasons []string `json:"reasons"`
	// Summary is one line for the approval prompt: each table with its
	// access and estimated rows, the sorts and temporary tables, and the
	// estimate, e.g. "big full ~50 000 · sort · est. 50 000 rows examined".
	Summary string `json:"summary"`
	// EstimatedRows is the estimated number of rows examined, saturated at
	// math.MaxInt64. Tables of unknown size count as one row.
	EstimatedRows int64 `json:"estimated_rows"`
}

// scan collects what the walk over the plan found.
type scan struct {
	tables     []string
	full       []sized // full table or index scans of known size
	unknown    []string
	cartesian  []string
	sorts      []sized // rows fed to each sort
	temps      []sized // rows fed to each temporary table
	correlated bool
}

type sized struct {
	name string
	rows int64
}

// Assess applies the cost model to p. Thresholds of l that are not set
// (zero or negative) take the defaults for the profile kind, so that a
// missing limit never disables the check. production turns a full scan of
// a table of unknown size into a WARN.
func Assess(p engine.Plan, l config.Limits, production bool) Verdict {
	def := config.DefaultLimits(production)
	warn, refuse := l.ExplainRowsWarn, l.ExplainRowsRefuse
	if refuse <= 0 {
		refuse = def.ExplainRowsRefuse
	}
	if warn <= 0 {
		warn = min(def.ExplainRowsWarn, refuse)
	}

	var s scan
	estimate := s.cost(&p.Root)

	v := Verdict{Level: OK, EstimatedRows: estimate}
	flag := func(lv Level, reason string) {
		v.Reasons = append(v.Reasons, reason)
		v.Level = max(v.Level, lv)
	}
	switch {
	case estimate > refuse:
		flag(Refuse, fmt.Sprintf("estimated rows examined %s > %s", num(estimate), num(refuse)))
	case estimate > warn:
		flag(Warn, fmt.Sprintf("estimated rows examined %s > %s", num(estimate), num(warn)))
	}
	for _, f := range s.full {
		switch {
		case f.rows > refuse:
			flag(Refuse, fmt.Sprintf("full scan of %s (~%s rows) > %s", f.name, num(f.rows), num(refuse)))
		case f.rows > warn:
			flag(Warn, fmt.Sprintf("full scan of %s (~%s rows)", f.name, num(f.rows)))
		}
	}
	for _, name := range s.cartesian {
		lv := Warn
		if estimate > warn {
			lv = Refuse
		}
		flag(lv, fmt.Sprintf("cartesian join on %s (no join condition)", name))
	}
	for _, x := range s.sorts {
		if x.rows > warn {
			flag(Warn, fmt.Sprintf("sort over ~%s rows", num(x.rows)))
		}
	}
	for _, x := range s.temps {
		if x.rows > warn {
			flag(Warn, fmt.Sprintf("temporary table over ~%s rows", num(x.rows)))
		}
	}
	if l.ExplainCostRefuse > 0 && p.Cost > l.ExplainCostRefuse {
		flag(Refuse, fmt.Sprintf("estimated cost %s > explain_cost_refuse %s", costText(p.Cost), costText(l.ExplainCostRefuse)))
	}
	if production {
		for _, name := range s.unknown {
			flag(Warn, fmt.Sprintf("full scan of %s (unknown size: the engine has no row count for it)", name))
		}
	}

	parts := s.tables
	if len(parts) == 0 {
		parts = []string{"no table"}
	}
	if len(s.sorts) > 0 {
		parts = append(parts, "sort")
	}
	if len(s.temps) > 0 {
		parts = append(parts, "temp table")
	}
	if s.correlated {
		parts = append(parts, "correlated subquery")
	}
	est := num(estimate)
	if len(s.unknown) > 0 {
		est += "+"
	}
	parts = append(parts, "est. "+est+" rows examined")
	if p.Cost > 0 {
		parts = append(parts, "cost "+costText(p.Cost))
	}
	v.Summary = strings.Join(parts, " · ")
	return v
}

// cost returns the rows examined by one execution of group g and records
// its tables and flags.
func (s *scan) cost(g *engine.PlanNode) int64 {
	var pipeline int64 = 1
	tables := 0
	for i := range g.Children {
		c := &g.Children[i]
		if c.Table == "" {
			continue
		}
		tables++
		pipeline = mul(pipeline, s.table(c))
	}
	var total int64
	if tables > 0 {
		total = pipeline
	}
	for i := range g.Children {
		c := &g.Children[i]
		if c.Table != "" {
			continue
		}
		sub := s.cost(c)
		if c.Correlated {
			s.correlated = true
			sub = mul(sub, pipeline)
		}
		total = add(total, sub)
	}
	if g.Sort {
		s.sorts = append(s.sorts, sized{g.Detail, total})
	}
	if g.Temp {
		s.temps = append(s.temps, sized{g.Detail, total})
	}
	return total
}

// table records a table node and returns the rows it contributes to its
// pipeline: its estimate, or 1 when the estimate is unknown or zero.
func (s *scan) table(t *engine.PlanNode) int64 {
	rows := "?"
	if t.EstRows >= 0 {
		rows = num(t.EstRows)
	}
	access := t.Access
	if access == "" {
		access = engine.AccessUnknown
	}
	s.tables = append(s.tables, fmt.Sprintf("%s %s ~%s", t.Table, access, rows))

	whole := access == engine.AccessFull || access == engine.AccessIndex
	switch {
	case t.EstRows < 0 && (whole || access == engine.AccessUnknown):
		s.unknown = append(s.unknown, t.Table)
	case whole:
		s.full = append(s.full, sized{t.Table, t.EstRows})
	}
	if t.NoJoinCond {
		s.cartesian = append(s.cartesian, t.Table)
	}
	// A table that is sorted or materialised by itself (MySQL reports
	// these on the table) counts like a group's sort.
	if t.Sort {
		s.sorts = append(s.sorts, sized{t.Table, max(t.EstRows, 0)})
	}
	if t.Temp {
		s.temps = append(s.temps, sized{t.Table, max(t.EstRows, 0)})
	}
	return max(t.EstRows, 1)
}

func mul(a, b int64) int64 {
	if a == 0 || b == 0 {
		return 0
	}
	if a > math.MaxInt64/b {
		return math.MaxInt64
	}
	return a * b
}

func add(a, b int64) int64 {
	if a > math.MaxInt64-b {
		return math.MaxInt64
	}
	return a + b
}

// num formats n with a space between groups of three digits: 50 000.
func num(n int64) string {
	d := strconv.FormatInt(n, 10)
	neg := strings.HasPrefix(d, "-")
	d = strings.TrimPrefix(d, "-")
	var b strings.Builder
	if neg {
		b.WriteByte('-')
	}
	for i, c := range d {
		if i > 0 && (len(d)-i)%3 == 0 {
			b.WriteByte(' ')
		}
		b.WriteRune(c)
	}
	return b.String()
}

// costText prints an engine cost rounded to two decimals.
func costText(c float64) string { return strconv.FormatFloat(math.Round(c*100)/100, 'f', -1, 64) }
