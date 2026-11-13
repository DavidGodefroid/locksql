package pii

import (
	"strings"

	"github.com/DavidGodefroid/locksql/internal/engine"
)

// maxCandidates caps the columns a refusal suggests.
const maxCandidates = 5

// Glob reports whether a pattern has a '*' in any segment: it may match
// columns created later, so matching none today is not an error.
func Glob(pattern string) bool { return strings.Contains(pattern, "*") }

// MatchesColumn reports whether pattern names some column of cols. The
// first segment is compared with ColumnInfo.DB: the database on MySQL and
// MariaDB, the schema on PostgreSQL, "main" on SQLite.
func MatchesColumn(pattern string, cols []engine.ColumnInfo) bool {
	for _, c := range cols {
		if anyMatch([]string{pattern}, [3]string{c.DB, c.Table, c.Column}) {
			return true
		}
	}
	return false
}

// Unmatched returns the patterns that name no column of cols, in order.
func Unmatched(patterns []string, cols []engine.ColumnInfo) []string {
	var out []string
	for _, p := range patterns {
		if !MatchesColumn(p, cols) {
			out = append(out, p)
		}
	}
	return out
}

// Candidates returns the columns, as db.table.column, that a pattern
// matching none of cols may have meant: those whose table and column it
// names under another first segment (app.customers.name for
// public.customers.name on PostgreSQL), else those whose column it names.
// At most maxCandidates, sorted.
func Candidates(pattern string, cols []engine.ColumnInfo) []string {
	seg := strings.Split(pattern, ".")
	if len(seg) != 3 {
		return nil
	}
	pick := func(match func(engine.ColumnInfo) bool) []string {
		var out []string
		for _, c := range cols {
			if match(c) {
				out = append(out, c.DB+"."+c.Table+"."+c.Column)
			}
		}
		out = canonical(out)
		if len(out) > maxCandidates {
			out = out[:maxCandidates]
		}
		return out
	}
	if out := pick(func(c engine.ColumnInfo) bool { return segMatch(seg[1], c.Table) && segMatch(seg[2], c.Column) }); len(out) > 0 {
		return out
	}
	return pick(func(c engine.ColumnInfo) bool { return segMatch(seg[2], c.Column) })
}

// FirstSegments returns the distinct first segments of cols (the schemas
// on PostgreSQL), sorted.
func FirstSegments(cols []engine.ColumnInfo) []string {
	out := make([]string, 0, len(cols))
	for _, c := range cols {
		out = append(out, c.DB)
	}
	return canonical(out)
}
