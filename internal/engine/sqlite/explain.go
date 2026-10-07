package sqlite

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"

	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

// eqpRow is one EXPLAIN QUERY PLAN row. It is also the raw plan format.
type eqpRow struct {
	ID     int64  `json:"id"`
	Parent int64  `json:"parent"`
	Detail string `json:"detail"`
}

// Explain runs EXPLAIN QUERY PLAN on q and normalises it. SQLite gives no
// row estimates: a table's size comes from sqlite_stat1 when ANALYZE has
// filled it, and is -1 otherwise.
func (s *session) Explain(ctx context.Context, db, q string) (engine.Plan, error) {
	toks, err := lexSingle(q)
	if err != nil {
		return engine.Plan{}, err
	}
	if err := s.checkDB(ctx, db); err != nil {
		return engine.Plan{}, err
	}
	ctx, cancel := s.withTimeout(ctx)
	defer cancel()

	rows, err := s.conn.QueryContext(ctx, "EXPLAIN QUERY PLAN "+q)
	if err != nil {
		return engine.Plan{}, wrap(ctx, err)
	}
	eqp := []eqpRow{}
	for rows.Next() {
		var r eqpRow
		var notUsed int64
		if err := rows.Scan(&r.ID, &r.Parent, &notUsed, &r.Detail); err != nil {
			rows.Close()
			return engine.Plan{}, wrap(ctx, err)
		}
		eqp = append(eqp, r)
	}
	if err := closeRows(rows); err != nil {
		return engine.Plan{}, wrap(ctx, err)
	}

	schemas, err := s.Databases(ctx)
	if err != nil {
		return engine.Plan{}, err
	}
	st, err := s.loadStats(ctx, schemas)
	if err != nil {
		return engine.Plan{}, err
	}
	names, err := s.objectNames(ctx, schemas)
	if err != nil {
		return engine.Plan{}, err
	}
	var raw bytes.Buffer
	enc := json.NewEncoder(&raw)
	enc.SetEscapeHTML(false) // keep "<" and ">" of constraints readable
	if err := enc.Encode(eqp); err != nil {
		return engine.Plan{}, err
	}
	return engine.Plan{Root: parsePlan(eqp, st, aliases(toks, names)), Raw: bytes.TrimSpace(raw.Bytes())}, nil
}

// aliases maps lower-cased aliases to table names, from "<table> [AS] <alias>"
// in the statement. names maps lower-cased table and view names to their
// spelling. EXPLAIN QUERY PLAN names a table by its alias when it has one.
func aliases(toks []sqlclass.Token, names map[string]string) map[string]string {
	out := map[string]string{}
	isIdent := func(t sqlclass.Token) bool {
		return t.Kind == sqlclass.TokWord || t.Kind == sqlclass.TokQuotedIdent
	}
	for i := 1; i < len(toks); i++ {
		if !isIdent(toks[i]) {
			continue
		}
		j := i - 1
		if toks[j].Kind == sqlclass.TokWord && toks[j].Text == "AS" && j > 0 {
			j--
		}
		if !isIdent(toks[j]) {
			continue
		}
		if table, ok := names[strings.ToLower(toks[j].Name())]; ok {
			alias := strings.ToLower(toks[i].Name())
			if _, seen := out[alias]; !seen {
				out[alias] = table
			}
		}
	}
	return out
}

type tnode struct {
	n    engine.PlanNode
	kids []*tnode
}

// parsePlan builds the normalised tree from EXPLAIN QUERY PLAN rows:
//   - "SCAN t" is a full scan, "SCAN t USING [COVERING] INDEX i" a full
//     index scan; both read the table's sqlite_stat1 row count;
//   - "SEARCH t USING ... (a=? AND b>?)" is a lookup, or a range when a
//     constraint is an inequality. A rowid lookup reads 1 row, an index
//     lookup the sqlite_stat1 figure for its equality prefix, and a range
//     what the equality prefix (or the table) leaves, divided by 4 per
//     bound, as SQLite itself assumes without sqlite_stat4;
//   - "USE TEMP B-TREE FOR ..." marks its group Temp (and Sort for ORDER BY,
//     GROUP BY and DISTINCT);
//   - every other row is a group (subquery, co-routine, compound arm...),
//     Correlated for "CORRELATED ..." and Temp for "MATERIALIZE ...".
//
// A table scanned after another table of the same pipeline is marked
// NoJoinCond: every outer row reads all of it.
func parsePlan(rows []eqpRow, st stats, alias map[string]string) engine.PlanNode {
	root := &tnode{n: engine.PlanNode{Detail: "QUERY", EstRows: -1}}
	byID := map[int64]*tnode{0: root}
	for _, r := range rows {
		parent := byID[r.Parent]
		if parent == nil {
			parent = root
		}
		d := r.Detail
		switch {
		case strings.HasPrefix(d, "USE TEMP B-TREE"):
			parent.n.Temp = true
			if strings.Contains(d, "ORDER BY") || strings.Contains(d, "GROUP BY") || strings.Contains(d, "DISTINCT") {
				parent.n.Sort = true
			}
			byID[r.ID] = parent
			continue
		case strings.Contains(d, "BLOOM FILTER"), d == "SCAN CONSTANT ROW":
			byID[r.ID] = parent
			continue
		}
		var node engine.PlanNode
		if strings.HasPrefix(d, "SCAN ") || strings.HasPrefix(d, "SEARCH ") {
			node = tableNode(d, st, alias)
		} else {
			node = engine.PlanNode{
				Detail:     d,
				EstRows:    -1,
				Correlated: strings.HasPrefix(d, "CORRELATED "),
				Temp:       strings.HasPrefix(d, "MATERIALIZE"),
			}
		}
		t := &tnode{n: node}
		parent.kids = append(parent.kids, t)
		byID[r.ID] = t
	}
	return build(root)
}

func build(t *tnode) engine.PlanNode {
	n := t.n
	seenTable := false
	for _, k := range t.kids {
		c := build(k)
		if c.Table != "" {
			if seenTable && (c.Access == engine.AccessFull || c.Access == engine.AccessIndex) {
				c.NoJoinCond = true
			}
			seenTable = true
		}
		n.Children = append(n.Children, c)
	}
	return n
}

func tableNode(detail string, st stats, alias map[string]string) engine.PlanNode {
	words := strings.Fields(detail)
	if len(words) < 2 {
		return engine.PlanNode{Table: "?", Access: engine.AccessUnknown, Detail: detail, EstRows: -1}
	}
	verb, name, rest := words[0], words[1], words[2:]
	if len(rest) >= 2 && rest[0] == "AS" { // "SCAN t AS a" in some versions
		rest = rest[2:]
	}
	table := name
	if t, ok := alias[strings.ToLower(name)]; ok {
		table = t
	}
	n := engine.PlanNode{Table: table, Detail: detail, EstRows: -1}
	size, known := st.tables[strings.ToLower(table)]
	if !known {
		size = -1
	}
	using := strings.Join(rest, " ")

	if strings.Contains(using, "VIRTUAL TABLE") {
		n.Access = engine.AccessUnknown
		return n
	}
	if verb == "SCAN" {
		n.Access = engine.AccessFull
		if strings.Contains(using, "INDEX") {
			n.Access = engine.AccessIndex
		}
		n.EstRows = size
		return n
	}

	// SEARCH: read the constraint list "(a=? AND b>?)".
	eq, bounds := 0, 0
	if open := strings.LastIndex(using, "("); open >= 0 {
		for _, c := range strings.Split(strings.Trim(using[open:], "()"), " AND ") {
			if strings.ContainsAny(c, "<>") {
				bounds++
			} else if strings.Contains(c, "=") {
				eq++
			}
		}
	}
	isRange := bounds > 0
	n.Access = engine.AccessLookup
	if isRange {
		n.Access = engine.AccessRange
	}
	base := size // rows left by the equality prefix
	switch {
	case strings.Contains(using, "AUTOMATIC"):
		// SQLite builds a transient index for this statement.
		n.Temp = true
		return n
	case strings.Contains(using, "PRIMARY KEY"):
		if !isRange {
			n.EstRows = 1
			return n
		}
	case strings.Contains(using, "INDEX"):
		idx := ""
		for i, w := range rest {
			if w == "INDEX" && i+1 < len(rest) {
				idx = rest[i+1]
				break
			}
		}
		if figs, ok := st.indexes[strings.ToLower(idx)]; ok && eq > 0 {
			if eq < len(figs) {
				base = figs[eq]
			} else {
				base = 1
			}
		} else if eq > 0 {
			base = -1
		}
		if !isRange {
			n.EstRows = base
			return n
		}
	default:
		n.Access = engine.AccessUnknown
		return n
	}
	if base >= 0 {
		n.EstRows = max(base>>(2*min(bounds, 2)), 1)
	}
	return n
}
