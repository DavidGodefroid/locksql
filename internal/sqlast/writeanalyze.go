package sqlast

import (
	"slices"
	"strings"

	"github.com/DavidGodefroid/locksql/internal/sqlclass"
	refusal "github.com/DavidGodefroid/locksql/internal/sqlrefusal"
)

// ---- Writes ----

// write analyses a data-modifying statement and returns the columns of
// its RETURNING list (nil without one).
//
// The write's own clauses (its WHERE, FROM and USING lists, ORDER BY,
// conflict target, the values it stores and the query an INSERT reads)
// decide which rows change and what they receive. The human approves
// them, and the affected-row count already tells what they select, so
// the PII filter rules of a read do not apply there (lenient); every
// column and function in them is still resolved and checked against the
// allowlist. What they store must not copy a PII column, and a column
// under a rule may only receive NULL or DEFAULT (store).
//
// The RETURNING list is a select list over the rows written: each target
// column carries both its own provenance and that of the values stored
// in it (an INSERT or UPDATE may also return a value the statement chose,
// a default or a trigger's), and is masked like a read's output.
func (an *analyzer) write(w *Write, parent *scope) ([]column, error) {
	an.writes = true
	if w.With != nil {
		defs := make([]*cteDef, 0, len(w.With.CTEs))
		an.ctes = append(an.ctes, defs)
		an.withs = append(an.withs, w.With)
		defer func() {
			an.ctes = an.ctes[:len(an.ctes)-1]
			an.withs = an.withs[:len(an.withs)-1]
		}()
		for _, c := range w.With.CTEs {
			if err := an.defineCTE(c, w.With.Recursive, parent); err != nil {
				return nil, err
			}
		}
	}
	if len(w.Target.Parts) == 1 && an.findCTE(w.Target.Parts[0]) != nil {
		return nil, refusef(refusal.InvalidSQL, "%s names a CTE: a write must name a table", strings.ToLower(w.Target.Parts[0]))
	}
	target, err := an.tableName(w.Target)
	if err != nil {
		return nil, err
	}
	level := 0
	if parent != nil {
		level = parent.level + 1
	}
	sc := &scope{parent: parent, level: level, rels: []*relation{target}, node: &nodeState{level: level}}
	written := map[string]Prov{}
	var from []*relation
	var fromStar []column
	err = an.lenient(func() error {
		for _, te := range w.From {
			rels, star, err := an.tableExpr(te, sc, parent)
			if err != nil {
				return err
			}
			sc.rels = append(sc.rels, rels...)
			from = append(from, rels...)
			fromStar = append(fromStar, star...)
		}
		if err := an.inserted(w, target, sc, parent, written); err != nil {
			return err
		}
		for _, a := range w.Set {
			if err := an.assign(a, sc, target, written); err != nil {
				return err
			}
		}
		if w.Where != nil {
			if err := an.filter(w.Where, sc, "where", true); err != nil {
				return err
			}
		}
		for _, o := range w.OrderBy {
			if _, err := an.value(o.Expr, sc, "order by"); err != nil {
				return err
			}
		}
		return an.upsert(w, target, sc, written)
	})
	if err != nil {
		return nil, err
	}
	if w.Returning == nil {
		return nil, nil
	}
	// The rows written, as RETURNING sees them.
	ret := &relation{name: target.name, qual: target.qual, lookup: true, cols: slices.Clone(target.cols)}
	for i, c := range ret.cols {
		if p, ok := written[c.name]; ok {
			ret.cols[i].prov = union(c.prov, p)
		}
	}
	rels := []*relation{ret}
	star := slices.Clone(ret.cols)
	if an.d == sqlclass.Postgres {
		// PostgreSQL's RETURNING also sees the FROM and USING items.
		rels = append(rels, from...)
		star = append(star, fromStar...)
	}
	rsc := &scope{parent: parent, level: level, rels: rels, node: &nodeState{level: level}}
	var cols []column
	for _, it := range w.Returning {
		if it.Star {
			exp, err := an.expandStar(it, rsc, star)
			if err != nil {
				return nil, err
			}
			cols = append(cols, exp...)
			continue
		}
		p, err := an.value(it.Expr, rsc, "returning")
		if err != nil {
			return nil, err
		}
		name, labeled := it.Alias, it.Alias != ""
		if name == "" {
			name = defaultName(it.Expr)
			_, labeled = it.Expr.(*ColumnRef)
		}
		cols = append(cols, column{name: name, prov: p, labeled: labeled})
	}
	if rsc.node.aggregate {
		return nil, refuse(refusal.InvalidSQL, "aggregate functions are not allowed in RETURNING")
	}
	return cols, nil
}

// lenient runs f with the PII usage rules off (see write).
func (an *analyzer) lenient(f func() error) error {
	saved := an.env.Masking
	an.env.Masking = false
	defer func() { an.env.Masking = saved }()
	return f()
}

// inserted analyses what an INSERT or REPLACE stores: its VALUES rows, its
// query or its MySQL SET list.
func (an *analyzer) inserted(w *Write, target *relation, sc, parent *scope, written map[string]Prov) error {
	if w.Verb != "INSERT" && w.Verb != "REPLACE" {
		return nil
	}
	var cols []*column
	if w.Columns == nil {
		for i := range target.cols {
			cols = append(cols, &target.cols[i])
		}
	} else {
		for _, n := range w.Columns {
			c := findCol(target.cols, n)
			if c == nil {
				return refusef(refusal.UnknownName, "unknown column %s", strings.ToLower(n))
			}
			cols = append(cols, c)
		}
	}
	// VALUES see no column.
	vsc := &scope{parent: parent, level: sc.level, node: sc.node}
	for _, row := range w.Rows {
		if len(row) != len(cols) {
			return refusef(refusal.InvalidSQL, "a VALUES row has %d values for %d columns", len(row), len(cols))
		}
		for i, e := range row {
			if e == nil {
				continue // DEFAULT
			}
			p, err := an.value(e, vsc, "values")
			if err != nil {
				return err
			}
			if err := an.locate(an.store(cols[i], p, isNull(e), written), e); err != nil {
				return err
			}
		}
	}
	if w.Source != nil {
		src, err := an.query(w.Source, parent)
		if err != nil {
			return err
		}
		if len(src) != len(cols) {
			return refusef(refusal.InvalidSQL, "the query stores %d columns into %d", len(src), len(cols))
		}
		for i, c := range src {
			if err := an.store(cols[i], c.prov, nullColumn(w.Source, i), written); err != nil {
				return err
			}
		}
	}
	return nil
}

// upsert analyses ON CONFLICT and ON DUPLICATE KEY UPDATE. In PostgreSQL
// and SQLite, EXCLUDED is the row proposed for insertion: a default or a
// value the INSERT stores in each column.
func (an *analyzer) upsert(w *Write, target *relation, sc *scope, written map[string]Prov) error {
	for _, e := range w.Conflict {
		if _, err := an.value(e, sc, "on conflict"); err != nil {
			return err
		}
	}
	if w.ConflictWhere != nil {
		if err := an.filter(w.ConflictWhere, sc, "on conflict", true); err != nil {
			return err
		}
	}
	if w.Upsert == nil {
		return nil
	}
	usc := sc
	if an.d != sqlclass.MySQL {
		ex := &relation{name: "EXCLUDED", cols: slices.Clone(target.cols)}
		for i, c := range ex.cols {
			if p, ok := written[c.name]; ok {
				ex.cols[i].prov = union(c.prov, p)
			}
		}
		usc = &scope{parent: sc.parent, level: sc.level, rels: append(slices.Clone(sc.rels), ex), node: sc.node}
	}
	for _, a := range w.Upsert {
		if err := an.assign(a, usc, target, written); err != nil {
			return err
		}
	}
	if w.UpsertWhere != nil {
		return an.filter(w.UpsertWhere, usc, "on conflict", true)
	}
	return nil
}

// assign analyses one SET assignment of the target.
func (an *analyzer) assign(a *Assignment, sc *scope, target *relation, written map[string]Prov) error {
	if len(a.Qualifier) > 0 && an.findRel(sc, a.Qualifier) != target {
		return refusef(refusal.UnknownName, "SET target %s is not a column of the table written", strings.ToLower(strings.Join(append(slices.Clone(a.Qualifier), a.Column), ".")))
	}
	col := findCol(target.cols, a.Column)
	if col == nil {
		return refusef(refusal.UnknownName, "unknown column %s", strings.ToLower(a.Column))
	}
	if a.Value == nil {
		return nil // DEFAULT
	}
	p, err := an.value(a.Value, sc, "set")
	if err != nil {
		return err
	}
	return an.locate(an.store(col, p, isNull(a.Value), written), a.Value)
}

// store checks a value p written into the target column col: it must not
// carry a PII column's values (a copy would come back unmasked under the
// name of the column written, through RETURNING or a later read), and a
// column under a rule may only receive NULL or DEFAULT (any other value is
// one the agent chose, which a later read would mask and hand back as a
// cell reference to a value the agent knows).
func (an *analyzer) store(col *column, p Prov, null bool, written map[string]Prov) error {
	if p.Sensitive {
		return refusef(refusal.MaskedWrite, "this write stores values of PII column %s, which could come back unmasked under the name of the column written (through RETURNING or a later read); do not copy PII columns, or run the write as an unmasked query", piiNames(p))
	}
	if !null && an.underRule(col.prov) {
		return refusef(refusal.MaskedWrite, "this write stores into PII column %s a value the agent chose (a literal, an expression or another column); while PII mask rules exist, a masked column cannot receive values the agent chose, since a later read would mask the value and hand it back as a cell reference to a value the agent already knows. Set it to NULL or DEFAULT only, or run the write as an unmasked query", strings.ToLower(col.name))
	}
	if old, ok := written[col.name]; ok {
		p = union(old, p)
	}
	written[col.name] = p
	return nil
}

// underRule reports a value with a source under a mask rule.
func (an *analyzer) underRule(p Prov) bool {
	for _, s := range p.Sources {
		if _, ok := an.env.Rule(s); ok {
			return true
		}
	}
	return false
}

// isNull reports the literal NULL, possibly parenthesised.
func isNull(e Expr) bool {
	for {
		p, ok := e.(*Paren)
		if !ok {
			break
		}
		e = p.X
	}
	l, ok := e.(*Literal)
	return ok && l.Kind == LitNull
}

// nullColumn reports whether column i of a query is the literal NULL in
// every arm.
func nullColumn(b Body, i int) bool {
	switch b := b.(type) {
	case *Query:
		return nullColumn(b.Body, i)
	case *SetOp:
		return nullColumn(b.Left, i) && nullColumn(b.Right, i)
	case *Select:
		if i >= len(b.Items) {
			return false
		}
		for _, it := range b.Items[:i+1] {
			if it.Star {
				return false
			}
		}
		return isNull(b.Items[i].Expr)
	}
	return false
}
