package sqlast

import (
	"strings"

	"github.com/DavidGodefroid/locksql/internal/sqlclass"
	refusal "github.com/DavidGodefroid/locksql/internal/sqlrefusal"
)

// ParseWrite parses one data-modifying statement for the write analysis
// (see NeedsWriteAnalysis): an INSERT, REPLACE, UPDATE or DELETE, possibly
// led by a WITH, or (PostgreSQL) a SELECT led by a WITH whose CTEs modify
// data. The grammar is the read grammar plus single-table writes:
//
//   - INSERT and REPLACE with a column list, VALUES rows (DEFAULT allowed),
//     DEFAULT VALUES, a query, or a MySQL SET list; PostgreSQL and SQLite
//     ON CONFLICT ... DO NOTHING | DO UPDATE SET, MySQL ON DUPLICATE KEY
//     UPDATE;
//   - UPDATE with a SET list (PostgreSQL (a, b) = (x, y) lists of values),
//     FROM (PostgreSQL, SQLite) and WHERE;
//   - DELETE FROM with USING (PostgreSQL) and WHERE;
//   - MySQL ORDER BY and LIMIT on UPDATE and DELETE;
//   - a RETURNING list, read as a select list.
//
// Anything else (MERGE, multi-table MySQL writes, ONLY, WHERE CURRENT OF,
// subfield or subscript targets, a subquery assigned to a column list,
// PostgreSQL 18 RETURNING WITH, ...) is refused, as is a statement that
// modifies nothing.
func ParseWrite(d sqlclass.Dialect, sql string) (*Statement, error) {
	p, err := newParser(d, sql)
	if err != nil {
		return nil, err
	}
	st, err := p.writeStatement()
	if err != nil {
		return nil, p.locate(err)
	}
	return st, nil
}

// writeStatement parses the whole write statement.
func (p *parser) writeStatement() (*Statement, error) {
	d := p.d
	st := &Statement{SQL: p.src, Dialect: d}
	var with *With
	var err error
	if p.word(0, "WITH") {
		p.topWith = true
		if with, err = p.with(); err != nil {
			return nil, err
		}
	}
	switch {
	case p.word(0, "INSERT", "REPLACE", "UPDATE", "DELETE"):
		w, err := p.write()
		if err != nil {
			return nil, err
		}
		w.With = with
		st.Write = w
	case with != nil && writesData(with) && (p.word(0, "SELECT") || p.punct(0, "(")):
		q, err := p.queryRest(&Query{With: with}, 0)
		if err != nil {
			return nil, err
		}
		st.Query = q
	case p.word(0, "MERGE"):
		return nil, refuse(refusal.UnsupportedSyntax, "MERGE is not supported when its rows come back or it stores a query's rows; use INSERT, UPDATE or DELETE, or run it as an unmasked query")
	default:
		return nil, refuse(refusal.StatementKind, "only INSERT, REPLACE, UPDATE, DELETE and a SELECT over data-modifying CTEs are analysed as writes")
	}
	if p.i < len(p.toks) {
		return nil, p.unexpected()
	}
	return st, nil
}

// writesData reports a WITH that holds a data-modifying CTE.
func writesData(w *With) bool {
	for _, c := range w.CTEs {
		if c.Write != nil {
			return true
		}
	}
	return false
}

// NeedsWriteAnalysis reports whether a write statement must pass the write
// analysis (ParseWrite, then Analyze) before it runs while mask rules
// exist: its rows come back (a RETURNING list, or a statement led by WITH
// whose main statement is a query), or it is an INSERT or REPLACE that
// holds a query (its source, a CTE or a subquery in VALUES). A statement
// that cannot be lexed reports true: the parser refuses it.
func NeedsWriteAnalysis(d sqlclass.Dialect, sql string) bool {
	toks, err := sqlclass.Lex(d, strings.TrimSpace(sql))
	if err != nil {
		return true
	}
	if len(toks) == 0 {
		return false
	}
	for _, t := range toks {
		if t.Kind == sqlclass.TokWord && t.Text == "RETURNING" {
			return true
		}
	}
	verb := ""
	for _, t := range toks {
		if t.Kind == sqlclass.TokWord && t.Depth == 0 {
			switch t.Text {
			case "SELECT", "VALUES", "TABLE", "INSERT", "REPLACE", "UPDATE", "DELETE", "MERGE":
				verb = t.Text
			}
		}
		if verb != "" {
			break
		}
	}
	lead := toks[0].Kind == sqlclass.TokWord && toks[0].Text == "WITH"
	switch verb {
	case "", "SELECT", "VALUES", "TABLE":
		return lead
	case "INSERT", "REPLACE":
		for _, t := range toks {
			if t.Kind == sqlclass.TokWord && (t.Text == "SELECT" || t.Text == "TABLE" || t.Text == "WITH") {
				return true
			}
		}
	}
	return false
}

// write reads an INSERT, REPLACE, UPDATE or DELETE.
func (p *parser) write() (*Write, error) {
	if err := p.enter(); err != nil {
		return nil, err
	}
	defer p.leave()
	start := p.i
	w := &Write{Verb: p.toks[p.i].Text}
	p.i++
	var err error
	switch w.Verb {
	case "INSERT", "REPLACE":
		err = p.insert(w)
	case "UPDATE":
		err = p.update(w)
	default:
		err = p.delete(w)
	}
	if err != nil {
		return nil, err
	}
	if p.word(0, "RETURNING") {
		p.i++
		if p.word(0, "WITH") && p.punct(1, "(") {
			return nil, refuse(refusal.UnsupportedSyntax, "RETURNING WITH (OLD/NEW AS ...) is not supported")
		}
		for {
			it, err := p.selectItem()
			if err != nil {
				return nil, err
			}
			w.Returning = append(w.Returning, it)
			if !p.punct(0, ",") {
				break
			}
			p.i++
		}
		if p.word(0, "INTO") {
			return nil, refuse(refusal.Forbidden, "RETURNING ... INTO is not allowed")
		}
	}
	w.Sp = p.span(start)
	return w, nil
}

// skipWords skips any of words, in any order.
func (p *parser) skipWords(words ...string) {
	for p.word(0, words...) {
		p.i++
	}
}

// sqliteOr skips SQLite's OR ROLLBACK | ABORT | REPLACE | FAIL | IGNORE.
func (p *parser) sqliteOr() error {
	if p.d != sqlclass.SQLite || !p.word(0, "OR") {
		return nil
	}
	if !p.word(1, "ROLLBACK", "ABORT", "REPLACE", "FAIL", "IGNORE") {
		p.i++
		return p.unexpected()
	}
	p.i += 2
	return nil
}

// target reads the name of the relation written.
func (p *parser) target() (*TableName, error) {
	start := p.i
	if p.word(0, "ONLY") {
		return nil, refuse(refusal.UnsupportedSyntax, "ONLY is not supported")
	}
	if p.mysqlDoubleQuoted(0) {
		return nil, refuse(refusal.UnsupportedSyntax, "double-quoted names are ambiguous in MySQL; use backquotes")
	}
	var parts []string
	for {
		name, ok := p.ident(false)
		if !ok {
			return nil, p.unexpected()
		}
		parts = append(parts, name)
		if !p.punct(0, ".") {
			break
		}
		p.i++
	}
	if len(parts) > 3 {
		return nil, p.unexpected()
	}
	if p.punct(0, "*") || p.word(0, "PARTITION", "INDEXED", "NOT") {
		return nil, p.unexpected()
	}
	return &TableName{Parts: parts, Sp: p.span(start)}, nil
}

// targetAlias reads an optional [AS] alias of the relation written; a bare
// alias is any non-reserved word but the words in stop.
func (p *parser) targetAlias(t *TableName, bare bool, stop ...string) error {
	if p.word(0, "AS") {
		p.i++
		name, ok := p.ident(true)
		if !ok {
			return p.unexpected()
		}
		t.Alias = name
		return nil
	}
	if !bare || p.word(0, stop...) {
		return nil
	}
	if tk, ok := p.tok(0); ok && (tk.Kind == sqlclass.TokQuotedIdent || tk.Kind == sqlclass.TokWord && !reserved[tk.Text]) {
		name, _ := p.ident(false)
		t.Alias = name
	}
	return nil
}

func (p *parser) insert(w *Write) error {
	if p.d == sqlclass.MySQL {
		p.skipWords("LOW_PRIORITY", "DELAYED", "HIGH_PRIORITY", "IGNORE")
		if p.word(0, "INTO") {
			p.i++
		}
	} else {
		if w.Verb == "INSERT" {
			if err := p.sqliteOr(); err != nil {
				return err
			}
		} else if p.d != sqlclass.SQLite {
			return p.unexpected() // REPLACE is MySQL and SQLite
		}
		if err := p.expectWord("INTO"); err != nil {
			return err
		}
	}
	t, err := p.target()
	if err != nil {
		return err
	}
	w.Target = t
	if p.d != sqlclass.MySQL {
		if err := p.targetAlias(t, false); err != nil {
			return err
		}
	}
	if p.punct(0, "(") && !p.word(1, "SELECT", "WITH") && !p.punct(1, "(") {
		cols, err := p.nameList()
		if err != nil {
			return err
		}
		w.Columns = cols
	}
	if p.d == sqlclass.Postgres && p.word(0, "OVERRIDING") {
		if !p.word(1, "SYSTEM", "USER") || !p.word(2, "VALUE") {
			return p.unexpected()
		}
		p.i += 3
	}
	switch {
	case p.word(0, "DEFAULT") && p.word(1, "VALUES") && p.d != sqlclass.MySQL:
		p.i += 2
	case p.word(0, "VALUES") || p.word(0, "VALUE") && p.d == sqlclass.MySQL:
		p.i++
		for {
			if p.word(0, "ROW") && p.d == sqlclass.MySQL {
				p.i++
			}
			row, err := p.valueRow()
			if err != nil {
				return err
			}
			w.Rows = append(w.Rows, row)
			if !p.punct(0, ",") {
				break
			}
			p.i++
		}
	case p.word(0, "SET") && p.d == sqlclass.MySQL && w.Columns == nil:
		p.i++
		set, err := p.assignments()
		if err != nil {
			return err
		}
		w.Set = set
	case p.word(0, "SELECT", "WITH") || p.punct(0, "("):
		q, err := p.query()
		if err != nil {
			return err
		}
		w.Source = q
	case p.word(0, "TABLE"):
		return refuse(refusal.StatementKind, "TABLE is not allowed: only SELECT is")
	default:
		return p.unexpected()
	}
	return p.onConflict(w)
}

// valueRow reads one parenthesised VALUES row.
func (p *parser) valueRow() ([]Expr, error) {
	if err := p.expectPunct("("); err != nil {
		return nil, err
	}
	var row []Expr
	for {
		e, err := p.valueOrDefault()
		if err != nil {
			return nil, err
		}
		row = append(row, e)
		if !p.punct(0, ",") {
			break
		}
		p.i++
	}
	return row, p.expectPunct(")")
}

// valueOrDefault reads a value written to a column: nil for DEFAULT.
func (p *parser) valueOrDefault() (Expr, error) {
	if p.word(0, "DEFAULT") {
		if p.punct(1, "(") || p.punct(1, ".") {
			return nil, refuse(refusal.UnsupportedSyntax, "DEFAULT(...) is not supported")
		}
		p.i++
		return nil, nil
	}
	return p.expr()
}

// assignments reads a SET list: col = value, [qualifier.]col = value
// (MySQL), (a, b) = (x, y) (PostgreSQL, SQLite).
func (p *parser) assignments() ([]*Assignment, error) {
	var out []*Assignment
	for {
		if p.punct(0, "(") {
			if p.d == sqlclass.MySQL {
				return nil, p.unexpected()
			}
			cols, err := p.nameList()
			if err != nil {
				return nil, err
			}
			if err := p.expectPunct("="); err != nil {
				return nil, err
			}
			if p.word(0, "ROW") {
				p.i++
			}
			if p.punct(0, "(") && p.word(1, "SELECT", "WITH") {
				return nil, refuse(refusal.UnsupportedSyntax, "a subquery assigned to a column list is not supported; assign each column")
			}
			vals, err := p.valueRow()
			if err != nil {
				return nil, err
			}
			if len(vals) != len(cols) {
				return nil, refusef(refusal.InvalidSQL, "a SET list assigns %d values to %d columns", len(vals), len(cols))
			}
			for i, c := range cols {
				out = append(out, &Assignment{Column: c, Value: vals[i]})
			}
		} else {
			var parts []string
			for {
				name, ok := p.ident(len(parts) > 0)
				if !ok {
					return nil, p.unexpected()
				}
				parts = append(parts, name)
				if !p.punct(0, ".") {
					break
				}
				p.i++
			}
			if len(parts) > 1 && p.d != sqlclass.MySQL {
				return nil, refuse(refusal.UnsupportedSyntax, "a subfield or a qualified column as a SET target is not supported")
			}
			if len(parts) > 3 {
				return nil, p.unexpected()
			}
			if err := p.expectPunct("="); err != nil {
				return nil, err
			}
			v, err := p.valueOrDefault()
			if err != nil {
				return nil, err
			}
			out = append(out, &Assignment{Qualifier: parts[:len(parts)-1], Column: parts[len(parts)-1], Value: v})
		}
		if !p.punct(0, ",") {
			return out, nil
		}
		p.i++
	}
}

// onConflict reads ON CONFLICT (PostgreSQL, SQLite) or ON DUPLICATE KEY
// UPDATE (MySQL).
func (p *parser) onConflict(w *Write) error {
	if !p.word(0, "ON") {
		return nil
	}
	if p.d == sqlclass.MySQL {
		if !p.word(1, "DUPLICATE") || !p.word(2, "KEY") || !p.word(3, "UPDATE") {
			return p.unexpected()
		}
		p.i += 4
		set, err := p.assignments()
		if err != nil {
			return err
		}
		w.Upsert = set
		return nil
	}
	if !p.word(1, "CONFLICT") {
		return p.unexpected()
	}
	p.i += 2
	switch {
	case p.punct(0, "("):
		p.i++
		list, err := p.exprList()
		if err != nil {
			return err
		}
		if err := p.expectPunct(")"); err != nil {
			return err
		}
		w.Conflict = list
		if p.word(0, "WHERE") {
			p.i++
			e, err := p.expr()
			if err != nil {
				return err
			}
			w.ConflictWhere = e
		}
	case p.word(0, "ON") && p.word(1, "CONSTRAINT") && p.d == sqlclass.Postgres:
		p.i += 2
		if _, ok := p.ident(false); !ok {
			return p.unexpected()
		}
	}
	if err := p.expectWord("DO"); err != nil {
		return err
	}
	if p.word(0, "NOTHING") {
		p.i++
	} else {
		if err := p.expectWord("UPDATE"); err != nil {
			return err
		}
		if err := p.expectWord("SET"); err != nil {
			return err
		}
		set, err := p.assignments()
		if err != nil {
			return err
		}
		w.Upsert = set
		if p.word(0, "WHERE") {
			p.i++
			e, err := p.expr()
			if err != nil {
				return err
			}
			w.UpsertWhere = e
		}
	}
	if p.word(0, "ON") {
		return refuse(refusal.UnsupportedSyntax, "only one ON CONFLICT clause is supported")
	}
	return nil
}

func (p *parser) update(w *Write) error {
	switch p.d {
	case sqlclass.MySQL:
		p.skipWords("LOW_PRIORITY", "IGNORE")
	case sqlclass.SQLite:
		if err := p.sqliteOr(); err != nil {
			return err
		}
	}
	t, err := p.target()
	if err != nil {
		return err
	}
	w.Target = t
	if err := p.targetAlias(t, true, "SET"); err != nil {
		return err
	}
	if !p.word(0, "SET") {
		if p.punct(0, ",") || p.word(0, "JOIN", "INNER", "LEFT", "RIGHT", "CROSS", "STRAIGHT_JOIN", "NATURAL") {
			return refuse(refusal.UnsupportedSyntax, "a multi-table UPDATE is not supported here; update one table")
		}
		return p.unexpected()
	}
	p.i++
	if w.Set, err = p.assignments(); err != nil {
		return err
	}
	if p.word(0, "FROM") && p.d != sqlclass.MySQL {
		p.i++
		if w.From, err = p.fromList(); err != nil {
			return err
		}
	}
	if err := p.writeWhere(w); err != nil {
		return err
	}
	return p.writeOrderLimit(w)
}

func (p *parser) delete(w *Write) error {
	if p.d == sqlclass.MySQL {
		p.skipWords("LOW_PRIORITY", "QUICK", "IGNORE")
	}
	if !p.word(0, "FROM") {
		return refuse(refusal.UnsupportedSyntax, "only DELETE FROM a single table is supported here")
	}
	p.i++
	t, err := p.target()
	if err != nil {
		return err
	}
	w.Target = t
	if err := p.targetAlias(t, true); err != nil {
		return err
	}
	if p.word(0, "USING") {
		if p.d != sqlclass.Postgres {
			return refuse(refusal.UnsupportedSyntax, "a multi-table DELETE is not supported here; delete from one table")
		}
		p.i++
		if w.From, err = p.fromList(); err != nil {
			return err
		}
	}
	if err := p.writeWhere(w); err != nil {
		return err
	}
	return p.writeOrderLimit(w)
}

// fromList reads a comma-separated list of FROM items.
func (p *parser) fromList() ([]TableExpr, error) {
	var out []TableExpr
	for {
		te, err := p.tableRef()
		if err != nil {
			return nil, err
		}
		out = append(out, te)
		if !p.punct(0, ",") {
			return out, nil
		}
		p.i++
	}
}

func (p *parser) writeWhere(w *Write) error {
	if !p.word(0, "WHERE") {
		return nil
	}
	p.i++
	if p.word(0, "CURRENT") && p.word(1, "OF") {
		return refuse(refusal.UnsupportedSyntax, "WHERE CURRENT OF is not supported")
	}
	e, err := p.expr()
	if err != nil {
		return err
	}
	w.Where = e
	return nil
}

// writeOrderLimit reads the MySQL ORDER BY and LIMIT of an UPDATE or a
// DELETE.
func (p *parser) writeOrderLimit(w *Write) error {
	if p.d != sqlclass.MySQL {
		return nil
	}
	if p.word(0, "ORDER") {
		p.i++
		if err := p.expectWord("BY"); err != nil {
			return err
		}
		list, err := p.orderList()
		if err != nil {
			return err
		}
		w.OrderBy = list
	}
	if p.word(0, "LIMIT") {
		l, err := p.limit()
		if err != nil {
			return err
		}
		w.Limit = l
	}
	return nil
}
