package sqlast

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

// maxDepth bounds the nesting of queries and expressions.
const maxDepth = 128

func refuse(reason string) error { return &sqlclass.Refusal{Reason: reason} }

func refusef(format string, args ...any) error {
	return &sqlclass.Refusal{Reason: fmt.Sprintf(format, args...)}
}

type set map[string]bool

func newSet(words ...string) set {
	s := make(set, len(words))
	for _, w := range words {
		s[w] = true
	}
	return s
}

// reserved words never serve as a bare alias, and never as a bare column
// name.
var reserved = newSet(
	"SELECT", "FROM", "WHERE", "GROUP", "HAVING", "ORDER", "LIMIT", "OFFSET", "FETCH", "UNION", "INTERSECT",
	"EXCEPT", "MINUS", "JOIN", "INNER", "LEFT", "RIGHT", "FULL", "OUTER", "CROSS", "NATURAL", "ON", "USING",
	"AS", "AND", "OR", "NOT", "XOR", "WINDOW", "FOR", "INTO", "LATERAL", "WITH", "CASE", "WHEN", "THEN",
	"ELSE", "END", "IS", "IN", "BETWEEN", "LIKE", "ILIKE", "GLOB", "REGEXP", "RLIKE", "SIMILAR", "ESCAPE",
	"COLLATE", "DISTINCT", "ALL", "BY", "ASC", "DESC", "NULLS", "STRAIGHT_JOIN", "LOCK", "PROCEDURE",
	"RETURNING", "VALUES", "TABLE", "QUALIFY", "NULL", "TRUE", "FALSE", "EXISTS", "OVER", "FILTER", "USE",
	"FORCE", "IGNORE", "PARTITION", "TABLESAMPLE", "MATCH", "DIV", "MOD", "INTERVAL", "ANY", "SOME",
	"DISTINCTROW", "HIGH_PRIORITY", "SQL_CALC_FOUND_ROWS", "SQL_SMALL_RESULT", "SQL_BIG_RESULT",
	"SQL_BUFFER_RESULT", "SQL_NO_CACHE", "SQL_CACHE", "ONLY", "ROWS", "WITHIN",
)

// systemNiladic are bare keywords that read session or server metadata.
var systemNiladic = newSet("CURRENT_USER", "SESSION_USER", "USER", "CURRENT_ROLE", "CURRENT_SCHEMA",
	"CURRENT_CATALOG", "SYSTEM_USER")

// timeNiladic are bare keywords for the current date and time.
var timeNiladic = newSet("CURRENT_DATE", "CURRENT_TIME", "CURRENT_TIMESTAMP", "LOCALTIME", "LOCALTIMESTAMP")

// typedLiteral words directly followed by a string make a typed literal.
var typedLiteral = newSet("DATE", "TIME", "TIMESTAMP", "TIMESTAMPTZ")

// typeContinuation words may follow the first word of a type name.
var typeContinuation = newSet("PRECISION", "VARYING", "WITH", "WITHOUT", "TIME", "ZONE", "INTEGER", "INT",
	"CHAR", "CHARACTER")

// intervalUnits are the MySQL INTERVAL units, and PostgreSQL interval
// qualifiers.
var intervalUnits = newSet("MICROSECOND", "SECOND", "MINUTE", "HOUR", "DAY", "WEEK", "MONTH", "QUARTER",
	"YEAR", "SECOND_MICROSECOND", "MINUTE_MICROSECOND", "MINUTE_SECOND", "HOUR_MICROSECOND", "HOUR_SECOND",
	"HOUR_MINUTE", "DAY_MICROSECOND", "DAY_SECOND", "DAY_MINUTE", "DAY_HOUR", "YEAR_MONTH")

var frameWords = newSet("ROWS", "RANGE", "GROUPS", "BETWEEN", "AND", "UNBOUNDED", "PRECEDING", "FOLLOWING",
	"CURRENT", "ROW", "EXCLUDE", "NO", "OTHERS", "TIES", "GROUP")

type parser struct {
	d     sqlclass.Dialect
	src   string
	toks  []sqlclass.Token
	i     int
	depth int
}

// Parse parses one read statement: SELECT, WITH ... SELECT or EXPLAIN
// followed by one of them. Anything else, or any construct outside the
// supported grammar, is refused with a *sqlclass.Refusal. A trailing ';'
// and surrounding blanks are dropped, as sqlclass.Classify does.
func Parse(d sqlclass.Dialect, sql string) (*Statement, error) {
	text := strings.TrimSpace(sql)
	if strings.HasSuffix(text, ";") {
		text = strings.TrimSpace(text[:len(text)-1])
	}
	if text == "" {
		return nil, refuse("empty statement")
	}
	toks, err := sqlclass.Lex(d, text)
	if err != nil {
		return nil, err
	}
	for _, t := range toks {
		if t.Kind == sqlclass.TokPunct && t.Text == ";" {
			return nil, refuse("exactly one statement is allowed (no ';' chaining)")
		}
	}
	p := &parser{d: d, src: text, toks: toks}
	st := &Statement{SQL: text, Dialect: d}
	if p.word(0, "EXPLAIN") {
		p.i++
		if !p.word(0, "SELECT", "WITH") && !p.punct(0, "(") {
			return nil, refuse("only EXPLAIN SELECT is allowed (no ANALYZE, options or other statements)")
		}
		st.Explain = true
	}
	if !p.word(0, "SELECT", "WITH") && !p.punct(0, "(") {
		return nil, p.notAllowed()
	}
	q, err := p.query()
	if err != nil {
		return nil, err
	}
	if p.i < len(p.toks) {
		return nil, p.unexpected()
	}
	st.Query = q
	return st, nil
}

// notAllowed refuses a statement that is not a read in the allowlist.
func (p *parser) notAllowed() error {
	t := p.toks[0]
	if t.Kind == sqlclass.TokWord {
		return refusef("%.40s is not allowed: only SELECT, WITH ... SELECT and EXPLAIN SELECT are (use the catalog commands to list tables and describe them)", t.Text)
	}
	return refuse("only SELECT, WITH ... SELECT and EXPLAIN SELECT are allowed")
}

func (p *parser) tok(k int) (sqlclass.Token, bool) {
	if p.i+k < len(p.toks) && p.i+k >= 0 {
		return p.toks[p.i+k], true
	}
	return sqlclass.Token{}, false
}

func (p *parser) word(k int, words ...string) bool {
	t, ok := p.tok(k)
	if !ok || t.Kind != sqlclass.TokWord {
		return false
	}
	for _, w := range words {
		if t.Text == w {
			return true
		}
	}
	return false
}

func (p *parser) punct(k int, s string) bool {
	t, ok := p.tok(k)
	return ok && t.Kind == sqlclass.TokPunct && t.Text == s
}

// unexpected refuses the current token. Literal values are never quoted.
func (p *parser) unexpected() error {
	t, ok := p.tok(0)
	if !ok {
		return refuse("the statement ends too early (unsupported or incomplete syntax)")
	}
	switch t.Kind {
	case sqlclass.TokWord, sqlclass.TokPunct:
		return refusef("unsupported syntax near %.40s: locksql only runs statements it can parse with certainty", t.Text)
	}
	return refuse("unsupported syntax near a literal or quoted name: locksql only runs statements it can parse with certainty")
}

func (p *parser) expectWord(w string) error {
	if !p.word(0, w) {
		return p.unexpected()
	}
	p.i++
	return nil
}

func (p *parser) expectPunct(s string) error {
	if !p.punct(0, s) {
		return p.unexpected()
	}
	p.i++
	return nil
}

// span is the source span from token start to the last consumed token.
func (p *parser) span(start int) Span {
	if start >= len(p.toks) || p.i == 0 {
		return Span{}
	}
	end := p.i - 1
	if end < start {
		return Span{p.toks[start].Pos, p.toks[start].Pos}
	}
	return Span{p.toks[start].Pos, p.toks[end].End}
}

func (p *parser) enter() error {
	p.depth++
	if p.depth > maxDepth {
		return refuse("the statement nests too deeply")
	}
	return nil
}

func (p *parser) leave() { p.depth-- }

// ident reads one identifier: an unquoted word that is not reserved, or a
// quoted identifier. MySQL double-quoted text is refused: it is a string or
// an identifier depending on the server's sql_mode.
func (p *parser) ident(allowReserved bool) (string, bool) {
	t, ok := p.tok(0)
	if !ok {
		return "", false
	}
	switch t.Kind {
	case sqlclass.TokWord:
		if !allowReserved && reserved[t.Text] {
			return "", false
		}
		p.i++
		return t.Text, true
	case sqlclass.TokQuotedIdent:
		p.i++
		return t.Name(), true
	}
	return "", false
}

func (p *parser) mysqlDoubleQuoted(k int) bool {
	t, ok := p.tok(k)
	return ok && p.d == sqlclass.MySQL && t.Kind == sqlclass.TokString && strings.HasPrefix(t.Text, `"`)
}

func (p *parser) query() (*Query, error) {
	if err := p.enter(); err != nil {
		return nil, err
	}
	defer p.leave()
	start := p.i
	q := &Query{}
	var err error
	if p.word(0, "WITH") {
		if q.With, err = p.with(); err != nil {
			return nil, err
		}
	}
	if q.Body, err = p.setExpr(); err != nil {
		return nil, err
	}
	if p.word(0, "ORDER") {
		p.i++
		if err := p.expectWord("BY"); err != nil {
			return nil, err
		}
		if q.OrderBy, err = p.orderList(); err != nil {
			return nil, err
		}
	}
	if q.Limit, err = p.limit(); err != nil {
		return nil, err
	}
	q.Sp = p.span(start)
	return q, nil
}

func (p *parser) with() (*With, error) {
	start := p.i
	p.i++ // WITH
	w := &With{}
	if p.word(0, "RECURSIVE") {
		w.Recursive = true
		p.i++
	}
	for {
		cs := p.i
		name, ok := p.ident(false)
		if !ok {
			return nil, p.unexpected()
		}
		c := &CTE{Name: name}
		if p.punct(0, "(") {
			cols, err := p.nameList()
			if err != nil {
				return nil, err
			}
			c.Columns = cols
		}
		if err := p.expectWord("AS"); err != nil {
			return nil, err
		}
		if p.word(0, "MATERIALIZED") || p.word(0, "NOT") {
			return nil, refuse("CTE materialization hints are not supported")
		}
		if err := p.expectPunct("("); err != nil {
			return nil, err
		}
		if !p.word(0, "SELECT", "WITH") && !p.punct(0, "(") {
			return nil, refuse("a CTE must be a SELECT (data-modifying CTEs are not allowed)")
		}
		q, err := p.query()
		if err != nil {
			return nil, err
		}
		if err := p.expectPunct(")"); err != nil {
			return nil, err
		}
		c.Query = q
		c.Sp = p.span(cs)
		w.CTEs = append(w.CTEs, c)
		if !p.punct(0, ",") {
			break
		}
		p.i++
	}
	if p.word(0, "SEARCH", "CYCLE") {
		return nil, refuse("SEARCH and CYCLE clauses are not supported")
	}
	w.Sp = p.span(start)
	return w, nil
}

// nameList reads "(a, b, c)".
func (p *parser) nameList() ([]string, error) {
	if err := p.expectPunct("("); err != nil {
		return nil, err
	}
	var out []string
	for {
		n, ok := p.ident(true)
		if !ok {
			return nil, p.unexpected()
		}
		out = append(out, n)
		if p.punct(0, ",") {
			p.i++
			continue
		}
		break
	}
	return out, p.expectPunct(")")
}

func (p *parser) setExpr() (Body, error) {
	start := p.i
	left, err := p.term()
	if err != nil {
		return nil, err
	}
	for p.word(0, "UNION", "INTERSECT", "EXCEPT") {
		op := p.toks[p.i].Text
		p.i++
		all := false
		switch {
		case p.word(0, "ALL"):
			all = true
			p.i++
		case p.word(0, "DISTINCT"):
			p.i++
		}
		right, err := p.term()
		if err != nil {
			return nil, err
		}
		left = &SetOp{Op: op, All: all, Left: left, Right: right, Sp: p.span(start)}
	}
	if p.word(0, "MINUS") {
		return nil, refuse("MINUS is not supported; use EXCEPT")
	}
	return left, nil
}

func (p *parser) term() (Body, error) {
	switch {
	case p.word(0, "SELECT"):
		return p.selectCore()
	case p.punct(0, "("):
		p.i++
		if !p.word(0, "SELECT", "WITH") && !p.punct(0, "(") {
			return nil, p.unexpected()
		}
		q, err := p.query()
		if err != nil {
			return nil, err
		}
		if err := p.expectPunct(")"); err != nil {
			return nil, err
		}
		return q, nil
	case p.word(0, "VALUES", "TABLE"):
		return nil, refusef("%s is not allowed: only SELECT is", p.toks[p.i].Text)
	}
	return nil, p.unexpected()
}

func (p *parser) selectCore() (*Select, error) {
	if err := p.enter(); err != nil {
		return nil, err
	}
	defer p.leave()
	start := p.i
	p.i++ // SELECT
	s := &Select{}
	switch {
	case p.word(0, "ALL"):
		p.i++
	case p.word(0, "DISTINCT"):
		p.i++
		s.Distinct = true
		if p.word(0, "ON") {
			if p.d != sqlclass.Postgres {
				return nil, p.unexpected()
			}
			p.i++
			if err := p.expectPunct("("); err != nil {
				return nil, err
			}
			list, err := p.exprList()
			if err != nil {
				return nil, err
			}
			if err := p.expectPunct(")"); err != nil {
				return nil, err
			}
			s.DistinctOn = list
		}
	}
	if t, ok := p.tok(0); ok && t.Kind == sqlclass.TokWord && (strings.HasPrefix(t.Text, "SQL_") ||
		t.Text == "HIGH_PRIORITY" || t.Text == "STRAIGHT_JOIN" || t.Text == "DISTINCTROW") {
		return nil, refusef("the select modifier %.40s is not supported", t.Text)
	}
	for {
		it, err := p.selectItem()
		if err != nil {
			return nil, err
		}
		s.Items = append(s.Items, it)
		if !p.punct(0, ",") {
			break
		}
		p.i++
	}
	if p.word(0, "INTO") {
		return nil, refuse("SELECT ... INTO is not allowed (it writes a table, a variable or a file)")
	}
	if p.word(0, "FROM") {
		p.i++
		fs := p.i
		for {
			te, err := p.tableRef()
			if err != nil {
				return nil, err
			}
			s.From = append(s.From, te)
			if !p.punct(0, ",") {
				break
			}
			p.i++
		}
		s.FromSp = p.span(fs)
	}
	if p.word(0, "WHERE") {
		p.i++
		ws := p.i
		e, err := p.expr()
		if err != nil {
			return nil, err
		}
		s.Where, s.WhereSp = e, p.span(ws)
	}
	if p.word(0, "GROUP") {
		p.i++
		if err := p.expectWord("BY"); err != nil {
			return nil, err
		}
		gs := p.i
		list, err := p.exprList()
		if err != nil {
			return nil, err
		}
		s.GroupBy, s.GroupSp = list, p.span(gs)
		if p.word(0, "WITH") && p.word(1, "ROLLUP") {
			return nil, refuse("WITH ROLLUP is not supported")
		}
	}
	if p.word(0, "HAVING") {
		p.i++
		hs := p.i
		e, err := p.expr()
		if err != nil {
			return nil, err
		}
		s.Having, s.HavingSp = e, p.span(hs)
	}
	if p.word(0, "WINDOW", "QUALIFY") {
		return nil, refusef("%s clauses are not supported", p.toks[p.i].Text)
	}
	if p.word(0, "FOR", "LOCK") {
		return nil, refuse("locking reads (FOR UPDATE, FOR SHARE, LOCK IN SHARE MODE) are not allowed")
	}
	s.Sp = p.span(start)
	return s, nil
}

func (p *parser) selectItem() (*SelectItem, error) {
	start := p.i
	if p.punct(0, "*") {
		p.i++
		return &SelectItem{Star: true, Sp: p.span(start)}, nil
	}
	// qualifier.* : one to three names followed by ".*".
	for n := 1; n <= 3; n++ {
		if p.starAfter(n) {
			var q []string
			for k := 0; k < n; k++ {
				name, ok := p.ident(true)
				if !ok {
					return nil, p.unexpected()
				}
				q = append(q, name)
				p.i++ // '.'
			}
			p.i++ // '*'
			return &SelectItem{Star: true, Qualifier: q, Sp: p.span(start)}, nil
		}
	}
	e, err := p.expr()
	if err != nil {
		return nil, err
	}
	it := &SelectItem{Expr: e}
	alias, err := p.alias()
	if err != nil {
		return nil, err
	}
	it.Alias = alias
	it.Sp = p.span(start)
	return it, nil
}

// starAfter reports whether n names joined by '.' start at the current
// token and are followed by ".*".
func (p *parser) starAfter(n int) bool {
	k := 0
	for j := 0; j < n; j++ {
		t, ok := p.tok(k)
		if !ok || (t.Kind != sqlclass.TokWord && t.Kind != sqlclass.TokQuotedIdent) {
			return false
		}
		if !p.punct(k+1, ".") {
			return false
		}
		k += 2
	}
	return p.punct(k, "*")
}

// alias reads an optional [AS] alias.
func (p *parser) alias() (string, error) {
	if p.word(0, "AS") {
		p.i++
		if p.mysqlDoubleQuoted(0) {
			return "", refuse("double-quoted aliases are ambiguous in MySQL; use backquotes")
		}
		name, ok := p.ident(true)
		if !ok {
			return "", p.unexpected()
		}
		return name, nil
	}
	t, ok := p.tok(0)
	if !ok {
		return "", nil
	}
	switch t.Kind {
	case sqlclass.TokWord:
		if reserved[t.Text] {
			return "", nil
		}
		p.i++
		return t.Text, nil
	case sqlclass.TokQuotedIdent:
		p.i++
		return t.Name(), nil
	case sqlclass.TokString:
		return "", refuse("string literals as aliases are not supported; use AS with an identifier")
	}
	return "", nil
}

func (p *parser) tableRef() (TableExpr, error) {
	if err := p.enter(); err != nil {
		return nil, err
	}
	defer p.leave()
	start := p.i
	left, err := p.tablePrimary()
	if err != nil {
		return nil, err
	}
	for {
		j := &Join{}
		if p.word(0, "NATURAL") {
			j.Natural = true
			p.i++
		}
		switch {
		case p.word(0, "JOIN"):
			j.Kind = "INNER"
		case p.word(0, "INNER") && p.word(1, "JOIN"):
			j.Kind = "INNER"
			p.i++
		case p.word(0, "CROSS") && p.word(1, "JOIN"):
			j.Kind = "CROSS"
			p.i++
		case p.word(0, "LEFT", "RIGHT", "FULL"):
			j.Kind = p.toks[p.i].Text
			p.i++
			if p.word(0, "OUTER") {
				p.i++
			}
			if !p.word(0, "JOIN") {
				return nil, p.unexpected()
			}
		default:
			if j.Natural {
				return nil, p.unexpected()
			}
			if p.word(0, "STRAIGHT_JOIN") {
				return nil, refuse("STRAIGHT_JOIN is not supported")
			}
			return left, nil
		}
		p.i++ // JOIN
		right, err := p.tablePrimary()
		if err != nil {
			return nil, err
		}
		j.Left, j.Right = left, right
		switch {
		case p.word(0, "ON"):
			if j.Natural || j.Kind == "CROSS" {
				return nil, p.unexpected()
			}
			p.i++
			e, err := p.expr()
			if err != nil {
				return nil, err
			}
			j.On = e
		case p.word(0, "USING"):
			if j.Natural || j.Kind == "CROSS" {
				return nil, p.unexpected()
			}
			p.i++
			cols, err := p.nameList()
			if err != nil {
				return nil, err
			}
			j.Using = cols
		default:
			if !j.Natural && j.Kind != "CROSS" && !(j.Kind == "INNER" && p.d != sqlclass.Postgres) {
				return nil, refusef("%s JOIN needs ON or USING", j.Kind)
			}
		}
		j.Sp = p.span(start)
		left = j
	}
}

func (p *parser) tablePrimary() (TableExpr, error) {
	start := p.i
	lateral := false
	if p.word(0, "LATERAL") {
		lateral = true
		p.i++
		if !p.punct(0, "(") {
			return nil, refuse("LATERAL table functions are not supported")
		}
	}
	if p.word(0, "ONLY") {
		return nil, refuse("ONLY is not supported")
	}
	if p.punct(0, "(") {
		// A derived table or a parenthesised join. "((" may open either:
		// try a query first, then a join.
		save := p.i
		p.i++
		if p.word(0, "SELECT", "WITH") || p.punct(0, "(") {
			direct := !p.punct(0, "(")
			q, err := p.query()
			if err == nil && p.punct(0, ")") {
				p.i++
				d := &Derived{Lateral: lateral, Query: q}
				if err := p.tableAlias(&d.Alias, &d.ColAliases); err != nil {
					return nil, err
				}
				d.Sp = p.span(start)
				return d, nil
			}
			if direct {
				if err == nil {
					err = p.unexpected()
				}
				return nil, err
			}
			p.i = save + 1
		}
		if lateral {
			return nil, p.unexpected()
		}
		inner, err := p.tableRef()
		if err != nil {
			return nil, err
		}
		if err := p.expectPunct(")"); err != nil {
			return nil, err
		}
		if t, ok := p.tok(0); ok && (t.Kind == sqlclass.TokQuotedIdent || t.Kind == sqlclass.TokWord && !reserved[t.Text]) || p.word(0, "AS") {
			return nil, refuse("an alias on a parenthesised join is not supported")
		}
		return inner, nil
	}
	if p.mysqlDoubleQuoted(0) {
		return nil, refuse("double-quoted names are ambiguous in MySQL; use backquotes")
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
	if p.punct(0, "(") {
		return nil, refuse("table functions in FROM are not allowed")
	}
	tn := &TableName{Parts: parts}
	if err := p.tableAlias(&tn.Alias, &tn.ColAliases); err != nil {
		return nil, err
	}
	if p.word(0, "USE", "FORCE", "IGNORE", "TABLESAMPLE", "PARTITION", "INDEXED", "NOT") {
		return nil, refusef("%s after a table name is not supported", p.toks[p.i].Text)
	}
	tn.Sp = p.span(start)
	return tn, nil
}

func (p *parser) tableAlias(alias *string, cols *[]string) error {
	a, err := p.alias()
	if err != nil {
		return err
	}
	*alias = a
	if a != "" && p.punct(0, "(") {
		c, err := p.nameList()
		if err != nil {
			return err
		}
		*cols = c
	}
	return nil
}

func (p *parser) limit() (*Limit, error) {
	var l *Limit
	readInt := func() (int64, error) {
		t, ok := p.tok(0)
		if !ok || t.Kind != sqlclass.TokNumber || !allDigits(t.Text) {
			if p.word(0, "ALL") {
				return 0, refuse("LIMIT ALL is not allowed")
			}
			return 0, refuse("LIMIT and OFFSET take integer literals only")
		}
		n, err := strconv.ParseInt(t.Text, 10, 64)
		if err != nil {
			return 0, refuse("LIMIT value is out of range")
		}
		p.i++
		return n, nil
	}
	for {
		switch {
		case p.word(0, "LIMIT"):
			if l != nil && l.Count >= 0 {
				return nil, p.unexpected()
			}
			p.i++
			n, err := readInt()
			if err != nil {
				return nil, err
			}
			if l == nil {
				l = &Limit{Count: n}
			} else {
				l.Count = n
			}
			if p.punct(0, ",") && p.d != sqlclass.Postgres {
				p.i++
				m, err := readInt()
				if err != nil {
					return nil, err
				}
				l.Offset, l.Count = n, m
			}
		case p.word(0, "OFFSET"):
			p.i++
			n, err := readInt()
			if err != nil {
				return nil, err
			}
			if p.d == sqlclass.Postgres && p.word(0, "ROW", "ROWS") {
				p.i++
			}
			if l == nil {
				l = &Limit{Count: -1}
			}
			l.Offset = n
		case p.word(0, "FETCH") && p.d == sqlclass.Postgres:
			if l != nil && l.Count >= 0 {
				return nil, p.unexpected()
			}
			p.i++
			if !p.word(0, "FIRST", "NEXT") {
				return nil, p.unexpected()
			}
			p.i++
			n := int64(1)
			if t, ok := p.tok(0); ok && t.Kind == sqlclass.TokNumber {
				v, err := readInt()
				if err != nil {
					return nil, err
				}
				n = v
			}
			if !p.word(0, "ROW", "ROWS") || !p.word(1, "ONLY") {
				return nil, refuse("FETCH must read FETCH FIRST n ROWS ONLY")
			}
			p.i += 2
			if l == nil {
				l = &Limit{}
			}
			l.Count = n
		default:
			return l, nil
		}
	}
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func (p *parser) orderList() ([]*OrderItem, error) {
	var out []*OrderItem
	for {
		e, err := p.expr()
		if err != nil {
			return nil, err
		}
		o := &OrderItem{Expr: e}
		switch {
		case p.word(0, "ASC"):
			p.i++
		case p.word(0, "DESC"):
			o.Desc = true
			p.i++
		}
		if p.word(0, "NULLS") {
			p.i++
			if !p.word(0, "FIRST", "LAST") {
				return nil, p.unexpected()
			}
			p.i++
		}
		if p.word(0, "USING") {
			return nil, refuse("ORDER BY ... USING is not supported")
		}
		out = append(out, o)
		if !p.punct(0, ",") {
			return out, nil
		}
		p.i++
	}
}

func (p *parser) exprList() ([]Expr, error) {
	var out []Expr
	for {
		e, err := p.expr()
		if err != nil {
			return nil, err
		}
		out = append(out, e)
		if !p.punct(0, ",") {
			return out, nil
		}
		p.i++
	}
}

// ---- Operators ----

// operators known per dialect, longest first within a run of adjacent
// operator characters.
var commonOps = newSet("<>", "!=", "<=", ">=", "<<", ">>", "||", "=", "<", ">", "+", "-", "*", "/", "%", "&", "|", "^", "~")

var dialectOps = map[sqlclass.Dialect]set{
	sqlclass.MySQL:    newSet("<=>", "->", "->>", "&&"),
	sqlclass.Postgres: newSet("::", "->", "->>", "#>", "#>>", "@>", "<@", "~*", "!~", "!~*", "?", "?|", "?&", "&&", "#", "^@", "@@"),
	sqlclass.SQLite:   newSet("==", "->", "->>"),
}

func isOpChar(s string) bool {
	return len(s) == 1 && strings.Contains("+-*/<>=~!@#%^&|`?:", s)
}

// op reads the operator at the current position without consuming it. It
// returns the operator and the number of tokens it spans. In PostgreSQL a
// run of adjacent operator characters is one operator (minus a trailing
// '+' or '-' when the run holds none of ~!@#%^&|`?): a run that is not a
// known operator is refused rather than split.
func (p *parser) op() (string, int, error) {
	t, ok := p.tok(0)
	if !ok || t.Kind != sqlclass.TokPunct || !isOpChar(t.Text) {
		return "", 0, nil
	}
	run := []sqlclass.Token{t}
	for k := 1; ; k++ {
		n, ok := p.tok(k)
		if !ok || n.Kind != sqlclass.TokPunct || !isOpChar(n.Text) || n.Pos != run[len(run)-1].End {
			break
		}
		run = append(run, n)
	}
	known := func(s string) bool { return commonOps[s] || dialectOps[p.d][s] }
	if p.d == sqlclass.MySQL && t.Text == "|" && len(run) > 1 && run[1].Text == "|" {
		return "", 0, refuse("|| is OR or concatenation depending on MySQL's sql_mode; use OR or CONCAT()")
	}
	if p.d == sqlclass.Postgres {
		text := ""
		for _, r := range run {
			text += r.Text
		}
		n := len(text)
		if n > 1 && !strings.ContainsAny(text, "~!@#%^&|`?") {
			for n > 1 && (text[n-1] == '+' || text[n-1] == '-') {
				n--
			}
		}
		if !known(text[:n]) {
			return "", 0, refusef("unsupported operator %.10s", text[:n])
		}
		return text[:n], n, nil
	}
	for n := min(len(run), 3); n >= 1; n-- {
		text := ""
		for _, r := range run[:n] {
			text += r.Text
		}
		if known(text) {
			return text, n, nil
		}
	}
	return "", 0, refusef("unsupported operator %.10s", t.Text)
}

// ---- Expressions ----

func (p *parser) expr() (Expr, error) {
	if err := p.enter(); err != nil {
		return nil, err
	}
	defer p.leave()
	return p.orExpr()
}

func (p *parser) orExpr() (Expr, error) {
	start := p.i
	l, err := p.andExpr()
	if err != nil {
		return nil, err
	}
	for {
		var op string
		switch {
		case p.word(0, "OR"):
			op = "OR"
		case p.word(0, "XOR") && p.d == sqlclass.MySQL:
			op = "XOR"
		default:
			return l, nil
		}
		p.i++
		r, err := p.andExpr()
		if err != nil {
			return nil, err
		}
		l = &Binary{Op: op, L: l, R: r, Sp: p.span(start)}
	}
}

func (p *parser) andExpr() (Expr, error) {
	start := p.i
	l, err := p.notExpr()
	if err != nil {
		return nil, err
	}
	for {
		switch {
		case p.word(0, "AND"):
			p.i++
		default:
			op, n, err := p.op()
			if err != nil {
				return nil, err
			}
			if op != "&&" {
				return l, nil
			}
			if p.d != sqlclass.MySQL {
				return nil, refuse("the && operator is not supported")
			}
			p.i += n
		}
		r, err := p.notExpr()
		if err != nil {
			return nil, err
		}
		l = &Binary{Op: "AND", L: l, R: r, Sp: p.span(start)}
	}
}

func (p *parser) notExpr() (Expr, error) {
	start := p.i
	if p.word(0, "NOT") {
		p.i++
		x, err := p.notExpr()
		if err != nil {
			return nil, err
		}
		return &Unary{Op: "NOT", X: x, Sp: p.span(start)}, nil
	}
	if p.punct(0, "!") {
		if op, _, _ := p.op(); op == "" || op == "!" {
			return nil, refuse("the ! operator is not supported; use NOT")
		}
	}
	return p.predicate()
}

var comparisonOps = newSet("=", "==", "<>", "!=", "<", ">", "<=", ">=", "<=>", "~", "~*", "!~", "!~*")

func (p *parser) predicate() (Expr, error) {
	start := p.i
	x, err := p.otherOp()
	if err != nil {
		return nil, err
	}
	not := false
	if p.word(0, "NOT") && p.word(1, "IN", "BETWEEN", "LIKE", "ILIKE", "GLOB", "REGEXP", "RLIKE") {
		not = true
		p.i++
	}
	switch {
	case p.word(0, "IN"):
		p.i++
		if err := p.expectPunct("("); err != nil {
			return nil, err
		}
		in := &In{X: x, Not: not}
		if p.word(0, "SELECT", "WITH") {
			q, err := p.query()
			if err != nil {
				return nil, err
			}
			in.Query = q
		} else {
			list, err := p.exprList()
			if err != nil {
				return nil, err
			}
			in.List = list
		}
		if err := p.expectPunct(")"); err != nil {
			return nil, err
		}
		in.Sp = p.span(start)
		return in, nil
	case p.word(0, "BETWEEN"):
		p.i++
		if p.word(0, "SYMMETRIC", "ASYMMETRIC") {
			return nil, refuse("BETWEEN SYMMETRIC is not supported")
		}
		lo, err := p.otherOp()
		if err != nil {
			return nil, err
		}
		if err := p.expectWord("AND"); err != nil {
			return nil, err
		}
		hi, err := p.otherOp()
		if err != nil {
			return nil, err
		}
		return &Between{X: x, Lo: lo, Hi: hi, Not: not, Sp: p.span(start)}, nil
	case p.word(0, "LIKE", "ILIKE", "GLOB", "REGEXP", "RLIKE"):
		op := p.toks[p.i].Text
		if op == "ILIKE" && p.d != sqlclass.Postgres || op == "GLOB" && p.d != sqlclass.SQLite ||
			(op == "REGEXP" || op == "RLIKE") && p.d == sqlclass.Postgres {
			return nil, p.unexpected()
		}
		p.i++
		pat, err := p.otherOp()
		if err != nil {
			return nil, err
		}
		l := &Like{Op: op, X: x, Pattern: pat, Not: not}
		if p.word(0, "ESCAPE") {
			p.i++
			esc, err := p.otherOp()
			if err != nil {
				return nil, err
			}
			l.Escape = esc
		}
		l.Sp = p.span(start)
		return l, nil
	case not:
		return nil, p.unexpected()
	case p.word(0, "IS"):
		p.i++
		it := &IsTest{X: x}
		if p.word(0, "NOT") {
			it.Not = true
			p.i++
		}
		switch {
		case p.word(0, "NULL", "TRUE", "FALSE", "UNKNOWN"):
			it.What = p.toks[p.i].Text
			p.i++
		case p.word(0, "DISTINCT") && p.word(1, "FROM"):
			p.i += 2
			y, err := p.otherOp()
			if err != nil {
				return nil, err
			}
			it.What, it.Y = "DISTINCT", y
		default:
			return nil, p.unexpected()
		}
		it.Sp = p.span(start)
		return it, nil
	case p.word(0, "SIMILAR", "MATCH", "ESCAPE"):
		return nil, refusef("%s is not supported", p.toks[p.i].Text)
	}
	op, n, err := p.op()
	if err != nil {
		return nil, err
	}
	if !comparisonOps[op] {
		return x, nil
	}
	if strings.ContainsRune(op, '~') && p.d != sqlclass.Postgres {
		return nil, p.unexpected()
	}
	p.i += n
	if p.word(0, "ANY", "SOME", "ALL") {
		quant := p.toks[p.i].Text
		p.i++
		if !p.punct(0, "(") || !p.word(1, "SELECT", "WITH") {
			return nil, refuse("ANY/ALL take a subquery only")
		}
		p.i++
		q, err := p.query()
		if err != nil {
			return nil, err
		}
		if err := p.expectPunct(")"); err != nil {
			return nil, err
		}
		switch {
		case quant != "ALL" && op == "=":
			return &In{X: x, Query: q, Sp: p.span(start)}, nil
		case quant == "ALL" && (op == "<>" || op == "!="):
			return &In{X: x, Query: q, Not: true, Sp: p.span(start)}, nil
		}
		return &Binary{Op: op + " " + quant, L: x, R: &Subquery{Query: q, Sp: p.span(start)}, Sp: p.span(start)}, nil
	}
	y, err := p.otherOp()
	if err != nil {
		return nil, err
	}
	if op == "==" {
		op = "="
	}
	return &Binary{Op: op, L: x, R: y, Sp: p.span(start)}, nil
}

// otherOps sit between the comparisons and the bitwise operators: string
// concatenation and the JSON and containment operators.
var otherOps = newSet("||", "->", "->>", "#>", "#>>", "@>", "<@", "?", "?|", "?&", "^@", "@@")

func (p *parser) otherOp() (Expr, error) {
	return p.binaryLevel(otherOps, p.bitOr)
}

func (p *parser) bitOr() (Expr, error) { return p.binaryLevel(newSet("|"), p.bitXorPG) }

// bitXorPG is PostgreSQL's '#' (bitwise XOR).
func (p *parser) bitXorPG() (Expr, error) { return p.binaryLevel(newSet("#"), p.bitAnd) }

func (p *parser) bitAnd() (Expr, error) { return p.binaryLevel(newSet("&"), p.shift) }

func (p *parser) shift() (Expr, error) { return p.binaryLevel(newSet("<<", ">>"), p.additive) }

func (p *parser) additive() (Expr, error) { return p.binaryLevel(newSet("+", "-"), p.multiplicative) }

func (p *parser) multiplicative() (Expr, error) {
	start := p.i
	l, err := p.power()
	if err != nil {
		return nil, err
	}
	for {
		var op string
		var n int
		if p.word(0, "DIV", "MOD") && p.d == sqlclass.MySQL {
			op, n = p.toks[p.i].Text, 1
		} else {
			o, k, err := p.op()
			if err != nil {
				return nil, err
			}
			if o != "*" && o != "/" && o != "%" {
				return l, nil
			}
			op, n = o, k
		}
		p.i += n
		r, err := p.power()
		if err != nil {
			return nil, err
		}
		l = &Binary{Op: op, L: l, R: r, Sp: p.span(start)}
	}
}

func (p *parser) power() (Expr, error) { return p.binaryLevel(newSet("^"), p.unary) }

func (p *parser) binaryLevel(ops set, next func() (Expr, error)) (Expr, error) {
	start := p.i
	l, err := next()
	if err != nil {
		return nil, err
	}
	for {
		op, n, err := p.op()
		if err != nil {
			return nil, err
		}
		if !ops[op] {
			return l, nil
		}
		p.i += n
		r, err := next()
		if err != nil {
			return nil, err
		}
		l = &Binary{Op: op, L: l, R: r, Sp: p.span(start)}
	}
}

func (p *parser) unary() (Expr, error) {
	start := p.i
	op, n, err := p.op()
	if err != nil {
		return nil, err
	}
	switch op {
	case "-", "+", "~":
		p.i += n
		if err := p.enter(); err != nil {
			return nil, err
		}
		x, err := p.unary()
		p.leave()
		if err != nil {
			return nil, err
		}
		return &Unary{Op: op, X: x, Sp: p.span(start)}, nil
	case "":
	default:
		return nil, p.unexpected()
	}
	return p.postfix()
}

func (p *parser) postfix() (Expr, error) {
	start := p.i
	x, err := p.primary()
	if err != nil {
		return nil, err
	}
	for {
		op, n, err := p.op()
		if err != nil {
			return nil, err
		}
		switch {
		case op == "::":
			p.i += n
			typ, err := p.typeName()
			if err != nil {
				return nil, err
			}
			x = &Cast{X: x, Type: typ, Sp: p.span(start)}
		case p.word(0, "COLLATE"):
			p.i++
			name, ok := p.ident(true)
			if !ok {
				if t, ok := p.tok(0); ok && t.Kind == sqlclass.TokString {
					p.i++
					name = t.Text
				} else {
					return nil, p.unexpected()
				}
			}
			x = &Collate{X: x, Name: name, Sp: p.span(start)}
		case p.punct(0, "["):
			return nil, refuse("array subscripts are not supported")
		default:
			return x, nil
		}
	}
}

// typeName reads a type for CAST and '::': words, an optional (n[, m]).
func (p *parser) typeName() (string, error) {
	start := p.i
	t, ok := p.tok(0)
	if !ok || t.Kind != sqlclass.TokWord {
		return "", refuse("unsupported type name")
	}
	p.i++
	for {
		nt, ok := p.tok(0)
		if !ok || nt.Kind != sqlclass.TokWord || !typeContinuation[nt.Text] {
			break
		}
		if nt.Text == "WITH" && !(p.word(1, "TIME") && p.word(2, "ZONE")) {
			break
		}
		p.i++
	}
	if p.punct(0, "(") {
		p.i++
		for {
			nt, ok := p.tok(0)
			if !ok || nt.Kind != sqlclass.TokNumber || !allDigits(nt.Text) {
				return "", refuse("unsupported type modifier")
			}
			p.i++
			if !p.punct(0, ",") {
				break
			}
			p.i++
		}
		if err := p.expectPunct(")"); err != nil {
			return "", err
		}
	}
	if p.punct(0, "[") {
		return "", refuse("array types are not supported")
	}
	sp := p.span(start)
	return strings.ToUpper(p.src[sp.Pos:sp.End]), nil
}

func (p *parser) primary() (Expr, error) {
	start := p.i
	t, ok := p.tok(0)
	if !ok {
		return nil, p.unexpected()
	}
	switch t.Kind {
	case sqlclass.TokNumber:
		if !numberLike(t.Text) {
			return nil, refuse("names starting with a digit are not supported; quote them")
		}
		p.i++
		return &Literal{Kind: LitNumber, Text: t.Text, Sp: p.span(start)}, nil
	case sqlclass.TokString:
		if p.mysqlDoubleQuoted(0) {
			return nil, refuse("double-quoted text is a string or a name depending on MySQL's sql_mode; use single quotes for strings and backquotes for names")
		}
		p.i++
		if n, ok := p.tok(0); ok && n.Kind == sqlclass.TokString {
			return nil, refuse("adjacent string literals are not supported; use one literal")
		}
		return &Literal{Kind: LitString, Text: t.Text, Sp: p.span(start)}, nil
	case sqlclass.TokQuotedIdent:
		return p.nameExpr()
	case sqlclass.TokPunct:
		if t.Text == "(" {
			p.i++
			if p.word(0, "SELECT", "WITH") {
				q, err := p.query()
				if err != nil {
					return nil, err
				}
				if err := p.expectPunct(")"); err != nil {
					return nil, err
				}
				return &Subquery{Query: q, Sp: p.span(start)}, nil
			}
			list, err := p.exprList()
			if err != nil {
				return nil, err
			}
			if err := p.expectPunct(")"); err != nil {
				return nil, err
			}
			if len(list) == 1 {
				return &Paren{X: list[0], Sp: p.span(start)}, nil
			}
			return &Tuple{Items: list, Sp: p.span(start)}, nil
		}
		return nil, p.unexpected()
	}
	// A word.
	w := t.Text
	next, hasNext := p.tok(1)
	adjacentString := hasNext && next.Kind == sqlclass.TokString && next.Pos == t.End
	switch {
	case w == "NULL":
		p.i++
		return &Literal{Kind: LitNull, Text: w, Sp: p.span(start)}, nil
	case w == "TRUE" || w == "FALSE":
		p.i++
		return &Literal{Kind: LitBool, Text: w, Sp: p.span(start)}, nil
	case w == "CASE":
		return p.caseExpr()
	case w == "CAST" && p.punct(1, "("):
		p.i += 2
		x, err := p.expr()
		if err != nil {
			return nil, err
		}
		if err := p.expectWord("AS"); err != nil {
			return nil, err
		}
		typ, err := p.typeName()
		if err != nil {
			return nil, err
		}
		if err := p.expectPunct(")"); err != nil {
			return nil, err
		}
		return &Cast{X: x, Type: typ, Sp: p.span(start)}, nil
	case w == "CONVERT" && p.punct(1, "(") && p.d == sqlclass.MySQL:
		p.i += 2
		x, err := p.expr()
		if err != nil {
			return nil, err
		}
		if p.word(0, "USING") {
			return nil, refuse("CONVERT ... USING is not supported")
		}
		if err := p.expectPunct(","); err != nil {
			return nil, err
		}
		typ, err := p.typeName()
		if err != nil {
			return nil, err
		}
		if err := p.expectPunct(")"); err != nil {
			return nil, err
		}
		return &Cast{X: x, Type: typ, Sp: p.span(start)}, nil
	case w == "EXTRACT" && p.punct(1, "("):
		p.i += 2
		if _, ok := p.ident(true); !ok {
			if ft, ok := p.tok(0); ok && ft.Kind == sqlclass.TokString {
				p.i++
			} else {
				return nil, p.unexpected()
			}
		}
		if err := p.expectWord("FROM"); err != nil {
			return nil, err
		}
		x, err := p.expr()
		if err != nil {
			return nil, err
		}
		if err := p.expectPunct(")"); err != nil {
			return nil, err
		}
		return &FuncCall{Name: "EXTRACT", Args: []Expr{x}, Sp: p.span(start)}, nil
	case w == "EXISTS" && p.punct(1, "("):
		p.i += 2
		if !p.word(0, "SELECT", "WITH") {
			return nil, p.unexpected()
		}
		q, err := p.query()
		if err != nil {
			return nil, err
		}
		if err := p.expectPunct(")"); err != nil {
			return nil, err
		}
		return &Exists{Query: q, Sp: p.span(start)}, nil
	case w == "INTERVAL":
		return p.interval()
	case typedLiteral[w] && hasNext && next.Kind == sqlclass.TokString:
		if p.mysqlDoubleQuoted(1) {
			return nil, refuse("double-quoted text is ambiguous in MySQL; use single quotes")
		}
		p.i += 2
		return &Literal{Kind: LitTyped, Text: p.src[t.Pos:next.End], Sp: p.span(start)}, nil
	case (w == "X" || w == "B" || w == "N") && adjacentString:
		if p.mysqlDoubleQuoted(1) {
			// MySQL forms these literals with single quotes only: X"a" is
			// the column x aliased a.
			return nil, refuse("double-quoted text is ambiguous in MySQL; use single quotes")
		}
		p.i += 2
		return &Literal{Kind: LitTyped, Text: p.src[t.Pos:next.End], Sp: p.span(start)}, nil
	case adjacentString:
		return nil, refuse("string prefixes and character set introducers are not supported")
	case timeNiladic[w]:
		p.i++
		if p.punct(0, "(") {
			if n, ok := p.tok(1); ok && n.Kind == sqlclass.TokNumber && p.punct(2, ")") {
				p.i += 3
			} else if p.punct(1, ")") {
				p.i += 2
			}
		}
		return &Literal{Kind: LitNiladic, Text: w, Sp: p.span(start)}, nil
	case systemNiladic[w]:
		return nil, refusef("%s reads session metadata; it is not allowed", w)
	case w == "ROW" || w == "ARRAY":
		return nil, refusef("%s constructors are not supported", w)
	case reserved[w] && p.punct(1, "("):
		// MOD(a, b), LEFT(s, n), IF(c, a, b), ...: the function allowlist
		// decides.
		p.i++
		return p.call(start, w)
	case reserved[w]:
		return nil, p.unexpected()
	}
	return p.nameExpr()
}

func numberLike(s string) bool {
	if strings.HasPrefix(s, "0X") || strings.HasPrefix(s, "0B") {
		return len(s) > 2
	}
	digits, dot, exp := 0, false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			digits++
		case c == '.' && !dot && !exp:
			dot = true
		case c == 'E' && !exp && digits > 0:
			exp = true
		default:
			return false
		}
	}
	return digits > 0
}

func (p *parser) interval() (Expr, error) {
	start := p.i
	p.i++ // INTERVAL
	if t, ok := p.tok(0); ok && t.Kind == sqlclass.TokString && p.d == sqlclass.Postgres {
		p.i++
		for p.word(0) {
			if nt := p.toks[p.i]; intervalUnits[nt.Text] || nt.Text == "TO" {
				p.i++
				continue
			}
			break
		}
		return &Literal{Kind: LitInterval, Text: p.src[p.toks[start].Pos:p.toks[p.i-1].End], Sp: p.span(start)}, nil
	}
	if p.d != sqlclass.MySQL {
		return nil, refuse("unsupported INTERVAL syntax")
	}
	x, err := p.otherOp()
	if err != nil {
		return nil, err
	}
	t, ok := p.tok(0)
	if !ok || t.Kind != sqlclass.TokWord || !intervalUnits[t.Text] {
		return nil, refuse("INTERVAL needs a unit (DAY, MONTH, ...)")
	}
	p.i++
	if l, ok := x.(*Literal); ok {
		return &Literal{Kind: LitInterval, Text: l.Text, Sp: p.span(start)}, nil
	}
	return &FuncCall{Name: "INTERVAL", Args: []Expr{x}, Sp: p.span(start)}, nil
}

func (p *parser) caseExpr() (Expr, error) {
	start := p.i
	p.i++ // CASE
	c := &Case{}
	if !p.word(0, "WHEN") {
		x, err := p.expr()
		if err != nil {
			return nil, err
		}
		c.Operand = x
	}
	for p.word(0, "WHEN") {
		p.i++
		cond, err := p.expr()
		if err != nil {
			return nil, err
		}
		if err := p.expectWord("THEN"); err != nil {
			return nil, err
		}
		res, err := p.expr()
		if err != nil {
			return nil, err
		}
		c.Whens = append(c.Whens, When{Cond: cond, Result: res})
	}
	if len(c.Whens) == 0 {
		return nil, p.unexpected()
	}
	if p.word(0, "ELSE") {
		p.i++
		e, err := p.expr()
		if err != nil {
			return nil, err
		}
		c.Else = e
	}
	if err := p.expectWord("END"); err != nil {
		return nil, err
	}
	c.Sp = p.span(start)
	return c, nil
}

// nameExpr reads a column reference or a function call.
func (p *parser) nameExpr() (Expr, error) {
	start := p.i
	var parts []string
	for {
		if p.mysqlDoubleQuoted(0) {
			return nil, refuse("double-quoted names are ambiguous in MySQL; use backquotes")
		}
		name, ok := p.ident(len(parts) > 0)
		if !ok {
			return nil, p.unexpected()
		}
		parts = append(parts, name)
		if !p.punct(0, ".") {
			break
		}
		p.i++
		if p.punct(0, "*") {
			return nil, refuse("a qualified star is only allowed as a select-list item")
		}
	}
	if len(parts) > 4 {
		return nil, p.unexpected()
	}
	if !p.punct(0, "(") {
		if len(parts) > 3 {
			return nil, p.unexpected()
		}
		return &ColumnRef{Parts: parts, Sp: p.span(start)}, nil
	}
	return p.call(start, strings.Join(parts, "."))
}

func (p *parser) call(start int, name string) (Expr, error) {
	p.i++ // '('
	f := &FuncCall{Name: name}
	switch {
	case p.punct(0, ")"):
	case p.punct(0, "*") && p.punct(1, ")"):
		f.Star = true
		p.i++
	default:
		if p.word(0, "DISTINCT") {
			f.Distinct = true
			p.i++
		} else if p.word(0, "ALL") {
			p.i++
		}
		switch name {
		case "POSITION":
			a, err := p.otherOp()
			if err != nil {
				return nil, err
			}
			if p.word(0, "IN") {
				p.i++
				b, err := p.otherOp()
				if err != nil {
					return nil, err
				}
				f.Args = []Expr{a, b}
				break
			}
			f.Args = []Expr{a}
			for p.punct(0, ",") {
				p.i++
				e, err := p.expr()
				if err != nil {
					return nil, err
				}
				f.Args = append(f.Args, e)
			}
		case "SUBSTRING", "SUBSTR":
			a, err := p.expr()
			if err != nil {
				return nil, err
			}
			f.Args = []Expr{a}
			if p.word(0, "FROM") {
				p.i++
				b, err := p.expr()
				if err != nil {
					return nil, err
				}
				f.Args = append(f.Args, b)
				if p.word(0, "FOR") {
					p.i++
					c, err := p.expr()
					if err != nil {
						return nil, err
					}
					f.Args = append(f.Args, c)
				}
				break
			}
			for p.punct(0, ",") {
				p.i++
				e, err := p.expr()
				if err != nil {
					return nil, err
				}
				f.Args = append(f.Args, e)
			}
		case "TRIM":
			if p.word(0, "LEADING", "TRAILING", "BOTH") {
				p.i++
			}
			if p.word(0, "FROM") {
				p.i++
			} else {
				a, err := p.expr()
				if err != nil {
					return nil, err
				}
				f.Args = []Expr{a}
				if p.word(0, "FROM") {
					p.i++
				}
			}
			if !p.punct(0, ")") {
				b, err := p.expr()
				if err != nil {
					return nil, err
				}
				f.Args = append(f.Args, b)
			}
		default:
			list, err := p.exprList()
			if err != nil {
				return nil, err
			}
			f.Args = list
			if p.word(0, "ORDER") {
				p.i++
				if err := p.expectWord("BY"); err != nil {
					return nil, err
				}
				ob, err := p.orderList()
				if err != nil {
					return nil, err
				}
				f.OrderBy = ob
			}
			if p.word(0, "SEPARATOR") && p.d == sqlclass.MySQL {
				p.i++
				t, ok := p.tok(0)
				if !ok || t.Kind != sqlclass.TokString || p.mysqlDoubleQuoted(0) {
					return nil, p.unexpected()
				}
				f.Separator = &Literal{Kind: LitString, Text: t.Text, Sp: Span{t.Pos, t.End}}
				p.i++
			}
		}
	}
	if err := p.expectPunct(")"); err != nil {
		return nil, err
	}
	if p.word(0, "WITHIN") {
		return nil, refuse("WITHIN GROUP is not supported")
	}
	if p.word(0, "RESPECT", "IGNORE") {
		return nil, refuse("RESPECT/IGNORE NULLS is not supported")
	}
	if p.word(0, "FILTER") {
		p.i++
		if err := p.expectPunct("("); err != nil {
			return nil, err
		}
		if err := p.expectWord("WHERE"); err != nil {
			return nil, err
		}
		e, err := p.expr()
		if err != nil {
			return nil, err
		}
		if err := p.expectPunct(")"); err != nil {
			return nil, err
		}
		f.Filter = e
	}
	if p.word(0, "OVER") {
		p.i++
		w, err := p.window()
		if err != nil {
			return nil, err
		}
		f.Over = w
	}
	f.Sp = p.span(start)
	return f, nil
}

func (p *parser) window() (*Window, error) {
	if !p.punct(0, "(") {
		return nil, refuse("named windows are not supported; spell the window out in OVER (...)")
	}
	p.i++
	w := &Window{}
	if t, ok := p.tok(0); ok && (t.Kind == sqlclass.TokQuotedIdent || t.Kind == sqlclass.TokWord && !reserved[t.Text] && !frameWords[t.Text]) {
		return nil, refuse("named windows are not supported")
	}
	if p.word(0, "PARTITION") {
		p.i++
		if err := p.expectWord("BY"); err != nil {
			return nil, err
		}
		list, err := p.exprList()
		if err != nil {
			return nil, err
		}
		w.PartitionBy = list
	}
	if p.word(0, "ORDER") {
		p.i++
		if err := p.expectWord("BY"); err != nil {
			return nil, err
		}
		ob, err := p.orderList()
		if err != nil {
			return nil, err
		}
		w.OrderBy = ob
	}
	if p.word(0, "ROWS", "RANGE", "GROUPS") {
		for !p.punct(0, ")") {
			t, ok := p.tok(0)
			if !ok {
				return nil, p.unexpected()
			}
			switch {
			case t.Kind == sqlclass.TokWord && frameWords[t.Text]:
			case t.Kind == sqlclass.TokNumber && allDigits(t.Text):
			default:
				return nil, refuse("window frames take integer offsets only")
			}
			p.i++
		}
	}
	if err := p.expectPunct(")"); err != nil {
		return nil, err
	}
	return w, nil
}
