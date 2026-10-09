package pii

import (
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

// maskText is the mask format: first character + "***" + "(length in
// characters)". An invalid UTF-8 byte counts as one U+FFFD character.
func maskText(s string) string {
	first := ""
	for _, r := range s {
		first = string(r)
		break
	}
	return first + "***(" + strconv.Itoa(utf8.RuneCountInString(s)) + ")"
}

// MaskResult masks res in place.
//
// A column is masked whole when its origin matches a rule. Engines report
// an origin only when the catalog confirms it is a base-table column; a
// view, a derived table or a CTE alias never counts. A view column is
// therefore masked only by its own name: a view that renames a rule column
// (CREATE VIEW v AS SELECT firstname AS contact ...) needs a rule for that
// name (*.*.contact or db.v.contact). When origin is false
// (the session reports no origins), or a column has none (an expression, a
// UNION, an untrusted origin the engine blanked), the column
// label is matched by name instead, see Rules.MatchesName; the console must
// then also refuse renamed uses with AliasViolation (see NeedsAliasCheck).
// Binary cells under a rule become "<masked bytes:N>"; NULL stays NULL.
//
// Every other text cell, and every integer (a national number or a card can
// be stored as one), goes through the detectors in place.
func MaskResult(res *engine.Result, r Rules, ds []Detector, origin bool) {
	whole := make([]bool, len(res.Columns))
	for i, c := range res.Columns {
		if origin && c.HasOrigin() {
			whole[i] = r.Matches(c.OriginDB, c.OriginTable, c.OriginColumn)
		} else {
			whole[i] = r.MatchesName(c.Label)
		}
	}
	for _, row := range res.Rows {
		for i, v := range row {
			if v == nil {
				continue
			}
			if i < len(whole) && whole[i] {
				row[i] = maskCell(v)
				continue
			}
			row[i] = detect(v, ds)
		}
	}
}

// NeedsAliasCheck reports whether the statement behind res must pass
// AliasViolation (ResultAliasViolation, given res.Columns) before its rows
// may be shown: the session reports no origins, or some result column came
// back without one.
func NeedsAliasCheck(res engine.Result, origin bool) bool {
	if len(res.Columns) == 0 {
		return false // no rows to show
	}
	if !origin {
		return true
	}
	for _, c := range res.Columns {
		if !c.HasOrigin() {
			return true
		}
	}
	return false
}

func maskCell(v any) any {
	switch x := v.(type) {
	case []byte:
		return "<masked bytes:" + strconv.Itoa(len(x)) + ">"
	case string:
		return maskText(x)
	case time.Time:
		return maskText(x.Format(time.RFC3339Nano))
	default:
		return maskText(fmt.Sprint(x))
	}
}

func detect(v any, ds []Detector) any {
	if len(ds) == 0 {
		return v
	}
	var in string
	switch x := v.(type) {
	case string:
		in = x
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		in = fmt.Sprint(x) // drivers use every width (pgx: int4 is int32)
	default:
		return v
	}
	out := cutForDetection(in)
	for _, d := range ds {
		out = d.Mask(out)
	}
	if out == in {
		return v // unchanged: keep the original type
	}
	return out
}

// DetectLimit is how much of a text cell the detectors scan. A longer cell
// is cut there, and ends with "…", before detection: nothing past the
// scanned part can reach the output. The renderer cuts cells much earlier
// (max_cell_chars), so the cut is normally invisible; it bounds the time a
// huge value can cost.
const DetectLimit = 64 << 10

// cutTail is how far back a cut retreats over value-like characters, so that
// a value split by the cut (a partial number or address) is dropped whole.
const cutTail = 64

func cutForDetection(s string) string {
	if len(s) <= DetectLimit {
		return s
	}
	end := DetectLimit
	for end > 0 && !utf8.RuneStart(s[end]) {
		end--
	}
	for back := 0; back < cutTail && end > 0 && strings.IndexByte(valueChars, s[end-1]) >= 0; back++ {
		end--
	}
	return s[:end] + "…"
}

// valueChars may belong to a detected value.
const valueChars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz@._%+-/() "

// AliasViolation is the fallback for result columns without an origin: it
// refuses a READ select in which a rule-matched column (matched by name, see
// Rules.MatchesName) is renamed or used inside an expression anywhere in a
// select list, since its values would then reach a label that no rule
// matches. Renaming covers "AS x", an implicit alias, a later UNION arm
// whose first arm labels the position differently, CTE column lists over a
// body that mentions a matched column or selects * from a source that may
// hold one, a * in a later arm over such a source, and table alias column lists
// ("t(x, y)"), which can rename any column. A PostgreSQL whole-row
// reference to a table that may hold such a column ("SELECT u",
// "row_to_json(u)", "to_jsonb(users.*)") is refused too, see wholeRow.
// A matched column or whole-row reference inside a VALUES list or the
// arguments of a FROM-clause function, and a TABLE arm after the first, are
// refused as well. Every named relation counts as a source that may hold a
// matched column, since it may be a view over a rule table.
// COUNT(...) is allowed. The
// error is a *sqlclass.Refusal that explains how to write the query.
//
// A statement that is not a plain READ select is checked the same way when
// it may return rows: a RETURNING list counts as a select list, and a
// statement led by SELECT, WITH, VALUES or TABLE that the classifier made
// WRITE (a data-modifying CTE) is checked whole. A write without RETURNING
// is only checked by writtenValues. Other statements (SHOW, DESCRIBE,
// PRAGMA, DDL) pass.
//
// On PostgreSQL, "rel.f" may be the call f(rel) on the whole row of rel
// when rel has no column f (attribute notation: b.row_to_json, t.name,
// big.record_out). Since a statement alone cannot tell such a call from a
// column, a qualified reference "rel.x" to a FROM-clause relation is refused
// wherever its value may reach the result (select lists, RETURNING, VALUES,
// FROM-clause function arguments), see attrCall. ResultAliasViolation
// accepts a plain qualified item of the outer select list whose result
// column carries an origin, which proves it is a base-table column.
//
// A write, with or without RETURNING, must not copy a rule-matched
// column's values into another column: a rule-matched column, a whole row
// or a star over a source that may hold one is refused anywhere its value
// may be written (SET values, the select list or VALUES of an INSERT
// source), see writtenValues.
func AliasViolation(st sqlclass.Statement, r Rules, d sqlclass.Dialect) error {
	return ResultAliasViolation(st, r, d, nil)
}

// ResultAliasViolation is AliasViolation once the statement has run, with
// the result columns it returned: a plain qualified PostgreSQL item of the
// outer select list ("SELECT b.id, ...") is accepted when its result column
// has an origin. With cols nil, every such item is refused.
func ResultAliasViolation(st sqlclass.Statement, r Rules, d sqlclass.Dialect, cols []engine.ResultColumn) error {
	if len(r.Mask) == 0 || st.Class == sqlclass.Read && st.Kind != "select" {
		return nil
	}
	toks, err := sqlclass.Lex(d, st.SQL)
	if err != nil {
		return err
	}
	if st.Class != sqlclass.Read && !mayReturnRows(toks) {
		// Nothing comes back, but a copy of a rule column would come
		// back unmasked from the next read of the column written.
		a := newAliasCheck(toks, r, d)
		a.write = true
		a.prepare()
		return a.writtenValues()
	}
	a := newAliasCheck(toks, r, d)
	a.cols = cols
	a.write = st.Class != sqlclass.Read
	return a.run()
}

// mayReturnRows reports whether a statement other than a plain READ select
// may return rows: it has a RETURNING list, or it is led by a read keyword
// (a WITH whose CTE modifies data, then selects).
func mayReturnRows(toks []sqlclass.Token) bool {
	if len(toks) == 0 {
		return false
	}
	if t := toks[0]; t.Kind == sqlclass.TokWord && (t.Text == "SELECT" || t.Text == "WITH" || t.Text == "VALUES" || t.Text == "TABLE") {
		return true
	}
	for _, t := range toks {
		if t.Kind == sqlclass.TokWord && t.Text == "RETURNING" {
			return true
		}
	}
	return false
}

// PlanCheck is the PII check a statement must pass before it runs, unless
// it is an unmask run: StatsViolation, then AliasViolation for a statement
// that is not a plain READ select (it runs before the write, whose result
// may carry no origin) or when the session reports no origins. A plain
// READ select on an origin-reporting session is checked after it runs,
// only when some result column has no origin (see NeedsAliasCheck).
func PlanCheck(st sqlclass.Statement, r Rules, d sqlclass.Dialect, origin bool) error {
	if err := StatsViolation(st, r, d); err != nil {
		return err
	}
	if !origin || st.Class != sqlclass.Read || st.Kind != "select" {
		return AliasViolation(st, r, d)
	}
	return nil
}

// statsRelations hold planner statistics: sample values of table columns
// (most common values, histogram bounds, min/max) under labels and origins
// that no rule matches.
var statsRelations = map[string]bool{
	// PostgreSQL.
	"PG_STATS": true, "PG_STATISTIC": true, "PG_STATS_EXT": true, "PG_STATS_EXT_EXPRS": true,
	"PG_STATISTIC_EXT_DATA": true,
	// MariaDB (ANALYZE ... PERSISTENT) and MySQL 8 histograms.
	"COLUMN_STATS": true, "COLUMN_STATISTICS": true,
	// SQLite (ANALYZE with SQLITE_ENABLE_STAT3/4).
	"SQLITE_STAT3": true, "SQLITE_STAT4": true,
}

// StatementTextRelation reports whether rel, a relation name as written
// ("name", "schema.name"), holds the text of past statements, and so the
// values the console substituted into them. On PostgreSQL these are
// pg_stat_statements and pg_stat_activity. On MySQL and MariaDB they are
// information_schema.PROCESSLIST, every performance_schema and sys
// relation (threads, events_statements_*, session, statement_analysis,
// x$...), and mysql.general_log and slow_log.
func StatementTextRelation(d sqlclass.Dialect, rel string) bool {
	parts := strings.Split(strings.ToUpper(rel), ".")
	name := parts[len(parts)-1]
	if name == "PG_STAT_STATEMENTS" || name == "PG_STAT_ACTIVITY" {
		return true
	}
	if d != sqlclass.MySQL {
		return false
	}
	if len(parts) > 1 {
		switch parts[len(parts)-2] {
		case "PERFORMANCE_SCHEMA", "SYS":
			return true
		}
	}
	return name == "PROCESSLIST" || name == "GENERAL_LOG" || name == "SLOW_LOG" ||
		strings.HasPrefix(name, "EVENTS_STATEMENTS_")
}

// StatsViolation refuses, while mask rules exist, a statement that names a
// planner statistics relation (pg_stats, pg_statistic, mysql.column_stats,
// information_schema.COLUMN_STATISTICS, sqlite_stat4, ...): they hold real
// values of the columns, rule columns included, which no rule can match.
// It refuses a statement-text relation (see StatementTextRelation) the
// same way.
func StatsViolation(st sqlclass.Statement, r Rules, d sqlclass.Dialect) error {
	if len(r.Mask) == 0 {
		return nil
	}
	toks, err := sqlclass.Lex(d, st.SQL)
	if err != nil {
		return err
	}
	a := &aliasCheck{toks: toks, d: d}
	for i := range toks {
		if n := a.name(i); statsRelations[n] {
			return &sqlclass.Refusal{Reason: fmt.Sprintf("%s holds sample values of table columns, PII columns included, that could not be masked; it cannot be read while PII mask rules exist", strings.ToLower(n))}
		}
		if a.name(i) == "" || a.isPunct(i-1, ".") {
			continue
		}
		// The name as written, with its qualifiers: "schema.name".
		rel := a.name(i)
		for j := i; a.isPunct(j+1, ".") && a.name(j+2) != ""; j += 2 {
			rel += "." + a.name(j+2)
		}
		if StatementTextRelation(d, rel) {
			return &sqlclass.Refusal{Reason: fmt.Sprintf("%s holds the text of past statements, substituted values included; it cannot be read while PII mask rules exist", strings.ToLower(rel))}
		}
	}
	return nil
}

type aliasCheck struct {
	toks  []sqlclass.Token
	r     Rules
	d     sqlclass.Dialect
	match []int           // index of the matching parenthesis, -1 for other tokens
	encl  []int           // index of the innermost enclosing '(' of each token, -1 at top level
	rows  map[string]bool // FROM-clause names whose whole row may carry a PII column
	// clause is the clause word in force at each token (see clauses).
	clause []string
	// cols are the result columns of the statement once run, nil before.
	cols []engine.ResultColumn
	// output is the SELECT or RETURNING whose list labels the result, -1
	// when unknown.
	output int
	write  bool // the statement is not a plain read
}

func newAliasCheck(toks []sqlclass.Token, r Rules, d sqlclass.Dialect) *aliasCheck {
	a := &aliasCheck{toks: toks, r: r, d: d, match: make([]int, len(toks)), encl: make([]int, len(toks))}
	var stack []int
	for i := range toks {
		a.match[i] = -1
		a.encl[i] = -1
		if len(stack) > 0 {
			a.encl[i] = stack[len(stack)-1]
		}
		if a.isPunct(i, "(") {
			stack = append(stack, i)
		} else if a.isPunct(i, ")") && len(stack) > 0 {
			o := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			a.match[o], a.match[i] = i, o
			a.encl[i] = a.encl[o]
		}
	}
	return a
}

func (a *aliasCheck) isPunct(i int, p string) bool {
	return i >= 0 && i < len(a.toks) && a.toks[i].Kind == sqlclass.TokPunct && a.toks[i].Text == p
}

func (a *aliasCheck) isWord(i int, words ...string) bool {
	if i < 0 || i >= len(a.toks) || a.toks[i].Kind != sqlclass.TokWord {
		return false
	}
	for _, w := range words {
		if a.toks[i].Text == w {
			return true
		}
	}
	return false
}

// name is the folded identifier a token names, including a MySQL
// double-quoted token, which is an identifier under ANSI_QUOTES.
func (a *aliasCheck) name(i int) string {
	if i < 0 || i >= len(a.toks) {
		return ""
	}
	t := a.toks[i]
	if a.d == sqlclass.MySQL && t.Kind == sqlclass.TokString && len(t.Text) >= 2 && t.Text[0] == '"' {
		return fold(strings.ReplaceAll(t.Text[1:len(t.Text)-1], `""`, `"`))
	}
	return t.Name()
}

// aliasName is name, plus a string literal, which MySQL and SQLite accept as
// an alias.
func (a *aliasCheck) aliasName(i int) string {
	if n := a.name(i); n != "" {
		return n
	}
	t := a.toks[i]
	if t.Kind == sqlclass.TokString && len(t.Text) >= 2 && (t.Text[0] == '\'' || t.Text[0] == '"') {
		q := t.Text[:1]
		return fold(strings.ReplaceAll(t.Text[1:len(t.Text)-1], q+q, q))
	}
	return ""
}

// matched reports whether token i is a column reference under a rule: a
// name, not a function name (followed by '(') nor a qualifier (followed by
// '.').
func (a *aliasCheck) matched(i int) bool {
	n := a.name(i)
	if n == "" || a.isPunct(i+1, "(") || a.isPunct(i+1, ".") {
		return false
	}
	return a.r.MatchesName(n)
}

func fold(s string) string { return strings.ToUpper(strings.ToLower(s)) }

func refusal(format string, args ...any) error {
	return &sqlclass.Refusal{Reason: fmt.Sprintf(format, args...) +
		"; this engine cannot tell where such a column comes from, so it could not be masked." +
		" Select PII columns by their plain name (SELECT email FROM ...), without alias or expression"}
}

// clauseWords switch the clause of the current parenthesis level.
var clauseWords = map[string]bool{
	"SELECT": true, "FROM": true, "JOIN": true, "WHERE": true, "ON": true, "USING": true, "GROUP": true,
	"HAVING": true, "ORDER": true, "LIMIT": true, "WINDOW": true, "UNION": true, "INTERSECT": true,
	"EXCEPT": true, "MINUS": true, "WITH": true, "OFFSET": true, "FETCH": true, "FOR": true,
	"QUALIFY": true, "VALUES": true,
}

// listEnd ends a select list at its own level.
var listEnd = map[string]bool{
	"FROM": true, "INTO": true, "WHERE": true, "GROUP": true, "HAVING": true, "ORDER": true,
	"LIMIT": true, "UNION": true, "INTERSECT": true, "EXCEPT": true, "MINUS": true, "WINDOW": true,
	"FETCH": true, "OFFSET": true, "FOR": true, "QUALIFY": true, "LOCK": true,
}

// selectModifiers may open a select list.
var selectModifiers = map[string]bool{
	"DISTINCT": true, "ALL": true, "DISTINCTROW": true, "HIGH_PRIORITY": true, "STRAIGHT_JOIN": true,
	"SQL_SMALL_RESULT": true, "SQL_BIG_RESULT": true, "SQL_BUFFER_RESULT": true, "SQL_NO_CACHE": true,
	"SQL_CACHE": true, "SQL_CALC_FOUND_ROWS": true,
}

// notAlias are words that, before a parenthesis in a FROM clause, do not
// make it a table alias column list.
var notAlias = map[string]bool{
	"FROM": true, "JOIN": true, "LATERAL": true, "INDEX": true, "KEY": true, "USE": true, "FORCE": true,
	"IGNORE": true, "PARTITION": true, "ONLY": true, "TABLESAMPLE": true, "ROWS": true, "UNNEST": true,
	"ON": true, "USING": true, "AS": true, "INNER": true, "LEFT": true, "RIGHT": true, "FULL": true,
	"OUTER": true, "CROSS": true, "NATURAL": true, "STRAIGHT_JOIN": true, "REPEATABLE": true,
	"SYSTEM": true, "BERNOULLI": true, "WITH": true, "ORDINALITY": true, "JSON_TABLE": true,
}

type selectItem struct {
	label string // output label when known ("" for an expression)
	star  bool   // "*" or "x.*": it expands to an unknown number of columns
}

// prepare computes the row sources, clauses and output list of the
// statement.
func (a *aliasCheck) prepare() {
	a.rows = a.rowSources()
	a.clause = a.clauses()
	a.output = a.outputList()
}

func (a *aliasCheck) run() error {
	a.prepare()
	if a.write {
		if err := a.writtenValues(); err != nil {
			return err
		}
	}
	if err := a.columnLists(); err != nil {
		return err
	}
	if err := a.valuesAndFromCalls(); err != nil {
		return err
	}
	// heads maps each SELECT to the select list of the first arm of its
	// UNION/INTERSECT/EXCEPT chain (its own list for a first arm), whose
	// labels the whole chain's output carries.
	heads := map[int][]selectItem{}
	for i := range a.toks {
		if a.isWord(i, "TABLE") && a.name(i+1) != "" {
			if later, _ := a.laterArm(i); later {
				// TABLE t is SELECT * FROM t: every column of t under the
				// first arm's labels.
				return refusal("a later UNION/INTERSECT/EXCEPT arm is TABLE %s, which puts all its columns, PII included, under the first arm's labels", strings.ToLower(a.name(i+1)))
			}
		}
		if a.isWord(i, "RETURNING") {
			// A RETURNING list is a select list of its own.
			if _, err := a.selectList(i, false, nil); err != nil {
				return err
			}
			continue
		}
		if !a.isWord(i, "SELECT") {
			continue
		}
		later, op := a.laterArm(i)
		var head []selectItem
		if later {
			// An unknown head (a VALUES or TABLE first arm) stays nil, and
			// refuses every matched column of this arm.
			if prev := a.prevArmSelect(op); prev >= 0 {
				head = heads[prev]
			}
		}
		items, err := a.selectList(i, later, head)
		if err != nil {
			return err
		}
		if later {
			heads[i] = head
		} else {
			heads[i] = items
		}
	}
	return nil
}

// prevArmSelect returns the SELECT that starts the arm before the set
// operator at op, or -1 when that arm is not a SELECT. A parenthesised arm
// is searched inside its parentheses.
func (a *aliasCheck) prevArmSelect(op int) int {
	k := op - 1
	if a.isPunct(k, ")") && a.match[k] >= 0 {
		return a.firstSelectIn(a.match[k])
	}
	depth := a.toks[op].Depth
	for ; k >= 0; k-- {
		t := a.toks[k]
		switch {
		case t.Depth < depth || a.isPunct(k, "(") && t.Depth == depth:
			return -1 // the start of the enclosing level
		case a.isPunct(k, ")") && a.match[k] >= 0:
			k = a.match[k]
		case t.Depth == depth && a.isWord(k, "SELECT"):
			return k
		}
	}
	return -1
}

// firstSelectIn returns a SELECT at the level opened by the parenthesis at
// o (any arm of a chain there shares the chain's head), looking into a
// leading nested parenthesis when that level has none, or -1.
func (a *aliasCheck) firstSelectIn(o int) int {
	depth := a.toks[o].Depth
	for k := o + 1; k < a.match[o]; k++ {
		if a.toks[k].Depth == depth && a.isWord(k, "SELECT") {
			return k
		}
	}
	if a.isPunct(o+1, "(") && a.match[o+1] >= 0 {
		return a.firstSelectIn(o + 1)
	}
	return -1
}

// laterArm reports whether the SELECT at i follows UNION/INTERSECT/EXCEPT,
// possibly through parentheses, and returns the index of that operator.
func (a *aliasCheck) laterArm(i int) (later bool, op int) {
	j := i - 1
	for a.isPunct(j, "(") {
		j--
	}
	if a.isWord(j, "ALL", "DISTINCT") {
		j--
	}
	return a.isWord(j, "UNION", "INTERSECT", "EXCEPT", "MINUS"), j
}

// selectList checks the select list opened by the SELECT at i.
func (a *aliasCheck) selectList(i int, later bool, head []selectItem) ([]selectItem, error) {
	depth := a.toks[i].Depth
	k := i + 1
	for k < len(a.toks) && a.toks[k].Kind == sqlclass.TokWord && selectModifiers[a.toks[k].Text] {
		k++
	}
	if a.isWord(k, "ON") && a.isPunct(k+1, "(") && a.match[k+1] > 0 { // PostgreSQL DISTINCT ON (...)
		k = a.match[k+1] + 1
	}
	if a.isWord(i, "RETURNING") && a.isWord(k, "WITH") && a.isPunct(k+1, "(") && a.match[k+1] > 0 { // PostgreSQL RETURNING WITH (OLD AS o)
		k = a.match[k+1] + 1
	}
	var items []selectItem
	start := k
	for ; ; k++ {
		end := k >= len(a.toks) || a.toks[k].Depth < depth ||
			(a.toks[k].Depth == depth && a.toks[k].Kind == sqlclass.TokWord && listEnd[a.toks[k].Text])
		if end || (a.isPunct(k, ",") && a.toks[k].Depth == depth) {
			if k > start {
				it, err := a.item(i, start, k, items, later, head)
				if err != nil {
					return nil, err
				}
				items = append(items, it)
			}
			start = k + 1
		}
		if end {
			return items, nil
		}
	}
}

// plainRef reports whether tokens [s, e) are name ('.' name)*.
func (a *aliasCheck) plainRef(s, e int) bool {
	if e <= s || (e-s)%2 == 0 {
		return false
	}
	for j := s; j < e; j++ {
		if (j-s)%2 == 0 && a.name(j) == "" || (j-s)%2 == 1 && !a.isPunct(j, ".") {
			return false
		}
	}
	return true
}

func (a *aliasCheck) item(sel, s, e int, prev []selectItem, later bool, head []selectItem) (selectItem, error) {
	pos := len(prev)
	star := a.isStar(e-1) && (e-s == 1 || a.plainRef(s, e-2))
	if star && !later {
		return selectItem{star: true}, nil
	}
	if star {
		// A star in a later arm puts its sources' columns, PII included,
		// under the head's labels, which no rule may match.
		if e-s == 1 && a.armBearing(sel) || e-s > 1 && a.rows[a.name(e-3)] {
			return selectItem{}, refusal("a later UNION/INTERSECT/EXCEPT arm selects * from a table that may hold PII columns, under the first arm's labels")
		}
		return selectItem{star: true}, nil
	}
	exprEnd, alias := e, ""
	switch {
	case a.plainRef(s, e):
	case e-s >= 3 && a.isWord(e-2, "AS"):
		exprEnd, alias = e-2, a.aliasName(e-1)
	case e-s >= 2 && a.plainRef(s, e-1) && a.aliasName(e-1) != "":
		exprEnd, alias = e-1, a.aliasName(e-1)
	}
	if err := a.wholeRow(s, exprEnd); err != nil {
		return selectItem{}, err
	}
	if err := a.attrCalls(s, e, a.provenColumn(sel, s, exprEnd, prev), "a select list"); err != nil {
		return selectItem{}, err
	}
	if a.plainRef(s, exprEnd) {
		ref := a.name(exprEnd - 1)
		label := ref
		if alias != "" {
			label = alias
		}
		if !a.matched(exprEnd - 1) {
			return selectItem{label: label}, nil
		}
		if later {
			// A star before this position, in the head or in this arm,
			// moves the real output position by an unknown amount.
			if pos < len(head) && head[pos].label == ref && !hasStar(head[:pos+1]) && !hasStar(prev) {
				return selectItem{label: label}, nil
			}
			return selectItem{}, refusal("PII column %s appears in a later UNION/INTERSECT/EXCEPT arm under another column's label", strings.ToLower(ref))
		}
		if alias != "" && alias != ref {
			return selectItem{}, refusal("PII column %s is renamed to %s", strings.ToLower(ref), strings.ToLower(alias))
		}
		return selectItem{label: label}, nil
	}
	for j := s; j < e; j++ {
		if a.matched(j) && !a.insideCount(j) {
			return selectItem{}, refusal("PII column %s is used inside an expression", strings.ToLower(a.name(j)))
		}
	}
	if err := a.nestedRows(s, e, "an expression"); err != nil {
		return selectItem{}, err
	}
	return selectItem{label: alias}, nil
}

func hasStar(items []selectItem) bool {
	for _, it := range items {
		if it.star {
			return true
		}
	}
	return false
}

// nestedRows refuses, in [s, e), a subquery that returns whole rows of a
// source that may hold a rule-matched column: "TABLE x", or a "*" / "x.*"
// select-list star over such a source ("(SELECT * FROM c LIMIT 1)",
// "ARRAY(TABLE c)"). The PII column is never named, and its values come
// out under the label of the enclosing expression, with no origin. A star
// inside EXISTS(...) or COUNT(...) only yields a boolean or a count.
func (a *aliasCheck) nestedRows(s, e int, where string) error {
	for k := s; k < e; k++ {
		if a.insideCount(k) || a.insideExists(k) {
			continue
		}
		if a.isWord(k, "TABLE") && a.name(k+1) != "" {
			return refusal("TABLE %s is used in %s, which puts its columns, PII included, under another label", strings.ToLower(a.name(k+1)), where)
		}
		if !a.isStar(k) {
			continue
		}
		bearing := false
		if a.isPunct(k-1, ".") {
			bearing = a.rows[a.name(k-2)]
		} else if sel := a.starSelect(k); sel >= 0 {
			bearing = a.armBearing(sel)
		} else {
			bearing = true
		}
		if bearing {
			return refusal("a subquery selects * in %s, which puts its columns, PII included, under another label", where)
		}
	}
	return nil
}

// starSelect returns the SELECT whose list holds the star at k, or -1.
func (a *aliasCheck) starSelect(k int) int {
	depth := a.toks[k].Depth
	for j := k - 1; j >= 0 && a.toks[j].Depth >= depth; j-- {
		if a.toks[j].Depth == depth && a.isWord(j, "SELECT") {
			return j
		}
	}
	return -1
}

// insideExists reports whether token j sits inside an EXISTS(...) call.
func (a *aliasCheck) insideExists(j int) bool {
	for o := a.encl[j]; o >= 0; o = a.encl[o] {
		if a.isWord(o-1, "EXISTS") {
			return true
		}
	}
	return false
}

// insideCount reports whether token j sits inside a COUNT(...) call.
func (a *aliasCheck) insideCount(j int) bool {
	for o := a.encl[j]; o >= 0; o = a.encl[o] {
		if a.isWord(o-1, "COUNT") {
			return true
		}
	}
	return false
}

// columnLists refuses CTE column lists whose body mentions a matched column
// ("WITH c(x) AS (SELECT email ...)") and table alias column lists in FROM
// clauses ("FROM users u(x)", "(SELECT ...) AS d(x)"), which rename columns
// by position.
func (a *aliasCheck) columnLists() error {
	clause := map[int]string{}
	for j, t := range a.toks {
		if t.Kind == sqlclass.TokWord && clauseWords[t.Text] {
			clause[t.Depth] = t.Text
		}
		if !a.isPunct(j, "(") || a.match[j] < 0 || !a.namesOnly(j+1, a.match[j]) {
			continue
		}
		p := j - 1
		if a.name(p) == "" || a.toks[p].Kind == sqlclass.TokWord && notAlias[a.toks[p].Text] {
			continue
		}
		// CTE: [WITH [RECURSIVE] | ,] name (cols) AS [NOT] [MATERIALIZED] (body)
		m := a.match[j]
		if a.isWord(p-1, "WITH", "RECURSIVE") || a.isPunct(p-1, ",") {
			if a.isWord(m+1, "AS") {
				b := m + 2
				if a.isWord(b, "NOT") {
					b++
				}
				if a.isWord(b, "MATERIALIZED") {
					b++
				}
				if a.isPunct(b, "(") && a.match[b] > b {
					bearing := false
					for k := b + 1; k < a.match[b]; k++ {
						if a.matched(k) {
							return refusal("PII column %s is renamed by the column list of %s", strings.ToLower(a.name(k)), strings.ToLower(a.name(p)))
						}
						if a.rows[a.name(k)] {
							bearing = true
						}
						if a.isWord(k, "TABLE") && a.name(k+1) != "" {
							return refusal("the column list of %s renames the columns of TABLE %s", strings.ToLower(a.name(p)), strings.ToLower(a.name(k+1)))
						}
					}
					for k := b + 1; k < a.match[b]; k++ {
						if a.isStar(k) && (a.isPunct(k-1, ".") && a.rows[a.name(k-2)] || !a.isPunct(k-1, ".") && bearing) {
							return refusal("the column list of %s renames the columns of a * that may hold PII columns", strings.ToLower(a.name(p)))
						}
					}
				}
				continue
			}
		}
		if c := clause[a.toks[p].Depth]; c != "FROM" && c != "JOIN" {
			continue
		}
		prev := p - 1
		if a.isWord(prev, "AS") || a.isPunct(prev, ")") ||
			(a.name(prev) != "" && !(a.toks[prev].Kind == sqlclass.TokWord && notAlias[a.toks[prev].Text])) {
			return refusal("the column list of %s renames table columns by position", strings.ToLower(a.name(p)))
		}
	}
	return nil
}

// isStar reports whether token k is a select-list star: "*" or the star of
// "x.*", not a multiplication nor COUNT(*).
func (a *aliasCheck) isStar(k int) bool {
	if !a.isPunct(k, "*") {
		return false
	}
	p := k - 1
	return a.isWord(p, "SELECT", "RETURNING") || a.isPunct(p, ",") || a.isPunct(p, ".") ||
		p >= 0 && a.toks[p].Kind == sqlclass.TokWord && selectModifiers[a.toks[p].Text]
}

// armBearing reports whether the FROM clause of the SELECT at i names a
// source in a.rows, one whose rows may carry a rule-matched column, or holds
// a parenthesised item (aliased or not) with a SELECT, a TABLE, a VALUES
// list or such a name inside.
func (a *aliasCheck) armBearing(i int) bool {
	depth := a.toks[i].Depth
	from := false
	for k := i + 1; k < len(a.toks) && a.toks[k].Depth >= depth; k++ {
		if from && a.isPunct(k, "(") && a.toks[k].Depth == depth+1 && a.match[k] > k {
			for j := k + 1; j < a.match[k]; j++ {
				if a.isWord(j, "SELECT", "TABLE", "VALUES") || a.rows[a.name(j)] {
					return true
				}
			}
		}
		if a.toks[k].Depth > depth {
			continue
		}
		if a.isWord(k, "FROM") {
			from = true
			continue
		}
		if a.toks[k].Kind == sqlclass.TokWord && listEnd[a.toks[k].Text] {
			return false
		}
		if from && a.rows[a.name(k)] {
			return true
		}
	}
	return false
}

// namesOnly reports whether [s, e) is a non-empty comma-separated list of
// names.
func (a *aliasCheck) namesOnly(s, e int) bool {
	if e <= s || (e-s)%2 == 0 {
		return false
	}
	for j := s; j < e; j++ {
		if (j-s)%2 == 0 && a.name(j) == "" || (j-s)%2 == 1 && !a.isPunct(j, ",") {
			return false
		}
	}
	return true
}

// wholeRow refuses a PostgreSQL whole-row reference in the select-list
// expression [s, e): a bare FROM-clause table or alias ("SELECT u",
// "row_to_json(u)", "u::text") or "name.*" used inside an expression
// ("to_jsonb(users.*)", "ROW(u.*)"). Such a column has no origin and a label
// that no rule matches, so a whole record would go out unmasked. Only names
// in a.rows count; a plain "u.*" item and COUNT(...) are allowed.
func (a *aliasCheck) wholeRow(s, e int) error {
	if a.d != sqlclass.Postgres {
		return nil // only PostgreSQL has whole-row references
	}
	for j := s; j < e; j++ {
		n := a.name(j)
		if n == "" || !a.rows[n] || a.insideCount(j) {
			continue
		}
		if a.isPunct(j+1, ".") && a.isPunct(j+2, "*") {
			if j+3 == e && a.plainRef(s, j+1) {
				continue // a plain "[schema.]u.*" item keeps its columns
			}
		} else if a.isPunct(j-1, ".") || a.isPunct(j+1, ".") || a.isPunct(j+1, "(") {
			continue // a column, a qualifier or a function name
		}
		return &sqlclass.Refusal{Reason: fmt.Sprintf("the whole row of %s is used as a value; this engine gives such a column no origin, so its PII columns could not be masked."+
			" List the columns instead (SELECT %s.id, %s.email ...); a column named like its table must be qualified (t.col)",
			strings.ToLower(n), strings.ToLower(n), strings.ToLower(n))}
	}
	return nil
}

// rowSources returns the names (table, schema and alias) of every FROM or
// JOIN item, at any level, whose rows may carry a rule-matched column: any
// named relation (a table no rule names may still be a view over one, and
// views have no origin), a CTE, or a function call or parenthesised item
// that holds a SELECT or names such a table. Names are
// gathered per statement, not per scope: a false match only refuses more.
func (a *aliasCheck) rowSources() map[string]bool {
	ctes := map[string]bool{}
	for j := range a.toks {
		// name [(cols)] AS [NOT] [MATERIALIZED] (
		k := j + 1
		if a.isPunct(k, "(") && a.match[k] > k {
			k = a.match[k] + 1
		}
		if n := a.name(j); n != "" && a.isWord(k, "AS") {
			k++
			if a.isWord(k, "NOT") {
				k++
			}
			if a.isWord(k, "MATERIALIZED") {
				k++
			}
			if a.isPunct(k, "(") {
				ctes[n] = true
			}
		}
	}
	type group struct {
		names   []string
		bearing bool
		call    bool // the item is a function call (its alias names no relation)
	}
	var groups []*group
	cur := map[int]*group{}
	clause := map[int]string{}
	inFrom := func(d int) bool { return clause[d] == "FROM" || clause[d] == "JOIN" }
	for j, t := range a.toks {
		switch {
		case a.isPunct(j, "("):
			d := t.Depth - 1
			if inFrom(d) && cur[d] != nil && a.match[j] > j && a.bearingSpan(j+1, a.match[j], ctes) {
				cur[d].bearing = true
			}
			if inFrom(d) && cur[d] != nil && len(cur[d].names) == 0 &&
				(a.isWord(j-1, "UNNEST", "JSON_TABLE") || a.isWord(j-1, "FROM") && a.isWord(j-2, "ROWS")) {
				cur[d].call = true
			}
			delete(clause, t.Depth) // a new level starts with no clause
		case t.Kind == sqlclass.TokWord && (t.Text == "FROM" || t.Text == "JOIN"):
			clause[t.Depth] = t.Text
			g := &group{}
			groups = append(groups, g)
			cur[t.Depth] = g
		case t.Kind == sqlclass.TokWord && (t.Text == "UPDATE" || t.Text == "INTO" || t.Text == "USING"):
			// The target of UPDATE, INSERT INTO or MERGE INTO, and a
			// DELETE or MERGE USING list: a RETURNING list may use their
			// whole rows. (An ON DUPLICATE KEY UPDATE list or a JOIN
			// USING list adds names too: a false match only refuses more.)
			clause[t.Depth] = "FROM"
			g := &group{}
			groups = append(groups, g)
			cur[t.Depth] = g
		case t.Kind == sqlclass.TokWord && (t.Text == "SET" || t.Text == "RETURNING" || t.Text == "DEFAULT"):
			clause[t.Depth] = t.Text
			cur[t.Depth] = nil
		case t.Kind == sqlclass.TokWord && clauseWords[t.Text]:
			clause[t.Depth] = t.Text
			cur[t.Depth] = nil
		case a.isPunct(j, ",") && inFrom(t.Depth):
			g := &group{}
			groups = append(groups, g)
			cur[t.Depth] = g
		case inFrom(t.Depth) && cur[t.Depth] != nil:
			n := a.name(j)
			if n == "" || t.Kind == sqlclass.TokWord && (notAlias[t.Text] || listEnd[t.Text]) {
				continue
			}
			g := cur[t.Depth]
			if len(g.names) == 0 && a.isPunct(j+1, "(") {
				g.call = true
			}
			g.names = append(g.names, n)
			if ctes[n] || a.tableUnderRule(n) {
				g.bearing = true
			}
		}
	}
	rows := map[string]bool{}
	for j := range a.toks {
		if !a.isWord(j, "RETURNING") {
			continue
		}
		// PostgreSQL 18: RETURNING old / new, renamed by RETURNING WITH
		// (OLD AS o, NEW AS n).
		rows["OLD"], rows["NEW"] = true, true
		if a.isWord(j+1, "WITH") && a.isPunct(j+2, "(") && a.match[j+2] > j+2 {
			for k := j + 3; k < a.match[j+2]; k++ {
				if n := a.name(k); n != "" {
					rows[n] = true
				}
			}
		}
	}
	for _, g := range groups {
		// A named relation bears even when no rule names its table: it may
		// be a view over one, and a view has no origin.
		if g.bearing || !g.call && len(g.names) > 0 {
			for _, n := range g.names {
				rows[n] = true
			}
		}
	}
	return rows
}

// bearingSpan reports whether tokens [s, e) hold a SELECT, a CTE name or a
// table under a rule.
func (a *aliasCheck) bearingSpan(s, e int, ctes map[string]bool) bool {
	for k := s; k < e; k++ {
		if a.isWord(k, "SELECT") {
			return true
		}
		if n := a.name(k); n != "" && (ctes[n] || a.tableUnderRule(n)) {
			return true
		}
	}
	return false
}

// tableUnderRule reports whether some Mask pattern's table segment matches
// the table name n.
func (a *aliasCheck) tableUnderRule(n string) bool {
	for _, p := range a.r.Mask {
		if s := strings.Split(p, "."); len(s) == 3 && segMatch(s[1], n) {
			return true
		}
	}
	return false
}

// fromCallSkip are words that, before a parenthesis in a FROM clause, open
// something other than a function call or a ROWS FROM list: index hints,
// partitions, sampling, a parenthesised join or a LATERAL subquery.
var fromCallSkip = map[string]bool{
	"FROM": true, "JOIN": true, "LATERAL": true, "INDEX": true, "KEY": true, "PARTITION": true,
	"ONLY": true, "TABLESAMPLE": true, "SYSTEM": true, "BERNOULLI": true, "REPEATABLE": true,
	"ON": true, "USING": true, "AS": true, "STRAIGHT_JOIN": true, "INNER": true, "LEFT": true,
	"RIGHT": true, "FULL": true, "OUTER": true, "CROSS": true, "NATURAL": true, "WITH": true,
}

// valuesAndFromCalls refuses a rule-matched column, or a PostgreSQL
// whole-row reference, inside a VALUES list or the arguments of a
// FROM-clause function (unnest(...), lower(b.email) x, JSON_TABLE(...),
// json_each(...), ROWS FROM (...)). Its values come out under labels such as
// column1, unnest or value that no rule matches, with no origin, and no
// select-list item of the query renames them.
func (a *aliasCheck) valuesAndFromCalls() error {
	clause := a.clauses()
	for j, t := range a.toks {
		if a.isWord(j, "VALUES") {
			e := j + 1
			for e < len(a.toks) && (a.toks[e].Depth > t.Depth ||
				a.toks[e].Depth == t.Depth && !(a.toks[e].Kind == sqlclass.TokWord && listEnd[a.toks[e].Text])) {
				e++
			}
			if err := a.spanLeak(j+1, e, clause, "a VALUES list"); err != nil {
				return err
			}
			continue
		}
		if !a.isPunct(j, "(") || a.match[j] < 0 {
			continue
		}
		if c := clause[j]; c != "FROM" && c != "JOIN" {
			continue
		}
		p := j - 1
		call := a.name(p) != "" && !(a.toks[p].Kind == sqlclass.TokWord && fromCallSkip[a.toks[p].Text])
		if a.isWord(p, "FROM") && a.isWord(p-1, "ROWS") {
			call = true
		}
		if !call {
			continue
		}
		if err := a.spanLeak(j+1, a.match[j], clause, "the arguments of a FROM-clause function"); err != nil {
			return err
		}
	}
	return nil
}

// spanLeak refuses a rule-matched column in [s, e), or a bare name of a
// PII-bearing source used as a value (a PostgreSQL whole-row reference),
// except where it names a table of a nested FROM clause.
func (a *aliasCheck) spanLeak(s, e int, clause []string, where string) error {
	if err := a.nestedRows(s, e, where); err != nil {
		return err
	}
	for k := s; k < e; k++ {
		if a.matched(k) && !a.insideCount(k) {
			return refusal("PII column %s is used in %s", strings.ToLower(a.name(k)), where)
		}
		if err := a.attrCall(k, where); err != nil {
			return err
		}
		n := a.name(k)
		if a.d != sqlclass.Postgres || n == "" || !a.rows[n] || a.insideCount(k) ||
			clause[k] == "FROM" || clause[k] == "JOIN" ||
			a.isPunct(k-1, ".") || a.isPunct(k+1, ".") || a.isPunct(k+1, "(") {
			continue
		}
		return refusal("the whole row of %s is used in %s", strings.ToLower(n), where)
	}
	return nil
}

// clauses returns, for each token, the clause word (see clauseWords, plus
// RETURNING and SET) in
// force at its parenthesis level; a parenthesis carries the clause of the
// level it sits in, and a new level starts with none.
func (a *aliasCheck) clauses() []string {
	out := make([]string, len(a.toks))
	cur := map[int]string{}
	for j, t := range a.toks {
		switch {
		case a.isPunct(j, "("):
			out[j] = cur[t.Depth-1]
			delete(cur, t.Depth)
			continue
		case a.isPunct(j, ")"):
			delete(cur, t.Depth+1)
		case t.Kind == sqlclass.TokWord && (clauseWords[t.Text] || t.Text == "RETURNING" || t.Text == "SET"):
			cur[t.Depth] = t.Text
		}
		out[j] = cur[t.Depth]
	}
	return out
}

// outputList returns the index of the list that labels the result: a
// top-level RETURNING, else the first top-level SELECT; -1 when there is
// neither (a parenthesised query, VALUES, TABLE).
func (a *aliasCheck) outputList() int {
	sel := -1
	for i, t := range a.toks {
		if t.Depth != 0 {
			continue
		}
		if a.isWord(i, "RETURNING") {
			return i
		}
		if sel < 0 && a.isWord(i, "SELECT") {
			sel = i
		}
	}
	return sel
}

// provenColumn reports whether the item [s, e) of the list opened at sel,
// after the items prev, is a plain qualified reference whose result column
// came back with an origin: then it is a base-table column, not a function
// called on a whole row.
func (a *aliasCheck) provenColumn(sel, s, e int, prev []selectItem) bool {
	return sel == a.output && a.cols != nil && e-s >= 3 && a.plainRef(s, e) &&
		!hasStar(prev) && len(prev) < len(a.cols) && a.cols[len(prev)].HasOrigin()
}

// valueClause reports whether token k sits where a value may reach the
// result: a select or RETURNING list, a VALUES list, a SET list, or a new
// parenthesis level (an expression, function arguments).
func (a *aliasCheck) valueClause(k int) bool {
	switch a.clause[k] {
	case "", "SELECT", "VALUES", "RETURNING", "SET":
		return true
	}
	return false
}

// attrCalls refuses a PostgreSQL qualified reference that may be a whole-row
// function call (see attrCall) in a value position of [s, e), unless the
// item is proven to be a base-table column.
func (a *aliasCheck) attrCalls(s, e int, proven bool, where string) error {
	if proven {
		return nil
	}
	for k := s; k < e; k++ {
		if !a.valueClause(k) {
			continue
		}
		if err := a.attrCall(k, where); err != nil {
			return err
		}
	}
	return nil
}

// attrCall refuses, on PostgreSQL, "rel.x" at token k where rel names a
// relation whose rows may hold a PII column (see rowSources) and x ends the
// reference: when rel has no column x, PostgreSQL reads it as the call x(rel)
// on the whole row (b.row_to_json, big.record_out, t.name, t.text), whose
// value has no origin and a label no rule matches. The statement alone cannot
// tell it from a column.
func (a *aliasCheck) attrCall(k int, where string) error {
	if a.d != sqlclass.Postgres || a.insideCount(k) {
		return nil
	}
	n := a.name(k)
	if n == "" || !a.rows[n] || !a.isPunct(k+1, ".") {
		return nil
	}
	x := a.name(k + 2)
	if x == "" || a.isPunct(k+3, ".") || a.isPunct(k+3, "(") {
		return nil
	}
	ln, lx := strings.ToLower(n), strings.ToLower(x)
	return &sqlclass.Refusal{Reason: fmt.Sprintf("%s.%s is used in %s without a proven origin; PostgreSQL reads it as %s(%s), a function called on the whole row, when %s has no column %s, and the PII columns of that row could not be masked."+
		" Use the unqualified column name (SELECT %s FROM ...), or select it as a plain item so that its origin can be checked",
		ln, lx, where, lx, ln, ln, lx, lx)}
}

// writeClauses switch the clause of a level in writtenValues.
var writeClauses = map[string]bool{
	"SELECT": true, "VALUES": true, "SET": true, "TABLE": true,
	"FROM": true, "JOIN": true, "WHERE": true, "ON": true, "USING": true, "GROUP": true, "HAVING": true,
	"ORDER": true, "LIMIT": true, "OFFSET": true, "FETCH": true, "WINDOW": true, "QUALIFY": true, "FOR": true,
	"INTO": true, "RETURNING": true, "UPDATE": true, "INSERT": true, "DELETE": true, "MERGE": true,
	"REPLACE": true, "WITH": true, "UNION": true, "INTERSECT": true, "EXCEPT": true, "MINUS": true,
	"CONFLICT": true,
}

// writeValueClauses are the clauses whose values a write may store: select
// lists and VALUES of an INSERT source, TABLE, and SET lists (an ON
// DUPLICATE KEY UPDATE list counts as SET). Every other clause reads,
// filters, names the target or is the RETURNING list, checked as a select
// list.
var writeValueClauses = map[string]bool{"": true, "SELECT": true, "VALUES": true, "SET": true, "TABLE": true}

// writeFilters are clauses whose nested levels only filter or name
// conflict targets: no value under them reaches a written column.
var writeFilters = map[string]bool{"WHERE": true, "ON": true, "HAVING": true, "CONFLICT": true}

// writtenValues refuses, in a write, a value derived from a PII column
// where the write may store it (SET values, the select list, VALUES or
// TABLE of an INSERT source, MERGE actions): a rule-matched column, a star
// or TABLE over a source that may hold one, or a PostgreSQL whole-row
// reference. Stored in a column no rule names, it would come back through
// RETURNING, or from the next plain read of that column, with a trusted
// origin and no mask. This holds even when the target is itself a rule
// column: rules match targets by name only, and the column written may be
// one no rule's origin covers. Target column lists and SET targets are not
// values.
func (a *aliasCheck) writtenValues() error {
	writes := false
	for i := range a.toks {
		if a.isWord(i, "INSERT", "UPDATE", "MERGE", "REPLACE") {
			writes = true
		}
	}
	if !writes {
		return nil
	}
	type level struct {
		clause string
		filter bool // opened under a filter clause
	}
	levels := map[int]*level{}
	get := func(d int) *level {
		if levels[d] == nil {
			levels[d] = &level{}
		}
		return levels[d]
	}
	const where = "the values a write stores"
	for k := 0; k < len(a.toks); k++ {
		t := a.toks[k]
		if a.isPunct(k, "(") {
			outer := get(t.Depth - 1)
			m := a.match[k]
			// Target column lists: INSERT INTO t (a, b), MERGE ... INSERT
			// (a, b), SET (a, b) = (...).
			if m > k && a.namesOnly(k+1, m) && (outer.clause == "INTO" || outer.clause == "INSERT" ||
				outer.clause == "SET" && a.isPunct(m+1, "=")) {
				k = m
				continue
			}
			levels[t.Depth] = &level{filter: outer.filter || writeFilters[outer.clause]}
			continue
		}
		if t.Kind == sqlclass.TokWord && writeClauses[t.Text] {
			c := t.Text
			if c == "UPDATE" && a.isWord(k-1, "KEY") { // ON DUPLICATE KEY UPDATE
				c = "SET"
			}
			get(t.Depth).clause = c
		}
		l := get(t.Depth)
		if l.filter || !writeValueClauses[l.clause] {
			continue
		}
		if err := a.nestedRows(k, k+1, where); err != nil {
			return err
		}
		if a.setTarget(k) {
			continue
		}
		if a.matched(k) && !a.insideCount(k) {
			return &sqlclass.Refusal{Reason: fmt.Sprintf("this write stores values of PII column %s, which could come back unmasked under the name of the column written (through RETURNING or a later read);"+
				" do not copy PII columns, or run the write as an unmasked query", strings.ToLower(a.name(k)))}
		}
		if a.d != sqlclass.Postgres {
			continue
		}
		if a.isPunct(k+1, ".") && a.setTarget(k+2) {
			continue
		}
		if err := a.attrCall(k, where); err != nil {
			return err
		}
		if n := a.name(k); n != "" && a.rows[n] && !a.insideCount(k) &&
			!a.isPunct(k-1, ".") && !a.isPunct(k+1, ".") && !a.isPunct(k+1, "(") {
			return refusal("the whole row of %s is used in %s", strings.ToLower(n), where)
		}
	}
	return nil
}

// setTarget reports whether token k names the column a SET list assigns:
// [qualifier .] name followed by '=', after SET, ',' or (ON DUPLICATE KEY)
// UPDATE.
func (a *aliasCheck) setTarget(k int) bool {
	if a.name(k) == "" || !a.isPunct(k+1, "=") {
		return false
	}
	j := k
	for a.isPunct(j-1, ".") && a.name(j-2) != "" {
		j -= 2
	}
	return a.isWord(j-1, "SET", "UPDATE") || a.isPunct(j-1, ",")
}
