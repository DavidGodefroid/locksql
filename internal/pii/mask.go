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
// A column is masked whole when its origin matches a rule. When origin is
// false (the session reports no origins), or a column has none (an
// expression, a UNION, an untrusted origin the engine blanked), the column
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
// AliasViolation before its rows may be shown: the session reports no
// origins, or some result column came back without one.
func NeedsAliasCheck(res engine.Result, origin bool) bool {
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
// COUNT(...) is allowed. The
// error is a *sqlclass.Refusal that explains how to write the query.
func AliasViolation(st sqlclass.Statement, r Rules, d sqlclass.Dialect) error {
	if st.Class != sqlclass.Read || st.Kind != "select" || len(r.Mask) == 0 {
		return nil
	}
	toks, err := sqlclass.Lex(d, st.SQL)
	if err != nil {
		return err
	}
	a := newAliasCheck(toks, r, d)
	return a.run()
}

type aliasCheck struct {
	toks  []sqlclass.Token
	r     Rules
	d     sqlclass.Dialect
	match []int           // index of the matching parenthesis, -1 for other tokens
	encl  []int           // index of the innermost enclosing '(' of each token, -1 at top level
	rows  map[string]bool // FROM-clause names whose whole row may carry a PII column
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
}

func (a *aliasCheck) run() error {
	a.rows = a.rowSources()
	if err := a.columnLists(); err != nil {
		return err
	}
	heads := map[int][]selectItem{}
	for i := range a.toks {
		if !a.isWord(i, "SELECT") {
			continue
		}
		depth := a.toks[i].Depth
		later, parenthesised := a.laterArm(i)
		var head []selectItem
		if later && !parenthesised {
			head = heads[depth]
		}
		items, err := a.selectList(i, later, head)
		if err != nil {
			return err
		}
		if !later {
			heads[depth] = items
		}
	}
	return nil
}

// laterArm reports whether the SELECT at i follows UNION/INTERSECT/EXCEPT,
// and whether it is wrapped in parentheses.
func (a *aliasCheck) laterArm(i int) (later, parenthesised bool) {
	j := i - 1
	for a.isPunct(j, "(") {
		parenthesised = true
		j--
	}
	if a.isWord(j, "ALL", "DISTINCT") {
		j--
	}
	return a.isWord(j, "UNION", "INTERSECT", "EXCEPT", "MINUS"), parenthesised
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
	var items []selectItem
	start := k
	for ; ; k++ {
		end := k >= len(a.toks) || a.toks[k].Depth < depth ||
			(a.toks[k].Depth == depth && a.toks[k].Kind == sqlclass.TokWord && listEnd[a.toks[k].Text])
		if end || (a.isPunct(k, ",") && a.toks[k].Depth == depth) {
			if k > start {
				it, err := a.item(i, start, k, len(items), later, head)
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

func (a *aliasCheck) item(sel, s, e, pos int, later bool, head []selectItem) (selectItem, error) {
	if later && a.isStar(e-1) && (e-s == 1 || a.plainRef(s, e-2)) {
		// A star in a later arm puts its sources' columns, PII included,
		// under the head's labels, which no rule may match.
		if e-s == 1 && a.armBearing(sel) || e-s > 1 && a.rows[a.name(e-3)] {
			return selectItem{}, refusal("a later UNION/INTERSECT/EXCEPT arm selects * from a table that may hold PII columns, under the first arm's labels")
		}
		return selectItem{}, nil
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
			if pos < len(head) && head[pos].label == ref {
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
	return selectItem{label: alias}, nil
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
	return a.isWord(p, "SELECT") || a.isPunct(p, ",") || a.isPunct(p, ".") ||
		p >= 0 && a.toks[p].Kind == sqlclass.TokWord && selectModifiers[a.toks[p].Text]
}

// armBearing reports whether the FROM clause of the SELECT at i names a
// source in a.rows, one whose rows may carry a rule-matched column.
func (a *aliasCheck) armBearing(i int) bool {
	depth := a.toks[i].Depth
	from := false
	for k := i + 1; k < len(a.toks) && a.toks[k].Depth >= depth; k++ {
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
// JOIN item, at any level, whose rows may carry a rule-matched column: a
// table a Mask pattern's table segment matches ('*' matches all), a CTE, or
// a parenthesised item that holds a SELECT or names such a table. Names are
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
			delete(clause, t.Depth) // a new level starts with no clause
		case t.Kind == sqlclass.TokWord && (t.Text == "FROM" || t.Text == "JOIN"):
			clause[t.Depth] = t.Text
			g := &group{}
			groups = append(groups, g)
			cur[t.Depth] = g
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
			g.names = append(g.names, n)
			if ctes[n] || a.tableUnderRule(n) {
				g.bearing = true
			}
		}
	}
	rows := map[string]bool{}
	for _, g := range groups {
		if g.bearing {
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
