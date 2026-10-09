package sqlast

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

// Source is a base column, as the catalog names it. For PostgreSQL DB is
// the schema.
type Source struct {
	DB, Table, Column string
	// View marks a column of a view (or of a relation whose base columns
	// are unknown): rules match it by column name.
	View bool
}

func (s Source) String() string { return s.DB + "." + s.Table + "." + s.Column }

// Kind says how a value derives from its sources.
type Kind int

// Kinds, from the least to the most transformed.
const (
	// KindConst involves no column.
	KindConst Kind = iota
	// KindCount is a row count (COUNT): it reveals no value of its sources.
	KindCount
	// KindIdentity is a value of one of its sources: a plain reference,
	// through aliases, subqueries, CTEs and set operations, or MIN/MAX.
	KindIdentity
	// KindAggregate is another aggregate of its sources (SUM, AVG, ...).
	KindAggregate
	// KindExpr is any other expression of its sources.
	KindExpr
)

// Prov is the provenance of a value.
type Prov struct {
	Sources []Source
	Kind    Kind
	// Sensitive is set when a source is under a mask rule and the value
	// reveals source values (Kind Identity, Aggregate or Expr).
	Sensitive bool
	// Modes are the mask modes of the sensitive sources.
	Modes []string
	// Lit is set when some values may be literals of the statement (a
	// UNION of a column and a constant, for instance).
	Lit bool
}

// Table is one relation of the catalog.
type Table struct {
	DB, Name string
	Columns  []string
	View     bool
}

// Catalog resolves table names.
type Catalog interface {
	// Lookup returns the relations a table name (folded parts, as written)
	// may denote: none when it is unknown, several when it is ambiguous.
	Lookup(parts []string) ([]Table, error)
}

// Env is what Analyze needs besides the statement.
type Env struct {
	Catalog Catalog
	// Rule returns the mask mode of a base column, and whether a rule
	// covers it.
	Rule func(Source) (mode string, masked bool)
	// Masking is false for an unmask plan: provenance and functions are
	// still checked, but not the PII usage rules.
	Masking bool
	// Value resolves a placeholder: the value the human typed for a name, or
	// the value of a referenced cell. ok is false when the console does not
	// know it (yet, for a typed name).
	Value func(kind ValueKind, name string) (value string, ok bool)
}

// Output is one result column.
type Output struct {
	// Label is the column label the engine must report (an alias or a
	// plain column name), "" when the engine chooses it.
	Label string
	Prov  Prov
	// Mask is the mask mode of the column, "" for none.
	Mask string
}

// Use is a PII column the statement touches, and where.
type Use struct {
	Source Source
	Clause string
}

// KCheck is a row-count query the console runs before the statement, to
// check that a PII filter, grouping or aggregate covers at least k rows.
type KCheck struct {
	SQL string
	// Grouped checks the smallest group (its result may be NULL when no
	// group remains); otherwise it counts the rows.
	Grouped bool
}

// Replacement substitutes a token literal with the value it stands for in
// the statement that runs.
type Replacement struct {
	Span Span
	Text string
}

// Analysis is what Analyze finds.
type Analysis struct {
	Outputs []Output
	// Relations are the base relations read, "db.table".
	Relations []string
	// Uses are the PII columns the statement touches.
	Uses []Use
	// KChecks must all pass (k rows or more) before the statement runs.
	KChecks []KCheck
	// PIIFilter is set when a PII column is compared with a constant: row
	// estimates must not reach the agent.
	PIIFilter bool
	// LitFilter is set when a PII column is compared for equality with a
	// literal the agent wrote (not a placeholder, not IS NULL), anywhere in
	// the statement. Its results carry no cell references: the agent chose
	// the value behind them, and the rows it selected may be linked to the
	// literal through any join, subquery or set operation.
	LitFilter    bool
	Replacements []Replacement
	// Values are the placeholders compared with PII columns.
	Values []ValueUse
	// KeyFilters are the non-PII columns compared with = and a literal in
	// WHERE (the console checks whether one is a unique key).
	KeyFilters []Source
}

// RunSQL is the statement with its replacements applied.
func (a *Analysis) RunSQL(sql string) string {
	return applyReplacements(sql, Span{0, len(sql)}, a.Replacements)
}

// Masked reports whether some output is masked.
func (a *Analysis) Masked() bool {
	for _, o := range a.Outputs {
		if o.Mask != "" {
			return true
		}
	}
	return false
}

// ---- Scopes ----

type column struct {
	name string // folded; "" when the engine names it
	prov Prov
	// labeled is set when the engine labels the column with name (an
	// alias, a plain column reference or a star expansion).
	labeled bool
}

type relation struct {
	name   string     // folded binding name
	qual   [][]string // folded qualifiers that also name it ([db, table])
	cols   []column
	lookup bool // a base relation: unknown columns are refused
}

type scope struct {
	parent *scope
	level  int
	rels   []*relation
	// aliases are the select-list outputs, for GROUP BY, HAVING and ORDER
	// BY references.
	aliases []column
	node    *nodeState
}

// nodeState follows one SELECT core while it is analysed.
type nodeState struct {
	level int
	// outer is set when a reference inside the node resolves above it.
	outer bool
	needK bool
	// constFilter is set when a PII column is compared with a constant.
	constFilter bool
	aggregate   bool
}

type cteDef struct {
	name      string
	cte       *CTE
	cols      []column
	recursive bool
	resolving bool
	selfCols  []column
}

type analyzer struct {
	env   Env
	st    *Statement
	d     sqlclass.Dialect
	a     *Analysis
	ctes  [][]*cteDef
	withs []*With
	// dry suppresses findings while a recursive CTE converges.
	dry       int
	inRecCTE  int
	relations map[string]bool
	uses      map[Use]bool
}

// Analyze resolves the provenance of every output column of st, checks the
// functions against the allowlist and, when env.Masking is set, applies
// the PII usage rules. Errors are *sqlclass.Refusal values.
func Analyze(st *Statement, env Env) (*Analysis, error) {
	if env.Rule == nil {
		env.Rule = func(Source) (string, bool) { return "", false }
	}
	if env.Value == nil {
		env.Value = func(ValueKind, string) (string, bool) { return "", false }
	}
	an := &analyzer{env: env, st: st, d: st.Dialect, a: &Analysis{}, relations: map[string]bool{}, uses: map[Use]bool{}}
	cols, err := an.query(st.Query, nil)
	if err != nil {
		return nil, err
	}
	for _, c := range cols {
		label := ""
		if c.labeled {
			label = c.name
		}
		an.a.Outputs = append(an.a.Outputs, Output{Label: label, Prov: c.prov, Mask: an.maskOf(c.prov)})
	}
	if st.Explain {
		if env.Masking && (an.a.PIIFilter || len(an.a.KChecks) > 0) {
			return nil, refuse("EXPLAIN of a statement that filters, groups or aggregates PII columns is not allowed: its row estimates would reveal what the k-anonymity check protects")
		}
		an.a.Outputs = nil
	}
	for r := range an.relations {
		an.a.Relations = append(an.a.Relations, r)
	}
	sort.Strings(an.a.Relations)
	for u := range an.uses {
		an.a.Uses = append(an.a.Uses, u)
	}
	sort.Slice(an.a.Uses, func(i, j int) bool {
		if an.a.Uses[i].Source.String() != an.a.Uses[j].Source.String() {
			return an.a.Uses[i].Source.String() < an.a.Uses[j].Source.String()
		}
		return an.a.Uses[i].Clause < an.a.Uses[j].Clause
	})
	if err := an.strayPlaceholders(); err != nil {
		return nil, err
	}
	return an.a, nil
}

// maskOf is the mask mode of an output column.
func (an *analyzer) maskOf(p Prov) string {
	if !an.env.Masking || !p.Sensitive {
		return ""
	}
	if p.Kind != KindIdentity {
		return "redact"
	}
	modes := slices.Compact(slices.Sorted(slices.Values(p.Modes)))
	if len(modes) == 1 {
		return modes[0]
	}
	return "redact"
}

func (an *analyzer) record(u Use) {
	if an.dry == 0 {
		an.uses[u] = true
	}
}

// ---- Queries ----

func (an *analyzer) query(q *Query, parent *scope) ([]column, error) {
	if q.With != nil {
		defs := make([]*cteDef, 0, len(q.With.CTEs))
		an.ctes = append(an.ctes, defs)
		an.withs = append(an.withs, q.With)
		defer func() {
			an.ctes = an.ctes[:len(an.ctes)-1]
			an.withs = an.withs[:len(an.withs)-1]
		}()
		for _, c := range q.With.CTEs {
			if err := an.defineCTE(c, q.With.Recursive, parent); err != nil {
				return nil, err
			}
		}
	}
	var body *Select
	if s, ok := q.Body.(*Select); ok {
		body = s
	}
	cols, sc, err := an.body(q.Body, parent)
	if err != nil {
		return nil, err
	}
	for _, o := range q.OrderBy {
		if err := an.orderItem(o.Expr, cols, body, sc); err != nil {
			return nil, err
		}
	}
	return cols, nil
}

// body analyses a query body. For a SELECT core it also returns its scope,
// for ORDER BY references to input columns.
func (an *analyzer) body(b Body, parent *scope) ([]column, *scope, error) {
	switch b := b.(type) {
	case *Select:
		return an.selectCore(b, parent)
	case *Query:
		cols, err := an.query(b, parent)
		return cols, nil, err
	case *SetOp:
		l, _, err := an.body(b.Left, parent)
		if err != nil {
			return nil, nil, err
		}
		r, _, err := an.body(b.Right, parent)
		if err != nil {
			return nil, nil, err
		}
		if len(l) != len(r) {
			return nil, nil, refusef("the arms of %s have different numbers of columns", b.Op)
		}
		out := make([]column, len(l))
		for i := range l {
			if err := an.setOpCompare(b, i, l[i].prov, r[i].prov); err != nil {
				return nil, nil, err
			}
			out[i] = column{name: l[i].name, prov: union(l[i].prov, r[i].prov), labeled: l[i].labeled}
		}
		return out, nil, nil
	}
	return nil, nil, refuse("unsupported query body")
}

// setOpCompare checks column i of a set operation. UNION (distinct),
// INTERSECT and EXCEPT compare their arms column by column: like a join, a
// PII column may only meet values that are themselves all PII, never a
// literal, an expression, an unmasked column or a mix the agent chose, or
// the result would tell whether that value is in the column, without any
// k-anonymity check. UNION ALL compares nothing. The arms of a nested set
// operation arrive merged, so every level is checked.
func (an *analyzer) setOpCompare(b *SetOp, i int, l, r Prov) error {
	if !an.env.Masking || b.All && strings.EqualFold(b.Op, "UNION") {
		return nil
	}
	if !l.Sensitive && !r.Sensitive || an.allPII(l) && an.allPII(r) {
		return nil
	}
	return refusef("a set operation compares a PII column with a value the agent chose (column %d)", i+1)
}

// allPII reports a plain value whose every source is under a mask rule and
// which cannot be a literal of the statement.
func (an *analyzer) allPII(p Prov) bool {
	if !p.Sensitive || p.Lit || p.Kind != KindIdentity || len(p.Sources) == 0 {
		return false
	}
	for _, s := range p.Sources {
		if _, ok := an.env.Rule(s); !ok {
			return false
		}
	}
	return true
}

// union merges the provenance of two values that may each be the result.
func union(a, b Prov) Prov {
	k := max(a.Kind, b.Kind)
	return Prov{
		Sources:   mergeSources(a.Sources, b.Sources),
		Kind:      k,
		Sensitive: a.Sensitive || b.Sensitive,
		Modes:     mergeSources(a.Modes, b.Modes),
		Lit:       a.Lit || b.Lit || a.Kind == KindConst || b.Kind == KindConst,
	}
}

// mergeSources appends to a the elements of b it lacks (sources, modes).
func mergeSources[T comparable](a, b []T) []T {
	out := slices.Clone(a)
	for _, s := range b {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

func (an *analyzer) defineCTE(c *CTE, recursive bool, parent *scope) error {
	defs := &an.ctes[len(an.ctes)-1]
	for _, d := range *defs {
		if d.name == c.Name {
			return refusef("CTE %s is defined twice", strings.ToLower(c.Name))
		}
	}
	def := &cteDef{name: c.Name, cte: c, recursive: recursive && an.selfReferencing(c)}
	*defs = append(*defs, def)
	if !def.recursive {
		cols, err := an.query(c.Query, parent)
		if err != nil {
			return err
		}
		def.cols, err = renameCols(cols, c.Columns, "CTE "+strings.ToLower(c.Name))
		return err
	}
	// A recursive CTE: start from its non-recursive arm, then widen the
	// provenance until it no longer changes.
	so, ok := c.Query.Body.(*SetOp)
	if !ok || c.Query.With != nil {
		return refusef("recursive CTE %s must be <anchor> UNION [ALL] <recursive part>", strings.ToLower(c.Name))
	}
	an.dry++
	anchor, _, err := an.body(so.Left, parent)
	an.dry--
	if err != nil {
		return err
	}
	cur, err := renameCols(anchor, c.Columns, "CTE "+strings.ToLower(c.Name))
	if err != nil {
		return err
	}
	an.inRecCTE++
	defer func() { an.inRecCTE-- }()
	converged := false
	for i := 0; i < 8; i++ {
		def.selfCols = cur
		an.dry++
		cols, err := an.query(c.Query, parent)
		an.dry--
		if err != nil {
			return err
		}
		next, err := renameCols(cols, c.Columns, "CTE "+strings.ToLower(c.Name))
		if err != nil {
			return err
		}
		for k := range next {
			next[k].prov = union(next[k].prov, cur[k].prov)
		}
		if sameCols(cur, next) {
			converged = true
			break
		}
		cur = next
	}
	if !converged {
		// The last iteration may still miss a literal or a source a few
		// hops away: refuse rather than mask on a partial provenance.
		return refusef("recursive CTE %s is too deep to analyse: its columns pass values to each other through too many steps", strings.ToLower(c.Name))
	}
	def.selfCols = cur
	if _, err := an.query(c.Query, parent); err != nil { // final pass, with findings
		return err
	}
	def.cols = cur
	return nil
}

// sameCols reports whether a recursive CTE's provenance has converged:
// every field that decides masking and references (kind, sensitivity,
// literals, sources, modes) is unchanged.
func sameCols(a, b []column) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		p, q := a[i].prov, b[i].prov
		if p.Kind != q.Kind || p.Sensitive != q.Sensitive || p.Lit != q.Lit || !sameSet(p.Sources, q.Sources) || !sameSet(p.Modes, q.Modes) {
			return false
		}
	}
	return true
}

// sameSet reports whether a and b hold the same elements, ignoring order
// and repeats.
func sameSet[T comparable](a, b []T) bool {
	for _, x := range a {
		if !slices.Contains(b, x) {
			return false
		}
	}
	for _, x := range b {
		if !slices.Contains(a, x) {
			return false
		}
	}
	return true
}

// selfReferencing reports whether a CTE of a WITH RECURSIVE names itself.
func (an *analyzer) selfReferencing(c *CTE) bool {
	toks, err := sqlclass.Lex(an.d, an.st.SQL[c.Query.Sp.Pos:c.Query.Sp.End])
	if err != nil {
		return true
	}
	for _, t := range toks {
		if t.Name() == c.Name {
			return true
		}
	}
	return false
}

func renameCols(cols []column, names []string, what string) ([]column, error) {
	if names == nil {
		return cols, nil
	}
	if len(names) != len(cols) {
		return nil, refusef("%s names %d columns but returns %d", what, len(names), len(cols))
	}
	out := make([]column, len(cols))
	for i := range cols {
		out[i] = column{name: names[i], prov: cols[i].prov, labeled: true}
	}
	return out, nil
}

// ---- SELECT ----

func (an *analyzer) selectCore(s *Select, parent *scope) ([]column, *scope, error) {
	level := 0
	if parent != nil {
		level = parent.level + 1
	}
	node := &nodeState{level: level}
	sc := &scope{parent: parent, level: level, node: node}
	var star []column
	for _, te := range s.From {
		rels, st, err := an.tableExpr(te, sc, parent)
		if err != nil {
			return nil, nil, err
		}
		sc.rels = append(sc.rels, rels...)
		star = append(star, st...)
	}
	if s.Where != nil {
		if err := an.filter(s.Where, sc, "where", true); err != nil {
			return nil, nil, err
		}
	}
	// Select list.
	var cols []column
	for _, it := range s.Items {
		if it.Star {
			exp, err := an.expandStar(it, sc, star)
			if err != nil {
				return nil, nil, err
			}
			cols = append(cols, exp...)
			continue
		}
		p, err := an.value(it.Expr, sc, "select")
		if err != nil {
			return nil, nil, err
		}
		name, labeled := it.Alias, it.Alias != ""
		if name == "" {
			name = defaultName(it.Expr)
			_, labeled = it.Expr.(*ColumnRef)
		}
		cols = append(cols, column{name: name, prov: p, labeled: labeled})
	}
	sc.aliases = cols
	// GROUP BY.
	for _, g := range s.GroupBy {
		p, err := an.groupKey(g, sc, cols)
		if err != nil {
			return nil, nil, err
		}
		if p.Sensitive && an.env.Masking {
			if p.Kind != KindIdentity {
				return nil, nil, refuse("GROUP BY over an expression of a PII column is not allowed")
			}
			node.needK = true
		}
		node.aggregate = true
	}
	if s.Having != nil {
		node.aggregate = true
		if err := an.filter(s.Having, sc, "having", true); err != nil {
			return nil, nil, err
		}
	}
	for _, e := range s.DistinctOn {
		p, err := an.value(e, sc, "distinct on")
		if err != nil {
			return nil, nil, err
		}
		if p.Sensitive && an.env.Masking {
			return nil, nil, refuse("DISTINCT ON a PII column is not allowed")
		}
	}
	if node.needK && an.env.Masking {
		if err := an.kCheck(s, cols, sc); err != nil {
			return nil, nil, err
		}
	}
	return cols, sc, nil
}

func defaultName(e Expr) string {
	switch e := e.(type) {
	case *ColumnRef:
		return e.Parts[len(e.Parts)-1]
	case *Paren:
		return defaultName(e.X)
	case *FuncCall:
		return e.Name
	}
	return ""
}

// expandStar expands * or t.* into the columns it stands for.
func (an *analyzer) expandStar(it *SelectItem, sc *scope, star []column) ([]column, error) {
	if it.Qualifier == nil {
		if len(sc.rels) == 0 {
			return nil, refuse("SELECT * needs a FROM clause")
		}
		for _, c := range star {
			an.touch(c.prov, "select")
		}
		return slices.Clone(star), nil
	}
	r := an.findRel(sc, it.Qualifier)
	if r == nil {
		return nil, refusef("unknown table %s in %s.*", strings.ToLower(strings.Join(it.Qualifier, ".")), strings.ToLower(strings.Join(it.Qualifier, ".")))
	}
	for _, c := range r.cols {
		an.touch(c.prov, "select")
	}
	return slices.Clone(r.cols), nil
}

// findRel finds the relation a qualifier names, in sc only.
func (an *analyzer) findRel(sc *scope, q []string) *relation {
	var found *relation
	for _, r := range sc.rels {
		if len(q) == 1 && r.name == q[0] {
			found = r
		}
		for _, alt := range r.qual {
			if slices.Equal(alt, q) {
				found = r
			}
		}
	}
	return found
}

// ---- FROM ----

// tableExpr binds a FROM item. It returns its relations and its columns as
// SELECT * lists them.
func (an *analyzer) tableExpr(te TableExpr, sc, parent *scope) ([]*relation, []column, error) {
	switch t := te.(type) {
	case *TableName:
		r, err := an.tableName(t)
		if err != nil {
			return nil, nil, err
		}
		return []*relation{r}, slices.Clone(r.cols), nil
	case *Derived:
		ps := parent
		if t.Lateral {
			// A LATERAL subquery sees the FROM items before it.
			ps = &scope{parent: parent, level: sc.level, rels: slices.Clone(sc.rels), node: sc.node}
		}
		cols, err := an.query(t.Query, ps)
		if err != nil {
			return nil, nil, err
		}
		if t.Alias == "" && an.d != sqlclass.SQLite && an.d != sqlclass.Postgres {
			return nil, nil, refuse("a derived table needs an alias")
		}
		cols, err = renameCols(cols, t.ColAliases, "derived table "+strings.ToLower(t.Alias))
		if err != nil {
			return nil, nil, err
		}
		r := &relation{name: t.Alias, cols: cols}
		return []*relation{r}, slices.Clone(cols), nil
	case *Join:
		lr, ls, err := an.tableExpr(t.Left, sc, parent)
		if err != nil {
			return nil, nil, err
		}
		inner := &scope{parent: parent, level: sc.level, rels: append(slices.Clone(sc.rels), lr...), node: sc.node}
		rr, rs, err := an.tableExpr(t.Right, inner, parent)
		if err != nil {
			return nil, nil, err
		}
		rels := append(lr, rr...)
		using := t.Using
		if t.Natural {
			for _, l := range ls {
				for _, r := range rs {
					if l.name != "" && l.name == r.name && !slices.Contains(using, l.name) {
						using = append(using, l.name)
					}
				}
			}
		}
		star, err := an.joinStar(ls, rs, using)
		if err != nil {
			return nil, nil, err
		}
		for _, u := range using {
			lp, rp := findCol(ls, u), findCol(rs, u)
			if lp == nil || rp == nil {
				return nil, nil, refusef("USING column %s is not on both sides", strings.ToLower(u))
			}
			if err := an.joinEquality(*lp, *rp); err != nil {
				return nil, nil, err
			}
		}
		if t.On != nil {
			on := &scope{parent: parent, level: sc.level, rels: append(slices.Clone(sc.rels), rels...), node: sc.node}
			if err := an.filter(t.On, on, "join", true); err != nil {
				return nil, nil, err
			}
		}
		return rels, star, nil
	}
	return nil, nil, refuse("unsupported FROM item")
}

func findCol(cols []column, name string) *column {
	for i := range cols {
		if cols[i].name == name {
			return &cols[i]
		}
	}
	return nil
}

// joinStar is the SELECT * list of a USING or NATURAL join: SQLite keeps
// the left columns in place and drops the right duplicates; MySQL and
// PostgreSQL list the merged columns first. The console checks the labels
// the engine returns against these names, so a wrong guess is refused, not
// leaked.
func (an *analyzer) joinStar(ls, rs []column, using []string) ([]column, error) {
	if len(using) == 0 {
		return append(slices.Clone(ls), rs...), nil
	}
	merged := func(name string) column {
		l, r := findCol(ls, name), findCol(rs, name)
		if l == nil || r == nil {
			return column{name: name}
		}
		return column{name: name, prov: union(l.prov, r.prov), labeled: true}
	}
	var out []column
	if an.d == sqlclass.SQLite {
		for _, c := range ls {
			if slices.Contains(using, c.name) {
				out = append(out, merged(c.name))
			} else {
				out = append(out, c)
			}
		}
	} else {
		order := using
		if an.d == sqlclass.MySQL {
			order = nil
			for _, c := range ls {
				if slices.Contains(using, c.name) {
					order = append(order, c.name)
				}
			}
		}
		for _, u := range order {
			out = append(out, merged(u))
		}
		for _, c := range ls {
			if !slices.Contains(using, c.name) {
				out = append(out, c)
			}
		}
	}
	for _, c := range rs {
		if !slices.Contains(using, c.name) {
			out = append(out, c)
		}
	}
	return out, nil
}

func (an *analyzer) tableName(t *TableName) (*relation, error) {
	binding := t.Alias
	if binding == "" {
		binding = t.Parts[len(t.Parts)-1]
	}
	if len(t.Parts) == 1 {
		if def := an.findCTE(t.Parts[0]); def != nil {
			cols := def.cols
			if def.resolving || (def.recursive && def.cols == nil) {
				cols = def.selfCols
			}
			cols, err := renameCols(cols, t.ColAliases, "table "+strings.ToLower(binding))
			if err != nil {
				return nil, err
			}
			return &relation{name: binding, cols: cols}, nil
		}
	}
	if an.d == sqlclass.MySQL && len(t.Parts) == 1 && t.Parts[0] == "DUAL" {
		return &relation{name: binding}, nil
	}
	if systemRelation(an.d, t.Parts) {
		return nil, refusef("%s holds server or catalog metadata; it cannot be queried (use the catalog commands)", strings.ToLower(strings.Join(t.Parts, ".")))
	}
	if an.env.Catalog == nil {
		return nil, refusef("unknown table %s", strings.ToLower(strings.Join(t.Parts, ".")))
	}
	tables, err := an.env.Catalog.Lookup(t.Parts)
	if err != nil {
		return nil, err
	}
	if len(tables) == 0 {
		return nil, refusef("unknown table %s (locksql resolves every table before running a statement)", strings.ToLower(strings.Join(t.Parts, ".")))
	}
	// Several candidates (an unqualified name in several schemas): each
	// column comes from any of them.
	r := &relation{name: binding, lookup: true}
	if t.Alias == "" {
		r.qual = [][]string{t.Parts}
		for _, tb := range tables {
			r.qual = append(r.qual, []string{fold(tb.DB), fold(tb.Name)})
		}
	}
	var names []string
	for k, tb := range tables {
		if an.dry == 0 {
			an.relations[tb.DB+"."+tb.Name] = true
		}
		if k > 0 && len(tb.Columns) != len(names) {
			return nil, refusef("table %s is ambiguous (several schemas hold it); qualify it", strings.ToLower(strings.Join(t.Parts, ".")))
		}
		for i, c := range tb.Columns {
			f := fold(c)
			if k == 0 {
				names = append(names, f)
				r.cols = append(r.cols, column{name: f, labeled: true})
			} else if names[i] != f {
				return nil, refusef("table %s is ambiguous (several schemas hold it); qualify it", strings.ToLower(strings.Join(t.Parts, ".")))
			}
			src := Source{DB: tb.DB, Table: tb.Name, Column: c, View: tb.View}
			if k == 0 {
				r.cols[i].prov = an.sourceProv(src)
			} else {
				r.cols[i].prov = union(r.cols[i].prov, an.sourceProv(src))
			}
		}
	}
	if t.ColAliases != nil {
		cols, err := renameCols(r.cols, t.ColAliases, "table "+strings.ToLower(binding))
		if err != nil {
			return nil, err
		}
		r.cols = cols
	}
	return r, nil
}

func (an *analyzer) sourceProv(s Source) Prov {
	p := Prov{Sources: []Source{s}, Kind: KindIdentity}
	if mode, ok := an.env.Rule(s); ok {
		p.Sensitive = true
		p.Modes = []string{mode}
	}
	return p
}

func (an *analyzer) findCTE(name string) *cteDef {
	for i := len(an.ctes) - 1; i >= 0; i-- {
		for _, d := range an.ctes[i] {
			if d.name == name {
				if d.cols == nil && !d.recursive {
					continue // defined later in the same WITH
				}
				return d
			}
		}
	}
	return nil
}

func fold(s string) string { return strings.ToUpper(strings.ToLower(s)) }

// ---- Column references ----

// resolve finds the column a reference names, searching the scope chain.
// Within GROUP BY, HAVING and ORDER BY a single name that is no input
// column may name a select-list output (aliasOK).
func (an *analyzer) resolve(ref *ColumnRef, sc *scope, aliasOK bool) (Prov, error) {
	name := ref.Parts[len(ref.Parts)-1]
	qual := ref.Parts[:len(ref.Parts)-1]
	if aliasOK && len(qual) == 0 {
		// Engines disagree on whether an output alias or an input column
		// wins (ORDER BY prefers the alias, GROUP BY the column): a name
		// that is both stands for both.
		var alias *Prov
		for _, c := range sc.aliases {
			if c.name == name {
				p := c.prov
				if alias != nil {
					p = union(*alias, p)
				}
				alias = &p
			}
		}
		if alias != nil {
			in, err := an.resolve(ref, sc, false)
			if err != nil {
				return *alias, nil
			}
			return union(*alias, in), nil
		}
	}
	for s := sc; s != nil; s = s.parent {
		var hits []column
		var known bool
		for _, r := range s.rels {
			if len(qual) > 0 && !(len(qual) == 1 && r.name == qual[0]) && !slices.ContainsFunc(r.qual, func(q []string) bool { return slices.Equal(q, qual) }) {
				continue
			}
			known = true
			for _, c := range r.cols {
				if c.name != "" && c.name == name {
					hits = append(hits, c)
				}
			}
		}
		if len(qual) > 0 && known && len(hits) == 0 {
			return Prov{}, refusef("unknown column %s", strings.ToLower(strings.Join(ref.Parts, ".")))
		}
		if len(hits) > 0 {
			if s != sc {
				an.markOuter(sc, s.level)
			}
			p := hits[0].prov
			for _, h := range hits[1:] {
				p = union(p, h.prov)
			}
			return p, nil
		}
	}
	return Prov{}, refusef("unknown column %s (locksql resolves every column before running a statement)", strings.ToLower(strings.Join(ref.Parts, ".")))
}

// markOuter records a reference from sc to the scope at level.
func (an *analyzer) markOuter(sc *scope, level int) {
	for s := sc; s != nil && s.level > level; s = s.parent {
		if s.node != nil {
			s.node.outer = true
		}
	}
}

// touch records the PII sources of a value used in a clause.
func (an *analyzer) touch(p Prov, clause string) {
	if !p.Sensitive {
		return
	}
	for _, s := range p.Sources {
		if _, ok := an.env.Rule(s); ok {
			an.record(Use{Source: s, Clause: clause})
		}
	}
}

// ---- Values ----

// value computes the provenance of an expression used as a value. An
// expression that transforms a PII column (anything but a plain reference,
// COUNT, MIN/MAX and the other aggregates) is refused: its result could
// reveal the column in a form no mask covers.
func (an *analyzer) value(e Expr, sc *scope, clause string) (Prov, error) {
	switch e := e.(type) {
	case *ColumnRef:
		p, err := an.resolve(e, sc, clause == "group by" || clause == "having" || clause == "order by")
		if err != nil {
			return Prov{}, err
		}
		an.touch(p, clause)
		return p, nil
	case *Literal:
		return Prov{Kind: KindConst, Lit: true}, nil
	case *Paren:
		return an.value(e.X, sc, clause)
	case *Subquery:
		cols, err := an.query(e.Query, sc)
		if err != nil {
			return Prov{}, err
		}
		if len(cols) != 1 {
			return Prov{}, refuse("a scalar subquery must return one column")
		}
		return cols[0].prov, nil
	case *FuncCall:
		return an.call(e, sc, clause)
	case *Exists:
		if _, err := an.query(e.Query, sc); err != nil {
			return Prov{}, err
		}
		return Prov{Kind: KindExpr}, nil
	case *In:
		parts := []Expr{e.X}
		parts = append(parts, e.List...)
		p, err := an.combine(parts, sc, clause, "IN")
		if err != nil {
			return Prov{}, err
		}
		if e.Query != nil {
			cols, err := an.query(e.Query, sc)
			if err != nil {
				return Prov{}, err
			}
			for _, c := range cols {
				p = an.mix(p, c.prov)
			}
			if err := an.noPII(p, "IN"); err != nil {
				return Prov{}, err
			}
		}
		return p, nil
	case *Binary:
		return an.combine([]Expr{e.L, e.R}, sc, clause, e.Op)
	case *Unary:
		return an.combine([]Expr{e.X}, sc, clause, e.Op)
	case *Case:
		var parts []Expr
		if e.Operand != nil {
			parts = append(parts, e.Operand)
		}
		for _, w := range e.Whens {
			parts = append(parts, w.Cond, w.Result)
		}
		if e.Else != nil {
			parts = append(parts, e.Else)
		}
		return an.combine(parts, sc, clause, "CASE")
	case *Cast:
		return an.combine([]Expr{e.X}, sc, clause, "CAST")
	case *Collate:
		return an.combine([]Expr{e.X}, sc, clause, "COLLATE")
	case *Between:
		return an.combine([]Expr{e.X, e.Lo, e.Hi}, sc, clause, "BETWEEN")
	case *Like:
		parts := []Expr{e.X, e.Pattern}
		if e.Escape != nil {
			parts = append(parts, e.Escape)
		}
		return an.combine(parts, sc, clause, e.Op)
	case *IsTest:
		parts := []Expr{e.X}
		if e.Y != nil {
			parts = append(parts, e.Y)
		}
		return an.combine(parts, sc, clause, "IS")
	case *Tuple:
		return an.combine(e.Items, sc, clause, "a row value")
	}
	return Prov{}, refuse("unsupported expression")
}

// combine is the provenance of an operator or function over parts: KindExpr
// over their sources. A PII part is refused.
func (an *analyzer) combine(parts []Expr, sc *scope, clause, what string) (Prov, error) {
	out := Prov{Kind: KindConst}
	for _, x := range parts {
		p, err := an.value(x, sc, clause)
		if err != nil {
			return Prov{}, err
		}
		out = an.mix(out, p)
	}
	if err := an.noPII(out, what); err != nil {
		return Prov{}, err
	}
	return out, nil
}

// mix adds p to an expression's provenance.
func (an *analyzer) mix(out, p Prov) Prov {
	out.Sources = mergeSources(out.Sources, p.Sources)
	out.Sensitive = out.Sensitive || p.Sensitive
	out.Modes = append(out.Modes, p.Modes...)
	out.Lit = out.Lit || p.Lit
	if p.Kind != KindConst {
		out.Kind = KindExpr
	}
	return out
}

func (an *analyzer) noPII(p Prov, what string) error {
	if !p.Sensitive || !an.env.Masking {
		return nil
	}
	return refusef("a PII column (%s) is used inside %s: only plain references, COUNT, MIN, MAX and aggregates may use PII columns, and filters may only compare them with constants for equality (or unmask the query)", piiNames(p), describeOp(what))
}

func describeOp(what string) string {
	switch {
	case what == "":
		return "an expression"
	case strings.ContainsAny(what[:1], "abcdefghijklmnopqrstuvwxyz"):
		return what
	case strings.IndexFunc(what, func(r rune) bool { return r >= 'A' && r <= 'Z' }) == 0:
		return what
	}
	return "the " + what + " operator"
}

func piiNames(p Prov) string {
	var names []string
	for _, s := range p.Sources {
		names = append(names, strings.ToLower(s.Table+"."+s.Column))
	}
	slices.Sort(names)
	names = slices.Compact(names)
	if len(names) > 3 {
		names = append(names[:3], "…")
	}
	return strings.Join(names, ", ")
}

// call is the provenance of a function call.
func (an *analyzer) call(f *FuncCall, sc *scope, clause string) (Prov, error) {
	if !funcAllowed(an.d, f.Name) {
		return Prov{}, refusef("function %s is not in the allowlist", strings.ToLower(f.Name))
	}
	if f.Over != nil {
		for _, e := range f.Over.PartitionBy {
			if err := an.noPIIValue(e, sc, "window PARTITION BY"); err != nil {
				return Prov{}, err
			}
		}
		for _, o := range f.Over.OrderBy {
			if err := an.noPIIValue(o.Expr, sc, "window ORDER BY"); err != nil {
				return Prov{}, err
			}
		}
		if windowOnly[f.Name] || aggregates[f.Name] {
			return an.combine(f.Args, sc, clause, "window function "+strings.ToLower(f.Name))
		}
		return Prov{}, refusef("%s is not a window function", strings.ToLower(f.Name))
	}
	if windowOnly[f.Name] {
		return Prov{}, refusef("%s needs OVER (...)", strings.ToLower(f.Name))
	}
	if !aggregates[f.Name] {
		if f.Distinct || f.Filter != nil || f.OrderBy != nil {
			return Prov{}, refusef("DISTINCT, FILTER and ORDER BY only apply to aggregates")
		}
		return an.combine(f.Args, sc, clause, "function "+strings.ToLower(f.Name))
	}
	// An aggregate.
	if sc.node != nil {
		sc.node.aggregate = true
	}
	if f.Filter != nil {
		if err := an.noPIIValue(f.Filter, sc, "FILTER"); err != nil {
			return Prov{}, err
		}
	}
	for _, o := range f.OrderBy {
		if err := an.noPIIValue(o.Expr, sc, "an aggregate's ORDER BY"); err != nil {
			return Prov{}, err
		}
	}
	if f.Star {
		return Prov{Kind: KindConst}, nil
	}
	var arg Prov
	switch {
	case len(f.Args) == 1:
		p, err := an.value(f.Args[0], sc, clause)
		if err != nil {
			return Prov{}, err
		}
		arg = p
	default:
		// string_agg(x, sep), GROUP_CONCAT(a, b), json_object_agg(k, v):
		// every argument is aggregated as a value.
		p, err := an.combineLoose(f.Args, sc, clause)
		if err != nil {
			return Prov{}, err
		}
		arg = p
	}
	if arg.Kind == KindExpr && arg.Sensitive && an.env.Masking {
		return Prov{}, refusef("a PII column (%s) is used inside an expression given to %s", piiNames(arg), strings.ToLower(f.Name))
	}
	if arg.Sensitive && an.env.Masking && sc.node != nil {
		sc.node.needK = true
	}
	switch {
	case countAggs[f.Name]:
		return Prov{Sources: arg.Sources, Kind: KindCount}, nil
	case identityAggs[f.Name] && len(f.Args) == 1:
		if arg.Kind == KindConst {
			return arg, nil
		}
		arg.Kind = max(arg.Kind, KindIdentity)
		return arg, nil
	}
	if arg.Kind == KindConst {
		return arg, nil
	}
	arg.Kind = max(arg.Kind, KindAggregate)
	return arg, nil
}

// combineLoose merges the provenance of several aggregate arguments,
// keeping plain PII references (each is aggregated as a value).
func (an *analyzer) combineLoose(parts []Expr, sc *scope, clause string) (Prov, error) {
	out := Prov{Kind: KindConst}
	for _, x := range parts {
		p, err := an.value(x, sc, clause)
		if err != nil {
			return Prov{}, err
		}
		if p.Sensitive && p.Kind != KindIdentity && an.env.Masking {
			return Prov{}, refusef("a PII column (%s) is used inside an expression given to an aggregate", piiNames(p))
		}
		k := max(out.Kind, p.Kind)
		out = Prov{Sources: mergeSources(out.Sources, p.Sources), Kind: k, Sensitive: out.Sensitive || p.Sensitive, Modes: append(out.Modes, p.Modes...)}
	}
	if out.Kind == KindIdentity && len(parts) > 1 {
		out.Kind = KindAggregate
	}
	return out, nil
}

// noPIIValue refuses a PII column anywhere in e.
func (an *analyzer) noPIIValue(e Expr, sc *scope, where string) error {
	p, err := an.value(e, sc, "order by")
	if err != nil {
		return err
	}
	if p.Sensitive && an.env.Masking {
		return refusef("a PII column (%s) is not allowed in %s: it would reveal the order or the grouping of its values", piiNames(p), where)
	}
	return nil
}

// groupKey resolves a GROUP BY key: a position, an output alias or an
// expression over the input columns.
func (an *analyzer) groupKey(g Expr, sc *scope, cols []column) (Prov, error) {
	if l, ok := g.(*Literal); ok && l.Kind == LitNumber && allDigits(l.Text) {
		n := atoiSafe(l.Text)
		if n < 1 || n > len(cols) {
			return Prov{}, refusef("GROUP BY position %s is out of range", l.Text)
		}
		an.touch(cols[n-1].prov, "group by")
		return cols[n-1].prov, nil
	}
	return an.value(g, sc, "group by")
}

func atoiSafe(s string) int {
	n := 0
	for i := 0; i < len(s) && i < 9; i++ {
		n = n*10 + int(s[i]-'0')
	}
	if len(s) > 9 {
		return -1
	}
	return n
}

// orderItem checks one ORDER BY entry of a query. Ordering by a PII value
// reveals the order of its values: it is refused.
func (an *analyzer) orderItem(e Expr, cols []column, body *Select, sc *scope) error {
	var p Prov
	switch {
	case isPosition(e):
		n := atoiSafe(e.(*Literal).Text)
		if n < 1 || n > len(cols) {
			return refuse("ORDER BY position is out of range")
		}
		p = cols[n-1].prov
	case sc == nil:
		// A set operation: only output names.
		ref, ok := e.(*ColumnRef)
		if !ok || len(ref.Parts) != 1 {
			return refuse("ORDER BY of a UNION, INTERSECT or EXCEPT takes output column names or positions")
		}
		c := findCol(cols, ref.Parts[0])
		if c == nil {
			return refusef("unknown column %s", strings.ToLower(ref.Parts[0]))
		}
		p = c.prov
	default:
		v, err := an.value(e, sc, "order by")
		if err != nil {
			return err
		}
		p = v
	}
	if p.Sensitive && an.env.Masking {
		return refusef("ORDER BY a PII column (%s) is not allowed: it reveals the order of its values", piiNames(p))
	}
	return nil
}

func isPosition(e Expr) bool {
	l, ok := e.(*Literal)
	return ok && l.Kind == LitNumber && allDigits(l.Text)
}

// ---- Filters ----

// filter checks a WHERE, HAVING or ON condition. A PII column may only
// appear in a positive atom reached through AND and parentheses (pos): under
// NOT, OR or XOR an atom could select the complement of the rows the
// k-anonymity checks count, or let another branch decide what the filter
// keeps. An atom compares a PII column for equality with a literal (or a
// list of literals, or IS NULL), which needs the k-anonymity checks, or
// with another PII column (a join).
func (an *analyzer) filter(e Expr, sc *scope, clause string, pos bool) error {
	switch e := e.(type) {
	case *Paren:
		return an.filter(e.X, sc, clause, pos)
	case *Binary:
		switch e.Op {
		case "AND":
			if err := an.filter(e.L, sc, clause, pos); err != nil {
				return err
			}
			return an.filter(e.R, sc, clause, pos)
		case "OR", "XOR":
			if err := an.filter(e.L, sc, clause, false); err != nil {
				return err
			}
			return an.filter(e.R, sc, clause, false)
		case "=", "<>", "!=", "<=>":
			return an.comparison(e.Op, e.L, e.R, sc, clause, pos)
		}
	case *Unary:
		if e.Op == "NOT" {
			return an.filter(e.X, sc, clause, false)
		}
	case *IsTest:
		if e.What == "NULL" {
			p, err := an.value(e.X, sc, clause)
			if err != nil {
				return err
			}
			if p.Sensitive && an.env.Masking {
				if p.Kind != KindIdentity {
					return refusef("a PII value (%s) may only be tested for NULL as a plain column", piiNames(p))
				}
				if e.Not || !pos {
					return negatedPII(p)
				}
				if isSubquery(e.X) {
					return scalarPII(p)
				}
				return an.constFilter(sc, clause, p, "IS NULL")
			}
			return nil
		}
		if e.What == "DISTINCT" {
			op := "IS DISTINCT FROM"
			if e.Not {
				op = "IS NOT DISTINCT FROM"
			}
			return an.comparison(op, e.X, e.Y, sc, clause, pos)
		}
	case *In:
		return an.inFilter(e, sc, clause, pos)
	case *Between:
		// Checked as a value (a PII operand is refused there); a positive
		// range between constants on a plain column is a key filter.
		p, err := an.value(e, sc, clause)
		if err != nil {
			return err
		}
		if ref, ok := e.X.(*ColumnRef); ok && !e.Not && !p.Sensitive {
			// Resolved again: a plain column, so no side effect repeats.
			x, err := an.value(ref, sc, clause)
			if err != nil {
				return err
			}
			an.keyFilterOf(x, clause, pos, e.Lo, e.Hi)
		}
		return nil
	case *Exists:
		// The subquery is a node of its own: its filters start positive
		// and its k-anonymity checks run on their own.
		_, err := an.query(e.Query, sc)
		return err
	}
	p, err := an.value(e, sc, clause)
	if err != nil {
		return err
	}
	if p.Sensitive && an.env.Masking {
		return refusef("a PII column (%s) may only be compared for equality with a constant or with another PII column in %s", piiNames(p), strings.ToUpper(clause))
	}
	return nil
}

// negatedPII refuses a PII atom outside the positive AND chain of a filter,
// or a negative comparison of a PII column.
func negatedPII(p Prov) error {
	return refusef("a PII column (%s) may only be filtered by positive conditions joined with AND: under NOT, OR or XOR, and with <>, !=, NOT IN, IS NOT NULL or IS DISTINCT FROM, it would select rows the k-anonymity check does not count", piiNames(p))
}

// scalarPII refuses a scalar subquery returning a PII value as a filter
// operand: the k-anonymity check of the enclosing node would count rows
// unrelated to the subject the subquery picks.
func scalarPII(p Prov) error {
	return refusef("a scalar subquery returning a PII column (%s) cannot be compared: filter on the column inside the subquery instead", piiNames(p))
}

// isSubquery reports a scalar subquery, possibly parenthesised.
func isSubquery(e Expr) bool {
	for {
		p, ok := e.(*Paren)
		if !ok {
			break
		}
		e = p.X
	}
	_, ok := e.(*Subquery)
	return ok
}

// constFilter notes a PII column compared with constants in a clause: pred
// is the comparison as it applies to the column ("= 'x'", "IN (1, 2)", "IS
// NULL"), with its token replacements applied. Besides the k-anonymity check
// of the node (kCheck), the subjects of every masked source of the column
// are counted in its own base table: a join cannot multiply them.
func (an *analyzer) constFilter(sc *scope, clause string, col Prov, pred string) error {
	if clause == "join" {
		return refuse("compare PII columns with constants in WHERE, not in a JOIN condition")
	}
	var checks []string
	for _, s := range col.Sources {
		if _, ok := an.env.Rule(s); !ok {
			continue
		}
		if s.View {
			return refusef("a PII column (%s) of a view (or of a relation whose base columns are unknown) cannot be compared with constants: the k-anonymity check could not count its subjects; filter on the base table instead", piiNames(Prov{Sources: []Source{s}}))
		}
		table := an.quoteIdent(s.DB) + "." + an.quoteIdent(s.Table)
		if s.DB == "" {
			table = an.quoteIdent(s.Table)
		}
		checks = append(checks, "SELECT COUNT(*) FROM "+table+" WHERE "+table+"."+an.quoteIdent(s.Column)+" "+pred)
	}
	if len(checks) == 0 {
		return refusef("a PII column (%s) has no base column the k-anonymity check could count", piiNames(col))
	}
	an.a.PIIFilter = an.a.PIIFilter || an.dry == 0
	if sc.node != nil {
		sc.node.needK = true
		sc.node.constFilter = true
	}
	if an.dry > 0 {
		return nil
	}
	for _, c := range checks {
		if !slices.ContainsFunc(an.a.KChecks, func(k KCheck) bool { return k.SQL == c }) {
			an.a.KChecks = append(an.a.KChecks, KCheck{SQL: c})
		}
	}
	return nil
}

// valueLiterals records the placeholders among lits, compared with the PII
// column col, and plans the substitution of those whose value is known.
// human reports that every literal is a placeholder: the agent chose none
// of the values, so the filter needs no k-anonymity check.
func (an *analyzer) valueLiterals(col Prov, lits []Expr, inList bool) (human bool, err error) {
	human = len(lits) > 0
	var target Source
	for _, s := range col.Sources {
		if _, ok := an.env.Rule(s); ok {
			target = s
			break
		}
	}
	for _, e := range lits {
		for {
			p, ok := e.(*Paren)
			if !ok {
				break
			}
			e = p.X
		}
		l, ok := e.(*Literal)
		if !ok || l.Kind != LitString {
			human = false
			continue
		}
		body, ok := unquote(an.d, l.Text)
		if !ok {
			human = false
			continue
		}
		kind, name, isPH, valid := ParsePlaceholder(body)
		if !isPH {
			human = false
			continue
		}
		if !valid {
			return false, refusef("malformed placeholder %q: write '${name}' (a-z, 0-9, _; 32 at most) or '${rN.R.C}'", body)
		}
		if an.dry == 0 {
			an.a.Values = append(an.a.Values, ValueUse{Kind: kind, Name: name, Column: target, InList: inList, Span: l.Sp})
		}
		value, known := an.env.Value(kind, name)
		if !known {
			if kind == ValueRef {
				return false, refusef("unknown reference %s: it is not from this console session, or its result is too old", name)
			}
			continue // the console asks the human before the run
		}
		q, err := quoteLiteral(an.d, value)
		if err != nil {
			if kind == ValueRef {
				// The agent never saw this value: the refusal must not
				// tell it what the value holds.
				return false, refusef("reference %s cannot be substituted", name)
			}
			return false, err
		}
		if an.dry == 0 {
			an.a.Replacements = append(an.a.Replacements, Replacement{Span: l.Sp, Text: q})
		}
	}
	return human, nil
}

// humanFilter is a PII filter whose values all come from placeholders: no
// k-anonymity check, but row estimates stay hidden from the agent.
func (an *analyzer) humanFilter(clause string) error {
	if clause == "join" {
		return refuse("compare PII columns with placeholders in WHERE, not in a JOIN condition")
	}
	an.a.PIIFilter = an.a.PIIFilter || an.dry == 0
	return nil
}

// litFilter notes a PII filter on a literal the agent wrote.
func (an *analyzer) litFilter() {
	an.a.LitFilter = an.a.LitFilter || an.dry == 0
}

// keyFilter records a non-PII column compared with = and a literal in
// WHERE.
func (an *analyzer) keyFilter(op string, l, r Prov, le, re Expr, clause string, pos bool) {
	if op != "=" {
		return
	}
	col := l
	if l.Kind != KindIdentity {
		col = r
		re = le
	}
	an.keyFilterOf(col, clause, pos, re)
}

// keyFilterOf records col as a key filter when the positive WHERE atom
// pins it to constants: = a literal, IN (literals) or BETWEEN two
// constants all narrow it to as few rows as a unique key holds values.
func (an *analyzer) keyFilterOf(col Prov, clause string, pos bool, consts ...Expr) {
	if an.dry > 0 || clause != "where" || !pos || col.Kind != KindIdentity || col.Sensitive || len(consts) == 0 {
		return
	}
	for _, c := range consts {
		if !isConstant(c) {
			return
		}
	}
	for _, s := range col.Sources {
		if !slices.Contains(an.a.KeyFilters, s) {
			an.a.KeyFilters = append(an.a.KeyFilters, s)
		}
	}
}

// strayPlaceholders refuses a placeholder that did not end up compared
// with a PII column: anywhere else its value could come back unmasked.
func (an *analyzer) strayPlaceholders() error {
	lits, err := placeholderLits(an.d, an.st.SQL)
	if err != nil {
		return refuse("the statement could not be checked for placeholders")
	}
	for _, l := range lits {
		if !l.plain {
			// E'...', $$...$$ and the like are never substituted: a
			// placeholder written that way is malformed.
			return refusef("malformed placeholder %s: write '${name}' (a-z, 0-9, _; 32 at most) or '${rN.R.C}' as a plain single-quoted string", l.text)
		}
		if !slices.ContainsFunc(an.a.Values, func(v ValueUse) bool { return v.Span.Pos == l.pos }) {
			return refuse("a placeholder may only be compared with a PII column: col = '${name}' or col IN ('${a}', '${b}')")
		}
	}
	return nil
}

// HasPlaceholder reports whether sql holds a placeholder: a plain string
// literal '${...}', or "${" in any other string form. A statement that
// cannot be lexed is reported as holding one.
func HasPlaceholder(d sqlclass.Dialect, sql string) bool {
	lits, err := placeholderLits(d, sql)
	return err != nil || len(lits) > 0
}

// phLit is a string literal of a statement that is or may be a placeholder.
type phLit struct {
	pos  int
	text string
	// plain is set for a plain single-quoted string whose body has the
	// '${...}' shape; otherwise the literal is another string form that
	// holds "${".
	plain bool
}

// placeholderLits lists the string literals of sql that are placeholders.
func placeholderLits(d sqlclass.Dialect, sql string) ([]phLit, error) {
	toks, err := sqlclass.Lex(d, sql)
	if err != nil {
		return nil, err
	}
	var out []phLit
	for _, t := range toks {
		if t.Kind != sqlclass.TokString {
			continue
		}
		body, ok := unquote(d, t.Text)
		if !ok {
			if strings.Contains(t.Text, "${") {
				out = append(out, phLit{pos: t.Pos, text: t.Text})
			}
			continue
		}
		if _, _, isPH, _ := ParsePlaceholder(body); isPH {
			out = append(out, phLit{pos: t.Pos, text: t.Text, plain: true})
		}
	}
	return out, nil
}

// quoteIdent quotes a catalog name as an identifier of the dialect.
func (an *analyzer) quoteIdent(name string) string {
	q := `"`
	if an.d == sqlclass.MySQL {
		q = "`"
	}
	return q + strings.ReplaceAll(name, q, q+q) + q
}

// frag is the text of sp with the token replacements applied.
func (an *analyzer) frag(sp Span) string {
	return applyReplacements(an.st.SQL, sp, an.a.Replacements)
}

// comparison checks l op r in a filter. A PII column may be compared for
// equality (=, <=>, IS NOT DISTINCT FROM) with a literal, or joined with
// another PII column; never with a value of an unmasked column, which would
// copy the PII value into a column the masks do not cover.
func (an *analyzer) comparison(op string, le, re Expr, sc *scope, clause string, pos bool) error {
	l, err := an.value(le, sc, clause)
	if err != nil {
		return err
	}
	r, err := an.value(re, sc, clause)
	if err != nil {
		return err
	}
	if !an.env.Masking || !l.Sensitive && !r.Sensitive {
		an.keyFilter(op, l, r, le, re, clause, pos)
		return nil
	}
	if l.Sensitive && l.Kind != KindIdentity || r.Sensitive && r.Kind != KindIdentity {
		return refusef("an aggregate or expression of a PII column (%s) cannot be compared", piiNames(mixProv(l, r)))
	}
	if l.Sensitive && isSubquery(le) {
		return scalarPII(l)
	}
	if r.Sensitive && isSubquery(re) {
		return scalarPII(r)
	}
	if !pos || op != "=" && op != "<=>" && op != "IS NOT DISTINCT FROM" {
		return negatedPII(mixProv(l, r))
	}
	col, other, otherExpr := l, r, re
	if !l.Sensitive {
		col, other, otherExpr = r, l, le
	}
	switch other.Kind {
	case KindConst:
		if !isConstant(otherExpr) {
			return refusef("a PII column (%s) may only be compared with a literal", piiNames(col))
		}
		human, err := an.valueLiterals(col, []Expr{otherExpr}, false)
		if err != nil {
			return err
		}
		if human {
			return an.humanFilter(clause)
		}
		an.litFilter()
		return an.constFilter(sc, clause, col, op+" "+an.frag(otherExpr.Span()))
	case KindIdentity:
		if !other.Sensitive {
			return unmaskedPartner(col, other)
		}
		if l.Lit || r.Lit {
			return litPartner(mixProv(l, r))
		}
		return nil
	}
	return refusef("a PII column (%s) may only be compared with a constant or another PII column", piiNames(col))
}

// unmaskedPartner refuses a PII column joined with a column no mask rule
// covers.
func unmaskedPartner(col, other Prov) error {
	return refusef("a PII column (%s) may only be joined with another PII column; %s has no mask rule: add a mask rule for %s or compare with a literal", piiNames(col), piiNames(other), piiNames(other))
}

// litPartner refuses a PII column compared with a value that may be a
// literal of the statement: no k-anonymity check could count its subjects.
func litPartner(p Prov) error {
	return refusef("a PII column (%s) is compared with values that may be literals of the statement (a UNION with a constant, for instance): compare the column with literals directly", piiNames(p))
}

func mixProv(a, b Prov) Prov {
	return Prov{Sources: mergeSources(a.Sources, b.Sources)}
}

// isConstant reports a literal, possibly signed or parenthesised.
func isConstant(e Expr) bool {
	switch e := e.(type) {
	case *Literal:
		return e.Kind != LitNiladic
	case *Paren:
		return isConstant(e.X)
	case *Unary:
		return (e.Op == "-" || e.Op == "+") && isConstant(e.X)
	}
	return false
}

func (an *analyzer) inFilter(e *In, sc *scope, clause string, pos bool) error {
	x, err := an.value(e.X, sc, clause)
	if err != nil {
		return err
	}
	if e.Query != nil {
		cols, err := an.query(e.Query, sc)
		if err != nil {
			return err
		}
		if len(cols) != 1 {
			if !(x.Kind == KindExpr && len(cols) > 1) {
				return refuse("IN (subquery) must return one column")
			}
		}
		if !an.env.Masking {
			return nil
		}
		sub := cols[0].prov
		for _, c := range cols[1:] {
			sub = union(sub, c.prov)
		}
		switch {
		case !x.Sensitive && !sub.Sensitive:
			return nil
		case x.Sensitive && x.Kind != KindIdentity, sub.Sensitive && sub.Kind != KindIdentity:
			return refusef("an aggregate or expression of a PII column (%s) cannot be compared", piiNames(mixProv(x, sub)))
		case e.Not || !pos:
			return negatedPII(mixProv(x, sub))
		case x.Sensitive && isSubquery(e.X):
			return scalarPII(x)
		case sub.Kind == KindConst, sub.Lit, x.Lit:
			// A subquery of constants (or a literal tested against a PII
			// subquery): no check could count the subjects per value.
			return refusef("a PII column (%s) may only be tested against literals written in the IN list, or against another PII column", piiNames(mixProv(x, sub)))
		case sub.Kind == KindIdentity && x.Kind == KindIdentity:
			// A semi-join: both sides must be PII.
			if !x.Sensitive {
				return unmaskedPartner(sub, x)
			}
			if !sub.Sensitive {
				return unmaskedPartner(x, sub)
			}
			return nil
		}
		return refusef("a PII column (%s) may only be compared with constants or another PII column", piiNames(mixProv(x, sub)))
	}
	listProv := Prov{Kind: KindConst}
	for _, it := range e.List {
		p, err := an.value(it, sc, clause)
		if err != nil {
			return err
		}
		listProv = an.mix(listProv, p)
	}
	if !an.env.Masking || !x.Sensitive && !listProv.Sensitive {
		if !e.Not && !listProv.Sensitive {
			an.keyFilterOf(x, clause, pos, e.List...)
		}
		return nil
	}
	if x.Sensitive && x.Kind != KindIdentity || listProv.Sensitive {
		return refusef("a PII column (%s) in IN (...) must be a plain column tested against literals", piiNames(mixProv(x, listProv)))
	}
	if e.Not || !pos {
		return negatedPII(x)
	}
	if isSubquery(e.X) {
		return scalarPII(x)
	}
	var items []string
	for _, it := range e.List {
		if !isConstant(it) {
			return refusef("a PII column (%s) may only be tested against a list of literals", piiNames(x))
		}
	}
	human, err := an.valueLiterals(x, e.List, true)
	if err != nil {
		return err
	}
	if human {
		return an.humanFilter(clause)
	}
	an.litFilter()
	for _, it := range e.List {
		items = append(items, an.frag(it.Span()))
	}
	return an.constFilter(sc, clause, x, "IN ("+strings.Join(items, ", ")+")")
}

// unquote returns the value of a plain single-quoted string literal.
func unquote(d sqlclass.Dialect, text string) (string, bool) {
	if len(text) < 2 || text[0] != '\'' || text[len(text)-1] != '\'' {
		return "", false
	}
	return strings.ReplaceAll(text[1:len(text)-1], "''", "'"), true
}

// StringValue returns the value of a string-literal token ('...', "..." in
// MySQL, E'...', N'...', $tag$...$tag$), or false for any other text. Unlike
// the substitution path it does not refuse backslashes: it serves warnings.
func StringValue(d sqlclass.Dialect, text string) (string, bool) {
	if len(text) >= 2 && text[0] == '$' {
		if i := strings.Index(text[1:], "$"); i >= 0 {
			tag := text[:i+2]
			if len(text) >= 2*len(tag) && strings.HasSuffix(text, tag) {
				return text[len(tag) : len(text)-len(tag)], true
			}
		}
		return "", false
	}
	if len(text) >= 3 && strings.ContainsRune("eEnN", rune(text[0])) && text[1] == '\'' {
		text = text[1:]
	}
	if len(text) < 2 || text[len(text)-1] != text[0] || text[0] != '\'' && !(text[0] == '"' && d == sqlclass.MySQL) {
		return "", false
	}
	q := string(text[0])
	return strings.ReplaceAll(text[1:len(text)-1], q+q, q), true
}

// quoteLiteral quotes a value as a string literal of the dialect. Values
// with a backslash or a NUL are refused: their meaning depends on server
// settings.
func quoteLiteral(d sqlclass.Dialect, v string) (string, error) {
	if strings.ContainsAny(v, "\\\x00") {
		return "", refuse("the value behind this token holds a backslash or a NUL; it cannot be substituted safely")
	}
	return "'" + strings.ReplaceAll(v, "'", "''") + "'", nil
}

// joinEquality checks the equality of a USING or NATURAL join: a PII column
// may only be joined with another PII column, never with values that may be
// literals of the statement.
func (an *analyzer) joinEquality(l, r column) error {
	if !an.env.Masking || !l.prov.Sensitive && !r.prov.Sensitive {
		return nil
	}
	if l.prov.Kind != KindIdentity || r.prov.Kind != KindIdentity {
		return refusef("PII columns (%s) may only be joined as plain columns", piiNames(mixProv(l.prov, r.prov)))
	}
	if !l.prov.Sensitive {
		return unmaskedPartner(r.prov, l.prov)
	}
	if !r.prov.Sensitive {
		return unmaskedPartner(l.prov, r.prov)
	}
	if l.prov.Lit || r.prov.Lit {
		return litPartner(mixProv(l.prov, r.prov))
	}
	return nil
}

// ---- k-anonymity ----

// kCheck plans the row-count query of a SELECT core whose PII filter,
// grouping or aggregate must cover at least k rows. It reuses the
// statement's own FROM, WHERE, GROUP BY and HAVING text. A constant PII
// filter also has its per-column subject counts (constFilter).
func (an *analyzer) kCheck(s *Select, cols []column, sc *scope) error {
	if an.dry > 0 {
		return nil
	}
	if sc.node.outer {
		return refuse("a correlated subquery cannot filter, group or aggregate PII columns (the k-anonymity check could not run on its own)")
	}
	if an.inRecCTE > 0 {
		return refuse("a recursive CTE cannot filter, group or aggregate PII columns")
	}
	if s.FromSp == (Span{}) {
		return refuse("a SELECT without FROM cannot filter, group or aggregate PII columns (the k-anonymity check has no rows to count)")
	}
	var b strings.Builder
	if w := an.withPrefix(); w != "" {
		b.WriteString(w)
		b.WriteString(" ")
	}
	inner := "FROM " + an.frag(s.FromSp)
	if s.Where != nil {
		inner += " WHERE " + an.frag(s.WhereSp)
	}
	if len(s.GroupBy) == 0 {
		b.WriteString("SELECT COUNT(*) " + inner)
		if s.Having != nil {
			b.WriteString(" HAVING " + an.frag(s.HavingSp))
		}
		an.a.KChecks = append(an.a.KChecks, KCheck{SQL: b.String()})
		return nil
	}
	var keys []string
	for _, g := range s.GroupBy {
		k, err := an.groupText(g, s, cols, sc)
		if err != nil {
			return err
		}
		keys = append(keys, k)
	}
	b.WriteString("SELECT MIN(locksql_n) FROM (SELECT COUNT(*) AS locksql_n " + inner + " GROUP BY " + strings.Join(keys, ", "))
	if s.Having != nil {
		b.WriteString(" HAVING " + an.frag(s.HavingSp))
	}
	b.WriteString(") AS locksql_k")
	an.a.KChecks = append(an.a.KChecks, KCheck{SQL: b.String(), Grouped: true})
	return nil
}

// groupText is the source text of a GROUP BY key; a position or an output
// alias is replaced by the select-list expression it names. A name that is
// both an input column of the node and an output alias standing for
// another value is refused: engines disagree on which one they group by,
// and the check must group as the statement does.
func (an *analyzer) groupText(g Expr, s *Select, cols []column, sc *scope) (string, error) {
	item := func(n int) (string, error) {
		k := 0
		for _, it := range s.Items {
			if it.Star {
				return "", refuse("GROUP BY a position after a * is not supported with PII columns")
			}
			if k == n {
				return an.frag(it.Expr.Span()), nil
			}
			k++
		}
		return "", refuse("GROUP BY position is out of range")
	}
	if isPosition(g) {
		return item(atoiSafe(g.(*Literal).Text) - 1)
	}
	if ref, ok := g.(*ColumnRef); ok && len(ref.Parts) == 1 {
		name := ref.Parts[0]
		in, isInput := inputColumn(name, sc)
		star := false
		for i, it := range s.Items {
			if it.Star {
				star = true
				continue
			}
			if it.Alias != name {
				continue
			}
			if !isInput {
				return item(i)
			}
			// Both: the select list maps one to one onto cols when no *
			// precedes.
			if star || !sameValue(cols[i].prov, in) {
				return "", refusef("GROUP BY %s names both an input column and an output alias for another value; rename the alias", strings.ToLower(name))
			}
		}
	}
	return an.frag(g.Span()), nil
}

// inputColumn resolves a single name among the input columns of a node (its
// FROM relations: base tables, derived tables, CTEs and joins), as resolve
// does without output aliases.
func inputColumn(name string, sc *scope) (Prov, bool) {
	var p Prov
	found := false
	for _, r := range sc.rels {
		for _, c := range r.cols {
			if c.name == "" || c.name != name {
				continue
			}
			if found {
				p = union(p, c.prov)
			} else {
				p, found = c.prov, true
			}
		}
	}
	return p, found
}

// sameValue reports whether two provenances denote the same plain value.
func sameValue(a, b Prov) bool {
	if a.Kind != b.Kind || a.Kind != KindIdentity || a.Lit || b.Lit || len(a.Sources) != len(b.Sources) {
		return false
	}
	for _, s := range a.Sources {
		if !slices.Contains(b.Sources, s) {
			return false
		}
	}
	return true
}

// withPrefix is the WITH clause visible to the current node: the CTEs of
// every enclosing WITH, outermost first.
func (an *analyzer) withPrefix() string {
	if len(an.withs) == 0 {
		return ""
	}
	recursive := false
	var parts []string
	for _, w := range an.withs {
		recursive = recursive || w.Recursive
		for _, c := range w.CTEs {
			parts = append(parts, applyReplacements(an.st.SQL, c.Sp, an.a.Replacements))
		}
	}
	head := "WITH "
	if recursive {
		head = "WITH RECURSIVE "
	}
	return head + strings.Join(parts, ", ")
}

// applyReplacements returns sql[sp] with the replacements inside sp
// applied.
func applyReplacements(sql string, sp Span, reps []Replacement) string {
	var b strings.Builder
	pos := sp.Pos
	sorted := slices.Clone(reps)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Span.Pos < sorted[j].Span.Pos })
	for _, r := range sorted {
		if r.Span.Pos < sp.Pos || r.Span.End > sp.End || r.Span.Pos < pos {
			continue
		}
		b.WriteString(sql[pos:r.Span.Pos])
		b.WriteString(r.Text)
		pos = r.Span.End
	}
	b.WriteString(sql[pos:sp.End])
	return b.String()
}

// String describes a Kind.
func (k Kind) String() string {
	switch k {
	case KindConst:
		return "constant"
	case KindCount:
		return "count"
	case KindIdentity:
		return "identity"
	case KindAggregate:
		return "aggregate"
	case KindExpr:
		return "expression"
	}
	return fmt.Sprintf("Kind(%d)", int(k))
}
