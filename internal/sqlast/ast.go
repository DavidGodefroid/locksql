// Package sqlast parses the read statements an agent may run (SELECT,
// WITH ... SELECT and EXPLAIN SELECT) into a syntax tree, per dialect, and
// analyses it: it resolves every column to the base columns it comes from
// (through aliases, functions, expressions, subqueries, CTEs, set operations
// and joins), checks functions against an allowlist and decides how PII
// columns may be used.
//
// The grammar is a deliberately small subset of SQL. Anything outside it is
// refused: a statement the parser cannot read with certainty never runs.
package sqlast

import "github.com/DavidGodefroid/locksql/internal/sqlclass"

// Span is a byte range [Pos, End) of the statement text.
type Span struct{ Pos, End int }

// Statement is one parsed read statement.
type Statement struct {
	// Explain is set for EXPLAIN SELECT: the console runs the EXPLAIN
	// itself, without ANALYZE.
	Explain bool
	Query   *Query
	// SQL is the statement text the spans refer to.
	SQL     string
	Dialect sqlclass.Dialect
}

// Query is a full query expression: an optional WITH, a body and the
// ORDER BY and LIMIT that apply to the whole body.
type Query struct {
	With    *With
	Body    Body
	OrderBy []*OrderItem
	Limit   *Limit
	Sp      Span
}

// Body is a *Select, a *SetOp or a parenthesised *Query.
type Body interface{ bodyNode() }

func (*Select) bodyNode() {}
func (*SetOp) bodyNode()  {}
func (*Query) bodyNode()  {}

// With is a WITH clause.
type With struct {
	Recursive bool
	CTEs      []*CTE
	Sp        Span
}

// CTE is one common table expression.
type CTE struct {
	Name    string
	Columns []string
	Query   *Query
	Sp      Span
}

// SetOp is UNION, INTERSECT or EXCEPT.
type SetOp struct {
	Op          string
	All         bool
	Left, Right Body
	Sp          Span
}

// Select is one SELECT core.
type Select struct {
	Distinct   bool
	DistinctOn []Expr
	Items      []*SelectItem
	From       []TableExpr
	Where      Expr
	GroupBy    []Expr
	Having     Expr
	Sp         Span
	// Spans of the FROM list, the WHERE condition, the GROUP BY list and
	// the HAVING condition (without their keywords); zero when absent.
	FromSp, WhereSp, GroupSp, HavingSp Span
}

// SelectItem is one select-list entry: an expression with an optional
// alias, or a star (optionally qualified: t.*).
type SelectItem struct {
	Star      bool
	Qualifier []string
	Expr      Expr
	Alias     string
	Sp        Span
}

// OrderItem is one ORDER BY entry.
type OrderItem struct {
	Expr Expr
	Desc bool
}

// Limit is a LIMIT/OFFSET or FETCH FIRST clause; both are literal integers.
type Limit struct {
	Count, Offset int64
}

// TableExpr is a *TableName, a *Derived or a *Join.
type TableExpr interface{ tableNode() }

func (*TableName) tableNode() {}
func (*Derived) tableNode()   {}
func (*Join) tableNode()      {}

// TableName is a named relation: a table, a view or a CTE.
type TableName struct {
	// Parts are the folded name parts: [table], [db, table] or
	// [catalog, schema, table].
	Parts      []string
	Alias      string
	ColAliases []string
	Sp         Span
}

// Derived is a subquery in FROM.
type Derived struct {
	Lateral    bool
	Query      *Query
	Alias      string
	ColAliases []string
	Sp         Span
}

// Join joins two table expressions.
type Join struct {
	Kind        string // INNER, LEFT, RIGHT, FULL, CROSS
	Natural     bool
	Left, Right TableExpr
	On          Expr
	Using       []string
	Sp          Span
}

// Expr is an expression node.
type Expr interface{ Span() Span }

// ColumnRef names a column: [col], [rel, col] or [db, rel, col] (folded).
type ColumnRef struct {
	Parts []string
	Sp    Span
}

// LitKind is the kind of a literal.
type LitKind int

// Literal kinds.
const (
	LitString LitKind = iota
	LitNumber
	LitNull
	LitBool
	LitTyped    // DATE '...', TIMESTAMP '...', X'..'
	LitInterval // INTERVAL '1 day', INTERVAL 1 DAY
	LitNiladic  // CURRENT_DATE, CURRENT_TIMESTAMP, ...
)

// Literal is a constant.
type Literal struct {
	Kind LitKind
	// Text is the source text of the literal (with its quotes).
	Text string
	Sp   Span
}

// FuncCall is a function call, aggregate or window function.
type FuncCall struct {
	// Name is the folded, dot-joined function name.
	Name     string
	Args     []Expr
	Star     bool // COUNT(*)
	Distinct bool
	// OrderBy is an ordered-set argument: string_agg(x, ',' ORDER BY y),
	// GROUP_CONCAT(x ORDER BY y).
	OrderBy []*OrderItem
	// Separator is the SEPARATOR string of a MySQL GROUP_CONCAT.
	Separator *Literal
	Filter    Expr
	Over      *Window
	Sp        Span
}

// Window is an OVER clause.
type Window struct {
	PartitionBy []Expr
	OrderBy     []*OrderItem
}

// Binary is a binary operator.
type Binary struct {
	Op   string
	L, R Expr
	Sp   Span
}

// Unary is a prefix operator (NOT, -, +, ~).
type Unary struct {
	Op string
	X  Expr
	Sp Span
}

// When is one WHEN ... THEN ... branch.
type When struct{ Cond, Result Expr }

// Case is a CASE expression.
type Case struct {
	Operand Expr
	Whens   []When
	Else    Expr
	Sp      Span
}

// Cast is CAST(x AS type), x::type or CONVERT(x, type).
type Cast struct {
	X    Expr
	Type string
	Sp   Span
}

// In is x [NOT] IN (list) or x [NOT] IN (subquery).
type In struct {
	X     Expr
	List  []Expr
	Query *Query
	Not   bool
	Sp    Span
}

// Exists is [NOT] EXISTS (subquery).
type Exists struct {
	Query *Query
	Not   bool
	Sp    Span
}

// Subquery is a scalar subquery.
type Subquery struct {
	Query *Query
	Sp    Span
}

// Between is x [NOT] BETWEEN lo AND hi.
type Between struct {
	X, Lo, Hi Expr
	Not       bool
	Sp        Span
}

// Like is a pattern match: LIKE, ILIKE, GLOB, REGEXP, RLIKE.
type Like struct {
	Op         string
	X, Pattern Expr
	Escape     Expr
	Not        bool
	Sp         Span
}

// IsTest is x IS [NOT] NULL|TRUE|FALSE|UNKNOWN or IS [NOT] DISTINCT FROM y.
type IsTest struct {
	X    Expr
	Not  bool
	What string // NULL, TRUE, FALSE, UNKNOWN, DISTINCT
	Y    Expr   // DISTINCT FROM y
	Sp   Span
}

// Tuple is a parenthesised list of two or more expressions.
type Tuple struct {
	Items []Expr
	Sp    Span
}

// Paren is a parenthesised expression.
type Paren struct {
	X  Expr
	Sp Span
}

// Collate is x COLLATE name.
type Collate struct {
	X    Expr
	Name string
	Sp   Span
}

func (e *ColumnRef) Span() Span { return e.Sp }
func (e *Literal) Span() Span   { return e.Sp }
func (e *FuncCall) Span() Span  { return e.Sp }
func (e *Binary) Span() Span    { return e.Sp }
func (e *Unary) Span() Span     { return e.Sp }
func (e *Case) Span() Span      { return e.Sp }
func (e *Cast) Span() Span      { return e.Sp }
func (e *In) Span() Span        { return e.Sp }
func (e *Exists) Span() Span    { return e.Sp }
func (e *Subquery) Span() Span  { return e.Sp }
func (e *Between) Span() Span   { return e.Sp }
func (e *Like) Span() Span      { return e.Sp }
func (e *IsTest) Span() Span    { return e.Sp }
func (e *Tuple) Span() Span     { return e.Sp }
func (e *Paren) Span() Span     { return e.Sp }
func (e *Collate) Span() Span   { return e.Sp }
