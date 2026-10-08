package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/DavidGodefroid/locksql/internal/engine"
)

// explainPrefix is how the console asks for a plan. VERBOSE adds the schema
// of each relation (to look up its size) and qualifies every column in the
// conditions with its table alias (to tell a join condition from a filter).
const explainPrefix = "EXPLAIN (FORMAT JSON, VERBOSE) "

// pgNode is one node of PostgreSQL's EXPLAIN (FORMAT JSON) output, reduced
// to the fields the normalisation reads.
type pgNode struct {
	TotalCost   *float64 `json:"Total Cost"`
	NodeType    string   `json:"Node Type"`
	Parent      string   `json:"Parent Relationship"`
	SubplanName string   `json:"Subplan Name"`
	Relation    string   `json:"Relation Name"`
	Schema      string   `json:"Schema"`
	Alias       string   `json:"Alias"`
	Function    string   `json:"Function Name"`
	CTE         string   `json:"CTE Name"`
	Index       string   `json:"Index Name"`
	PlanRows    float64  `json:"Plan Rows"`
	IndexCond   string   `json:"Index Cond"`
	RecheckCond string   `json:"Recheck Cond"`
	Filter      string   `json:"Filter"`
	JoinFilter  string   `json:"Join Filter"`
	Strategy    string   `json:"Strategy"`
	Plans       []pgNode `json:"Plans"`
}

// Relation is a table, as named in a plan.
type Relation struct {
	Schema, Name string
}

// key is the sizes map key of a relation: "schema.name", or "name" when the
// plan carries no schema (EXPLAIN without VERBOSE).
func (r Relation) key() string {
	if r.Schema == "" {
		return r.Name
	}
	return r.Schema + "." + r.Name
}

func decode(raw []byte) (pgNode, error) {
	var top []struct {
		Plan *pgNode `json:"Plan"`
	}
	if err := json.Unmarshal(raw, &top); err != nil {
		return pgNode{}, fmt.Errorf("explain: not a JSON plan: %w", err)
	}
	if len(top) == 0 || top[0].Plan == nil || top[0].Plan.NodeType == "" {
		return pgNode{}, errors.New("explain: plan has no Plan node")
	}
	return *top[0].Plan, nil
}

// PlanRelations lists, sorted and without duplicates, the relations a plan
// reads with a full table or index scan: the ones whose size ParsePlan
// wants, since PostgreSQL's Plan Rows counts the rows a scan returns, not
// the rows it reads.
func PlanRelations(raw []byte) ([]Relation, error) {
	top, err := decode(raw)
	if err != nil {
		return nil, err
	}
	seen := map[Relation]bool{}
	var walk func(n *pgNode)
	walk = func(n *pgNode) {
		if n.Relation != "" && wholeScan(n) {
			seen[Relation{n.Schema, n.Relation}] = true
		}
		for i := range n.Plans {
			walk(&n.Plans[i])
		}
	}
	walk(&top)
	out := make([]Relation, 0, len(seen))
	for r := range seen {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key() < out[j].key() })
	return out, nil
}

// wholeScan reports a node that reads a whole relation: a sequential scan,
// or an index scan without an index condition.
func wholeScan(n *pgNode) bool {
	switch n.NodeType {
	case "Seq Scan", "Sample Scan":
		return true
	case "Index Scan", "Index Only Scan":
		return n.IndexCond == ""
	}
	return false
}

// ParsePlan normalises the output of EXPLAIN (FORMAT JSON) into an
// engine.Plan whose Raw is the server's plan unchanged. sizes holds the
// row counts of tables ("schema.table") from pg_class.reltuples; a full scan
// of a table found there counts as reading all of it. nil sizes keep
// PostgreSQL's Plan Rows, which, for a filtered scan, is the number of rows
// returned, not read.
//
// Mapping:
//   - Seq Scan → full; Index Scan / Index Only Scan / Bitmap Heap Scan →
//     lookup when the index condition only has equalities, range otherwise,
//     index when there is no index condition; Tid Scan → lookup; function,
//     VALUES, CTE and subquery scans → full; anything else → unknown.
//   - Plan Rows → EstRows (per loop, as PostgreSQL reports it).
//   - Sort / Incremental Sort → Sort; hashed Aggregate or SetOp,
//     Materialize, Memoize, Recursive Union → Temp.
//   - Nested Loop: the inner side joins the outer pipeline (rows multiply).
//     An inner full scan with no Join Filter and no filter on an outer
//     column → NoJoinCond (a cartesian product).
//   - Hash Join / Merge Join: the outer side is the pipeline, the inner side
//     is read once, so it becomes a child group (cost adds).
//   - Append members, subquery scans and InitPlans → child groups; SubPlan →
//     a Correlated child group. A child group under a Nested Loop's inner
//     side runs once per outer row, so it is Correlated too.
func ParsePlan(raw []byte, sizes map[string]int64) (engine.Plan, error) {
	top, err := decode(raw)
	if err != nil {
		return engine.Plan{}, err
	}
	root := engine.PlanNode{Detail: "QUERY", EstRows: -1}
	b := builder{sizes: sizes}
	b.walk(&top, &root, walkCtx{})
	cost := -1.0
	if top.TotalCost != nil {
		cost = *top.TotalCost
	}
	return engine.Plan{Root: root, Cost: cost, Raw: json.RawMessage(bytes.Clone(raw))}, nil
}

type builder struct {
	sizes map[string]int64
}

// walkCtx is what a node inherits from the nodes above it.
type walkCtx struct {
	// loop is set under a Nested Loop's inner side: the subtree runs once
	// per outer row.
	loop bool
	// checkJoin is set under the inner side of a Nested Loop that has no
	// Join Filter: a full scan there that does not filter on one of the
	// outer aliases is a cartesian product.
	checkJoin bool
	outer     []string
}

// walk adds node n to group g and returns the aliases of the tables it
// added to g's pipeline.
func (b *builder) walk(n *pgNode, g *engine.PlanNode, c walkCtx) []string {
	var aliases []string
	var regular, attached []*pgNode
	for i := range n.Plans {
		ch := &n.Plans[i]
		switch ch.Parent {
		case "InitPlan", "SubPlan":
			attached = append(attached, ch)
		default:
			regular = append(regular, ch)
		}
	}

	switch n.NodeType {
	case "Seq Scan", "Sample Scan", "Index Scan", "Index Only Scan", "Bitmap Heap Scan",
		"Tid Scan", "Tid Range Scan", "Foreign Scan", "Custom Scan",
		"Function Scan", "Table Function Scan", "Values Scan", "CTE Scan",
		"WorkTable Scan", "Named Tuplestore Scan":
		t := b.table(n, regular)
		if c.checkJoin && (t.Access == engine.AccessFull || t.Access == engine.AccessIndex) &&
			!refersTo(n.Filter+" "+n.IndexCond+" "+n.RecheckCond, c.outer) {
			t.NoJoinCond = true
		}
		g.Children = append(g.Children, t)
		aliases = append(aliases, n.Alias)
		// Custom and foreign scans may have children of their own; bitmap
		// index scans were folded into the table.
		if n.NodeType == "Foreign Scan" || n.NodeType == "Custom Scan" {
			for _, ch := range regular {
				b.group(ch, g, "member", c.loop)
			}
		}

	case "Subquery Scan":
		t := engine.PlanNode{Table: nonEmpty(n.Alias, "subquery"), Access: engine.AccessFull,
			EstRows: rows(n.PlanRows), Detail: n.NodeType}
		g.Children = append(g.Children, t)
		aliases = append(aliases, n.Alias)
		for _, ch := range regular {
			b.group(ch, g, "subquery "+n.Alias, c.loop)
		}

	case "Nested Loop":
		outer, inner := split(regular)
		if outer != nil {
			aliases = append(aliases, b.walk(outer, g, c)...)
		}
		if inner != nil {
			ic := walkCtx{loop: true, checkJoin: n.JoinFilter == "",
				outer: append(append([]string{}, c.outer...), aliases...)}
			if !ic.checkJoin {
				ic.outer = nil
			}
			aliases = append(aliases, b.walk(inner, g, ic)...)
		}

	case "Hash Join", "Merge Join":
		outer, inner := split(regular)
		if outer != nil {
			aliases = append(aliases, b.walk(outer, g, c)...)
		}
		if inner != nil {
			b.group(inner, g, n.NodeType+" inner", c.loop)
		}

	case "Append", "Merge Append", "Recursive Union", "BitmapAnd", "BitmapOr":
		if n.NodeType == "Recursive Union" {
			g.Temp = true
		}
		for _, ch := range regular {
			b.group(ch, g, n.NodeType+" member", c.loop)
		}

	default:
		switch n.NodeType {
		case "Sort", "Incremental Sort":
			g.Sort = true
		case "Materialize", "Memoize":
			g.Temp = true
		case "Aggregate", "SetOp":
			if n.Strategy == "Hashed" || n.Strategy == "Mixed" {
				g.Temp = true
			}
		}
		// Pass-through nodes (Limit, Unique, Gather, Hash, ModifyTable,
		// Result, WindowAgg, ...): their inputs stay in the pipeline.
		for _, ch := range regular {
			aliases = append(aliases, b.walk(ch, g, c)...)
		}
	}

	for _, ch := range attached {
		name := nonEmpty(ch.SubplanName, ch.Parent)
		sub := engine.PlanNode{EstRows: -1, Detail: name, Correlated: ch.Parent == "SubPlan"}
		b.walk(ch, &sub, walkCtx{})
		g.Children = append(g.Children, sub)
	}
	return aliases
}

// group adds n to g as a child group, read once per execution of g, or once
// per outer row when loop is set.
func (b *builder) group(n *pgNode, g *engine.PlanNode, detail string, loop bool) {
	sub := engine.PlanNode{EstRows: -1, Detail: detail, Correlated: loop}
	b.walk(n, &sub, walkCtx{})
	g.Children = append(g.Children, sub)
}

// split returns the outer and inner children of a join.
func split(children []*pgNode) (outer, inner *pgNode) {
	for _, ch := range children {
		switch {
		case ch.Parent == "Inner" && inner == nil:
			inner = ch
		case outer == nil:
			outer = ch
		case inner == nil:
			inner = ch
		}
	}
	return outer, inner
}

// table builds the table node of a scan. children are its regular
// children: bitmap index scans for a Bitmap Heap Scan.
func (b *builder) table(n *pgNode, children []*pgNode) engine.PlanNode {
	t := engine.PlanNode{EstRows: rows(n.PlanRows), Detail: n.NodeType}
	if n.Index != "" {
		t.Detail += " using " + n.Index
	}
	switch {
	case n.Relation != "":
		t.Table = n.Relation
	case n.Function != "":
		t.Table = n.Function
	case n.CTE != "":
		t.Table = n.CTE
	default:
		t.Table = nonEmpty(n.Alias, strings.ToLower(n.NodeType))
	}
	switch n.NodeType {
	case "Seq Scan", "Sample Scan":
		t.Access = engine.AccessFull
	case "Index Scan", "Index Only Scan":
		t.Access = condAccess(n.IndexCond)
	case "Bitmap Heap Scan":
		cond := n.RecheckCond
		var idxRows int64
		for _, ch := range children {
			idxRows += bitmapRows(ch)
			if cond == "" {
				cond = bitmapCond(ch)
			}
		}
		t.Access = condAccess(cond)
		if t.Access == engine.AccessIndex { // a bitmap scan always has a condition
			t.Access = engine.AccessRange
		}
		t.EstRows = max(t.EstRows, idxRows)
	case "Tid Scan":
		t.Access = engine.AccessLookup
	case "Tid Range Scan":
		t.Access = engine.AccessRange
	case "Function Scan", "Table Function Scan", "Values Scan", "CTE Scan",
		"WorkTable Scan", "Named Tuplestore Scan":
		t.Access = engine.AccessFull
	default:
		t.Access = engine.AccessUnknown
	}
	if n.Relation != "" && wholeScan(n) {
		if size, ok := b.size(Relation{n.Schema, n.Relation}); ok {
			t.EstRows = max(t.EstRows, size)
		}
	}
	return t
}

func (b *builder) size(r Relation) (int64, bool) {
	if v, ok := b.sizes[r.key()]; ok && v >= 0 {
		return v, true
	}
	return 0, false
}

// bitmapRows sums the Plan Rows of the bitmap index scans under a node.
func bitmapRows(n *pgNode) int64 {
	if n.NodeType == "Bitmap Index Scan" {
		return rows(n.PlanRows)
	}
	var sum int64
	for i := range n.Plans {
		sum = satAdd(sum, bitmapRows(&n.Plans[i]))
	}
	return sum
}

// bitmapCond joins the index conditions of the bitmap index scans under a
// node.
func bitmapCond(n *pgNode) string {
	if n.NodeType == "Bitmap Index Scan" {
		return n.IndexCond
	}
	var parts []string
	for i := range n.Plans {
		parts = append(parts, bitmapCond(&n.Plans[i]))
	}
	return strings.Join(parts, " ")
}

func satAdd(a, b int64) int64 {
	if a > math.MaxInt64-b {
		return math.MaxInt64
	}
	return a + b
}

// condAccess classifies an index condition: none → index (full index
// scan), equalities only → lookup, anything else (comparisons, ANY, LIKE,
// operators of other index types) → range. Literals are removed first, so
// that their content does not count.
func condAccess(cond string) string {
	cond = stripLiterals(cond)
	if strings.TrimSpace(cond) == "" {
		return engine.AccessIndex
	}
	if strings.ContainsAny(cond, "<>~@&!|#?^") || strings.Contains(cond, " ANY ") ||
		strings.Contains(cond, " ANY(") || strings.Contains(cond, "LIKE") {
		return engine.AccessRange
	}
	return engine.AccessLookup
}

// stripLiterals removes the '...' string literals of an expression as
// PostgreSQL prints it (” escapes a quote).
func stripLiterals(s string) string {
	var b strings.Builder
	in := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '\'' {
			if in && i+1 < len(s) && s[i+1] == '\'' {
				i++
				continue
			}
			in = !in
			continue
		}
		if !in {
			b.WriteByte(ch)
		}
	}
	return b.String()
}

// refersTo reports whether expr mentions a column of one of the aliases
// ("alias.column", with the alias at an identifier boundary). Literals are
// ignored.
func refersTo(expr string, aliases []string) bool {
	expr = stripLiterals(expr)
	for _, a := range aliases {
		if a == "" {
			continue
		}
		for _, needle := range []string{a + ".", `"` + a + `".`} {
			for i := 0; ; {
				k := strings.Index(expr[i:], needle)
				if k < 0 {
					break
				}
				k += i
				if k == 0 || !isIdentByte(expr[k-1]) {
					return true
				}
				i = k + 1
			}
		}
	}
	return false
}

func isIdentByte(c byte) bool {
	return c == '_' || c == '$' || c == '"' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= 0x80
}

// rows converts a Plan Rows estimate to a row count.
func rows(f float64) int64 {
	switch {
	case math.IsNaN(f) || f < 0:
		return -1
	case f >= math.MaxInt64:
		return math.MaxInt64
	}
	return int64(math.Round(f))
}

func nonEmpty(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// Explain runs EXPLAIN (FORMAT JSON, VERBOSE) inside a READ ONLY
// transaction that is rolled back (EXPLAIN without ANALYZE does not run the
// statement, and PostgreSQL plans writes in a read-only transaction too),
// then reads the size of every fully scanned table from pg_class.
func (s *session) Explain(ctx context.Context, db, q string) (engine.Plan, error) {
	if err := lexSingle(q); err != nil {
		return engine.Plan{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dc, err := s.conn(ctx, db)
	if err != nil {
		return engine.Plan{}, err
	}
	var raw []byte
	var sizes map[string]int64
	_, err = s.inTx(ctx, dc, "BEGIN READ ONLY", false, func(ctx context.Context) (engine.Result, error) {
		res, _, err := s.stream(ctx, dc, explainPrefix+q, 1)
		if err != nil {
			return engine.Result{}, err
		}
		if len(res.Rows) != 1 || len(res.Rows[0]) != 1 {
			return engine.Result{}, localError{errors.New("postgres: EXPLAIN returned no plan")}
		}
		switch v := res.Rows[0][0].(type) {
		case string:
			raw = []byte(v)
		case []byte:
			raw = v
		default:
			return engine.Result{}, localError{errors.New("postgres: EXPLAIN returned no plan")}
		}
		rels, err := PlanRelations(raw)
		if err != nil {
			return engine.Result{}, localError{err}
		}
		sizes, err = relSizes(ctx, dc.conn, rels)
		return engine.Result{}, local(ctx, dc, err)
	})
	if err != nil {
		return engine.Plan{}, err
	}
	return ParsePlan(raw, sizes)
}

// relSizes reads pg_class.reltuples for each relation. A table never
// analysed (reltuples -1, or 0 on an empty-looking PostgreSQL 13 table) is
// left out, so that the plan keeps the planner's own estimate.
func relSizes(ctx context.Context, c *pgx.Conn, rels []Relation) (map[string]int64, error) {
	sizes := map[string]int64{}
	for _, r := range rels {
		if r.Schema == "" {
			continue
		}
		var tuples float64
		var pages int64
		err := c.QueryRow(ctx, `SELECT c.reltuples::float8, c.relpages::int8
			FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname = $1::text AND c.relname = $2::text`, r.Schema, r.Name).Scan(&tuples, &pages)
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if tuples < 0 || tuples == 0 && pages == 0 {
			continue
		}
		sizes[r.key()] = rows(tuples)
	}
	return sizes, nil
}
