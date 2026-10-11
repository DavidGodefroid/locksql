package sqlast

import (
	"errors"
	"go/ast"
	goparser "go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

var allDialects = []sqlclass.Dialect{sqlclass.MySQL, sqlclass.Postgres, sqlclass.SQLite}

// fuzzCatalog is testCatalog plus a table whose PII column names exist in
// no other table: an output that references one of them by name can only
// be that masked column.
var fuzzCatalog = fakeCatalog{
	"app.users":    testCatalog["app.users"],
	"app.orders":   testCatalog["app.orders"],
	"app.contacts": testCatalog["app.contacts"],
	"app.people":   {"pid", "ssn", "phone", "city"},
}

var fuzzRules = map[string]string{
	"app.users.email":    "partial",
	"app.users.salary":   "redact",
	"app.contacts.email": "email",
	"app.people.ssn":     "redact",
	"app.people.phone":   "partial",
}

// uniquePII are the masked column names no unmasked column shares.
var uniquePII = map[string]bool{"SSN": true, "PHONE": true}

func fuzzEnv(masking bool) Env {
	return Env{
		Catalog: fuzzCatalog,
		Rule: func(s Source) (string, bool) {
			m, ok := fuzzRules[s.DB+"."+s.Table+"."+s.Column]
			return m, ok
		},
		Masking: masking,
		Value: func(_ ValueKind, name string) (string, bool) {
			if name == "email" || name == "r1.1.1" {
				return "o'brien@example.com", true
			}
			return "", false
		},
	}
}

// seedStatements are the SQL strings of the sqlclass corpus and of this
// package's tests, read from their sources so the seeds follow them.
func seedStatements(tb testing.TB) []string {
	tb.Helper()
	files := []string{
		"../sqlclass/corpus_test.go",
		"adversarial_test.go",
		"analyze_test.go",
		"parser_test.go",
		"placeholder_test.go",
	}
	seen := map[string]bool{}
	var out []string
	for _, name := range files {
		f, err := goparser.ParseFile(token.NewFileSet(), filepath.FromSlash(name), nil, 0)
		if err != nil {
			tb.Fatalf("seeds: %v", err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			s, err := strconv.Unquote(lit.Value)
			if err != nil || len(s) < 6 || !strings.Contains(s, " ") || seen[s] {
				return true
			}
			seen[s] = true
			out = append(out, s)
			return true
		})
	}
	if len(out) < 200 {
		tb.Fatalf("seeds: only %d statements found", len(out))
	}
	return out
}

func extraSeeds() []string {
	return []string{
		"SELECT ssn, phone, city FROM people LIMIT 1",
		"SELECT p.ssn AS x, u.email FROM people p JOIN users u ON u.id = p.pid LIMIT 1",
		"WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r WHERE n < 3) SELECT n FROM r LIMIT 3",
		"SELECT id FROM users WHERE email = '${email}' LIMIT 5",
		"SELECT id FROM users WHERE email IN ('${r1.1.1}', '${nope}') LIMIT 5",
		"SELECT (((((((((((1))))))))))) LIMIT 1",
		"SELECT \xff\xfe LIMIT 1",
		"SELECT $",
		"SELECT E'",
		"SELECT [",
	}
}

func wantRefusal(t *testing.T, what string, d sqlclass.Dialect, sql string, err error) {
	t.Helper()
	var r *sqlclass.Refusal
	if !errors.As(err, &r) {
		t.Fatalf("%s(%v, %q): error %T (%v) is not *sqlclass.Refusal", what, d, sql, err, err)
	}
}

// FuzzParseNoPanic checks that the parser never panics, that its errors
// are refusals and that every span of an accepted statement lies within
// its text. CI nightly runs it with -fuzz; a plain `go test` runs the
// seed corpus only.
func FuzzParseNoPanic(f *testing.F) {
	for _, s := range seedStatements(f) {
		f.Add(s)
	}
	for _, s := range extraSeeds() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, sql string) {
		for _, d := range allDialects {
			st, err := Parse(d, sql)
			if err != nil {
				wantRefusal(t, "Parse", d, sql, err)
				continue
			}
			if st.Query == nil || st.Dialect != d || !strings.Contains(sql, st.SQL) {
				t.Fatalf("Parse(%v, %q): malformed statement %+v", d, sql, st)
			}
			checkSpans(t, st)
		}
	})
}

// FuzzAnalyzeNoPanic parses and analyses any input, with and without
// masking, and checks the provenance properties of every accepted
// statement (see checkAnalysis).
func FuzzAnalyzeNoPanic(f *testing.F) {
	for _, s := range seedStatements(f) {
		f.Add(s)
	}
	for _, s := range extraSeeds() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, sql string) {
		for _, d := range allDialects {
			st, err := Parse(d, sql)
			if err != nil {
				continue
			}
			for _, masking := range []bool{true, false} {
				env := fuzzEnv(masking)
				a, err := Analyze(st, env)
				if err != nil {
					wantRefusal(t, "Analyze", d, sql, err)
					continue
				}
				checkAnalysis(t, st, env, a, 0)
			}
		}
	})
}

// checkSpans walks the tree and checks that every span is a valid range
// of the statement text: replacements and k-checks slice the text by them.
func checkSpans(t *testing.T, st *Statement) {
	t.Helper()
	check := func(what string, sp Span) {
		if sp.Pos < 0 || sp.End < sp.Pos || sp.End > len(st.SQL) {
			t.Fatalf("%v %q: %s span %+v out of [0, %d]", st.Dialect, st.SQL, what, sp, len(st.SQL))
		}
	}
	walkStatement(st, func(n any) {
		switch n := n.(type) {
		case *Query:
			check("query", n.Sp)
		case *Select:
			check("select", n.Sp)
			check("from", n.FromSp)
			check("where", n.WhereSp)
			check("group by", n.GroupSp)
			check("having", n.HavingSp)
		case *SetOp:
			check("set operation", n.Sp)
		case *With:
			check("with", n.Sp)
		case *CTE:
			check("cte", n.Sp)
		case *SelectItem:
			check("select item", n.Sp)
		case *TableName:
			check("table", n.Sp)
		case *Derived:
			check("derived table", n.Sp)
		case *Join:
			check("join", n.Sp)
		case Expr:
			check("expression", n.Span())
		}
	})
}

// checkAnalysis checks the properties every accepted statement must have:
//   - an output that is the value of a column (identity) names at least
//     one source; an expression or aggregate may have none when it only
//     involves constants (EXISTS (SELECT 1), sum(1)): a stricter kind than
//     needed, never a looser one;
//   - an output is sensitive only with a masked source, and with masking
//     on exactly the sensitive outputs are masked; the value of a masked
//     column (identity) is sensitive. An aggregate or expression may name a
//     masked source it only counts (n + 1 over COUNT(email)), so it is
//     left to the wraps and the oracle below;
//   - a plain reference to a column that only a masked column can be is
//     never returned unmasked;
//   - the statement with its replacements applied can be built.
//
// With masking on, it also wraps the statement in a subquery and in a CTE:
// each wrap is refused or keeps the provenance (see compareAnalyses).
// depth is 1 for a statement that is already a rewrite: it is not wrapped.
func checkAnalysis(t *testing.T, st *Statement, env Env, a *Analysis, depth int) {
	t.Helper()
	_ = a.RunSQL(st.SQL)
	where := func() string {
		return st.Dialect.String() + " masking=" + strconv.FormatBool(env.Masking) + " " + strconv.Quote(st.SQL)
	}
	if st.Explain && len(a.Outputs) > 0 {
		t.Fatalf("%s: EXPLAIN has outputs", where())
	}
	for i, o := range a.Outputs {
		p := o.Prov
		if p.Kind == KindIdentity && len(p.Sources) == 0 {
			t.Fatalf("%s: output %d (%s) is a column value without a source", where(), i, o.Label)
		}
		masked := false
		for _, s := range p.Sources {
			if _, ok := env.Rule(s); ok {
				masked = true
			}
		}
		if p.Kind == KindIdentity && masked && !p.Sensitive {
			t.Fatalf("%s: output %d (%s) is the value of a masked source but is not sensitive: %+v", where(), i, o.Label, p)
		}
		if p.Sensitive && !masked {
			t.Fatalf("%s: output %d (%s) is sensitive without a masked source: %+v", where(), i, o.Label, p)
		}
		switch {
		case !env.Masking && o.Mask != "":
			t.Fatalf("%s: output %d (%s) masked %q without masking", where(), i, o.Label, o.Mask)
		case env.Masking && p.Sensitive && o.Mask == "":
			t.Fatalf("%s: sensitive output %d (%s) is not masked: %+v", where(), i, o.Label, p)
		case env.Masking && !p.Sensitive && o.Mask != "":
			t.Fatalf("%s: output %d (%s) masked %q but not sensitive", where(), i, o.Label, o.Mask)
		}
	}
	if !env.Masking || st.Explain {
		return
	}
	if depth == 0 {
		for _, wrap := range []string{
			"SELECT * FROM (" + st.SQL + ") AS locksql_s",
			"WITH locksql_w AS (" + st.SQL + ") SELECT * FROM locksql_w",
		} {
			wst, wa, err := analyzeSQL(st.Dialect, wrap, env)
			if err != nil {
				continue
			}
			checkAnalysis(t, wst, env, wa, depth+1)
			compareAnalyses(t, where()+" wrapped as "+strconv.Quote(wrap), a, wa, true)
		}
	}
	// The independent oracle: a top-level SELECT over base tables only,
	// whose item is a bare reference to a name only masked columns have.
	sel, ok := st.Query.Body.(*Select)
	if !ok || st.Query.With != nil || !baseTablesOnly(sel.From) {
		return
	}
	n := 0
	for _, it := range sel.Items {
		if it.Star {
			n = -1 // star expansions are not followed here
			break
		}
		e := it.Expr
		for {
			p, ok := e.(*Paren)
			if !ok {
				break
			}
			e = p.X
		}
		if ref, ok := e.(*ColumnRef); ok && uniquePII[ref.Parts[len(ref.Parts)-1]] {
			if n >= len(a.Outputs) || a.Outputs[n].Mask == "" {
				t.Fatalf("%s: item %d is a masked column returned unmasked: %+v", where(), n, a.Outputs)
			}
		}
		n++
	}
	if n >= 0 && n != len(a.Outputs) {
		t.Fatalf("%s: %d items, %d outputs", where(), n, len(a.Outputs))
	}
}

func baseTablesOnly(from []TableExpr) bool {
	for _, te := range from {
		switch te := te.(type) {
		case *TableName:
		case *Join:
			if !baseTablesOnly([]TableExpr{te.Left, te.Right}) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// walkStatement calls fn on every node of st, depth first.
func walkStatement(st *Statement, fn func(any)) {
	var query func(*Query)
	var body func(Body)
	var table func(TableExpr)
	var expr func(Expr)
	order := func(items []*OrderItem) {
		for _, o := range items {
			expr(o.Expr)
		}
	}
	query = func(q *Query) {
		if q == nil {
			return
		}
		fn(q)
		if q.With != nil {
			fn(q.With)
			for _, c := range q.With.CTEs {
				fn(c)
				query(c.Query)
			}
		}
		body(q.Body)
		order(q.OrderBy)
	}
	body = func(b Body) {
		switch b := b.(type) {
		case *Select:
			fn(b)
			for _, e := range b.DistinctOn {
				expr(e)
			}
			for _, it := range b.Items {
				fn(it)
				expr(it.Expr)
			}
			for _, te := range b.From {
				table(te)
			}
			expr(b.Where)
			for _, e := range b.GroupBy {
				expr(e)
			}
			expr(b.Having)
		case *SetOp:
			fn(b)
			body(b.Left)
			body(b.Right)
		case *Query:
			query(b)
		}
	}
	table = func(te TableExpr) {
		switch te := te.(type) {
		case *TableName:
			fn(te)
		case *Derived:
			fn(te)
			query(te.Query)
		case *Join:
			fn(te)
			table(te.Left)
			table(te.Right)
			expr(te.On)
		}
	}
	expr = func(e Expr) {
		if e == nil {
			return
		}
		fn(e)
		switch e := e.(type) {
		case *FuncCall:
			for _, a := range e.Args {
				expr(a)
			}
			order(e.OrderBy)
			if e.Separator != nil {
				expr(e.Separator)
			}
			expr(e.Filter)
			if e.Over != nil {
				for _, x := range e.Over.PartitionBy {
					expr(x)
				}
				order(e.Over.OrderBy)
			}
		case *Binary:
			expr(e.L)
			expr(e.R)
		case *Unary:
			expr(e.X)
		case *Case:
			expr(e.Operand)
			for _, w := range e.Whens {
				expr(w.Cond)
				expr(w.Result)
			}
			expr(e.Else)
		case *Cast:
			expr(e.X)
		case *In:
			expr(e.X)
			for _, x := range e.List {
				expr(x)
			}
			query(e.Query)
		case *Exists:
			query(e.Query)
		case *Subquery:
			query(e.Query)
		case *Between:
			expr(e.X)
			expr(e.Lo)
			expr(e.Hi)
		case *Like:
			expr(e.X)
			expr(e.Pattern)
			expr(e.Escape)
		case *IsTest:
			expr(e.X)
			expr(e.Y)
		case *Tuple:
			for _, x := range e.Items {
				expr(x)
			}
		case *Paren:
			expr(e.X)
		case *Collate:
			expr(e.X)
		}
	}
	query(st.Query)
}
