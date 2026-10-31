package sqlast

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

// Metamorphic tests: rewrites that keep the meaning of a statement must
// keep the provenance of its outputs. A rewrite may be refused (the
// grammar or the rules may not follow it), but it must never be accepted
// with a different or cleaner provenance, and a refused statement must
// stay refused once rewritten.

// metaBases are written without ORDER BY or LIMIT: every variant gets
// LIMIT 5 at the end.
var metaBases = []string{
	"SELECT id, email FROM users",
	"SELECT email AS e, name FROM users WHERE id = 3",
	"SELECT u.email, o.total FROM users u JOIN orders o ON o.user_id = u.id",
	"SELECT u.name, c.email FROM users u, contacts c WHERE c.id = u.id",
	"SELECT o.id, u.email, u.salary FROM orders o INNER JOIN users u ON u.id = o.user_id WHERE o.total > 10",
	"SELECT * FROM users",
	"SELECT * FROM users JOIN contacts USING (email)",
	"SELECT * FROM users u NATURAL JOIN contacts c",
	"SELECT u.id, p.ssn FROM users u CROSS JOIN people p",
	"SELECT u.email, c.email AS ce FROM users u JOIN contacts c ON c.email = u.email",
	"SELECT u.id, o.email FROM users u LEFT JOIN orders o ON o.user_id = u.id",
	"SELECT count(*) AS n, max(salary) AS m FROM users",
	"SELECT status, count(email) AS n FROM users GROUP BY status",
	"SELECT sum(salary) AS s, avg(salary) FROM users",
	"SELECT name FROM users UNION SELECT email FROM contacts",
	"SELECT email FROM users UNION ALL SELECT 'x'",
	"SELECT x FROM (SELECT email AS x FROM users) s",
	"WITH c(z) AS (SELECT email FROM users) SELECT z FROM c",
	"SELECT (SELECT max(email) FROM users) AS m",
	"SELECT 1 AS one, 'a' AS s",
	"SELECT id + 1, upper(name) FROM users",
	"SELECT id FROM users WHERE email = 'a@b.c'",
	"SELECT phone, city FROM people WHERE city = 'x'",
	"SELECT DISTINCT city, ssn FROM people",
	"SELECT p.phone, u.email FROM people p JOIN users u ON u.id = p.pid JOIN contacts c ON c.id = u.id",
	// Refused bases.
	"SELECT lower(email) FROM users",
	"SELECT id FROM users WHERE email LIKE 'a%'",
	"SELECT o.total FROM orders o JOIN users u ON u.email = o.email",
	"SELECT id FROM users WHERE email <> 'x'",
	"SELECT length(x) FROM (SELECT email AS x FROM users) s",
	"SELECT c.id FROM contacts c JOIN users u ON u.email <> c.email",
	"SELECT u.id FROM users u JOIN orders o ON u.salary = o.total",
	"SELECT id FROM users GROUP BY id, lower(email)",
	"SELECT row_number() OVER (ORDER BY email) AS r FROM users",
	"SELECT nope FROM users",
	"SELECT id FROM nope",
}

// metaDialectBases add each dialect's own quoting and syntax.
var metaDialectBases = map[sqlclass.Dialect][]string{
	sqlclass.MySQL: {
		"SELECT `u`.`email`, IFNULL(o.total, 0) AS t FROM `users` u JOIN orders o ON o.user_id = u.id",
		"SELECT u.id, c.email FROM users AS u INNER JOIN contacts AS c USING (id)",
		"SELECT GROUP_CONCAT(name ORDER BY id SEPARATOR ',') AS g FROM users",
		"SELECT email FROM users WHERE email = 'a' XOR id = 1",
	},
	sqlclass.Postgres: {
		`SELECT "u"."email", o.total::text AS t FROM "users" u JOIN orders o ON o.user_id = u.id`,
		"SELECT DISTINCT ON (status) status, email FROM users",
		"SELECT string_agg(name, ',' ORDER BY id) AS g FROM users",
		"SELECT id FROM users WHERE email ILIKE 'a%'",
	},
	sqlclass.SQLite: {
		`SELECT "u"."email", name || 'x' AS n FROM "users" u JOIN orders o ON o.user_id = u.id`,
		"SELECT [email], `name` FROM users",
		"SELECT group_concat(name, ',') AS g FROM users",
		"SELECT id FROM users WHERE email GLOB 'a*'",
	},
}

type rewrite struct {
	name string
	// apply returns the rewritten statement, "" when it does not apply.
	apply func(st *Statement) string
	// ordered is false when the rewrite may reorder the outputs.
	ordered bool
}

var rewrites = []rewrite{
	{"alias", aliasItems, true},
	{"cte", func(st *Statement) string { return "WITH locksql_w AS (" + st.SQL + ") SELECT * FROM locksql_w" }, true},
	{"subquery", func(st *Statement) string { return "SELECT * FROM (" + st.SQL + ") AS locksql_s" }, true},
	{"swap-join", swapJoin, false},
	{"union-all", func(st *Statement) string { return st.SQL + " UNION ALL " + st.SQL }, true},
}

// leftmostSelect is the SELECT core that names the outputs of q.
func leftmostSelect(b Body) *Select {
	for {
		switch x := b.(type) {
		case *Select:
			return x
		case *SetOp:
			b = x.Left
		case *Query:
			b = x.Body
		default:
			return nil
		}
	}
}

// aliasItems gives every unaliased item of the naming SELECT an alias.
func aliasItems(st *Statement) string {
	sel := leftmostSelect(st.Query.Body)
	if sel == nil {
		return ""
	}
	var b strings.Builder
	last := 0
	for i, it := range sel.Items {
		if it.Star || it.Alias != "" {
			continue
		}
		b.WriteString(st.SQL[last:it.Sp.End])
		fmt.Fprintf(&b, " AS locksql_a%d", i)
		last = it.Sp.End
	}
	if last == 0 {
		return ""
	}
	return b.String() + st.SQL[last:]
}

func tableSpan(te TableExpr) Span {
	switch te := te.(type) {
	case *TableName:
		return te.Sp
	case *Derived:
		return te.Sp
	case *Join:
		return te.Sp
	}
	return Span{}
}

// swapJoin swaps the first two FROM items of the naming SELECT, or the two
// sides of its first inner or cross join.
func swapJoin(st *Statement) string {
	sel := leftmostSelect(st.Query.Body)
	if sel == nil || len(sel.From) == 0 {
		return ""
	}
	var l, r TableExpr
	switch j, ok := sel.From[0].(*Join); {
	case len(sel.From) >= 2:
		l, r = sel.From[0], sel.From[1]
	case ok && (j.Kind == "INNER" || j.Kind == "CROSS"):
		l, r = j.Left, j.Right
	default:
		return ""
	}
	s := st.SQL
	ls, rs := tableSpan(l), tableSpan(r)
	// A nested join moved to the right needs parentheses to keep its ON.
	text := func(te TableExpr, sp Span) string {
		if _, ok := te.(*Join); ok {
			return "(" + s[sp.Pos:sp.End] + ")"
		}
		return s[sp.Pos:sp.End]
	}
	return s[:ls.Pos] + text(r, rs) + s[ls.End:rs.Pos] + text(l, ls) + s[rs.End:]
}

// provKey is the comparable part of an output's provenance. Lit is left
// out: a rewrite may set it (a stricter value), see compareAnalyses.
func provKey(o Output) string {
	var src []string
	for _, s := range o.Prov.Sources {
		src = append(src, fmt.Sprintf("%s/%v", s, s.View))
	}
	slices.Sort(src)
	modes := slices.Compact(slices.Sorted(slices.Values(o.Prov.Modes)))
	return fmt.Sprintf("src=%v kind=%v sensitive=%v modes=%v mask=%q",
		slices.Compact(src), o.Prov.Kind, o.Prov.Sensitive, modes, o.Mask)
}

func analyzeSQL(d sqlclass.Dialect, sql string, env Env) (*Statement, *Analysis, error) {
	st, err := Parse(d, sql)
	if err != nil {
		return nil, nil, err
	}
	a, err := Analyze(st, env)
	return st, a, err
}

func TestMetamorphicProvenance(t *testing.T) {
	for _, d := range allDialects {
		for _, masking := range []bool{true, false} {
			env := fuzzEnv(masking)
			accepted := map[string]int{}
			applied := map[string]int{}
			for _, base := range slices.Concat(metaBases, metaDialectBases[d]) {
				st, err := Parse(d, base)
				if err != nil {
					t.Errorf("%s: base %q does not parse: %v", d, base, err)
					continue
				}
				_, ba, berr := analyzeSQL(d, base+" LIMIT 5", env)
				for _, rw := range rewrites {
					sql := rw.apply(st)
					if sql == "" {
						continue
					}
					sql += " LIMIT 5"
					name := fmt.Sprintf("%s masking=%v %s %q", d, masking, rw.name, sql)
					rst, ra, rerr := analyzeSQL(d, sql, env)
					switch {
					case berr != nil && rerr == nil:
						t.Errorf("%s: accepted, but the base is refused: %v", name, berr)
						continue
					case berr != nil:
						continue
					case rerr != nil:
						applied[rw.name]++
						t.Logf("%s: refused: %v", name, rerr)
						continue
					}
					applied[rw.name]++
					accepted[rw.name]++
					checkAnalysis(t, rst, env, ra, 1)
					compareAnalyses(t, name, ba, ra, rw.ordered)
				}
			}
			for _, rw := range rewrites {
				if accepted[rw.name] == 0 || accepted[rw.name]*4 < applied[rw.name]*3 {
					t.Errorf("%s masking=%v %s: %d of %d rewrites accepted, want at least 3/4",
						d, masking, rw.name, accepted[rw.name], applied[rw.name])
				}
			}
		}
	}
}

// compareAnalyses checks that ra has the provenance of ba, and that it
// keeps every check and flag of ba.
func compareAnalyses(t *testing.T, name string, ba, ra *Analysis, ordered bool) {
	t.Helper()
	var bk, rk []string
	for _, o := range ba.Outputs {
		bk = append(bk, provKey(o))
	}
	for _, o := range ra.Outputs {
		rk = append(rk, provKey(o))
	}
	if !ordered {
		slices.Sort(bk)
		slices.Sort(rk)
	}
	if !slices.Equal(bk, rk) {
		t.Errorf("%s: provenance changed\n base:    %v\n rewrite: %v", name, bk, rk)
	}
	// A value that may be a literal of the statement must stay one (a
	// UNION ALL may make a constant column one).
	if ordered && len(ba.Outputs) == len(ra.Outputs) {
		for i := range ba.Outputs {
			if ba.Outputs[i].Prov.Lit && !ra.Outputs[i].Prov.Lit {
				t.Errorf("%s: output %d lost Lit", name, i)
			}
		}
	}
	if !slices.Equal(ba.Relations, ra.Relations) {
		t.Errorf("%s: relations %v, base %v", name, ra.Relations, ba.Relations)
	}
	if len(ba.KChecks) > 0 && len(ra.KChecks) == 0 {
		t.Errorf("%s: k-checks dropped, base %+v", name, ba.KChecks)
	}
	if ba.PIIFilter && !ra.PIIFilter {
		t.Errorf("%s: PIIFilter %v, base %v", name, ra.PIIFilter, ba.PIIFilter)
	}
}

func TestMetamorphicRewrites(t *testing.T) {
	cases := []struct{ rw, sql, want string }{
		{"alias", "SELECT id, email AS e, * FROM users", "SELECT id AS locksql_a0, email AS e, * FROM users"},
		{"alias", "SELECT a FROM t UNION SELECT b FROM u", "SELECT a AS locksql_a0 FROM t UNION SELECT b FROM u"},
		{"alias", "SELECT * FROM users", ""},
		{"swap-join", "SELECT 1 FROM a, b WHERE a.x = b.x", "SELECT 1 FROM b, a WHERE a.x = b.x"},
		{"swap-join", "SELECT 1 FROM a x JOIN b y ON x.i = y.i", "SELECT 1 FROM b y JOIN a x ON x.i = y.i"},
		{"swap-join", "SELECT 1 FROM a JOIN b ON a.i = b.i JOIN c ON c.i = b.i", "SELECT 1 FROM c JOIN (a JOIN b ON a.i = b.i) ON c.i = b.i"},
		{"swap-join", "SELECT 1 FROM a LEFT JOIN b ON a.i = b.i", ""},
		{"swap-join", "SELECT 1 FROM a", ""},
	}
	for _, c := range cases {
		st, err := Parse(sqlclass.Postgres, c.sql)
		if err != nil {
			t.Fatalf("%q: %v", c.sql, err)
		}
		i := slices.IndexFunc(rewrites, func(r rewrite) bool { return r.name == c.rw })
		if got := rewrites[i].apply(st); got != c.want {
			t.Errorf("%s %q = %q, want %q", c.rw, c.sql, got, c.want)
		}
	}
}
