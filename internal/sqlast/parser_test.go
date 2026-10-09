package sqlast

import (
	"errors"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

var (
	my = sqlclass.MySQL
	pg = sqlclass.Postgres
	sl = sqlclass.SQLite
)

func TestParseAccepts(t *testing.T) {
	all := []sqlclass.Dialect{my, pg, sl}
	cases := []struct {
		ds  []sqlclass.Dialect
		sql string
	}{
		{all, "SELECT 1"},
		{all, "select a, b as c, d e from t where a = 1 and (b > 2 or c is null) limit 10"},
		{all, "SELECT t.* FROM t LIMIT 5"},
		{all, "SELECT * FROM a JOIN b ON a.id = b.aid LEFT JOIN c USING (id) LIMIT 1"},
		{all, "SELECT count(*), count(distinct x), max(y) FROM t GROUP BY z HAVING count(*) > 5 ORDER BY 1 DESC LIMIT 3"},
		{all, "WITH x AS (SELECT a FROM t), y(b) AS (SELECT a FROM x) SELECT b FROM y LIMIT 1"},
		{all, "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r WHERE n < 5) SELECT n FROM r LIMIT 10"},
		{all, "SELECT a FROM t UNION SELECT b FROM u EXCEPT SELECT c FROM v LIMIT 2"},
		{all, "(SELECT a FROM t LIMIT 1) UNION ALL (SELECT b FROM u LIMIT 1) LIMIT 2"},
		{all, "SELECT (SELECT max(a) FROM t) AS m FROM u WHERE EXISTS (SELECT 1 FROM v WHERE v.x = u.x) LIMIT 1"},
		{all, "SELECT a FROM t WHERE a IN (1, 2, 3) AND b NOT IN (SELECT b FROM u) AND c BETWEEN 1 AND 5 LIMIT 1"},
		{all, "SELECT CASE WHEN a > 1 THEN 'x' ELSE 'y' END, CASE a WHEN 1 THEN 2 END FROM t LIMIT 1"},
		{all, "SELECT CAST(a AS INTEGER), COALESCE(b, 0), lower(c) FROM t WHERE d LIKE 'x%' LIMIT 1"},
		{all, "SELECT a FROM (SELECT a FROM t) AS s LIMIT 1"},
		{all, "SELECT a FROM ((SELECT a FROM t) UNION (SELECT a FROM u)) AS s LIMIT 1"},
		{all, "SELECT x.a FROM (t AS x JOIN u ON x.id = u.id) LIMIT 1"},
		{all, "SELECT row_number() OVER (PARTITION BY a ORDER BY b ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) FROM t LIMIT 1"},
		{all, "SELECT a FROM t WHERE b IS NOT NULL ORDER BY a ASC LIMIT 5 OFFSET 10"},
		{all, "EXPLAIN SELECT a FROM t"},
		{all, "SELECT -a, +b, ~c, a * b / c % d, a << 1 FROM t LIMIT 1"},
		{all, "SELECT CURRENT_DATE, CURRENT_TIMESTAMP FROM t LIMIT 1"},
		{[]sqlclass.Dialect{my, sl}, "SELECT a FROM t LIMIT 10, 5"},
		{[]sqlclass.Dialect{my}, "SELECT a DIV 2, a MOD 2, IF(a, 1, 2), `b` FROM `db`.`t` LIMIT 1"},
		{[]sqlclass.Dialect{my}, "SELECT DATE_ADD(d, INTERVAL 1 DAY), d + INTERVAL 2 MONTH FROM t LIMIT 1"},
		{[]sqlclass.Dialect{my}, "SELECT GROUP_CONCAT(DISTINCT a ORDER BY a SEPARATOR ',') FROM t LIMIT 1"},
		{[]sqlclass.Dialect{my}, "SELECT a <=> b, j->>'$.x' FROM t LIMIT 1"},
		{[]sqlclass.Dialect{pg}, `SELECT a::text, "B", s.t.c FROM s.t LIMIT 1`},
		{[]sqlclass.Dialect{pg}, "SELECT DISTINCT ON (a) a, b FROM t ORDER BY a, b FETCH FIRST 5 ROWS ONLY"},
		{[]sqlclass.Dialect{pg}, "SELECT a FROM t WHERE b ILIKE 'x' AND c ~* 'y' AND d = ANY (SELECT d FROM u) LIMIT 1"},
		{[]sqlclass.Dialect{pg}, "SELECT now() - INTERVAL '1 day', j->>'k', j @> '{}' FROM t LIMIT 1"},
		{[]sqlclass.Dialect{pg}, "SELECT string_agg(a, ',' ORDER BY a), count(*) FILTER (WHERE b > 1) FROM t LIMIT 1"},
		{[]sqlclass.Dialect{pg}, "SELECT a FROM t, LATERAL (SELECT b FROM u WHERE u.a = t.a LIMIT 1) l LIMIT 1"},
		{[]sqlclass.Dialect{pg}, "SELECT a FROM t WHERE b <-1 LIMIT 1"},
		{[]sqlclass.Dialect{pg}, "SELECT EXTRACT(year FROM d), POSITION('a' IN b), SUBSTRING(c FROM 1 FOR 2), TRIM(BOTH ' ' FROM e) FROM t LIMIT 1"},
		{[]sqlclass.Dialect{sl}, "SELECT a FROM t WHERE a == 1 AND b GLOB 'x*' LIMIT 1"},
		{[]sqlclass.Dialect{sl}, "SELECT [a b] FROM [t] LIMIT 1"},
		{all, "SELECT a FROM t;"},
	}
	for _, c := range cases {
		for _, d := range c.ds {
			if _, err := Parse(d, c.sql); err != nil {
				t.Errorf("%s: Parse(%q): %v", d, c.sql, err)
			}
		}
	}
}

func TestParseRefuses(t *testing.T) {
	all := []sqlclass.Dialect{my, pg, sl}
	cases := []struct {
		ds  []sqlclass.Dialect
		sql string
	}{
		{all, "SHOW TABLES"},
		{all, "DESCRIBE t"},
		{all, "VALUES (1)"},
		{all, "INSERT INTO t VALUES (1)"},
		{all, "UPDATE t SET a = 1"},
		{all, "DELETE FROM t"},
		{all, "EXPLAIN ANALYZE SELECT 1"},
		{all, "EXPLAIN DELETE FROM t"},
		{all, "SELECT a FROM t FOR UPDATE"},
		{all, "SELECT a INTO b FROM t"},
		{all, "SELECT a FROM t; SELECT 1"},
		{all, "SELECT a FROM t WHERE a = 1 -- x"},
		{all, "SELECT a FROM generate_series(1, 10) a"},
		{all, "SELECT CURRENT_USER"},
		{all, "SELECT a FROM t LIMIT b"},
		{all, "SELECT ARRAY[1]"},
		{all, "SELECT a FROM t WINDOW w AS (ORDER BY a)"},
		{all, "SELECT a.b.c.d.e FROM t"},
		{all, "SELECT a FROM t GROUP BY a WITH ROLLUP"},
		{all, "WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d"},
		{all, "SELECT 'a' 'b'"},
		{all, "SELECT a 'alias' FROM t"},
		{[]sqlclass.Dialect{pg}, "SELECT a FROM t JOIN u"},
		{[]sqlclass.Dialect{my}, `SELECT "email" FROM t`},
		{[]sqlclass.Dialect{my}, "SELECT a || b FROM t"},
		{[]sqlclass.Dialect{my}, "SELECT _utf8mb4'x'"},
		{[]sqlclass.Dialect{my}, "SELECT SQL_NO_CACHE a FROM t"},
		{[]sqlclass.Dialect{my}, "SELECT a FROM t USE INDEX (i)"},
		{[]sqlclass.Dialect{my}, "SELECT CONVERT(a USING latin1) FROM t"},
		{[]sqlclass.Dialect{pg}, "SELECT a FROM t WHERE b !=- 1"},
		{[]sqlclass.Dialect{pg}, "SELECT a FROM ONLY t"},
		{[]sqlclass.Dialect{pg}, "SELECT a FROM t TABLESAMPLE SYSTEM (1)"},
		{[]sqlclass.Dialect{pg}, "SELECT a[1] FROM t"},
		{[]sqlclass.Dialect{pg}, "SELECT a FROM t WHERE b < ANY (ARRAY[1])"},
	}
	for _, c := range cases {
		for _, d := range c.ds {
			_, err := Parse(d, c.sql)
			var r *sqlclass.Refusal
			if !errors.As(err, &r) {
				t.Errorf("%s: Parse(%q) = %v, want a refusal", d, c.sql, err)
			}
		}
	}
}

func TestParseSpans(t *testing.T) {
	sql := "WITH c AS (SELECT a FROM t) SELECT x.a, count(*) FROM c AS x WHERE x.a = 'k' GROUP BY x.a HAVING count(*) > 1 LIMIT 3"
	st, err := Parse(pg, sql)
	if err != nil {
		t.Fatal(err)
	}
	s := st.Query.Body.(*Select)
	check := func(name string, sp Span, want string) {
		if got := sql[sp.Pos:sp.End]; got != want {
			t.Errorf("%s span = %q, want %q", name, got, want)
		}
	}
	check("with", st.Query.With.Sp, "WITH c AS (SELECT a FROM t)")
	check("from", s.FromSp, "c AS x")
	check("where", s.WhereSp, "x.a = 'k'")
	check("group", s.GroupSp, "x.a")
	check("having", s.HavingSp, "count(*) > 1")
	if st.Query.Limit == nil || st.Query.Limit.Count != 3 {
		t.Errorf("limit = %+v", st.Query.Limit)
	}
}

// MySQL forms hex, bit and national literals with single quotes only:
// X"email" is the column x aliased email, never a constant. The parser
// refuses it, like a double-quoted alias.
func TestParseMySQLDoubleQuotedPrefix(t *testing.T) {
	for _, sql := range []string{
		`SELECT X"email" FROM users LIMIT 1`,
		`SELECT x"email" FROM users LIMIT 1`,
		`SELECT B"01" FROM users LIMIT 1`,
		`SELECT N"name" FROM users LIMIT 1`,
		`SELECT id FROM users WHERE X"41" = id LIMIT 1`,
	} {
		_, err := Parse(my, sql)
		var r *sqlclass.Refusal
		if !errors.As(err, &r) {
			t.Errorf("Parse(%q) = %v, want a refusal", sql, err)
		}
	}
	for _, sql := range []string{
		"SELECT X'0A', B'01', N'x' FROM users LIMIT 1",
		"SELECT x'0a', b'01', n'x' FROM users LIMIT 1",
	} {
		st, err := Parse(my, sql)
		if err != nil {
			t.Errorf("Parse(%q): %v", sql, err)
			continue
		}
		for _, it := range st.Query.Body.(*Select).Items {
			if l, ok := it.Expr.(*Literal); !ok || l.Kind != LitTyped {
				t.Errorf("Parse(%q): item %#v, want a typed literal", sql, it.Expr)
			}
		}
	}
}
