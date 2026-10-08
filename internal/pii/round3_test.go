package pii

import (
	"testing"

	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

type dsql struct {
	d   sqlclass.Dialect
	sql string
}

func classify(t *testing.T, c dsql) sqlclass.Statement {
	t.Helper()
	st, err := sqlclass.Classify(c.d, c.sql, 0)
	if err != nil {
		t.Fatalf("Classify(%q): %v", c.sql, err)
	}
	return st
}

// Round 3: statements that return rows without being plain reads
// (RETURNING, data-modifying CTEs), nested stars and TABLE inside
// expressions, and planner statistics.
func TestPlanCheckRound3(t *testing.T) {
	r := Rules{Mask: []string{"*.big.email", "main.users.firstname", "app.users.firstname"}}
	refused := []dsql{
		// Writes that return rows.
		{sqlclass.Postgres, "UPDATE big SET status = status WHERE id < 3 RETURNING upper(email)"},
		{sqlclass.Postgres, "UPDATE big SET status = status WHERE id < 3 RETURNING email AS x"},
		{sqlclass.Postgres, "UPDATE big b SET status = status RETURNING row_to_json(b)"},
		{sqlclass.Postgres, "DELETE FROM big WHERE id = 1 RETURNING big"},
		{sqlclass.Postgres, "UPDATE big SET status = status RETURNING to_json(old)"},
		{sqlclass.Postgres, "UPDATE big SET status = status RETURNING WITH (OLD AS o) to_json(o)"},
		{sqlclass.Postgres, "INSERT INTO small (id) SELECT id FROM big RETURNING (SELECT upper(email) FROM big LIMIT 1)"},
		{sqlclass.MySQL, "DELETE FROM big WHERE id = 1 RETURNING upper(email) AS x"},
		{sqlclass.SQLite, "DELETE FROM big WHERE id = 1 RETURNING upper(email)"},
		{sqlclass.Postgres, "WITH d AS (DELETE FROM small WHERE false RETURNING 1) SELECT upper(email) AS x FROM big LIMIT 3"},
		{sqlclass.Postgres, "SELECT upper(email) AS delete FROM big LIMIT 3"},
		// Nested * or TABLE inside a select-list expression.
		{sqlclass.SQLite, "WITH c AS (SELECT firstname FROM users) SELECT (SELECT * FROM c LIMIT 1) || '' AS x LIMIT 5"},
		{sqlclass.SQLite, "WITH c AS (SELECT firstname FROM users) SELECT id FROM t UNION SELECT (SELECT * FROM c LIMIT 1) LIMIT 5"},
		{sqlclass.MySQL, "WITH c AS (SELECT firstname FROM users) SELECT (SELECT * FROM c LIMIT 1) AS x LIMIT 5"},
		{sqlclass.MySQL, "WITH c AS (SELECT firstname FROM users) SELECT (TABLE c LIMIT 1) AS x LIMIT 5"},
		{sqlclass.MySQL, "WITH c AS (SELECT firstname FROM users) SELECT JSON_ARRAYAGG((SELECT * FROM c LIMIT 1)) AS x LIMIT 5"},
		{sqlclass.MySQL, "WITH c AS (SELECT firstname FROM users) VALUES ROW((TABLE c LIMIT 1)) LIMIT 5"},
		{sqlclass.Postgres, "WITH c AS (SELECT firstname FROM users) SELECT ARRAY(TABLE c) AS x LIMIT 5"},
		{sqlclass.Postgres, "WITH c AS (SELECT firstname FROM users) SELECT * FROM unnest(ARRAY(TABLE c)) LIMIT 5"},
		{sqlclass.Postgres, "WITH c AS (SELECT firstname FROM users) SELECT (TABLE c LIMIT 1) AS x LIMIT 5"},
		{sqlclass.Postgres, "WITH c AS (SELECT firstname FROM users) VALUES ((TABLE c LIMIT 1)) LIMIT 5"},
		{sqlclass.Postgres, "WITH c AS (SELECT firstname FROM users) SELECT id FROM t UNION SELECT (TABLE c LIMIT 1) LIMIT 5"},
		{sqlclass.Postgres, "WITH c AS (SELECT firstname FROM users) SELECT (SELECT c.* FROM c LIMIT 1) AS x LIMIT 5"},
		{sqlclass.Postgres, "SELECT ARRAY(SELECT * FROM v) AS x LIMIT 5"},
		// Planner statistics hold sample values of rule columns.
		{sqlclass.Postgres, "SELECT most_common_vals::text, histogram_bounds::text FROM pg_stats WHERE tablename = 'users' AND attname = 'firstname' LIMIT 5"},
		{sqlclass.Postgres, "SELECT stavalues1::text FROM pg_catalog.pg_statistic LIMIT 5"},
		{sqlclass.Postgres, `SELECT * FROM "pg_stats_ext_exprs" LIMIT 5`},
		{sqlclass.MySQL, "SELECT min_value, max_value FROM mysql.column_stats LIMIT 5"},
		{sqlclass.MySQL, "SELECT HISTOGRAM FROM information_schema.COLUMN_STATISTICS LIMIT 5"},
		{sqlclass.SQLite, "SELECT sample FROM sqlite_stat4 LIMIT 5"},
	}
	for _, c := range refused {
		st := classify(t, c)
		if PlanCheck(st, r, c.d, false) == nil {
			t.Errorf("accepted without origins: %s", c.sql)
		}
		// With origins, a plain read is checked after it runs, when some
		// column has none (AliasViolation); the rest before it runs.
		plain := st.Class == sqlclass.Read && st.Kind == "select"
		if plain && AliasViolation(st, r, c.d) == nil && StatsViolation(st, r, c.d) == nil ||
			!plain && PlanCheck(st, r, c.d, true) == nil {
			t.Errorf("accepted with origins: %s", c.sql)
		}
	}
	for _, c := range refused[len(refused)-6:] { // statistics: before the run
		if PlanCheck(classify(t, c), r, c.d, true) == nil {
			t.Errorf("statistics accepted: %s", c.sql)
		}
	}
	allowed := []dsql{
		{sqlclass.Postgres, "UPDATE big SET status = 'x' WHERE id < 3 RETURNING id, email"},
		{sqlclass.Postgres, "DELETE FROM big WHERE email LIKE '%x' RETURNING id"},
		{sqlclass.Postgres, "SELECT id FROM t WHERE EXISTS (SELECT * FROM users) LIMIT 5"},
		{sqlclass.Postgres, "SELECT count(*) FROM users LIMIT 5"},
		{sqlclass.Postgres, "SELECT (SELECT count(*) FROM users) AS n LIMIT 5"},
		{sqlclass.Postgres, "SELECT CASE WHEN EXISTS (SELECT * FROM users) THEN 1 END AS e LIMIT 5"},
		{sqlclass.MySQL, "CREATE TABLE x AS SELECT upper(email) AS e FROM big"},
		{sqlclass.SQLite, "INSERT INTO small (id) VALUES (1) RETURNING id"},
	}
	for _, c := range allowed {
		st := classify(t, c)
		if err := PlanCheck(st, r, c.d, true); err != nil {
			t.Errorf("refused %s: %v", c.sql, err)
		}
	}
	// No rule: nothing to protect.
	st := classify(t, dsql{sqlclass.Postgres, "SELECT histogram_bounds::text FROM pg_stats LIMIT 5"})
	if err := PlanCheck(st, Rules{}, sqlclass.Postgres, true); err != nil {
		t.Errorf("no rules: %v", err)
	}
}
