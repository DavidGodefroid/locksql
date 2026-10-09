package pii

import (
	"testing"

	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

// Round 4: PostgreSQL attribute notation (rel.f is f(rel)), and writes that
// copy a rule column into a column they return.
func TestAttributeNotationRound4(t *testing.T) {
	r := Rules{Mask: []string{"public.big.email"}}
	noOrigin := []engine.ResultColumn{{Label: "x"}, {Label: "y"}}
	refused := []string{
		"SELECT b.row_to_json FROM big b LIMIT 2",
		"SELECT big.record_out::text AS r FROM big LIMIT 2",
		"SELECT public.big.row_to_json FROM public.big LIMIT 2",
		`SELECT "b"."name" FROM big b LIMIT 2`,
		"SELECT upper(b.name) FROM big b LIMIT 2",
		"SELECT x.key, x.value FROM big b, json_each_text(b.row_to_json) x LIMIT 4",
		"WITH c AS (SELECT b.row_to_json AS j FROM big b) SELECT j FROM c LIMIT 2",
		"SELECT id FROM small UNION SELECT (SELECT b.to_json FROM big b LIMIT 1) LIMIT 2",
		"VALUES ((SELECT b.text FROM big b LIMIT 1)) LIMIT 1",
	}
	for _, q := range refused {
		st := classify(t, dsql{sqlclass.Postgres, q})
		if AliasViolation(st, r, sqlclass.Postgres) == nil {
			t.Errorf("accepted: %s", q)
		}
		if ResultAliasViolation(st, r, sqlclass.Postgres, noOrigin) == nil {
			t.Errorf("accepted without origins: %s", q)
		}
	}
	writes := []string{
		"UPDATE big SET id = id WHERE id < 3 RETURNING big.row_to_json",
		"UPDATE big b SET id = id WHERE id < 3 RETURNING b.record_out",
		"DELETE FROM big WHERE id < 0 RETURNING (big.text)",
	}
	for _, q := range writes {
		if PlanCheck(classify(t, dsql{sqlclass.Postgres, q}), r, sqlclass.Postgres, true) == nil {
			t.Errorf("accepted: %s", q)
		}
	}
	// A qualified column that comes back with an origin is a real column.
	q := "SELECT b.id, b.email, count(*) OVER () AS n FROM big b LIMIT 5"
	st := classify(t, dsql{sqlclass.Postgres, q})
	cols := []engine.ResultColumn{
		{Label: "id", OriginDB: "public", OriginTable: "big", OriginColumn: "id"},
		{Label: "email", OriginDB: "public", OriginTable: "big", OriginColumn: "email"},
		{Label: "n"},
	}
	if err := ResultAliasViolation(st, r, sqlclass.Postgres, cols); err != nil {
		t.Errorf("refused %s: %v", q, err)
	}
	cols[0] = engine.ResultColumn{Label: "id"}
	if ResultAliasViolation(st, r, sqlclass.Postgres, cols) == nil {
		t.Errorf("accepted with a no-origin qualified column: %s", q)
	}
	allowed := []dsql{
		{sqlclass.Postgres, "SELECT id, lower(status), count(*) OVER () FROM big b WHERE b.id < 3 LIMIT 5"},
		{sqlclass.Postgres, "SELECT x.key FROM json_each_text('{}') x LIMIT 5"},
		{sqlclass.MySQL, "SELECT upper(b.status) AS s FROM big b LIMIT 5"},
		{sqlclass.SQLite, "SELECT upper(b.status) AS s FROM big b LIMIT 5"},
	}
	for _, c := range allowed {
		if err := AliasViolation(classify(t, c), r, c.d); err != nil {
			t.Errorf("refused %s: %v", c.sql, err)
		}
	}
}

func TestWriteCopiesRuleColumnRound4(t *testing.T) {
	r := Rules{Mask: []string{"*.big.email", "*.users.firstname"}}
	refused := []dsql{
		{sqlclass.Postgres, "INSERT INTO small (id, label) SELECT 1000 + id, email FROM big WHERE id < 3 RETURNING label"},
		{sqlclass.Postgres, "UPDATE small SET label = (SELECT email FROM big WHERE big.id = small.id) WHERE id = 1 RETURNING label"},
		{sqlclass.Postgres, "WITH i AS (INSERT INTO small (id, label) SELECT 1000 + id, email FROM big WHERE id < 3 RETURNING label) SELECT label FROM i LIMIT 5"},
		{sqlclass.Postgres, "UPDATE big SET status = email WHERE id < 3 RETURNING status"},
		{sqlclass.Postgres, "UPDATE big SET status = CASE WHEN id = 1 THEN email END WHERE id < 3 RETURNING status"},
		{sqlclass.Postgres, "INSERT INTO small SELECT * FROM big RETURNING label"},
		{sqlclass.Postgres, "INSERT INTO small TABLE big RETURNING label"},
		{sqlclass.Postgres, "UPDATE small s SET label = b.row_to_json FROM big b WHERE b.id = s.id RETURNING label"},
		{sqlclass.Postgres, "MERGE INTO small s USING big b ON b.id = s.id WHEN MATCHED THEN UPDATE SET label = b.email RETURNING s.label"},
		{sqlclass.Postgres, "INSERT INTO small (id, label) SELECT id, x FROM (SELECT id, email AS x FROM big) d RETURNING label"},
		{sqlclass.MySQL, "INSERT INTO small (id, label) SELECT 1000 + id, email FROM big WHERE id < 3 RETURNING label"},
		{sqlclass.MySQL, "INSERT INTO small (id, label) VALUES (5, 'x') ON DUPLICATE KEY UPDATE label = (SELECT email FROM big LIMIT 1) RETURNING label"},
		{sqlclass.SQLite, "UPDATE small SET label = (SELECT email FROM big LIMIT 1) RETURNING label"},
		{sqlclass.SQLite, "INSERT INTO small (id, label) SELECT id, firstname FROM users RETURNING label"},
	}
	for _, c := range refused {
		if PlanCheck(classify(t, c), r, c.d, true) == nil {
			t.Errorf("accepted: %s", c.sql)
		}
	}
	allowed := []dsql{
		// A rule column may only be set to NULL or DEFAULT (planted_test.go).
		{sqlclass.Postgres, "UPDATE users SET firstname = NULL WHERE id = 1 RETURNING id"},
		{sqlclass.Postgres, "UPDATE users SET (firstname, id) = (NULL, 2) WHERE id = 1 RETURNING id"},
		{sqlclass.Postgres, "INSERT INTO users (id, firstname) VALUES (1, DEFAULT) RETURNING id"},
		{sqlclass.Postgres, "UPDATE big SET status = 'x' WHERE email LIKE '%x' RETURNING id, email"},
		{sqlclass.Postgres, "UPDATE small SET label = 'x' WHERE id IN (SELECT id FROM big WHERE email LIKE 'a%') RETURNING id"},
		{sqlclass.Postgres, "DELETE FROM big WHERE email LIKE '%x' RETURNING id"},
		{sqlclass.SQLite, "INSERT INTO small (id) VALUES (1) RETURNING id"},
	}
	for _, c := range allowed {
		if err := PlanCheck(classify(t, c), r, c.d, true); err != nil {
			t.Errorf("refused %s: %v", c.sql, err)
		}
	}
}

// originCols are n result columns that all carry an origin.
func originCols(n int) []engine.ResultColumn {
	out := make([]engine.ResultColumn, n)
	for i := range out {
		out[i] = engine.ResultColumn{Label: "c", OriginDB: "db", OriginTable: "t", OriginColumn: "c"}
	}
	return out
}
