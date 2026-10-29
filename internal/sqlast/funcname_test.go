package sqlast

import (
	"errors"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

// A function is matched against the allowlist by the name the engine
// resolves, not by a folded spelling of it: a quoted name (PostgreSQL
// "LOWER" is not lower; a MySQL backquoted name is not the built-in), a
// name with non-ASCII letters (ſ folds to S), and in MySQL a blank before
// '(' (it can make the server look for a stored function) are refused.

func parseAnalyze(d sqlclass.Dialect, sql string) error {
	st, err := Parse(d, sql)
	if err != nil {
		return err
	}
	_, err = Analyze(st, testEnv(true))
	return err
}

func TestFunctionNameSpelling(t *testing.T) {
	pg, my, lite := sqlclass.Postgres, sqlclass.MySQL, sqlclass.SQLite
	refused := []struct {
		d   sqlclass.Dialect
		sql string
	}{
		{pg, `SELECT "LOWER"('x') AS x LIMIT 1`},
		{pg, `SELECT "lower"('x') AS x LIMIT 1`},
		{pg, `SELECT "Lower"(status) AS x FROM users LIMIT 1`},
		{pg, `SELECT id FROM users WHERE "UPPER"(status) = 'A' LIMIT 1`},
		{pg, `SELECT COUNT(*) AS n FROM users GROUP BY "LOWER"(status) LIMIT 1`},
		{pg, "SELECT ſqrt(4) AS x LIMIT 1"},
		{pg, "SELECT ſubstring('abc', 1, 1) AS x LIMIT 1"},
		{pg, "SELECT lower(ſqrt(4)::text) AS x LIMIT 1"},
		{pg, "SELECT id FROM users WHERE exiſts(SELECT 1) LIMIT 1"},
		{pg, "SELECT ｌower('x') AS x LIMIT 1"},
		{pg, "SELECT ſum(id) AS x FROM users LIMIT 1"},
		{my, "SELECT `lower`('x') AS x LIMIT 1"},
		{my, "SELECT `COUNT`(*) AS n FROM users LIMIT 1"},
		{my, "SELECT ſqrt(4) AS x LIMIT 1"},
		{my, "SELECT count (*) AS n FROM users LIMIT 1"},
		{my, "SELECT lower ('x') AS x LIMIT 1"},
		{my, "SELECT now\n() AS x LIMIT 1"},
		{my, "SELECT CAST ('1' AS CHAR) AS x LIMIT 1"},
		{my, "SELECT extract (YEAR FROM now()) AS x LIMIT 1"},
		{my, "SELECT mod (5, 2) AS x LIMIT 1"},
		{lite, `SELECT "lower"('x') AS x LIMIT 1`},
		{lite, "SELECT [lower]('x') AS x LIMIT 1"},
		{lite, "SELECT ſqrt(4) AS x LIMIT 1"},
	}
	for _, c := range refused {
		var r *sqlclass.Refusal
		if err := parseAnalyze(c.d, c.sql); !errors.As(err, &r) {
			t.Errorf("%s %q: got %v, want a refusal", c.d, c.sql, err)
		}
	}
	accepted := []struct {
		d   sqlclass.Dialect
		sql string
	}{
		{pg, `SELECT lower("status") AS x FROM "users" LIMIT 1`},
		{pg, "SELECT LOWER(status) AS x FROM users LIMIT 1"},
		{pg, "SELECT count (*) AS n FROM users LIMIT 1"},
		{pg, "SELECT lower('é') AS x LIMIT 1"},
		{pg, "WITH c(x) AS (SELECT 1) SELECT x FROM c LIMIT 1"},
		{pg, "SELECT extract(year FROM now()) AS x LIMIT 1"},
		{my, "SELECT lower(`status`) AS x FROM `users` LIMIT 1"},
		{my, "SELECT COUNT(*) AS n FROM users LIMIT 1"},
		{my, "SELECT id FROM users WHERE EXISTS (SELECT 1) AND id IN (1, 2) LIMIT 1"},
		{lite, `SELECT lower("status") AS x FROM users LIMIT 1`},
		{lite, "SELECT count (*) AS n FROM users LIMIT 1"},
	}
	for _, c := range accepted {
		if err := parseAnalyze(c.d, c.sql); err != nil {
			t.Errorf("%s %q: %v", c.d, c.sql, err)
		}
	}
}
