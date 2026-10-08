package sqlast

import (
	"errors"
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

// Regression tests for bypasses of the PII filter rules and of the
// k-anonymity checks found by an adversarial review.

func wantRefused(t *testing.T, d sqlclass.Dialect, sql string) {
	t.Helper()
	_, err := analyze(t, d, sql)
	var r *sqlclass.Refusal
	if !errors.As(err, &r) {
		t.Errorf("%s %q: got %v, want a refusal", d, sql, err)
	}
}

// F1: the k-check counted the rows of the joined FROM, not the subjects of
// the PII column; a FROM-less node had no check at all.
func TestAdvJoinAmplification(t *testing.T) {
	quoted := map[sqlclass.Dialect]string{
		sqlclass.Postgres: `SELECT COUNT(*) FROM "app"."users" WHERE "app"."users"."salary" IN (50000, 50001, 50002)`,
		sqlclass.SQLite:   `SELECT COUNT(*) FROM "app"."users" WHERE "app"."users"."salary" IN (50000, 50001, 50002)`,
		sqlclass.MySQL:    "SELECT COUNT(*) FROM `app`.`users` WHERE `app`.`users`.`salary` IN (50000, 50001, 50002)",
	}
	for d, want := range quoted {
		sql := "SELECT o.id FROM users u, orders o WHERE u.id = 3 AND u.salary IN (50000, 50001, 50002) LIMIT 1"
		a, err := analyze(t, d, sql)
		if err != nil {
			t.Errorf("%s %q: %v", d, sql, err)
			continue
		}
		found := false
		for _, k := range a.KChecks {
			found = found || k.SQL == want && !k.Grouped
		}
		if !found {
			t.Errorf("%s: no subject count on users.salary in %+v", d, a.KChecks)
		}
		// A PII-valued scalar subquery as a filter operand.
		wantRefused(t, d, "SELECT count(*) FROM orders WHERE (SELECT salary FROM users WHERE id = 3) IN (50000, 50001) LIMIT 1")
		wantRefused(t, d, "SELECT count(*) FROM orders WHERE (SELECT email FROM users WHERE id = 3) = 'x' LIMIT 1")
		wantRefused(t, d, "SELECT count(*) FROM orders WHERE (SELECT email FROM users WHERE id = 3) IS NULL LIMIT 1")
	}
	for _, d := range []sqlclass.Dialect{sqlclass.Postgres, sqlclass.SQLite} {
		wantRefused(t, d, "SELECT 1 WHERE (SELECT email FROM users WHERE id = 3) = 'victim@x.example' LIMIT 1")
		// A node without FROM that needs a check.
		_, err := analyze(t, d, "SELECT count((SELECT email FROM users WHERE id = 3)) LIMIT 1")
		if err == nil || !strings.Contains(err.Error(), "without FROM") {
			t.Errorf("%s: FROM-less aggregate of a PII value: %v", d, err)
		}
	}
}

// F2: complements (<>, NOT, IS DISTINCT FROM, NOT IN, IS NOT NULL) and
// compositions (OR, XOR, EXCEPT) of PII atoms.
func TestAdvComplement(t *testing.T) {
	for _, sql := range []string{
		"SELECT id FROM users WHERE email <> 'victim@x.example' LIMIT 1000",
		"SELECT id FROM users WHERE email != 'victim@x.example' LIMIT 1000",
		"SELECT id FROM users WHERE NOT email = 'victim@x.example' LIMIT 1000",
		"SELECT id FROM users WHERE NOT (id = 1 AND email = 'victim@x.example') LIMIT 1000",
		"SELECT id FROM users WHERE email IS DISTINCT FROM 'victim@x.example' LIMIT 1000",
		"SELECT id FROM users WHERE email NOT IN ('victim@x.example') LIMIT 1000",
		"SELECT id FROM users WHERE email IS NOT NULL LIMIT 1000",
		"SELECT id FROM contacts WHERE email NOT IN (SELECT email FROM users) LIMIT 1000",
		"SELECT id FROM contacts WHERE id = 1 OR email IN (SELECT email FROM users) LIMIT 1000",
		"SELECT id FROM users EXCEPT SELECT id FROM users WHERE email <> 'victim@x.example' LIMIT 1",
		"SELECT id FROM users WHERE email = 'victim@x.example' OR status = 'active' EXCEPT SELECT id FROM users WHERE status = 'active' LIMIT 1",
		"SELECT s.id, s.name FROM (SELECT id, name, status FROM users WHERE email = 'victim@x.example' OR status = 'active') s WHERE s.status <> 'active' LIMIT 1",
		"SELECT c.id FROM contacts c JOIN users u ON NOT u.email = c.email LIMIT 1",
	} {
		wantRefused(t, sqlclass.Postgres, sql)
	}
	wantRefused(t, sqlclass.MySQL, "SELECT id FROM users WHERE email = 'victim@x.example' XOR TRUE LIMIT 1000")
	// Positive atoms stay allowed, IS NOT DISTINCT FROM is an equality.
	for _, sql := range []string{
		"SELECT id FROM users WHERE (email = 'a' AND (status = 'x' OR id = 2)) LIMIT 1",
		"SELECT id FROM users WHERE email IS NOT DISTINCT FROM 'a' LIMIT 1",
	} {
		if _, err := analyze(t, sqlclass.Postgres, sql); err != nil {
			t.Errorf("%q: %v", sql, err)
		}
	}
}

// F3: a PII column joined with an unmasked column copies its values where
// no mask applies, without any k-check.
func TestAdvPIIJoinNonPII(t *testing.T) {
	for _, sql := range []string{
		"SELECT u.id, o.total FROM users u JOIN orders o ON u.salary = o.total LIMIT 100",
		"SELECT a.id, b.id AS v FROM users a JOIN users b ON a.salary = b.id LIMIT 100",
		"SELECT a.id, b.name FROM users a, users b WHERE a.email = b.name AND a.id = 3 LIMIT 1",
		"SELECT u.id FROM users u WHERE u.salary IN (SELECT total FROM orders WHERE id = 7) LIMIT 1",
		"SELECT o.id FROM orders o WHERE o.total IN (SELECT salary FROM users) LIMIT 1",
		"SELECT u.id FROM users u NATURAL JOIN orders o LIMIT 1",
	} {
		wantRefused(t, sqlclass.Postgres, sql)
	}
	// Between two masked columns, a join needs no check.
	for _, sql := range []string{
		"SELECT u.id FROM users u JOIN contacts c ON c.email = u.email LIMIT 1",
		"SELECT u.id FROM users u JOIN contacts c USING (email) LIMIT 1",
		"SELECT id FROM contacts WHERE email IN (SELECT email FROM users) LIMIT 1",
	} {
		a, err := analyze(t, sqlclass.Postgres, sql)
		if err != nil {
			t.Errorf("%q: %v", sql, err)
		} else if len(a.KChecks) > 0 || a.PIIFilter {
			t.Errorf("%q: checks %+v", sql, a.KChecks)
		}
	}
}

// F4: a GROUP BY name that is both an output alias and an input column of a
// derived table, a CTE or a join: the k-check grouped by the alias
// expression while the engine grouped by the column.
func TestAdvGroupAlias(t *testing.T) {
	for _, sql := range []string{
		"SELECT 1+0 AS email, count(*) FROM (SELECT email FROM users) s GROUP BY email LIMIT 100",
		"SELECT 1+0 AS email, count(*) FROM users u JOIN orders o ON o.user_id = u.id GROUP BY u.email, email LIMIT 100",
		"WITH c AS (SELECT email FROM users) SELECT 1+0 AS email, count(*) FROM c GROUP BY email LIMIT 100",
		"SELECT 1+0 AS email, count(*) FROM users GROUP BY email LIMIT 100",
	} {
		wantRefused(t, sqlclass.Postgres, sql)
	}
	cases := map[string]string{
		// The alias names the same column: no ambiguity.
		"SELECT email AS email, count(*) FROM (SELECT email FROM users) s GROUP BY email LIMIT 100": "GROUP BY email)",
		// Only an alias: grouped by its expression.
		"SELECT u.email AS e, count(*) FROM users u GROUP BY e LIMIT 100": "GROUP BY u.email)",
	}
	for sql, want := range cases {
		a, err := analyze(t, sqlclass.Postgres, sql)
		if err != nil {
			t.Errorf("%q: %v", sql, err)
			continue
		}
		if len(a.KChecks) != 1 || !a.KChecks[0].Grouped || !strings.Contains(a.KChecks[0].SQL, want) {
			t.Errorf("%q: checks %+v, want %q", sql, a.KChecks, want)
		}
	}
}

type viewCatalog struct{}

func (viewCatalog) Lookup(parts []string) ([]Table, error) {
	if parts[len(parts)-1] == "V" {
		return []Table{{DB: "app", Name: "v", Columns: []string{"id", "email"}, View: true}}, nil
	}
	return testCatalog.Lookup(parts)
}

// A PII column of a view has no base table to count its subjects in.
func TestAdvViewConstFilter(t *testing.T) {
	env := testEnv(true)
	env.Catalog = viewCatalog{}
	rule := env.Rule
	env.Rule = func(s Source) (string, bool) {
		if s.View {
			return "partial", s.Column == "email"
		}
		return rule(s)
	}
	for sql, ok := range map[string]bool{
		"SELECT id FROM v WHERE email = 'x' LIMIT 1":                   false,
		"SELECT id FROM v WHERE email IS NULL LIMIT 1":                 false,
		"SELECT id FROM v WHERE id = 1 LIMIT 1":                        true,
		"SELECT v.id FROM v JOIN users u ON u.email = v.email LIMIT 1": true,
	} {
		st, err := Parse(sqlclass.Postgres, sql)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Analyze(st, env)
		if (err == nil) != ok {
			t.Errorf("%q: err %v, want allowed %v", sql, err, ok)
		}
	}
}
