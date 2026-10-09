package sqlast

import (
	"errors"
	"maps"
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

// A set operation compares its arms column by column: INTERSECT, EXCEPT
// and the duplicate removal of UNION are equality tests between a PII
// column and a value the agent chose, wherever the set operation sits.
func TestAdvSetOpOracle(t *testing.T) {
	dialects := []sqlclass.Dialect{sqlclass.MySQL, sqlclass.Postgres, sqlclass.SQLite}
	for _, d := range dialects {
		for _, sql := range []string{
			"SELECT name FROM users u WHERE EXISTS (SELECT u.email INTERSECT SELECT 'x@example.com') LIMIT 10",
			"SELECT name FROM users u WHERE NOT EXISTS (SELECT u.email INTERSECT SELECT 'x@example.com') LIMIT 10",
			"SELECT name, (SELECT COUNT(*) FROM (SELECT u.email INTERSECT SELECT 'x') d) AS hit FROM users u LIMIT 100",
			"SELECT name FROM users u WHERE (SELECT COUNT(*) FROM (SELECT u.email UNION SELECT 'b@example.com') d) = 1 LIMIT 10",
			"SELECT 1 AS hit FROM (SELECT email FROM users INTERSECT SELECT 'x') t LIMIT 1",
			"SELECT 'x' EXCEPT SELECT email FROM users LIMIT 1",
			"SELECT n FROM (SELECT 1 AS n, 'a@example.com' AS e UNION ALL SELECT 2, 'zz@example.com') c WHERE EXISTS (SELECT c.e INTERSECT SELECT email FROM users) LIMIT 10",
			// Nested set operations are checked at every level.
			"SELECT email FROM users UNION ALL SELECT 'x' INTERSECT SELECT email FROM contacts LIMIT 5",
			"SELECT email FROM contacts INTERSECT (SELECT email FROM users UNION ALL SELECT name FROM users) LIMIT 5",
			"SELECT 1 AS hit FROM users u WHERE EXISTS (SELECT u.email EXCEPT ALL SELECT 'x') LIMIT 1",
			"WITH c AS (SELECT email FROM users UNION SELECT name FROM users) SELECT 1 FROM c LIMIT 1",
			"SELECT salary FROM users INTERSECT SELECT total + 1 FROM orders LIMIT 5",
			"SELECT name FROM users UNION SELECT email FROM users LIMIT 1",
			"SELECT email FROM users INTERSECT (SELECT 'x') LIMIT 5",
			"SELECT email FROM users UNION SELECT NULL LIMIT 5",
			"WITH RECURSIVE r(e) AS (SELECT email FROM users UNION SELECT 'x' FROM r) SELECT e FROM r LIMIT 5",
		} {
			_, err := analyze(t, d, sql)
			if err == nil || !strings.Contains(err.Error(), "set operation compares a PII column") {
				t.Errorf("%s %q: got %v, want a set operation refusal", d, sql, err)
			}
		}
		// UNION ALL compares nothing: the column is masked in its mode and,
		// as it may hold a literal, gets no reference (plain <redacted>).
		for sql, mask := range map[string]string{
			"SELECT email FROM users UNION ALL SELECT 'x' LIMIT 5": "partial",
			"SELECT salary FROM users UNION ALL SELECT 1 LIMIT 5":  "redact",
		} {
			a, err := analyze(t, d, sql)
			if err != nil {
				t.Errorf("%s %q: %v", d, sql, err)
			} else if a.Outputs[0].Mask != mask || !a.Outputs[0].Prov.Lit {
				t.Errorf("%s %q: outputs %+v, want mask %s and Lit", d, sql, a.Outputs, mask)
			}
		}
		// Two PII arms, or two non-PII arms, compare nothing the agent chose.
		for _, sql := range []string{
			"SELECT email FROM users INTERSECT SELECT email FROM contacts LIMIT 5",
			"SELECT name FROM users UNION SELECT name FROM users LIMIT 5",
		} {
			if _, err := analyze(t, d, sql); err != nil {
				t.Errorf("%s %q: %v", d, sql, err)
			}
		}
		a, err := analyze(t, d, "SELECT email FROM users WHERE email = 'x' LIMIT 5")
		if err != nil {
			t.Errorf("%s: constant filter: %v", d, err)
		} else if len(a.KChecks) != 2 {
			t.Errorf("%s: constant filter: checks %+v, want 2", d, a.KChecks)
		}
	}
}

// UNION ALL compares nothing, but a duplicate removal over its result does:
// DISTINCT, an aggregate's DISTINCT or GROUP BY over a column mixing PII
// values with values the agent chose is the same equality oracle.
func TestAdvDedupeOracle(t *testing.T) {
	for _, d := range []sqlclass.Dialect{sqlclass.MySQL, sqlclass.Postgres, sqlclass.SQLite} {
		for _, sql := range []string{
			"SELECT COUNT(*) FROM (SELECT DISTINCT e FROM (SELECT email AS e FROM users UNION ALL SELECT 'x@example.com') t) s LIMIT 1",
			"SELECT DISTINCT e FROM (SELECT email AS e FROM users UNION ALL SELECT 'x@example.com') t LIMIT 10",
			"SELECT COUNT(DISTINCT e) FROM (SELECT email AS e FROM users WHERE id = 1 UNION ALL SELECT 'x@example.com') t LIMIT 1",
			"SELECT e, COUNT(*) FROM (SELECT email AS e FROM users UNION ALL SELECT 'x@example.com') t GROUP BY e LIMIT 10",
			"SELECT e, COUNT(*) FROM (SELECT email AS e FROM users UNION ALL SELECT name FROM users) t GROUP BY 1 LIMIT 10",
		} {
			_, err := analyze(t, d, sql)
			if err == nil || !strings.Contains(err.Error(), "duplicate removal compares a PII column") {
				t.Errorf("%s %q: got %v, want a duplicate removal refusal", d, sql, err)
			}
		}
		for _, sql := range []string{
			"SELECT DISTINCT email FROM users LIMIT 5",
			"SELECT COUNT(DISTINCT email) FROM users LIMIT 1",
			"SELECT DISTINCT name FROM users UNION ALL SELECT 'x' LIMIT 5",
		} {
			if _, err := analyze(t, d, sql); err != nil {
				t.Errorf("%s %q: %v", d, sql, err)
			}
		}
	}
}

// A PII column compared with itself is IS NOT NULL in disguise: it selects
// rows with no constant for the k-anonymity check to count. Two instances
// of the column (a join, a self-join) stay a PII join.
func TestAdvSelfComparison(t *testing.T) {
	for _, d := range []sqlclass.Dialect{sqlclass.MySQL, sqlclass.Postgres, sqlclass.SQLite} {
		refused := []string{
			"SELECT name FROM users WHERE email = email LIMIT 10",
			"SELECT name FROM users WHERE users.email = email LIMIT 10",
			"SELECT name FROM users u WHERE (u.email) = email LIMIT 10",
			"SELECT name FROM users WHERE email IS NOT DISTINCT FROM email LIMIT 10",
			"SELECT name FROM users u JOIN contacts c ON u.email = u.email LIMIT 10",
			"SELECT name FROM (SELECT name, email AS a, email AS b FROM users) t WHERE a = b LIMIT 10",
			"WITH c AS (SELECT email AS a, email AS b FROM users) SELECT a FROM c WHERE a = b LIMIT 10",
			"SELECT id FROM orders o WHERE EXISTS (SELECT 1 FROM users u WHERE u.id = o.user_id AND u.email = u.email) LIMIT 10",
			"SELECT name FROM users u WHERE u.email IN (SELECT u.email FROM orders) LIMIT 10",
		}
		if d == sqlclass.MySQL {
			refused = append(refused, "SELECT name FROM users WHERE email <=> email LIMIT 10")
		}
		for _, sql := range refused {
			_, err := analyze(t, d, sql)
			if err == nil || !strings.Contains(err.Error(), "a PII column compared with itself selects the rows the k-anonymity check does not count") {
				t.Errorf("%s %q: got %v, want a self-comparison refusal", d, sql, err)
			}
		}
		for _, sql := range []string{
			"SELECT u.name FROM users u JOIN contacts c ON u.email = c.email LIMIT 10",
			"SELECT a.name FROM users a JOIN users b ON a.email = b.email LIMIT 10",
			"WITH c AS (SELECT email FROM users) SELECT x.email FROM c x JOIN c y ON x.email = y.email LIMIT 10",
			"SELECT name FROM users u WHERE u.email IN (SELECT v.email FROM users v) LIMIT 10",
		} {
			if _, err := analyze(t, d, sql); err != nil {
				t.Errorf("%s %q: %v", d, sql, err)
			}
		}
	}
}

// Size functions allocate their result per cell: an unbounded length
// passes the EXPLAIN gate with a constant-cost plan and exhausts memory.
func TestAdvSizeFunctionCap(t *testing.T) {
	const msg = ": the length argument must be an integer literal at most 65536"
	shapes := func(call string) []string {
		return []string{
			strings.ReplaceAll(call, "N", "1073741823"),
			strings.ReplaceAll(call, "N", "65537"),
			strings.ReplaceAll(call, "N", "-1"),
			strings.ReplaceAll(call, "N", "id"),
			strings.ReplaceAll(call, "N", "10 * 10"),
			strings.ReplaceAll(call, "N", "1.5"),
			strings.ReplaceAll(call, "N", "'10'"),
			strings.ReplaceAll(call, "N", "(SELECT 10)"),
		}
	}
	funcs := map[string]string{"repeat": "repeat(name, N)", "lpad": "lpad(name, N, '0')", "rpad": "rpad(name, N, '0')"}
	for _, d := range []sqlclass.Dialect{sqlclass.MySQL, sqlclass.Postgres, sqlclass.SQLite} {
		all := maps.Clone(funcs)
		switch d {
		case sqlclass.MySQL:
			all["space"] = "space(N)"
		case sqlclass.SQLite:
			all["zeroblob"] = "zeroblob(N)"
		}
		for name, call := range all {
			for _, expr := range shapes(call) {
				sql := "SELECT " + expr + " FROM users LIMIT 1"
				_, err := analyze(t, d, sql)
				if err == nil || !strings.Contains(err.Error(), name+msg) {
					t.Errorf("%s %q: got %v, want a length refusal", d, sql, err)
				}
			}
			sql := "SELECT " + strings.ReplaceAll(call, "N", "65536") + " FROM users LIMIT 1"
			if _, err := analyze(t, d, sql); err != nil {
				t.Errorf("%s %q: %v", d, sql, err)
			}
		}
		wantRefused(t, d, "SELECT repeat('x', 1073741823), repeat('y', 1073741823) LIMIT 1")
		for _, sql := range []string{
			"SELECT lpad(name, 10, '0') FROM users LIMIT 1",
			"SELECT rpad(name, 0, '0') FROM users LIMIT 1",
			"SELECT repeat('-', 3) FROM users LIMIT 1",
		} {
			if _, err := analyze(t, d, sql); err != nil {
				t.Errorf("%s %q: %v", d, sql, err)
			}
		}
	}
}
