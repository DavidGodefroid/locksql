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
		sqlclass.Postgres: `SELECT MIN(locksql_n) FROM (SELECT COUNT(*) AS locksql_n FROM "app"."users" WHERE "app"."users"."salary" = 50000 UNION ALL SELECT COUNT(*) FROM "app"."users" WHERE "app"."users"."salary" = 50001 UNION ALL SELECT COUNT(*) FROM "app"."users" WHERE "app"."users"."salary" = 50002) AS locksql_k`,
		sqlclass.SQLite:   `SELECT MIN(locksql_n) FROM (SELECT COUNT(*) AS locksql_n FROM "app"."users" WHERE "app"."users"."salary" = 50000 UNION ALL SELECT COUNT(*) FROM "app"."users" WHERE "app"."users"."salary" = 50001 UNION ALL SELECT COUNT(*) FROM "app"."users" WHERE "app"."users"."salary" = 50002) AS locksql_k`,
		sqlclass.MySQL:    "SELECT MIN(locksql_n) FROM (SELECT COUNT(*) AS locksql_n FROM `app`.`users` WHERE `app`.`users`.`salary` = 50000 UNION ALL SELECT COUNT(*) FROM `app`.`users` WHERE `app`.`users`.`salary` = 50001 UNION ALL SELECT COUNT(*) FROM `app`.`users` WHERE `app`.`users`.`salary` = 50002) AS locksql_k",
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
// rows with no constant for the k-anonymity check to count. A self-join on
// the column is the same probe, whatever the relation instances; a join
// between two different PII columns stays allowed.
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
			"SELECT a.name FROM users a JOIN users b ON a.email = b.email LIMIT 10",
			"SELECT a.name FROM users a JOIN users b ON a.id = b.id WHERE a.email = b.email LIMIT 10",
			"SELECT name FROM users u WHERE u.email IN (SELECT v.email FROM users v WHERE v.id = u.id) LIMIT 10",
			"SELECT name FROM users u WHERE u.email IN (SELECT v.email FROM users v) LIMIT 10",
			"SELECT name FROM users u WHERE EXISTS (SELECT 1 FROM users v WHERE v.id = u.id AND v.email = u.email) LIMIT 10",
			"SELECT a.name FROM users a NATURAL JOIN users b LIMIT 10",
			"SELECT a.name FROM users a JOIN users b USING (email) LIMIT 10",
			"WITH c AS (SELECT email FROM users) SELECT x.email FROM c x JOIN c y ON x.email = y.email LIMIT 10",
			// A set operation compares its arms like a join.
			"SELECT id FROM users u WHERE EXISTS (SELECT u.email INTERSECT SELECT u2.email FROM users u2 WHERE u2.id = 7) LIMIT 10",
			"SELECT email FROM users WHERE id=5 INTERSECT SELECT email FROM users WHERE id=6 LIMIT 1",
			"SELECT email FROM users WHERE id=5 EXCEPT SELECT email FROM users WHERE id=6 LIMIT 1",
			"SELECT email FROM users WHERE id=5 UNION SELECT email FROM users WHERE id=6 LIMIT 1",
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
		wantRefused(t, d, "SELECT name FROM users WHERE email IN (email) LIMIT 10")
		for _, sql := range []string{
			"SELECT u.name FROM users u JOIN contacts c ON u.email = c.email LIMIT 10",
			"SELECT u.name FROM users u JOIN contacts c USING (email) LIMIT 10",
			"SELECT name FROM users u WHERE u.email IN (SELECT c.email FROM contacts c) LIMIT 10",
			"SELECT email FROM users INTERSECT SELECT email FROM contacts LIMIT 5",
			"SELECT email FROM users WHERE id=5 UNION ALL SELECT email FROM users WHERE id=6 LIMIT 1",
		} {
			if _, err := analyze(t, d, sql); err != nil {
				t.Errorf("%s %q: %v", d, sql, err)
			}
		}
	}
}

// Size functions allocate their result per cell: an unbounded length
// passes the EXPLAIN gate with a constant-cost plan and exhausts memory.
// Nesting them, or feeding them to a replacement, multiplies the sizes.
func TestAdvSizeFunctionCap(t *testing.T) {
	shapes := func(call string) []string {
		var out []string
		for _, n := range []string{"1073741823", "65537", "-1", "id", "10 * 10", "1.5", "'10'", "(SELECT 10)", "length(name)"} {
			out = append(out, strings.ReplaceAll(call, "N", n))
		}
		return out
	}
	funcs := map[string]string{"repeat": "repeat('x', N)", "lpad": "lpad(name, N, '0')", "rpad": "rpad(name, N, '0')"}
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
				if err == nil || !strings.Contains(err.Error(), name+": ") {
					t.Errorf("%s %q: got %v, want a %s refusal", d, sql, err, name)
				}
			}
			sql := "SELECT " + strings.ReplaceAll(call, "N", "65536") + " FROM users LIMIT 1"
			if _, err := analyze(t, d, sql); err != nil {
				t.Errorf("%s %q: %v", d, sql, err)
			}
		}
		refused := map[string]string{
			"SELECT repeat('x', 1073741823), repeat('y', 1073741823) LIMIT 1":                      "repeat: the length argument must be an integer literal at most 65536",
			"SELECT repeat(repeat('x', 65536), 16000) FROM users LIMIT 1":                          "repeat: arguments must be literals or columns",
			"SELECT lpad(repeat('x', 10), 10, '0') FROM users LIMIT 1":                             "lpad: arguments must be literals or columns",
			"SELECT lpad(name, 10, lower(name)) FROM users LIMIT 1":                                "lpad: arguments must be literals or columns",
			"SELECT repeat(name, 10) FROM users LIMIT 1":                                           "repeat: the string argument must be a string literal",
			"SELECT repeat('ab', 32769) FROM users LIMIT 1":                                        "repeat: the result would exceed 65536 bytes",
			"SELECT replace(repeat('x', 65536), 'x', repeat('y', 65536)) FROM users LIMIT 1":       "replace: the replacement must be a string literal of at most 1024 bytes",
			"SELECT replace(name, 'a', repeat('b', 10)) FROM users LIMIT 1":                        "replace: the replacement must be a string literal of at most 1024 bytes",
			"SELECT replace(name, 'a', name) FROM users LIMIT 1":                                   "replace: the replacement must be a string literal of at most 1024 bytes",
			"SELECT replace(name, 'a', '" + strings.Repeat("b", 1025) + "') FROM users LIMIT 1":    "replace: the replacement must be a string literal of at most 1024 bytes",
			"SELECT replace(repeat('x', 65536), 'x', 'yy') FROM users LIMIT 1":                     "the statement could build a value larger than 65536 bytes",
			"SELECT replace(name, 'a', '" + strings.Repeat("b", 65) + "') FROM users LIMIT 1":      "the statement could build a value wider than 64 columns",
			"SELECT replace(replace(name, 'a', 'bbbbbbbbb'), 'b', 'ccccccccc') FROM users LIMIT 1": "the statement could build a value wider than 64 columns",
		}
		for sql, msg := range refused {
			_, err := analyze(t, d, sql)
			if err == nil || !strings.Contains(err.Error(), msg) {
				t.Errorf("%s %q: got %v, want %q", d, sql, err, msg)
			}
		}
		for _, sql := range []string{
			"SELECT lpad(name, 10, '0') FROM users LIMIT 1",
			"SELECT rpad(name, 0, '0') FROM users LIMIT 1",
			"SELECT repeat('-', 3) FROM users LIMIT 1",
			"SELECT repeat('ab', 32768) FROM users LIMIT 1",
			"SELECT replace(name, 'a', 'b') FROM users LIMIT 1",
			"SELECT replace(replace(name, '-', ''), ' ', '') FROM users LIMIT 1",
			"SELECT replace(replace(name, 'a', 'bbbb'), 'b', '') FROM users LIMIT 1",
			"SELECT concat(repeat('-', 10), name) FROM users LIMIT 1",
			// Bounded by the width rule: 100 bytes, 16 columns, the input.
			"SELECT replace(lower(lpad(name, 100, 'x')), 'x', 'y') FROM users LIMIT 1",
			"SELECT replace(replace(name, 'a', 'bbbb'), 'b', 'cccc') FROM users LIMIT 1",
			"SELECT replace(name, (SELECT repeat('x', 10)), 'y') FROM users LIMIT 1",
		} {
			if _, err := analyze(t, d, sql); err != nil {
				t.Errorf("%s %q: %v", d, sql, err)
			}
		}
	}
	for _, sql := range []string{
		"SELECT regexp_replace(name, '', repeat('x', 10)) FROM users LIMIT 1",
		"SELECT replace(regexp_replace(name, '', '" + strings.Repeat("x", 40) + "', 'g'), 'x', 'yy') FROM users LIMIT 1",
		"SELECT translate(name, 'a', name) FROM users LIMIT 1",
	} {
		wantRefused(t, sqlclass.Postgres, sql)
	}
	for _, sql := range []string{
		"SELECT regexp_replace(name, 'a', 'b', 'g') FROM users LIMIT 1",
		"SELECT replace(translate(name, 'ab', 'cd'), 'c', 'e') FROM users LIMIT 1",
		"SELECT replace(regexp_replace(name, '', 'xx', 'g'), 'x', 'yy') FROM users LIMIT 1",
	} {
		if _, err := analyze(t, sqlclass.Postgres, sql); err != nil {
			t.Errorf("%q: %v", sql, err)
		}
	}
}

// printf-style formats pad to the width they are given: a literal width
// or precision is capped like a length argument, and one taken from an
// argument (*) or a format string that is not a literal is refused.
func TestAdvFormatWidthCap(t *testing.T) {
	funcs := map[sqlclass.Dialect][]string{
		sqlclass.Postgres: {"format"},
		sqlclass.SQLite:   {"format", "printf"},
	}
	for d, names := range funcs {
		for _, name := range names {
			refused := map[string]string{
				"('%1000000000s', 'x')":        "a width or precision exceeds 65536",
				"('%65537s', 'x')":             "a width or precision exceeds 65536",
				"('%-0000000001000000s', 'x')": "a width or precision exceeds 65536",
				"('%*s', 1000000000, 'x')":     "a width or precision taken from an argument (*)",
				"(name, 'x')":                  "the format string must be a literal",
				"('%' || '9999999s', 'x')":     "the format string must be a literal",
			}
			if d == sqlclass.SQLite {
				refused["('%.1000000000c', 'x')"] = "a width or precision exceeds 65536"
				refused["('%.*c', 1000000000, 'x')"] = "a width or precision taken from an argument (*)"
			} else {
				refused["('%1$1000000000s', 'x')"] = "a width or precision exceeds 65536"
				refused["(E'%\\061000000000s', 'x')"] = "the format string must be a literal"
			}
			for args, msg := range refused {
				sql := "SELECT " + name + args + " FROM users LIMIT 1"
				_, err := analyze(t, d, sql)
				if err == nil || !strings.Contains(err.Error(), name+": "+msg) {
					t.Errorf("%s %q: got %v, want %q", d, sql, err, msg)
				}
			}
			accepted := []string{"('%-10s|%5s', name, 'x')", "('%65536s', 'x')", "('100%% %s', name)", "('%s', name)"}
			if d == sqlclass.Postgres {
				accepted = append(accepted, "('%1$s %1$I', name)")
			} else {
				accepted = append(accepted, "('%.2f %lld', 1.5, 3)")
			}
			for _, args := range accepted {
				sql := "SELECT " + name + args + " FROM users LIMIT 1"
				if _, err := analyze(t, d, sql); err != nil {
					t.Errorf("%s %q: %v", d, sql, err)
				}
			}
		}
	}
	// MySQL FORMAT(x, d) formats a number (at most 30 decimals): no format
	// string to check.
	if _, err := analyze(t, sqlclass.MySQL, "SELECT format(id, 2) FROM users LIMIT 1"); err != nil {
		t.Errorf("mysql format: %v", err)
	}
}

// A concatenating aggregate builds one value from all its rows: an argument
// of more than 1 024 bytes, or wider than one column, is multiplied by the
// row count.
func TestAdvConcatAggregateSize(t *testing.T) {
	refused := map[sqlclass.Dialect][]string{
		sqlclass.Postgres: {
			"SELECT string_agg(repeat('x', 65536), '') FROM users LIMIT 1",
			"SELECT string_agg(lower(lpad(name, 65536, 'x')), ',') FROM users LIMIT 1",
			"SELECT array_agg(format('%65536s', name)) FROM users LIMIT 1",
			"SELECT json_agg(replace(name, 'a', 'bbbb')) FROM users LIMIT 1",
			"SELECT string_agg(regexp_replace(name, '', 'x', 'g'), '') FROM users LIMIT 1",
			"SELECT string_agg(name, repeat(',', 2000)) FROM users LIMIT 1",
			"SELECT string_agg((SELECT repeat('x', 2000)), ',') OVER () FROM users LIMIT 1",
			"SELECT string_agg(repeat('x', 2000), '') FROM users LIMIT 1",
			"SELECT string_agg(name || name, ',') FROM users LIMIT 1",
		},
		sqlclass.MySQL: {
			"SELECT group_concat(repeat('x', 65536)) FROM users LIMIT 1",
			"SELECT group_concat(space(65536) SEPARATOR '') FROM users LIMIT 1",
			"SELECT json_arrayagg(rpad(name, 65536, 'x')) FROM users LIMIT 1",
			"SELECT group_concat(name SEPARATOR '" + strings.Repeat(",", 1025) + "') FROM users LIMIT 1",
		},
		sqlclass.SQLite: {
			"SELECT group_concat(repeat('x', 65536), '') FROM users LIMIT 1",
			"SELECT json_group_array(zeroblob(65536)) FROM users LIMIT 1",
			"SELECT group_concat(printf('%65536s', name)) FROM users LIMIT 1",
		},
	}
	accepted := map[sqlclass.Dialect][]string{
		sqlclass.Postgres: {
			"SELECT string_agg(name, ',') FROM users LIMIT 1",
			"SELECT string_agg(replace(name, '-', ''), ',') FROM users LIMIT 1",
			"SELECT max(repeat('x', 10)) FROM users LIMIT 1",
			"SELECT string_agg(name, repeat(',', 1000)) FROM users LIMIT 1",
		},
		sqlclass.MySQL:  {"SELECT group_concat(name) FROM users LIMIT 1", "SELECT group_concat(name SEPARATOR ', ') FROM users LIMIT 1"},
		sqlclass.SQLite: {"SELECT group_concat(name, ','), json_group_array(name) FROM users LIMIT 1"},
	}
	for d, list := range refused {
		for _, sql := range list {
			_, err := analyze(t, d, sql)
			if err == nil || !strings.Contains(err.Error(), ": an argument that may exceed 1024 bytes is not allowed") {
				t.Errorf("%s %q: got %v, want a concatenating aggregate refusal", d, sql, err)
			}
		}
	}
	for d, list := range accepted {
		for _, sql := range list {
			if _, err := analyze(t, d, sql); err != nil {
				t.Errorf("%s %q: %v", d, sql, err)
			}
		}
	}
}

// A column keeps its width in the queries that read it: a derived table, a
// CTE or a set operation does not hide a large value.
func TestAdvGrownColumn(t *testing.T) {
	b := strings.Repeat("b", 1024)
	aggs := map[sqlclass.Dialect]string{
		sqlclass.Postgres: "string_agg(x, '')",
		sqlclass.MySQL:    "group_concat(x SEPARATOR '')",
		sqlclass.SQLite:   "group_concat(x, '')",
	}
	for d, agg := range aggs {
		refused := map[string]string{
			"SELECT replace(y, 'b', '" + b + "') FROM (SELECT replace(x, 'a', '" + b + "') AS y FROM (SELECT repeat('a', 65536) AS x) t) u LIMIT 1": "the statement could build a value larger than 65536 bytes",
			"WITH t AS (SELECT repeat('a', 65536) AS x) SELECT replace(x, 'a', 'bb') FROM t LIMIT 1":                                                "the statement could build a value larger than 65536 bytes",
		}
		for _, sql := range []string{
			"SELECT " + agg + " FROM (SELECT repeat('a', 65536) AS x FROM users) t LIMIT 1",
			"WITH c AS (SELECT repeat('a', 65536) AS x FROM users) SELECT " + agg + " FROM c LIMIT 1",
			"SELECT " + agg + " FROM (SELECT y AS x FROM (SELECT lpad(name, 65536, 'a') AS y FROM users) t) u LIMIT 1",
			"SELECT " + agg + " FROM (SELECT name AS x FROM users UNION ALL SELECT repeat('a', 65536) FROM users) t LIMIT 1",
			"SELECT " + agg + " FROM (SELECT * FROM (SELECT repeat('a', 65536) AS x FROM users) t) u LIMIT 1",
			"SELECT " + agg + " FROM (SELECT coalesce(lower(y), '') AS x FROM (SELECT repeat('a', 65536) AS y FROM users) t) u LIMIT 1",
		} {
			refused[sql] = "an argument that may exceed 1024 bytes is not allowed"
		}
		for sql, msg := range refused {
			_, err := analyze(t, d, sql)
			if err == nil || !strings.Contains(err.Error(), msg) {
				t.Errorf("%s %q: got %v, want %q", d, sql, err, msg)
			}
		}
		for _, sql := range []string{
			"SELECT " + agg + " FROM (SELECT name AS x FROM users) t LIMIT 1",
			"SELECT replace(x, '-', '') FROM (SELECT repeat('a-', 100) AS x) t LIMIT 1",
			"SELECT x FROM (SELECT repeat('a', 65536) AS x) t LIMIT 1",
			"SELECT lpad(x, 10, '0') FROM (SELECT repeat('a', 65536) AS x) t LIMIT 1",
		} {
			if _, err := analyze(t, d, sql); err != nil {
				t.Errorf("%s %q: %v", d, sql, err)
			}
		}
	}
}

// Every value carries a width estimate (the bytes its literals and length
// arguments contribute, and the number of column-width inputs it
// combines): reusing a value through CTE or derived-table layers multiplies
// it, whatever the operator (||, concat, format), and the bound refuses the
// layer that would pass 65 536 bytes or 64 columns.
func TestAdvValueWidth(t *testing.T) {
	cat := func(x string, n int) string { return strings.TrimSuffix(strings.Repeat(x+"||", n), "||") }
	concat := func(x string, n int) string {
		return "concat(" + strings.TrimSuffix(strings.Repeat(x+", ", n), ", ") + ")"
	}
	lit32 := "'" + strings.Repeat("x", 32) + "'"
	big := "lpad('x', 40000, 'x')"
	all := []sqlclass.Dialect{sqlclass.MySQL, sqlclass.Postgres, sqlclass.SQLite}
	// MySQL refuses || (OR or concatenation, depending on sql_mode).
	pipes := []sqlclass.Dialect{sqlclass.Postgres, sqlclass.SQLite}
	formats := []sqlclass.Dialect{sqlclass.Postgres, sqlclass.SQLite}
	refused := map[string][]sqlclass.Dialect{
		// 32 MiB per cell with || over three layers.
		"WITH a AS (SELECT lpad('x',65536,'x') AS v), b AS (SELECT " + cat("v", 8) + " AS w FROM a), c AS (SELECT " + cat("w", 8) + " AS z FROM b) SELECT " + cat("z", 8) + " FROM c LIMIT 1": pipes,
		// The same with nested concat over derived tables.
		"SELECT " + concat("z", 8) + " FROM (SELECT " + concat("w", 8) + " AS z FROM (SELECT " + concat("v", 8) + " AS w FROM (SELECT lpad('x', 65536, 'x') AS v) a) b) c LIMIT 1": all,
		// No size function: a 32-byte literal, eight copies per layer, five
		// layers (1 MiB).
		"WITH a AS (SELECT " + lit32 + " AS v), b AS (SELECT " + cat("v", 8) + " AS v FROM a), c AS (SELECT " + cat("v", 8) + " AS v FROM b), d AS (SELECT " + cat("v", 8) + " AS v FROM c), e AS (SELECT " + cat("v", 8) + " AS v FROM d) SELECT " + cat("v", 8) + " FROM e LIMIT 1": pipes,
		"SELECT " + concat("v", 8) + " FROM (SELECT " + concat("v", 8) + " AS v FROM (SELECT " + concat("v", 8) + " AS v FROM (SELECT " + concat("v", 8) + " AS v FROM (SELECT " + lit32 + " AS v) a) b) c) d LIMIT 1":                                                                all,
		// A position referenced many times, two arguments, two widths.
		"SELECT format('%1$s%1$s%1$s%1$s', lpad('x', 65536, 'x')) LIMIT 1": formats,
		"SELECT format('%s%s', " + big + ", " + big + ") LIMIT 1":          formats,
		"SELECT format('%65536s%65536s', 'a', 'b') LIMIT 1":                formats,
		"SELECT format('%L', " + big + ") LIMIT 1":                         {sqlclass.Postgres},
		"SELECT printf('%s%s', " + big + ", " + big + ") LIMIT 1":          {sqlclass.SQLite},
		// Two values joined, a separator repeated, a padding cast, an
		// escaping function.
		"SELECT " + big + " || " + big + " LIMIT 1":                                                     pipes,
		"SELECT concat_ws(lpad('x', 30000, 'x'), name, name, name, name) FROM users LIMIT 1":            all,
		"SELECT CAST('x' AS char(100000)) LIMIT 1":                                                      {sqlclass.Postgres},
		"SELECT hex(" + big + ") LIMIT 1":                                                               all,
		"SELECT to_json(to_json(to_json(to_json(to_json(to_json(to_json(name))))))) FROM users LIMIT 1": {sqlclass.Postgres},
		// A comparison operand and a function argument are bounded too.
		"SELECT id FROM users WHERE name = concat(" + big + ", " + big + ") LIMIT 1": all,
		"SELECT length(concat(" + big + ", " + big + ")) LIMIT 1":                    all,
		// A derived column reused 65 times in one concatenation.
		"SELECT " + concat("x", 65) + " FROM (SELECT name AS x FROM users) t LIMIT 1": all,
		"SELECT " + cat("x", 65) + " FROM (SELECT name AS x FROM users) t LIMIT 1":    pipes,
	}
	for sql, dialects := range refused {
		for _, d := range dialects {
			_, err := analyze(t, d, sql)
			if err == nil || !strings.Contains(err.Error(), "the statement could build a value") {
				t.Errorf("%s %q: got %v, want a size bound refusal", d, sql, err)
			}
		}
	}
	accepted := map[string][]sqlclass.Dialect{
		"SELECT lpad(a, 10, '0') || '-' || b FROM (SELECT name AS a, name AS b FROM users) t LIMIT 1":                                    pipes,
		"SELECT name||name||name FROM users LIMIT 1":                                                                                     pipes,
		"SELECT " + cat("x", 64) + " FROM (SELECT name AS x FROM users) t LIMIT 1":                                                       pipes,
		"WITH a AS (SELECT " + lit32 + " AS v), b AS (SELECT " + cat("v", 8) + " AS v FROM a) SELECT " + cat("v", 8) + " FROM b LIMIT 1": pipes,
		"SELECT concat(lpad(a, 10, '0'), '-', b) FROM (SELECT name AS a, name AS b FROM users) t LIMIT 1":                                all,
		"SELECT " + concat("x", 64) + " FROM (SELECT name AS x FROM users) t LIMIT 1":                                                    all,
		"SELECT lpad('x', 65536, 'x') LIMIT 1":                                                                                           all,
		"SELECT hex(name), coalesce(name, lpad('x', 65536, 'x')) FROM users LIMIT 1":                                                     all,
		"SELECT json_build_object('a', name, 'b', name), to_json(name), CAST(name AS char(10)) FROM users LIMIT 1":                       {sqlclass.Postgres},
		"SELECT format('%1$s-%1$s', name), format('%65536s', 'x') FROM users LIMIT 1":                                                    formats,
	}
	for sql, dialects := range accepted {
		for _, d := range dialects {
			if _, err := analyze(t, d, sql); err != nil {
				t.Errorf("%s %q: %v", d, sql, err)
			}
		}
	}
	// A recursive CTE whose column grows on every pass.
	for _, d := range all {
		for _, sql := range []string{
			"WITH RECURSIVE r(n, s) AS (SELECT 1, 'a' UNION ALL SELECT n + 1, concat(s, 'a') FROM r WHERE n < 10) SELECT s FROM r LIMIT 10",
			"WITH RECURSIVE r(n, s) AS (SELECT 1, name FROM users UNION ALL SELECT n + 1, concat(s, '-') FROM r WHERE n < 30) SELECT s FROM r LIMIT 10",
		} {
			_, err := analyze(t, d, sql)
			if err == nil || !strings.Contains(err.Error(), "a recursive CTE builds growing values") {
				t.Errorf("%s %q: got %v, want a growing recursive CTE refusal", d, sql, err)
			}
		}
		for _, sql := range []string{
			"WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r WHERE n < 10) SELECT n FROM r LIMIT 10",
			"WITH RECURSIVE r(n, s) AS (SELECT 1, 'a' UNION ALL SELECT n + 1, 'abc' FROM r WHERE n < 10) SELECT s FROM r LIMIT 10",
		} {
			if _, err := analyze(t, d, sql); err != nil {
				t.Errorf("%s %q: %v", d, sql, err)
			}
		}
	}
}
