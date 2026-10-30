package sqlast

import (
	"errors"
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

// Writes whose values come back (RETURNING, data-modifying CTEs) or that
// store a query's rows (INSERT ... SELECT) are analysed like reads: every
// returned column is resolved to its base columns and masked, anything
// that cannot be resolved is refused.

func analyzeWrite(t *testing.T, d sqlclass.Dialect, sql string) (*Analysis, error) {
	t.Helper()
	st, err := ParseWrite(d, sql)
	if err != nil {
		return nil, err
	}
	return Analyze(st, testEnv(true))
}

func wantWriteRefused(t *testing.T, d sqlclass.Dialect, sql string) error {
	t.Helper()
	_, err := analyzeWrite(t, d, sql)
	var r *sqlclass.Refusal
	if !errors.As(err, &r) {
		t.Errorf("%s %q: got %v, want a refusal", d, sql, err)
	}
	return err
}

func TestWriteReturningMasked(t *testing.T) {
	pg, my, lite := sqlclass.Postgres, sqlclass.MySQL, sqlclass.SQLite
	cases := []struct {
		d     sqlclass.Dialect
		sql   string
		masks []string
	}{
		// PostgreSQL RETURNING.
		{pg, "UPDATE users SET status = 'x' WHERE id = 1 RETURNING id, email", []string{"", "partial"}},
		{pg, "UPDATE users SET status = 'x' WHERE id = 1 RETURNING email AS e", []string{"partial"}},
		{pg, "UPDATE users AS u SET status = 'x' WHERE u.id = 1 RETURNING u.email AS id, u.id AS email", []string{"partial", ""}},
		{pg, "DELETE FROM users WHERE id = 1 RETURNING *", []string{"", "partial", "", "redact", ""}},
		{pg, "DELETE FROM users u WHERE id = 1 RETURNING u.*", []string{"", "partial", "", "redact", ""}},
		{pg, "UPDATE users u SET status = 'x' FROM orders o WHERE o.user_id = u.id RETURNING o.email, u.email AS ue", []string{"", "partial"}},
		{pg, "DELETE FROM users u USING contacts c WHERE c.id = u.id RETURNING c.email AS ce, u.id", []string{"email", ""}},
		{pg, "UPDATE users SET status = 'x' WHERE id = 1 RETURNING (SELECT email FROM contacts LIMIT 1) AS m", []string{"email"}},
		{pg, "UPDATE notes SET v = 'x' RETURNING v", []string{""}},
		{pg, "UPDATE users SET email = NULL, salary = DEFAULT WHERE id = 1 RETURNING email, salary", []string{"partial", "redact"}},
		{pg, "INSERT INTO users (id, status) VALUES (1, 'a') RETURNING email AS x, status", []string{"partial", ""}},
		{pg, "INSERT INTO users AS u (id, email) VALUES (1, NULL) ON CONFLICT (id) DO UPDATE SET status = excluded.status WHERE u.id > 0 RETURNING u.email", []string{"partial"}},
		{pg, "INSERT INTO users (id) VALUES (1) ON CONFLICT DO NOTHING RETURNING salary", []string{"redact"}},
		{pg, "INSERT INTO users DEFAULT VALUES RETURNING email", []string{"partial"}},
		{pg, "INSERT INTO notes (id, v) SELECT id, status FROM users WHERE id < 3 RETURNING v", []string{""}},
		// MariaDB RETURNING (INSERT, REPLACE, DELETE).
		{my, "DELETE FROM users WHERE id = 1 RETURNING email AS x, id", []string{"partial", ""}},
		{my, "DELETE FROM users WHERE id = 1 ORDER BY id LIMIT 1 RETURNING *", []string{"", "partial", "", "redact", ""}},
		{my, "INSERT INTO users (id, status) VALUES (1, 'a') RETURNING email, status", []string{"partial", ""}},
		{my, "INSERT IGNORE users (id, status) VALUE (1, 'a'), (2, DEFAULT) RETURNING `email`", []string{"partial"}},
		{my, "INSERT INTO users SET id = 1, status = 'a' RETURNING email", []string{"partial"}},
		{my, "INSERT INTO users (id) VALUES (1) ON DUPLICATE KEY UPDATE status = 'b' RETURNING salary AS s", []string{"redact"}},
		{my, "REPLACE INTO users (id, status) VALUES (1, 'a') RETURNING *", []string{"", "partial", "", "redact", ""}},
		{my, "INSERT INTO notes (id, v) SELECT id, status FROM users WHERE id < 3 RETURNING v", []string{""}},
		// SQLite RETURNING.
		{lite, "UPDATE users SET status = 'x' WHERE id = 1 RETURNING email", []string{"partial"}},
		{lite, "INSERT OR REPLACE INTO users (id, status) VALUES (1, 'a') RETURNING email", []string{"partial"}},
		{lite, "DELETE FROM users WHERE id = 1 RETURNING salary AS s", []string{"redact"}},
		// Data-modifying CTEs: the outer SELECT is a read of the RETURNING
		// columns.
		{pg, "WITH u AS (UPDATE users SET status = 'x' WHERE id = 1 RETURNING email AS e) SELECT e AS z FROM u", []string{"partial"}},
		{pg, "WITH u(a, b) AS (UPDATE users SET status = 'x' WHERE id = 1 RETURNING id, email) SELECT b AS id, a AS email FROM u", []string{"partial", ""}},
		{pg, "WITH d AS (DELETE FROM users WHERE id = 1 RETURNING *) SELECT * FROM d", []string{"", "partial", "", "redact", ""}},
		{pg, "WITH i AS (INSERT INTO notes (id, v) VALUES (1, 'x') RETURNING v) SELECT v FROM i", []string{""}},
		{pg, "WITH u AS (UPDATE users SET status = 'x' WHERE id = 1 RETURNING email) SELECT count(*) FROM u", []string{""}},
		{pg, "WITH u AS (UPDATE users SET status = 'x' WHERE id = 1 RETURNING email) SELECT x.email FROM u x JOIN orders o ON o.id = 1", []string{"partial"}},
		{pg, "WITH d AS (DELETE FROM notes WHERE id = 1) SELECT email FROM users LIMIT 1", []string{"partial"}},
		{pg, "WITH u AS (UPDATE users SET status = 'x' RETURNING email) UPDATE notes SET v = 'y' RETURNING (SELECT email FROM u LIMIT 1) AS m", []string{"partial"}},
	}
	for _, c := range cases {
		a, err := analyzeWrite(t, c.d, c.sql)
		if err != nil {
			t.Errorf("%s %q: %v", c.d, c.sql, err)
			continue
		}
		if len(a.Outputs) != len(c.masks) {
			t.Errorf("%s %q: %d outputs, want %d", c.d, c.sql, len(a.Outputs), len(c.masks))
			continue
		}
		for i, o := range a.Outputs {
			if o.Mask != c.masks[i] {
				t.Errorf("%s %q: output %d (%s) mask %q, want %q", c.d, c.sql, i, o.Label, o.Mask, c.masks[i])
			}
		}
	}
}

// A RETURNING list or the outer SELECT of a data-modifying CTE that
// transforms, orders or filters a masked column is refused, as in a read;
// so is anything the analysis cannot resolve.
func TestWriteReturningRefused(t *testing.T) {
	pg, my, lite := sqlclass.Postgres, sqlclass.MySQL, sqlclass.SQLite
	for _, c := range []struct {
		d   sqlclass.Dialect
		sql string
	}{
		// Transforming a masked column.
		{pg, "UPDATE users SET status = 'x' WHERE id = 1 RETURNING upper(email)"},
		{pg, "UPDATE users SET status = 'x' RETURNING email || ''"},
		{pg, "UPDATE users SET status = 'x' RETURNING salary + 0 AS s"},
		{pg, "DELETE FROM users WHERE id = 1 RETURNING substr(email, 1, 1) AS c"},
		{pg, "DELETE FROM users WHERE id = 1 RETURNING CASE WHEN email LIKE 'a%' THEN 1 END AS f"},
		{pg, "UPDATE users SET status = 'x' RETURNING (SELECT lower(email) FROM contacts LIMIT 1)"},
		{my, "DELETE FROM users WHERE id = 1 RETURNING concat(email, '') AS x"},
		{my, "INSERT INTO notes (id, v) VALUES (1, 'x') RETURNING (SELECT lower(email) FROM users LIMIT 1) AS y"},
		{my, "REPLACE INTO users (id, status) VALUES (1, 'a') RETURNING length(email)"},
		{lite, "UPDATE users SET status = 'x' WHERE id = 1 RETURNING email || '' AS x"},
		// Whole rows, attribute notation, PostgreSQL 18 old/new.
		{pg, "UPDATE users SET status = 'x' RETURNING users"},
		{pg, "UPDATE users SET status = 'x' RETURNING users.row_to_json"},
		{pg, "UPDATE users u SET status = 'x' RETURNING row_to_json(u)"},
		{pg, "UPDATE users SET status = 'x' RETURNING old.email"},
		{pg, "UPDATE users SET status = 'x' RETURNING WITH (OLD AS o) o.email"},
		// Functions outside the allowlist, anywhere in the statement.
		{pg, "UPDATE users SET status = 'x' RETURNING pg_read_file('x')"},
		{pg, "UPDATE notes SET v = myfunc(id) RETURNING v"},
		{pg, "DELETE FROM notes WHERE myfunc(id) RETURNING id"},
		// Data-modifying CTEs: the outer SELECT follows the read rules; a
		// k-anonymity check would run the write again.
		{pg, "WITH u AS (UPDATE users SET status = 'x' RETURNING email AS e) SELECT upper(e) FROM u"},
		{pg, "WITH u AS (UPDATE users SET status = 'x' RETURNING email AS e) SELECT e FROM u ORDER BY e"},
		{pg, "WITH u AS (UPDATE users SET status = 'x' RETURNING email AS e) SELECT e FROM u GROUP BY e"},
		{pg, "WITH u AS (UPDATE users SET status = 'x' RETURNING email AS e) SELECT DISTINCT e FROM u"},
		{pg, "WITH u AS (UPDATE users SET status = 'x' RETURNING email AS e) SELECT 1 FROM u WHERE e = 'a@x.example'"},
		{pg, "UPDATE users SET status = 'x' RETURNING (SELECT max(email) FROM contacts) AS m"},
		{pg, "UPDATE users SET status = 'x' RETURNING max(id)"},
		{pg, "WITH u AS (UPDATE users SET status = 'x' RETURNING id) SELECT id FROM users WHERE email LIKE 'a%'"},
		{pg, "WITH u AS (UPDATE users SET status = 'x' RETURNING email AS e) SELECT e FROM u UNION SELECT 'a@x.example'"},
		{pg, "WITH u AS (UPDATE users SET status = 'x' RETURNING id) SELECT email FROM u"},
		{pg, "WITH u AS (DELETE FROM users WHERE id = 1) SELECT id FROM u"},
		{pg, "WITH u AS (UPDATE u SET status = 'x' RETURNING id) SELECT id FROM u"},
		{pg, "SELECT * FROM (WITH u AS (UPDATE users SET status = 'x' RETURNING email) SELECT email FROM u) s"},
		{pg, "WITH u AS (MERGE INTO users USING orders o ON o.id = users.id WHEN MATCHED THEN DELETE RETURNING email) SELECT * FROM u"},
		{my, "WITH u AS (DELETE FROM users RETURNING email) SELECT * FROM u"},
		// Unsupported syntax is refused, never guessed.
		{pg, "MERGE INTO users USING orders o ON o.id = users.id WHEN MATCHED THEN DELETE RETURNING email"},
		{pg, "UPDATE users SET (status, name) = (SELECT status, name FROM users u2 WHERE u2.id = 1) RETURNING id"},
		{pg, "UPDATE users SET email.f = NULL RETURNING id"},
		{pg, "UPDATE ONLY users SET status = 'x' RETURNING email"},
		{pg, "DELETE FROM users WHERE CURRENT OF c RETURNING email"},
		{my, "DELETE users FROM users JOIN orders o ON o.user_id = users.id RETURNING users.email"},
		{my, "UPDATE users JOIN orders o ON o.user_id = users.id SET users.status = 'x' RETURNING users.email"},
		{my, "INSERT INTO users (id) VALUES (1) ON DUPLICATE KEY UPDATE status = VALUES(status) RETURNING email"},
		{pg, "UPDATE users SET status = 'x' RETURNING email; SELECT 1"},
	} {
		wantWriteRefused(t, c.d, c.sql)
	}
}

// A write must not copy a masked column into another column, nor store in
// a masked column a value the agent chose: resolved by provenance, through
// aliases, alias column lists, CTEs and derived tables, which a check by
// column name cannot follow.
func TestWriteCopiesAndPlantsRefused(t *testing.T) {
	pg, my := sqlclass.Postgres, sqlclass.MySQL
	for _, c := range []struct {
		d    sqlclass.Dialect
		sql  string
		want string
	}{
		{pg, "INSERT INTO notes (id, v) SELECT i, x FROM users AS u(i, x, n, s, st)", "stores values of PII column"},
		{pg, "INSERT INTO notes (id, v) SELECT i, x FROM users AS u(i, x, n, s, st) RETURNING v", "stores values of PII column"},
		{pg, "WITH s(a, b) AS (SELECT id, email FROM users) INSERT INTO notes SELECT a, b FROM s", "stores values of PII column"},
		{pg, "INSERT INTO notes SELECT * FROM contacts", "stores values of PII column"},
		{pg, "INSERT INTO notes (v, id) SELECT max(email), 1 FROM users", "stores values of PII column"},
		{pg, "INSERT INTO notes (id, v) SELECT id, status FROM users UNION ALL SELECT id, email FROM contacts", "stores values of PII column"},
		{pg, "INSERT INTO notes (id, v) VALUES (1, (SELECT x FROM users AS u(i, x, n, s, st) LIMIT 1)) RETURNING id", "stores values of PII column"},
		{pg, "UPDATE notes SET v = (SELECT x FROM users AS u(i, x, n, s, st) LIMIT 1) RETURNING id", "stores values of PII column"},
		{pg, "UPDATE notes n SET v = c.email FROM contacts c WHERE c.id = n.id RETURNING n.id", "stores values of PII column"},
		{pg, "WITH d AS (DELETE FROM users WHERE id = 1 RETURNING email AS e) INSERT INTO notes (id, v) SELECT 1, e FROM d", "stores values of PII column"},
		{pg, "INSERT INTO notes (id, v) VALUES (1, 'x') ON CONFLICT (id) DO UPDATE SET v = (SELECT email FROM contacts LIMIT 1)", "stores values of PII column"},
		{my, "INSERT INTO notes (id, v) SELECT id, x FROM (SELECT id, email AS x FROM users) d", "stores values of PII column"},
		{my, "INSERT INTO notes (id, v) WITH s AS (SELECT id, email FROM users) SELECT * FROM s", "stores values of PII column"},
		{my, "REPLACE INTO notes (id, v) SELECT id, email FROM contacts", "stores values of PII column"},
		// Planted values: a masked target receives only NULL or DEFAULT.
		{pg, "INSERT INTO users (id, email) SELECT id, 'v@x.example' FROM orders", "a value the agent chose"},
		{pg, "INSERT INTO users (id, salary) SELECT id, total FROM orders", "a value the agent chose"},
		{pg, "INSERT INTO users (id, email) SELECT id, NULL FROM orders UNION ALL SELECT 1, 'v@x.example'", "a value the agent chose"},
		{pg, "INSERT INTO users SELECT id, user_id, 'n', total, 's' FROM orders", "a value the agent chose"},
		{pg, "INSERT INTO users (id, email) VALUES (1, 'v@x.example') RETURNING id", "a value the agent chose"},
		{pg, "INSERT INTO users VALUES (1, NULL, 'n', 5, 's') RETURNING id", "a value the agent chose"},
		{pg, "UPDATE users SET salary = 5 RETURNING id", "a value the agent chose"},
		{pg, "INSERT INTO users (id) VALUES (1) ON CONFLICT (id) DO UPDATE SET email = excluded.status RETURNING id", "a value the agent chose"},
		{my, "INSERT INTO users SET id = 1, email = 'v@x.example' RETURNING id", "a value the agent chose"},
		{my, "INSERT INTO users (id, email) SELECT id, email FROM contacts", "stores values of PII column"},
	} {
		err := wantWriteRefused(t, c.d, c.sql)
		if err != nil && !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s %q: %v, want %q", c.d, c.sql, err, c.want)
		}
		if err != nil && strings.Contains(err.Error(), "v@x") {
			t.Errorf("%s %q: the refusal quotes a value: %v", c.d, c.sql, err)
		}
	}
	for _, c := range []struct {
		d   sqlclass.Dialect
		sql string
	}{
		// The write's own clauses (which rows, from where) are the human's
		// to approve, as the affected-row count already reveals them.
		{pg, "INSERT INTO notes (id, v) SELECT id, status FROM users WHERE email = 'a@x.example'"},
		{pg, "INSERT INTO notes SELECT id, status FROM users"},
		{pg, "INSERT INTO users (id, email) SELECT id, NULL FROM orders"},
		{pg, "INSERT INTO users (id, email) (SELECT id, NULL FROM orders)"},
		{pg, "INSERT INTO notes (id, v) SELECT count(email), 'x' FROM users"},
		{pg, "INSERT INTO users VALUES (1, NULL, 'n', DEFAULT, 's') RETURNING id"},
		{pg, "DELETE FROM users WHERE email = 'a@x.example' RETURNING id"},
		{pg, "UPDATE users SET status = 'x' WHERE email LIKE 'a%' RETURNING id"},
		{my, "INSERT INTO notes (id, v) SELECT id, status FROM users ORDER BY email LIMIT 3"},
		{my, "INSERT INTO notes (id, v) WITH s AS (SELECT id, status FROM users) SELECT * FROM s"},
	} {
		if _, err := analyzeWrite(t, c.d, c.sql); err != nil {
			t.Errorf("%s %q: %v", c.d, c.sql, err)
		}
	}
}

// Parse keeps refusing writes and data-modifying CTEs: only ParseWrite
// reads them.
func TestParseRefusesWrites(t *testing.T) {
	for _, q := range []string{
		"UPDATE users SET status = 'x' RETURNING email",
		"WITH u AS (UPDATE users SET status = 'x' RETURNING email) SELECT * FROM u",
	} {
		if _, err := Parse(sqlclass.Postgres, q); err == nil {
			t.Errorf("Parse accepted %q", q)
		}
	}
	if _, err := ParseWrite(sqlclass.Postgres, "SELECT 1"); err == nil {
		t.Error("ParseWrite accepted a plain SELECT")
	}
}

func TestNeedsWriteAnalysis(t *testing.T) {
	pg, my := sqlclass.Postgres, sqlclass.MySQL
	for _, c := range []struct {
		d    sqlclass.Dialect
		sql  string
		want bool
	}{
		{pg, "UPDATE users SET status = 'x' RETURNING id", true},
		{my, "DELETE FROM users RETURNING id", true},
		{pg, "WITH u AS (UPDATE users SET status = 'x' RETURNING id) SELECT id FROM u", true},
		{pg, "WITH u AS (DELETE FROM users) (SELECT 1)", true},
		{pg, "INSERT INTO notes SELECT * FROM users", true},
		{pg, "INSERT INTO notes (SELECT * FROM users)", true},
		{my, "REPLACE INTO notes SELECT * FROM users", true},
		{my, "INSERT INTO notes TABLE users", true},
		{pg, "WITH s AS (SELECT 1) INSERT INTO notes VALUES (1, 'x')", true},
		{pg, "INSERT INTO notes VALUES (1, (SELECT email FROM users LIMIT 1))", true},
		{pg, "UPDATE users SET status = 'x'", false},
		{pg, "UPDATE users SET status = 'returning'", false},
		{pg, "INSERT INTO notes VALUES (1, 'x')", false},
		{pg, "DELETE FROM notes WHERE id IN (SELECT id FROM users)", false},
		{my, "WITH c AS (SELECT 1 AS id) UPDATE notes SET v = 'x' WHERE id IN (SELECT id FROM c)", false},
		{pg, `UPDATE users SET "returning" = 'x'`, false},
	} {
		if got := NeedsWriteAnalysis(c.d, c.sql); got != c.want {
			t.Errorf("%s %q: %v, want %v", c.d, c.sql, got, c.want)
		}
	}
}

func FuzzParseWriteNoPanic(f *testing.F) {
	for _, s := range []string{
		"UPDATE users SET status = 'x' WHERE id = 1 RETURNING email AS e",
		"WITH u AS (UPDATE users SET status = 'x' RETURNING email) SELECT * FROM u",
		"INSERT INTO users AS u (id, email) VALUES (1, NULL) ON CONFLICT (id) DO UPDATE SET status = excluded.status RETURNING *",
		"INSERT INTO notes (id, v) SELECT i, x FROM users AS u(i, x, n, s, st)",
		"DELETE FROM users u USING contacts c WHERE c.id = u.id RETURNING c.email",
		"REPLACE INTO users SET id = 1, status = 'a' RETURNING email",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, sql string) {
		for _, d := range []sqlclass.Dialect{sqlclass.MySQL, sqlclass.Postgres, sqlclass.SQLite} {
			NeedsWriteAnalysis(d, sql)
			if st, err := ParseWrite(d, sql); err == nil {
				_, _ = Analyze(st, testEnv(true))
			}
		}
	})
}
