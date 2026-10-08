package sqlast

import (
	"errors"
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

type fakeCatalog map[string][]string // "db.table" -> columns

func (f fakeCatalog) Lookup(parts []string) ([]Table, error) {
	var out []Table
	for key, cols := range f {
		db, name, _ := strings.Cut(key, ".")
		switch {
		case len(parts) == 1 && fold(name) == parts[0],
			len(parts) == 2 && fold(db) == parts[0] && fold(name) == parts[1]:
			out = append(out, Table{DB: db, Name: name, Columns: cols})
		}
	}
	return out, nil
}

var testCatalog = fakeCatalog{
	"app.users":    {"id", "email", "name", "salary", "status"},
	"app.orders":   {"id", "user_id", "email", "total"},
	"app.contacts": {"id", "email"},
}

var testRules = map[string]string{
	"app.users.email":    "partial",
	"app.users.salary":   "redact",
	"app.contacts.email": "hash",
}

func testEnv(masking bool) Env {
	return Env{
		Catalog: testCatalog,
		Rule: func(s Source) (string, bool) {
			m, ok := testRules[s.DB+"."+s.Table+"."+s.Column]
			return m, ok
		},
		Masking: masking,
		Token: func(lit string) (string, bool, bool) {
			if !strings.HasPrefix(lit, "tok_") {
				return "", false, false
			}
			if lit == "tok_known" {
				return "a@b.example", true, true
			}
			return "", true, false
		},
	}
}

func analyze(t *testing.T, d sqlclass.Dialect, sql string) (*Analysis, error) {
	t.Helper()
	st, err := Parse(d, sql)
	if err != nil {
		t.Fatalf("Parse(%q): %v", sql, err)
	}
	return Analyze(st, testEnv(true))
}

func TestProvenanceMasksResolvedSource(t *testing.T) {
	cases := []struct {
		sql   string
		masks []string // per output
	}{
		{"SELECT email FROM users LIMIT 1", []string{"partial"}},
		{"SELECT email AS x FROM users LIMIT 1", []string{"partial"}},
		{"SELECT u.email AS id, id AS email FROM users u LIMIT 1", []string{"partial", ""}},
		{"SELECT x FROM (SELECT email AS x FROM users) s LIMIT 1", []string{"partial"}},
		{"WITH c(z) AS (SELECT email FROM users) SELECT z FROM c LIMIT 1", []string{"partial"}},
		{"SELECT name FROM users UNION SELECT email FROM users LIMIT 1", []string{"partial"}},
		{"SELECT (SELECT max(email) FROM users) AS m LIMIT 1", []string{"partial"}},
		{"SELECT * FROM users LIMIT 1", []string{"", "partial", "", "redact", ""}},
		{"SELECT o.email, u.email FROM orders o JOIN users u ON u.id = o.user_id LIMIT 1", []string{"", "partial"}},
		{"SELECT sum(salary) AS s FROM users LIMIT 1", []string{"redact"}},
		{"SELECT count(email) FROM users LIMIT 1", []string{""}},
		{"SELECT email FROM contacts LIMIT 1", []string{"hash"}},
		{"SELECT email FROM users UNION SELECT email FROM contacts LIMIT 1", []string{"redact"}},
		{"SELECT id FROM users JOIN contacts USING (id) LIMIT 1", []string{""}},
		{"SELECT * FROM users JOIN contacts USING (email) LIMIT 1", []string{"redact", "", "", "redact", "", ""}},
	}
	for _, c := range cases {
		a, err := analyze(t, sqlclass.Postgres, c.sql)
		if err != nil {
			t.Errorf("%q: %v", c.sql, err)
			continue
		}
		if len(a.Outputs) != len(c.masks) {
			t.Errorf("%q: %d outputs, want %d", c.sql, len(a.Outputs), len(c.masks))
			continue
		}
		for i, o := range a.Outputs {
			if o.Mask != c.masks[i] {
				t.Errorf("%q: output %d (%s) mask %q, want %q", c.sql, i, o.Label, o.Mask, c.masks[i])
			}
		}
	}
}

func TestPIIUsageRefused(t *testing.T) {
	refused := []string{
		// Expressions over a PII column, in any clause.
		"SELECT lower(email) FROM users LIMIT 1",
		"SELECT CASE WHEN email LIKE 'a%' THEN 1 ELSE 0 END FROM users LIMIT 1",
		"SELECT email = 'x' AS f FROM users LIMIT 1",
		"SELECT count(CASE WHEN email LIKE 'a%' THEN 1 END) FROM users LIMIT 1",
		"SELECT length(x) FROM (SELECT email AS x FROM users) s LIMIT 1",
		"WITH c AS (SELECT substr(email, 1, 1) AS ch FROM users) SELECT ch FROM c LIMIT 1",
		"SELECT id FROM users WHERE email LIKE 'a%' LIMIT 1",
		"SELECT id FROM users WHERE substr(email, 1, 1) = 'a' LIMIT 1",
		"SELECT id FROM users WHERE salary > 1000 LIMIT 1",
		"SELECT id FROM users WHERE salary BETWEEN 1 AND 2 LIMIT 1",
		"SELECT id FROM users WHERE email = lower(name) LIMIT 1",
		"SELECT id FROM users ORDER BY email LIMIT 1",
		"SELECT email AS id FROM users ORDER BY id LIMIT 1",
		"SELECT id FROM users GROUP BY lower(email) LIMIT 1",
		"SELECT row_number() OVER (ORDER BY email) FROM users LIMIT 1",
		"SELECT count(*) FILTER (WHERE email = 'x') FROM users LIMIT 1",
		"SELECT id FROM users u JOIN orders o ON o.user_id = u.id AND u.email = 'x' LIMIT 1",
		"SELECT id FROM users WHERE sum(salary) > 1 LIMIT 1",
		"SELECT id FROM users GROUP BY id HAVING max(salary) > 1000 LIMIT 1",
		"SELECT email FROM contacts WHERE email = 'tok_unknown' LIMIT 1",
		"SELECT id FROM users WHERE email = 'tok_known' LIMIT 1",
		"SELECT (SELECT count(*) FROM users u WHERE u.email = 'x' AND u.id = o.user_id) FROM orders o LIMIT 1",
		"WITH g(x) AS (SELECT 'a@b.c') SELECT u.id FROM users u JOIN g ON u.email = g.x LIMIT 1",
		"EXPLAIN SELECT id FROM users WHERE email = 'x'",
		// Unknown names, metadata and functions outside the allowlist.
		"SELECT nope FROM users LIMIT 1",
		"SELECT id FROM nope LIMIT 1",
		"SELECT id FROM pg_shadow LIMIT 1",
		"SELECT table_name FROM information_schema.tables LIMIT 1",
		"SELECT pg_read_file('x') LIMIT 1",
		"SELECT version() LIMIT 1",
		"SELECT myschema.f(id) FROM users LIMIT 1",
	}
	for _, sql := range refused {
		_, err := analyze(t, sqlclass.Postgres, sql)
		var r *sqlclass.Refusal
		if !errors.As(err, &r) {
			t.Errorf("%q: got %v, want a refusal", sql, err)
		}
	}
}

func TestPIIUsageAllowed(t *testing.T) {
	allowed := []string{
		"SELECT id, email FROM users WHERE id = 3 LIMIT 1",
		"SELECT o.total FROM orders o JOIN users u ON u.email = o.email LIMIT 1",
		"SELECT count(*) FROM users WHERE email IS NULL LIMIT 1",
		"SELECT id FROM orders WHERE email IN (SELECT email FROM users) LIMIT 1",
		"SELECT status, count(*) FROM users GROUP BY status ORDER BY count(*) DESC LIMIT 5",
	}
	for _, sql := range allowed {
		if _, err := analyze(t, sqlclass.Postgres, sql); err != nil {
			t.Errorf("%q: %v", sql, err)
		}
	}
}

func TestKAnonymityChecks(t *testing.T) {
	cases := []struct {
		sql     string
		checks  []string
		grouped bool
	}{
		{"SELECT id FROM users WHERE email = 'a@b.c' LIMIT 1",
			[]string{"SELECT COUNT(*) FROM users WHERE email = 'a@b.c'"}, false},
		{"SELECT email, count(*) FROM users GROUP BY email LIMIT 5",
			[]string{"SELECT MIN(locksql_n) FROM (SELECT COUNT(*) AS locksql_n FROM users GROUP BY email) AS locksql_k"}, true},
		{"SELECT status, avg(salary) FROM users u WHERE status = 'x' GROUP BY 1 LIMIT 5",
			[]string{"SELECT MIN(locksql_n) FROM (SELECT COUNT(*) AS locksql_n FROM users u WHERE status = 'x' GROUP BY status) AS locksql_k"}, true},
		{"WITH c AS (SELECT * FROM users) SELECT count(*) FROM c WHERE email IN ('a', 'b') LIMIT 1",
			[]string{"WITH c AS (SELECT * FROM users) SELECT COUNT(*) FROM c WHERE email IN ('a', 'b')"}, false},
		{"SELECT id FROM contacts WHERE email = 'tok_known' LIMIT 1",
			[]string{"SELECT COUNT(*) FROM contacts WHERE email = 'a@b.example'"}, false},
		{"WITH g(x) AS (SELECT 'a@b.c' UNION SELECT name FROM users) SELECT u.id FROM users u, g WHERE u.email = g.x LIMIT 1",
			[]string{"WITH g(x) AS (SELECT 'a@b.c' UNION SELECT name FROM users) SELECT COUNT(*) FROM users u, g WHERE u.email = g.x"}, false},
		{"SELECT id FROM users WHERE id = 3 LIMIT 1", nil, false},
	}
	for _, c := range cases {
		a, err := analyze(t, sqlclass.Postgres, c.sql)
		if err != nil {
			t.Errorf("%q: %v", c.sql, err)
			continue
		}
		var got []string
		for _, k := range a.KChecks {
			got = append(got, k.SQL)
			if k.Grouped != c.grouped {
				t.Errorf("%q: grouped = %v", c.sql, k.Grouped)
			}
		}
		if strings.Join(got, "\n") != strings.Join(c.checks, "\n") {
			t.Errorf("%q:\n got %q\nwant %q", c.sql, got, c.checks)
		}
	}
}

func TestTokenSubstitution(t *testing.T) {
	sql := "SELECT id FROM contacts WHERE email = 'tok_known' LIMIT 1"
	a, err := analyze(t, sqlclass.Postgres, sql)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := a.RunSQL(sql), "SELECT id FROM contacts WHERE email = 'a@b.example' LIMIT 1"; got != want {
		t.Errorf("RunSQL = %q, want %q", got, want)
	}
	if !a.PIIFilter {
		t.Error("PIIFilter not set")
	}
}

func TestUnmaskSkipsPIIRules(t *testing.T) {
	st, err := Parse(sqlclass.Postgres, "SELECT lower(email) FROM users ORDER BY email LIMIT 1")
	if err != nil {
		t.Fatal(err)
	}
	a, err := Analyze(st, testEnv(false))
	if err != nil {
		t.Fatal(err)
	}
	if a.Masked() || len(a.KChecks) > 0 {
		t.Errorf("unmask plan masks or checks: %+v", a)
	}
	// Functions are still checked.
	st, _ = Parse(sqlclass.Postgres, "SELECT pg_sleep(1) LIMIT 1")
	if _, err := Analyze(st, testEnv(false)); err == nil {
		t.Error("pg_sleep allowed on an unmask plan")
	}
}

func TestUsesAndRelations(t *testing.T) {
	a, err := analyze(t, sqlclass.Postgres, "SELECT u.email FROM users u JOIN orders o ON o.email = u.email WHERE u.id = 1 LIMIT 1")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(a.Relations, ",") != "app.orders,app.users" {
		t.Errorf("relations = %v", a.Relations)
	}
	var uses []string
	for _, u := range a.Uses {
		uses = append(uses, u.Source.Table+"."+u.Source.Column+"@"+u.Clause)
	}
	if strings.Join(uses, ",") != "users.email@join,users.email@select" {
		t.Errorf("uses = %v", uses)
	}
}

func TestDialectStarOrder(t *testing.T) {
	// users(id, email, ...) JOIN contacts(id, email) USING (email).
	sql := "SELECT * FROM users JOIN contacts USING (email) LIMIT 1"
	for d, first := range map[sqlclass.Dialect]string{sqlclass.Postgres: "EMAIL", sqlclass.MySQL: "EMAIL", sqlclass.SQLite: "ID"} {
		a, err := analyze(t, d, sql)
		if err != nil {
			t.Fatal(err)
		}
		if a.Outputs[0].Label != first {
			t.Errorf("%s: first column %s, want %s", d, a.Outputs[0].Label, first)
		}
	}
}
