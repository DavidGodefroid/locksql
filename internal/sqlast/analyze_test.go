package sqlast

import (
	"errors"
	"slices"
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
	"app.contacts.email": "email",
}

func testEnv(masking bool) Env {
	return Env{
		Catalog: testCatalog,
		Rule: func(s Source) (string, bool) {
			m, ok := testRules[s.DB+"."+s.Table+"."+s.Column]
			return m, ok
		},
		Masking: masking,
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
		{"SELECT name FROM users UNION ALL SELECT email FROM users LIMIT 1", []string{"partial"}},
		{"SELECT (SELECT max(email) FROM users) AS m LIMIT 1", []string{"partial"}},
		{"SELECT * FROM users LIMIT 1", []string{"", "partial", "", "redact", ""}},
		{"SELECT o.email, u.email FROM orders o JOIN users u ON u.id = o.user_id LIMIT 1", []string{"", "partial"}},
		{"SELECT sum(salary) AS s FROM users LIMIT 1", []string{"redact"}},
		{"SELECT count(email) FROM users LIMIT 1", []string{""}},
		{"SELECT email FROM contacts LIMIT 1", []string{"email"}},
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
		"SELECT (SELECT count(*) FROM users u WHERE u.email = 'x' AND u.id = o.user_id) FROM orders o LIMIT 1",
		"WITH g(x) AS (SELECT 'a@b.c') SELECT u.id FROM users u JOIN g ON u.email = g.x LIMIT 1",
		"EXPLAIN SELECT id FROM users WHERE email = 'x'",
		// Joins with an unmasked column, literal-tainted partners.
		"SELECT o.total FROM orders o JOIN users u ON u.email = o.email LIMIT 1",
		"SELECT id FROM orders WHERE email IN (SELECT email FROM users) LIMIT 1",
		"SELECT id FROM users JOIN orders USING (email) LIMIT 1",
		"WITH g(x) AS (SELECT 'a@b.c' UNION SELECT name FROM users) SELECT u.id FROM users u, g WHERE u.email = g.x LIMIT 1",
		"WITH g(x) AS (SELECT 'a@b.c' UNION SELECT email FROM contacts) SELECT u.id FROM users u, g WHERE u.email = g.x LIMIT 1",
		"SELECT id FROM users WHERE email IN (SELECT 'a@b.c') LIMIT 1",
		// Negations and disjunctions of PII atoms.
		"SELECT id FROM users WHERE email IS NOT NULL LIMIT 1",
		"SELECT id FROM users WHERE NOT (email IS NULL) LIMIT 1",
		"SELECT id FROM users WHERE email IS NULL OR id = 1 LIMIT 1",
		"SELECT c.id FROM contacts c JOIN users u ON u.email <> c.email LIMIT 1",
		"SELECT c.id FROM contacts c JOIN users u ON u.email = c.email OR u.id = c.id LIMIT 1",
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
		"SELECT c.id FROM contacts c JOIN users u ON u.email = c.email LIMIT 1",
		"SELECT count(*) FROM users WHERE email IS NULL LIMIT 1",
		"SELECT id FROM contacts WHERE email IN (SELECT email FROM users) LIMIT 1",
		"SELECT id FROM users WHERE status = 'x' AND (email = 'a' AND id > 1) LIMIT 1",
		"SELECT id FROM users WHERE id = 1 OR status = 'x' LIMIT 1",
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
		sql    string
		checks []KCheck
	}{
		{"SELECT id FROM users WHERE email = 'a@b.c' LIMIT 1", []KCheck{
			{SQL: `SELECT COUNT(*) FROM "app"."users" WHERE "app"."users"."email" = 'a@b.c'`},
			{SQL: "SELECT COUNT(*) FROM users WHERE email = 'a@b.c'"},
		}},
		{"SELECT email, count(*) FROM users GROUP BY email LIMIT 5", []KCheck{
			{SQL: "SELECT MIN(locksql_n) FROM (SELECT COUNT(*) AS locksql_n FROM users GROUP BY email) AS locksql_k", Grouped: true},
		}},
		{"SELECT status, avg(salary) FROM users u WHERE status = 'x' GROUP BY 1 LIMIT 5", []KCheck{
			{SQL: "SELECT MIN(locksql_n) FROM (SELECT COUNT(*) AS locksql_n FROM users u WHERE status = 'x' GROUP BY status) AS locksql_k", Grouped: true},
		}},
		{"WITH c AS (SELECT * FROM users) SELECT count(*) FROM c WHERE email IN ('a', 'b') LIMIT 1", []KCheck{
			{SQL: `SELECT COUNT(*) FROM "app"."users" WHERE "app"."users"."email" IN ('a', 'b')`},
			{SQL: "WITH c AS (SELECT * FROM users) SELECT COUNT(*) FROM c WHERE email IN ('a', 'b')"},
		}},
		// The subjects are counted in the column's own table, whatever the
		// join multiplies.
		{"SELECT o.id FROM users u JOIN orders o ON o.user_id = u.id WHERE u.email IS NULL AND u.salary IN (1, 2) LIMIT 1", []KCheck{
			{SQL: `SELECT COUNT(*) FROM "app"."users" WHERE "app"."users"."email" IS NULL`},
			{SQL: `SELECT COUNT(*) FROM "app"."users" WHERE "app"."users"."salary" IN (1, 2)`},
			{SQL: "SELECT COUNT(*) FROM users u JOIN orders o ON o.user_id = u.id WHERE u.email IS NULL AND u.salary IN (1, 2)"},
		}},
		{"SELECT u.id FROM users u JOIN contacts c ON c.email = u.email LIMIT 1", nil},
		{"SELECT id FROM users WHERE id = 3 LIMIT 1", nil},
	}
	for _, c := range cases {
		a, err := analyze(t, sqlclass.Postgres, c.sql)
		if err != nil {
			t.Errorf("%q: %v", c.sql, err)
			continue
		}
		if !slices.Equal(a.KChecks, c.checks) {
			t.Errorf("%q:\n got %+v\nwant %+v", c.sql, a.KChecks, c.checks)
		}
	}
}

func TestKCheckQuoting(t *testing.T) {
	for d, want := range map[sqlclass.Dialect]string{
		sqlclass.Postgres: `SELECT COUNT(*) FROM "app"."users" WHERE "app"."users"."email" = 'x'`,
		sqlclass.SQLite:   `SELECT COUNT(*) FROM "app"."users" WHERE "app"."users"."email" = 'x'`,
		sqlclass.MySQL:    "SELECT COUNT(*) FROM `app`.`users` WHERE `app`.`users`.`email` = 'x'",
	} {
		a, err := analyze(t, d, "SELECT id FROM users WHERE email = 'x' LIMIT 1")
		if err != nil {
			t.Fatal(err)
		}
		if len(a.KChecks) == 0 || a.KChecks[0].SQL != want {
			t.Errorf("%s: checks %+v, want first %q", d, a.KChecks, want)
		}
	}
}

func TestQuoteLiteral(t *testing.T) {
	got, err := quoteLiteral(sqlclass.Postgres, "o'k")
	if err != nil || got != "'o''k'" {
		t.Errorf("quoteLiteral = %q, %v", got, err)
	}
	if _, err := quoteLiteral(sqlclass.Postgres, `a\b`); err == nil {
		t.Error("a backslash was accepted")
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
	a, err := analyze(t, sqlclass.Postgres, "SELECT u.email FROM users u JOIN contacts c ON c.email = u.email WHERE u.id = 1 LIMIT 1")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(a.Relations, ",") != "app.contacts,app.users" {
		t.Errorf("relations = %v", a.Relations)
	}
	var uses []string
	for _, u := range a.Uses {
		uses = append(uses, u.Source.Table+"."+u.Source.Column+"@"+u.Clause)
	}
	if strings.Join(uses, ",") != "contacts.email@join,users.email@join,users.email@select" {
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

// On PostgreSQL pg_stat_statements is a view in a user schema and
// pg_stat_activity is reachable unqualified: both are refused on the read
// path even when the catalog lists them.
func TestStatementTextViewsRefusedPostgres(t *testing.T) {
	env := testEnv(true)
	env.Catalog = fakeCatalog{
		"public.pg_stat_statements": {"query"},
		"public.pg_stat_activity":   {"query"},
	}
	for _, sql := range []string{
		"SELECT query FROM pg_stat_statements LIMIT 1",
		"SELECT query FROM public.pg_stat_statements LIMIT 1",
		"SELECT query FROM pg_stat_activity LIMIT 1",
	} {
		st, err := Parse(sqlclass.Postgres, sql)
		if err != nil {
			t.Fatalf("Parse(%q): %v", sql, err)
		}
		_, err = Analyze(st, env)
		var r *sqlclass.Refusal
		if !errors.As(err, &r) {
			t.Errorf("%q: got %v, want a refusal", sql, err)
		}
	}
}

// A recursive CTE whose recursive arm brings a literal keeps Lit on its
// column: the fixpoint must not stop on a provenance that only lost it.
func TestRecursiveCTELiteralKeepsLit(t *testing.T) {
	for _, sql := range []string{
		"WITH RECURSIVE c(e, n) AS (SELECT email, 1 FROM users UNION ALL SELECT 'x', n+1 FROM c WHERE n < 2) SELECT e FROM c LIMIT 5",
		"WITH RECURSIVE c(e, n) AS (SELECT salary, 1 FROM users UNION ALL SELECT 'x', n+1 FROM c WHERE n < 2) SELECT e FROM c LIMIT 5",
	} {
		a, err := analyze(t, sqlclass.MySQL, sql)
		if err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
		if p := a.Outputs[0].Prov; !p.Lit || !p.Sensitive {
			t.Errorf("%s: provenance %+v, want Lit and Sensitive", sql, p)
		}
	}
	// Without a literal the column stays literal-free.
	a, err := analyze(t, sqlclass.MySQL, "WITH RECURSIVE c(e, n) AS (SELECT email, 1 FROM users UNION ALL SELECT e, n+1 FROM c WHERE n < 2) SELECT e FROM c LIMIT 5")
	if err != nil {
		t.Fatal(err)
	}
	if a.Outputs[0].Prov.Lit {
		t.Errorf("plain recursive column marked Lit: %+v", a.Outputs[0].Prov)
	}
}

// LitFilter marks a statement that filters a PII column with a literal the
// agent wrote, wherever it sits; placeholders and IS NULL do not count.
func TestLitFilter(t *testing.T) {
	cases := map[string]bool{
		"SELECT email FROM users WHERE email = 'v@x.com' LIMIT 5":                                             true,
		"SELECT email FROM users WHERE email IN ('v@x.com', 'b@x.com') LIMIT 5":                               true,
		"SELECT email FROM users GROUP BY email HAVING email = 'v@x.com' LIMIT 5":                             true,
		"SELECT email FROM users INTERSECT SELECT email FROM users WHERE email = 'v@x.com' LIMIT 5":           true,
		"SELECT b.email FROM users a JOIN contacts b ON a.email = b.email WHERE a.email = 'v@x.com' LIMIT 5":  true,
		"SELECT email FROM users WHERE id IN (SELECT id FROM users WHERE email = 'v@x.com') LIMIT 5":          true,
		"SELECT email FROM users WHERE email IN ('${email}', 'v@x.com') LIMIT 5":                              true,
		"SELECT email FROM users LIMIT 5":                                                                     false,
		"SELECT email FROM users WHERE id = 1 LIMIT 5":                                                        false,
		"SELECT email FROM users WHERE email IS NULL LIMIT 5":                                                 false,
		"SELECT email FROM users WHERE email = '${email}' LIMIT 5":                                            false,
		"SELECT email FROM users WHERE email IN ('${email}', '${other}') LIMIT 5":                             false,
		"SELECT b.email FROM users a JOIN contacts b ON a.email = b.email WHERE a.email = '${email}' LIMIT 5": false,
	}
	for sql, want := range cases {
		a, err := analyze(t, sqlclass.MySQL, sql)
		if err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
		if a.LitFilter != want {
			t.Errorf("%s: LitFilter %v, want %v", sql, a.LitFilter, want)
		}
	}
}

// A recursive CTE whose provenance does not converge within the fixpoint
// bound is refused: its last iteration may still miss a literal.
func TestRecursiveCTENotConvergedRefused(t *testing.T) {
	sql := "WITH RECURSIVE c(a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,n) AS (SELECT email,'victim@x.com',email,email,email,email,email,email,email,email,1 FROM users UNION ALL SELECT a10,a2,a2,a3,a4,a5,a6,a7,a8,a9,n+1 FROM c WHERE n < 12) SELECT a1 FROM c WHERE n >= 10 LIMIT 50"
	_, err := analyze(t, sqlclass.MySQL, sql)
	var r *sqlclass.Refusal
	if !errors.As(err, &r) || !strings.Contains(r.Reason, "too deep") {
		t.Fatalf("got %v, want a refusal", err)
	}
	// Modes stay deduplicated through unions.
	p := union(Prov{Modes: []string{"redact", "partial"}}, Prov{Modes: []string{"partial", "redact"}})
	if len(p.Modes) != 2 {
		t.Errorf("modes %v", p.Modes)
	}
}
