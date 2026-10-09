package sqlast

import (
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

func TestParsePlaceholder(t *testing.T) {
	cases := []struct {
		body     string
		kind     ValueKind
		name     string
		isPH, ok bool
	}{
		{"${email}", ValueTyped, "email", true, true},
		{"${email_2}", ValueTyped, "email_2", true, true},
		{"${r3.1.2}", ValueRef, "r3.1.2", true, true},
		{"${Email}", 0, "", true, false},
		{"${r0.1.1}", 0, "", true, false},
		{"${r3.01.2}", 0, "", true, false},
		{"${}", 0, "", true, false},
		{"${a b}", 0, "", true, false},
		{"$" + "{" + strings.Repeat("a", 33) + "}", 0, "", true, false},
		{"alice@example.com", 0, "", false, false},
		{"{email}", 0, "", false, false},
	}
	for _, c := range cases {
		k, n, isPH, ok := ParsePlaceholder(c.body)
		if k != c.kind || n != c.name || isPH != c.isPH || ok != c.ok {
			t.Errorf("ParsePlaceholder(%q) = %v %q %v %v", c.body, k, n, isPH, ok)
		}
	}
}

func valueEnv(values map[string]string) Env {
	e := testEnv(true)
	e.Value = func(_ ValueKind, name string) (string, bool) {
		v, ok := values[name]
		return v, ok
	}
	return e
}

func analyzeWith(t *testing.T, sql string, env Env) (*Analysis, error) {
	t.Helper()
	st, err := Parse(sqlclass.Postgres, sql)
	if err != nil {
		t.Fatalf("Parse(%q): %v", sql, err)
	}
	return Analyze(st, env)
}

func TestPlaceholderSubstitutedWithoutKCheck(t *testing.T) {
	sql := "SELECT id FROM users WHERE email = '${email}' LIMIT 5"
	a, err := analyzeWith(t, sql, valueEnv(map[string]string{"email": "o'brien@example.com"}))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := a.RunSQL(sql), "SELECT id FROM users WHERE email = 'o''brien@example.com' LIMIT 5"; got != want {
		t.Errorf("RunSQL = %q, want %q", got, want)
	}
	if len(a.KChecks) != 0 {
		t.Errorf("k-checks for a typed value: %+v", a.KChecks)
	}
	if !a.PIIFilter {
		t.Error("PIIFilter not set: row estimates would reach the agent")
	}
	if len(a.Values) != 1 || a.Values[0].Kind != ValueTyped || a.Values[0].Name != "email" ||
		a.Values[0].Column != (Source{DB: "app", Table: "users", Column: "email"}) {
		t.Errorf("Values = %+v", a.Values)
	}
}

func TestPlaceholderUnknownTypedIsRecorded(t *testing.T) {
	sql := "SELECT id FROM users WHERE email IN ('${a}', '${b}') LIMIT 5"
	a, err := analyzeWith(t, sql, valueEnv(nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Values) != 2 || !a.Values[0].InList || len(a.Replacements) != 0 {
		t.Errorf("Values %+v Replacements %+v", a.Values, a.Replacements)
	}
	if len(a.KChecks) != 0 {
		t.Errorf("k-checks for typed values: %+v", a.KChecks)
	}
	if !a.PIIFilter {
		t.Error("PIIFilter not set")
	}
}

func TestPlaceholderUnknownRefRefused(t *testing.T) {
	_, err := analyzeWith(t, "SELECT id FROM users WHERE email = '${r9.1.1}' LIMIT 5", valueEnv(nil))
	if err == nil || !strings.Contains(err.Error(), "unknown reference r9.1.1") {
		t.Fatalf("err = %v", err)
	}
}

func TestMixedLiteralsKeepKCheck(t *testing.T) {
	sql := "SELECT id FROM users WHERE email IN ('${a}', 'x@example.com') LIMIT 5"
	a, err := analyzeWith(t, sql, valueEnv(map[string]string{"a": "a@example.com"}))
	if err != nil {
		t.Fatal(err)
	}
	if len(a.KChecks) == 0 || !strings.Contains(a.KChecks[0].SQL, "'a@example.com'") {
		t.Errorf("KChecks = %+v", a.KChecks)
	}
}

func TestPlaceholderElsewhereRefused(t *testing.T) {
	const (
		stray     = "a placeholder may only be compared with a PII column"
		malformed = "malformed placeholder"
	)
	for _, c := range []struct{ sql, reason string }{
		{"SELECT '${email}' AS x FROM users LIMIT 1", stray},
		{"SELECT id FROM users WHERE lower(email) = lower('${email}') LIMIT 1", "is used inside function lower"},
		{"SELECT id FROM users WHERE id = '${email}' LIMIT 1", stray},
		{"SELECT id FROM users WHERE name = '${email}' LIMIT 1", stray},
		{"SELECT id FROM users WHERE email = '${Email}' LIMIT 1", malformed},
		{"SELECT id FROM users u JOIN orders o ON o.user_id = u.id AND u.email = '${email}' LIMIT 1", "not in a JOIN condition"},
		// Spec 8: function argument, CONCAT, CASE, UNION constant, ref vs
		// ref.
		{"SELECT length('${email}') AS n FROM users LIMIT 1", stray},
		{"SELECT id FROM users WHERE length('${email}') > 3 LIMIT 1", stray},
		{"SELECT concat('${email}', id) AS x FROM users LIMIT 1", stray},
		{"SELECT CASE WHEN id = 1 THEN '${email}' END AS x FROM users LIMIT 1", stray},
		{"SELECT id FROM users WHERE email = '${email}' UNION SELECT '${email}' LIMIT 1", stray},
		{"SELECT id FROM users WHERE '${r1.1.1}' = '${r1.1.2}' LIMIT 1", stray},
		{"SELECT id FROM users WHERE '${email}' = '${email}' LIMIT 1", stray},
		{"SELECT id FROM users WHERE name IN ('${email}') LIMIT 1", stray},
		// Only plain single-quoted strings are substituted.
		{"SELECT id FROM users WHERE email = E'${email}' LIMIT 1", malformed},
		{"SELECT E'${email}' AS x FROM users LIMIT 1", malformed},
		{"SELECT $$${email}$$ AS x FROM users LIMIT 1", malformed},
		{"SELECT $t$${email}$t$ AS x FROM users LIMIT 1", malformed},
	} {
		env := valueEnv(map[string]string{"email": "a@b.example", "r1.1.1": "a@b.example", "r1.1.2": "c@d.example"})
		_, err := analyzeWith(t, c.sql, env)
		if err == nil || !strings.Contains(err.Error(), c.reason) {
			t.Errorf("%q: err = %v, want %q", c.sql, err, c.reason)
		}
	}
	st, err := Parse(sqlclass.Postgres, "SELECT email FROM users WHERE email = '${email}' LIMIT 1")
	if err != nil {
		t.Fatal(err)
	}
	env := valueEnv(map[string]string{"email": "a@b.example"})
	env.Masking = false
	if _, err := Analyze(st, env); err == nil || !strings.Contains(err.Error(), stray) {
		t.Errorf("placeholder in an unmask plan: err = %v", err)
	}
}

func TestKeyFilters(t *testing.T) {
	a, err := analyzeWith(t, "SELECT id FROM users WHERE id = 57 AND email = '${r1.1.2}' LIMIT 1",
		valueEnv(map[string]string{"r1.1.2": "a@b.example"}))
	if err != nil {
		t.Fatal(err)
	}
	if len(a.KeyFilters) != 1 || a.KeyFilters[0] != (Source{DB: "app", Table: "users", Column: "id"}) {
		t.Errorf("KeyFilters = %+v", a.KeyFilters)
	}
	// IN (literals) and BETWEEN constants pin a row as well as =.
	env := valueEnv(map[string]string{"r1.1.2": "a@b.example"})
	for _, w := range []string{"id IN (57)", "id IN (57, 58)", "id BETWEEN 57 AND 57", "(id BETWEEN 1 AND 2)"} {
		a, err := analyzeWith(t, "SELECT id FROM users WHERE "+w+" AND email = '${r1.1.2}' LIMIT 1", env)
		if err != nil {
			t.Fatal(err)
		}
		if len(a.KeyFilters) != 1 || a.KeyFilters[0].Column != "id" {
			t.Errorf("%s: KeyFilters = %+v", w, a.KeyFilters)
		}
	}
	// Negated, disjunctive or non-constant: not a key filter.
	for _, w := range []string{"id NOT IN (57)", "NOT id IN (57)", "id NOT BETWEEN 1 AND 2", "(id IN (57) OR id = 3)", "id BETWEEN id AND 57", "id IN (id)"} {
		a, err := analyzeWith(t, "SELECT id FROM users WHERE "+w+" AND email = '${r1.1.2}' LIMIT 1", env)
		if err != nil {
			t.Fatal(err)
		}
		if len(a.KeyFilters) != 0 {
			t.Errorf("%s: KeyFilters = %+v", w, a.KeyFilters)
		}
	}
}

func TestHasPlaceholder(t *testing.T) {
	for _, c := range []struct {
		d    sqlclass.Dialect
		sql  string
		want bool
	}{
		{sqlclass.MySQL, "UPDATE users SET email = '${email}' WHERE id = 7", true},
		{sqlclass.MySQL, "DELETE FROM users WHERE email = '${r1.1.2}'", true},
		{sqlclass.MySQL, "UPDATE users SET email = '${bad name}'", true},
		{sqlclass.MySQL, `INSERT INTO users (email) VALUES ("${email}")`, true},
		{sqlclass.Postgres, "INSERT INTO users (email) VALUES (E'${email}')", true},
		{sqlclass.Postgres, "INSERT INTO users (email) VALUES ($$${email}$$)", true},
		{sqlclass.MySQL, "UPDATE users SET note = 'cost: ${x}' WHERE id = 1", false},
		{sqlclass.MySQL, "UPDATE `${email}` SET note = 'x'", false},
		// Comments do not lex: reported as holding one (fail closed).
		{sqlclass.MySQL, "UPDATE users SET note = 'x' -- c", true},
	} {
		if got := HasPlaceholder(c.d, c.sql); got != c.want {
			t.Errorf("%s: got %v", c.sql, got)
		}
	}
}
