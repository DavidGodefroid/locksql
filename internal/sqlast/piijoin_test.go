package sqlast

import (
	"errors"
	"slices"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/sqlclass"
	refusal "github.com/DavidGodefroid/locksql/internal/sqlrefusal"
)

// A PII-to-PII equality is accepted with no count: it is recorded in
// PIIJoins, never in PIIFilter or KChecks (#150).
func TestPIIJoinsRecorded(t *testing.T) {
	want := []string{"app.contacts.email = app.users.email"}
	joins := []string{
		"SELECT c.id FROM contacts c JOIN users u ON u.email = c.email LIMIT 1",
		"SELECT c.id FROM contacts c JOIN users u ON c.email IS NOT DISTINCT FROM u.email LIMIT 1",
		"SELECT c.id FROM contacts c, users u WHERE c.email = u.email LIMIT 1",
		"SELECT id FROM contacts WHERE email IN (SELECT email FROM users) LIMIT 1",
		"SELECT c.id FROM contacts c JOIN users u USING (email) LIMIT 1",
		"SELECT id FROM contacts NATURAL JOIN users LIMIT 1",
		// Both orders and repeats name the pair once.
		"SELECT c.id FROM contacts c JOIN users u ON u.email = c.email AND c.email = u.email LIMIT 1",
	}
	for _, sql := range joins {
		a, err := analyze(t, sqlclass.Postgres, sql)
		if err != nil {
			t.Errorf("%q: %v", sql, err)
			continue
		}
		if !slices.Equal(a.PIIJoins, want) {
			t.Errorf("%q: PIIJoins %q, want %q", sql, a.PIIJoins, want)
		}
		if a.PIIFilter || len(a.KChecks) > 0 {
			t.Errorf("%q: PIIFilter %v, KChecks %+v, want none", sql, a.PIIFilter, a.KChecks)
		}
	}
	a, err := analyze(t, sqlclass.MySQL, "SELECT c.id FROM contacts c JOIN users u ON u.email <=> c.email LIMIT 1")
	if err != nil || !slices.Equal(a.PIIJoins, want) {
		t.Errorf("MySQL <=>: PIIJoins %v (%v), want %q", a, err, want)
	}
}

func TestPIIJoinsEmpty(t *testing.T) {
	sqls := []string{
		"SELECT u.id FROM users u JOIN orders o ON o.user_id = u.id LIMIT 1",
		"SELECT id FROM users WHERE id IN (SELECT user_id FROM orders) LIMIT 1",
		"SELECT o.id FROM orders o JOIN notes n USING (id) LIMIT 1",
	}
	for _, sql := range sqls {
		a, err := analyze(t, sqlclass.Postgres, sql)
		if err != nil {
			t.Errorf("%q: %v", sql, err)
			continue
		}
		if len(a.PIIJoins) > 0 {
			t.Errorf("%q: PIIJoins %q, want none", sql, a.PIIJoins)
		}
	}
	// No mask rule applies: nothing is recorded.
	for _, sql := range []string{
		"SELECT c.id FROM contacts c JOIN users u ON u.email = c.email LIMIT 1",
		"SELECT c.id FROM contacts c JOIN users u USING (email) LIMIT 1",
	} {
		st, err := Parse(sqlclass.Postgres, sql)
		if err != nil {
			t.Fatal(err)
		}
		a, err := Analyze(st, testEnv(false))
		if err != nil {
			t.Errorf("%q unmasked: %v", sql, err)
			continue
		}
		if len(a.PIIJoins) > 0 {
			t.Errorf("%q unmasked: PIIJoins %q, want none", sql, a.PIIJoins)
		}
	}
}

func TestPIIJoinExplainRefused(t *testing.T) {
	for _, sql := range []string{
		"EXPLAIN SELECT c.id FROM contacts c JOIN users u ON u.email = c.email",
		"EXPLAIN SELECT id FROM contacts WHERE email IN (SELECT email FROM users)",
		"EXPLAIN SELECT id FROM contacts NATURAL JOIN users",
	} {
		_, err := analyze(t, sqlclass.Postgres, sql)
		var r *sqlclass.Refusal
		if !errors.As(err, &r) || r.Code != refusal.MaskedFilter {
			t.Errorf("%q: got %v, want %s", sql, err, refusal.MaskedFilter)
		}
	}
	if _, err := analyze(t, sqlclass.Postgres, "EXPLAIN SELECT u.id FROM users u JOIN orders o ON o.user_id = u.id"); err != nil {
		t.Errorf("EXPLAIN of a non-PII join: %v", err)
	}
}

// A write that joins PII columns runs no count, so it stays allowed.
func TestPIIJoinWriteAllowed(t *testing.T) {
	cases := []struct {
		d   sqlclass.Dialect
		sql string
	}{
		{sqlclass.Postgres, "UPDATE contacts c SET id = c.id FROM users u WHERE u.email = c.email"},
		{sqlclass.Postgres, "DELETE FROM contacts c USING users u WHERE u.email = c.email"},
		{sqlclass.MySQL, "UPDATE contacts SET id = id WHERE email IN (SELECT email FROM users)"},
	}
	for _, c := range cases {
		a, err := analyzeWrite(t, c.d, c.sql)
		if err != nil {
			t.Errorf("%s %q: %v", c.d, c.sql, err)
			continue
		}
		if want := []string{"app.contacts.email = app.users.email"}; !slices.Equal(a.PIIJoins, want) {
			t.Errorf("%s %q: PIIJoins %q, want %q", c.d, c.sql, a.PIIJoins, want)
		}
	}
}
