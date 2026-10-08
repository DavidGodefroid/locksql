package pii

import (
	"testing"

	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

// A label that differs from a rule column only by Unicode case or accents
// may name that column (MySQL resolves identifiers by collation weight), so
// it is masked when it has no origin.
func TestMatchesNameUnicode(t *testing.T) {
	r := Rules{Mask: []string{"app.users.firstname", "app.users.prénom"}}
	for _, n := range []string{"fİrstname", "FIRSTNAME", "fírstname", "prenom", "PRÉNOM", "nöte"} {
		if !r.MatchesName(n) {
			t.Errorf("MatchesName(%q) = false", n)
		}
	}
	for _, n := range []string{"note", "first", "pren0m"} {
		if r.MatchesName(n) {
			t.Errorf("MatchesName(%q) = true", n)
		}
	}
	if (Rules{}).MatchesName("nöte") {
		t.Error("no rules: nothing matches")
	}
	res := engine.Result{Columns: []engine.ResultColumn{{Label: "fİrstname"}}, Rows: [][]any{{"Alice"}}}
	MaskResult(&res, r, nil, true)
	if res.Rows[0][0] != "A***(5)" {
		t.Errorf("not masked: %v", res.Rows[0][0])
	}
}

func TestAliasViolationRound2(t *testing.T) {
	r := Rules{Mask: []string{"app.users.email", "app.users.firstname"}}
	cases := []struct {
		d   sqlclass.Dialect
		sql string
	}{
		// Unicode names that may resolve to a rule column.
		{sqlclass.MySQL, "SELECT id FROM t UNION SELECT fírstname FROM users LIMIT 5"},
		{sqlclass.MySQL, "SELECT fírstname AS x FROM users LIMIT 5"},
		// Later-arm star over an unaliased derived table.
		{sqlclass.Postgres, "SELECT id FROM t UNION SELECT * FROM (SELECT email FROM users) LIMIT 10"},
		{sqlclass.Postgres, "SELECT id FROM t INTERSECT SELECT * FROM (SELECT email FROM users) LIMIT 10"},
		{sqlclass.Postgres, "SELECT id FROM t UNION SELECT * FROM (TABLE users) LIMIT 10"},
		{sqlclass.Postgres, "SELECT id FROM t UNION SELECT * FROM (SELECT * FROM users) LIMIT 10"},
		{sqlclass.SQLite, "SELECT id FROM t UNION SELECT * FROM (SELECT email FROM users) LIMIT 10"},
		// A star in the head shifts positions.
		{sqlclass.Postgres, "SELECT t.*, users.email FROM t, users UNION SELECT id, email, id FROM users LIMIT 10"},
		{sqlclass.MySQL, "SELECT t.*, users.email FROM t, users UNION SELECT id, email, id FROM users LIMIT 10"},
		{sqlclass.SQLite, "SELECT *, email FROM t, users UNION SELECT id, email, id FROM users LIMIT 10"},
		// A star earlier in the later arm shifts positions too.
		{sqlclass.Postgres, "SELECT a, email, x FROM users UNION SELECT g.*, email FROM unnest(array[1], array[2]) g, users LIMIT 10"},
		// The head of a later arm is its own chain's first arm.
		{sqlclass.Postgres, "WITH x AS (SELECT email FROM users) SELECT * FROM ((SELECT id FROM t) UNION SELECT email FROM users) b LIMIT 10"},
		{sqlclass.MySQL, "SELECT * FROM (SELECT email FROM users) a CROSS JOIN ((SELECT id FROM t) UNION SELECT email FROM users) b LIMIT 10"},
		{sqlclass.Postgres, "SELECT * FROM ((SELECT id FROM t) UNION SELECT x FROM y UNION SELECT email FROM users) b LIMIT 10"},
		{sqlclass.Postgres, "SELECT * FROM (SELECT email FROM users) a, (VALUES (1) UNION SELECT email FROM users) b LIMIT 10"},
	}
	for _, c := range cases {
		st, err := sqlclass.Classify(c.d, c.sql, 0)
		if err != nil {
			t.Fatalf("Classify(%q): %v", c.sql, err)
		}
		if AliasViolation(st, r, c.d) == nil {
			t.Errorf("accepted: %s", c.sql)
		}
	}
	ok := []struct {
		d   sqlclass.Dialect
		sql string
	}{
		{sqlclass.Postgres, "SELECT * FROM ((SELECT email FROM users) UNION SELECT email FROM users) b LIMIT 10"},
		{sqlclass.Postgres, "SELECT email FROM users UNION SELECT x FROM y UNION SELECT email FROM users LIMIT 10"},
		{sqlclass.Postgres, "SELECT * FROM ((SELECT email FROM users) UNION (SELECT email FROM users)) b LIMIT 10"},
		{sqlclass.Postgres, "SELECT id, email FROM users UNION SELECT id, email FROM users LIMIT 10"},
		{sqlclass.Postgres, "SELECT id FROM t UNION SELECT * FROM generate_series(1, 3) LIMIT 10"},
		{sqlclass.MySQL, "SELECT firstname FROM users WHERE id IN (SELECT id FROM other) LIMIT 5"},
	}
	for _, c := range ok {
		st, err := sqlclass.Classify(c.d, c.sql, 0)
		if err != nil {
			t.Fatalf("Classify(%q): %v", c.sql, err)
		}
		if err := AliasViolation(st, r, c.d); err != nil {
			t.Errorf("refused %s: %v", c.sql, err)
		}
	}
}

func TestParsePatternRejectsControls(t *testing.T) {
	for _, p := range []string{"a.b.c\x1b[2J", "a.b\u202e.c", "a.b.c ", "a.b\x00.c", "a.b.c\u0085", "a.b.c "} {
		if _, err := parsePattern(p); err == nil {
			t.Errorf("parsePattern(%q) accepted", p)
		}
	}
	if _, err := parsePattern("app.users.prénom"); err != nil {
		t.Errorf("non-ASCII letters refused: %v", err)
	}
}
