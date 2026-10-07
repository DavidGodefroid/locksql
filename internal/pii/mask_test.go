package pii

import (
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

func TestMaskResultByOrigin(t *testing.T) {
	r := Rules{Mask: []string{"app.users.email", "*.*.name"}, Allow: []string{"app.t.name"}}
	ds, _ := Detectors([]string{"email"})
	res := engine.Result{
		Columns: []engine.ResultColumn{
			{Label: "x", OriginDB: "app", OriginTable: "users", OriginColumn: "email"},
			{Label: "name", OriginDB: "app", OriginTable: "t", OriginColumn: "name"}, // allowed
			{Label: "note", OriginDB: "app", OriginTable: "users", OriginColumn: "note"},
			{Label: "email"}, // no origin, but labelled like a rule: masked by name
			{Label: "photo", OriginDB: "app", OriginTable: "users", OriginColumn: "name"},
			{Label: "n"},
		},
		Rows: [][]any{
			{"jean.dupont@ex.be", "Template A", "mail me at jean@ex.be", "a@b.cd", []byte("abc"), int64(5)},
			{nil, nil, nil, nil, nil, nil},
		},
	}
	MaskResult(&res, r, ds, true)
	row := res.Rows[0]
	if row[0] != "j***(17)" {
		t.Errorf("origin rule: %v", row[0])
	}
	if row[1] != "Template A" {
		t.Errorf("allow rule: %v", row[1])
	}
	if s := row[2].(string); strings.Contains(s, "jean@ex.be") || !strings.HasPrefix(s, "mail me at j***(") {
		t.Errorf("detector: %v", s)
	}
	if row[3] != "a***(6)" {
		t.Errorf("label fallback: %v", row[3])
	}
	if row[4] != "<masked bytes:3>" {
		t.Errorf("bytes: %v", row[4])
	}
	if row[5] != int64(5) {
		t.Errorf("int kept: %v", row[5])
	}
	for i, v := range res.Rows[1] {
		if v != nil {
			t.Errorf("NULL %d became %v", i, v)
		}
	}
}

func TestMaskResultWithoutOriginUsesLabels(t *testing.T) {
	r := Rules{Mask: []string{"app.users.email"}}
	res := engine.Result{
		Columns: []engine.ResultColumn{{Label: "EMAIL", OriginDB: "app", OriginTable: "users", OriginColumn: "id"}, {Label: "id"}},
		Rows:    [][]any{{"x@y.zz", "1"}},
	}
	MaskResult(&res, r, nil, false) // origins ignored when the session does not report them
	if res.Rows[0][0] != "x***(6)" || res.Rows[0][1] != "1" {
		t.Errorf("rows = %v", res.Rows)
	}
}

func TestMaskResultNumbersGoThroughDetectors(t *testing.T) {
	ds, _ := Detectors([]string{"be_niss", "card", "nl_bsn"})
	res := engine.Result{
		Columns: []engine.ResultColumn{{Label: "a"}, {Label: "b"}, {Label: "c"}, {Label: "d"}},
		Rows:    [][]any{{int64(85073003328), uint64(4111111111111111), int64(42), int32(111222333)}},
	}
	MaskResult(&res, Rules{}, ds, true)
	if res.Rows[0][0] != "8***(11)" || res.Rows[0][1] != "4***(16)" || res.Rows[0][2] != int64(42) || res.Rows[0][3] != "1***(9)" {
		t.Errorf("rows = %#v", res.Rows[0])
	}
}

func TestNeedsAliasCheck(t *testing.T) {
	with := engine.Result{Columns: []engine.ResultColumn{{Label: "a", OriginTable: "t", OriginColumn: "a"}}}
	without := engine.Result{Columns: []engine.ResultColumn{{Label: "a", OriginTable: "t", OriginColumn: "a"}, {Label: "b"}}}
	if NeedsAliasCheck(with, true) || !NeedsAliasCheck(with, false) || !NeedsAliasCheck(without, true) {
		t.Error("NeedsAliasCheck")
	}
}

func TestAliasViolation(t *testing.T) {
	r := Rules{Mask: []string{"app.users.email", "*.*.prenom"}}
	cases := []struct {
		d   sqlclass.Dialect
		sql string
		bad bool
	}{
		{sqlclass.MySQL, "SELECT email AS x FROM users LIMIT 10", true},
		{sqlclass.MySQL, "SELECT CONCAT(email,'') FROM users LIMIT 10", true},
		{sqlclass.MySQL, "SELECT email FROM users LIMIT 10", false},
		{sqlclass.MySQL, "SELECT u.email, u.id AS user_id FROM users u LIMIT 10", false},
		{sqlclass.MySQL, "SELECT email AS email FROM users LIMIT 10", false},
		{sqlclass.MySQL, "SELECT email x FROM users LIMIT 10", true},
		{sqlclass.MySQL, "SELECT `email` AS `EMAIL` FROM users LIMIT 10", false},
		{sqlclass.MySQL, "SELECT u.email AS mail FROM users u LIMIT 10", true},
		{sqlclass.MySQL, "SELECT LOWER(u.email) AS email FROM users u LIMIT 10", true},
		{sqlclass.MySQL, "SELECT COUNT(email) AS n FROM users LIMIT 10", false},
		{sqlclass.MySQL, "SELECT COUNT(DISTINCT email) FROM users LIMIT 10", false},
		{sqlclass.MySQL, "SELECT id FROM users WHERE CONCAT(email,'') = 'x' LIMIT 10", false},
		{sqlclass.MySQL, "SELECT * FROM users LIMIT 10", false},
		{sqlclass.MySQL, "SELECT x FROM (SELECT email AS x FROM users) d LIMIT 10", true},
		{sqlclass.MySQL, "SELECT (SELECT email FROM users LIMIT 1) AS x LIMIT 1", true},
		{sqlclass.MySQL, "SELECT id, prenom FROM users WHERE id IN (SELECT id FROM t) LIMIT 10", false},
		{sqlclass.MySQL, "SELECT id FROM a UNION SELECT email FROM users LIMIT 10", true},
		{sqlclass.MySQL, "SELECT email FROM a UNION ALL SELECT email FROM users LIMIT 10", false},
		{sqlclass.MySQL, "SELECT email FROM a UNION SELECT prenom FROM users LIMIT 10", true},
		{sqlclass.MySQL, "WITH c(x) AS (SELECT email FROM users) SELECT x FROM c LIMIT 10", true},
		{sqlclass.MySQL, "WITH c AS (SELECT email FROM users) SELECT email FROM c LIMIT 10", false},
		{sqlclass.Postgres, "SELECT x FROM (SELECT email FROM users) AS d(x) LIMIT 10", true},
		{sqlclass.Postgres, "SELECT x FROM users u(x) LIMIT 10", true},
		{sqlclass.Postgres, "SELECT DISTINCT ON (email) email FROM users LIMIT 10", false},
		{sqlclass.Postgres, `SELECT "email" AS "x" FROM users LIMIT 10`, true},
		{sqlclass.Postgres, "SELECT CAST(id AS varchar(10)) AS i, lower(status) FROM users LIMIT 10", false},
		{sqlclass.Postgres, "SELECT a.id FROM a JOIN b USING (id) WHERE NOT lower(a.s) = 'x' LIMIT 10", false},
		{sqlclass.SQLite, "SELECT email || '' FROM users LIMIT 10", true},
		{sqlclass.SQLite, "SELECT [email] FROM users LIMIT 10", false},
		{sqlclass.MySQL, "SHOW TABLES", false},
	}
	for _, c := range cases {
		st, err := sqlclass.Classify(c.d, c.sql, 0)
		if err != nil {
			t.Fatalf("Classify(%q): %v", c.sql, err)
		}
		err = AliasViolation(st, r, c.d)
		if (err != nil) != c.bad {
			t.Errorf("AliasViolation(%q) = %v, want violation %v", c.sql, err, c.bad)
		}
		if err != nil {
			if _, ok := err.(*sqlclass.Refusal); !ok {
				t.Errorf("AliasViolation(%q) error type %T", c.sql, err)
			}
		}
	}
	// No rules, no violation.
	st, _ := sqlclass.Classify(sqlclass.MySQL, "SELECT email AS x FROM users LIMIT 1", 0)
	if err := AliasViolation(st, Rules{}, sqlclass.MySQL); err != nil {
		t.Errorf("no rules: %v", err)
	}
}

// A star puts every column of its sources in place, whatever the labels
// around it say: in a later compound arm and under a CTE column list it is
// refused when a source may hold a rule-matched column.
func TestAliasViolationStar(t *testing.T) {
	r := Rules{Mask: []string{"app.users.email"}}
	cases := []struct {
		d   sqlclass.Dialect
		sql string
		bad bool
	}{
		// A star in a later arm puts its table's columns under the head's labels.
		{sqlclass.MySQL, "SELECT id, note FROM t UNION ALL SELECT * FROM users LIMIT 10", true},
		{sqlclass.Postgres, "SELECT id, note FROM t UNION ALL SELECT u.* FROM users u LIMIT 10", true},
		{sqlclass.SQLite, "SELECT id, note FROM t UNION SELECT * FROM (SELECT * FROM users) d LIMIT 10", true},
		{sqlclass.SQLite, "SELECT id FROM t UNION SELECT id FROM t2 UNION SELECT DISTINCT * FROM users LIMIT 10", true},
		{sqlclass.MySQL, "SELECT id, note FROM t UNION ALL SELECT * FROM orders LIMIT 10", false},
		{sqlclass.MySQL, "SELECT id, note FROM t UNION ALL SELECT o.* FROM orders o JOIN t ON t.id = o.id LIMIT 10", false},
		{sqlclass.MySQL, "SELECT * FROM users UNION ALL SELECT id, COUNT(*) FROM orders GROUP BY id LIMIT 10", false},
		// A CTE column list over a star renames whatever the star brings.
		{sqlclass.SQLite, "WITH c(id, x) AS (SELECT * FROM users) SELECT x || '' FROM c LIMIT 10", true},
		{sqlclass.Postgres, "WITH c(id, x) AS (SELECT u.* FROM users u) SELECT x FROM c LIMIT 10", true},
		{sqlclass.MySQL, "WITH c(id, x) AS (SELECT * FROM users) SELECT CONCAT(x) FROM c LIMIT 10", true},
		{sqlclass.MySQL, "WITH c(id, x) AS (SELECT * FROM orders) SELECT CONCAT(x) FROM c LIMIT 10", false},
		{sqlclass.MySQL, "WITH c(id, n) AS (SELECT id, COUNT(*) FROM users GROUP BY id) SELECT n FROM c LIMIT 10", false},
	}
	for _, c := range cases {
		st, err := sqlclass.Classify(c.d, c.sql, 0)
		if err != nil {
			t.Fatalf("Classify(%q): %v", c.sql, err)
		}
		if err = AliasViolation(st, r, c.d); (err != nil) != c.bad {
			t.Errorf("AliasViolation(%q) = %v, want violation %v", c.sql, err, c.bad)
		}
	}
}

func TestAliasViolationWholeRow(t *testing.T) {
	r := Rules{Mask: []string{"app.users.email"}}
	cases := []struct {
		sql string
		bad bool
	}{
		{"SELECT u FROM users u LIMIT 10", true},
		{"SELECT row_to_json(u) FROM users u LIMIT 10", true},
		{"SELECT to_jsonb(users.*) AS j FROM users LIMIT 10", true},
		{"SELECT ROW(u.*) FROM users AS u LIMIT 10", true},
		{"SELECT u::text FROM public.users u LIMIT 10", true},
		{"SELECT CAST(u AS text) FROM ONLY users u LIMIT 10", true},
		{"SELECT json_agg(u) FROM orders o JOIN users u ON o.uid = u.id LIMIT 10", true},
		{"SELECT o.id, users FROM orders o, users LIMIT 10", true},
		{"SELECT d FROM (SELECT email FROM users) d LIMIT 10", true},
		{"WITH c AS (SELECT email FROM users) SELECT row_to_json(c) FROM c LIMIT 10", true},
		{"SELECT x FROM (SELECT u FROM users u) d LIMIT 10", true},
		{"SELECT to_json(public.users.*) FROM public.users LIMIT 10", true},
		{"SELECT u.* FROM users u LIMIT 10", false},
		{"SELECT public.users.* FROM public.users LIMIT 10", false},
		{"SELECT u.email, u.id FROM users u LIMIT 10", false},
		{"SELECT COUNT(u) FROM users u LIMIT 10", false},
		{"SELECT o FROM orders o LIMIT 10", false},
		{"SELECT row_to_json(o) FROM orders o JOIN users u ON u.id = o.uid LIMIT 10", false},
		{"SELECT g FROM generate_series(1, 3) g LIMIT 10", false},
		{"SELECT u.id FROM users u WHERE u IS NOT NULL LIMIT 10", false},
	}
	for _, c := range cases {
		st, err := sqlclass.Classify(sqlclass.Postgres, c.sql, 0)
		if err != nil {
			t.Fatalf("Classify(%q): %v", c.sql, err)
		}
		err = AliasViolation(st, r, sqlclass.Postgres)
		if (err != nil) != c.bad {
			t.Errorf("AliasViolation(%q) = %v, want violation %v", c.sql, err, c.bad)
		}
	}
}

func FuzzAliasViolationNoPanic(f *testing.F) {
	f.Add("SELECT email AS x FROM (SELECT email FROM u) d(x) UNION (SELECT prenom FROM t) LIMIT 1")
	f.Add("WITH c(x) AS NOT MATERIALIZED (SELECT email FROM u) SELECT DISTINCT ON (x) x FROM c LIMIT 1")
	r := Rules{Mask: []string{"*.*.email", "*.*.prenom"}}
	f.Fuzz(func(t *testing.T, sql string) {
		for _, d := range []sqlclass.Dialect{sqlclass.MySQL, sqlclass.Postgres, sqlclass.SQLite} {
			st := sqlclass.Statement{Class: sqlclass.Read, Kind: "select", SQL: sql, Limit: 1}
			_ = AliasViolation(st, r, d)
		}
	})
}

func TestMaskResultCutsHugeCellsBeforeDetection(t *testing.T) {
	ds, _ := Detectors([]string{"card", "email"})
	big := strings.Repeat("word ", DetectLimit/5-2) + "4111 1111 1111 1111 jean@example.com" + strings.Repeat("z", 1<<20)
	res := engine.Result{Columns: []engine.ResultColumn{{Label: "a"}}, Rows: [][]any{{big}, {"short"}}}
	MaskResult(&res, Rules{}, ds, true)
	got := res.Rows[0][0].(string)
	if len(got) > DetectLimit+len("…") || !strings.HasSuffix(got, "…") {
		t.Errorf("len = %d, suffix %q", len(got), got[len(got)-10:])
	}
	for _, leak := range []string{"4111", "jean", "1111"} {
		if strings.Contains(got[len(got)-200:], leak) {
			t.Errorf("partial value %q left at the cut: %q", leak, got[len(got)-80:])
		}
	}
	if res.Rows[1][0] != "short" {
		t.Errorf("short cell = %v", res.Rows[1][0])
	}
}
