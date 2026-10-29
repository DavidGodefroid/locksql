package sqlast

import (
	"errors"
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/sqlclass"
	refusal "github.com/DavidGodefroid/locksql/internal/sqlrefusal"
)

// write_functions = "allowlist" (issue #60): every function a write calls
// must be on the read allowlist or the short list of write built-ins.

func TestWriteFunctionsAccepted(t *testing.T) {
	pg, my, lite := sqlclass.Postgres, sqlclass.MySQL, sqlclass.SQLite
	cases := []struct {
		d   sqlclass.Dialect
		sql string
	}{
		// Allowlisted read functions, at any depth and in every clause.
		{pg, "INSERT INTO t (a, b) VALUES (lower('X'), now())"},
		{pg, "INSERT INTO t (a) VALUES (COALESCE(NULL, upper(trim(' x '))))"},
		{pg, "UPDATE t SET a = round(b * 1.1, 2), c = DEFAULT WHERE id = abs(-1)"},
		{pg, "DELETE FROM t WHERE created < now() - INTERVAL '1 day'"},
		{pg, "DELETE FROM t WHERE extract(year FROM created) < 2020"},
		{pg, "INSERT INTO t (a) SELECT max(b) FROM u WHERE length(c) > 2"},
		{pg, "WITH x AS (SELECT lower(a) AS a FROM u LIMIT 3) INSERT INTO t (a) SELECT a FROM x"},
		{pg, "INSERT INTO t (id, a) VALUES (1, 'x') ON CONFLICT (id) DO UPDATE SET a = upper(excluded.a)"},
		{pg, "UPDATE t SET a = 'x' WHERE id = 1 RETURNING lower(a)"},
		{pg, "INSERT INTO t (a) VALUES (CAST('1' AS INTEGER))"},
		{pg, "INSERT INTO t (a) VALUES (CURRENT_TIMESTAMP)"},
		{my, "INSERT INTO t (a) VALUES (CURRENT_TIMESTAMP())"},
		{my, "UPDATE t SET a = date_add(now(), INTERVAL 1 DAY) WHERE id = 1"},
		{my, "INSERT INTO t SET a = concat('a', 'b')"},
		{my, "INSERT INTO t (a) VALUES (1) ON DUPLICATE KEY UPDATE a = greatest(a, 2)"},
		{my, "INSERT INTO t (a, b) VALUES (1, 2) ON DUPLICATE KEY UPDATE b = VALUES(b)"},
		{my, "INSERT INTO t (a, b) VALUES (1, 2) ON DUPLICATE KEY UPDATE b = values(b) + 1"},
		{my, "REPLACE INTO t (a) VALUES (lower('x'))"},
		{lite, "INSERT INTO t (a) VALUES (strftime('%s', 'now'))"},
		{lite, "REPLACE INTO t (a) VALUES (json_extract('{}', '$.a'))"},
		// Write built-ins.
		{pg, "INSERT INTO t (id) VALUES (gen_random_uuid())"},
		{pg, "INSERT INTO t (id) VALUES (nextval('t_id_seq'))"},
		{my, "INSERT INTO t (id) VALUES (UUID())"},
		{my, "INSERT INTO t (id) VALUES (uuid_to_bin(uuid()))"},
		{my, "INSERT INTO t (id) VALUES (SYS_GUID())"},
		{lite, "INSERT INTO t (id) VALUES (randomblob(16))"},
		// Quoted and non-ASCII table and column names are not calls.
		{pg, `INSERT INTO "My Table" ("Col") VALUES (lower('x'))`},
		{my, "INSERT INTO `t` (`a`) VALUES (lower('x'))"},
		{lite, `INSERT INTO [t] ([a]) VALUES (lower('x'))`},
		{pg, `UPDATE "t" SET "a" = upper("b") WHERE "id" = 1`},
		{pg, "INSERT INTO café (thé) VALUES (lower('x'))"},
		// Columns named like functions are not calls.
		{pg, "UPDATE t SET evil = 1 WHERE pg_notify = 2"},
		// No function at all.
		{my, "DELETE FROM t WHERE id = 1"},
	}
	for _, c := range cases {
		if err := CheckWriteFunctions(c.d, c.sql); err != nil {
			t.Errorf("%s %q: %v", c.d, c.sql, err)
		}
	}
}

func TestWriteFunctionsRefused(t *testing.T) {
	pg, my, lite := sqlclass.Postgres, sqlclass.MySQL, sqlclass.SQLite
	cases := []struct {
		d       sqlclass.Dialect
		sql     string
		wantErr string // in the refusal reason
	}{
		// Unknown and user-defined functions, anywhere in the write.
		{pg, "INSERT INTO t (a) VALUES (my_func(1))", "my_func"},
		{pg, "UPDATE t SET a = 1 WHERE id = my_func(1)", "my_func"},
		{pg, "DELETE FROM t WHERE id IN (SELECT id FROM u WHERE my_func(a) LIMIT 1)", "my_func"},
		{pg, "INSERT INTO t (a) SELECT my_func(b) FROM u", "my_func"},
		{pg, "WITH x AS (SELECT my_func(1) AS a) INSERT INTO t (a) SELECT a FROM x", "my_func"},
		{pg, "INSERT INTO t (id) VALUES (1) ON CONFLICT (id) DO UPDATE SET a = my_func(excluded.a)", "my_func"},
		{pg, "UPDATE t SET a = 1 RETURNING my_func(a)", "my_func"},
		{pg, "UPDATE t SET a = lower(upper(trim(my_func(a))))", "my_func"},
		{pg, "UPDATE t SET a = CASE WHEN b THEN my_func(a) ELSE a END", "my_func"},
		{pg, "UPDATE t SET a = CAST(my_func(a) AS TEXT)", "my_func"},
		{my, "INSERT INTO t (a) VALUES (1) ON DUPLICATE KEY UPDATE a = my_func(a)", "my_func"},
		{my, "INSERT INTO t SET a = my_func(1)", "my_func"},
		{my, "INSERT INTO t (a) VALUES (1) ON DUPLICATE KEY UPDATE a = VALUES(my_func(a))", "values"},
		{my, "INSERT INTO t (a) VALUES (1) ON DUPLICATE KEY UPDATE a = VALUES(a) + my_func(1)", "my_func"},
		{lite, "INSERT INTO t (a) VALUES (my_func(1))", "my_func"},
		// Schema-qualified calls, even of an allowlisted name.
		{pg, "INSERT INTO t SELECT cron.schedule('* * * * *', 'DELETE FROM t')", "cron.schedule"},
		{pg, "INSERT INTO t (a) VALUES (pg_catalog.lower('x'))", "pg_catalog.lower"},
		{pg, "INSERT INTO t (a) VALUES (public.lower('x'))", "public.lower"},
		{my, "INSERT INTO t (a) VALUES (db.f(1))", "db.f"},
		// Casing does not matter.
		{pg, "INSERT INTO t (a) VALUES (My_Func(1))", "my_func"},
		{my, "INSERT INTO t (a) VALUES (MY_FUNC(1))", "my_func"},
		// Functions harmless in a read but not on the write list.
		{pg, "INSERT INTO t (a) VALUES (setval('s', 1))", "setval"},
		{pg, "INSERT INTO t (a) VALUES (current_setting('x'))", "current_setting"},
		{my, "INSERT INTO t (a) VALUES (last_insert_id(5))", "last_insert_id"},
		// Denylisted names are refused here too.
		{pg, "INSERT INTO t SELECT pg_notify('c', 'x')", "pg_notify"},
		{my, "INSERT INTO t (a) VALUES (sleep(1))", "sleep"},
	}
	for _, c := range cases {
		err := CheckWriteFunctions(c.d, c.sql)
		var r *sqlclass.Refusal
		if !errors.As(err, &r) {
			t.Errorf("%s %q: got %v, want a refusal", c.d, c.sql, err)
			continue
		}
		if r.Code != refusal.Function {
			t.Errorf("%s %q: code %s, want %s (%v)", c.d, c.sql, r.Code, refusal.Function, err)
		}
		if !strings.Contains(strings.ToLower(err.Error()), c.wantErr) {
			t.Errorf("%s %q: %v, want it to name %s", c.d, c.sql, err, c.wantErr)
		}
	}
}

// A function name the classifier would fold onto an allowlisted one, but
// the engine resolves differently, is refused: quoted names (PostgreSQL
// "LOWER" is not lower), MySQL ANSI double-quoted names, and names with
// non-ASCII letters (ſqrt folds to SQRT).
func TestWriteFunctionsSpellings(t *testing.T) {
	pg, my, lite := sqlclass.Postgres, sqlclass.MySQL, sqlclass.SQLite
	cases := []struct {
		d   sqlclass.Dialect
		sql string
	}{
		{pg, `INSERT INTO t (a) VALUES ("LOWER"('x'))`},
		{pg, `INSERT INTO t (a) VALUES ("lower"('x'))`},
		{pg, `UPDATE t SET a = "my_func"(a)`},
		{my, "INSERT INTO t (a) VALUES (`lower`('x'))"},
		{my, `INSERT INTO t (a) VALUES ("lower"('x'))`},
		{lite, `INSERT INTO t (a) VALUES ([lower]('x'))`},
		{pg, "INSERT INTO t (a) VALUES (ſqrt(4))"},
		{pg, "INSERT INTO t (a) VALUES (lower(ſqrt(4)))"},
		{my, "UPDATE t SET a = ſqrt(4)"},
		{pg, "INSERT INTO t (a) VALUES (ｌower('x'))"},
		// A blank before '(': MySQL then calls the stored function of
		// that name, not the built-in.
		{my, "INSERT INTO t (a) VALUES (lower ('x'))"},
		{my, "UPDATE t SET a = upper\n('x')"},
		{pg, "INSERT INTO t (a) VALUES (lower\t('x'))"},
		{lite, "INSERT INTO t (a) VALUES (lower ('x'))"},
		{pg, "INSERT INTO t (a) VALUES (My_Func (1))"},
	}
	for _, c := range cases {
		err := CheckWriteFunctions(c.d, c.sql)
		var r *sqlclass.Refusal
		if !errors.As(err, &r) {
			t.Errorf("%s %q: got %v, want a refusal", c.d, c.sql, err)
		}
	}
}

// A write the parser does not read is refused: its calls cannot be listed.
func TestWriteFunctionsUnparsed(t *testing.T) {
	cases := []struct {
		d   sqlclass.Dialect
		sql string
	}{
		{sqlclass.Postgres, "MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN UPDATE SET a = my_func(s.a)"},
		{sqlclass.Postgres, "INSERT INTO t (a) SELECT x FROM generate_series(1, 3) x"},
		{sqlclass.MySQL, "UPDATE t, u SET t.a = my_func(u.a) WHERE t.id = u.id"},
		{sqlclass.Postgres, "CALL my_proc()"},
	}
	for _, c := range cases {
		err := CheckWriteFunctions(c.d, c.sql)
		var r *sqlclass.Refusal
		if !errors.As(err, &r) {
			t.Errorf("%s %q: got %v, want a refusal", c.d, c.sql, err)
			continue
		}
		if !strings.Contains(err.Error()+" "+r.Hint, "write_functions") {
			t.Errorf("%s %q: %v (hint %q), want it to name write_functions", c.d, c.sql, err, r.Hint)
		}
	}
}

// With WriteFuncs, the write analysis accepts the write built-ins, and it
// resolves every column against the catalog: PostgreSQL reads rel.name,
// when rel has no column name, as the call name(rel) (attribute notation).
func TestWriteFunctionsAnalysis(t *testing.T) {
	env := testEnv(false)
	env.WriteFuncs = true
	for _, sql := range []string{
		"UPDATE users SET status = gen_random_uuid()::text WHERE id = 1",
		"UPDATE users SET status = lower(status) WHERE users.id = 1",
	} {
		st, err := ParseWrite(sqlclass.Postgres, sql)
		if err == nil {
			_, err = Analyze(st, env)
		}
		if err != nil {
			t.Errorf("%q: %v", sql, err)
		}
	}
	for _, sql := range []string{
		"UPDATE users SET status = users.evil WHERE id = 1",
		"UPDATE users u SET status = 'x' WHERE u.evil",
		"DELETE FROM users WHERE users.evil IS NULL",
		"INSERT INTO users (id) SELECT o.evil FROM orders o",
	} {
		st, err := ParseWrite(sqlclass.Postgres, sql)
		if err == nil {
			_, err = Analyze(st, env)
		}
		var r *sqlclass.Refusal
		if !errors.As(err, &r) {
			t.Errorf("%q: got %v, want a refusal", sql, err)
		}
	}
	env.WriteFuncs = false
	st, err := ParseWrite(sqlclass.Postgres, "UPDATE users SET status = gen_random_uuid()::text WHERE id = 1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Analyze(st, env); err == nil {
		t.Error("gen_random_uuid accepted without WriteFuncs")
	}
}
