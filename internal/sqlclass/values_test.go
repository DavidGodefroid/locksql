package sqlclass

import "testing"

func TestValuesRows(t *testing.T) {
	for _, c := range []struct {
		d    Dialect
		sql  string
		want int64
	}{
		{MySQL, "INSERT INTO t VALUES (1, 'a'), (2, 'b'), (3, '(,)')", 3},
		{MySQL, "INSERT INTO t (a, b) VALUES (1, (SELECT 2)), (3, 4)", 2},
		{MySQL, "INSERT INTO t VALUE (1)", 1},
		{MySQL, "INSERT INTO t VALUES ROW(1, 2), ROW(3, 4)", 2},
		{MySQL, "REPLACE INTO t VALUES (1), (2)", 4},
		{MySQL, "INSERT INTO t VALUES (1), (2) ON DUPLICATE KEY UPDATE a = VALUES(a)", 4},
		{MySQL, "INSERT INTO t VALUES (1), (2) AS n ON DUPLICATE KEY UPDATE a = n.a", 4},
		{MySQL, "INSERT INTO t SELECT * FROM u", 0},
		{MySQL, "INSERT INTO t SELECT * FROM (VALUES ROW(1), ROW(2)) v", 0},
		{MySQL, "UPDATE t SET a = 1", 0},
		{SQLite, "INSERT INTO t VALUES (1), (2), (3) ON CONFLICT DO NOTHING", 3},
		{SQLite, "REPLACE INTO t VALUES (1), (2)", 2},
		{SQLite, "INSERT OR REPLACE INTO t VALUES (1), (2)", 2},
		{SQLite, "INSERT INTO t VALUES (1), (2) RETURNING id", 2},
		{Postgres, "INSERT INTO t VALUES (1), (2) ON CONFLICT (id) DO UPDATE SET a = 1", 2},
		{Postgres, "WITH x AS (SELECT 1) INSERT INTO t VALUES (1)", 0},
		{MySQL, "INSERT INTO t VALUES ('unterminated", 0},
	} {
		if got := ValuesRows(c.d, c.sql); got != c.want {
			t.Errorf("ValuesRows(%q) = %d, want %d", c.sql, got, c.want)
		}
	}
}
