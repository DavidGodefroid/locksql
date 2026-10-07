package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
)

var update = flag.Bool("update", false, "rewrite the plan fixtures under testdata/explain/sqlite")

func TestParsePlan(t *testing.T) {
	st := stats{
		tables:  map[string]int64{"users": 5_000_000, "orders": 20_000_000},
		indexes: map[string][]int64{"orders_user": {20_000_000, 4}},
	}
	rows := []eqpRow{
		{ID: 2, Parent: 0, Detail: "SCAN u"},
		{ID: 4, Parent: 0, Detail: "SEARCH o USING INDEX orders_user (user_id=?)"},
		{ID: 6, Parent: 0, Detail: "CORRELATED SCALAR SUBQUERY 1"},
		{ID: 8, Parent: 6, Detail: "SEARCH orders USING INTEGER PRIMARY KEY (rowid>? AND rowid<?)"},
		{ID: 9, Parent: 0, Detail: "SCAN t2 USING COVERING INDEX t2_i"},
		{ID: 10, Parent: 0, Detail: "USE TEMP B-TREE FOR ORDER BY"},
		{ID: 11, Parent: 0, Detail: "SCAN CONSTANT ROW"},
	}
	aliases := map[string]string{"u": "users", "o": "orders"}
	root := parsePlan(rows, st, aliases)

	if !root.Sort || !root.Temp {
		t.Errorf("root sort/temp = %v/%v", root.Sort, root.Temp)
	}
	if len(root.Children) != 4 {
		t.Fatalf("children = %+v", root.Children)
	}
	u, o, sub, t2 := root.Children[0], root.Children[1], root.Children[2], root.Children[3]
	if u.Table != "users" || u.Access != "full" || u.EstRows != 5_000_000 || u.NoJoinCond {
		t.Errorf("users = %+v", u)
	}
	if o.Table != "orders" || o.Access != "lookup" || o.EstRows != 4 {
		t.Errorf("orders = %+v", o)
	}
	if !sub.Correlated || sub.Table != "" || len(sub.Children) != 1 {
		t.Fatalf("subquery = %+v", sub)
	}
	if r := sub.Children[0]; r.Table != "orders" || r.Access != "range" || r.EstRows != 1_250_000 {
		t.Errorf("range = %+v", r)
	}
	if t2.Table != "t2" || t2.Access != "index" || t2.EstRows != -1 || !t2.NoJoinCond {
		t.Errorf("t2 = %+v", t2)
	}
}

// fixtureDB builds a schema whose sqlite_stat1 claims production-like sizes,
// so the captured plans exercise the weight model (Task 8).
func fixtureDB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fixtures.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, s := range []string{
		`CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, country TEXT)`,
		`CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INT, total INT)`,
		`CREATE INDEX orders_user ON orders (user_id)`,
		`CREATE TABLE countries (id INTEGER PRIMARY KEY, code TEXT, name TEXT)`,
		`CREATE TABLE nostat (id INT, v TEXT)`,
		`INSERT INTO users VALUES (1, 'a', 'b')`,
		`INSERT INTO orders VALUES (1, 1, 1)`,
		`INSERT INTO countries VALUES (1, 'BE', 'Belgium')`,
		`ANALYZE`,
		`DELETE FROM sqlite_stat1`,
		`INSERT INTO sqlite_stat1 VALUES ('users', NULL, '5000000')`,
		`INSERT INTO sqlite_stat1 VALUES ('orders', 'orders_user', '40000 4')`,
		`INSERT INTO sqlite_stat1 VALUES ('countries', NULL, '200')`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("setup %q: %v", s, err)
		}
	}
	return path
}

var fixtureQueries = []struct{ name, sql string }{
	{"ref", "SELECT * FROM users WHERE id = 1"},
	{"range", "SELECT id, user_id FROM orders WHERE user_id > 100 AND user_id < 105"},
	{"small_scan", "SELECT * FROM countries"},
	{"join", "SELECT * FROM countries c JOIN users u ON u.id = c.id"},
	{"subquery", "SELECT * FROM countries WHERE id IN (SELECT user_id FROM orders WHERE user_id = 3)"},
	{"full_scan", "SELECT * FROM users WHERE email = 'x'"},
	{"filesort", "SELECT * FROM users ORDER BY email"},
	{"group_by", "SELECT country, count(*) FROM users GROUP BY country"},
	{"union", "SELECT email FROM users UNION SELECT name FROM countries"},
	{"cartesian", "SELECT * FROM users, orders"},
	{"correlated", "SELECT u.id, (SELECT count(*) FROM orders o WHERE o.total = u.id) FROM users u"},
	{"unknown_size", "SELECT * FROM nostat WHERE v = 'x'"},
}

// TestExplainFixtures captures normalised plans for the weight model tests.
// Run with -update to rewrite them.
func TestExplainFixtures(t *testing.T) {
	s := connect(t, fixtureDB(t), config.TierRead)
	dir := filepath.Join("..", "..", "..", "testdata", "explain", "sqlite")
	for _, q := range fixtureQueries {
		p, err := s.Explain(context.Background(), "main", q.sql)
		if err != nil {
			t.Fatalf("%s: %v", q.name, err)
		}
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(p); err != nil {
			t.Fatal(err)
		}
		got := buf.Bytes()
		file := filepath.Join(dir, q.name+".json")
		if *update {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(file, got, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("%s: %v (run go test -update)", q.name, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s: plan differs from %s:\n%s", q.name, file, got)
		}
		var back engine.Plan
		if err := json.Unmarshal(want, &back); err != nil {
			t.Errorf("%s: fixture does not decode: %v", q.name, err)
		}
	}
}
