package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

// setupDB creates a database file with a few tables, runs ANALYZE through a
// read-write handle and returns its path.
func setupDB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "app.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, s := range []string{
		`CREATE TABLE big (id INTEGER PRIMARY KEY, x INT, y TEXT, email TEXT NOT NULL DEFAULT '')`,
		`WITH RECURSIVE c(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM c WHERE n < 1000)
		 INSERT INTO big (id, x, y, email) SELECT n, n % 100, 'y' || n, 'user' || n || '@example.com' FROM c`,
		`CREATE TABLE items (id INTEGER PRIMARY KEY, x INT, label TEXT)`,
		`CREATE INDEX items_x ON items (x)`,
		`WITH RECURSIVE c(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM c WHERE n < 1000)
		 INSERT INTO items (id, x, label) SELECT n, n, 'l' || n FROM c`,
		`CREATE TABLE uniq (id INTEGER PRIMARY KEY, v INT UNIQUE)`,
		`INSERT INTO uniq VALUES (1, 1), (2, 2), (3, 3)`,
		`CREATE VIEW emails AS SELECT id, email FROM big`,
		`ANALYZE`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("setup %q: %v", s, err)
		}
	}
	return path
}

func profile(path string, tier config.Tier) config.Profile {
	return config.Profile{
		Name:   "test",
		Engine: config.EngineSQLite,
		Path:   path,
		Tier:   tier,
		Limits: config.DefaultLimits(false),
	}
}

func connect(t *testing.T, path string, tier config.Tier) engine.Session {
	t.Helper()
	e, err := engine.Get(config.EngineSQLite)
	if err != nil {
		t.Fatal(err)
	}
	s, err := e.Connect(context.Background(), profile(path, tier), nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func classify(t *testing.T, q string) sqlclass.Statement {
	t.Helper()
	st, err := sqlclass.Classify(sqlclass.SQLite, q, 0)
	if err != nil {
		t.Fatalf("classify %q: %v", q, err)
	}
	return st
}

func TestRegistered(t *testing.T) {
	if _, err := engine.Get("sqlite"); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Get("oracle"); err == nil {
		t.Fatal("unknown engine accepted")
	}
}

func TestSessionBasics(t *testing.T) {
	s := connect(t, setupDB(t), config.TierRead)
	if s.Flavor() != engine.FlavorSQLite {
		t.Fatalf("flavor = %q", s.Flavor())
	}
	if !strings.HasPrefix(s.ServerVersion(), "3.") {
		t.Fatalf("version = %q", s.ServerVersion())
	}
	if !s.OriginColumns() {
		t.Fatal("sqlite reports origin columns")
	}
	if err := s.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestReadTierIsReadOnly(t *testing.T) {
	path := setupDB(t)
	s := connect(t, path, config.TierRead)
	ctx := context.Background()

	// A WRITE statement above the tier is refused by the session.
	if _, err := s.Run(ctx, "main", classify(t, "INSERT INTO uniq VALUES (9, 9)"), 10); err == nil {
		t.Fatal("INSERT accepted on a read tier")
	}
	// A statement forged as READ still fails: query_only is on.
	forged := sqlclass.Statement{Class: sqlclass.Read, Kind: "select", SQL: "INSERT INTO uniq VALUES (9, 9)", Limit: -1}
	if _, err := s.Run(ctx, "main", forged, 10); err == nil {
		t.Fatal("forged INSERT accepted with query_only")
	}
	// Even with query_only switched off, mode=ro keeps the file read-only.
	off := sqlclass.Statement{Class: sqlclass.Read, Kind: "pragma", SQL: "PRAGMA query_only=0", Limit: -1}
	if _, err := s.Run(ctx, "main", off, 10); err != nil {
		t.Fatalf("pragma: %v", err)
	}
	if _, err := s.Run(ctx, "main", forged, 10); err == nil {
		t.Fatal("forged INSERT accepted on a mode=ro handle")
	}
	assertCount(t, path, "SELECT count(*) FROM uniq", 3)
}

func TestRefusesChainedStatements(t *testing.T) {
	s := connect(t, setupDB(t), config.TierWrite)
	forged := sqlclass.Statement{Class: sqlclass.Read, Kind: "select", SQL: "SELECT 1; DELETE FROM uniq", Limit: -1}
	if _, err := s.Run(context.Background(), "main", forged, 10); err == nil {
		t.Fatal("chained statements accepted by Run")
	}
	if _, err := s.Explain(context.Background(), "main", forged.SQL); err == nil {
		t.Fatal("chained statements accepted by Explain")
	}
}

func TestCatalog(t *testing.T) {
	s := connect(t, setupDB(t), config.TierRead)
	ctx := context.Background()

	dbs, err := s.Databases(ctx)
	if err != nil || !reflect.DeepEqual(dbs, []string{"main"}) {
		t.Fatalf("Databases = %v, %v", dbs, err)
	}
	tables, err := s.Tables(ctx, "main")
	if err != nil || !reflect.DeepEqual(tables, []string{"big", "emails", "items", "uniq"}) {
		t.Fatalf("Tables = %v, %v", tables, err)
	}
	if _, err := s.Tables(ctx, "nope"); err == nil {
		t.Fatal("unknown database accepted")
	}

	info, err := s.Describe(ctx, "main", "big")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, c := range info.Columns {
		names = append(names, c.Name+" "+c.Type)
	}
	if want := []string{"id INTEGER", "x INT", "y TEXT", "email TEXT"}; !reflect.DeepEqual(names, want) {
		t.Fatalf("columns = %v", names)
	}
	if !info.Columns[0].PrimaryKey || info.Columns[3].Nullable || !info.Columns[1].Nullable {
		t.Fatalf("column flags = %+v", info.Columns)
	}
	if info.EstRows != 1000 {
		t.Fatalf("EstRows = %d, want 1000 from sqlite_stat1", info.EstRows)
	}
	if info.DB != "main" || info.Table != "big" {
		t.Fatalf("info = %+v", info)
	}

	items, err := s.Describe(ctx, "main", "items")
	if err != nil {
		t.Fatal(err)
	}
	if len(items.Indexes) != 1 || items.Indexes[0].Name != "items_x" || !reflect.DeepEqual(items.Indexes[0].Columns, []string{"x"}) {
		t.Fatalf("indexes = %+v", items.Indexes)
	}
	if _, err := s.Describe(ctx, "main", "missing"); err == nil {
		t.Fatal("unknown table accepted")
	}

	cols, err := s.Columns(ctx, "main")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range cols {
		if c == (engine.ColumnInfo{DB: "main", Table: "big", Column: "email", Type: "TEXT"}) {
			found = true
		}
	}
	if !found {
		t.Fatalf("Columns misses big.email: %v", cols)
	}
}

func firstTable(n engine.PlanNode) *engine.PlanNode {
	if n.Table != "" {
		return &n
	}
	for _, c := range n.Children {
		if f := firstTable(c); f != nil {
			return f
		}
	}
	return nil
}

func TestExplain(t *testing.T) {
	s := connect(t, setupDB(t), config.TierRead)
	ctx := context.Background()
	cases := []struct {
		sql    string
		table  string
		access []string
		rows   int64
	}{
		{"SELECT * FROM big WHERE x=1 LIMIT 10", "big", []string{"full"}, 1000},
		{"SELECT * FROM big b WHERE b.x=1 LIMIT 10", "big", []string{"full"}, 1000},
		{"SELECT * FROM items WHERE x=1 LIMIT 10", "items", []string{"lookup", "range"}, -2},
		{"SELECT * FROM items WHERE x>10 AND x<20 LIMIT 10", "items", []string{"range", "lookup"}, -2},
		{"SELECT * FROM big WHERE id=5 LIMIT 10", "big", []string{"lookup"}, 1},
	}
	for _, c := range cases {
		p, err := s.Explain(ctx, "main", c.sql)
		if err != nil {
			t.Fatalf("%s: %v", c.sql, err)
		}
		n := firstTable(p.Root)
		if n == nil {
			t.Fatalf("%s: no table node in %+v", c.sql, p.Root)
		}
		if n.Table != c.table {
			t.Errorf("%s: table = %q", c.sql, n.Table)
		}
		ok := false
		for _, a := range c.access {
			ok = ok || n.Access == a
		}
		if !ok {
			t.Errorf("%s: access = %q, want one of %v", c.sql, n.Access, c.access)
		}
		if c.rows != -2 && n.EstRows != c.rows {
			t.Errorf("%s: EstRows = %d, want %d", c.sql, n.EstRows, c.rows)
		}
		if len(p.Raw) == 0 {
			t.Errorf("%s: no raw plan", c.sql)
		}
	}

	p, err := s.Explain(ctx, "main", "SELECT * FROM big ORDER BY y LIMIT 10")
	if err != nil {
		t.Fatal(err)
	}
	if !p.Root.Sort || !p.Root.Temp {
		t.Errorf("ORDER BY on an unindexed column: root = %+v", p.Root)
	}
}

func TestRunCapsRows(t *testing.T) {
	s := connect(t, setupDB(t), config.TierRead)
	ctx := context.Background()

	r, err := s.Run(ctx, "main", classify(t, "SELECT id, email FROM big ORDER BY id LIMIT 50"), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Rows) != 10 || !r.Truncated {
		t.Fatalf("rows = %d, truncated = %v", len(r.Rows), r.Truncated)
	}
	if r.Rows[0][0] != int64(1) || r.Rows[0][1] != "user1@example.com" {
		t.Fatalf("first row = %v", r.Rows[0])
	}

	r, err = s.Run(ctx, "main", classify(t, "SELECT id FROM big ORDER BY id LIMIT 10"), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Rows) != 10 || r.Truncated {
		t.Fatalf("exactly maxRows: rows = %d, truncated = %v", len(r.Rows), r.Truncated)
	}
}

func TestRunReportsOrigins(t *testing.T) {
	s := connect(t, setupDB(t), config.TierRead)
	ctx := context.Background()

	r, err := s.Run(ctx, "main", classify(t, "SELECT b.email AS x, b.email || '' AS y, e.email FROM big b JOIN emails e ON e.id = b.id LIMIT 1"), 10)
	if err != nil {
		t.Fatal(err)
	}
	want := []engine.ResultColumn{
		{Label: "x", OriginDB: "main", OriginTable: "big", OriginColumn: "email"},
		{Label: "y"},
		{Label: "email", OriginDB: "main", OriginTable: "big", OriginColumn: "email"},
	}
	if !reflect.DeepEqual(r.Columns, want) {
		t.Fatalf("columns = %+v", r.Columns)
	}

	// Compound selects report only the first arm: no origin is given.
	r, err = s.Run(ctx, "main", classify(t, "SELECT email FROM big UNION SELECT label FROM items LIMIT 1"), 10)
	if err != nil {
		t.Fatal(err)
	}
	if r.Columns[0] != (engine.ResultColumn{Label: "email"}) {
		t.Fatalf("compound origin = %+v", r.Columns[0])
	}
}

func TestDeadlineInterruptsQuery(t *testing.T) {
	s := connect(t, setupDB(t), config.TierRead)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	st := classify(t, "WITH RECURSIVE c(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM c) SELECT count(*) FROM c LIMIT 1")
	start := time.Now()
	_, err := s.Run(ctx, "main", st, 10)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want deadline exceeded", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("interrupt took %v", d)
	}
	// The session stays usable.
	if _, err := s.Run(context.Background(), "main", classify(t, "SELECT 1 LIMIT 1"), 10); err != nil {
		t.Fatalf("after interrupt: %v", err)
	}
}

func TestWriteTier(t *testing.T) {
	path := setupDB(t)
	s := connect(t, path, config.TierWrite)
	ctx := context.Background()

	r, err := s.Run(ctx, "main", classify(t, "UPDATE big SET y = 'z' WHERE id <= 10"), 10)
	if err != nil {
		t.Fatal(err)
	}
	if r.Affected != 10 {
		t.Fatalf("Affected = %d", r.Affected)
	}
	assertCount(t, path, "SELECT count(*) FROM big WHERE y = 'z'", 10)

	// A failing statement rolls back as a whole.
	if _, err := s.Run(ctx, "main", classify(t, "UPDATE uniq SET v = 2 WHERE id IN (1, 3)"), 10); err == nil {
		t.Fatal("unique violation accepted")
	}
	assertCount(t, path, "SELECT count(*) FROM uniq WHERE v = 2", 1)

	// DDL is above the write tier.
	if _, err := s.Run(ctx, "main", classify(t, "DROP TABLE uniq"), 10); err == nil {
		t.Fatal("DDL accepted on a write tier")
	}
}

func TestExtraPrivileges(t *testing.T) {
	path := setupDB(t)
	ro := connect(t, path, config.TierRead)
	w, err := ro.ExtraPrivileges(context.Background(), config.TierRead)
	if err != nil || len(w) != 1 || !strings.Contains(w[0], "writable") {
		t.Fatalf("read tier on a writable file: %v, %v", w, err)
	}
	rw := connect(t, path, config.TierWrite)
	w, err = rw.ExtraPrivileges(context.Background(), config.TierWrite)
	if err != nil || len(w) != 0 {
		t.Fatalf("write tier: %v, %v", w, err)
	}
}

func TestConnectMissingFile(t *testing.T) {
	e, _ := engine.Get(config.EngineSQLite)
	p := profile(filepath.Join(t.TempDir(), "missing.db"), config.TierWrite)
	if _, err := e.Connect(context.Background(), p, nil); err == nil {
		t.Fatal("missing database file was accepted (would be created)")
	}
}

func assertCount(t *testing.T, path, q string, want int) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(q).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != want {
		t.Fatalf("%s = %d, want %d", q, n, want)
	}
}

func TestConnectEscapesPath(t *testing.T) {
	src := setupDB(t)
	dir := filepath.Join(t.TempDir(), "a b#c%d")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "app.db")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	s := connect(t, path, config.TierRead)
	tables, err := s.Tables(context.Background(), "main")
	if err != nil || len(tables) != 4 {
		t.Fatalf("Tables = %v, %v", tables, err)
	}
}

func TestBuildDSNRefusesURIParameters(t *testing.T) {
	if _, _, err := buildDSN("file:app.db?mode=rw", config.TierRead); err == nil {
		t.Fatal("file: URI parameters accepted")
	}
}
