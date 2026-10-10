//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-mysql-org/go-mysql/client"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	lsmysql "github.com/DavidGodefroid/locksql/internal/engine/mysql"
	"github.com/DavidGodefroid/locksql/internal/pii"
	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

const mysqlSeedCommon = `
CREATE DATABASE app;
CREATE DATABASE other;
CREATE TABLE app.big (id INT PRIMARY KEY AUTO_INCREMENT, status VARCHAR(20), email VARCHAR(100),
  created_at DATETIME, KEY idx_created (created_at));
CREATE TABLE app.small (id INT PRIMARY KEY, label VARCHAR(20));
CREATE TABLE other.t (id INT PRIMARY KEY);
INSERT INTO app.small VALUES (1,'a'),(2,'b'),(3,'c');
INSERT INTO other.t VALUES (42);
CREATE USER 'ro'@'%' IDENTIFIED BY '` + ROPassword + `';
GRANT SELECT, SHOW VIEW ON app.* TO 'ro'@'%';
GRANT SELECT ON other.* TO 'ro'@'%';
CREATE USER 'rw'@'%' IDENTIFIED BY '` + RWPassword + `';
GRANT ALL PRIVILEGES ON *.* TO 'rw'@'%';
`

const mariadbSeed = `
USE app;
INSERT INTO app.big (status, email, created_at)
  SELECT IF(seq % 10 = 0, 'failed', 'sent'), CONCAT('user', seq, '@example.com'), NOW() - INTERVAL seq MINUTE FROM seq_1_to_50000;
ANALYZE TABLE app.big, app.small;
`

const mysqlSeed = `
SET SESSION cte_max_recursion_depth = 100000;
INSERT INTO app.big (status, email, created_at)
  WITH RECURSIVE seq (n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM seq WHERE n < 50000)
  SELECT IF(n % 10 = 0, 'failed', 'sent'), CONCAT('user', n, '@example.com'), NOW() - INTERVAL n MINUTE FROM seq;
ANALYZE TABLE app.big, app.small;
`

type mysqlTarget struct {
	flavor  engine.Flavor
	version string
}

func (m mysqlTarget) image() string { return string(m.flavor) + ":" + m.version }

func mysqlTargets() []mysqlTarget {
	var out []mysqlTarget
	for _, img := range Versions("LOCKSQL_IT_MYSQL", "mariadb:10.11", "mariadb:11.4", "mysql:8.0", "mysql:8.4") {
		flavor, version, _ := strings.Cut(strings.TrimSpace(img), ":")
		out = append(out, mysqlTarget{engine.Flavor(flavor), version})
	}
	return out
}

func startMySQL(t *testing.T, m mysqlTarget) Server {
	env := []string{"MYSQL_ROOT_PASSWORD=" + RootPassword}
	cli := "mysql"
	seed := mysqlSeed
	if m.flavor == engine.FlavorMariaDB {
		env = []string{"MARIADB_ROOT_PASSWORD=" + RootPassword}
		cli, seed = "mariadb", mariadbSeed
	}
	ready := func(ctx context.Context, host string, port int) error {
		c, err := client.ConnectWithContext(ctx, fmt.Sprintf("%s:%d", host, port), "root", RootPassword, "", 3*time.Second)
		if err != nil {
			return err
		}
		defer c.Close()
		_, err = c.Execute("SELECT 1")
		return err
	}
	return Start(t, m.image(), 3306, env, ready, func(s Server) error {
		return Exec(s, mysqlSeedCommon+seed, cli, "-uroot", "-p"+RootPassword)
	})
}

func mysqlProfile(m mysqlTarget, srv Server, user string, tier config.Tier, timeout time.Duration) config.Profile {
	return config.Profile{
		Name: "it", Engine: string(m.flavor), Host: srv.Host, Port: srv.Port, User: user,
		Database: "app", Credentials: config.CredentialsAsk, Tier: tier,
		Limits: config.Limits{StatementTimeout: timeout, MaxRows: 200},
	}
}

func connectMySQL(t *testing.T, m mysqlTarget, srv Server, user string, tier config.Tier, timeout time.Duration) engine.Session {
	t.Helper()
	e, err := engine.Get(string(m.flavor))
	if err != nil {
		t.Fatal(err)
	}
	pw := ROPassword
	if user == "rw" {
		pw = RWPassword
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	s, err := e.Connect(ctx, mysqlProfile(m, srv, user, tier, timeout), []byte(pw), nil)
	if err != nil {
		t.Fatalf("connect %s: %v", user, err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func read(q string) sqlclass.Statement {
	return sqlclass.Statement{Class: sqlclass.Read, Kind: "select", SQL: q, Limit: -1}
}

func mustRun(t *testing.T, s engine.Session, q string) engine.Result {
	t.Helper()
	r, err := s.Run(context.Background(), "app", read(q), 100)
	if err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return r
}

func TestMySQL(t *testing.T) {
	for _, m := range mysqlTargets() {
		t.Run(m.image(), func(t *testing.T) {
			srv := startMySQL(t, m)
			testMySQLServer(t, m, srv)
		})
	}
}

func testMySQLServer(t *testing.T, m mysqlTarget, srv Server) {
	ctx := context.Background()

	t.Run("version and flavor", func(t *testing.T) {
		s := connectMySQL(t, m, srv, "ro", config.TierRead, 5*time.Second)
		if s.Flavor() != m.flavor {
			t.Errorf("flavor = %s, want %s", s.Flavor(), m.flavor)
		}
		if !strings.HasPrefix(s.ServerVersion(), m.version+".") {
			t.Errorf("version = %q, want prefix %s.", s.ServerVersion(), m.version)
		}
		if !s.OriginColumns() {
			t.Error("OriginColumns = false")
		}
		if err := s.Ping(ctx); err != nil {
			t.Error(err)
		}
	})

	t.Run("privileges", func(t *testing.T) {
		ro := connectMySQL(t, m, srv, "ro", config.TierRead, 5*time.Second)
		extra, err := ro.ExtraPrivileges(ctx, config.TierRead)
		if err != nil || len(extra) != 0 {
			t.Errorf("ro extras = %q, %v", extra, err)
		}
		rw := connectMySQL(t, m, srv, "rw", config.TierRead, 5*time.Second)
		extra, err = rw.ExtraPrivileges(ctx, config.TierRead)
		// MariaDB reports ALL PRIVILEGES as such; MySQL 8 expands it into
		// the list of static and dynamic privileges.
		want := []string{"ALL PRIVILEGES"}
		if m.flavor == engine.FlavorMySQL {
			want = []string{"INSERT", "DROP", "SUPER"}
		}
		for _, w := range want {
			if err != nil || !slices.Contains(extra, w) {
				t.Errorf("rw extras = %q, %v; want %s", extra, err, w)
			}
		}
		for _, e := range extra {
			if strings.Contains(e, RWPassword) || strings.Contains(e, "*") && strings.Contains(e, "PASSWORD") {
				t.Errorf("extra leaks a credential: %q", e)
			}
		}
		extra, err = rw.ExtraPrivileges(ctx, config.TierAdmin)
		if err != nil || len(extra) != 0 {
			t.Errorf("rw extras at tier admin = %q, %v", extra, err)
		}
	})

	t.Run("tier read blocks writes for rw", func(t *testing.T) {
		s := connectMySQL(t, m, srv, "rw", config.TierRead, 5*time.Second)
		ins := sqlclass.Statement{Class: sqlclass.Write, Kind: "insert", SQL: "INSERT INTO small VALUES (9, 'z')", Limit: -1}
		if _, err := s.Run(ctx, "app", ins, 10); err == nil {
			t.Fatal("write statement ran on tier read")
		}
		// A classifier bypass, simulated: the server's read-only
		// transaction must still refuse the write.
		ins.Class = sqlclass.Read
		_, err := s.Run(ctx, "app", ins, 10)
		if err == nil || !strings.Contains(strings.ToUpper(err.Error()), "READ ONLY") {
			t.Fatalf("mislabelled INSERT: err = %v", err)
		}
		r := mustRun(t, s, "SELECT COUNT(*) FROM small WHERE id = 9")
		if fmt.Sprint(r.Rows[0][0]) != "0" {
			t.Errorf("row written: %v", r.Rows)
		}
	})

	t.Run("server timeout", func(t *testing.T) {
		s := connectMySQL(t, m, srv, "ro", config.TierRead, time.Second)
		start := time.Now()
		_, err := s.Run(ctx, "app", read("SELECT SLEEP(5)"), 10)
		if err == nil {
			t.Fatal("SLEEP(5) was not interrupted")
		}
		if d := time.Since(start); d > 3500*time.Millisecond {
			t.Errorf("interrupted after %s", d)
		}
		if r := mustRun(t, s, "SELECT 1"); fmt.Sprint(r.Rows) != "[[1]]" {
			t.Errorf("after timeout: %v", r.Rows)
		}
	})

	t.Run("context cancel kills the query", func(t *testing.T) {
		s := connectMySQL(t, m, srv, "rw", config.TierWrite, 30*time.Second)
		cctx, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		start := time.Now()
		_, err := s.Run(cctx, "app", read("SELECT SLEEP(5)"), 10)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err = %v, want deadline exceeded", err)
		}
		if d := time.Since(start); d > 3500*time.Millisecond {
			t.Errorf("cancelled after %s", d)
		}
		for range 3 {
			if r := mustRun(t, s, "SELECT 1"); fmt.Sprint(r.Rows) != "[[1]]" {
				t.Errorf("after cancel: %v", r.Rows)
			}
		}
	})

	t.Run("databases hide system schemas", func(t *testing.T) {
		s := connectMySQL(t, m, srv, "rw", config.TierRead, 5*time.Second)
		dbs, err := s.Databases(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(dbs, "app") || !slices.Contains(dbs, "other") {
			t.Errorf("databases = %q", dbs)
		}
		for _, sys := range []string{"mysql", "information_schema", "performance_schema", "sys"} {
			if slices.Contains(dbs, sys) {
				t.Errorf("databases include %s: %q", sys, dbs)
			}
		}
	})

	t.Run("origin columns", func(t *testing.T) {
		s := connectMySQL(t, m, srv, "ro", config.TierRead, 5*time.Second)
		r := mustRun(t, s, "SELECT email AS x, CONCAT(email, '') AS y, b.id FROM big b ORDER BY id LIMIT 1")
		c := r.Columns
		if len(c) != 3 || c[0].Label != "x" || c[0].OriginDB != "app" || c[0].OriginTable != "big" || c[0].OriginColumn != "email" {
			t.Errorf("x = %+v", c)
		}
		if c[1].HasOrigin() {
			t.Errorf("expression has an origin: %+v", c[1])
		}
		if c[2].Label != "id" || c[2].OriginTable != "big" || c[2].OriginColumn != "id" {
			t.Errorf("id = %+v", c[2])
		}
	})

	t.Run("untrusted origins are dropped", func(t *testing.T) {
		admin := connectMySQL(t, m, srv, "rw", config.TierDDL, 5*time.Second)
		ddl := func(q string) {
			t.Helper()
			if _, err := admin.Run(ctx, "app", sqlclass.Statement{Class: sqlclass.DDL, Kind: "ddl", SQL: q, Limit: -1}, 0); err != nil {
				t.Fatalf("%s: %v", q, err)
			}
		}
		ddl("CREATE VIEW v_big AS SELECT id, email FROM big")
		t.Cleanup(func() { ddl("DROP VIEW IF EXISTS v_big") })
		s := connectMySQL(t, m, srv, "ro", config.TierRead, 5*time.Second)
		rules := pii.Rules{Mask: []string{"app.big.email"}}
		for _, q := range []string{
			// MariaDB reports the derived table as the origin (app.d.x).
			"SELECT d.x FROM (SELECT email AS x FROM big) d ORDER BY d.x LIMIT 1",
			// The alias names an existing base table and column.
			"SELECT small.label FROM (SELECT email AS label FROM big) small ORDER BY 1 LIMIT 1",
			"WITH small AS (SELECT email AS label FROM big) SELECT small.label FROM small ORDER BY 1 LIMIT 1",
			// A view reports itself, not the table behind it.
			"SELECT email AS e FROM v_big ORDER BY id LIMIT 1",
		} {
			r := mustRun(t, s, q)
			if len(r.Columns) != 1 || r.Columns[0].HasOrigin() {
				t.Errorf("%s: columns = %+v", q, r.Columns)
				continue
			}
			if !pii.NeedsAliasCheck(r, s.OriginColumns()) {
				t.Errorf("%s: no alias check", q)
			}
			st, err := sqlclass.Classify(sqlclass.MySQL, q, 200)
			if err != nil {
				t.Fatalf("%s: %v", q, err)
			}
			if pii.AliasViolation(st, rules, sqlclass.MySQL) == nil {
				t.Errorf("%s: not refused", q)
			}
		}
		// A plain base-table column keeps its origin, and the view case
		// without a rename is masked by name.
		r := mustRun(t, s, "SELECT email FROM v_big ORDER BY id LIMIT 1")
		pii.MaskResult(&r, rules, nil, s.OriginColumns())
		if v := fmt.Sprint(r.Rows[0][0]); v != "<redacted>" { // the rule has no mode
			t.Errorf("view email not masked: %s", v)
		}
		r = mustRun(t, s, "SELECT b.email FROM big b ORDER BY id LIMIT 1")
		if c := r.Columns[0]; c.OriginTable != "big" || c.OriginColumn != "email" {
			t.Errorf("base column origin = %+v", c)
		}
	})

	t.Run("an alias on a view gives no origin", func(t *testing.T) {
		admin := connectMySQL(t, m, srv, "rw", config.TierDDL, 5*time.Second)
		ddl := func(q string) {
			t.Helper()
			if _, err := admin.Run(ctx, "app", sqlclass.Statement{Class: sqlclass.DDL, Kind: "ddl", SQL: q, Limit: -1}, 0); err != nil {
				t.Fatalf("%s: %v", q, err)
			}
		}
		ddl("CREATE VIEW v_def AS SELECT id, email AS label FROM big")
		ddl("CREATE ALGORITHM = MERGE VIEW v_merge AS SELECT id, email AS label FROM big")
		t.Cleanup(func() { ddl("DROP VIEW IF EXISTS v_def, v_merge") })
		s := connectMySQL(t, m, srv, "ro", config.TierRead, 5*time.Second)
		rules := pii.Rules{Mask: []string{"app.big.email", "app.v_def.label", "app.v_merge.label"}}
		// MariaDB reports a merged view column read through an alias as
		// app.<alias>.<view column>, which names a real column of small.
		assertNoLeak(t, s, sqlclass.MySQL, rules, []string{
			"SELECT small.label FROM v_def AS small ORDER BY id LIMIT 5",
			"SELECT small.label FROM v_merge small ORDER BY id LIMIT 5",
			"SELECT label FROM v_merge AS small ORDER BY id LIMIT 5",
		})
		r := mustRun(t, s, "SELECT small.label FROM v_def AS small ORDER BY id LIMIT 5")
		if c := r.Columns[0]; c.HasOrigin() {
			t.Errorf("view through alias origin = %+v", c)
		}
		// A base table read through an alias keeps its origin.
		r = mustRun(t, s, "SELECT s.label FROM small AS s ORDER BY id LIMIT 1")
		if c := r.Columns[0]; c.OriginTable != "small" || c.OriginColumn != "label" {
			t.Errorf("base column through alias origin = %+v", c)
		}
	})

	t.Run("no leak through unicode names, stars or union heads", func(t *testing.T) {
		s := connectMySQL(t, m, srv, "ro", config.TierRead, 5*time.Second)
		assertNoLeak(t, s, sqlclass.MySQL, pii.Rules{Mask: []string{"app.big.email"}}, leakQueries(sqlclass.MySQL))
	})

	t.Run("no leak through rows returned by a write", func(t *testing.T) {
		s := connectMySQL(t, m, srv, "rw", config.TierWrite, 5*time.Second)
		assertNoLeak(t, s, sqlclass.MySQL, pii.Rules{Mask: []string{"app.big.email"}}, writeLeakQueries(sqlclass.MySQL))
	})

	t.Run("placeholder and reference round trip", func(t *testing.T) {
		id := insertObrien(t, connectMySQL(t, m, srv, "rw", config.TierWrite, 5*time.Second), "big")
		s := connectMySQL(t, m, srv, "ro", config.TierRead, 5*time.Second)
		assertPlaceholderRoundTrip(t, s, pii.Rules{Mask: []string{"app.big.email"}}, id)
	})

	t.Run("tls when the server offers it", func(t *testing.T) {
		s := connectMySQL(t, m, srv, "ro", config.TierRead, 5*time.Second)
		r := mustRun(t, s, "SHOW SESSION STATUS LIKE 'Ssl_cipher'")
		cipher := ""
		if len(r.Rows) == 1 {
			cipher = fmt.Sprint(r.Rows[0][1])
		}
		// mariadb:10.11 images ship without a certificate; MariaDB 11.4
		// and MySQL 8 generate one at startup.
		wantTLS := !(m.flavor == engine.FlavorMariaDB && strings.HasPrefix(m.version, "10."))
		if wantTLS && cipher == "" {
			t.Errorf("no TLS: %v", r.Rows)
		}
		if !wantTLS && cipher != "" {
			t.Logf("TLS on a server expected without it: %s", cipher)
		}
	})

	t.Run("multi-statements are rejected", func(t *testing.T) {
		c, err := client.ConnectWithContext(ctx, fmt.Sprintf("%s:%d", srv.Host, srv.Port), "ro", ROPassword, "app",
			5*time.Second, lsmysql.DriverOptions()...)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if _, err := c.Execute("SELECT 1; SELECT 2"); err == nil {
			t.Error("driver accepted two statements")
		}
		s := connectMySQL(t, m, srv, "ro", config.TierRead, 5*time.Second)
		if _, err := s.Run(ctx, "app", read("SELECT 1; SELECT 2"), 10); err == nil {
			t.Error("Run accepted two statements")
		}
	})

	t.Run("rows, truncation and values", func(t *testing.T) {
		s := connectMySQL(t, m, srv, "ro", config.TierRead, 5*time.Second)
		r, err := s.Run(ctx, "app", read("SELECT id FROM big ORDER BY id LIMIT 10"), 3)
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Rows) != 3 || !r.Truncated {
			t.Errorf("rows = %v truncated = %v", r.Rows, r.Truncated)
		}
		r = mustRun(t, s, "SELECT 1, -2, 1.5e0, NULL, 'é', CAST('x' AS BINARY), 12.50, 18446744073709551615")
		want := []any{int64(1), int64(-2), 1.5, nil, "é", []byte("x"), "12.50", uint64(18446744073709551615)}
		for i, w := range want {
			if fmt.Sprintf("%T %v", r.Rows[0][i], r.Rows[0][i]) != fmt.Sprintf("%T %v", w, w) {
				t.Errorf("col %d = %T %v, want %T %v", i, r.Rows[0][i], r.Rows[0][i], w, w)
			}
		}
		r, err = s.Run(ctx, "other", read("SELECT id FROM t"), 10)
		if err != nil || fmt.Sprint(r.Rows) != "[[42]]" {
			t.Errorf("db switch: %v %v", r.Rows, err)
		}
		if _, err := s.Run(ctx, "nope", read("SELECT 1"), 10); err == nil {
			t.Error("unknown database accepted")
		}
	})

	t.Run("write tier", func(t *testing.T) {
		s := connectMySQL(t, m, srv, "rw", config.TierWrite, 5*time.Second)
		up := sqlclass.Statement{Class: sqlclass.Write, Kind: "update", SQL: "UPDATE small SET label = 'z' WHERE id = 3", Limit: -1}
		r, err := s.Run(ctx, "app", up, 10)
		if err != nil || r.Affected != 1 {
			t.Fatalf("update: %+v %v", r, err)
		}
		bad := sqlclass.Statement{Class: sqlclass.Write, Kind: "update", SQL: "UPDATE small SET id = 1 WHERE id = 2", Limit: -1}
		if _, err := s.Run(ctx, "app", bad, 10); err == nil {
			t.Fatal("duplicate key update succeeded")
		}
		if r := mustRun(t, s, "SELECT label FROM small WHERE id IN (2, 3) ORDER BY id"); fmt.Sprint(r.Rows) != "[[b] [z]]" {
			t.Errorf("after write: %v", r.Rows)
		}
		up.SQL = "UPDATE small SET label = 'c' WHERE id = 3"
		if _, err := s.Run(ctx, "app", up, 10); err != nil {
			t.Fatal(err)
		}
		ddl := sqlclass.Statement{Class: sqlclass.DDL, Kind: "create", SQL: "CREATE TABLE x (id INT)", Limit: -1}
		if _, err := s.Run(ctx, "app", ddl, 10); err == nil {
			t.Error("DDL ran on tier write")
		}
	})

	t.Run("catalog", func(t *testing.T) {
		s := connectMySQL(t, m, srv, "ro", config.TierRead, 5*time.Second)
		tables, err := s.Tables(ctx, "app")
		if err != nil || fmt.Sprint(tables) != "[big small]" {
			t.Errorf("tables = %v, %v", tables, err)
		}
		info, err := s.Describe(ctx, "app", "big")
		if err != nil {
			t.Fatal(err)
		}
		if len(info.Columns) != 4 || info.Columns[0].Name != "id" || !info.Columns[0].PrimaryKey || info.Columns[0].Nullable {
			t.Errorf("columns = %+v", info.Columns)
		}
		if info.Columns[2].Name != "email" || info.Columns[2].Type != "varchar(100)" || !info.Columns[2].Nullable {
			t.Errorf("email = %+v", info.Columns[2])
		}
		var idx []string
		for _, i := range info.Indexes {
			idx = append(idx, fmt.Sprintf("%s%v%v%v", i.Name, i.Columns, i.Unique, i.Primary))
		}
		if fmt.Sprint(idx) != "[PRIMARY[id]truetrue idx_created[created_at]falsefalse]" {
			t.Errorf("indexes = %v", idx)
		}
		if info.EstRows < 10_000 {
			t.Errorf("est rows = %d", info.EstRows)
		}
		if _, err := s.Describe(ctx, "app", "missing"); err == nil {
			t.Error("missing table described")
		}
		cols, err := s.Columns(ctx, "app")
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(cols, engine.ColumnInfo{DB: "app", Table: "big", Column: "email", Type: "varchar(100)"}) {
			t.Errorf("columns = %+v", cols)
		}
	})

	t.Run("explain", func(t *testing.T) {
		s := connectMySQL(t, m, srv, "ro", config.TierRead, 5*time.Second)
		p, err := s.Explain(ctx, "app", "SELECT * FROM big WHERE status = 'x' LIMIT 10")
		if err != nil {
			t.Fatal(err)
		}
		if len(p.Root.Children) != 1 || p.Root.Children[0].Table != "big" || p.Root.Children[0].Access != engine.AccessFull {
			t.Errorf("plan = %+v", p.Root)
		}
		if _, err := s.Explain(ctx, "app", "SELECT 1; SELECT 2"); err == nil {
			t.Error("explain accepted two statements")
		}
		w := connectMySQL(t, m, srv, "rw", config.TierWrite, 5*time.Second)
		p, err = w.Explain(ctx, "app", "UPDATE small SET label = 'q' WHERE id = 1")
		if err != nil {
			t.Fatalf("explain update: %v", err)
		}
		if len(p.Root.Children) != 1 || p.Root.Children[0].Table != "small" {
			t.Errorf("update plan = %+v", p.Root)
		}
		if r := mustRun(t, w, "SELECT label FROM small WHERE id = 1"); fmt.Sprint(r.Rows) != "[[a]]" {
			t.Errorf("explain changed data: %v", r.Rows)
		}
	})

	t.Run("lost connection", func(t *testing.T) {
		s := connectMySQL(t, m, srv, "ro", config.TierRead, 5*time.Second)
		id := fmt.Sprint(mustRun(t, s, "SELECT CONNECTION_ID()").Rows[0][0])
		admin := connectMySQL(t, m, srv, "rw", config.TierAdmin, 5*time.Second)
		kill := sqlclass.Statement{Class: sqlclass.Admin, Kind: "kill", SQL: "KILL CONNECTION " + id, Limit: -1}
		if _, err := admin.Run(ctx, "app", kill, 10); err != nil {
			t.Fatal(err)
		}
		_, err := s.Run(ctx, "app", read("SELECT 1"), 10)
		if !errors.Is(err, engine.ErrConnLost) {
			t.Errorf("err = %v, want ErrConnLost", err)
		}
		if err := s.Ping(ctx); !errors.Is(err, engine.ErrConnLost) {
			t.Errorf("ping = %v, want ErrConnLost", err)
		}
	})

	t.Run("bad password is not echoed", func(t *testing.T) {
		e, _ := engine.Get(string(m.flavor))
		_, err := e.Connect(ctx, mysqlProfile(m, srv, "ro", config.TierRead, time.Second), []byte("wrong-secret-xyz"), nil)
		if err == nil || strings.Contains(err.Error(), "wrong-secret-xyz") {
			t.Errorf("err = %v", err)
		}
	})
}
