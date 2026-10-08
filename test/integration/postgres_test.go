//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	_ "github.com/DavidGodefroid/locksql/internal/engine/postgres"
	"github.com/DavidGodefroid/locksql/internal/pii"
	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

// Test-only password of the CREATEROLE account.
const CRPassword = "cr-test-only"

// The seed runs as the superuser "postgres" in database "app". Roles: ro
// (SELECT only), rw (SELECT, INSERT, UPDATE, DELETE), cr (CREATEROLE, no
// table privilege). CREATE on schema public is revoked from PUBLIC so that
// PostgreSQL 13 behaves like 15+.
const postgresSeed = `
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
CREATE TABLE big (id serial PRIMARY KEY, status varchar(20), email varchar(100), created_at timestamptz);
CREATE INDEX idx_created ON big (created_at);
CREATE TABLE small (id int PRIMARY KEY, label varchar(20));
CREATE VIEW v_big AS SELECT id, email FROM big;
INSERT INTO small VALUES (1, 'a'), (2, 'b'), (3, 'c');
INSERT INTO big (status, email, created_at)
  SELECT CASE WHEN n % 10 = 0 THEN 'failed' ELSE 'sent' END, 'user' || n || '@example.com',
         TIMESTAMPTZ '2026-01-01 00:00:00+00' - n * INTERVAL '1 minute'
  FROM generate_series(1, 50000) AS n;
ANALYZE;
CREATE ROLE ro LOGIN PASSWORD '` + ROPassword + `';
CREATE ROLE rw LOGIN PASSWORD '` + RWPassword + `';
CREATE ROLE cr LOGIN CREATEROLE PASSWORD '` + CRPassword + `';
GRANT SELECT ON ALL TABLES IN SCHEMA public TO ro;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO rw;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO rw;
CREATE DATABASE other;
\c other
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
CREATE TABLE t (id int PRIMARY KEY);
INSERT INTO t VALUES (42);
GRANT SELECT ON t TO ro, rw;
`

func pgVersions() []string { return Versions("LOCKSQL_IT_POSTGRES", "13", "17") }

func startPostgres(t *testing.T, version string) Server {
	env := []string{"POSTGRES_PASSWORD=" + RootPassword, "POSTGRES_DB=app"}
	ready := func(ctx context.Context, host string, port int) error {
		c, err := pgx.Connect(ctx, fmt.Sprintf("host=%s port=%d user=postgres password=%s dbname=app sslmode=disable",
			host, port, RootPassword))
		if err != nil {
			return err
		}
		defer c.Close(context.Background())
		return c.Ping(ctx)
	}
	return Start(t, "postgres:"+version, 5432, env, ready, func(s Server) error {
		return Exec(s, postgresSeed, "psql", "-q", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "app")
	})
}

func pgProfile(srv Server, user string, tier config.Tier, timeout time.Duration) config.Profile {
	return config.Profile{
		Name: "it", Engine: config.EnginePostgres, Host: srv.Host, Port: srv.Port, User: user,
		Database: "app", Credentials: config.CredentialsAsk, Tier: tier,
		Limits: config.Limits{StatementTimeout: timeout, MaxRows: 200},
	}
}

func pgPassword(user string) string {
	switch user {
	case "postgres":
		return RootPassword
	case "rw":
		return RWPassword
	case "cr":
		return CRPassword
	}
	return ROPassword
}

func connectPG(t *testing.T, srv Server, user string, tier config.Tier, timeout time.Duration) engine.Session {
	t.Helper()
	e, err := engine.Get(config.EnginePostgres)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	s, err := e.Connect(ctx, pgProfile(srv, user, tier, timeout), []byte(pgPassword(user)))
	if err != nil {
		t.Fatalf("connect %s: %v", user, err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestPostgres(t *testing.T) {
	for _, v := range pgVersions() {
		t.Run("postgres:"+v, func(t *testing.T) {
			srv := startPostgres(t, v)
			testPostgresServer(t, v, srv)
		})
	}
}

func testPostgresServer(t *testing.T, version string, srv Server) {
	ctx := context.Background()

	t.Run("version and flavor", func(t *testing.T) {
		s := connectPG(t, srv, "ro", config.TierRead, 5*time.Second)
		if s.Flavor() != engine.FlavorPostgres {
			t.Errorf("flavor = %s", s.Flavor())
		}
		if !strings.HasPrefix(s.ServerVersion(), version+".") {
			t.Errorf("version = %q, want prefix %s.", s.ServerVersion(), version)
		}
		if !s.OriginColumns() {
			t.Error("OriginColumns = false")
		}
		if err := s.Ping(ctx); err != nil {
			t.Error(err)
		}
	})

	t.Run("tier read blocks writes for a superuser", func(t *testing.T) {
		s := connectPG(t, srv, "postgres", config.TierRead, 5*time.Second)
		ins := sqlclass.Statement{Class: sqlclass.Write, Kind: "insert", SQL: "INSERT INTO small VALUES (9, 'z')", Limit: -1}
		if _, err := s.Run(ctx, "app", ins, 10); err == nil {
			t.Fatal("write statement ran on tier read")
		}
		// A classifier bypass, simulated: BEGIN READ ONLY must still
		// refuse the write.
		ins.Class = sqlclass.Read
		_, err := s.Run(ctx, "app", ins, 10)
		if err == nil || !strings.Contains(err.Error(), "read-only transaction") {
			t.Fatalf("mislabelled INSERT: err = %v", err)
		}
		// So must the session default, for a statement that would end the
		// read-only transaction.
		r := mustRun(t, s, "SELECT current_setting('default_transaction_read_only'), count(*) FROM small WHERE id = 9")
		if fmt.Sprint(r.Rows) != "[[on 0]]" {
			t.Errorf("after write attempt: %v", r.Rows)
		}
	})

	t.Run("statement timeout", func(t *testing.T) {
		s := connectPG(t, srv, "ro", config.TierRead, time.Second)
		start := time.Now()
		_, err := s.Run(ctx, "app", read("SELECT pg_sleep(5)"), 10)
		if err == nil {
			t.Fatal("pg_sleep(5) was not interrupted")
		}
		if !strings.Contains(err.Error(), "statement timeout") {
			t.Errorf("err = %v", err)
		}
		if d := time.Since(start); d > 3500*time.Millisecond {
			t.Errorf("interrupted after %s", d)
		}
		if r := mustRun(t, s, "SELECT 1"); fmt.Sprint(r.Rows) != "[[1]]" {
			t.Errorf("after timeout: %v", r.Rows)
		}
	})

	t.Run("context cancel stops the query", func(t *testing.T) {
		s := connectPG(t, srv, "rw", config.TierWrite, 30*time.Second)
		cctx, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		start := time.Now()
		_, err := s.Run(cctx, "app", read("SELECT pg_sleep(5)"), 10)
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

	t.Run("privileges", func(t *testing.T) {
		cases := []struct {
			user string
			tier config.Tier
			want []string // nil: no extra
		}{
			{"ro", config.TierRead, nil},
			{"rw", config.TierRead, []string{"INSERT", "UPDATE", "DELETE"}},
			{"rw", config.TierWrite, nil},
			{"cr", config.TierRead, []string{"CREATEROLE"}},
			{"cr", config.TierDDL, []string{"CREATEROLE"}},
			{"postgres", config.TierDDL, []string{"SUPERUSER"}},
			{"postgres", config.TierAdmin, nil},
		}
		for _, c := range cases {
			s := connectPG(t, srv, c.user, config.TierRead, 5*time.Second)
			extra, err := s.ExtraPrivileges(ctx, c.tier)
			if err != nil {
				t.Errorf("%s at %s: %v", c.user, c.tier, err)
				continue
			}
			if c.want == nil && len(extra) != 0 {
				t.Errorf("%s at %s: extras = %q, want none", c.user, c.tier, extra)
			}
			for _, w := range c.want {
				if !slices.Contains(extra, w) {
					t.Errorf("%s at %s: extras = %q, want %s", c.user, c.tier, extra, w)
				}
			}
		}
	})

	t.Run("origin columns", func(t *testing.T) {
		s := connectPG(t, srv, "ro", config.TierRead, 5*time.Second)
		r := mustRun(t, s, "SELECT email AS x, email || '' AS y, b.id FROM big b ORDER BY id LIMIT 1")
		c := r.Columns
		if len(c) != 3 || c[0].Label != "x" || c[0].OriginDB != "public" || c[0].OriginTable != "big" || c[0].OriginColumn != "email" {
			t.Errorf("x = %+v", c)
		}
		if c[1].HasOrigin() {
			t.Errorf("expression has an origin: %+v", c[1])
		}
		if c[2].Label != "id" || c[2].OriginTable != "big" || c[2].OriginColumn != "id" {
			t.Errorf("id = %+v", c[2])
		}
		// A view would report itself, not the table behind it: such an
		// origin is dropped, so masking falls back to the column name and
		// the alias check.
		r = mustRun(t, s, "SELECT email AS e FROM v_big ORDER BY id LIMIT 1")
		if c := r.Columns[0]; c.HasOrigin() {
			t.Errorf("view column origin = %+v", c)
		}
		if !pii.NeedsAliasCheck(r, s.OriginColumns()) {
			t.Error("view: no alias check")
		}
		// Derived tables and CTEs resolve to the base table.
		r = mustRun(t, s, "WITH c AS (SELECT email AS x FROM big) SELECT d.x FROM (SELECT x FROM c) d LIMIT 1")
		if c := r.Columns[0]; c.OriginTable != "big" || c.OriginColumn != "email" {
			t.Errorf("derived column origin = %+v", c)
		}
	})

	t.Run("no leak through unicode names, stars or union heads", func(t *testing.T) {
		s := connectPG(t, srv, "ro", config.TierRead, 5*time.Second)
		assertNoLeak(t, s, sqlclass.Postgres, pii.Rules{Mask: []string{"public.big.email"}}, leakQueries(sqlclass.Postgres))
	})

	t.Run("no leak through rows returned by a write", func(t *testing.T) {
		s := connectPG(t, srv, "rw", config.TierWrite, 5*time.Second)
		assertNoLeak(t, s, sqlclass.Postgres, pii.Rules{Mask: []string{"public.big.email"}}, writeLeakQueries(sqlclass.Postgres))
	})

	t.Run("origins follow a rename by another session", func(t *testing.T) {
		admin := connectPG(t, srv, "postgres", config.TierAdmin, 5*time.Second)
		ddl := func(q string) {
			t.Helper()
			if _, err := admin.Run(ctx, "app", sqlclass.Statement{Class: sqlclass.DDL, Kind: "ddl", SQL: q, Limit: -1}, 0); err != nil {
				t.Fatalf("%s: %v", q, err)
			}
		}
		ddl("CREATE TABLE ren (id int, notes text)")
		t.Cleanup(func() { ddl("DROP TABLE IF EXISTS ren") })
		ddl("GRANT SELECT ON ren TO ro")
		s := connectPG(t, srv, "ro", config.TierRead, 5*time.Second)
		if c := mustRun(t, s, "SELECT notes AS n FROM ren").Columns[0]; c.OriginColumn != "notes" {
			t.Fatalf("before rename: %+v", c)
		}
		ddl("ALTER TABLE ren RENAME COLUMN notes TO email")
		if c := mustRun(t, s, "SELECT email AS n FROM ren").Columns[0]; c.OriginTable != "ren" || c.OriginColumn != "email" {
			t.Errorf("after rename: %+v", c)
		}
	})

	t.Run("partitions, inheritance and foreign tables", func(t *testing.T) {
		admin := connectPG(t, srv, "postgres", config.TierAdmin, 30*time.Second)
		ddl := func(q string) {
			t.Helper()
			if _, err := admin.Run(ctx, "app", sqlclass.Statement{Class: sqlclass.DDL, Kind: "ddl", SQL: q, Limit: -1}, 0); err != nil {
				t.Fatalf("%s: %v", q, err)
			}
		}
		t.Cleanup(func() {
			ddl("DROP TABLE IF EXISTS pt, ip, ic, secret CASCADE")
			ddl("DROP EXTENSION IF EXISTS postgres_fdw CASCADE")
		})
		// Partitions: one direct, one two levels down, one attached with
		// another column order (different attribute numbers).
		ddl("CREATE TABLE pt (id int, email text) PARTITION BY RANGE (id)")
		ddl("CREATE TABLE pt_1 PARTITION OF pt FOR VALUES FROM (0) TO (100)")
		ddl("CREATE TABLE pt_2 PARTITION OF pt FOR VALUES FROM (100) TO (200) PARTITION BY RANGE (id)")
		ddl("CREATE TABLE pt_2a PARTITION OF pt_2 FOR VALUES FROM (100) TO (200)")
		ddl("CREATE TABLE pt_3 (email text, id int)")
		ddl("ALTER TABLE pt ATTACH PARTITION pt_3 FOR VALUES FROM (200) TO (300)")
		ddl("INSERT INTO pt VALUES (1, 'p1@example.com'), (150, 'p2@example.com'), (250, 'p3@example.com')")
		// Classic inheritance.
		ddl("CREATE TABLE ip (id int, email text)")
		ddl("CREATE TABLE ic () INHERITS (ip)")
		ddl("INSERT INTO ic VALUES (1, 'i1@example.com')")
		// A foreign table over a loopback server.
		ddl("CREATE TABLE secret (id int, email text)")
		ddl("INSERT INTO secret VALUES (1, 'f1@example.com')")
		ddl("CREATE EXTENSION postgres_fdw")
		ddl("CREATE SERVER loop FOREIGN DATA WRAPPER postgres_fdw OPTIONS (host 'localhost', dbname 'app')")
		ddl("CREATE USER MAPPING FOR ro SERVER loop OPTIONS (user 'postgres', password_required 'false')")
		ddl("CREATE FOREIGN TABLE ft (id int, email text) SERVER loop OPTIONS (table_name 'secret')")
		ddl("GRANT SELECT ON pt, pt_1, pt_2, pt_2a, pt_3, ip, ic, secret, ft TO ro")

		s := connectPG(t, srv, "ro", config.TierRead, 5*time.Second)
		for _, rel := range []string{"pt_1", "pt_2", "pt_2a", "pt_3"} {
			c := mustRun(t, s, "SELECT email FROM "+rel+" LIMIT 1").Columns[0]
			if c.OriginDB != "public" || c.OriginTable != "pt" || c.OriginColumn != "email" {
				t.Errorf("%s: origin = %+v, want the root public.pt.email", rel, c)
			}
		}
		for _, rel := range []string{"ip", "ic", "ft"} {
			if c := mustRun(t, s, "SELECT email FROM "+rel+" LIMIT 1").Columns[0]; c.HasOrigin() {
				t.Errorf("%s: origin = %+v, want none", rel, c)
			}
		}
		assertNoLeak(t, s, sqlclass.Postgres, pii.Rules{Mask: []string{"public.pt.email"}}, []string{
			"SELECT email FROM pt_1 LIMIT 5", "SELECT email FROM pt_2a LIMIT 5", "SELECT id, email FROM pt_3 LIMIT 5",
		})
		assertNoLeak(t, s, sqlclass.Postgres, pii.Rules{Mask: []string{"public.ic.email"}}, []string{
			"SELECT email FROM ip LIMIT 5", "SELECT email FROM ONLY ic LIMIT 5",
		})
		assertNoLeak(t, s, sqlclass.Postgres, pii.Rules{Mask: []string{"public.ip.email"}}, []string{
			"SELECT email FROM ic LIMIT 5",
		})
		assertNoLeak(t, s, sqlclass.Postgres, pii.Rules{Mask: []string{"public.secret.email"}}, []string{
			"SELECT email FROM ft LIMIT 5", "SELECT f.email FROM ft f LIMIT 5",
		})
	})

	t.Run("multi-statements are rejected", func(t *testing.T) {
		// The driver mode the engine uses (extended protocol) refuses a
		// second statement on the server side.
		cfg, err := pgx.ParseConfig(fmt.Sprintf("host=%s port=%d user=ro password=%s dbname=app sslmode=disable",
			srv.Host, srv.Port, ROPassword))
		if err != nil {
			t.Fatal(err)
		}
		cfg.DefaultQueryExecMode = pgx.QueryExecModeExec
		c, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close(ctx)
		rows, err := c.Query(ctx, "SELECT 1; SELECT 2")
		if err == nil {
			rows.Close()
			err = rows.Err()
		}
		if err == nil {
			t.Error("extended protocol accepted two statements")
		}
		s := connectPG(t, srv, "ro", config.TierRead, 5*time.Second)
		if _, err := s.Run(ctx, "app", read("SELECT 1; SELECT 2"), 10); err == nil {
			t.Error("Run accepted two statements")
		}
	})

	t.Run("rows, truncation and values", func(t *testing.T) {
		s := connectPG(t, srv, "ro", config.TierRead, 5*time.Second)
		r, err := s.Run(ctx, "app", read("SELECT id FROM big ORDER BY id LIMIT 10"), 3)
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Rows) != 3 || !r.Truncated {
			t.Errorf("rows = %v truncated = %v", r.Rows, r.Truncated)
		}
		r = mustRun(t, s, `SELECT 1, -2::int8, 1.5::float8, NULL, 'é', decode('78', 'hex'), 12.50::numeric, true,
			'2026-01-02 03:04:05+00'::timestamptz AT TIME ZONE 'UTC', 3::int2`)
		want := []any{int64(1), int64(-2), 1.5, nil, "é", []byte("x"), "12.50", true, "2026-01-02 03:04:05", int64(3)}
		for i, w := range want {
			if fmt.Sprintf("%T %v", r.Rows[0][i], r.Rows[0][i]) != fmt.Sprintf("%T %v", w, w) {
				t.Errorf("col %d = %T %v, want %T %v", i, r.Rows[0][i], r.Rows[0][i], w, w)
			}
		}
		r = mustRun(t, s, "SELECT 'NaN'::float8")
		if f, ok := r.Rows[0][0].(float64); !ok || !math.IsNaN(f) {
			t.Errorf("NaN = %T %v", r.Rows[0][0], r.Rows[0][0])
		}
		r, err = s.Run(ctx, "other", read("SELECT id FROM t"), 10)
		if err != nil || fmt.Sprint(r.Rows) != "[[42]]" {
			t.Errorf("db switch: %v %v", r.Rows, err)
		}
		if r := mustRun(t, s, "SELECT current_database()"); fmt.Sprint(r.Rows) != "[[app]]" {
			t.Errorf("default database after a switch: %v", r.Rows)
		}
		if _, err := s.Run(ctx, "nope", read("SELECT 1"), 10); err == nil {
			t.Error("unknown database accepted")
		}
		if r := mustRun(t, s, "SELECT 1"); fmt.Sprint(r.Rows) != "[[1]]" {
			t.Errorf("after an unknown database: %v", r.Rows)
		}
	})

	t.Run("write tier", func(t *testing.T) {
		s := connectPG(t, srv, "rw", config.TierWrite, 5*time.Second)
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
		ins := sqlclass.Statement{Class: sqlclass.Write, Kind: "insert", SQL: "INSERT INTO small VALUES (7, 'q') RETURNING id, label", Limit: -1}
		r, err = s.Run(ctx, "app", ins, 10)
		if err != nil || r.Affected != 1 || fmt.Sprint(r.Rows) != "[[7 q]]" || r.Columns[1].OriginColumn != "label" {
			t.Errorf("insert returning: %+v %v", r, err)
		}
		del := sqlclass.Statement{Class: sqlclass.Write, Kind: "delete", SQL: "DELETE FROM small WHERE id = 7", Limit: -1}
		if r, err := s.Run(ctx, "app", del, 10); err != nil || r.Affected != 1 {
			t.Errorf("delete: %+v %v", r, err)
		}
		up.SQL = "UPDATE small SET label = 'c' WHERE id = 3"
		if _, err := s.Run(ctx, "app", up, 10); err != nil {
			t.Fatal(err)
		}
		ddl := sqlclass.Statement{Class: sqlclass.DDL, Kind: "create", SQL: "CREATE TABLE x (id int)", Limit: -1}
		if _, err := s.Run(ctx, "app", ddl, 10); err == nil {
			t.Error("DDL ran on tier write")
		}
	})

	t.Run("admin outside a transaction", func(t *testing.T) {
		s := connectPG(t, srv, "postgres", config.TierAdmin, 30*time.Second)
		vac := sqlclass.Statement{Class: sqlclass.Admin, Kind: "vacuum", SQL: "VACUUM small", Limit: -1}
		if _, err := s.Run(ctx, "app", vac, 10); err != nil {
			t.Errorf("vacuum: %v", err)
		}
		for _, q := range []string{"CLUSTER", "REINDEX SCHEMA public"} {
			st := sqlclass.Statement{Class: sqlclass.Admin, Kind: "admin", SQL: q, Limit: -1}
			if _, err := s.Run(ctx, "app", st, 10); err != nil {
				t.Errorf("%s: %v", q, err)
			}
		}
	})

	t.Run("catalog", func(t *testing.T) {
		s := connectPG(t, srv, "ro", config.TierRead, 5*time.Second)
		dbs, err := s.Databases(ctx)
		if err != nil || !slices.Contains(dbs, "app") || !slices.Contains(dbs, "other") || slices.Contains(dbs, "template1") {
			t.Errorf("databases = %q, %v", dbs, err)
		}
		tables, err := s.Tables(ctx, "app")
		if err != nil || fmt.Sprint(tables) != "[big small v_big]" {
			t.Errorf("tables = %v, %v", tables, err)
		}
		tables, err = s.Tables(ctx, "other")
		if err != nil || fmt.Sprint(tables) != "[t]" {
			t.Errorf("other tables = %v, %v", tables, err)
		}
		info, err := s.Describe(ctx, "app", "big")
		if err != nil {
			t.Fatal(err)
		}
		if info.DB != "public" || info.Table != "big" {
			t.Errorf("info = %s.%s", info.DB, info.Table)
		}
		if len(info.Columns) != 4 || info.Columns[0].Name != "id" || !info.Columns[0].PrimaryKey || info.Columns[0].Nullable ||
			info.Columns[0].Default == nil || !strings.HasPrefix(*info.Columns[0].Default, "nextval(") {
			t.Errorf("columns = %+v", info.Columns)
		}
		if info.Columns[2].Name != "email" || info.Columns[2].Type != "character varying(100)" || !info.Columns[2].Nullable {
			t.Errorf("email = %+v", info.Columns[2])
		}
		var idx []string
		for _, i := range info.Indexes {
			idx = append(idx, fmt.Sprintf("%s%v%v%v", i.Name, i.Columns, i.Unique, i.Primary))
		}
		if fmt.Sprint(idx) != "[big_pkey[id]truetrue idx_created[created_at]falsefalse]" {
			t.Errorf("indexes = %v", idx)
		}
		if info.EstRows < 10_000 {
			t.Errorf("est rows = %d", info.EstRows)
		}
		if info, err := s.Describe(ctx, "app", "public.small"); err != nil || len(info.Columns) != 2 {
			t.Errorf("qualified describe: %+v %v", info, err)
		}
		if info, err := s.Describe(ctx, "app", "v_big"); err != nil || info.EstRows != -1 {
			t.Errorf("view describe: %+v %v", info, err)
		}
		if _, err := s.Describe(ctx, "app", "missing"); err == nil {
			t.Error("missing table described")
		}
		cols, err := s.Columns(ctx, "app")
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(cols, engine.ColumnInfo{DB: "public", Table: "big", Column: "email", Type: "character varying(100)"}) {
			t.Errorf("columns = %+v", cols)
		}
		for _, c := range cols {
			if c.DB == "pg_catalog" || c.DB == "information_schema" {
				t.Fatalf("system column listed: %+v", c)
			}
		}
	})

	t.Run("explain", func(t *testing.T) {
		s := connectPG(t, srv, "ro", config.TierRead, 5*time.Second)
		p, err := s.Explain(ctx, "app", "SELECT * FROM big WHERE status = 'x' LIMIT 10")
		if err != nil {
			t.Fatal(err)
		}
		if len(p.Root.Children) != 1 || p.Root.Children[0].Table != "big" || p.Root.Children[0].Access != engine.AccessFull ||
			p.Root.Children[0].EstRows < 40_000 {
			t.Errorf("plan = %+v", p.Root)
		}
		if _, err := s.Explain(ctx, "app", "SELECT 1; SELECT 2"); err == nil {
			t.Error("explain accepted two statements")
		}
		w := connectPG(t, srv, "rw", config.TierWrite, 5*time.Second)
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
		if p, err := s.Explain(ctx, "other", "SELECT * FROM t LIMIT 1"); err != nil || p.Root.Children[0].Table != "t" {
			t.Errorf("explain in other: %+v %v", p.Root, err)
		}
	})

	t.Run("lost connection", func(t *testing.T) {
		s := connectPG(t, srv, "ro", config.TierRead, 5*time.Second)
		pid := fmt.Sprint(mustRun(t, s, "SELECT pg_backend_pid()").Rows[0][0])
		admin := connectPG(t, srv, "postgres", config.TierAdmin, 5*time.Second)
		if _, err := admin.Run(ctx, "app", read("SELECT pg_terminate_backend("+pid+")"), 10); err != nil {
			t.Fatal(err)
		}
		time.Sleep(200 * time.Millisecond)
		_, err := s.Run(ctx, "app", read("SELECT 1"), 10)
		if !errors.Is(err, engine.ErrConnLost) {
			t.Errorf("err = %v, want ErrConnLost", err)
		}
		if err := s.Ping(ctx); !errors.Is(err, engine.ErrConnLost) {
			t.Errorf("ping = %v, want ErrConnLost", err)
		}
	})

	t.Run("bad password is not echoed", func(t *testing.T) {
		e, _ := engine.Get(config.EnginePostgres)
		_, err := e.Connect(ctx, pgProfile(srv, "ro", config.TierRead, time.Second), []byte("wrong-secret-xyz"))
		if err == nil || strings.Contains(err.Error(), "wrong-secret-xyz") {
			t.Errorf("err = %v", err)
		}
	})
}
