package postgres

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

func TestRegistered(t *testing.T) {
	e, err := engine.Get(config.EnginePostgres)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Connect(context.Background(), config.Profile{Engine: config.EngineMySQL}, nil, nil); err == nil {
		t.Error("connected a mysql profile")
	}
}

func TestConnConfigIgnoresTheEnvironment(t *testing.T) {
	t.Setenv("PGPASSWORD", "env-secret")
	t.Setenv("PGOPTIONS", "-c default_transaction_read_only=off")
	t.Setenv("PGSSLMODE", "disable")
	t.Setenv("PGTARGETSESSIONATTRS", "read-write")
	t.Setenv("PGDATABASE", "envdb")
	p := config.Profile{Engine: config.EnginePostgres, Host: "db.example", Port: 5433, User: "o'brien", Database: "app"}
	cfg, err := connConfig(p, []byte("s3cret"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Password != "s3cret" || cfg.Host != "db.example" || cfg.Port != 5433 || cfg.User != "o'brien" || cfg.Database != "app" {
		t.Errorf("config = %s@%s:%d/%s pw=%q", cfg.User, cfg.Host, cfg.Port, cfg.Database, cfg.Password)
	}
	if len(cfg.RuntimeParams) != 2 || cfg.RuntimeParams["application_name"] != "locksql" {
		t.Errorf("runtime params = %v", cfg.RuntimeParams)
	}
	if cfg.ValidateConnect != nil || cfg.AfterConnect != nil {
		t.Error("environment hooks kept")
	}
	if cfg.TLSConfig == nil {
		t.Error("PGSSLMODE=disable overrode the profile's tls mode")
	}
	if cfg.DefaultQueryExecMode != pgx.QueryExecModeExec {
		t.Errorf("exec mode = %v", cfg.DefaultQueryExecMode)
	}
	cfg, err = connConfig(config.Profile{Engine: config.EnginePostgres, Host: "h", User: "u"}, nil)
	if err != nil || cfg.Password != "" || cfg.Database == "envdb" {
		t.Errorf("no secret, no database: pw=%q db=%q err=%v", cfg.Password, cfg.Database, err)
	}
}

func TestKV(t *testing.T) {
	if got := kv("user", `a'b\c`); got != `user='a\'b\\c'` {
		t.Errorf("kv = %s", got)
	}
}

func TestValue(t *testing.T) {
	cases := []struct {
		raw  []byte
		oid  uint32
		want any
	}{
		{nil, pgtype.TextOID, nil},
		{[]byte("42"), pgtype.Int4OID, int64(42)},
		{[]byte("-9223372036854775808"), pgtype.Int8OID, int64(math.MinInt64)},
		{[]byte("1.5"), pgtype.Float8OID, 1.5},
		{[]byte("Infinity"), pgtype.Float8OID, math.Inf(1)},
		{[]byte("-Infinity"), pgtype.Float4OID, math.Inf(-1)},
		{[]byte("t"), pgtype.BoolOID, true},
		{[]byte("f"), pgtype.BoolOID, false},
		{[]byte(`\x00ff`), pgtype.ByteaOID, []byte{0, 255}},
		{[]byte("12.50"), pgtype.NumericOID, "12.50"},
		{[]byte("2026-01-02 03:04:05+00"), pgtype.TimestamptzOID, "2026-01-02 03:04:05+00"},
		{[]byte{0xff, 0xfe}, pgtype.TextOID, []byte{0xff, 0xfe}},
		{[]byte(""), pgtype.TextOID, ""},
	}
	for _, c := range cases {
		got := value(c.raw, c.oid)
		if fmt.Sprintf("%T %v", got, got) != fmt.Sprintf("%T %v", c.want, c.want) {
			t.Errorf("value(%q, %d) = %T %v, want %T %v", c.raw, c.oid, got, got, c.want, c.want)
		}
	}
	if f, ok := value([]byte("NaN"), pgtype.Float8OID).(float64); !ok || !math.IsNaN(f) {
		t.Error("NaN not decoded")
	}
	// The driver reuses its buffer: values must not alias it.
	buf := []byte(`\x41`)
	b := value(buf, pgtype.ByteaOID).([]byte)
	s := value([]byte("ab"), pgtype.TextOID).(string)
	buf[2] = '0'
	if string(b) != "A" || s != "ab" {
		t.Error("value aliases the driver buffer")
	}
}

func TestNeedsNoTx(t *testing.T) {
	cases := map[string]bool{
		"VACUUM":                                 true,
		"VACUUM ANALYZE big":                     true,
		"CREATE DATABASE x":                      true,
		"DROP DATABASE x":                        true,
		"CREATE INDEX CONCURRENTLY i ON t (x)":   true,
		"REINDEX TABLE CONCURRENTLY t":           true,
		"CREATE TABLE t (id int)":                false,
		"CREATE TABLE database (id int)":         false,
		"ANALYZE big":                            false,
		"COMMENT ON TABLE t IS 'CONCURRENTLY'":   false,
		"REFRESH MATERIALIZED VIEW CONCURRENTLY": true,
		"REINDEX DATABASE app":                   true,
		"REINDEX SYSTEM app":                     true,
		"REINDEX SCHEMA public":                  true,
		"REINDEX (VERBOSE) DATABASE app":         true,
		"REINDEX TABLE t":                        false,
		"REINDEX INDEX database":                 false,
		"CLUSTER":                                true,
		"CLUSTER VERBOSE":                        true,
		"CLUSTER (VERBOSE)":                      true,
		"CLUSTER t":                              false,
		"CLUSTER VERBOSE t USING i":              false,
	}
	for q, want := range cases {
		class := sqlclass.DDL
		if strings.HasPrefix(q, "VACUUM") || strings.HasPrefix(q, "ANALYZE") || strings.HasPrefix(q, "RE") || strings.HasPrefix(q, "CLUSTER") {
			class = sqlclass.Admin
		}
		if got := needsNoTx(sqlclass.Statement{Class: class, SQL: q}); got != want {
			t.Errorf("needsNoTx(%q) = %v, want %v", q, got, want)
		}
	}
	if needsNoTx(sqlclass.Statement{Class: sqlclass.Write, SQL: "UPDATE t SET x = 1 -- VACUUM"}) {
		t.Error("write outside a transaction")
	}
}

func TestLexSingle(t *testing.T) {
	if err := lexSingle("SELECT ';' FROM t"); err != nil {
		t.Error(err)
	}
	if err := lexSingle("SELECT $$;$$"); err != nil {
		t.Error(err)
	}
	for _, q := range []string{"SELECT 1; SELECT 2", "SELECT 1;"} {
		if err := lexSingle(q); err == nil {
			t.Errorf("lexSingle(%q) accepted", q)
		}
	}
}

func TestRunRefusesAboveTier(t *testing.T) {
	s := &session{tier: config.TierRead, conns: map[string]*dbConn{}}
	st := sqlclass.Statement{Class: sqlclass.Write, SQL: "DELETE FROM t", Limit: -1}
	if _, err := s.Run(context.Background(), "", st, 10); err == nil || !strings.Contains(err.Error(), "exceeds tier") {
		t.Errorf("err = %v", err)
	}
	st = sqlclass.Statement{Class: sqlclass.Read, SQL: "SELECT 1; DELETE FROM t", Limit: -1}
	if _, err := s.Run(context.Background(), "", st, 10); err == nil {
		t.Error("chained statement accepted")
	}
}

func TestCondAccessAndRefersTo(t *testing.T) {
	for cond, want := range map[string]string{
		"":                                   engine.AccessIndex,
		"(t.id = 3)":                         engine.AccessLookup,
		"((t.a = 1) AND (t.b = 'x<y'))":      engine.AccessLookup,
		"(t.id > 3)":                         engine.AccessRange,
		"(t.id <> 3)":                        engine.AccessRange,
		"(t.id = ANY ('{1,2}'::integer[]))":  engine.AccessRange,
		"((t.name)::text ~~ 'ab%'::text)":    engine.AccessRange,
		"(t.geom && '(0,0),(1,1)'::box)":     engine.AccessRange,
		"(t.doc @> '{\"a\": 1}'::jsonb)":     engine.AccessRange,
		"((t.s)::text = 'it''s > ok'::text)": engine.AccessLookup,
	} {
		if got := condAccess(cond); got != want {
			t.Errorf("condAccess(%q) = %s, want %s", cond, got, want)
		}
	}
	for expr, want := range map[string]bool{
		"(b.x = a.x)":         true,
		"(b.x = ba.x)":        false,
		"(b.x = 'a.x')":       false,
		`(b.x = "a".x)`:       true,
		"((a.x)::text = b.y)": true,
		"(b.x = 1)":           false,
	} {
		if got := refersTo(expr, []string{"a"}); got != want {
			t.Errorf("refersTo(%q) = %v, want %v", expr, got, want)
		}
	}
}

func TestFailKeepsTheSessionOnLocalErrors(t *testing.T) {
	s := &session{conns: map[string]*dbConn{}}
	cause := errors.New("explain: not a JSON plan")
	err := s.fail(context.Background(), nil, localError{cause})
	if !errors.Is(err, cause) || errors.Is(err, engine.ErrConnLost) {
		t.Errorf("err = %v", err)
	}
	if s.dead.Load() {
		t.Error("a local error killed the session")
	}
}

func TestConnConfigFallbacks(t *testing.T) {
	base := config.Profile{Engine: config.EnginePostgres, Host: "db.example", User: "u"}
	cases := []struct {
		mode          string
		wantTLS       bool
		wantFallbacks int // plain fallbacks
	}{
		{config.TLSDisable, false, 0},
		{config.TLSPrefer, true, 1},
		{config.TLSRequire, true, 0},
		{config.TLSVerifyFull, true, 0},
	}
	for _, c := range cases {
		p := base
		p.TLS = c.mode
		cfg, err := connConfig(p, nil)
		if err != nil {
			t.Fatalf("%s: %v", c.mode, err)
		}
		if (cfg.TLSConfig != nil) != c.wantTLS {
			t.Errorf("%s: TLSConfig = %v", c.mode, cfg.TLSConfig)
		}
		plain := 0
		for _, fb := range cfg.Fallbacks {
			if fb.TLSConfig == nil {
				plain++
			}
		}
		if plain != c.wantFallbacks {
			t.Errorf("%s: %d plain fallbacks, want %d", c.mode, plain, c.wantFallbacks)
		}
	}
	p := base
	p.TLS = config.TLSVerifyFull
	cfg, _ := connConfig(p, nil)
	if cfg.TLSConfig.ServerName != "db.example" || cfg.TLSConfig.InsecureSkipVerify {
		t.Errorf("verify-full: %+v", cfg.TLSConfig)
	}
}
