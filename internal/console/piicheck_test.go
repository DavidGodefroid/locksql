package console

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/ipc"
	"github.com/DavidGodefroid/locksql/internal/pii"
)

// pgCatalogSession is a PostgreSQL session whose database app holds
// public.customers: ColumnInfo.DB is the schema, as the engine reports it.
type pgCatalogSession struct{ *shadowSession }

func (s pgCatalogSession) Columns(_ context.Context, db string) ([]engine.ColumnInfo, error) {
	if s.colsErr != nil {
		return nil, s.colsErr
	}
	if db != "app" {
		return []engine.ColumnInfo{}, nil
	}
	return []engine.ColumnInfo{
		{DB: "public", Table: "customers", Column: "id", Type: "integer", Generated: true},
		{DB: "public", Table: "customers", Column: "name", Type: "text"},
	}, nil
}

// pgCatalog serves database app of a PostgreSQL profile whose customers
// rows carry fictitious names.
func pgCatalog(c *ServerConfig) {
	ss := &shadowSession{}
	withShadows(ss)(c)
	ss.result = engine.Result{
		Columns: []engine.ResultColumn{
			{Label: "id", OriginDB: "public", OriginTable: "customers", OriginColumn: "id"},
			{Label: "name", OriginDB: "public", OriginTable: "customers", OriginColumn: "name"},
		},
		Rows: [][]any{{int64(1), "Test Person One"}, {int64(2), "Test Person Two"}},
	}
	c.Session = pgCatalogSession{ss}
	c.Databases = []string{"app"}
	c.Policy = config.NewPolicy(pgProfile(), nil, nil)
}

func pgProfile() config.Profile {
	p := uatProfile()
	p.Engine, p.Port, p.Database = config.EnginePostgres, 5432, "app"
	return p
}

// withColumn adds a column to the catalog of the fake MySQL session.
func withColumn(db, table, column string) hopt {
	return func(c *ServerConfig) {
		f := c.Session.(*fakeSession)
		f.cols = append(f.cols, engine.ColumnInfo{DB: db, Table: table, Column: column, Type: "text"})
	}
}

func selectCustomers(t *testing.T, h *harness) [][]any {
	t.Helper()
	pr := h.plan(t, "SELECT id, name FROM customers LIMIT 10", false)
	h.io.answers = []string{"y"}
	var rr ipc.RunResult
	h.okRun(t, pr.PlanID, &rr)
	return rr.Rows
}

// On PostgreSQL the database.table.column form names no column (rules are
// schema.table.column): pii.add refuses it with the column meant, and the
// rule is neither saved nor in force (locksql#207).
func TestPIIAddPostgresDatabasePatternRefused(t *testing.T) {
	h := newHarness(t, pgProfile(), pgCatalog)
	resp := h.call(t, ipc.MethodPIIAdd, ipc.PIIAddParams{Pattern: "app.customers.name"})
	wantCode(t, resp, ipc.CodeInvalidParams)
	for _, want := range []string{"app.customers.name matches no column", "did you mean public.customers.name?", "schema.table.column", "schemas: public"} {
		if !strings.Contains(resp.Error.Message, want) {
			t.Errorf("refusal %q lacks %q", resp.Error.Message, want)
		}
	}
	if len(h.s.rules.Mask) != 0 {
		t.Errorf("rule in force: %v", h.s.rules.Mask)
	}
	if r, err := pii.LoadRulesFile(h.s.cfg.RulesPath); err != nil || len(r.Mask) != 0 {
		t.Errorf("rule saved: %+v %v", r, err)
	}
}

// The schema.table.column pattern masks the column at once (locksql#207).
func TestPIIAddPostgresSchemaPatternMasks(t *testing.T) {
	h := newHarness(t, pgProfile(), pgCatalog)
	if rows := selectCustomers(t, h); rows[0][1] != "Test Person One" {
		t.Fatalf("before the rule: %v", rows)
	}
	h.ok(t, ipc.MethodPIIAdd, ipc.PIIAddParams{Pattern: "public.customers.name"}, nil)
	rows := selectCustomers(t, h)
	for _, r := range rows {
		if r[1] != "<redacted>" {
			t.Fatalf("name in clear after the rule: %v", rows)
		}
	}
	var u ipc.PIIUnmatchedResult
	h.ok(t, ipc.MethodPIIUnmatched, nil, &u)
	if len(u.Mask) != 0 || len(u.Allow) != 0 {
		t.Errorf("live rule reported dead: %+v", u)
	}
}

// A glob that matches nothing today is added (it may match a column
// created later), and the console says so; pii.unmatched reports it.
func TestPIIAddGlobMatchingNothingWarned(t *testing.T) {
	h := newHarness(t, pgProfile(), pgCatalog)
	h.ok(t, ipc.MethodPIIAdd, ipc.PIIAddParams{Pattern: "*.*.iban*"}, nil)
	if !slices.Contains(h.s.rules.Mask, "*.*.iban*") {
		t.Fatalf("glob not in force: %v", h.s.rules.Mask)
	}
	if !strings.Contains(h.io.output(), "*.*.iban* matches no column today") {
		t.Errorf("no warning on the console: %q", h.io.output())
	}
	var u ipc.PIIUnmatchedResult
	h.ok(t, ipc.MethodPIIUnmatched, nil, &u)
	if !slices.Equal(u.Mask, []string{"*.*.iban*"}) {
		t.Errorf("pii.unmatched = %+v", u)
	}
}

// A catalog that cannot be read does not block a mask rule, which only
// tightens; the console says it was not checked, and pii.unmatched fails.
func TestPIIAddCatalogUnreadable(t *testing.T) {
	h := newHarness(t, pgProfile(), pgCatalog, func(c *ServerConfig) {
		c.Session.(pgCatalogSession).colsErr = errors.New("catalog unavailable")
	})
	h.ok(t, ipc.MethodPIIAdd, ipc.PIIAddParams{Pattern: "app.customers.name"}, nil)
	if !slices.Contains(h.s.rules.Mask, "app.customers.name") {
		t.Fatalf("rule not in force: %v", h.s.rules.Mask)
	}
	if !strings.Contains(h.io.output(), "not checked against the catalog") {
		t.Errorf("no notice on the console: %q", h.io.output())
	}
	if resp := h.call(t, ipc.MethodPIIUnmatched, nil); resp.Error == nil {
		t.Error("pii.unmatched answered without a catalog")
	}
}

// MySQL keeps db.table.column: an existing column is added, a missing one
// refused with the columns it may mean.
func TestPIIAddMySQLDatabasePattern(t *testing.T) {
	h := newHarness(t, uatProfile(), withColumn("app", "users", "phone"))
	h.ok(t, ipc.MethodPIIAdd, ipc.PIIAddParams{Pattern: "app.users.phone"}, nil)
	if !h.s.rules.Matches("app", "users", "phone") {
		t.Fatalf("rules: %+v", h.s.rules)
	}
	resp := h.call(t, ipc.MethodPIIAdd, ipc.PIIAddParams{Pattern: "shop.users.note"})
	wantCode(t, resp, ipc.CodeInvalidParams)
	if !strings.Contains(resp.Error.Message, "did you mean app.users.note, other.users.note?") || strings.Contains(resp.Error.Message, "PostgreSQL") {
		t.Errorf("refusal: %q", resp.Error.Message)
	}

	// Rules the human wrote that name no column are dead: pii.unmatched
	// lists them.
	var u ipc.PIIUnmatchedResult
	h.ok(t, ipc.MethodPIIUnmatched, nil, &u)
	if len(u.Mask) != 0 {
		t.Errorf("live rules reported dead: %+v", u)
	}
	h.s.rules.Mask = append(h.s.rules.Mask, "app.users.fax")
	h.s.rules.Allow = []string{"app.users.status", "app.users.gone"}
	h.ok(t, ipc.MethodPIIUnmatched, nil, &u)
	if !slices.Equal(u.Mask, []string{"app.users.fax"}) || !slices.Equal(u.Allow, []string{"app.users.gone"}) {
		t.Errorf("pii.unmatched = %+v", u)
	}
}
