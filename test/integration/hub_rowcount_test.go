//go:build integration

package integration

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	kconsole "github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/hubclient"
	"github.com/DavidGodefroid/lockkit/hubclient/hubtest"
	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/console"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/ipc"
	"github.com/DavidGodefroid/locksql/internal/pii"
	"github.com/DavidGodefroid/locksql/internal/product"
	audit "github.com/DavidGodefroid/locksql/internal/sqlaudit"
	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

// assertCountedRun checks a counted run on a real server (engine.RowChecker):
// update changes some rows; the check sees how many before the commit, an
// error of it rolls the write back (probe, a one-cell read, answers the
// same), and a nil one commits it.
func assertCountedRun(t *testing.T, s engine.Session, d sqlclass.Dialect, db, update, probe string) {
	t.Helper()
	ctx := context.Background()
	st, err := sqlclass.Classify(d, update, 0)
	if err != nil {
		t.Fatal(err)
	}
	cell := func() string {
		t.Helper()
		r, err := s.Run(ctx, db, sqlclass.Statement{Class: sqlclass.Read, Kind: "select", SQL: probe, Limit: -1}, 10)
		if err != nil || len(r.Rows) != 1 {
			t.Fatalf("%s: %v %v", probe, r.Rows, err)
		}
		return fmt.Sprint(r.Rows[0][0])
	}
	before := cell()
	over := errors.New("over the bound")
	var seen int64
	if _, err := engine.RunCounted(ctx, s, db, st, 10, func(n int64) error { seen = n; return over }); !errors.Is(err, over) || seen < 1 {
		t.Fatalf("counted run: %v after %d rows", err, seen)
	}
	if got := cell(); got != before {
		t.Fatalf("not rolled back: %q, was %q", got, before)
	}
	if err := s.Ping(ctx); err != nil {
		t.Fatalf("a failed check lost the session: %v", err)
	}
	res, err := engine.RunCounted(ctx, s, db, st, 10, func(int64) error { return nil })
	if err != nil || res.Affected != seen {
		t.Fatalf("committed run: %+v %v, want %d rows", res, err, seen)
	}
	if got := cell(); got == before {
		t.Fatalf("not committed: %q", got)
	}
}

// Hub mode on a real PostgreSQL (lockkit's fake hub): a write that would
// change more rows than its approval allows is rolled back in its own
// transaction and answered stale with a new ticket whose bound covers
// them (decision H2); approved again, it commits. Another agent's token
// is refused the ticket (H3).
func TestHubRowcountPG(t *testing.T) {
	srv := startPostgresVariant(t, "17", "hubrows")
	psql := func(sql string) {
		t.Helper()
		if err := Exec(srv, sql, "psql", "-q", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "app"); err != nil {
			t.Fatal(err)
		}
	}
	psql(`CREATE TABLE hr_t (id int PRIMARY KEY, label text);
INSERT INTO hr_t SELECT n, 'a' FROM generate_series(1, 5) n;
ANALYZE hr_t;
CREATE TABLE hr_log (id int);
CREATE FUNCTION hr_trg() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN INSERT INTO hr_log VALUES (NEW.id); RETURN NEW; END';
CREATE TABLE hr_trig (id int PRIMARY KEY, label text);
CREATE TRIGGER hr_trig_log AFTER UPDATE ON hr_trig FOR EACH ROW EXECUTE FUNCTION hr_trg();
INSERT INTO hr_trig VALUES (1, 'a');
GRANT SELECT, UPDATE, DELETE ON hr_t, hr_trig TO rw;
GRANT INSERT ON hr_log TO rw;`)
	rw := connectPG(t, srv, "rw", config.TierWrite, 30*time.Second)
	t.Run("counted run", func(t *testing.T) {
		assertCountedRun(t, rw, sqlclass.Postgres, "app", "UPDATE hr_t SET label = label || 'x' WHERE id = 1", "SELECT label FROM hr_t WHERE id = 1")
	})

	home := t.TempDir()
	const inst = "sql-rows"
	key, err := hubclient.InstanceKey(home, inst)
	if err != nil {
		t.Fatal(err)
	}
	hub := hubtest.New(t, inst, key.Public().(ed25519.PublicKey))
	keyFile := filepath.Join(t.TempDir(), "hub.pub")
	if err := os.WriteFile(keyFile, []byte(base64.StdEncoding.EncodeToString(hub.Pub)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h, err := kconsole.OpenHub(product.P, kconsole.HubOptions{URL: hub.URL(), KeyFile: keyFile, Instance: inst, Home: home}, t.TempDir(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	io := yesIO{t}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); h.Watch(ctx, io) }()
	t.Cleanup(func() { cancel(); <-done; _ = h.Close() })
	log, err := audit.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := config.Profile{Name: "it", Engine: config.EnginePostgres, Host: "127.0.0.1", Tier: config.TierWrite, Credentials: config.CredentialsAsk,
		Limits: config.DefaultLimits(false), Detectors: []string{}}
	s, err := console.NewServer(console.ServerConfig{
		Policy: config.NewPolicy(p, nil, nil), RulesPath: filepath.Join(t.TempDir(), pii.RulesFile), Session: nopClose{rw},
		DBUser: "it", Databases: []string{"app"}, Audit: log, IO: io, Version: "it", Hub: h, Approver: h.Approver(kconsole.NewTypedApprover(io)),
	})
	if err != nil {
		t.Fatal(err)
	}
	call := func(method string, params any, out any) *ipc.RPCError {
		t.Helper()
		raw, _ := json.Marshal(params)
		r := s.Handle(context.Background(), ipc.Request{JSONRPC: "2.0", ID: 1, Method: method, Params: raw})
		if r.Error == nil && out != nil {
			if err := json.Unmarshal(r.Result, out); err != nil {
				t.Fatal(err)
			}
		}
		return r.Error
	}
	agent := ipc.Requester{Agent: "dev-1", Token: "hash-of-dev-1"}
	type answer struct{ Status, Ticket string }
	submit := func(sql string) string {
		t.Helper()
		var pr ipc.PlanResult
		if e := call(ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: sql, Requester: agent}, &pr); e != nil {
			t.Fatalf("plan: %+v", e)
		}
		var a answer
		if e := call(ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID, Requester: agent}, &a); e != nil || a.Status != "pending" {
			t.Fatalf("run: %+v %+v", a, e)
		}
		return a.Ticket
	}
	run := func(tk string, who ipc.Requester, out any) *ipc.RPCError {
		t.Helper()
		deadline := time.Now().Add(20 * time.Second)
		for {
			e := call(ipc.MethodQueryRun, ipc.RunParams{Ticket: tk, Requester: who}, out)
			if e == nil || !strings.Contains(e.Message, "no decision") || time.Now().After(deadline) {
				return e
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	count := func() string {
		t.Helper()
		r, err := rw.Run(context.Background(), "app", sqlclass.Statement{Class: sqlclass.Read, Kind: "select", SQL: "SELECT count(*) FROM hr_t WHERE label = 'b'", Limit: -1}, 1)
		if err != nil {
			t.Fatal(err)
		}
		return fmt.Sprint(r.Rows[0][0])
	}

	// The planner expects a few rows (5 after ANALYZE); 40 more land
	// after the approval.
	const q = "UPDATE hr_t SET label = 'b' WHERE id > 4"
	tk := submit(q)
	// EXPLAIN of the write gave an estimate (without one the bound is 10).
	if raw := string(hub.Ticket(tk)); !strings.Contains(raw, "rows changed: at most ") || strings.Contains(raw, "at most 10 ") {
		t.Fatalf("the screen shows no bound: %s", raw)
	}
	psql(`INSERT INTO hr_t SELECT n, 'a' FROM generate_series(6, 45) n;`)
	hub.Decide(tk, ticket.Approved, "")
	if e := run(tk, ipc.Requester{Agent: "dev-2", Token: "hash-of-dev-2"}, nil); e == nil || e.Code != ipc.CodeWrongRequester {
		t.Fatalf("another agent's run: %+v", e)
	}
	var a answer
	if e := run(tk, agent, &a); e != nil || a.Status != "stale" || a.Ticket == "" || a.Ticket == tk {
		t.Fatalf("over the bound: %+v %+v", a, e)
	}
	if n := count(); n != "0" {
		t.Fatalf("the write over its bound committed %s rows", n)
	}
	if raw := string(hub.Ticket(a.Ticket)); !strings.Contains(raw, "would have changed 41 rows") {
		t.Fatalf("the new screen does not say why: %s", raw)
	}
	hub.Decide(a.Ticket, ticket.Approved, "")
	var rr ipc.RunResult
	if e := run(a.Ticket, agent, &rr); e != nil || rr.Affected != 41 {
		t.Fatalf("the new ticket: %+v %+v", rr, e)
	}
	if n := count(); n != "41" {
		t.Fatalf("committed %s rows, want 41", n)
	}

	// A data-modifying WITH: its command tag counts only the outer
	// statement, so it is refused before any ticket.
	t.Run("data-modifying WITH refused", func(t *testing.T) {
		pushed := hub.Pushed()
		var pr ipc.PlanResult
		e := call(ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: "WITH d AS (DELETE FROM hr_t WHERE id > 40 RETURNING id) UPDATE hr_t SET label = 'c' WHERE id = 1", Requester: agent}, &pr)
		if e == nil {
			e = call(ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID, Requester: agent}, nil)
		}
		if e == nil || e.Data == nil || e.Data.Code != "E_STATEMENT_KIND" || hub.Pushed() != pushed {
			t.Fatalf("data-modifying WITH: %+v (pushed %d)", e, hub.Pushed()-pushed)
		}
	})

	// A trigger changes rows the bound does not count: the ticket says so.
	t.Run("trigger named on the ticket", func(t *testing.T) {
		tk := submit("UPDATE hr_trig SET label = 'b' WHERE id = 1")
		raw := string(hub.Ticket(tk))
		if !strings.Contains(raw, "rows the bound does not count may change too") || !strings.Contains(raw, "hr_trig_log") || !strings.Contains(raw, "claims lea agent") {
			t.Fatalf("ticket: %s", raw)
		}
	})
}
