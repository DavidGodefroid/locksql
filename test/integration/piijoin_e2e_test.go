//go:build integration

package integration

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/console"
	"github.com/DavidGodefroid/locksql/internal/engine"
	_ "github.com/DavidGodefroid/locksql/internal/engine/sqlite"
	"github.com/DavidGodefroid/locksql/internal/ipc"
	"github.com/DavidGodefroid/locksql/internal/pii"
	audit "github.com/DavidGodefroid/locksql/internal/sqlaudit"
)

// A join between two PII columns, end to end on SQLite and a fake lockhub
// (#150): the plan gives the agent no row estimate, the ticket the hub
// receives and the audit record of the decision carry the join warning,
// and no value appears in either.
//
//	go test -tags integration -run TestPIIJoinEndToEnd ./test/integration
func TestPIIJoinEndToEnd(t *testing.T) {
	path := filepath.Join(t.TempDir(), "piijoin.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		"CREATE TABLE people (id INTEGER PRIMARY KEY, email TEXT)",
		"CREATE TABLE contacts (id INTEGER PRIMARY KEY, email TEXT)",
		"INSERT INTO people VALUES (1, 'alice@example.com'), (2, 'bob@example.com')",
		"INSERT INTO contacts VALUES (1, 'alice@example.com'), (2, 'carol@example.com')",
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	db.Close()
	e, err := engine.Get(config.EngineSQLite)
	if err != nil {
		t.Fatal(err)
	}
	p := config.Profile{Name: "it", Engine: config.EngineSQLite, Path: path, Tier: config.TierRead,
		Credentials: config.CredentialsAsk, Limits: config.DefaultLimits(false)}
	s, err := e.Connect(context.Background(), p, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })

	state := t.TempDir()
	log, err := audit.Open(state)
	if err != nil {
		t.Fatal(err)
	}
	hub, fake := inProcessHub(t, yesIO{t})
	srv, err := console.NewServer(console.ServerConfig{
		Policy:    config.NewPolicy(p, []string{"main.people.email", "main.contacts.email"}, nil),
		RulesPath: filepath.Join(t.TempDir(), pii.RulesFile), Session: nopClose{s},
		DBUser: "it", Databases: []string{"main"}, Audit: log, IO: yesIO{t}, Version: "it", Hub: hub,
	})
	if err != nil {
		t.Fatal(err)
	}
	call := func(method string, params any, out any) *ipc.RPCError {
		t.Helper()
		raw, _ := json.Marshal(params)
		r := srv.Handle(context.Background(), ipc.Request{JSONRPC: "2.0", ID: 1, Method: method, Params: raw})
		if r.Error == nil && out != nil {
			if err := json.Unmarshal(r.Result, out); err != nil {
				t.Fatal(err)
			}
		}
		return r.Error
	}

	const q = "SELECT p.id FROM people p JOIN contacts c ON c.email = p.email LIMIT 5"
	const warning = "joins PII columns: main.contacts.email = main.people.email"
	var pr ipc.PlanResult
	if e := call(ipc.MethodQueryPlan, ipc.PlanParams{DB: "main", SQL: q}, &pr); e != nil {
		t.Fatalf("plan: %s", e.Message)
	}
	if pr.Summary != "estimates hidden: the statement joins PII columns" || pr.Reasons != nil {
		t.Fatalf("plan result gives estimates: %+v", pr)
	}
	var rr ipc.RunResult
	if e := call(ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}, &rr); e != nil || rr.Status != "pending" || rr.Ticket == "" {
		t.Fatalf("run: %+v %v, want pending", rr, e)
	}
	tk := rr.Ticket
	if raw := string(fake.Ticket(tk)); !strings.Contains(raw, warning) || strings.Contains(raw, "@example.com") {
		t.Fatalf("hub ticket: %s", raw)
	}
	fake.Decide(tk, ticket.Approved, "")
	rr = ipc.RunResult{}
	if e := untilDecided(t, 30*time.Second, 50*time.Millisecond, func(o any) *ipc.RPCError {
		return call(ipc.MethodQueryRun, ipc.RunParams{Ticket: tk}, o)
	}, &rr); e != nil {
		t.Fatalf("run of the ticket: %s", e.Message)
	}
	if len(rr.Rows) != 1 {
		t.Fatalf("rows %+v, want the one shared subject", rr.Rows)
	}
	b, err := os.ReadFile(filepath.Join(state, "locksql", "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	var decided bool
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(line, "@example.com") {
			t.Errorf("audit record names a value: %s", line)
		}
		if rec["ticket"] == tk && rec["event"] != "pending" && strings.Contains(line, warning) {
			decided = true
		}
	}
	if !decided {
		t.Errorf("no audit record of the decision carries the join warning:\n%s", b)
	}
}
