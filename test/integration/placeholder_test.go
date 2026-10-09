//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/locksql/internal/audit"
	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/console"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/ipc"
	"github.com/DavidGodefroid/locksql/internal/pii"
	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

// secretIO approves every prompt, answers the value prompt with secret and
// keeps what the console prints.
type secretIO struct {
	secret string
	mu     sync.Mutex
	out    []string
}

func (s *secretIO) Println(line string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.out = append(s.out, line)
}
func (s *secretIO) Ask(context.Context, string, time.Duration) (string, bool) { return "y", true }
func (s *secretIO) AskSecret(context.Context, string) ([]byte, error) {
	return []byte(s.secret), nil
}

// placeholderValue is the typed value of the round trip: a quote, so that
// the substitution's quoting reaches the engine.
const placeholderValue = "o'brien@example.org"

// assertPlaceholderRoundTrip runs, through a console server on a real
// engine, a typed placeholder on the masked big.email and a reference to a
// redacted cell of an earlier result. Each must find the right row; no
// value may reach the client answers, the console screen or the audit log.
// The row holding placeholderValue must exist, with id obrienID.
func assertPlaceholderRoundTrip(t *testing.T, s engine.Session, rules pii.Rules, obrienID int64) {
	t.Helper()
	dir := t.TempDir()
	log, err := audit.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	p := config.Profile{Name: "it", Engine: string(s.Flavor()), Host: "127.0.0.1", Tier: config.TierRead, Credentials: config.CredentialsAsk,
		Limits: config.DefaultLimits(false), Detectors: []string{"email"}}
	io := &secretIO{secret: placeholderValue}
	srv, err := console.NewServer(console.ServerConfig{
		Policy: config.NewPolicy(p, rules.Mask, rules.Allow), RulesPath: filepath.Join(t.TempDir(), pii.RulesFile), Session: nopClose{s},
		DBUser: "it", Databases: []string{"app"}, Audit: log, IO: io, Version: "it",
	})
	if err != nil {
		t.Fatal(err)
	}
	var answers []string
	run := func(q string) ipc.RunResult {
		t.Helper()
		call := func(method string, params any) ipc.Response {
			raw, _ := json.Marshal(params)
			resp := srv.Handle(context.Background(), ipc.Request{JSONRPC: "2.0", ID: 1, Method: method, Params: raw})
			answers = append(answers, string(resp.Result))
			if resp.Error != nil {
				answers = append(answers, resp.Error.Message)
				t.Fatalf("%s: %s\nconsole:\n%s", q, resp.Error.Message, strings.Join(io.out, "\n"))
			}
			return resp
		}
		var pr ipc.PlanResult
		if err := json.Unmarshal(call(ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: q}).Result, &pr); err != nil {
			t.Fatal(err)
		}
		var rr ipc.RunResult
		if err := json.Unmarshal(call(ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}).Result, &rr); err != nil {
			t.Fatal(err)
		}
		return rr
	}
	id := func(rr ipc.RunResult, want int64) {
		t.Helper()
		if len(rr.Rows) != 1 || fmt.Sprint(rr.Rows[0][0]) != fmt.Sprint(want) {
			t.Errorf("rows %v, want the row with id %d", rr.Rows, want)
		}
	}

	// A typed value with a quote finds its row; the agent gets a reference.
	rr := run("SELECT id, email FROM big WHERE email = '${email}' LIMIT 5")
	id(rr, obrienID)
	if len(rr.Rows) == 1 && rr.Rows[0][1] != "<redacted:r1.1.2>" {
		t.Errorf("email cell %v", rr.Rows[0][1])
	}
	// The reference to that cell finds the same row, with no prompt.
	io.secret = "unused@example.org"
	id(run("SELECT id, status FROM big WHERE email = '${r1.1.2}' LIMIT 5"), obrienID)
	// A reference to a cell the agent never filtered on.
	rr = run("SELECT id, email FROM big WHERE id = 7 LIMIT 1")
	if len(rr.Rows) != 1 || rr.Rows[0][1] != "<redacted:r3.1.2>" {
		t.Fatalf("rows %v", rr.Rows)
	}
	id(run("SELECT id FROM big WHERE email IN ('${r3.1.2}') LIMIT 5"), 7)

	b, err := os.ReadFile(filepath.Join(dir, "locksql", "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	io.mu.Lock()
	screen := strings.Join(io.out, "\n")
	io.mu.Unlock()
	for where, text := range map[string]string{"client answers": strings.Join(answers, "\n"), "audit log": string(b), "console screen": screen} {
		for _, v := range []string{"brien", "user7@"} {
			if strings.Contains(text, v) {
				t.Errorf("%q reached the %s", v, where)
			}
		}
	}
	if !strings.Contains(string(b), "${r3.1.2}") {
		t.Error("the audit log lacks the statement as written")
	}
}

func insertObrien(t *testing.T, s engine.Session, table string) int64 {
	t.Helper()
	ins := sqlclass.Statement{Class: sqlclass.Write, Kind: "insert",
		SQL: "INSERT INTO " + table + " (status, email) VALUES ('sent', 'o''brien@example.org')", Limit: -1}
	if _, err := s.Run(context.Background(), "app", ins, 10); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		del := sqlclass.Statement{Class: sqlclass.Write, Kind: "delete",
			SQL: "DELETE FROM " + table + " WHERE email = 'o''brien@example.org'", Limit: -1}
		if _, err := s.Run(context.Background(), "app", del, 10); err != nil {
			t.Error(err)
		}
	})
	r, err := s.Run(context.Background(), "app", read("SELECT id FROM "+table+" WHERE email = 'o''brien@example.org'"), 10)
	if err != nil || len(r.Rows) != 1 {
		t.Fatalf("seeded row: %v %v", r.Rows, err)
	}
	var id int64
	if _, err := fmt.Sscan(fmt.Sprint(r.Rows[0][0]), &id); err != nil {
		t.Fatal(err)
	}
	return id
}
