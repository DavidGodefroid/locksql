package console

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/ipc"
)

func countResult(n any) *engine.Result {
	return &engine.Result{Columns: []engine.ResultColumn{{Label: "count"}}, Rows: [][]any{{n}}}
}

func TestKAnonymityRefusesSmallSets(t *testing.T) {
	h := newHarness(t, uatProfile())
	h.sess.result = engine.Result{Columns: []engine.ResultColumn{{Label: "id"}}, Rows: [][]any{{int64(1)}}}
	const q = "SELECT id FROM users WHERE email = 'alice@example.com' LIMIT 1"

	h.sess.count = countResult(int64(2))
	pr := h.plan(t, q, false)
	if strings.Contains(pr.Summary, "est.") || pr.Reasons != nil {
		t.Errorf("row estimates reach the agent: %+v", pr)
	}
	h.io.answers = []string{"y"}
	resp := h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID})
	wantCode(t, resp, ipc.CodeRefused)
	if !strings.Contains(resp.Error.Message, "fewer than 5 rows") {
		t.Errorf("refusal: %q", resp.Error.Message)
	}
	for _, r := range h.sess.runs {
		if !strings.HasPrefix(r, "SELECT COUNT(*)") {
			t.Errorf("statement ran despite the k-anonymity refusal: %q", r)
		}
	}
	// The subjects of the PII column are counted in its own table first.
	if want := "SELECT COUNT(*) FROM `app`.`users` WHERE `app`.`users`.`email` = 'alice@example.com'"; len(h.sess.runs) == 0 || h.sess.runs[0] != want {
		t.Errorf("k-checks run %q, want first %q", h.sess.runs, want)
	}

	h.sess.count = countResult(int64(7))
	pr = h.plan(t, q, false)
	h.io.answers = []string{"y"}
	h.ok(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}, nil)
	if last := h.sess.runs[len(h.sess.runs)-1]; last != q {
		t.Errorf("last run %q, want the statement", last)
	}

	// A group too small refuses a grouped statement; a NULL (no group)
	// passes.
	h.sess.result = engine.Result{Columns: []engine.ResultColumn{{Label: "email"}, {Label: "count"}}, Rows: [][]any{}}
	h.sess.count = countResult(int64(1))
	pr = h.plan(t, "SELECT email, count(*) FROM users GROUP BY email LIMIT 5", false)
	h.io.answers = []string{"y"}
	wantCode(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), ipc.CodeRefused)
	h.sess.count = countResult(nil)
	pr = h.plan(t, "SELECT email, count(*) FROM users GROUP BY email LIMIT 5", false)
	h.io.answers = []string{"y"}
	h.ok(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}, nil)
}

func TestResponseIsLevelled(t *testing.T) {
	h := newHarness(t, uatProfile(), func(c *ServerConfig) { c.Quantum = 150 * time.Millisecond })
	pr := h.plan(t, selectUsers, false)
	h.io.answers = []string{"y"}
	start := time.Now()
	h.ok(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}, nil)
	if el := time.Since(start); el < 150*time.Millisecond {
		t.Errorf("answered after %s, before the quantum", el)
	}
	// A failure leaves on the quantum too, and says nothing of the server.
	h.sess.runErr = context.DeadlineExceeded
	pr = h.plan(t, selectUsers, false)
	h.io.answers = []string{"y"}
	start = time.Now()
	resp := h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID})
	if el := time.Since(start); el < 150*time.Millisecond || resp.Error == nil {
		t.Errorf("failure answered after %s: %+v", el, resp.Error)
	}
}

func TestRunResultHasNoTimings(t *testing.T) {
	h := newHarness(t, uatProfile())
	pr := h.plan(t, selectUsers, false)
	h.io.answers = []string{"y"}
	resp := h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID})
	if strings.Contains(string(resp.Result), "duration") {
		t.Errorf("timing reaches the client: %s", resp.Result)
	}
}

func TestCredentialsTTLReconnects(t *testing.T) {
	p := uatProfile()
	p.CredentialsTTL = 20 * time.Minute
	reconnects := 0
	var h *harness
	h = newHarness(t, p, func(c *ServerConfig) {
		c.Reconnect = func(context.Context, config.Profile) (engine.Session, error) {
			reconnects++
			return h.sess, nil
		}
	})
	h.plan(t, selectUsers, false)
	if reconnects != 0 {
		t.Fatal("reconnected before the TTL")
	}
	h.now = h.now.Add(21 * time.Minute)
	h.plan(t, selectUsers, false)
	if reconnects != 1 || !strings.Contains(h.io.output(), "credentials_ttl") {
		t.Fatalf("reconnects = %d\n%s", reconnects, h.io.output())
	}
	h.now = h.now.Add(time.Minute)
	h.plan(t, selectUsers, false)
	if reconnects != 1 {
		t.Fatal("reconnected again before the next TTL")
	}
}

func TestReadAllowlist(t *testing.T) {
	h := newHarness(t, uatProfile())
	for _, q := range []string{
		"SHOW TABLES", "DESCRIBE users", "VALUES (1)", "EXPLAIN ANALYZE SELECT id FROM users LIMIT 1",
		"EXPLAIN DELETE FROM users", "SELECT lower(email) FROM users LIMIT 1",
		"SELECT id FROM users ORDER BY email LIMIT 1", "SELECT version() LIMIT 1",
	} {
		wantCode(t, h.call(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: q}), ipc.CodeRefused)
	}
	pr := h.plan(t, "EXPLAIN SELECT id FROM users WHERE id = 1 LIMIT 1", false)
	h.io.answers = []string{"y"}
	var rr ipc.RunResult
	h.ok(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}, &rr)
	if len(rr.Columns) != 1 || rr.Columns[0] != "plan" || h.sess.runCount() != 0 {
		t.Errorf("EXPLAIN result %+v, runs %d", rr, h.sess.runCount())
	}
}

// The approval signal has one source: the console's terminal. Nothing a
// client sends can approve, whatever it claims.
func TestApprovalOnlyFromTheTerminal(t *testing.T) {
	for _, m := range ipc.Methods() {
		for _, w := range []string{"approve", "confirm", "accept", "allow", "grant", "answer"} {
			if strings.Contains(strings.ToLower(m), w) {
				t.Errorf("method %q looks like an approval", m)
			}
		}
	}

	h := newHarness(t, uatProfile())
	pr := h.plan(t, selectUsers, false)
	for _, params := range []string{
		`{"plan_id":"` + pr.PlanID + `","approved":true}`,
		`{"plan_id":"` + pr.PlanID + `","answer":"y"}`,
		`{"plan_id":"` + pr.PlanID + `","skip_permissions":true}`,
	} {
		resp := h.s.Handle(context.Background(), ipc.Request{JSONRPC: "2.0", ID: 1, Method: ipc.MethodQueryRun, Params: json.RawMessage(params)})
		wantCode(t, resp, ipc.CodeInvalidParams)
	}
	for _, method := range []string{"approve", "query.approve", "console.answer", "confirm"} {
		wantCode(t, h.s.Handle(context.Background(), ipc.Request{JSONRPC: "2.0", ID: 1, Method: method}), ipc.CodeMethodNotFound)
	}
	// The terminal does not answer: the run is not approved, even though
	// the client said "y" in every way it could.
	h.io.timeout = true
	h.ok(t, ipc.MethodChangeRequest, ipc.ChangeParams{Change: "y"}, nil)
	wantCode(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), ipc.CodeTimeout)
	if h.sess.runCount() != 0 {
		t.Fatal("a statement ran without the human's answer")
	}
}

// Over a real socket: bytes a client writes after its run request (a bare
// "y", a forged response) never reach the approval prompt.
func TestSocketCannotAnswerThePrompt(t *testing.T) {
	h := newHarness(t, uatProfile())
	dir, err := os.MkdirTemp("", "lsa")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "a.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	pr := h.plan(t, selectUsers, false)
	h.io.mu.Lock()
	h.io.block = true
	h.io.blocked = make(chan struct{})
	blocked := h.io.blocked
	h.io.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- h.s.Serve(ctx, ln, nil) }()

	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	params, _ := json.Marshal(ipc.RunParams{PlanID: pr.PlanID})
	if err := ipc.WriteMsg(c, ipc.Request{JSONRPC: "2.0", ID: 1, Method: ipc.MethodQueryRun, Params: params}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-blocked:
	case <-time.After(5 * time.Second):
		t.Fatal("approval prompt not reached")
	}
	for _, raw := range []string{"y\n", `{"jsonrpc":"2.0","id":1,"result":"y"}` + "\n", `{"jsonrpc":"2.0","id":2,"method":"query.run","params":{"plan_id":"` + pr.PlanID + `"}}` + "\n"} {
		if _, err := c.Write([]byte(raw)); err != nil {
			break
		}
	}
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	r := bufio.NewReader(c)
	var resp ipc.Response
	_ = ipc.ReadMsg(r, &resp)
	if h.sess.runCount() != 0 {
		t.Fatal("bytes from the socket approved a statement")
	}
	cancel()
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not stop")
	}
	if h.sess.runCount() != 0 {
		t.Fatal("a statement ran")
	}
}

func TestStatementTextViewsRefused(t *testing.T) {
	h := newHarness(t, uatProfile())
	h.sess.cols = append(h.sess.cols, engine.ColumnInfo{DB: "app", Table: "pg_stat_statements", Column: "query", View: true})
	resp := h.call(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: "SELECT query FROM pg_stat_statements LIMIT 1"})
	wantCode(t, resp, ipc.CodeRefused)
	if !strings.Contains(resp.Error.Message, "text of past statements") {
		t.Errorf("refusal: %q", resp.Error.Message)
	}
	// MySQL/MariaDB system schemas are not in the catalog: refused as unknown.
	resp = h.call(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: "SELECT processlist_info FROM performance_schema.threads LIMIT 1"})
	wantCode(t, resp, ipc.CodeRefused)
}

func TestReferenceRoundTrip(t *testing.T) {
	h := newHarness(t, uatProfile())
	pr := h.plan(t, "SELECT id, email, note FROM users WHERE id = 1 LIMIT 1", false)
	h.io.answers = []string{"y"}
	var rr ipc.RunResult
	h.ok(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}, &rr)
	if rr.Rows[0][1] != "<redacted:r1.1.2>" || strings.Contains(rr.Text, "alice@") {
		t.Fatalf("row %v", rr.Rows[0])
	}
	h.sess.result = engine.Result{Columns: []engine.ResultColumn{{Label: "id"}}, Rows: [][]any{{int64(1)}}}
	q := "SELECT id FROM users WHERE email = '${r1.1.2}' LIMIT 1"
	pr = h.plan(t, q, false)
	if pr.SQL != q {
		t.Errorf("the plan shows %q", pr.SQL)
	}
	h.io.answers = []string{"y"}
	h.ok(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}, &rr)
	last := h.sess.runs[len(h.sess.runs)-1]
	if last != "SELECT id FROM users WHERE email = 'alice@example.com' LIMIT 1" {
		t.Errorf("ran %q", last)
	}
	for _, r := range h.sess.runs {
		if strings.HasPrefix(r, "SELECT COUNT(*)") {
			t.Errorf("k-check ran for a reference: %q", r)
		}
	}
	if strings.Contains(h.auditLog(t), "alice@example.com") {
		t.Error("the value reached the audit log")
	}
}

// A column that may hold a literal the agent wrote gets no reference on any
// row: a reference to it would be a lookup of a chosen value without the
// k-anonymity check. INTERSECT with a literal is an equality test on the
// PII column, refused outright.
func TestNoReferenceForLiteralColumn(t *testing.T) {
	h := newHarness(t, uatProfile())
	h.sess.result = engine.Result{Columns: []engine.ResultColumn{{Label: "email"}}, Rows: [][]any{{"alice@example.com"}, {"john@x.com"}}}
	pr := h.plan(t, "SELECT email FROM users UNION ALL SELECT 'john@x.com' LIMIT 50", false)
	h.io.answers = []string{"y"}
	var rr ipc.RunResult
	h.ok(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}, &rr)
	for _, row := range rr.Rows {
		if row[0] != "<redacted>" {
			t.Errorf("row %v", row)
		}
	}
	resp := h.call(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: "SELECT email FROM users INTERSECT SELECT 'john@x.com' LIMIT 50"})
	wantCode(t, resp, ipc.CodeRefused)
	if !strings.Contains(resp.Error.Message, "set operation compares a PII column") {
		t.Errorf("INTERSECT refusal %q", resp.Error.Message)
	}
}

// The plan of EXPLAIN quotes the statement's literals: with a placeholder
// it would hand the agent the value behind it.
func TestExplainWithPlaceholderRefused(t *testing.T) {
	h := newHarness(t, uatProfile())
	pr := h.plan(t, "SELECT id, email, note FROM users WHERE id = 1 LIMIT 1", false)
	h.io.answers = []string{"y"}
	h.ok(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}, nil)
	for _, q := range []string{
		"EXPLAIN SELECT id FROM users WHERE email = '${r1.1.2}' LIMIT 1",
		"EXPLAIN SELECT id FROM users WHERE email = '${email}' LIMIT 1",
	} {
		resp := h.call(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: q})
		wantCode(t, resp, ipc.CodeRefused)
		if !strings.Contains(resp.Error.Message, "EXPLAIN") {
			t.Errorf("%s: refusal %q", q, resp.Error.Message)
		}
	}
}

// A UNION arm of an unmasked column, or an aggregate of a PII column, gets
// no reference: the agent may know the value behind it.
func TestNoReferenceForMixedOrAggregateColumn(t *testing.T) {
	for _, q := range []string{
		"SELECT email FROM users UNION ALL SELECT note FROM users LIMIT 50",
		"SELECT email FROM users UNION ALL SELECT CAST(id AS char) FROM users LIMIT 50",
		"SELECT group_concat(email SEPARATOR 'x') AS email FROM users LIMIT 50",
	} {
		h := newHarness(t, uatProfile())
		h.sess.result = engine.Result{Columns: []engine.ResultColumn{{Label: "email"}}, Rows: [][]any{{"alice@example.com"}, {"7"}}}
		h.sess.count = &engine.Result{Columns: []engine.ResultColumn{{Label: "n"}}, Rows: [][]any{{int64(100)}}}
		pr := h.plan(t, q, false)
		h.io.answers = []string{"y"}
		var rr ipc.RunResult
		h.ok(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}, &rr)
		for _, row := range rr.Rows {
			if row[0] != "<redacted>" {
				t.Errorf("%s: row %v", q, row)
			}
		}
	}
	// A plain column keeps its references.
	h := newHarness(t, uatProfile())
	h.sess.result = engine.Result{Columns: []engine.ResultColumn{{Label: "email"}}, Rows: [][]any{{"alice@example.com"}}}
	pr := h.plan(t, "SELECT email FROM users WHERE id = 1 LIMIT 5", false)
	h.io.answers = []string{"y"}
	var rr ipc.RunResult
	h.ok(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}, &rr)
	if rr.Rows[0][0] != "<redacted:r1.1.1>" {
		t.Errorf("plain column: %v", rr.Rows[0])
	}
}

// A recursive CTE whose recursive arm adds a literal gets no reference.
func TestNoReferenceForRecursiveCTELiteral(t *testing.T) {
	h := newHarness(t, uatProfile())
	h.sess.result = engine.Result{Columns: []engine.ResultColumn{{Label: "e"}}, Rows: [][]any{{"alice@example.com"}, {"x"}}}
	pr := h.plan(t, "WITH RECURSIVE c(e, n) AS (SELECT email, 1 FROM users UNION ALL SELECT 'x', n+1 FROM c WHERE n < 2) SELECT e FROM c LIMIT 5", false)
	h.io.answers = []string{"y"}
	var rr ipc.RunResult
	h.ok(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}, &rr)
	for _, row := range rr.Rows {
		if row[0] != "<redacted>" {
			t.Errorf("row %v", row)
		}
	}
}

// A statement that filters a PII column with a literal the agent wrote gets
// no reference on any column: the agent chose the value behind it, and a
// reference would let it look that value up without the k-anonymity check.
func TestNoReferenceUnderAgentLiteralFilter(t *testing.T) {
	for _, q := range []string{
		"SELECT email FROM users WHERE email = 'victim@x.com' LIMIT 50",
		"SELECT email FROM users WHERE email IN ('victim@x.com', 'b@x.com') LIMIT 50",
		"SELECT email FROM users GROUP BY email HAVING email = 'victim@x.com' LIMIT 5",
		"SELECT email FROM users INTERSECT SELECT email FROM users WHERE email = 'victim@x.com' LIMIT 5",
		"SELECT email FROM users UNION SELECT email FROM users WHERE email = 'victim@x.com' LIMIT 5",
		"SELECT u.email FROM users u JOIN orders o ON o.user_id = u.id WHERE u.email = 'victim@x.com' LIMIT 5",
		"SELECT email FROM users WHERE id IN (SELECT id FROM users WHERE email = 'victim@x.com') LIMIT 5",
		"SELECT email FROM users WHERE email IN ('${r9.1.1}', 'victim@x.com') LIMIT 5",
	} {
		h := newHarness(t, uatProfile())
		h.sess.result = engine.Result{Columns: []engine.ResultColumn{{Label: "email"}}, Rows: [][]any{{"victim@x.com"}}}
		h.sess.count = &engine.Result{Columns: []engine.ResultColumn{{Label: "n"}}, Rows: [][]any{{int64(100)}}}
		if strings.Contains(q, "r9.1.1") {
			// A reference to a known cell, mixed with a literal.
			pr := h.plan(t, "SELECT email FROM users WHERE id = 1 LIMIT 1", false)
			h.io.answers = []string{"y"}
			h.ok(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}, nil)
			q = strings.Replace(q, "r9.1.1", "r1.1.1", 1)
		}
		pr := h.plan(t, q, false)
		h.io.answers = []string{"y"}
		var rr ipc.RunResult
		h.ok(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}, &rr)
		if len(rr.Rows) == 0 || rr.Rows[0][0] != "<redacted>" {
			t.Errorf("%s: rows %v", q, rr.Rows)
		}
	}
}

// A plain fetch, and a fetch filtered by a reference or a typed value, keep
// their references: the agent chose none of the values.
func TestReferenceUnderPlaceholderFilter(t *testing.T) {
	h := newHarness(t, uatProfile())
	h.sess.result = engine.Result{Columns: []engine.ResultColumn{{Label: "email"}}, Rows: [][]any{{"alice@example.com"}}}
	run := func(q string) ipc.RunResult {
		t.Helper()
		pr := h.plan(t, q, false)
		h.io.answers = []string{"y"}
		var rr ipc.RunResult
		h.ok(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}, &rr)
		return rr
	}
	if rr := run("SELECT email FROM users LIMIT 5"); rr.Rows[0][0] != "<redacted:r1.1.1>" {
		t.Errorf("plain fetch: %v", rr.Rows)
	}
	if rr := run("SELECT email FROM users WHERE email = '${r1.1.1}' LIMIT 5"); rr.Rows[0][0] != "<redacted:r2.1.1>" {
		t.Errorf("reference filter: %v", rr.Rows)
	}
	h.io.secrets = []string{"alice@example.com"}
	if rr := run("SELECT email FROM users WHERE email IN ('${email}', '${r1.1.1}') LIMIT 5"); rr.Rows[0][0] != "<redacted:r3.1.1>" {
		t.Errorf("typed value filter: %v", rr.Rows)
	}
}

// A recursive CTE too deep for the fixpoint is refused, not referenced.
func TestRecursiveCTENotConvergedRefused(t *testing.T) {
	h := newHarness(t, uatProfile())
	resp := h.call(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: "WITH RECURSIVE c(a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,n) AS (SELECT email,'victim@x.com',email,email,email,email,email,email,email,email,1 FROM users UNION ALL SELECT a10,a2,a2,a3,a4,a5,a6,a7,a8,a9,n+1 FROM c WHERE n < 12) SELECT a1 FROM c WHERE n >= 10 LIMIT 50"})
	wantCode(t, resp, ipc.CodeRefused)
}
