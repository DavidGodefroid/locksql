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
