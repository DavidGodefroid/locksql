package console

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/engine/sqlite"
	"github.com/DavidGodefroid/locksql/internal/ipc"
)

func countResult(n any) *engine.Result {
	return &engine.Result{Columns: []engine.ResultColumn{{Label: "count"}}, Rows: [][]any{{n}}}
}

// kRun plans q and runs it once the hub decided its ticket with out. It
// returns the response and the warnings of the ticket, as its pending
// record holds them.
func kRun(t *testing.T, h *harness, q string, out ticket.Outcome, reason string) (resp ipc.Response, warnings string) {
	t.Helper()
	pr := h.plan(t, q, false)
	resp = h.decideRun(t, pr.PlanID, out, reason)
	recs := h.auditRecords(t)
	for i := len(recs) - 1; i >= 0; i-- {
		if recs[i]["event"] == "pending" {
			return resp, fmt.Sprint(recs[i]["warnings"])
		}
	}
	t.Fatal("no pending record")
	return resp, ""
}

// A count under k does not refuse: it runs before the ticket and warns the
// human on it, who decides as usual.
func TestKAnonymityWarnsBeforeApproval(t *testing.T) {
	h := newHarness(t, uatProfile())
	h.sess.result = engine.Result{Columns: []engine.ResultColumn{{Label: "id"}}, Rows: [][]any{{int64(1)}}}
	const q = "SELECT id FROM users WHERE email = 'alice@example.com' LIMIT 1"

	h.sess.count = countResult(int64(2))
	pr := h.plan(t, q, false)
	if strings.Contains(pr.Summary, "est.") || pr.Reasons != nil {
		t.Errorf("row estimates reach the agent: %+v", pr)
	}
	under, warn := kRun(t, h, q, ticket.Approved, "")
	if under.Error != nil {
		t.Fatalf("a count under k refused the statement: %q", under.Error.Message)
	}
	// The subjects of the PII column are counted in its own table, before
	// the ticket.
	if want := "SELECT COUNT(*) FROM `app`.`users` WHERE `app`.`users`.`email` = 'alice@example.com'"; len(h.sess.runs) == 0 || h.sess.runs[0] != want {
		t.Errorf("k-checks run %q, want first %q", h.sess.runs, want)
	}
	if last := h.sess.runs[len(h.sess.runs)-1]; last != q {
		t.Errorf("last run %q, want the statement", last)
	}
	const alert = "k-anonymity: the PII filter matches fewer than k=5 rows (2)"
	if !strings.Contains(warn, alert) {
		t.Errorf("ticket lacks the warning: %s", warn)
	}

	// Above k: no warning, and the agent's answer is the same.
	h.sess.count = countResult(int64(7))
	over, warn := kRun(t, h, q, ticket.Approved, "")
	if strings.Contains(warn, "k-anonymity:") {
		t.Errorf("a count above k warns: %s", warn)
	}
	if string(under.Result) != string(over.Result) {
		t.Errorf("the agent's answer depends on the count:\nunder k %s\nabove k %s", under.Result, over.Result)
	}
	recs := h.auditRecords(t)
	if w := fmt.Sprint(recs[len(recs)-1]["warnings"]); strings.Contains(w, "k-anonymity") {
		t.Errorf("a count above k is audited with a warning: %s", w)
	}

	// A denial after the warning is an ordinary denial.
	h.sess.count = countResult(int64(2))
	resp, _ := kRun(t, h, q, ticket.Denied, "too narrow")
	wantCode(t, resp, ipc.CodeDenied)
	if !strings.Contains(resp.Error.Message, "too narrow") || strings.Contains(resp.Error.Message, "k-anonymity") {
		t.Errorf("denial: %q", resp.Error.Message)
	}

	// A group too small warns about the group; a NULL (no group) does not.
	h.sess.result = engine.Result{Columns: []engine.ResultColumn{{Label: "email"}, {Label: "count"}}, Rows: [][]any{}}
	h.sess.count = countResult(int64(1))
	resp, warn = kRun(t, h, "SELECT email, count(*) FROM users GROUP BY email LIMIT 5", ticket.Approved, "")
	if resp.Error != nil || !strings.Contains(warn, "k-anonymity: a group covers fewer than k=5 rows (1)") {
		t.Errorf("small group: %+v %s", resp.Error, warn)
	}
	h.sess.count = countResult(nil)
	resp, warn = kRun(t, h, "SELECT email, count(*) FROM users GROUP BY email LIMIT 5", ticket.Approved, "")
	if resp.Error != nil || strings.Contains(warn, "k-anonymity") {
		t.Errorf("no group: %+v %s", resp.Error, warn)
	}
}

// A count that cannot run warns too; the statement is the human's to run.
func TestKAnonymityCountFailureWarns(t *testing.T) {
	h := newHarness(t, uatProfile())
	h.sess.result = engine.Result{Columns: []engine.ResultColumn{{Label: "id"}}, Rows: [][]any{{int64(1)}}}
	h.sess.count = &engine.Result{Columns: []engine.ResultColumn{{Label: "count"}}, Rows: [][]any{{"many"}}}
	resp, warn := kRun(t, h, "SELECT id FROM users WHERE email = 'alice@example.com' LIMIT 1", ticket.Approved, "")
	if resp.Error != nil {
		t.Fatalf("refused: %q", resp.Error.Message)
	}
	if !strings.Contains(warn, "k-anonymity: a count returned no number") {
		t.Errorf("no warning: %s", warn)
	}
}

// The demo statement of a customer's spend, on a real SQLite database
// with k = 5 and four orders per customer: each group is under k, so the
// approval frame warns, and the human's y runs it.
func TestKAnonymityDemoStatementRunsOnApproval(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shop.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	stmts := []string{
		`CREATE TABLE customers (id INTEGER PRIMARY KEY, name TEXT, email TEXT, country_code TEXT)`,
		`CREATE TABLE orders (id INTEGER PRIMARY KEY, customer_id INTEGER, total_cents INTEGER)`,
	}
	for c := 1; c <= 6; c++ {
		stmts = append(stmts, fmt.Sprintf(`INSERT INTO customers (id, name, email, country_code) VALUES (%d, 'n%d', 'c%d@example.com', 'BE')`, c, c, c))
		for o := 0; o < 4; o++ {
			stmts = append(stmts, fmt.Sprintf(`INSERT INTO orders (customer_id, total_cents) VALUES (%d, %d)`, c, 100*c+o))
		}
	}
	for _, q := range stmts {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	p := config.Profile{
		Name: "lite", Engine: config.EngineSQLite, Path: path, Tier: config.TierRead,
		Detectors: []string{"email"}, Limits: config.DefaultLimits(false),
	}
	p.Limits.KAnonymity = 5
	sess, err := sqlite.Engine{}.Connect(context.Background(), p, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sess.Close() })
	h := newHarness(t, p, func(c *ServerConfig) {
		c.Policy = config.NewPolicy(p, []string{"main.customers.name", "main.customers.email"}, nil)
		c.Session, c.Databases = sess, []string{"main"}
	})
	const q = `SELECT c.id, c.name, c.email, SUM(o.total_cents) AS spend
FROM customers c JOIN orders o ON o.customer_id = c.id
WHERE c.country_code = 'BE'
GROUP BY c.id, c.name, c.email ORDER BY spend DESC LIMIT 3`
	var pr ipc.PlanResult
	h.ok(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "main", SQL: q}, &pr)
	var rr ipc.RunResult
	h.okRun(t, pr.PlanID, &rr)
	if len(rr.Rows) != 3 {
		t.Errorf("rows %v", rr.Rows)
	}
	if w := fmt.Sprint(recordsOf(t, h, "pending")[0]["warnings"]); !strings.Contains(w, "k-anonymity: a group covers fewer than k=5 rows (4)") {
		t.Errorf("ticket lacks the warning: %s", w)
	}
}

// An IN list is an OR over its values: with k = 2, two values that exist
// twice each must not carry a third, absent one through the check. Each value
// is counted apart on a real SQLite database and the smallest count decides.
func TestKAnonymityINCountsEachValue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, note TEXT)`,
		`INSERT INTO users (email, note) VALUES ('a@example.com', 'n'), ('a@example.com', 'n'), ('b@example.com', 'n'), ('b@example.com', 'n')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	p := config.Profile{
		Name: "lite", Engine: config.EngineSQLite, Path: path, Tier: config.TierRead,
		Detectors: []string{"email"}, Limits: config.DefaultLimits(false),
	}
	p.Limits.KAnonymity = 2
	sess, err := sqlite.Engine{}.Connect(context.Background(), p, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sess.Close() })
	h := newHarness(t, p, func(c *ServerConfig) {
		c.Policy = config.NewPolicy(p, []string{"main.users.email"}, nil)
		c.Session, c.Databases = sess, []string{"main"}
	})
	run := func(q string) (ipc.Response, string) {
		t.Helper()
		var pr ipc.PlanResult
		h.ok(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "main", SQL: q}, &pr)
		resp := h.approveRun(t, pr.PlanID)
		recs := recordsOf(t, h, "pending")
		return resp, fmt.Sprint(recs[len(recs)-1]["warnings"])
	}
	resp, warn := run("SELECT id FROM users WHERE email IN ('a@example.com', 'b@example.com', 'absent@example.com') LIMIT 5")
	if resp.Error != nil {
		t.Fatalf("refused: %q", resp.Error.Message)
	}
	out := ansi.ReplaceAllString(h.io.output(), "")
	if !strings.Contains(out, "SELECT MIN(locksql_n) FROM (SELECT COUNT(*) AS locksql_n FROM") {
		t.Errorf("approval screen does not show the per-value count:\n%s", out)
	}
	if !strings.Contains(warn, "k-anonymity: the PII filter matches fewer than k=2 rows (0)") {
		t.Errorf("the absent value does not warn: %s", warn)
	}
	// The values that exist pass without a warning.
	resp, warn = run("SELECT id FROM users WHERE email IN ('a@example.com', 'b@example.com') LIMIT 5")
	if resp.Error != nil {
		t.Errorf("existing values refused: %d %q", resp.Error.Code, resp.Error.Message)
	}
	if strings.Contains(warn, "k-anonymity") {
		t.Errorf("existing values warn: %s", warn)
	}
}

func TestResponseIsLevelled(t *testing.T) {
	h := newHarness(t, uatProfile(), func(c *ServerConfig) { c.Quantum = 150 * time.Millisecond })
	pr := h.plan(t, selectUsers, false)
	h.io.answers = []string{"y"}
	start := time.Now()
	h.okRun(t, pr.PlanID, nil)
	if el := time.Since(start); el < 150*time.Millisecond {
		t.Errorf("answered after %s, before the quantum", el)
	}
	// A failure leaves on the quantum too, and says nothing of the server.
	h.sess.runErr = context.DeadlineExceeded
	pr = h.plan(t, selectUsers, false)
	h.io.answers = []string{"y"}
	start = time.Now()
	resp := h.approveRun(t, pr.PlanID)
	if el := time.Since(start); el < 150*time.Millisecond || resp.Error == nil {
		t.Errorf("failure answered after %s: %+v", el, resp.Error)
	}
}

func TestRunResultHasNoTimings(t *testing.T) {
	h := newHarness(t, uatProfile())
	pr := h.plan(t, selectUsers, false)
	h.io.answers = []string{"y"}
	resp := h.approveRun(t, pr.PlanID)
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
	h.okRun(t, pr.PlanID, &rr)
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
	// The client said "y" in every way it could: the run still waits for
	// the human's decision in lockhub.
	h.ok(t, ipc.MethodChangeRequest, ipc.ChangeParams{Change: "y"}, nil)
	pendingTicket(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), "pending")
	if h.sess.runCount() != 0 {
		t.Fatal("a statement ran without the human's answer")
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
	h.okRun(t, pr.PlanID, &rr)
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
	h.okRun(t, pr.PlanID, nil)
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
		h.okRun(t, pr.PlanID, &rr)
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
	h.okRun(t, pr.PlanID, &rr)
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
	h.okRun(t, pr.PlanID, &rr)
	for _, row := range rr.Rows {
		if row[0] != "<redacted>" {
			t.Errorf("row %v", row)
		}
	}
}

// A recursive CTE too deep for the fixpoint is refused, not referenced.
func TestRecursiveCTENotConvergedRefused(t *testing.T) {
	h := newHarness(t, uatProfile())
	resp := h.call(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: "WITH RECURSIVE c(a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,n) AS (SELECT email,'victim@x.com',email,email,email,email,email,email,email,email,1 FROM users UNION ALL SELECT a10,a2,a2,a3,a4,a5,a6,a7,a8,a9,n+1 FROM c WHERE n < 12) SELECT a1 FROM c WHERE n >= 10 LIMIT 50"})
	wantCode(t, resp, ipc.CodeRefused)
}

// Under a PII filter the weight verdict is a 1-bit oracle on the planner's
// statistics: query.plan answers OK with the estimates hidden, and query.run
// shows the REFUSE to the human and sends the ticket to lockhub: the client
// gets a generic refusal only once the human decided. Neither the main
// EXPLAIN nor a k-anonymity count's makes the answer come without the human.
func TestWeightVerdictUnderPIIFilterDecidedAtRun(t *testing.T) {
	const q = "SELECT id FROM users WHERE email = 'alice@example.com' LIMIT 1"
	heavy := heavyPlan()
	for _, tc := range []struct {
		name string
		opts []hopt
		set  func(*fakeSession)
	}{
		{"main EXPLAIN", nil, func(f *fakeSession) { f.plan = heavyPlan() }},
		{"k-anonymity count", nil, func(f *fakeSession) { f.kplan = &heavy }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, uatProfile(), tc.opts...)
			tc.set(h.sess)
			resp := h.call(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: q})
			if resp.Error != nil {
				t.Fatalf("plan refused under a PII filter: %q", resp.Error.Message)
			}
			var pr ipc.PlanResult
			if err := json.Unmarshal(resp.Result, &pr); err != nil {
				t.Fatal(err)
			}
			if pr.PlanID == "" || pr.Verdict != "OK" || pr.Summary != "estimates hidden: the statement filters on a PII column" || pr.Reasons != nil {
				t.Fatalf("plan result: %+v", pr)
			}
			if strings.Contains(h.auditLog(t), `"event":"refused"`) {
				t.Error("plan refusal audited under a PII filter")
			}
			run := h.approveRun(t, pr.PlanID) // an approval refuses too
			wantCode(t, run, ipc.CodeRefused)
			if run.Error.Message != "refused by the weight check (the details are shown on the console)" {
				t.Errorf("run refusal: %q", run.Error.Message)
			}
			if h.io.promptCount() != 0 {
				t.Errorf("prompts %q", h.io.prompts)
			}
			if h.sess.runCount() != 0 {
				t.Fatal("a REFUSE verdict ran")
			}
			// The plan id is random hex and may hold "000": only the
			// fields that could carry an estimate are checked.
			noID := pr
			noID.PlanID = ""
			shown, _ := json.Marshal(noID)
			for _, s := range []string{string(shown), run.Error.Message} {
				if strings.Contains(s, "000") || strings.Contains(s, "est.") {
					t.Errorf("an estimate reaches the client: %s", s)
				}
			}
			out := ansi.ReplaceAllString(h.io.output(), "")
			for _, want := range []string{"verdict REFUSE", "50 000 000"} {
				if !strings.Contains(out, want) {
					t.Errorf("the console does not show %q: %s", want, out)
				}
			}
			// The audit record keeps the weight reason the client does
			// not get.
			recs := h.auditRecords(t)
			if last := recs[len(recs)-1]; last["event"] != "refused" || last["code"] != "E_COST" || !strings.Contains(fmt.Sprint(last["error"]), "50 000 000") {
				t.Errorf("run refusal record: %v", last)
			}
		})
	}

	// Without a PII filter the verdict is answered at plan time, as before.
	h := newHarness(t, uatProfile())
	h.sess.plan = heavyPlan()
	resp := h.call(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: "SELECT id FROM users WHERE id = 1 LIMIT 1"})
	wantCode(t, resp, ipc.CodeRefused)
	if !strings.HasPrefix(resp.Error.Message, "weight check") {
		t.Errorf("plan refusal: %q", resp.Error.Message)
	}
}
