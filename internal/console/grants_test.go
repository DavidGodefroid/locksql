package console

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	kconsole "github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/plans"
	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/ipc"
)

// agentA is the agent of the grant tests that name none: grants need an
// agent token.
var agentA = ipc.Requester{Agent: "a", Token: "token-a"}

// orAgentA is who, or agentA when it is empty.
func orAgentA(who ipc.Requester) ipc.Requester {
	if who == (ipc.Requester{}) {
		return agentA
	}
	return who
}

// askGrant asks for a grant and returns its pending ticket.
func askGrant(t *testing.T, h *harness, p ipc.GrantParams) string {
	t.Helper()
	p.Requester = orAgentA(p.Requester)
	if p.DB == "" {
		p.DB = "app"
	}
	return pendingTicket(t, h.call(t, ipc.MethodGrant, p), "pending")
}

// activateGrant activates ticket tk once the hub's decision reached the
// console.
func activateGrant(t *testing.T, h *harness, tk string, who ipc.Requester) ipc.Response {
	t.Helper()
	who = orAgentA(who)
	deadline := time.Now().Add(10 * time.Second)
	for {
		r := h.call(t, ipc.MethodGrant, ipc.GrantParams{Ticket: tk, Requester: who})
		if r.Error == nil || !strings.Contains(r.Error.Message, "no decision") || time.Now().After(deadline) {
			return r
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// newGrant asks for a grant, has the hub approve it and activates it.
func newGrant(t *testing.T, h *harness, p ipc.GrantParams) ipc.GrantInfo {
	t.Helper()
	tk := askGrant(t, h, p)
	h.hub.Decide(tk, ticket.Approved, "")
	r := activateGrant(t, h, tk, orAgentA(p.Requester))
	if r.Error != nil {
		t.Fatalf("activate: %d %q", r.Error.Code, r.Error.Message)
	}
	var gr ipc.GrantResult
	if err := json.Unmarshal(r.Result, &gr); err != nil || gr.Status != "active" || gr.Grant == nil {
		t.Fatalf("activate: %s", r.Result)
	}
	return *gr.Grant
}

// runOf plans and runs sql for who: the run answer, without a hub decision.
func runOf(t *testing.T, h *harness, sql string, who ipc.Requester) ipc.Response {
	t.Helper()
	who = orAgentA(who)
	var pr ipc.PlanResult
	h.ok(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: sql, Requester: who}, &pr)
	return h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID, Requester: who})
}

// covered reports a run answered at once under a grant: its result.
func covered(t *testing.T, r ipc.Response) (ipc.RunResult, bool) {
	t.Helper()
	if r.Error != nil {
		t.Fatalf("run: %d %q", r.Error.Code, r.Error.Message)
	}
	var rr ipc.RunResult
	if err := json.Unmarshal(r.Result, &rr); err != nil {
		t.Fatal(err)
	}
	return rr, rr.Status == "" && rr.Grant != ""
}

func wantTicket(t *testing.T, r ipc.Response, why string) {
	t.Helper()
	if rr, ok := covered(t, r); ok || rr.Status != "pending" {
		t.Fatalf("%s: ran under a grant or no ticket: %+v", why, rr)
	}
}

func grantStatus(t *testing.T, h *harness) []ipc.GrantInfo {
	t.Helper()
	var st ipc.StatusResult
	h.ok(t, ipc.MethodStatus, nil, &st)
	return st.Grants
}

const readUsers = "SELECT id, email, note FROM users WHERE id = 1 LIMIT 10"

// One grant, then N reads of its tables within budget: one hub decision,
// N audited runs, no ticket for them.
func TestGrantCoversReads(t *testing.T) {
	h := newHarness(t, uatProfile())
	g := newGrant(t, h, ipc.GrantParams{Tables: []string{"users"}, Intent: "debug the sign-up"})
	if g.DB != "app" || strings.Join(g.Tables, ",") != "app.users" || g.Budget != (ipc.GrantBudget{Statements: 200, Rows: 10_000, Bytes: 1 << 20}) || g.ExpiresInS != 3600 {
		t.Fatalf("grant %+v", g)
	}
	tickets := len(h.hub.Tickets())
	for i := range 3 {
		rr, ok := covered(t, runOf(t, h, readUsers, ipc.Requester{}))
		if !ok || len(rr.Rows) != 1 || strings.Contains(rr.Text, "alice@") || rr.GrantLeft == nil || rr.GrantLeft.Statements != int64(199-i) {
			t.Fatalf("run %d: %+v", i, rr)
		}
	}
	if n := len(h.hub.Tickets()); n != tickets || h.io.promptCount() != 0 {
		t.Fatalf("%d tickets after the grant's, prompts %q", n-tickets, h.io.prompts)
	}
	runs := auditRecords(t, h, "run", g.ID)
	if len(runs) != 3 {
		t.Fatalf("%d run records under the grant", len(runs))
	}
	act := auditRecords(t, h, "grant", g.ID)
	if len(act) != 1 || act[0]["hub_sig"] == "" || act[0]["decision"] != "approved" {
		t.Fatalf("activation records %v", act)
	}
	for _, r := range runs {
		if r["grant"] != g.ID || r["hub_sig"] != act[0]["hub_sig"] || r["approval"] != kconsole.HubApproval || r["sql"] == "" {
			t.Fatalf("run record %v", r)
		}
	}
	st := grantStatus(t, h)
	if len(st) != 1 || st[0].Remaining.Statements != 197 || st[0].Remaining.Rows != 10_000-3 || st[0].Remaining.Bytes >= 1<<20 {
		t.Fatalf("status %+v", st)
	}
}

// Decision 1: a read that filters on a PII column is never covered,
// whatever the k-anonymity counts say and whatever the budget has left:
// the agent learns nothing from "ran" versus "ticket".
func TestGrantNeverCoversPIIFilters(t *testing.T) {
	for _, n := range []int64{1, 1_000_000} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			h := newHarness(t, uatProfile())
			h.sess.count = &engine.Result{Columns: []engine.ResultColumn{{Label: "n"}}, Rows: [][]any{{n}}}
			g := newGrant(t, h, ipc.GrantParams{Tables: []string{"users"}, Rows: 1})
			for _, q := range []string{
				"SELECT id FROM users WHERE email = 'alice@example.com' LIMIT 10",
				"SELECT COUNT(*) FROM users WHERE email IN ('alice@example.com') LIMIT 1",
				"SELECT email, COUNT(*) FROM users GROUP BY email LIMIT 10",
			} {
				wantTicket(t, runOf(t, h, q, ipc.Requester{}), q)
			}
			if st := grantStatus(t, h); st[0].Remaining.Statements != g.Budget.Statements {
				t.Fatalf("a PII read was charged: %+v", st[0])
			}
		})
	}
}

// Decision 5: each run costs one statement and returns at most what is
// left; a cut result is marked truncated; spent, the next read asks.
func TestGrantBudgetRows(t *testing.T) {
	h := newHarness(t, uatProfile())
	h.sess.result = engine.Result{Columns: []engine.ResultColumn{{Label: "id", OriginDB: "app", OriginTable: "users", OriginColumn: "id"}}}
	for i := range 5 {
		h.sess.result.Rows = append(h.sess.result.Rows, []any{int64(i)})
	}
	g := newGrant(t, h, ipc.GrantParams{Tables: []string{"users"}, Rows: 3})
	const q = "SELECT id FROM users WHERE id > 0 LIMIT 10"
	rr, ok := covered(t, runOf(t, h, q, ipc.Requester{}))
	if !ok || len(rr.Rows) != 3 || !rr.Truncated || rr.GrantLeft.Rows != 0 {
		t.Fatalf("capped run %+v", rr)
	}
	wantTicket(t, runOf(t, h, q, ipc.Requester{}), "rows spent")
	if st := grantStatus(t, h); st[0].Remaining.Rows != 0 || st[0].Remaining.Statements != g.Budget.Statements-1 {
		t.Fatalf("status %+v", st)
	}
}

func TestGrantBudgetBytes(t *testing.T) {
	h := newHarness(t, uatProfile())
	h.sess.result = engine.Result{Columns: []engine.ResultColumn{{Label: "note", OriginDB: "app", OriginTable: "users", OriginColumn: "note"}}}
	for range 50 {
		h.sess.result.Rows = append(h.sess.result.Rows, []any{strings.Repeat("x", 40)})
	}
	newGrant(t, h, ipc.GrantParams{Tables: []string{"users"}, Bytes: 600})
	const q = "SELECT note FROM users WHERE id > 0 LIMIT 100"
	rr, ok := covered(t, runOf(t, h, q, ipc.Requester{}))
	if !ok || !rr.Truncated || len(rr.Rows) == 0 || len(rr.Rows) >= 50 {
		t.Fatalf("capped run %+v", rr)
	}
	left := rr.GrantLeft.Bytes
	if left < 0 || left >= 600 {
		t.Fatalf("bytes left %d", left)
	}
	// What is left is charged again until less than a result's envelope
	// remains: never past the budget.
	for left >= minGrantBytes {
		rr, ok = covered(t, runOf(t, h, q, ipc.Requester{}))
		if !ok || rr.GrantLeft.Bytes < 0 || rr.GrantLeft.Bytes >= left {
			t.Fatalf("run %+v (left %d before)", rr, left)
		}
		left = rr.GrantLeft.Bytes
	}
	wantTicket(t, runOf(t, h, q, ipc.Requester{}), "bytes spent")
}

func TestGrantBudgetStatementsAndEstimate(t *testing.T) {
	h := newHarness(t, uatProfile())
	newGrant(t, h, ipc.GrantParams{Tables: []string{"users"}, Statements: 2, Rows: 40})
	// The EXPLAIN estimate is above the rows left: a ticket, not charged.
	h.sess.plan = engine.Plan{Root: engine.PlanNode{Detail: "QUERY", EstRows: -1, Children: []engine.PlanNode{{Table: "users", Access: engine.AccessRange, EstRows: 50}}}}
	wantTicket(t, runOf(t, h, readUsers, ipc.Requester{}), "estimate above the rows left")
	h.sess.plan = okPlan()
	for i := range 2 {
		if _, ok := covered(t, runOf(t, h, readUsers, ipc.Requester{})); !ok {
			t.Fatalf("run %d not covered", i)
		}
	}
	wantTicket(t, runOf(t, h, readUsers, ipc.Requester{}), "statements spent")
}

// Decision 6: a grant is the requesting agent's; a read is covered when
// every table it reads, CTEs and subqueries included, is in the first
// covering grant, which alone is charged.
func TestGrantScopeAndOwner(t *testing.T) {
	h := newHarness(t, uatProfile())
	me := ipc.Requester{Agent: "a", Token: "token-a"}
	other := ipc.Requester{Agent: "b", Token: "token-b"}
	first := newGrant(t, h, ipc.GrantParams{Tables: []string{"users"}, Statements: 1, Requester: me})
	second := newGrant(t, h, ipc.GrantParams{Tables: []string{"users", "orders"}, Requester: me})

	wantTicket(t, runOf(t, h, readUsers, other), "another agent")
	h.sess.result = idResult()
	for _, q := range []string{
		"WITH o AS (SELECT user_id FROM orders) SELECT u.id FROM users u JOIN o ON o.user_id = u.id LIMIT 10",
		"SELECT id FROM users WHERE id IN (SELECT user_id FROM orders) LIMIT 10",
	} {
		// orders is in the second grant only: the first does not cover.
		rr, ok := covered(t, runOf(t, h, q, me))
		if !ok || rr.Grant != second.ID {
			t.Fatalf("%s: %+v", q, rr)
		}
	}
	h.sess.result = userResult()
	rr, ok := covered(t, runOf(t, h, readUsers, me))
	if !ok || rr.Grant != first.ID {
		t.Fatalf("users read: %+v, want the first grant", rr)
	}
	st := grantStatus(t, h)
	if st[0].Remaining.Statements != 0 || st[1].Remaining.Statements != second.Budget.Statements-2 {
		t.Fatalf("charged %+v", st)
	}
	// The first grant covers users but is spent: the read asks.
	wantTicket(t, runOf(t, h, readUsers, me), "first grant spent")

	// A grant of users alone never covers orders hidden in a CTE or a
	// subquery, nor another database.
	h2 := newHarness(t, uatProfile())
	newGrant(t, h2, ipc.GrantParams{Tables: []string{"users"}})
	for _, q := range []string{
		"SELECT id FROM orders WHERE id = 1 LIMIT 10",
		"WITH o AS (SELECT user_id FROM orders) SELECT u.id FROM users u JOIN o ON o.user_id = u.id LIMIT 10",
		"SELECT id FROM users WHERE id IN (SELECT user_id FROM orders) LIMIT 10",
		"SELECT u.id FROM users u WHERE EXISTS (SELECT 1 FROM orders o WHERE o.user_id = u.id) LIMIT 10",
		"SELECT id FROM other.users WHERE id = 1 LIMIT 10",
	} {
		wantTicket(t, runOf(t, h2, q, ipc.Requester{}), q)
	}
}

// Decision 6: only the agent that asked for a grant activates it.
func TestGrantActivatedByItsAgentOnly(t *testing.T) {
	h := newHarness(t, uatProfile())
	tk := askGrant(t, h, ipc.GrantParams{Tables: []string{"users"}, Requester: ipc.Requester{Token: "token-a"}})
	h.hub.Decide(tk, ticket.Approved, "")
	wantCode(t, activateGrant(t, h, tk, ipc.Requester{Token: "token-b"}), ipc.CodeWrongRequester)
	if r := activateGrant(t, h, tk, ipc.Requester{Token: "token-a"}); r.Error != nil {
		t.Fatalf("own activation: %q", r.Error.Message)
	}
}

// Decision 2 and the ticket: risk grant, never auto, the plan hash binds
// the scope; the screen shows the clamped scope (decision 4); production
// asks for the instance name.
func TestGrantTicket(t *testing.T) {
	p := prodProfile()
	h := newHarness(t, p)
	tk := askGrant(t, h, ipc.GrantParams{Tables: []string{"users", "orders"}, Duration: "5h", Rows: 1_000_000_000, Statements: 3, Intent: "find the stuck orders"})
	var got ticket.Ticket
	if err := json.Unmarshal(h.hub.Ticket(tk), &got); err != nil {
		t.Fatal(err)
	}
	want, _ := ticket.HashOf(grantScope{Database: "app", Tables: []string{"app.orders", "app.users"}, Duration: "1h0m0s",
		Budget: ipc.GrantBudget{Statements: 3, Rows: 10_000, Bytes: 1 << 20}})
	if got.Risk != ticket.RiskGrant || !got.Flags.NeverAuto || !got.Flags.Production || got.PlanHash != want {
		t.Fatalf("ticket risk %s flags %+v hash %s, want %s", got.Risk, got.Flags, got.PlanHash, want)
	}
	sc := got.Screen
	body := strings.Join(sc.Body, "\n")
	if sc.Header != "grant on "+hubInstanceName || sc.Note != "find the stuck orders" || len(sc.Body) != 3 ||
		!strings.Contains(body, "app.orders, app.users") || !strings.Contains(body, "1h0m0s") || !strings.Contains(body, "asked 5h0m0s") ||
		!strings.Contains(body, "10000 rows (asked 1000000000)") || !strings.Contains(body, "3 statements ·") {
		t.Fatalf("screen %+v", sc)
	}
	// Not yet decided: nothing is active.
	if r := h.call(t, ipc.MethodGrant, ipc.GrantParams{Ticket: tk}); r.Error == nil || len(grantStatus(t, h)) != 0 {
		t.Fatal("activated before a decision")
	}
	// Decided, the grant's ticket does not run as a statement's; it still
	// activates the grant.
	h.hub.Decide(tk, ticket.Approved, "")
	deadline := time.Now().Add(10 * time.Second)
	for {
		r := h.call(t, ipc.MethodQueryRun, ipc.RunParams{Ticket: tk, Requester: agentA})
		if r.Error != nil && strings.Contains(r.Error.Message, "no decision") && time.Now().Before(deadline) {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		if r.Error == nil || r.Error.Code != ipc.CodeInvalidParams || !strings.Contains(r.Error.Message, "locksql_grant") {
			t.Fatalf("query.run of a grant ticket: %+v", r)
		}
		break
	}
	if r := activateGrant(t, h, tk, ipc.Requester{}); r.Error != nil {
		t.Fatalf("activation after query.run: %q", r.Error.Message)
	}
	// A statement's ticket is not a grant's.
	h.s.Command(context.Background(), ":revoke")
	var pr ipc.PlanResult
	h.ok(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: readUsers, Requester: agentA}, &pr)
	qt := pendingTicket(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID, Requester: agentA}), "pending")
	h.hub.Decide(qt, ticket.Approved, "")
	wantCode(t, activateGrant(t, h, qt, ipc.Requester{}), ipc.CodeInvalidParams)
}

// idResult is a result of one column, users.id.
func idResult() engine.Result {
	return engine.Result{Columns: []engine.ResultColumn{{Label: "id", OriginDB: "app", OriginTable: "users", OriginColumn: "id"}}, Rows: [][]any{{int64(1)}}}
}

// Decision 2: the decision must be acted on within the 4 h of a grant
// ticket; the grant's own duration counts from the activation.
func TestGrantActivationWindowAndDuration(t *testing.T) {
	h := newHarness(t, uatProfile())
	tk := askGrant(t, h, ipc.GrantParams{Tables: []string{"users"}})
	h.hub.DecideWith(tk, ticket.Approved, "", nil, func(d *ticket.Decision) { d.At = d.At.Add(-5 * time.Hour) })
	if r := activateGrant(t, h, tk, ipc.Requester{}); r.Error == nil || len(grantStatus(t, h)) != 0 {
		t.Fatalf("a decision older than 4 h activated a grant: %s", r.Result)
	}

	g := newGrant(t, h, ipc.GrantParams{Tables: []string{"users"}, Duration: "30m"})
	h.now = h.now.Add(29 * time.Minute)
	if _, ok := covered(t, runOf(t, h, readUsers, ipc.Requester{})); !ok {
		t.Fatal("not covered before its end")
	}
	h.now = h.now.Add(2 * time.Minute)
	wantTicket(t, runOf(t, h, readUsers, ipc.Requester{}), "expired")
	if ends := auditRecords(t, h, "grant_end", g.ID); len(ends) != 1 || ends[0]["decision"] != "expired" || ends[0]["hub_sig"] == "" {
		t.Fatalf("end records %v", ends)
	}
}

// Decision 4: grant_max_duration = 0 turns grants off.
func TestGrantsOff(t *testing.T) {
	p := uatProfile()
	p.Limits.GrantsOff = true
	h := newHarness(t, p)
	r := h.call(t, ipc.MethodGrant, ipc.GrantParams{Requester: agentA, DB: "app", Tables: []string{"users"}})
	wantCode(t, r, ipc.CodeRefused)
	if r.Error.Data == nil || r.Error.Data.Code != "E_GRANTS_OFF" {
		t.Fatalf("refusal %+v", r.Error)
	}
	wantCode(t, h.call(t, ipc.MethodGrant, ipc.GrantParams{Requester: agentA, DB: "app", Tables: []string{"nosuch"}}), ipc.CodeRefused)
}

func TestGrantUnknownTableRefused(t *testing.T) {
	h := newHarness(t, uatProfile())
	r := h.call(t, ipc.MethodGrant, ipc.GrantParams{Requester: agentA, DB: "app", Tables: []string{"nosuch"}})
	wantCode(t, r, ipc.CodeRefused)
	if r.Error.Data == nil || r.Error.Data.Code != "E_UNKNOWN_NAME" {
		t.Fatalf("refusal %+v", r.Error)
	}
	wantCode(t, h.call(t, ipc.MethodGrant, ipc.GrantParams{Requester: agentA, DB: "app"}), ipc.CodeInvalidParams)
	wantCode(t, h.call(t, ipc.MethodGrant, ipc.GrantParams{Requester: agentA, DB: "app", Tables: []string{"users"}, Duration: "soon"}), ipc.CodeInvalidParams)
	wantCode(t, h.call(t, ipc.MethodGrant, ipc.GrantParams{Requester: agentA, DB: "app", Tables: []string{"users"}, Rows: -1}), ipc.CodeInvalidParams)
	wantCode(t, h.call(t, ipc.MethodGrant, ipc.GrantParams{Requester: agentA, DB: "nosuch", Tables: []string{"users"}}), ipc.CodeRefused)
}

// A grant never covers an unmask or a write: they get a ticket.
func TestGrantNeverCoversUnmaskOrWrites(t *testing.T) {
	p := uatProfile()
	p.Tier = config.TierWrite
	h := newHarness(t, p, allowUnmask)
	newGrant(t, h, ipc.GrantParams{Tables: []string{"users"}})
	var pr ipc.PlanResult
	h.ok(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: readUsers, Unmask: true, Requester: agentA}, &pr)
	wantTicket(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID, Requester: agentA}), "unmask")
	wantTicket(t, runOf(t, h, "UPDATE users SET status = 'x' WHERE id = 1", ipc.Requester{}), "write")
}

// Decision 7: a WARN verdict runs under a grant; EXPLAIN SELECT is a read
// that costs one statement.
func TestGrantWarnAndExplain(t *testing.T) {
	p := uatProfile()
	p.Limits.ExplainRowsWarn = 10
	h := newHarness(t, p)
	newGrant(t, h, ipc.GrantParams{Tables: []string{"users"}})
	h.sess.plan = engine.Plan{Root: engine.PlanNode{Detail: "QUERY", EstRows: -1, Children: []engine.PlanNode{{Table: "users", Access: engine.AccessRange, EstRows: 50}}}}
	if _, ok := covered(t, runOf(t, h, readUsers, ipc.Requester{})); !ok {
		t.Fatal("a WARN read was not covered")
	}
	runs := h.sess.runCount()
	rr, ok := covered(t, runOf(t, h, "EXPLAIN SELECT id FROM users WHERE id = 1 LIMIT 1", ipc.Requester{}))
	if !ok || len(rr.Columns) != 1 || rr.Columns[0] != "plan" || h.sess.runCount() != runs || rr.GrantLeft.Statements != 198 {
		t.Fatalf("EXPLAIN under a grant: %+v", rr)
	}
}

// Decision 8: :revoke ends every grant, :revoke ID one; the end of the
// session ends them all; each end is audited with the grant and the
// decision's signature, and an activated ticket never activates again.
func TestGrantRevokeAndSessionEnd(t *testing.T) {
	h := newHarness(t, uatProfile())
	a := newGrant(t, h, ipc.GrantParams{Tables: []string{"users"}, Intent: "a"})
	b := newGrant(t, h, ipc.GrantParams{Tables: []string{"orders"}, Intent: "b"})
	c := newGrant(t, h, ipc.GrantParams{Tables: []string{"users", "orders"}, Intent: "c"})
	ctx := context.Background()
	before := len(h.io.out)
	h.s.Command(ctx, ":status")
	if out := ansi.ReplaceAllString(strings.Join(h.io.out[before:], "\n"), ""); !strings.Contains(out, a.ID) || !strings.Contains(out, "200/200 statements") {
		t.Fatalf(":status lacks the grants:\n%s", out)
	}
	h.s.Command(ctx, ":revoke "+a.ID)
	if st := grantStatus(t, h); len(st) != 2 {
		t.Fatalf("after :revoke ID: %+v", st)
	}
	h.s.Command(ctx, ":revoke")
	if st := grantStatus(t, h); len(st) != 0 {
		t.Fatalf("after :revoke: %+v", st)
	}
	for _, g := range []ipc.GrantInfo{a, b, c} {
		ends := auditRecords(t, h, "grant_end", g.ID)
		if len(ends) != 1 || ends[0]["decision"] != "revoked" || ends[0]["grant"] != g.ID || ends[0]["hub_sig"] == "" {
			t.Fatalf("end of %s: %v", g.ID, ends)
		}
	}
	wantTicket(t, runOf(t, h, readUsers, ipc.Requester{}), "revoked")
	if r := h.call(t, ipc.MethodGrant, ipc.GrantParams{Ticket: a.ID}); r.Error == nil {
		t.Fatal("a used grant ticket activated again")
	}

	d := newGrant(t, h, ipc.GrantParams{Tables: []string{"users"}, Intent: "d"})
	h.s.End("quit")
	h.s.Close()
	if ends := auditRecords(t, h, "grant_end", d.ID); len(ends) != 1 || !strings.HasPrefix(ends[0]["decision"].(string), "session end") {
		t.Fatalf("session end: %v", ends)
	}
}

// Grants live in the console's memory: a console started again has none,
// and the grant's ticket, consumed at its activation, gives none either.
func TestGrantsDoNotSurviveRestart(t *testing.T) {
	h := newHarness(t, uatProfile())
	g := newGrant(t, h, ipc.GrantParams{Tables: []string{"users"}})
	cfg := h.s.cfg
	h.s.Close()
	s2, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.s = s2
	if st := grantStatus(t, h); len(st) != 0 {
		t.Fatalf("grants after a restart: %+v", st)
	}
	wantTicket(t, runOf(t, h, readUsers, ipc.Requester{}), "after a restart")
	if r := h.call(t, ipc.MethodGrant, ipc.GrantParams{Ticket: g.ID}); r.Error == nil {
		t.Fatal("the grant's ticket activated again after a restart")
	}
}

// Finding 3: any change of the approved policy's fingerprint ends every
// grant, a tightening too (a lower limit, production); the same policy
// applied again ends none.
func TestGrantPolicyChangeEndsGrants(t *testing.T) {
	h := newHarness(t, uatProfile())
	g := newGrant(t, h, ipc.GrantParams{Tables: []string{"users"}})
	p := h.s.approved
	if err := h.s.ApplyPolicy(kpolicy{p}); err != nil {
		t.Fatal(err)
	}
	if st := grantStatus(t, h); len(st) != 1 {
		t.Fatalf("the same policy ended the grant: %+v", st)
	}
	p.Profile.Limits.GrantMaxRows = 5
	if err := h.s.ApplyPolicy(kpolicy{p}); err != nil {
		t.Fatal(err)
	}
	if st := grantStatus(t, h); len(st) != 0 {
		t.Fatalf("after a lower limit: %+v", st)
	}
	if ends := auditRecords(t, h, "grant_end", g.ID); len(ends) != 1 || ends[0]["decision"] != "policy_changed" || ends[0]["hub_sig"] == "" {
		t.Fatalf("end records %v", ends)
	}
	g2 := newGrant(t, h, ipc.GrantParams{Tables: []string{"users"}})
	p.Profile.Production = true
	if err := h.s.ApplyPolicy(kpolicy{p}); err != nil {
		t.Fatal(err)
	}
	if ends := auditRecords(t, h, "grant_end", g2.ID); len(ends) != 1 || ends[0]["decision"] != "policy_changed" {
		t.Fatalf("production: end records %v", ends)
	}
}

// A grant's ticket is never renewed: the agent asks for a new grant.
func TestGrantNotRenewed(t *testing.T) {
	h := newHarness(t, uatProfile())
	body, err := json.Marshal(hubPlan{Kind: grantKind, DB: "app", Grant: &grantScope{Database: "app", Tables: []string{"app.users"}, Duration: "1h0m0s"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := h.s.hubRecompute(&plans.Plan{Body: body}); err == nil {
		t.Fatal("a grant's plan was recomputed for a renewal")
	}
}

// Finding 4: a grant needs the agent's lea token, to ask for it, to
// activate it and to run under it: without one, every process of the
// account would share it.
func TestGrantNeedsAgentToken(t *testing.T) {
	h := newHarness(t, uatProfile())
	r := h.call(t, ipc.MethodGrant, ipc.GrantParams{DB: "app", Tables: []string{"users"}})
	wantCode(t, r, ipc.CodeRefused)
	if r.Error.Data == nil || r.Error.Data.Code != "E_GRANT_NEEDS_AGENT" {
		t.Fatalf("ask without a token: %+v", r.Error)
	}
	tk := askGrant(t, h, ipc.GrantParams{Tables: []string{"users"}})
	h.hub.Decide(tk, ticket.Approved, "")
	r = h.call(t, ipc.MethodGrant, ipc.GrantParams{Ticket: tk})
	wantCode(t, r, ipc.CodeRefused)
	if r.Error.Data == nil || r.Error.Data.Code != "E_GRANT_NEEDS_AGENT" {
		t.Fatalf("activation without a token: %+v", r.Error)
	}
	if r := activateGrant(t, h, tk, agentA); r.Error != nil {
		t.Fatalf("activation with the token: %q", r.Error.Message)
	}
	var pr ipc.PlanResult
	h.ok(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: readUsers}, &pr)
	wantTicket(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), "a run without a token")
}

// Finding 1: a grant is no oracle on columns the detectors mask. A text
// column no rule names (users.note) may be returned plainly under a grant,
// never compared, matched, cut, ordered or grouped: that would probe its
// values one character at a time without a ticket. A read whose approval
// screen would carry a warning gets a ticket too.
func TestGrantNeverCoversDetectorProbes(t *testing.T) {
	var h *harness
	for i, q := range []string{
		"SELECT id FROM users WHERE note = 'x@y' LIMIT 10",
		"SELECT id FROM users WHERE note LIKE 'b%' LIMIT 10",
		"SELECT id FROM users WHERE SUBSTRING(note, 10, 1) = 'b' LIMIT 10",
		"SELECT id FROM users ORDER BY note LIMIT 10",
		"SELECT status, COUNT(*) FROM users GROUP BY status LIMIT 10",
		"SELECT id FROM users u JOIN orders o ON o.user_id = u.id AND u.note = 'b' LIMIT 10",
		"SELECT CASE WHEN note LIKE 'b%' THEN 1 ELSE 0 END FROM users WHERE id = 1 LIMIT 10",
		"SELECT id FROM (SELECT id, note AS n FROM users) d WHERE n = 'b' LIMIT 10",
		"SELECT id, 'alice@example.com' FROM users WHERE id = 1 LIMIT 10",
		"SELECT id FROM users WHERE id IN (SELECT note FROM users) LIMIT 10",
	} {
		if i%4 == 0 {
			// A fresh console now and then: the hub caps the tickets
			// pending at once.
			h = newHarness(t, uatProfile())
			newGrant(t, h, ipc.GrantParams{Tables: []string{"users", "orders"}})
		}
		wantTicket(t, runOf(t, h, q, ipc.Requester{}), q)
	}
	// Returned plainly, a text column is masked by the detectors: covered.
	if _, ok := covered(t, runOf(t, h, readUsers, ipc.Requester{})); !ok {
		t.Fatal("a plain read of note was not covered")
	}
}

// A column an allow rule declares not personal may be a predicate under a
// grant.
func TestGrantCoversAllowedTextPredicate(t *testing.T) {
	allowNote := func(c *ServerConfig) {
		c.Policy = config.NewPolicy(c.Policy.Profile, []string{"app.users.email"}, []string{"app.users.note"})
	}
	h := newHarness(t, uatProfile(), allowNote)
	newGrant(t, h, ipc.GrantParams{Tables: []string{"users"}})
	if _, ok := covered(t, runOf(t, h, "SELECT id, email, note FROM users WHERE note LIKE 'b%' LIMIT 10", ipc.Requester{})); !ok {
		t.Fatal("a predicate on an allowed column was not covered")
	}
}

// textRows counts the rows of a TSV rendering: the lines between the
// header and the footer.
func textRows(text string) int {
	n := 0
	for i, l := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		if i > 0 && !strings.HasPrefix(l, "(") && !strings.HasPrefix(l, "[") {
			n++
		}
	}
	return n
}

// Finding 2: the TSV text carries exactly the rows of the JSON result, and
// both renderings are charged, so that what the agent gets never exceeds
// the budget.
func TestGrantBudgetCoversBothRenderings(t *testing.T) {
	p := uatProfile()
	p.Limits.MaxOutputBytes = 2000
	h := newHarness(t, p)
	h.sess.result = engine.Result{Columns: []engine.ResultColumn{{Label: "note", OriginDB: "app", OriginTable: "users", OriginColumn: "note"}}}
	for range 80 {
		h.sess.result.Rows = append(h.sess.result.Rows, []any{strings.Repeat("y", 30)})
	}
	const budget = 6000
	newGrant(t, h, ipc.GrantParams{Tables: []string{"users"}, Rows: 100, Bytes: budget})
	const q = "SELECT note FROM users WHERE id > 0 LIMIT 100"
	rows, text := 0, 0
	var left ipc.GrantBudget
	for i := range 2 {
		rr, ok := covered(t, runOf(t, h, q, ipc.Requester{}))
		if !ok {
			t.Fatalf("run %d not covered", i)
		}
		if tr := textRows(rr.Text); tr != len(rr.Rows) {
			t.Fatalf("run %d: the text carries %d rows, the JSON %d", i, tr, len(rr.Rows))
		}
		rows += len(rr.Rows)
		text += len(rr.Text)
		left = *rr.GrantLeft
	}
	if rows > 100 || 100-left.Rows != int64(rows) {
		t.Fatalf("%d rows delivered, %d charged", rows, 100-left.Rows)
	}
	if left.Bytes < 0 || budget-left.Bytes < int64(text) {
		t.Fatalf("%d bytes charged for %d bytes of text alone (left %d)", budget-left.Bytes, text, left.Bytes)
	}
}

// Finding 5: the end of a grant records what it used: statements, rows
// and bytes, 0 included.
func TestGrantEndRecordsUsage(t *testing.T) {
	h := newHarness(t, uatProfile())
	used := newGrant(t, h, ipc.GrantParams{Tables: []string{"users"}})
	idle := newGrant(t, h, ipc.GrantParams{Tables: []string{"orders"}})
	rr, ok := covered(t, runOf(t, h, readUsers, ipc.Requester{}))
	if !ok {
		t.Fatal("not covered")
	}
	h.s.Command(context.Background(), ":revoke")
	end := auditRecords(t, h, "grant_end", used.ID)
	if len(end) != 1 || end[0]["statements_used"] != float64(1) || end[0]["rows"] != float64(1) ||
		end[0]["bytes_used"] != float64(used.Budget.Bytes-rr.GrantLeft.Bytes) {
		t.Fatalf("end of the used grant: %v", end)
	}
	end = auditRecords(t, h, "grant_end", idle.ID)
	if len(end) != 1 || end[0]["statements_used"] != float64(0) || end[0]["bytes_used"] != float64(0) {
		t.Fatalf("end of the idle grant: %v", end)
	}
}

// digitsProfile is uatProfile with the default detectors, which match
// digits (phone, card, iban): a number column can hold what they mask.
func digitsProfile() config.Profile {
	p := uatProfile()
	p.Detectors = config.DefaultDetectors()
	return p
}

// withNISS adds users.niss, a bigint no rule names, to the fake catalog.
func withNISS(h *harness) {
	h.sess.cols = append(h.sess.cols, engine.ColumnInfo{DB: "app", Table: "users", Column: "niss", Type: "bigint(20)"})
}

// Review finding A: with a detector that matches digits, a number column no
// rule names is no grant predicate either: a range, a modulo, a sign, an
// ordering or a division by zero would probe its value without a ticket.
// The id the database generates (auto_increment) stays a predicate.
func TestGrantNeverCoversNumberProbes(t *testing.T) {
	var h *harness
	for i, q := range []string{
		"SELECT id FROM users WHERE niss BETWEEN 85000000000 AND 86000000000 LIMIT 10",
		"SELECT id FROM users WHERE id = 1 AND niss % 10 = 3 LIMIT 10",
		"SELECT id FROM users WHERE id = 1 AND niss > 0 LIMIT 10",
		"SELECT id FROM users ORDER BY niss LIMIT 10",
		"SELECT id FROM users WHERE id = 1 AND 1 / (niss - 85010112345) = 1 LIMIT 10",
	} {
		if i%4 == 0 {
			h = newHarness(t, digitsProfile())
			withNISS(h)
			newGrant(t, h, ipc.GrantParams{Tables: []string{"users"}})
		}
		wantTicket(t, runOf(t, h, q, ipc.Requester{}), q)
	}
	h.sess.result = idResult()
	if _, ok := covered(t, runOf(t, h, "SELECT id FROM users WHERE id = 1 LIMIT 10", ipc.Requester{})); !ok {
		t.Fatal("a predicate on the generated id was not covered")
	}
	// Without a digit detector, numbers hold nothing the detectors mask.
	h = newHarness(t, uatProfile())
	withNISS(h)
	newGrant(t, h, ipc.GrantParams{Tables: []string{"users"}})
	h.sess.result = idResult()
	if _, ok := covered(t, runOf(t, h, "SELECT id FROM users WHERE niss > 0 LIMIT 10", ipc.Requester{})); !ok {
		t.Fatal("a number predicate was not covered without a digit detector")
	}
}

// A number column an allow rule names stays a predicate.
func TestGrantCoversAllowedNumberPredicate(t *testing.T) {
	allow := func(c *ServerConfig) {
		c.Policy = config.NewPolicy(c.Policy.Profile, []string{"app.users.email"}, []string{"app.users.niss"})
	}
	h := newHarness(t, digitsProfile(), allow)
	withNISS(h)
	newGrant(t, h, ipc.GrantParams{Tables: []string{"users"}})
	h.sess.result = idResult()
	if _, ok := covered(t, runOf(t, h, "SELECT id FROM users WHERE niss > 0 LIMIT 10", ipc.Requester{})); !ok {
		t.Fatal("a predicate on an allowed number column was not covered")
	}
}
