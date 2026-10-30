package console

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	kconsole "github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/hubclient"
	"github.com/DavidGodefroid/lockkit/hubclient/hubtest"
	"github.com/DavidGodefroid/lockkit/plans"
	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/ipc"
	"github.com/DavidGodefroid/locksql/internal/product"
	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

const hubInstanceName = "sql-uat"

// withHub puts the harness console in hub mode against a fake lockhub.
func withHub(t *testing.T, hub **hubtest.Hub) hopt {
	return func(c *ServerConfig) {
		home := t.TempDir()
		key, err := hubclient.InstanceKey(home, hubInstanceName)
		if err != nil {
			t.Fatal(err)
		}
		*hub = hubtest.New(t, hubInstanceName, key.Public().(ed25519.PublicKey))
		keyFile := filepath.Join(t.TempDir(), "hub.pub")
		if err := os.WriteFile(keyFile, []byte(base64.StdEncoding.EncodeToString((*hub).Pub)+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		h, err := kconsole.OpenHub(product.P, kconsole.HubOptions{URL: (*hub).URL(), KeyFile: keyFile, Instance: hubInstanceName, Home: home}, t.TempDir(), time.Now)
		if err != nil {
			t.Fatal(err)
		}
		c.Hub = h
		c.Approver = h.Approver(newTypedApprover(c.IO))
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { defer close(done); h.Watch(ctx, c.IO) }()
		// Watch writes the hub state under the temporary directories: it
		// ends before they are removed.
		t.Cleanup(func() {
			cancel()
			<-done
			if err := h.Close(); err != nil {
				t.Error(err)
			}
		})
	}
}

func pendingTicket(t *testing.T, resp ipc.Response, status string) string {
	t.Helper()
	if resp.Error != nil {
		t.Fatalf("query.run: %d %q", resp.Error.Code, resp.Error.Message)
	}
	var m map[string]string
	if err := json.Unmarshal(resp.Result, &m); err != nil || m["status"] != status || m["ticket"] == "" || m["lock"] != "locksql" || m["instance"] != hubInstanceName {
		t.Fatalf("result %s, want %s with a ticket", resp.Result, status)
	}
	return m["ticket"]
}

// runTicket runs a ticket until the hub's decision has reached the console.
func runTicket(t *testing.T, h *harness, tk string) ipc.Response {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		r := h.call(t, ipc.MethodQueryRun, ipc.RunParams{Ticket: tk})
		if r.Error == nil || !strings.Contains(r.Error.Message, "no decision") || time.Now().After(deadline) {
			return r
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Hub mode: query.run answers pending with a ticket, nothing is asked on
// the terminal and the ticket carries no value of the statement in clear;
// the ticket runs once, after the hub approved it.
func TestHubModePendingThenRun(t *testing.T) {
	var hub *hubtest.Hub
	h := newHarness(t, uatProfile(), withHub(t, &hub))
	const q = "SELECT id, email, note FROM users WHERE email = 'alice@example.com' LIMIT 10"
	pr := h.plan(t, q, false)
	tk := pendingTicket(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), "pending")
	// Only the k-anonymity counts ran, before the ticket.
	if h.io.promptCount() != 0 || slices.Contains(h.sess.runs, q) {
		t.Fatalf("prompts %q runs %q in hub mode", h.io.prompts, h.sess.runs)
	}
	raw := hub.Ticket(tk)
	if raw == nil || strings.Contains(string(raw), "alice@example.com") {
		t.Fatalf("hub ticket %s", raw)
	}
	if log := h.auditLog(t); !strings.Contains(log, `"event":"pending"`) || !strings.Contains(log, `"ticket":"`+tk+`"`) {
		t.Errorf("no pending record:\n%s", h.auditLog(t))
	}
	if r := h.call(t, ipc.MethodQueryRun, ipc.RunParams{Ticket: tk}); r.Error == nil {
		t.Fatal("ran before a decision")
	}
	hub.Decide(tk, ticket.Approved, "")
	r := runTicket(t, h, tk)
	if r.Error != nil {
		t.Fatalf("run of the approved ticket: %q", r.Error.Message)
	}
	var rr ipc.RunResult
	if err := json.Unmarshal(r.Result, &rr); err != nil || strings.Contains(rr.Text, "alice@") || len(rr.Rows) != 1 {
		t.Fatalf("result %s", r.Result)
	}
	if !hub.Consumed(tk) || h.io.promptCount() != 0 {
		t.Errorf("consumed %v, prompts %q", hub.Consumed(tk), h.io.prompts)
	}
	if r := h.call(t, ipc.MethodQueryRun, ipc.RunParams{Ticket: tk}); r.Error == nil {
		t.Fatal("a ticket ran twice")
	}
	if strings.Contains(h.io.output(), "auto mode:") {
		t.Error("auto mode in hub mode")
	}
	h.s.Key(KeyShiftTab)
	if h.s.autoApprove() {
		t.Error("Shift+Tab turned auto mode on in hub mode")
	}
}

// A denial reaches the agent with the human's reason, and nothing runs.
func TestHubModeDenied(t *testing.T) {
	var hub *hubtest.Hub
	h := newHarness(t, uatProfile(), withHub(t, &hub))
	pr := h.plan(t, selectUsers, false)
	tk := pendingTicket(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), "pending")
	hub.Decide(tk, ticket.Denied, "too wide")
	r := runTicket(t, h, tk)
	wantCode(t, r, ipc.CodeDenied)
	if !strings.Contains(r.Error.Message, "too wide") || h.sess.runCount() != 0 {
		t.Fatalf("denial %q, runs %d", r.Error.Message, h.sess.runCount())
	}
}

// What the statement resolves to changed between the decision and the
// run: stale, with a new ticket, and nothing ran.
func TestHubModeStale(t *testing.T) {
	var hub *hubtest.Hub
	h := newHarness(t, uatProfile(), withHub(t, &hub))
	st := guarded(h)
	pr := h.plan(t, selectUsers, false)
	tk := pendingTicket(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), "pending")
	hub.Decide(tk, ticket.Approved, "")
	st.Objects[1].Def = "SELECT 2" // CREATE OR REPLACE FUNCTION
	r := runTicket(t, h, tk)
	next := pendingTicket(t, r, "stale")
	if next == tk || h.sess.runCount() != 0 || hub.Pushed() != 2 {
		t.Fatalf("new ticket %q (old %q), runs %d, pushed %d", next, tk, h.sess.runCount(), hub.Pushed())
	}
	// The new ticket runs once approved.
	hub.Decide(next, ticket.Approved, "")
	if r := runTicket(t, h, next); r.Error != nil {
		t.Fatalf("run of the new ticket: %q", r.Error.Message)
	}
}

// Values typed in the console cannot be typed in hub mode.
func TestHubModeRefusesPlaceholders(t *testing.T) {
	var hub *hubtest.Hub
	h := newHarness(t, uatProfile(), withHub(t, &hub))
	pr := h.plan(t, typedQ, false)
	r := h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID})
	wantCode(t, r, ipc.CodeRefused)
	if hub.Pushed() != 0 || h.io.promptCount() != 0 {
		t.Fatalf("pushed %d prompts %q", hub.Pushed(), h.io.prompts)
	}
}

// A literal over several lines is masked on each of them: no line of it
// leaves the lock in clear (review of #104).
func TestHubScreenMultilineLiteral(t *testing.T) {
	const q = "SELECT id FROM users WHERE note = 'x\nJohnSecretSmith lives MainStreet\ny' LIMIT 1"
	for _, l := range statementLines(sqlclass.MySQL, q) {
		for _, p := range l {
			if strings.Contains(p.Text, "JohnSecretSmith") && !p.Value {
				t.Fatalf("line %+v sends a literal as structure", l)
			}
		}
	}
	var hub *hubtest.Hub
	h := newHarness(t, uatProfile(), withHub(t, &hub))
	h.sess.result = engine.Result{Columns: []engine.ResultColumn{{Label: "id"}}, Rows: [][]any{{int64(1)}}}
	pr := h.plan(t, q, false)
	tk := pendingTicket(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), "pending")
	if raw := string(hub.Ticket(tk)); strings.Contains(raw, "JohnSecretSmith") || strings.Contains(raw, "MainStreet") {
		t.Fatalf("hub ticket carries the literal: %s", raw)
	}
	// A statement that does not lex is a value throughout.
	for _, l := range statementLines(sqlclass.MySQL, "SELECT 'unterminated\nsecret") {
		for _, p := range l {
			if !p.Value {
				t.Fatalf("unlexed statement sent as structure: %+v", l)
			}
		}
	}
}

// A weight refusal hidden under a PII filter goes to the hub like any
// request and is refused only after the decision, without running.
func TestHubModeHiddenRefusal(t *testing.T) {
	const q = "SELECT id FROM users WHERE email = 'alice@example.com' LIMIT 1"
	var hub *hubtest.Hub
	h := newHarness(t, uatProfile(), withHub(t, &hub))
	h.sess.plan = heavyPlan()
	pr := h.plan(t, q, false)
	tk := pendingTicket(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), "pending")
	hub.Decide(tk, ticket.Approved, "")
	r := runTicket(t, h, tk)
	wantCode(t, r, ipc.CodeRefused)
	if r.Error.Message != hiddenWeightRefusal || slices.Contains(h.sess.runs, q) {
		t.Fatalf("refusal %q, runs %q", r.Error.Message, h.sess.runs)
	}
}

// A policy change between the submission and the run makes the ticket
// stale: its decision was taken under another policy.
func TestHubModePolicyChangedIsStale(t *testing.T) {
	var hub *hubtest.Hub
	h := newHarness(t, uatProfile(), withHub(t, &hub))
	pr := h.plan(t, selectUsers, false)
	tk := pendingTicket(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), "pending")
	tight := h.s.approved
	tight.Profile.Limits.MaxRows = 50
	if err := h.s.adopt(tight, "tightened"); err != nil {
		t.Fatal(err)
	}
	hub.Decide(tk, ticket.Approved, "")
	pendingTicket(t, runTicket(t, h, tk), "stale")
	if slices.Contains(h.sess.runs, selectUsers) {
		t.Fatal("ran under another policy")
	}
}

// A hidden refusal stays hidden through a stale resubmission: the new
// ticket is refused after its decision too, without running.
func TestHubModeHiddenRefusalSurvivesStale(t *testing.T) {
	const q = "SELECT id FROM users WHERE email = 'alice@example.com' LIMIT 1"
	var hub *hubtest.Hub
	h := newHarness(t, uatProfile(), withHub(t, &hub))
	st := guarded(h)
	h.sess.plan = heavyPlan()
	pr := h.plan(t, q, false)
	tk := pendingTicket(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), "pending")
	st.Objects[1].Def = "SELECT 2"
	hub.Decide(tk, ticket.Approved, "")
	next := pendingTicket(t, runTicket(t, h, tk), "stale")
	// The new plan keeps the refusal waiting for its decision.
	p, err := h.s.cfg.Hub.Store.ByTicket(next, hubCaller(context.Background(), ipc.Requester{}))
	if err != nil {
		t.Fatal(err)
	}
	var body hubPlan
	if err := json.Unmarshal(p.Body, &body); err != nil || !body.Refuse {
		t.Fatalf("resubmitted plan body %s: the hidden refusal was dropped", p.Body)
	}
	hub.Decide(next, ticket.Approved, "")
	r := runTicket(t, h, next)
	wantCode(t, r, ipc.CodeRefused)
	if r.Error.Message != hiddenWeightRefusal || slices.Contains(h.sess.runs, q) {
		t.Fatalf("refusal %q, runs %q", r.Error.Message, h.sess.runs)
	}
}

// A plan and its ticket run only for the agent that asked for them (its
// lea token, decision H3): another agent's token is refused, and the plan
// stays the requester's.
func TestHubModeWrongRequester(t *testing.T) {
	var hub *hubtest.Hub
	h := newHarness(t, uatProfile(), withHub(t, &hub))
	alice := ipc.Requester{Agent: "dev-alice", Token: "hash-of-alice-token"}
	bob := ipc.Requester{Agent: "dev-bob", Token: "hash-of-bob-token"}
	var pr ipc.PlanResult
	h.ok(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: selectUsers, Requester: alice}, &pr)
	wantCode(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID, Requester: bob}), ipc.CodeWrongRequester)
	wantCode(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), ipc.CodeWrongRequester)
	tk := pendingTicket(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID, Requester: alice}), "pending")
	raw := string(hub.Ticket(tk))
	if !strings.Contains(raw, `claims lea agent \"dev-alice\"`) || strings.Contains(raw, alice.Token) {
		t.Fatalf("ticket requester: %s", raw)
	}
	hub.Decide(tk, ticket.Approved, "")
	run := func(who ipc.Requester) ipc.Response {
		deadline := time.Now().Add(10 * time.Second)
		for {
			r := h.call(t, ipc.MethodQueryRun, ipc.RunParams{Ticket: tk, Requester: who})
			if r.Error == nil || !strings.Contains(r.Error.Message, "no decision") || time.Now().After(deadline) {
				return r
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	for _, who := range []ipc.Requester{bob, {}, {Agent: "dev-alice", Token: "forged"}} {
		wantCode(t, run(who), ipc.CodeWrongRequester)
	}
	if slices.Contains(h.sess.runs, selectUsers) {
		t.Fatal("another agent's ticket ran")
	}
	if r := run(alice); r.Error != nil {
		t.Fatalf("the requester's run: %q", r.Error.Message)
	}
	if strings.Contains(h.auditLog(t), alice.Token) {
		t.Error("the token is in the audit log")
	}
}

// Outside hub mode a plan id runs only for its requester too.
func TestPlanIDWrongRequester(t *testing.T) {
	h := newHarness(t, uatProfile())
	var pr ipc.PlanResult
	h.ok(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: selectUsers, Requester: ipc.Requester{Token: "a"}}, &pr)
	wantCode(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID, Requester: ipc.Requester{Token: "b"}}), ipc.CodeWrongRequester)
	if h.io.promptCount() != 0 {
		t.Fatal("asked the human for another agent's plan")
	}
}

func writeProfile() config.Profile {
	p := uatProfile()
	p.Tier = config.TierWrite
	return p
}

// A write that changes more rows than its approval allows is rolled back
// in its own transaction and answered stale with a new ticket, whose bound
// covers what it would have changed (decision H2); approved again, it runs.
// Both on an engine that checks the definitions (guarded) and one that
// only counts the rows.
func TestHubModeRowcountRecheck(t *testing.T) {
	for _, withGuard := range []bool{true, false} {
		name := "counted"
		if withGuard {
			name = "guarded"
		}
		t.Run(name, func(t *testing.T) {
			const q = "UPDATE users SET note = 'x' WHERE id = 1"
			var hub *hubtest.Hub
			h := newHarness(t, writeProfile(), withHub(t, &hub))
			if withGuard {
				guarded(h)
			}
			pr := h.plan(t, q, false)
			tk := pendingTicket(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), "pending")
			body := hubBody(t, h, tk)
			if body.MaxAffected <= 0 || body.MaxAffected >= 500 {
				t.Fatalf("bound %d", body.MaxAffected)
			}
			if raw := string(hub.Ticket(tk)); !strings.Contains(raw, "rows changed: at most") {
				t.Fatalf("the screen does not show the bound: %s", raw)
			}
			h.sess.result = engine.Result{Affected: 500}
			hub.Decide(tk, ticket.Approved, "")
			next := pendingTicket(t, runTicket(t, h, tk), "stale")
			if !slices.Contains(h.sess.rolledBack, q) {
				t.Fatalf("not rolled back: %q", h.sess.rolledBack)
			}
			nb := hubBody(t, h, next)
			if nb.MaxAffected < 500 {
				t.Fatalf("the new bound %d does not cover the 500 rows", nb.MaxAffected)
			}
			if raw := string(hub.Ticket(next)); !strings.Contains(raw, "would have changed 500 rows") {
				t.Fatalf("the new screen does not say why: %s", raw)
			}
			hub.Decide(next, ticket.Approved, "")
			r := runTicket(t, h, next)
			if r.Error != nil {
				t.Fatalf("run of the new ticket: %q", r.Error.Message)
			}
			var rr ipc.RunResult
			if err := json.Unmarshal(r.Result, &rr); err != nil || rr.Affected != 500 || len(h.sess.rolledBack) != 1 {
				t.Fatalf("result %s, rolled back %q", r.Result, h.sess.rolledBack)
			}
			if withGuard && h.sess.countedRuns != 0 || !withGuard && h.sess.countedRuns != 2 {
				t.Errorf("counted runs %d", h.sess.countedRuns)
			}
		})
	}
}

// A write within its bound commits at once.
func TestHubModeRowcountWithinBound(t *testing.T) {
	const q = "DELETE FROM users WHERE id = 1"
	var hub *hubtest.Hub
	h := newHarness(t, writeProfile(), withHub(t, &hub))
	h.sess.result = engine.Result{Affected: 1}
	pr := h.plan(t, q, false)
	tk := pendingTicket(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), "pending")
	hub.Decide(tk, ticket.Approved, "")
	if r := runTicket(t, h, tk); r.Error != nil || len(h.sess.rolledBack) != 0 || !hub.Consumed(tk) {
		t.Fatalf("run %+v, rolled back %q", r.Error, h.sess.rolledBack)
	}
}

// Without object definitions (MySQL, SQLite), the ticket of a write lists
// the triggers of the tables it names (#120); a read asks for none.
func TestHubModeTriggersListed(t *testing.T) {
	var hub *hubtest.Hub
	h := newHarness(t, writeProfile(), withHub(t, &hub))
	h.sess.triggers = []string{"trigger app.users.users_log (after update)"}
	pr := h.plan(t, "UPDATE users SET note = 'x' WHERE id = 1", false)
	tk := pendingTicket(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), "pending")
	raw := string(hub.Ticket(tk))
	if !strings.Contains(raw, "rows the bound does not count may change too") || !strings.Contains(raw, "users_log (after update)") {
		t.Fatalf("ticket: %s", raw)
	}
	if len(h.sess.triggerNames) != 1 || !slices.Contains(h.sess.triggerNames[0], "users") {
		t.Fatalf("asked about %q", h.sess.triggerNames)
	}
	h.plan(t, "SELECT id FROM users LIMIT 1", false)
	if len(h.sess.triggerNames) != 1 {
		t.Fatalf("a read listed triggers: %q", h.sess.triggerNames)
	}
}

// A multi-row VALUES gets a bound of at least its rows, though EXPLAIN
// gives no estimate for them (#120).
func TestHubModeValuesBound(t *testing.T) {
	var hub *hubtest.Hub
	h := newHarness(t, writeProfile(), withHub(t, &hub))
	rows := make([]string, 30)
	for i := range rows {
		rows[i] = "(" + strconv.Itoa(i+100) + ", 'x')"
	}
	pr := h.plan(t, "INSERT INTO users (id, note) VALUES "+strings.Join(rows, ", "), false)
	tk := pendingTicket(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), "pending")
	if body := hubBody(t, h, tk); body.MaxAffected < 30 {
		t.Fatalf("bound %d for 30 rows", body.MaxAffected)
	}
}

// A write whose rows the engine cannot count before a commit (a
// non-transactional table on MySQL) is refused with E_STATEMENT_KIND, not
// the generic failure, so that the agent does not retry it (#120).
func TestHubModeUncountedRefused(t *testing.T) {
	var hub *hubtest.Hub
	h := newHarness(t, writeProfile(), withHub(t, &hub))
	pr := h.plan(t, "UPDATE users SET note = 'x' WHERE id = 1", false)
	tk := pendingTicket(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), "pending")
	h.sess.runErr = engine.Uncounted(errors.New("mysql: the write reaches tables a ROLLBACK may not undo: app.users (base table myisam); its rows cannot be checked before a commit"))
	hub.Decide(tk, ticket.Approved, "")
	r := runTicket(t, h, tk)
	if r.Error == nil || r.Error.Data == nil || r.Error.Data.Code != "E_STATEMENT_KIND" || !strings.Contains(r.Error.Message, "app.users") || !strings.Contains(r.Error.Message, "do not retry") {
		t.Fatalf("run: %+v", r.Error)
	}
}

func hubBody(t *testing.T, h *harness, tk string) hubPlan {
	t.Helper()
	p, err := h.s.cfg.Hub.Store.ByTicket(tk, hubCaller(context.Background(), ipc.Requester{}))
	if err != nil {
		t.Fatal(err)
	}
	var body hubPlan
	if err := json.Unmarshal(p.Body, &body); err != nil {
		t.Fatal(err)
	}
	return body
}

func TestRowBound(t *testing.T) {
	for n, want := range map[int64]int64{-1: 10, 0: 10, 1: 11, 10: 20, 500: 1000, math.MaxInt64: math.MaxInt64} {
		if got := rowBound(n); got != want {
			t.Errorf("rowBound(%d) = %d, want %d", n, got, want)
		}
	}
}

// The screen names the peer as the kernel reports it; the lea name is the
// client's unverified claim, labelled so, escaped and cut.
func TestAgentNameIsAClaim(t *testing.T) {
	ctx := context.Background()
	peer := kconsole.PeerText(ctx)
	if got := agentName(ctx, ipc.Requester{}); got != peer {
		t.Fatalf("no claim: %q", got)
	}
	got := agentName(ctx, ipc.Requester{Agent: "lead\x1b[2Jroot" + strings.Repeat("é", 100)})
	if !strings.HasPrefix(got, peer+" · claims lea agent ") || strings.Contains(got, "\x1b") || len([]rune(got)) > len([]rune(peer))+100 {
		t.Fatalf("claim: %q", got)
	}
}

func TestNestedDML(t *testing.T) {
	for q, want := range map[string]bool{
		"WITH d AS (DELETE FROM t RETURNING id) UPDATE u SET x = 1":                               true,
		"WITH d AS (INSERT INTO t VALUES (1) RETURNING id) SELECT * FROM d":                       true,
		"WITH d AS MATERIALIZED (MERGE INTO t USING s ON true WHEN MATCHED THEN DELETE) SELECT 1": true,
		"WITH d AS NOT MATERIALIZED (UPDATE t SET x = 1 RETURNING x) SELECT * FROM d":             true,
		"WITH s AS (SELECT id FROM t) UPDATE u SET x = 1 WHERE id IN (SELECT id FROM s)":          false,
		"UPDATE u SET note = 'delete' WHERE id = 1":                                               false,
		"INSERT INTO u SELECT * FROM t":                                                           false,
		"INSERT INTO b (id, update) VALUES (1, 2)":                                                false,
		"DELETE FROM q WHERE id IN (SELECT id FROM q LIMIT 5 FOR UPDATE SKIP LOCKED)":             false,
		"DELETE FROM q WHERE id IN (SELECT id FROM q FOR NO KEY UPDATE)":                          false,
		"WITH d AS (SELECT 1) SELECT * FROM (WITH e AS (DELETE FROM t RETURNING 1) SELECT 1) x":   true,
	} {
		if got := nestedDML(sqlclass.Postgres, q); got != want {
			t.Errorf("nestedDML(%q) = %v", q, got)
		}
	}
	if nestedDML(sqlclass.MySQL, "UPDATE t SET s = CONCAT(INSERT(s, 1, 1, 'X'), 'y')") {
		t.Error("MySQL's INSERT() function taken for a nested write")
	}
}

func TestSideEffects(t *testing.T) {
	st := engine.ObjectState{Objects: []engine.ObjectDef{
		{Kind: "relation", Name: "app.users", Def: "r"},
		{Kind: "trigger", Name: "app.users.audit", Def: "O"},
		{Kind: "rule", Name: "app.users.r1", Def: "O"},
		{Kind: "constraint", Name: "app.orders.fk", Def: "f\x1fFOREIGN KEY (uid) REFERENCES users(id) ON DELETE CASCADE"},
		{Kind: "constraint", Name: "app.notes.fk", Def: "f\x1fFOREIGN KEY (uid) REFERENCES users(id)"},
	}}
	got := strings.Join(sideEffects(st), "|")
	if got != "trigger app.users.audit|rule app.users.r1|foreign key app.orders.fk" {
		t.Fatalf("side effects %q", got)
	}
}

// A hub-mode write refuses a data-modifying statement inside it, and
// names the triggers its bound does not count on its ticket.
func TestHubModeWriteSideEffects(t *testing.T) {
	var hub *hubtest.Hub
	h := newHarness(t, writeProfile(), withHub(t, &hub))
	st := guarded(h)
	st.Objects = append(st.Objects, engine.ObjectDef{Kind: "trigger", Name: "app.users.audit", Def: "O"})
	pr := h.plan(t, "UPDATE users SET note = 'x' WHERE id = 1", false)
	tk := pendingTicket(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), "pending")
	if raw := string(hub.Ticket(tk)); !strings.Contains(raw, "trigger app.users.audit") {
		t.Fatalf("ticket: %s", raw)
	}
}

// A write plan stored without a rowcount bound (an older console) never
// runs unbounded: it is stale.
func TestBindRows(t *testing.T) {
	w := &plan{st: sqlclass.Statement{Class: sqlclass.Write}}
	if err := w.bindRows(hubPlan{}); !errors.Is(err, plans.ErrStale) {
		t.Fatalf("unbounded write: %v", err)
	}
	if err := w.bindRows(hubPlan{MaxAffected: 12}); err != nil || w.maxAffected != 12 {
		t.Fatalf("bounded write: %v %d", err, w.maxAffected)
	}
	r := &plan{st: sqlclass.Statement{Class: sqlclass.Read}}
	if err := r.bindRows(hubPlan{}); err != nil {
		t.Fatalf("read: %v", err)
	}
}

func TestSideEffectsVolatileFunction(t *testing.T) {
	fn := func(vol string) engine.ObjectDef {
		return engine.ObjectDef{Kind: "function", Name: "app.f(integer)", Def: strings.Join([]string{vol, "BEGIN \x1f weird END", "", "", "f", "f", "plpgsql", "integer", "integer", "", "alice"}, "\x1f")}
	}
	if got := sideEffects(engine.ObjectState{Objects: []engine.ObjectDef{fn("v")}}); len(got) != 1 || got[0] != "function app.f(integer)" {
		t.Fatalf("volatile: %q", got)
	}
	if got := sideEffects(engine.ObjectState{Objects: []engine.ObjectDef{fn("i"), fn("s")}}); len(got) != 0 {
		t.Fatalf("immutable/stable: %q", got)
	}
}

// auditRecords are the records of the harness's audit log with event
// (any event when empty) on ticket tk.
func auditRecords(t *testing.T, h *harness, event, tk string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(h.auditLog(t)), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("audit line %q: %v", l, err)
		}
		if m["ticket"] == tk && (event == "" || m["event"] == event) {
			out = append(out, m)
		}
	}
	return out
}

// decideSigned decides ticket tk at the hub and returns the decision as
// the hub signed it; mod, when not nil, changes it before signing.
func decideSigned(t *testing.T, hub *hubtest.Hub, tk string, out ticket.Outcome, reason string, mod func(*ticket.Decision)) *ticket.Decision {
	t.Helper()
	var d *ticket.Decision
	hub.DecideWith(tk, out, reason, nil, func(x *ticket.Decision) {
		if mod != nil {
			mod(x)
		}
		d = x
	})
	raw, err := d.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ticket.VerifyDecision(hub.Pub, raw); err != nil || d.Sig == "" {
		t.Fatalf("the hub's decision does not verify: %v", err)
	}
	return d
}

// wantHubSigned checks that rec records decision d of the hub: its
// signature, who answered and on which facade, as lockhub's `lock audit
// verify --lock` matches them.
func wantHubSigned(t *testing.T, rec map[string]any, d *ticket.Decision) {
	t.Helper()
	ap, _ := rec["approver"].(map[string]any)
	if rec["hub_sig"] != d.Sig || rec["approval"] != kconsole.HubApproval || ap["id"] != d.Approver.ID || rec["facade"] != d.Facade {
		t.Fatalf("record %v, want the hub's signature %s, approver %s on %s", rec, d.Sig, d.Approver.ID, d.Facade)
	}
}

// The hub's decisions are audited with the hub's signature (#118): the
// approval (not the run that follows it) and the denial, once each.
func TestHubModeDecisionsCarryHubSig(t *testing.T) {
	var hub *hubtest.Hub
	h := newHarness(t, uatProfile(), withHub(t, &hub))
	pr := h.plan(t, selectUsers, false)
	tk := pendingTicket(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), "pending")
	d := decideSigned(t, hub, tk, ticket.Approved, "", nil)
	if r := runTicket(t, h, tk); r.Error != nil {
		t.Fatalf("run of the approved ticket: %q", r.Error.Message)
	}
	approved := auditRecords(t, h, "approved", tk)
	if len(approved) != 1 || approved[0]["decision"] != "approved" {
		t.Fatalf("approval records %v", approved)
	}
	wantHubSigned(t, approved[0], d)
	runs := auditRecords(t, h, "run", tk)
	if len(runs) != 1 || runs[0]["hub_sig"] != nil {
		t.Fatalf("run records %v, want one without the hub's signature", runs)
	}

	pr = h.plan(t, "SELECT id FROM users WHERE id = 2 LIMIT 10", false)
	dt := pendingTicket(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), "pending")
	dd := decideSigned(t, hub, dt, ticket.Denied, "too wide", nil)
	wantCode(t, runTicket(t, h, dt), ipc.CodeDenied)
	wantCode(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{Ticket: dt}), ipc.CodeDenied)
	denied := auditRecords(t, h, "denied", dt)
	if len(denied) != 1 || denied[0]["decision"] != "denied" || denied[0]["reason"] != "too wide" ||
		denied[0]["sql"] != "SELECT id FROM users WHERE id = 2 LIMIT 10" || denied[0]["db"] == nil {
		t.Fatalf("denial records %v, want one with the statement and the reason", denied)
	}
	wantHubSigned(t, denied[0], dd)
	if h.sess.runCount() != 1 {
		t.Fatalf("runs %d", h.sess.runCount())
	}
}
