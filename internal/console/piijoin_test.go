package console

import (
	"slices"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/hubclient/hubtest"
	"github.com/DavidGodefroid/lockkit/ticket"
	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/ipc"
)

const piiJoinWarning = "joins PII columns: app.orders.email = app.users.email; if either side holds a value the agent knows, the result tells it which subjects share it"

// piiJoinHarness masks app.users.email and app.orders.email.
func piiJoinHarness(t *testing.T, p config.Profile, opts ...hopt) *harness {
	t.Helper()
	opts = append(opts, func(c *ServerConfig) {
		c.Policy = config.NewPolicy(p, []string{"app.users.email", "app.orders.email"}, nil)
	})
	h := newHarness(t, p, opts...)
	h.sess.cols = []engine.ColumnInfo{{DB: "app", Table: "orders", Column: "email", Type: "text"}}
	h.sess.result = engine.Result{Columns: []engine.ResultColumn{{Label: "id", OriginDB: "app", OriginTable: "users", OriginColumn: "id"}}, Rows: [][]any{{int64(1)}}}
	return h
}

// A PII join hides the row estimates from the agent, warns the human
// (naming the columns, never a value) and is not grantable (#150).
func TestPIIJoinReadWarnedAndHidden(t *testing.T) {
	var hub *hubtest.Hub
	h := piiJoinHarness(t, uatProfile(), withHub(t, &hub))
	h.sess.plan = heavyPlan() // estimates the agent must not see
	for _, q := range []string{
		"SELECT u.id FROM users u JOIN orders o ON o.email = u.email LIMIT 5",
		"SELECT id FROM users WHERE email IN (SELECT email FROM orders) LIMIT 5",
		"SELECT u.id FROM users u JOIN orders o USING (email) LIMIT 5",
	} {
		pr := h.plan(t, q, false)
		if pr.Summary != "estimates hidden: the statement joins PII columns" || pr.Reasons != nil || pr.Verdict != "OK" {
			t.Errorf("%s: plan result %+v", q, pr)
		}
		pl := h.s.plans[pr.PlanID]
		if !estimatesHidden(pl) {
			t.Errorf("%s: estimates not hidden", q)
		}
		if w := h.s.warnings(pl); !slices.Equal(w, []string{piiJoinWarning}) {
			t.Errorf("%s: warnings %q", q, w)
		}
		pl.warnings = h.s.warnings(pl)
		if grantable(pl) {
			t.Errorf("%s: a PII join is grantable", q)
		}
	}
	// The ticket and the audit record of the decision carry the warning.
	h.sess.plan = okPlan()
	pr := h.plan(t, "SELECT u.id FROM users u JOIN orders o ON o.email = u.email LIMIT 5", false)
	tk := pendingTicket(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), "pending")
	if raw := string(hub.Ticket(tk)); !strings.Contains(raw, "joins PII columns: app.orders.email = app.users.email") {
		t.Errorf("ticket without the join warning: %s", raw)
	}
	hub.Decide(tk, ticket.Approved, "")
	if r := runTicket(t, h, tk); r.Error != nil {
		t.Fatalf("run: %q", r.Error.Message)
	}
	recs := h.auditRecords(t)
	last := recs[len(recs)-1]
	if !slices.Contains(anyStrings(last["warnings"]), piiJoinWarning) {
		t.Errorf("decision audited without the join warning: %v", last)
	}
}

func anyStrings(v any) []string {
	var out []string
	l, _ := v.([]any)
	for _, x := range l {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}

// A non-PII join gets no warning and keeps its estimates.
func TestNonPIIJoinNotWarned(t *testing.T) {
	h := piiJoinHarness(t, uatProfile())
	pr := h.plan(t, "SELECT u.id FROM users u JOIN orders o ON o.user_id = u.id LIMIT 5", false)
	pl := h.s.plans[pr.PlanID]
	if estimatesHidden(pl) || len(h.s.warnings(pl)) != 0 || strings.HasPrefix(pr.Summary, "estimates hidden") {
		t.Errorf("non-PII join: hidden %v warnings %q summary %q", estimatesHidden(pl), h.s.warnings(pl), pr.Summary)
	}
}

// A write that joins PII columns is allowed and gets the join warning only.
func TestPIIJoinWriteWarned(t *testing.T) {
	p := uatProfile()
	p.Tier = config.TierWrite
	h := piiJoinHarness(t, p)
	pr := h.plan(t, "UPDATE users SET note = 'x' WHERE email IN (SELECT email FROM orders)", false)
	pl := h.s.plans[pr.PlanID]
	if w := h.s.warnings(pl); !slices.Equal(w, []string{piiJoinWarning}) {
		t.Errorf("write warnings %q", w)
	}
}
